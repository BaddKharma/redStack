#!/bin/bash
# adaptix_setup.sh - AdaptixC2 server initial provisioning
# Configures OS, SSH, firewall, VNC desktop, builds and starts the AdaptixC2
# teamserver (Go), and drops build_adaptix_client.sh for manual execution
# after boot (the Qt6 GUI client is built as a Docker AppImage).
#
# The AdaptixC2 build is deliberately non-fatal: a build failure must not strand
# the VNC desktop or the rest of provisioning. cloud-init runs user-data with no
# HOME, so HOME/GOPATH/GOCACHE are set explicitly before any go/make call.

set -e

exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "===== AdaptixC2 Server Setup Started $(date) ====="

SSH_PASSWORD="${ssh_password}"
MAIN_VPC_CIDR="${main_vpc_cidr}"
REDIRECTOR_VPC_CIDR="${redirector_vpc_cidr}"
REDIRECTOR_PUBLIC_IP="${redirector_public_ip}"
ADAPTIX_URI_PREFIX="${adaptix_uri_prefix}"
C2_HEADER_NAME="${c2_header_name}"
C2_HEADER_VALUE="${c2_header_value}"
export SSH_PASSWORD

# cloud-init has no HOME; Go needs it (and GOPATH/GOCACHE) or module verification
# fails with "missing $GOPATH: HOME is not set".
export HOME=/root
export GOPATH=/root/go
export GOCACHE=/root/.cache/go-build
export PATH=$PATH:/usr/local/go/bin

# Set hostname
hostnamectl set-hostname adaptix

# Configure /etc/hosts for lab machines
cat >> /etc/hosts << HOSTS

# redStack lab hosts
${adaptix_private_ip}    adaptix
${guacamole_private_ip}  guac
${mythic_private_ip}     mythic
${sliver_private_ip}     sliver
${redirector_private_ip} redirector
${windows_private_ip}    windows
${kali_private_ip}       kali
HOSTS

# ── SSH first — ensures recovery access even if later steps fail ─────────────
echo "admin:$SSH_PASSWORD" | chpasswd
mkdir -p /home/admin
chown admin:admin /home/admin
usermod -d /home/admin -s /bin/bash admin

cat >> /etc/ssh/sshd_config << 'SSHCONF'

# Default: require SSH keys
PasswordAuthentication no
PubkeyAuthentication yes

# Allow password auth from private networks (for Guacamole access via VPC)
Match Address 172.16.0.0/12,10.0.0.0/8
    PasswordAuthentication yes
SSHCONF

systemctl restart sshd
echo "[+] SSH password auth active — recovery access available"

# Update system
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Build deps for the AdaptixC2 server + extenders (mingw cross-compiles the
# Windows beacon), Docker for the client AppImage build, and an XFCE/VNC
# desktop so the Qt6 client can run on the box and be reached via Guacamole.
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git \
    make \
    gcc \
    g++ \
    build-essential \
    mingw-w64 \
    g++-mingw-w64 \
    libssl-dev \
    curl \
    wget \
    ufw \
    net-tools \
    jq \
    ca-certificates \
    openssl \
    docker.io \
    xfce4 \
    xfce4-terminal \
    tigervnc-standalone-server \
    dbus-x11 \
    libfuse2

systemctl enable --now docker || echo "[!] docker enable failed — client build will need it started manually"
usermod -aG docker admin || true

# Configure UFW firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow from $REDIRECTOR_VPC_CIDR to any port 80 proto tcp comment 'HTTP C2 from redirector'
ufw allow from $REDIRECTOR_VPC_CIDR to any port 443 proto tcp comment 'HTTPS C2 from redirector'
ufw allow 4321/tcp comment 'Adaptix teamserver (operator client)'
ufw allow from $MAIN_VPC_CIDR to any port 5901 proto tcp comment 'VNC from main VPC'
ufw --force enable

# ── Go toolchain (AdaptixServer requires golang 1.25.4) ──────────────────────
GO_VERSION="1.25.4"
if /usr/local/go/bin/go version 2>/dev/null | grep -q "$GO_VERSION"; then
    echo "[*] Go $GO_VERSION already installed, skipping"
else
    echo "[*] Installing Go $GO_VERSION..."
    wget -q "https://go.dev/dl/go$${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
fi
ln -sf /usr/local/go/bin/go /usr/local/bin/go
mkdir -p "$GOPATH" "$GOCACHE"
go version

# ── yq for profile editing ───────────────────────────────────────────────────
if ! command -v yq >/dev/null 2>&1; then
    wget -q https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/local/bin/yq
    chmod +x /usr/local/bin/yq
fi

# ── Clone + build AdaptixC2 server + extenders (NON-FATAL) ────────────────────
# A build failure must not abort the rest of provisioning (VNC desktop, service
# units, client build script). If it fails, ~/build_adaptix_server.sh retries it.
ADAPTIX_BUILT=0
set +e
if [ ! -d /opt/AdaptixC2/.git ]; then
    echo "[*] Cloning AdaptixC2..."
    git clone https://github.com/Adaptix-Framework/AdaptixC2.git /opt/AdaptixC2
fi
echo "[*] Building AdaptixC2 server + extenders (make server-ext)..."
( cd /opt/AdaptixC2 && make server-ext )
if [ -f /opt/AdaptixC2/dist/adaptixserver ]; then
    ADAPTIX_BUILT=1
    echo "[+] AdaptixC2 server built"
else
    echo "[!] AdaptixC2 server build FAILED — desktop/services still provisioned; run ~/build_adaptix_server.sh to retry"
fi
set -e

# ── Teamserver cert + profile (only if the build produced a binary) ──────────
if [ "$ADAPTIX_BUILT" = "1" ]; then
    cd /opt/AdaptixC2/dist
    if [ ! -f server.rsa.key ] || [ ! -f server.rsa.crt ]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout server.rsa.key -out server.rsa.crt -days 3650 \
            -subj "/CN=adaptix"
    fi
    # Patch the shipped server profile: operator password = lab secret, pinned
    # endpoint/port. Extenders stay as shipped so all beacon listeners exist.
    if [ -f /opt/AdaptixC2/dist/profile.yaml ]; then
        yq -i '.Teamserver.password = strenv(SSH_PASSWORD)' profile.yaml
        yq -i '.Teamserver.endpoint = "/adaptix"' profile.yaml
        yq -i '.Teamserver.port = 4321' profile.yaml
        yq -i '.Teamserver.interface = "0.0.0.0"' profile.yaml
        yq -i '.Teamserver.cert = "server.rsa.crt"' profile.yaml
        yq -i '.Teamserver.key = "server.rsa.key"' profile.yaml
        echo "[+] profile.yaml patched"
    else
        echo "[!] WARNING: /opt/AdaptixC2/dist/profile.yaml not found after build"
    fi
fi
chown -R admin:admin /opt/AdaptixC2 2>/dev/null || true

# ── Systemd service: AdaptixC2 teamserver (unit written regardless) ──────────
cat > /etc/systemd/system/adaptix.service << 'SVCEOF'
[Unit]
Description=AdaptixC2 Teamserver
After=network.target

[Service]
Type=simple
User=admin
Group=admin
WorkingDirectory=/opt/AdaptixC2/dist
ExecStart=/opt/AdaptixC2/dist/adaptixserver -profile profile.yaml
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

# ── Manual server (re)build+start script, for a failed/updated build ─────────
cat > /home/admin/build_adaptix_server.sh << 'SRVBUILD'
#!/bin/bash
# build_adaptix_server.sh - (re)build the AdaptixC2 teamserver and start it.
# Runs with a proper HOME/GOPATH so the Go module verification works.
set -e
export HOME=/root
export GOPATH=/root/go
export GOCACHE=/root/.cache/go-build
export PATH=$PATH:/usr/local/go/bin
sudo mkdir -p /root/go /root/.cache/go-build
echo "[*] Building AdaptixC2 server + extenders..."
sudo -E env HOME=/root GOPATH=/root/go GOCACHE=/root/.cache/go-build PATH="$PATH" \
    bash -c 'cd /opt/AdaptixC2 && make server-ext'
cd /opt/AdaptixC2/dist
if [ ! -f server.rsa.key ] || [ ! -f server.rsa.crt ]; then
    sudo openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout server.rsa.key -out server.rsa.crt -days 3650 -subj "/CN=adaptix"
fi
APASS='${ssh_password}'
export APASS
sudo -E yq -i '.Teamserver.password = strenv(APASS)' profile.yaml
sudo yq -i '.Teamserver.endpoint = "/adaptix"' profile.yaml
sudo yq -i '.Teamserver.port = 4321' profile.yaml
sudo yq -i '.Teamserver.interface = "0.0.0.0"' profile.yaml
sudo yq -i '.Teamserver.cert = "server.rsa.crt"' profile.yaml
sudo yq -i '.Teamserver.key = "server.rsa.key"' profile.yaml
sudo chown -R admin:admin /opt/AdaptixC2
sudo systemctl daemon-reload
sudo systemctl enable adaptix.service
sudo systemctl restart adaptix.service
echo "[+] Teamserver (re)started — sudo systemctl status adaptix"
SRVBUILD
chmod +x /home/admin/build_adaptix_server.sh

# ── TigerVNC desktop (operator runs the Adaptix client here) ─────────────────
mkdir -p /home/admin/.vnc
printf '%s\n' "$SSH_PASSWORD" | vncpasswd -f > /home/admin/.vnc/passwd
chmod 600 /home/admin/.vnc/passwd

cat > /home/admin/.vnc/xstartup << 'XSTART'
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
exec startxfce4
XSTART
chmod +x /home/admin/.vnc/xstartup

# Autostart the Adaptix client when the XFCE session begins
# (fails silently until build_adaptix_client.sh has been run)
mkdir -p /home/admin/.config/autostart
cat > /home/admin/.config/autostart/adaptix-client.desktop << 'AUTOSTART'
[Desktop Entry]
Type=Application
Name=AdaptixC2 Client
Exec=adaptix-client
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
AUTOSTART

mkdir -p /home/admin/Desktop
cat > /home/admin/Desktop/Adaptix-Client.desktop << 'DESKICON'
[Desktop Entry]
Type=Application
Name=AdaptixC2 Client
Comment=Connect to the AdaptixC2 Teamserver
Exec=adaptix-client
Icon=utilities-terminal
Terminal=false
Categories=Network;
DESKICON
chmod +x /home/admin/Desktop/Adaptix-Client.desktop

cat > /etc/systemd/system/vncserver@.service << 'VNCSVC'
[Unit]
Description=TigerVNC Desktop :%i
After=network.target

[Service]
Type=forking
User=admin
WorkingDirectory=/home/admin
ExecStartPre=-/usr/bin/vncserver -kill :%i > /dev/null 2>&1
ExecStart=/usr/bin/vncserver :%i -geometry 1280x800 -depth 24 -localhost no
ExecStop=/usr/bin/vncserver -kill :%i
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
VNCSVC

# ── Manual client build script (Docker AppImage; Qt6 lives in the container) ──
cat > /home/admin/build_adaptix_client.sh << 'BUILDSCRIPT'
#!/bin/bash
# build_adaptix_client.sh - Build the AdaptixC2 GUI client as a static AppImage
# Run manually after boot: ~/build_adaptix_client.sh
# Debian 12's apt Qt is 6.4 (the client needs >6.8), so the build runs inside
# Docker and emits a self-contained AppImage. Logs to ~/adaptix_client_build.log

set -e
exec > >(tee /home/admin/adaptix_client_build.log) 2>&1

echo "===== Adaptix Client Build Started $(date) ====="
echo "[*] Estimated time: 10-20 minutes (Docker pulls a Qt6 build image)"

if ! docker info >/dev/null 2>&1; then
    echo "[!] Docker is not available to this user. Try: sudo systemctl start docker"
    echo "    or re-log so the 'docker' group membership applies, then re-run."
    exit 1
fi

cd /opt/AdaptixC2
make docker-build-client

CLIENT=$(ls /opt/AdaptixC2/dist/*.AppImage 2>/dev/null | head -1)
if [ -z "$CLIENT" ]; then
    echo "[!] No AppImage found in /opt/AdaptixC2/dist after build — check the log above"
    exit 1
fi
echo "[+] Client built: $CLIENT"

# Extract instead of FUSE-mounting so it runs on a minimal desktop
rm -rf /opt/AdaptixC2/client-appimage
mkdir -p /opt/AdaptixC2/client-appimage
cd /opt/AdaptixC2/client-appimage
"$CLIENT" --appimage-extract >/dev/null
chown -R admin:admin /opt/AdaptixC2/client-appimage

sudo tee /usr/local/bin/adaptix-client > /dev/null << 'WRAPPER'
#!/bin/bash
exec /opt/AdaptixC2/client-appimage/squashfs-root/AppRun "$@"
WRAPPER
sudo chmod +x /usr/local/bin/adaptix-client

echo ""
echo "===== Adaptix Client Build Complete $(date) ====="
echo "  Launch:  adaptix-client   (or reconnect the VNC desktop — it autostarts)"
echo "  Connect: host adaptix (or localhost), port 4321, endpoint /adaptix"
echo "  See ~/adaptix_quickstart.txt for the listener values"
BUILDSCRIPT
chmod +x /home/admin/build_adaptix_client.sh

# ── Operator quickstart (bakes the real callback/URI/header values) ──────────
cat > /home/admin/adaptix_quickstart.txt << QUICKSTART
===== AdaptixC2 Quick Start =====

The teamserver runs as a systemd service and starts on boot:
  sudo systemctl status adaptix
If the server build failed at deploy, run once:
  ~/build_adaptix_server.sh

1. Build the GUI client (one time, ~10-20 min):
     ~/build_adaptix_client.sh
   Then launch it (or reconnect VNC via Guacamole — it autostarts):
     adaptix-client

2. Connect the client to the teamserver:
     Host:      adaptix        (or localhost)
     Port:      4321
     Endpoint:  /adaptix
     Username:  (any nickname)
     Password:  $SSH_PASSWORD

3. Create the HTTP beacon listener (Listeners > Add, BeaconHTTP).
   These values put it behind the redirector on the HTTPS/443 re-encrypt path
   and make beacons call back to the redirector public EIP:

     Bind host:port:      0.0.0.0 : 443
     Use SSL:             yes  (self-signed is fine; the redirector uses
                               SSLProxyVerify none)
     Callback addresses:  $REDIRECTOR_PUBLIC_IP : 443
     URI:                 $ADAPTIX_URI_PREFIX
     Request header:      $C2_HEADER_NAME: $C2_HEADER_VALUE
     Trust X-Forwarded-For: yes  (listener sits behind the redirector)

   The redirector gates inbound beacon traffic on that header + URI, then
   re-encrypts to this listener on 443. Without the header it serves the decoy.

4. Generate a beacon (Agents > Generate) against the listener above and drop
   it on the target. Callbacks appear as beacons in the client.
QUICKSTART
chmod 644 /home/admin/adaptix_quickstart.txt

# MOTD — operators see this on first SSH login
cat > /etc/motd << 'MOTD'
╔═══════════════════════════════════════════════════╗
║        AdaptixC2 — Teamserver auto-starts         ║
╠═══════════════════════════════════════════════════╣
║  Build the GUI client (~10-20 min):               ║
║      ~/build_adaptix_client.sh                    ║
║                                                   ║
║  Server build failed? retry with:                 ║
║      ~/build_adaptix_server.sh                    ║
║                                                   ║
║  Connect + listener values:                       ║
║      ~/adaptix_quickstart.txt                     ║
╚═══════════════════════════════════════════════════╝
MOTD

# Set ownership on everything in admin home
chown -R admin:admin /home/admin

# Enable and start services
systemctl daemon-reload
systemctl enable adaptix.service
if [ "$ADAPTIX_BUILT" = "1" ]; then
    systemctl start adaptix.service || echo "[!] adaptix teamserver start failed — check 'journalctl -u adaptix'"
else
    echo "[!] adaptix teamserver not started (build pending) — run ~/build_adaptix_server.sh"
fi
systemctl enable vncserver@1.service
systemctl start vncserver@1.service || echo "[!] VNC start failed — run 'sudo systemctl start vncserver@1' manually after boot"

echo ""
echo "===== AdaptixC2 Server Setup Completed $(date) ====="
echo "[+] SSH available with password auth from VPC"
echo "[+] Teamserver on 4321 (operator client), listeners bind 80/443"
echo "[+] VNC desktop on port 5901"
echo "[+] Client build: ~/build_adaptix_client.sh (10-20 min)"
