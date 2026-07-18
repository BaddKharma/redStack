#!/bin/bash
# adaptix_setup.sh - AdaptixC2 teamserver provisioning (headless)
# Builds and starts the AdaptixC2 teamserver (Go) pinned to a released tag.
# The operator GUI client runs on the Windows workstation, not on this box, so
# there is no desktop/VNC/Docker here. The BeaconHTTP listener defaults are
# preset for redStack (callback EIP, URI prefix, validation header) by patching
# the listener extender's AxScript after the build.
#
# cloud-init runs user-data with no HOME, so HOME/GOPATH/GOCACHE are set before
# any go/make call. The build is non-fatal: a failure must not strand the box,
# ~/build_adaptix_server.sh retries it with a proper environment.

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
ADAPTIX_VERSION="${adaptix_version}"
export SSH_PASSWORD

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
# Windows beacon). No desktop/Docker — the operator client lives on Windows.
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
    openssl

# Configure UFW firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow from $REDIRECTOR_VPC_CIDR to any port 80 proto tcp comment 'HTTP C2 from redirector'
ufw allow from $REDIRECTOR_VPC_CIDR to any port 443 proto tcp comment 'HTTPS C2 from redirector'
ufw allow 4321/tcp comment 'Adaptix teamserver (operator client)'
ufw --force enable

# Swap — the Go build and beacon payload generation can spike RAM; without swap
# a t3.small can OOM mid-build (same rationale as the Sliver box).
if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "[+] 2GB swap enabled"
fi

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

# ── Clone + pin + build AdaptixC2 server + extenders (NON-FATAL) ──────────────
# Pinned to a released tag so the lab is reproducible and does not drift with
# upstream main. A build failure won't abort provisioning; retry with the
# dropped ~/build_adaptix_server.sh.
ADAPTIX_BUILT=0
set +e
if [ ! -d /opt/AdaptixC2/.git ]; then
    echo "[*] Cloning AdaptixC2..."
    git clone https://github.com/Adaptix-Framework/AdaptixC2.git /opt/AdaptixC2
fi
echo "[*] Checking out $ADAPTIX_VERSION..."
git -C /opt/AdaptixC2 checkout "$ADAPTIX_VERSION" 2>&1 || echo "[!] checkout $ADAPTIX_VERSION failed — staying on default branch"
echo "[*] Building AdaptixC2 server + extenders (make server-ext)..."
( cd /opt/AdaptixC2 && make server-ext )
if [ -f /opt/AdaptixC2/dist/adaptixserver ]; then
    ADAPTIX_BUILT=1
    echo "[+] AdaptixC2 server built ($ADAPTIX_VERSION)"
else
    echo "[!] AdaptixC2 server build FAILED — run ~/build_adaptix_server.sh to retry"
fi
set -e

# ── Teamserver cert + profile + preset listener (only if the build succeeded) ─
if [ "$ADAPTIX_BUILT" = "1" ]; then
    cd /opt/AdaptixC2/dist
    if [ ! -f server.rsa.key ] || [ ! -f server.rsa.crt ]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout server.rsa.key -out server.rsa.crt -days 3650 -subj "/CN=adaptix"
    fi
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
    # Preset the BeaconHTTP listener form defaults for redStack (callback EIP,
    # URI prefix, validation header, SSL on, trust XFF). Operators just click
    # Create.
    AXF=/opt/AdaptixC2/dist/extenders/beacon_listener_http/ax_config.axs
    if [ -f "$AXF" ]; then
        sed -i 's|textCallback.addItem("address:port");|textCallback.addItem("${redirector_public_ip}:443");|' "$AXF"
        sed -i 's|textUri.addItems(\["/api/v1/status", "/updates/check.php", "/content.html"\]);|textUri.addItems(["${adaptix_uri_prefix}/api/v1/status", "${adaptix_uri_prefix}/updates/check", "${adaptix_uri_prefix}/content"]);|' "$AXF"
        sed -i 's|ssl_group.setChecked(false);|ssl_group.setChecked(true);|' "$AXF"
        sed -i 's|let textRequestHeaders = form.create_textmulti();|let textRequestHeaders = form.create_textmulti("${c2_header_name}: ${c2_header_value}");|' "$AXF"
        sed -i 's|let checkTrust = form.create_check("Trust X-Forwarded-For");|let checkTrust = form.create_check("Trust X-Forwarded-For");\n    checkTrust.setChecked(true);|' "$AXF"
        echo "[+] BeaconHTTP listener defaults preset for redStack"
    fi
fi
chown -R admin:admin /opt/AdaptixC2 2>/dev/null || true

# ── Systemd service: AdaptixC2 teamserver ────────────────────────────────────
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

# ── Manual server (re)build+start script, with a proper HOME/GOPATH ──────────
cat > /home/admin/build_adaptix_server.sh << 'SRVBUILD'
#!/bin/bash
# build_adaptix_server.sh - (re)build the pinned AdaptixC2 teamserver and start it.
set -e
export HOME=/root
export GOPATH=/root/go
export GOCACHE=/root/.cache/go-build
export PATH=$PATH:/usr/local/go/bin
sudo mkdir -p /root/go /root/.cache/go-build
sudo -E env HOME=/root GOPATH=/root/go GOCACHE=/root/.cache/go-build PATH="$PATH" \
    bash -c 'cd /opt/AdaptixC2 && git checkout ${adaptix_version} 2>/dev/null; make server-ext'
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
AXF=/opt/AdaptixC2/dist/extenders/beacon_listener_http/ax_config.axs
if [ -f "$AXF" ]; then
    sudo sed -i 's|textCallback.addItem("address:port");|textCallback.addItem("${redirector_public_ip}:443");|' "$AXF"
    sudo sed -i 's|textUri.addItems(\["/api/v1/status", "/updates/check.php", "/content.html"\]);|textUri.addItems(["${adaptix_uri_prefix}/api/v1/status", "${adaptix_uri_prefix}/updates/check", "${adaptix_uri_prefix}/content"]);|' "$AXF"
    sudo sed -i 's|ssl_group.setChecked(false);|ssl_group.setChecked(true);|' "$AXF"
    sudo sed -i 's|let textRequestHeaders = form.create_textmulti();|let textRequestHeaders = form.create_textmulti("${c2_header_name}: ${c2_header_value}");|' "$AXF"
fi
sudo chown -R admin:admin /opt/AdaptixC2
sudo systemctl daemon-reload
sudo systemctl enable adaptix.service
sudo systemctl restart adaptix.service
echo "[+] Teamserver (re)started — sudo systemctl status adaptix"
SRVBUILD
chmod +x /home/admin/build_adaptix_server.sh

# ── Operator quickstart (headless; client is on the Windows box) ─────────────
cat > /home/admin/adaptix_quickstart.txt << QUICKSTART
===== AdaptixC2 (redStack) — headless teamserver =====

The operator GUI client runs on the WINDOWS workstation
(C:\Tools\AdaptixClient\AdaptixClient.exe, desktop shortcut), reached via
Guacamole > Windows (RDP). Nothing to run on this box.

Teamserver:
  sudo systemctl status adaptix
  Connect URL:  https://adaptix:4321/adaptix
  User:         (any nickname)
  Password:     $SSH_PASSWORD

BeaconHTTP listener (defaults are preset for redStack — just click Create):
  Bind:        0.0.0.0:443, SSL on
  Callback:    $REDIRECTOR_PUBLIC_IP:443   (redirector public EIP)
  URI prefix:  $ADAPTIX_URI_PREFIX
  Request hdr: $C2_HEADER_NAME: $C2_HEADER_VALUE
  Trust X-Forwarded-For: on

If the server build failed at deploy, run once: ~/build_adaptix_server.sh
QUICKSTART
chmod 644 /home/admin/adaptix_quickstart.txt

# MOTD — operators see this on first SSH login
cat > /etc/motd << 'MOTD'
╔═══════════════════════════════════════════════════╗
║   AdaptixC2 teamserver (headless) — auto-starts   ║
╠═══════════════════════════════════════════════════╣
║  Operator client runs on the Windows workstation  ║
║  (Guacamole > Windows RDP > AdaptixClient).        ║
║                                                   ║
║  Status:   sudo systemctl status adaptix          ║
║  Rebuild:  ~/build_adaptix_server.sh              ║
║  Details:  ~/adaptix_quickstart.txt               ║
╚═══════════════════════════════════════════════════╝
MOTD

# Set ownership on everything in admin home
chown -R admin:admin /home/admin

# Enable and start the teamserver
systemctl daemon-reload
systemctl enable adaptix.service
if [ "$ADAPTIX_BUILT" = "1" ]; then
    systemctl start adaptix.service || echo "[!] adaptix teamserver start failed — check 'journalctl -u adaptix'"
else
    echo "[!] adaptix teamserver not started (build pending) — run ~/build_adaptix_server.sh"
fi

echo ""
echo "===== AdaptixC2 Server Setup Completed $(date) ====="
echo "[+] Headless teamserver on 4321 (operator client), listeners bind 80/443"
echo "[+] Operator GUI client: Windows workstation (C:\\Tools\\AdaptixClient)"
