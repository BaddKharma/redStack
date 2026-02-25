#!/bin/bash
# havoc_setup.sh - Havoc C2 server initial provisioning
# Configures OS, SSH, firewall, VNC desktop, and drops build_havoc.sh
# for manual execution after boot.

set -e

exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "===== Havoc C2 Server Setup Started $(date) ====="

SSH_PASSWORD="${ssh_password}"
REDIRECTOR_VPC_CIDR="${redirector_vpc_cidr}"

# Set hostname
echo "[*] Setting hostname..."
hostnamectl set-hostname havoc

# Configure /etc/hosts for lab machines
echo "[*] Configuring /etc/hosts..."
cat >> /etc/hosts << HOSTS

# redStack lab hosts
${havoc_private_ip}      havoc
${guacamole_private_ip}  guac
${mythic_private_ip}     mythic
${sliver_private_ip}     sliver
${redirector_private_ip} redirector
${windows_private_ip}    win-operator
HOSTS

# ── SSH first — ensures recovery access even if later steps fail ─────────────
echo "[*] Configuring SSH authentication..."
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
echo "[*] Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install all build deps and runtime deps up front so build_havoc.sh
# does not need apt access and can focus solely on the build steps.
echo "[*] Installing packages (build deps, Qt5, XFCE4, TigerVNC)..."
apt-get install -y \
    git \
    build-essential \
    cmake \
    nasm \
    mingw-w64 \
    curl \
    wget \
    ufw \
    net-tools \
    jq \
    python3 \
    python3-pip \
    python3-dev \
    libssl-dev \
    xfce4 \
    xfce4-terminal \
    tigervnc-standalone-server \
    dbus-x11 \
    libqt5websockets5 \
    libqt5websockets5-dev \
    qtbase5-dev \
    qtchooser \
    qt5-qmake \
    qtbase5-dev-tools \
    qtdeclarative5-dev \
    libqt5svg5-dev \
    libfontconfig1-dev \
    libglu1-mesa-dev \
    libgtest-dev \
    libspdlog-dev \
    libboost-all-dev

# Configure UFW firewall
echo "[*] Configuring firewall rules..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow from $REDIRECTOR_VPC_CIDR to any port 80 proto tcp comment 'HTTP C2 from redirector'
ufw allow from $REDIRECTOR_VPC_CIDR to any port 443 proto tcp comment 'HTTPS C2 from redirector'
ufw allow 40056/tcp comment 'Havoc teamserver'
ufw allow from 10.0.0.0/8 to any port 5901 proto tcp comment 'VNC from internal VPC'
ufw --force enable

# Create Havoc profile (contains SSH_PASSWORD — must be templated here)
# build_havoc.sh copies this into /opt/Havoc/profiles/ after cloning.
echo "[*] Creating Havoc profile template..."
mkdir -p /home/admin/.havoc
cat > /home/admin/.havoc/default.yaotl << PROFILE
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm       = "/usr/bin/nasm"
    }
}

Demon {
    Sleep    = 2
    Jitter   = 0
    TrustXForwardedFor = false
}

Operators {
    user "operator" {
        Password = "$SSH_PASSWORD"
    }
}
PROFILE

# TigerVNC desktop setup
echo "[*] Configuring TigerVNC desktop..."
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

# Autostart Havoc client when the XFCE session begins
# (will fail silently until build_havoc.sh has been run)
mkdir -p /home/admin/.config/autostart
cat > /home/admin/.config/autostart/havoc-client.desktop << 'AUTOSTART'
[Desktop Entry]
Type=Application
Name=Havoc C2 Client
Exec=havoc-client client
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
AUTOSTART

mkdir -p /home/admin/Desktop
cat > /home/admin/Desktop/Havoc-Client.desktop << 'DESKICON'
[Desktop Entry]
Type=Application
Name=Havoc C2 Client
Comment=Connect to Havoc Teamserver
Exec=havoc-client client
Icon=utilities-terminal
Terminal=false
Categories=Network;
DESKICON
chmod +x /home/admin/Desktop/Havoc-Client.desktop

# Systemd service: Havoc teamserver
cat > /etc/systemd/system/havoc.service << 'SVCEOF'
[Unit]
Description=Havoc C2 Teamserver
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/Havoc
ExecStart=/opt/Havoc/teamserver/teamserver server --profile /opt/Havoc/profiles/default.yaotl
User=admin
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

# Systemd service: TigerVNC (template unit)
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

# Drop the build script into admin's home directory.
# Operators run this manually after connecting via SSH or VNC terminal.
cat > /home/admin/build_havoc.sh << 'BUILDSCRIPT'
#!/bin/bash
# build_havoc.sh - Build and install Havoc C2 framework
# Run manually after initial boot: ~/build_havoc.sh
# Logs output to ~/havoc_build.log

set -e
exec > >(tee /home/admin/havoc_build.log) 2>&1

echo "===== Havoc Build Started $(date) ====="
echo "[*] Estimated time: 15-25 minutes"
echo ""

# ── Go installation ──────────────────────────────────────────────────────────
GO_VERSION="1.22.5"
if /usr/local/go/bin/go version 2>/dev/null | grep -q "$GO_VERSION"; then
    echo "[*] Go $GO_VERSION already installed, skipping"
else
    echo "[*] Installing Go $GO_VERSION..."
    wget -q "https://go.dev/dl/go$${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    echo "[+] Go installed"
fi

export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
go version

# ── Clone Havoc ──────────────────────────────────────────────────────────────
if [ -d "/opt/Havoc/.git" ]; then
    echo "[*] /opt/Havoc already cloned, skipping"
else
    echo "[*] Fetching latest Havoc release tag..."
    HAVOC_TAG=$(curl -sL https://api.github.com/repos/HavocFramework/Havoc/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    if [ -z "$HAVOC_TAG" ]; then
        echo "[!] Could not fetch latest tag, using main"
        HAVOC_TAG="main"
    fi
    echo "[+] Cloning Havoc $HAVOC_TAG..."
    sudo git clone --branch "$HAVOC_TAG" https://github.com/HavocFramework/Havoc.git /opt/Havoc
    sudo chown -R admin:admin /opt/Havoc
fi

# Copy profile and create data directory
sudo mkdir -p /opt/Havoc/profiles /opt/Havoc/teamserver/data
sudo cp /home/admin/.havoc/default.yaotl /opt/Havoc/profiles/default.yaotl
sudo chown -R admin:admin /opt/Havoc

# ── Build teamserver ─────────────────────────────────────────────────────────
echo "[*] Building Havoc teamserver..."
cd /opt/Havoc/teamserver
/usr/local/go/bin/go build -buildvcs=false -o teamserver .
sudo setcap 'cap_net_bind_service=+ep' /opt/Havoc/teamserver/teamserver
echo "[+] Teamserver built"

# ── Build client (Qt5) ───────────────────────────────────────────────────────
echo "[*] Building Havoc client (Qt5 — this takes a while)..."
cd /opt/Havoc
git submodule update --init --recursive
mkdir -p client/Build
cd client/Build
cmake ..
cmake --build /opt/Havoc/client/Build -- -j$(nproc)
echo "[+] Client built"

# ── Wrapper script ───────────────────────────────────────────────────────────
sudo tee /usr/local/bin/havoc-client > /dev/null << 'WRAPPER'
#!/bin/bash
cd /opt/Havoc
exec /opt/Havoc/client/Havoc "$@"
WRAPPER
sudo chmod +x /usr/local/bin/havoc-client

# ── Final ownership and service start ────────────────────────────────────────
sudo chown -R admin:admin /opt/Havoc

echo "[*] Starting Havoc teamserver..."
sudo systemctl daemon-reload
sudo systemctl enable havoc.service
sudo systemctl start havoc.service

echo ""
echo "===== Havoc Build Complete $(date) ====="
echo ""
echo "  Teamserver:   sudo systemctl status havoc"
echo "  Profile:      /opt/Havoc/profiles/default.yaotl"
echo "  Client:       havoc-client client"
echo "  VNC:          Reconnect via Guacamole — client autostarts on desktop"
echo ""
echo "  To connect the Havoc client:"
echo "    Host:     localhost    Port: 40056"
echo "    User:     operator     Pass: (see /opt/Havoc/profiles/default.yaotl)"
BUILDSCRIPT
chmod +x /home/admin/build_havoc.sh

# MOTD — operators see this on first SSH login
cat > /etc/motd << 'MOTD'
╔═══════════════════════════════════════════════════╗
║           Havoc C2 — Build Required               ║
╠═══════════════════════════════════════════════════╣
║  Run to build Havoc (~15-25 min):                 ║
║                                                   ║
║      ~/build_havoc.sh                             ║
║                                                   ║
║  Log: ~/havoc_build.log                           ║
╚═══════════════════════════════════════════════════╝
MOTD

# Set ownership on everything in admin home
chown -R admin:admin /home/admin

# Enable and start services
systemctl daemon-reload
systemctl enable havoc.service
systemctl enable vncserver@1.service
systemctl start vncserver@1.service || echo "[!] VNC start failed — run 'sudo systemctl start vncserver@1' manually after boot"

echo ""
echo "===== Havoc C2 Server Setup Completed $(date) ====="
echo "[+] SSH available with password auth from VPC"
echo "[+] VNC desktop running on port 5901"
echo "[+] Run ~/build_havoc.sh to build Havoc (15-25 min)"
