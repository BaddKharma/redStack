#!/bin/bash
# havoc_setup.sh - Havoc C2 server installation
# Runs automatically via user_data on first boot

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

# Update system
echo "[*] Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install build dependencies
echo "[*] Installing build dependencies..."
apt-get install -y \
    git \
    build-essential \
    cmake \
    nasm \
    mingw-w64 \
    curl \
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

# Configure SSH password authentication for Guacamole access
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

# Install Go (Havoc requires Go 1.21+)
echo "[*] Installing Go..."
GO_VERSION="1.22.5"
wget -q "https://go.dev/dl/go$${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
rm /tmp/go.tar.gz

# Set Go environment for all users
cat > /etc/profile.d/golang.sh << 'GOENV'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
GOENV
chmod +x /etc/profile.d/golang.sh
export PATH=$PATH:/usr/local/go/bin

# Verify Go installation
go version

# Clone Havoc C2 framework at latest release tag
echo "[*] Fetching latest Havoc release tag..."
HAVOC_TAG=$(curl -sL https://api.github.com/repos/HavocFramework/Havoc/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$HAVOC_TAG" ]; then
    echo "[!] Could not fetch latest tag, falling back to main"
    HAVOC_TAG="main"
fi
echo "[+] Using Havoc release: $HAVOC_TAG"
git clone --branch "$HAVOC_TAG" https://github.com/HavocFramework/Havoc.git /opt/Havoc
echo "$HAVOC_TAG" > /opt/Havoc/.release_tag
chown -R admin:admin /opt/Havoc

# Build Havoc teamserver
echo "[*] Building Havoc teamserver (this may take several minutes)..."
cd /opt/Havoc/teamserver
export HOME=/root
export GOPATH=/root/go
sudo -E /usr/local/go/bin/go build -buildvcs=false -o teamserver . 2>&1 || {
    echo "[!] Teamserver build failed, attempting alternative build..."
    cd /opt/Havoc
    make teamserver 2>&1 || echo "[!] Build failed - may need manual build"
}
# Allow teamserver to bind privileged ports (80/443) as non-root user
setcap 'cap_net_bind_service=+ep' /opt/Havoc/teamserver/teamserver

# Build Havoc client (Qt5 GUI)
echo "[*] Building Havoc client (this may take several minutes)..."
cd /opt/Havoc
git submodule update --init --recursive
mkdir -p client/Build
cd client/Build && cmake .. 2>&1
cmake --build /opt/Havoc/client/Build -- -j 4 2>&1 && echo "[+] Havoc client built successfully" || \
    echo "[!] Client build failed - may need manual build"

# Create havoc-client wrapper script (cd to /opt/Havoc required for client config)
if [ -f "/opt/Havoc/client/Havoc" ]; then
    cat > /usr/local/bin/havoc-client << 'WRAPPER'
#!/bin/bash
cd /opt/Havoc
exec /opt/Havoc/client/Havoc "$@"
WRAPPER
    chmod +x /usr/local/bin/havoc-client
    echo "[+] Havoc client wrapper created at /usr/local/bin/havoc-client"
else
    echo "[!] Havoc client binary not found at /opt/Havoc/client/Havoc"
fi

# Create default Havoc profile
echo "[*] Creating default Havoc profile..."
mkdir -p /opt/Havoc/profiles
cat > /opt/Havoc/profiles/default.yaotl << PROFILE
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
chown -R admin:admin /opt/Havoc

# Create data directory required by teamserver (stores SQLite DB)
mkdir -p /opt/Havoc/teamserver/data
chown admin:admin /opt/Havoc/teamserver/data

# Set up TigerVNC desktop for Havoc client access
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

# Desktop shortcut for manual re-launch
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

chown -R admin:admin /home/admin/.vnc /home/admin/.config /home/admin/Desktop

# Create systemd service for Havoc teamserver
echo "[*] Creating Havoc systemd service..."
cat > /etc/systemd/system/havoc.service << 'SVCEOF'
[Unit]
Description=Havoc C2 Teamserver
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/Havoc/teamserver
ExecStart=/opt/Havoc/teamserver/teamserver server --profile /opt/Havoc/profiles/default.yaotl
User=admin
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable havoc.service

# Create systemd service for TigerVNC (template unit)
echo "[*] Creating TigerVNC systemd service..."
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

systemctl daemon-reload
systemctl enable vncserver@1.service

# Create quick-start helper script
cat > /root/havoc_quickstart.sh << QUICKSTART
#!/bin/bash
echo "===== Havoc C2 Quick Start ====="
echo ""
echo "Access the Havoc GUI:"
echo "  1. Open Guacamole in your browser"
echo "  2. Connect to: Havoc C2 Desktop (VNC)"
echo "  3. The Havoc client launches automatically on the desktop"
echo ""
echo "Havoc client connection details (enter in the GUI dialog):"
echo "  Host:     localhost"
echo "  Port:     40056"
echo "  Username: operator"
echo "  Password: $SSH_PASSWORD"
echo ""
echo "Teamserver status:"
systemctl status havoc --no-pager 2>/dev/null || echo "Havoc service not active"
echo ""
echo "VNC status:"
systemctl status vncserver@1 --no-pager 2>/dev/null || echo "VNC service not active"
echo ""
echo "Default profile: /opt/Havoc/profiles/default.yaotl"
QUICKSTART
chmod +x /root/havoc_quickstart.sh

echo "===== Havoc C2 Server Setup Completed $(date) ====="
echo "===== Run /root/havoc_quickstart.sh for usage instructions ====="
