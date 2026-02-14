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
    python3-pip

# Configure SSH password authentication for Guacamole access
echo "[*] Configuring SSH authentication..."
echo "admin:$SSH_PASSWORD" | chpasswd

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

# Clone Havoc C2 framework
echo "[*] Cloning Havoc C2 framework..."
git clone https://github.com/HavocFramework/Havoc.git /opt/Havoc
chown -R admin:admin /opt/Havoc

# Build Havoc teamserver
echo "[*] Building Havoc teamserver (this may take several minutes)..."
cd /opt/Havoc/teamserver
export HOME=/root
export GOPATH=/root/go
sudo -E /usr/local/go/bin/go build -o teamserver . 2>&1 || {
    echo "[!] Teamserver build failed, attempting alternative build..."
    cd /opt/Havoc
    make teamserver 2>&1 || echo "[!] Build failed - may need manual build"
}

# Create default Havoc profile
echo "[*] Creating default Havoc profile..."
mkdir -p /opt/Havoc/profiles
cat > /opt/Havoc/profiles/default.yaotl << 'PROFILE'
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm       = "/usr/bin/nasm"
    }
}

Operators {
    user "operator" {
        Password = "Training123!"
    }
}

Listeners {
    Http {
        Name         = "HTTP Listener"
        Hosts        = ["0.0.0.0"]
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        PortBind     = 80
        Secure       = false
        UserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
}
PROFILE
chown -R admin:admin /opt/Havoc

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

# Create quick-start helper script
cat > /root/havoc_quickstart.sh << 'QUICKSTART'
#!/bin/bash
echo "===== Havoc C2 Quick Start ====="
echo ""
echo "1. Start the Havoc teamserver:"
echo "   sudo systemctl start havoc"
echo "   OR manually:"
echo "   cd /opt/Havoc/teamserver && ./teamserver server --profile /opt/Havoc/profiles/default.yaotl"
echo ""
echo "2. Connect from Havoc client (on Windows workstation):"
echo "   - Teamserver IP: $(hostname -I | awk '{print $1}')"
echo "   - Port: 40056"
echo "   - Username: operator"
echo "   - Password: Training123!"
echo ""
echo "3. Configure HTTP listener through redirector:"
echo "   - The default profile already has an HTTP listener on port 80"
echo "   - Redirector forwards /api/ URI prefix -> this server port 80"
echo ""
echo "Current status:"
systemctl status havoc --no-pager 2>/dev/null || echo "Havoc service not active"
echo ""
echo "Default profile: /opt/Havoc/profiles/default.yaotl"
echo "Teamserver port: 40056"
QUICKSTART
chmod +x /root/havoc_quickstart.sh

echo "===== Havoc C2 Server Setup Completed $(date) ====="
echo "===== Run /root/havoc_quickstart.sh for usage instructions ====="
