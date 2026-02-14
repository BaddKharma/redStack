#!/bin/bash
# mythic_setup.sh - User data script for Mythic team server initialization

set -e

# Logging
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "===== Mythic Team Server Setup Started $(date) ====="

# Variables from Terraform template
LOCAL_PUB_IP="${localPub_ip}"
ENABLE_AUTOSTART="${enable_autostart}"
SSH_PASSWORD="${ssh_password}"
VPC_CIDR="${vpc_cidr}"
REDIRECTOR_VPC_CIDR="${redirector_vpc_cidr}"

# Set hostname
echo "[*] Setting hostname..."
hostnamectl set-hostname mythic

# Configure /etc/hosts for lab machines
echo "[*] Configuring /etc/hosts..."
cat >> /etc/hosts << HOSTS

# redStack lab hosts
${mythic_private_ip}     mythic
${guacamole_private_ip}  guac
${sliver_private_ip}     sliver
${havoc_private_ip}      havoc
${redirector_private_ip} redirector
${windows_private_ip}    win-operator
HOSTS

# Update system
echo "[*] Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install dependencies
echo "[*] Installing Docker and dependencies..."
apt-get install -y \
    docker.io \
    make \
    git \
    curl \
    ufw \
    jq

# Enable Docker
systemctl enable docker
systemctl start docker

# Add admin user to docker group
usermod -aG docker admin

# Configure SSH password authentication for Guacamole access only
# Public IP access still requires SSH keys, only VPC IPs can use passwords
echo "[*] Configuring SSH authentication (keys for public, passwords for VPC)..."
echo "admin:$SSH_PASSWORD" | chpasswd

# Configure SSH: default requires keys, VPC IPs can use passwords
cat >> /etc/ssh/sshd_config << 'SSHCONF'

# Default: require SSH keys
PasswordAuthentication no
PubkeyAuthentication yes

# Allow password auth only from private networks (for Guacamole access via VPC)
Match Address 172.16.0.0/12,10.0.0.0/8
    PasswordAuthentication yes
SSHCONF

systemctl restart sshd

# Install Docker Compose V2 manually (not available in Debian repos)
echo "[*] Installing Docker Compose V2..."
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Verify Docker Compose installation
docker compose version

# Configure UFW firewall
echo "[*] Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from $LOCAL_PUB_IP to any port 22 proto tcp comment 'SSH from instructor'
ufw allow from $LOCAL_PUB_IP to any port 7443:7444 proto tcp comment 'Mythic UI from instructor'
ufw allow from $VPC_CIDR to any port 22 proto tcp comment 'SSH from Guacamole via VPC'
ufw allow from $VPC_CIDR to any port 7443:7444 proto tcp comment 'Mythic UI from Windows client'
ufw allow from $REDIRECTOR_VPC_CIDR to any port 80 proto tcp comment 'HTTP C2 from redirector'
ufw allow from $REDIRECTOR_VPC_CIDR to any port 443 proto tcp comment 'HTTPS C2 from redirector'
ufw --force enable

# Clone Mythic
echo "[*] Cloning Mythic C2 framework..."
cd /opt
git clone https://github.com/its-a-feature/Mythic
chown -R admin:admin Mythic
cd Mythic

# Install Mythic CLI
echo "[*] Installing Mythic CLI..."
make

# Start Mythic (first run generates configs)
echo "[*] Starting Mythic (this will take 3-5 minutes)..."
sudo -u admin ./mythic-cli start

# Wait for Mythic to be fully operational
echo "[*] Waiting for Mythic initialization..."
sleep 180

# Check status
sudo -u admin ./mythic-cli status

# Install default C2 profiles and agents
echo "[*] Installing HTTP C2 profile and Apollo agent..."
sudo -u admin ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo -u admin ./mythic-cli install github https://github.com/MythicAgents/apollo

# Restart to apply new profiles
echo "[*] Restarting Mythic to load new components..."
sudo -u admin ./mythic-cli stop
sleep 10
sudo -u admin ./mythic-cli start
sleep 60

# Extract admin password for logs
MYTHIC_PASSWORD=$(grep MYTHIC_ADMIN_PASSWORD .env | cut -d'=' -f2)
echo "===== Mythic Admin Password: $MYTHIC_PASSWORD ====="

# Optional: Create systemd service for autostart
if [ "$ENABLE_AUTOSTART" = "true" ]; then
    echo "[*] Creating systemd service for Mythic autostart..."
    cat > /etc/systemd/system/mythic.service <<EOF
[Unit]
Description=Mythic C2 Framework
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/Mythic
ExecStart=/opt/Mythic/mythic-cli start
ExecStop=/opt/Mythic/mythic-cli stop
User=admin
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable mythic.service
fi

echo "===== Mythic Team Server Setup Completed $(date) ====="
echo "===== Access Mythic UI at https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):7443 ====="
