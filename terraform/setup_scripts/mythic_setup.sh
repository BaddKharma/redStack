#!/bin/bash
# mythic_setup.sh - User data script for Mythic team server initialization

set -e

# Logging
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "===== Mythic Team Server Setup Started $(date) ====="

# Variables from Terraform template
LOCAL_PUB_IPS="${localPub_ip}"
ENABLE_AUTOSTART="${enable_autostart}"
SSH_PASSWORD="${ssh_password}"
VPC_CIDR="${vpc_cidr}"
REDIRECTOR_VPC_CIDR="${redirector_vpc_cidr}"
MYTHIC_ADMIN_PASSWORD="${mythic_admin_password}"

# Set hostname
hostnamectl set-hostname mythic

# Configure /etc/hosts for lab machines
cat >> /etc/hosts << HOSTS

# redStack lab hosts
${mythic_private_ip}     mythic
${guacamole_private_ip}  guac
${sliver_private_ip}     sliver
${adaptix_private_ip}      adaptix
${redirector_private_ip} redirector
${windows_private_ip}    windows
${kali_private_ip}       kali
HOSTS

# Update system
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install dependencies
apt-get install -y \
    docker.io \
    make \
    git \
    curl \
    ufw \
    jq \
    python3-pip

# Enable Docker
systemctl enable docker
systemctl start docker

# Add admin user to docker group
usermod -aG docker admin

# Configure SSH password authentication for Guacamole access only
# Public IP access still requires SSH keys, only VPC IPs can use passwords
echo "admin:$SSH_PASSWORD" | chpasswd
mkdir -p /home/admin
chown admin:admin /home/admin
usermod -d /home/admin -s /bin/bash admin

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
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Verify Docker Compose installation
docker compose version

# Configure UFW firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
for ip in $LOCAL_PUB_IPS; do
  ufw allow from $ip to any port 22 proto tcp comment 'SSH from instructor'
  ufw allow from $ip to any port 7443:7444 proto tcp comment 'Mythic UI from instructor'
done
ufw allow from $VPC_CIDR to any port 22 proto tcp comment 'SSH from Guacamole via VPC'
ufw allow from $VPC_CIDR to any port 7443:7444 proto tcp comment 'Mythic UI from Windows client'
ufw allow from $REDIRECTOR_VPC_CIDR to any port 80 proto tcp comment 'HTTP C2 from redirector'
ufw allow from $REDIRECTOR_VPC_CIDR to any port 443 proto tcp comment 'HTTPS C2 from redirector'
ufw --force enable

# Clone Mythic
cd /opt
git clone https://github.com/its-a-feature/Mythic
chown -R admin:admin Mythic
cd Mythic

# Install Mythic CLI
make

# Set admin password before first start so it's deterministic
./mythic-cli config set MYTHIC_ADMIN_PASSWORD "$MYTHIC_ADMIN_PASSWORD"

# Readiness helpers (poll instead of blind sleeps; the cold-boot nginx cert race
# and post-install 'Created' containers slip right through fixed sleeps).
wait_http() {
    # Wait until the web UI actually serves the login page (nginx crash-loops on
    # the self-signed cert until mythic_server writes it, then returns 200).
    # -f returns non-zero on HTTP >= 400, so a clean exit means the login page served.
    # (Avoids curl's -w write-out format, which Terraform templatefile would otherwise treat as a directive.)
    for _ in $(seq 1 60); do
        curl -skf -o /dev/null https://127.0.0.1:7443/new/login 2>/dev/null && return 0
        sleep 5
    done
    return 1
}

wait_running() {
    # Wait until the named container reports State=running.
    name="$1"
    for _ in $(seq 1 60); do
        state=$(docker inspect -f '{{.State.Status}}' "$name" 2>/dev/null || echo missing)
        [ "$state" = "running" ] && return 0
        sleep 5
    done
    return 1
}

# Start Mythic (first run generates configs)
echo "[*] Starting Mythic (this will take 3-5 minutes)..."
./mythic-cli start

# Wait for the web UI to actually serve before proceeding
echo "[*] Waiting for Mythic web UI on 7443..."
if wait_http; then
    echo "[+] Mythic web UI is serving on 7443"
else
    echo "[!] Mythic web UI did not return 200 in time; check 'mythic-cli logs mythic_nginx'"
fi

# Check status
./mythic-cli status

# Install default C2 profiles and agents
echo "[*] Installing HTTP C2 profile and Apollo agent..."
./mythic-cli install github https://github.com/MythicC2Profiles/http
./mythic-cli install github https://github.com/MythicAgents/apollo

# Serve the http C2 profile over TLS on 443 so the redirector re-encrypts to it
# (matches the redirector's https backend forward; the profile auto-generates a
#  self-signed cert on start). Applied before the restart below so it loads cleanly.
HTTP_C2_CONFIG=/opt/Mythic/InstalledServices/http/http/c2_code/config.json
if [ -f "$HTTP_C2_CONFIG" ]; then
    sed -i 's/"use_ssl": false/"use_ssl": true/; s/"port": 80/"port": 443/' "$HTTP_C2_CONFIG"
    echo "[+] http C2 profile configured for TLS on port 443"
else
    echo "[!] http C2 profile config not found at $HTTP_C2_CONFIG (SSL not enabled)"
fi

# Restart to apply new profiles
echo "[*] Restarting Mythic to load new components..."
./mythic-cli restart

# Newly installed services frequently land in 'Created' (image pulled, container
# never started). Start them explicitly, then verify each reaches 'running' with
# one retry, so the operator never has to hand-fix apollo/http at the podium.
echo "[*] Starting installed services (http, apollo)..."
./mythic-cli start http apollo || true

for svc in http apollo; do
    if wait_running "$svc"; then
        echo "[+] $svc is running"
    else
        echo "[!] $svc not running, retrying start once..."
        ./mythic-cli start "$svc" || true
        if wait_running "$svc"; then
            echo "[+] $svc is running after retry"
        else
            echo "[!] $svc STILL not running after retry; check 'mythic-cli logs $svc'"
        fi
    fi
done

# Confirm the web UI is still serving after the restart
wait_http && echo "[+] Mythic web UI serving after restart" || echo "[!] Mythic web UI not serving after restart"

./mythic-cli status

# Install mythic-py for CLI-based payload building
pip3 install mythic --break-system-packages

# Extract admin password for logs
MYTHIC_PASSWORD=$(grep MYTHIC_ADMIN_PASSWORD .env | cut -d'=' -f2)
echo "===== Mythic Admin Password: $MYTHIC_PASSWORD ====="

# Optional: Create systemd service for autostart
if [ "$ENABLE_AUTOSTART" = "true" ]; then
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
