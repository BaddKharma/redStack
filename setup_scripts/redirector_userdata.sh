#!/bin/bash
# redirector_userdata.sh - Minimal bootstrap for Apache redirector
# Only configures SSH access so Guacamole can connect.
# Run /root/setup_redirector.sh manually to complete Apache/redirector setup.

set -e
exec > >(tee /var/log/user-data.log)
exec 2>&1
echo "===== Apache Redirector Bootstrap Started $(date) ====="

SSH_PASSWORD="${ssh_password}"

# Update system
echo "[*] Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Configure SSH password authentication for Guacamole access only
# Public IP access still requires SSH keys, only VPC IPs can use passwords
echo "[*] Configuring SSH authentication (keys for public, passwords from VPC)..."
echo "ubuntu:$SSH_PASSWORD" | chpasswd

# Configure SSH: default requires keys, main VPC IPs can use passwords (via VPC peering)
cat >> /etc/ssh/sshd_config << 'SSHCONF'

# Default: require SSH keys
PasswordAuthentication no
PubkeyAuthentication yes

# Allow password auth from private networks (for Guacamole access via VPC peering)
Match Address 172.16.0.0/12,10.0.0.0/8
    PasswordAuthentication yes
SSHCONF

systemctl restart sshd

# Write the full redirector setup script for manual execution
echo "[*] Writing setup script to /root/setup_redirector.sh..."
echo "${setup_script_b64}" | base64 -d | gunzip > /root/setup_redirector.sh
chmod +x /root/setup_redirector.sh

echo "===== Bootstrap Complete $(date) ====="
echo "===== Run 'sudo /root/setup_redirector.sh' to complete redirector setup ====="
