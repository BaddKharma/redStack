#!/bin/bash
# redirector_userdata.sh - Bootstrap and full setup for Apache redirector
# Configures SSH access, then automatically runs the full Apache/redirector setup.

set -e
exec > >(tee /var/log/user-data.log)
exec 2>&1
echo "===== Apache Redirector Bootstrap Started $(date) ====="

SSH_PASSWORD="${ssh_password}"

# Set hostname
echo "[*] Setting hostname..."
hostnamectl set-hostname redirector

# Configure /etc/hosts for lab machines
echo "[*] Configuring /etc/hosts..."
cat >> /etc/hosts << HOSTS

# redStack lab hosts
${redirector_private_ip} redirector
${guacamole_private_ip}  guac
${mythic_private_ip}     mythic
${sliver_private_ip}     sliver
${havoc_private_ip}      havoc
${windows_private_ip}    win-attacker
HOSTS

# Update system
echo "[*] Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Configure SSH password authentication for Guacamole access only
# Public IP access still requires SSH keys, only VPC IPs can use passwords
echo "[*] Configuring SSH authentication (keys for public, passwords from VPC)..."
echo "admin:$SSH_PASSWORD" | chpasswd

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

# Write and execute the full redirector setup script
echo "[*] Writing setup script to /root/setup_redirector.sh..."
echo "${setup_script_b64}" | base64 -d | gunzip > /root/setup_redirector.sh
chmod +x /root/setup_redirector.sh

echo "[*] Executing full redirector setup..."
/root/setup_redirector.sh

echo "===== Redirector fully configured $(date) ====="
