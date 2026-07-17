#!/bin/bash
# redirector_userdata.sh - Bootstrap user data for Apache redirector instance

set -e

# Logging
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "===== Redirector Bootstrap Started $(date) ====="

# Variables from Terraform template
SSH_PASSWORD="${ssh_password}"

# Set hostname
hostnamectl set-hostname redirector

# Configure /etc/hosts for lab machines
cat >> /etc/hosts << HOSTS

# redStack lab hosts
${redirector_private_ip} redirector
${guacamole_private_ip}  guac
${mythic_private_ip}     mythic
${sliver_private_ip}     sliver
${adaptix_private_ip}      adaptix
${windows_private_ip}    windows
${kali_private_ip}       kali
HOSTS

# Set SSH password for Guacamole access
echo "admin:$SSH_PASSWORD" | chpasswd
mkdir -p /home/admin
chown admin:admin /home/admin
usermod -d /home/admin -s /bin/bash admin

cat >> /etc/ssh/sshd_config << 'SSHCONF'

# Default: require SSH keys
PasswordAuthentication no
PubkeyAuthentication yes

# Allow password auth only from private networks (for Guacamole access via VPC)
Match Address 172.16.0.0/12,10.0.0.0/8
    PasswordAuthentication yes

# Enable opt-in remote port forwarding for Kali callback workflows.
# 'clientspecified' means an operator must explicitly request a non-localhost
# bind via `ssh -R *:port:host:port` or `ssh -R bind:port:host:port`.
# Without this, all `ssh -R` listeners would silently bind to 127.0.0.1
# and be unreachable by external CTF targets through tun0.
GatewayPorts clientspecified
SSHCONF

systemctl restart sshd

# Decode and run the setup script
echo "${setup_script_b64}" | base64 -d | gunzip > /root/redirector_setup.sh
chmod +x /root/redirector_setup.sh
bash /root/redirector_setup.sh

echo "===== Redirector Bootstrap Complete $(date) ====="
