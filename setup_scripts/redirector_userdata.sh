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
${windows_private_ip}    win-operator
HOSTS

# Set SSH password for Guacamole access
echo "[*] Configuring SSH..."
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
SSHCONF

systemctl restart sshd

# Decode and run the setup script
echo "[*] Extracting setup script..."
echo "${setup_script_b64}" | base64 -d | gunzip > /root/redirector_setup.sh
chmod +x /root/redirector_setup.sh

echo "[*] Running redirector setup..."
bash /root/redirector_setup.sh

echo "===== Redirector Bootstrap Complete $(date) ====="
