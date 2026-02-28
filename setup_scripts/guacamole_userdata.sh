#!/bin/bash
# guacamole_userdata.sh - Bootstrap user data for Guacamole server

set -e

# Logging
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "===== Guacamole Bootstrap Started $(date) ====="

# Variables from Terraform template
SSH_PASSWORD="${ssh_password}"

# Set hostname
echo "[*] Setting hostname..."
hostnamectl set-hostname guac

# Configure /etc/hosts for lab machines
echo "[*] Configuring /etc/hosts..."
cat >> /etc/hosts << HOSTS

# redStack lab hosts
${guacamole_private_ip}  guac
${mythic_private_ip}     mythic
${sliver_private_ip}     sliver
${havoc_private_ip}      havoc
${redirector_private_ip} redirector
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

# Allow password auth from localhost, Docker bridge networks, and private VPCs
Match Address 127.0.0.1,::1,172.16.0.0/12,10.0.0.0/8
    PasswordAuthentication yes
SSHCONF

systemctl restart sshd

# Decode and run the setup script
echo "[*] Extracting setup script..."
echo "${setup_script_b64}" | base64 -d | gunzip > /root/guacamole_setup.sh
chmod +x /root/guacamole_setup.sh

echo "[*] Running Guacamole setup..."
bash /root/guacamole_setup.sh

echo "===== Guacamole Bootstrap Complete $(date) ====="
