#!/bin/bash
# kali_setup.sh - Kali Linux operator workstation provisioning
# Runs automatically via user_data on first boot.
#
# Behavior:
#   - Renames the AMI's default `kali` user to `admin` (matches other lab Linux boxes).
#   - Configures /etc/hosts, SSH password auth (private-CIDR only), UFW.
#   - Installs minimal packages only. The 21-tool curated lineup is installed
#     on demand via /usr/local/sbin/install-kali-tools.
#   - If kali_deployment_mode=gui: installs XFCE + XRDP at boot.
#   - If kali_deployment_mode=headless: ships /usr/local/sbin/kali-go-gui for
#     post-deploy GUI conversion without re-running terraform.

set -e
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "===== Kali Operator Setup Started $(date) ====="

SSH_PASSWORD="${ssh_password}"
KALI_MODE="${kali_deployment_mode}"

# ----------------------------------------------------------------------------
# 1. Rename the AMI's default `kali` user to `admin` (matches other lab boxes)
#    This is the FIRST action so the rename completes before any operator
#    can successfully SSH in. The AMI's pre-baked SSH key follows the home dir.
# ----------------------------------------------------------------------------
if id kali >/dev/null 2>&1; then
    # Rename login name and move home directory contents
    usermod -l admin -d /home/admin -m kali
    # Rename the primary group to match
    groupmod -n admin kali 2>/dev/null || true
    # Relocate cloud-init's per-user sudoers entry if present
    if [ -f /etc/sudoers.d/90-cloud-init-users ]; then
        sed -i 's/\bkali\b/admin/g' /etc/sudoers.d/90-cloud-init-users
    fi
    if [ -f /etc/sudoers.d/kali ]; then
        sed -i 's/\bkali\b/admin/g' /etc/sudoers.d/kali
        mv /etc/sudoers.d/kali /etc/sudoers.d/admin
    fi
else
    echo "[!] No 'kali' user found. AMI may have changed; admin user must be created manually."
fi

# ----------------------------------------------------------------------------
# 2. Hostname + /etc/hosts
# ----------------------------------------------------------------------------
hostnamectl set-hostname kali

# Disable cloud-init hosts management so lab hostname entries survive reboots
sed -i 's/manage_etc_hosts: true/manage_etc_hosts: false/' /etc/cloud/cloud.cfg
sed -i 's/manage_etc_hosts: true/manage_etc_hosts: false/' /etc/cloud/cloud.cfg.d/01_debian_cloud.cfg 2>/dev/null || true

cat >> /etc/hosts << HOSTS

# redStack lab hosts
${kali_private_ip}       kali
${guacamole_private_ip}  guac
${mythic_private_ip}     mythic
${sliver_private_ip}     sliver
${adaptix_private_ip}      adaptix
${redirector_private_ip} redirector
${windows_private_ip}    windows
HOSTS

# ----------------------------------------------------------------------------
# 3. apt update + minimal package install
#    No `apt upgrade` (Kali rolling churns and can break tools).
#    Heavy tooling is opt-in via /usr/local/sbin/install-kali-tools.
# ----------------------------------------------------------------------------
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl \
    wget \
    git \
    net-tools \
    ufw \
    jq \
    ca-certificates \
    openssh-server

# ----------------------------------------------------------------------------
# 4. SSH password auth for Guacamole access (private CIDRs only)
# ----------------------------------------------------------------------------
echo "admin:$SSH_PASSWORD" | chpasswd

cat >> /etc/ssh/sshd_config << 'SSHCONF'

# Default: require SSH keys
PasswordAuthentication no
PubkeyAuthentication yes

# Allow password auth from private networks (for Guacamole access via VPC)
Match Address 172.16.0.0/12,10.0.0.0/8
    PasswordAuthentication yes
SSHCONF

systemctl restart ssh

# ----------------------------------------------------------------------------
# 5. UFW firewall
# ----------------------------------------------------------------------------
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 3389/tcp comment 'XRDP (gated at SG; always open at OS so kali-go-gui works)'
ufw --force enable

# ----------------------------------------------------------------------------
# 6. install-kali-tools helper (curated 21-package AD/enum lineup)
#    Operator runs `sudo install-kali-tools` after first SSH login.
# ----------------------------------------------------------------------------
cat > /usr/local/sbin/install-kali-tools << 'TOOLSCRIPT'
#!/bin/bash
# install-kali-tools - One-shot installer for the redStack curated tool lineup.
#
# Twenty-two tools, weighted toward Active Directory enumeration and attack.
# Idempotent: safe to re-run. Does not use `set -e` so a single failure does
# not abort the rest.
#
# Install methods:
#   apt  (18): nmap, enum4linux-ng, smbmap, mitm6, ldap-utils, seclists,
#              gobuster, coercer, impacket-scripts, netexec, evil-winrm,
#              bloodhound.py, certipy-ad, responder, hashcat, john, pipx,
#              proxychains4
#   pipx  (1): adidnsdump
#   pipx+git(1): pre2k (not on PyPI — installed from github.com/garrettfoster13/pre2k)
#   binary(2): kerbrute, windapsearch  (GitHub release binaries)

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root (sudo install-kali-tools)" >&2
    exit 1
fi

PACKAGES=(
    nmap
    enum4linux-ng
    smbmap
    mitm6
    seclists
    gobuster
    coercer
    ldap-utils
    impacket-scripts
    netexec
    evil-winrm
    bloodhound.py
    certipy-ad
    responder
    hashcat
    john
    pipx
    proxychains4
)

echo "[*] redStack curated Kali tool installer"
echo "[*] Installing 22 tools: $${#PACKAGES[@]} via apt, 2 via pipx, 2 via GitHub binary."
echo ""

apt-get update

INSTALLED=()
FAILED=()

for pkg in "$${PACKAGES[@]}"; do
    echo "----- $pkg -----"
    if DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"; then
        INSTALLED+=("$pkg")
    else
        FAILED+=("$pkg")
    fi
done


# ---- Non-apt tools: pipx and GitHub binaries ----
echo ""
echo "===== Non-apt tools ====="

export PATH="$${PATH}:/root/.local/bin"

# adidnsdump is on PyPI
echo "----- adidnsdump (pipx) -----"
if pipx install --force adidnsdump > /dev/null 2>&1; then
    INSTALLED+=("adidnsdump")
else
    FAILED+=("adidnsdump")
fi

# pre2k is NOT on PyPI — install from GitHub
echo "----- pre2k (pipx from github) -----"
if pipx install --force "git+https://github.com/garrettfoster13/pre2k" > /dev/null 2>&1; then
    INSTALLED+=("pre2k")
else
    FAILED+=("pre2k")
fi

echo "----- kerbrute (github binary) -----"
KERBRUTE_URL=$(curl -sf https://api.github.com/repos/ropnop/kerbrute/releases/latest \
    | jq -r '.assets[] | select(.name == "kerbrute_linux_amd64") | .browser_download_url')
if [ -n "$${KERBRUTE_URL}" ] \
    && wget -q "$${KERBRUTE_URL}" -O /usr/local/bin/kerbrute \
    && chmod 755 /usr/local/bin/kerbrute; then
    INSTALLED+=("kerbrute")
    echo "    -> /usr/local/bin/kerbrute"
else
    FAILED+=("kerbrute")
fi

echo "----- windapsearch (github binary) -----"
WIND_URL=$(curl -sf https://api.github.com/repos/ropnop/go-windapsearch/releases/latest \
    | jq -r '.assets[] | select(.name == "windapsearch-linux-amd64") | .browser_download_url')
if [ -n "$${WIND_URL}" ] \
    && wget -q "$${WIND_URL}" -O /usr/local/bin/windapsearch \
    && chmod 755 /usr/local/bin/windapsearch; then
    INSTALLED+=("windapsearch")
    echo "    -> /usr/local/bin/windapsearch"
else
    FAILED+=("windapsearch")
fi

echo ""
echo "===== Install summary ====="
echo "Installed: $${#INSTALLED[@]} / 21"
if [ "$${#FAILED[@]}" -gt 0 ]; then
    echo "Failed:"
    for pkg in "$${FAILED[@]}"; do
        echo "  - $${pkg}"
    done
    echo ""
    echo "Re-run sudo install-kali-tools to retry failed items."
    exit 1
fi
echo "All 21 curated tools installed."
TOOLSCRIPT
chmod 755 /usr/local/sbin/install-kali-tools

# Run the installer now so tools are ready on first operator login.
echo "[*] Running install-kali-tools at setup (8-12 min)..."
/usr/local/sbin/install-kali-tools || true

# ----------------------------------------------------------------------------
# 7. kali-go-gui helper (post-deploy headless -> GUI conversion)
# ----------------------------------------------------------------------------
cat > /usr/local/sbin/kali-go-gui << 'GUISCRIPT'
#!/bin/bash
# kali-go-gui - Convert a headless Kali deployment to GUI without re-running terraform.
#
# Installs kali-desktop-xfce + xrdp, enables the service, and prints the
# Guacamole RDP connection details. SG already permits 3389 from Guacamole.

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root (sudo kali-go-gui)" >&2
    exit 1
fi

echo "[*] Installing XFCE desktop and XRDP. This takes about 4 minutes."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    kali-desktop-xfce \
    xrdp

echo "[*] Configuring XRDP to launch XFCE..."
# Rewrite startwm.sh to call startxfce4 directly — most reliable approach on Kali.
# The default startwm.sh calls /etc/X11/Xsession which has inconsistent .xsession handling.
cat > /etc/xrdp/startwm.sh << 'STARTWM'
#!/bin/sh
if test -r /etc/profile; then
    . /etc/profile
fi
if test -r ~/.profile; then
    . ~/.profile
fi
exec startxfce4
STARTWM
chmod +x /etc/xrdp/startwm.sh

echo "[*] Enabling xrdp service..."
systemctl enable xrdp
systemctl restart xrdp

# Update the MOTD banner so future logins reflect GUI mode
if [ -f /etc/update-motd.d/99-kali-mode ]; then
    sed -i 's/Current Mode:   HEADLESS/Current Mode:   GUI (converted post-deploy)/' /etc/update-motd.d/99-kali-mode
fi

cat << 'DONE'

[+] GUI conversion complete.

Next step: register the XRDP connection in Guacamole by running this on the Guacamole host:

    sudo /opt/redstack/register-kali-rdp.sh

Then open Guacamole and connect via "Kali Operator (XRDP)".

DONE
GUISCRIPT
chmod 755 /usr/local/sbin/kali-go-gui

# ----------------------------------------------------------------------------
# 8. MOTD banner (shown on every SSH login)
# ----------------------------------------------------------------------------
cat > /etc/update-motd.d/99-kali-mode << MOTD
#!/bin/bash
cat << BANNER

+=====================================================================+
|  redStack KALI WORKSTATION                                          |
+=====================================================================+
   Current Mode:   $(echo "${kali_deployment_mode}" | tr '[:lower:]' '[:upper:]')
   Tools:          22-tool AD/enum suite (installed at setup)
   Refresh/fix:    sudo install-kali-tools
   Convert to GUI: sudo kali-go-gui            (only needed in HEADLESS mode)
+=====================================================================+

BANNER
MOTD
chmod 755 /etc/update-motd.d/99-kali-mode

# Disable all default Kali motd scripts — keep only ours
for f in /etc/update-motd.d/*; do
    [ "$(basename "$f")" = "99-kali-mode" ] && continue
    chmod -x "$f" 2>/dev/null || true
done
# Also clear the static /etc/motd file (sometimes contains Kali developer message)
truncate -s 0 /etc/motd 2>/dev/null || true

# Disable /usr/bin/kali-motd called from /etc/profile.d/kali.sh (Kali developer message).
# Remove the entire if block — an empty if/fi with only a comment is a syntax error in sh.
if [ -f /etc/profile.d/kali.sh ]; then
    sed -i '/^# Display message.*cloud systems/,/^fi$/d' /etc/profile.d/kali.sh
    echo '# kali-motd disabled by redStack' >> /etc/profile.d/kali.sh
fi

# ----------------------------------------------------------------------------
# 9. GUI install if mode == gui
# ----------------------------------------------------------------------------
if [ "$KALI_MODE" = "gui" ]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        kali-desktop-xfce \
        xrdp

    cat > /etc/xrdp/startwm.sh << 'STARTWM'
#!/bin/sh
if test -r /etc/profile; then
    . /etc/profile
fi
if test -r ~/.profile; then
    . ~/.profile
fi
exec startxfce4
STARTWM
    chmod +x /etc/xrdp/startwm.sh

    systemctl enable xrdp
    systemctl restart xrdp
fi

echo "===== Kali Operator Setup Completed $(date) ====="
