#!/bin/bash
# setup_redirector.sh - Apache redirector setup script
# Run this manually after logging into the Apache redirector instance:
#   sudo /root/setup_redirector.sh
#
# After setup, obtain a Let's Encrypt SSL certificate:
#   sudo certbot --apache -d <your-domain>

set -e

echo "===== Apache Redirector Setup Started $(date) ====="

# Variables (populated by Terraform during deployment)
MYTHIC_PRIVATE_IP="${mythic_private_ip}"
SLIVER_PRIVATE_IP="${sliver_private_ip}"
HAVOC_PRIVATE_IP="${havoc_private_ip}"
DOMAIN_NAME="${domain_name}"
MYTHIC_URI_PREFIX="${mythic_uri_prefix}"
SLIVER_URI_PREFIX="${sliver_uri_prefix}"
HAVOC_URI_PREFIX="${havoc_uri_prefix}"
C2_HEADER_NAME="${c2_header_name}"
C2_HEADER_VALUE="${c2_header_value}"
ENABLE_VPN="${enable_external_vpn}"
MAIN_VPC_CIDR="${main_vpc_cidr}"

# ============================================================================
# CREATE TEST SCRIPT EARLY (available even if setup fails partway)
# ============================================================================

echo "[*] Creating connectivity test script..."
cat > /root/test_redirector.sh << 'TESTSCRIPT'
#!/bin/bash
echo "===== Redirector Connectivity Test ====="
echo ""
echo "[*] Apache status:"
systemctl status apache2 --no-pager
echo ""
echo "[*] Enabled Apache modules:"
apache2ctl -M 2>/dev/null | grep -E "proxy|rewrite|ssl|headers|deflate"
echo ""
echo "[*] Active VirtualHosts:"
apache2ctl -S 2>/dev/null
echo ""
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
echo "[*] Testing direct backend connectivity:"
curl -I -m 5 -A "$UA" http://MYTHIC_IP_PLACEHOLDER/ 2>/dev/null && echo "  Mythic: OK" || echo "  Mythic: FAILED"
curl -I -m 5 -A "$UA" http://SLIVER_IP_PLACEHOLDER/ 2>/dev/null && echo "  Sliver: OK" || echo "  Sliver: FAILED"
curl -I -m 5 -A "$UA" http://HAVOC_IP_PLACEHOLDER/ 2>/dev/null && echo "  Havoc:  OK" || echo "  Havoc:  FAILED"
echo ""
echo "[*] Testing decoy page (no header - should get CloudEdge CDN page):"
curl -s -A "$UA" http://localhost/ | head -5
echo ""
echo "[*] Testing C2 routing WITH correct header:"
curl -v -A "$UA" -H "HEADER_NAME_PLACEHOLDER: HEADER_VALUE_PLACEHOLDER" http://localhost/MYTHIC_PREFIX_PLACEHOLDER/ 2>&1 | head -15
echo ""
echo "[*] Testing C2 routing WITHOUT header (should get decoy):"
curl -v -A "$UA" http://localhost/MYTHIC_PREFIX_PLACEHOLDER/ 2>&1 | head -15
echo ""
echo "[*] UFW status:"
ufw status verbose
echo ""
echo "[*] Java version:"
java -version 2>&1
echo ""
echo "[*] Header validation:"
echo "  Header:  HEADER_NAME_PLACEHOLDER: HEADER_VALUE_PLACEHOLDER"
echo ""
echo "[*] URI routing (requires correct header):"
echo "  MYTHIC_PREFIX_PLACEHOLDER/ -> Mythic  (MYTHIC_IP_PLACEHOLDER)"
echo "  SLIVER_PREFIX_PLACEHOLDER/ -> Sliver  (SLIVER_IP_PLACEHOLDER)"
echo "  HAVOC_PREFIX_PLACEHOLDER/ -> Havoc   (HAVOC_IP_PLACEHOLDER)"
TESTSCRIPT
sed -i "s|MYTHIC_IP_PLACEHOLDER|$MYTHIC_PRIVATE_IP|g" /root/test_redirector.sh
sed -i "s|SLIVER_IP_PLACEHOLDER|$SLIVER_PRIVATE_IP|g" /root/test_redirector.sh
sed -i "s|HAVOC_IP_PLACEHOLDER|$HAVOC_PRIVATE_IP|g" /root/test_redirector.sh
sed -i "s|MYTHIC_PREFIX_PLACEHOLDER|$MYTHIC_URI_PREFIX|g" /root/test_redirector.sh
sed -i "s|SLIVER_PREFIX_PLACEHOLDER|$SLIVER_URI_PREFIX|g" /root/test_redirector.sh
sed -i "s|HAVOC_PREFIX_PLACEHOLDER|$HAVOC_URI_PREFIX|g" /root/test_redirector.sh
sed -i "s|HEADER_NAME_PLACEHOLDER|$C2_HEADER_NAME|g" /root/test_redirector.sh
sed -i "s|HEADER_VALUE_PLACEHOLDER|$C2_HEADER_VALUE|g" /root/test_redirector.sh
chmod +x /root/test_redirector.sh

# Update package lists
echo "[*] Updating package lists..."
apt-get update

# Install Apache and core utilities
echo "[*] Installing Apache web server and utilities..."
apt-get install -y apache2 openssl curl ufw net-tools

# Install OpenVPN client if VPN feature is enabled
if [ "$ENABLE_VPN" = "true" ]; then
    echo "[*] Installing OpenVPN client..."
    apt-get install -y openvpn
fi

# Install SSL development libraries
echo "[*] Installing SSL packages..."
apt-get install -y libssl-dev ca-certificates

# Install Certbot for SSL certificate management
echo "[*] Installing Certbot for SSL..."
apt-get install -y certbot python3-certbot-apache

# Install OpenJDK 17
echo "[*] Installing OpenJDK 17..."
apt-get install -y openjdk-17-jdk

# Enable IP forwarding if VPN routing is enabled
if [ "$ENABLE_VPN" = "true" ]; then
    echo "[*] Enabling IP forwarding for VPN routing..."
    echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-vpn-forward.conf
    sysctl -p /etc/sysctl.d/99-vpn-forward.conf
fi

# Enable Apache service
systemctl enable apache2

# Enable Apache modules via a2enmod
echo "[*] Enabling Apache modules..."
a2enmod rewrite
a2enmod ssl
a2enmod proxy
a2enmod proxy_http
a2enmod proxy_connect
a2enmod headers
a2enmod deflate
a2enmod proxy_balancer
a2enmod proxy_html
a2enmod lbmethod_byrequests

# Disable directory listing
echo "[*] Disabling directory listing..."
a2dismod autoindex -f

# Restart Apache to load newly enabled modules
systemctl restart apache2

# Configure UFW firewall
echo "[*] Configuring firewall rules..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp

if [ "$ENABLE_VPN" = "true" ]; then
    echo "[*] Adding VPN routing firewall rules..."
    ufw allow in from $MAIN_VPC_CIDR
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
fi

ufw --force enable

# Generate self-signed SSL certificate (placeholder until Certbot is run)
echo "[*] Generating self-signed SSL certificate..."
mkdir -p /etc/apache2/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/redirector.key \
    -out /etc/apache2/ssl/redirector.crt \
    -subj "/C=US/ST=State/L=City/O=Company/CN=$DOMAIN_NAME"

# ============================================================================
# REDIRECT RULES (block security scanners, AV vendors, TOR exit nodes)
# ============================================================================

echo "[*] Downloading redirect.rules from redStack repo..."
REDIRECT_URL="https://raw.githubusercontent.com/BaddKharma/redStack/main/setup_scripts/redirect.rules"
if curl -sL --max-time 30 "$REDIRECT_URL" -o /etc/apache2/redirect.rules; then
    echo "[+] Installed redirect.rules ($(grep -c 'RewriteCond' /etc/apache2/redirect.rules) total rules, cloud IPs commented out)"
else
    echo "[!] Failed to download redirect.rules - creating empty placeholder"
    echo "# redirect.rules - download failed at $(date), add rules manually" > /etc/apache2/redirect.rules
fi

# ============================================================================
# DECOY PAGE (served when header validation fails)
# ============================================================================

echo "[*] Creating decoy landing page..."
mkdir -p /var/www/html/decoy
cat > /var/www/html/decoy/index.html << 'DECOYHTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CloudEdge CDN - Service Portal</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f4f4; color: #333; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.container { text-align: center; background: white; padding: 60px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 500px; }
h1 { color: #2c3e50; font-size: 24px; margin-bottom: 10px; }
p { color: #7f8c8d; font-size: 14px; line-height: 1.6; }
.status { margin-top: 20px; padding: 10px; background: #eaf7ea; border-radius: 4px; color: #27ae60; font-size: 13px; }
.ref { margin-top: 20px; font-size: 12px; color: #bdc3c7; }
</style>
</head>
<body>
<div class="container">
<h1>CloudEdge CDN</h1>
<p>Content delivery service is currently undergoing scheduled maintenance.<br>All services will be restored shortly.</p>
<div class="status">System Status: Maintenance Window Active</div>
<p class="ref">Reference: CE-2024-MAINT-001</p>
</div>
</body>
</html>
DECOYHTML

# Also serve decoy for any sub-path via .htaccess
cat > /var/www/html/decoy/.htaccess << 'HTACCESS'
RewriteEngine On
RewriteCond %%{REQUEST_FILENAME} !-f
RewriteCond %%{REQUEST_FILENAME} !-d
RewriteRule . /index.html [L]
HTACCESS

# ============================================================================
# CONSOLIDATED VIRTUALHOST - HTTP (port 80)
# Header validation + URI prefix routing, decoy fallback
# ============================================================================

echo "[*] Configuring consolidated HTTP VirtualHost..."
cat > /etc/apache2/sites-available/redirector-http.conf << 'APACHECONF'
<VirtualHost *:80>
    ServerName DOMAIN_PLACEHOLDER
    DocumentRoot /var/www/html/decoy

    RewriteEngine On
    LogLevel warn rewrite:trace3
    ErrorLog /var/log/apache2/redirector-error.log
    CustomLog /var/log/apache2/redirector-access.log combined

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-For "%%{REMOTE_ADDR}e"

    # Block known scanners, AV vendors, and TOR exit nodes (403 Forbidden)
    Include /etc/apache2/redirect.rules

    # Mythic C2 - header validation + URI prefix routing
    RewriteCond %%{HTTP:HEADER_NAME_PLACEHOLDER} ^HEADER_VALUE_PLACEHOLDER$
    RewriteRule ^MYTHIC_PREFIX_PLACEHOLDER/(.*) http://MYTHIC_IP_PLACEHOLDER/$1 [P,L]
    ProxyPassReverse MYTHIC_PREFIX_PLACEHOLDER/ http://MYTHIC_IP_PLACEHOLDER/

    # Sliver C2 - header validation + URI prefix routing
    RewriteCond %%{HTTP:HEADER_NAME_PLACEHOLDER} ^HEADER_VALUE_PLACEHOLDER$
    RewriteRule ^SLIVER_PREFIX_PLACEHOLDER/(.*) http://SLIVER_IP_PLACEHOLDER/$1 [P,L]
    ProxyPassReverse SLIVER_PREFIX_PLACEHOLDER/ http://SLIVER_IP_PLACEHOLDER/

    # Havoc C2 - header validation + URI prefix routing
    RewriteCond %%{HTTP:HEADER_NAME_PLACEHOLDER} ^HEADER_VALUE_PLACEHOLDER$
    RewriteRule ^HAVOC_PREFIX_PLACEHOLDER/(.*) http://HAVOC_IP_PLACEHOLDER/$1 [P,L]
    ProxyPassReverse HAVOC_PREFIX_PLACEHOLDER/ http://HAVOC_IP_PLACEHOLDER/

    # Default: serve decoy page (falls through to DocumentRoot)
</VirtualHost>
APACHECONF

# ============================================================================
# CONSOLIDATED VIRTUALHOST - HTTPS (port 443)
# Header validation + URI prefix routing, decoy fallback
# ============================================================================

echo "[*] Configuring consolidated HTTPS VirtualHost..."
cat > /etc/apache2/sites-available/redirector-https.conf << 'APACHECONF'
<VirtualHost *:443>
    ServerName DOMAIN_PLACEHOLDER
    DocumentRoot /var/www/html/decoy

    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/redirector.crt
    SSLCertificateKeyFile /etc/apache2/ssl/redirector.key

    RewriteEngine On
    LogLevel warn rewrite:trace3
    ErrorLog /var/log/apache2/redirector-ssl-error.log
    CustomLog /var/log/apache2/redirector-ssl-access.log combined

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-For "%%{REMOTE_ADDR}e"

    # Block known scanners, AV vendors, and TOR exit nodes (403 Forbidden)
    Include /etc/apache2/redirect.rules

    # Mythic C2 - header validation + URI prefix routing
    RewriteCond %%{HTTP:HEADER_NAME_PLACEHOLDER} ^HEADER_VALUE_PLACEHOLDER$
    RewriteRule ^MYTHIC_PREFIX_PLACEHOLDER/(.*) https://MYTHIC_IP_PLACEHOLDER/$1 [P,L]
    ProxyPassReverse MYTHIC_PREFIX_PLACEHOLDER/ https://MYTHIC_IP_PLACEHOLDER/

    # Sliver C2 - header validation + URI prefix routing
    RewriteCond %%{HTTP:HEADER_NAME_PLACEHOLDER} ^HEADER_VALUE_PLACEHOLDER$
    RewriteRule ^SLIVER_PREFIX_PLACEHOLDER/(.*) https://SLIVER_IP_PLACEHOLDER/$1 [P,L]
    ProxyPassReverse SLIVER_PREFIX_PLACEHOLDER/ https://SLIVER_IP_PLACEHOLDER/

    # Havoc C2 - header validation + URI prefix routing
    RewriteCond %%{HTTP:HEADER_NAME_PLACEHOLDER} ^HEADER_VALUE_PLACEHOLDER$
    RewriteRule ^HAVOC_PREFIX_PLACEHOLDER/(.*) https://HAVOC_IP_PLACEHOLDER/$1 [P,L]
    ProxyPassReverse HAVOC_PREFIX_PLACEHOLDER/ https://HAVOC_IP_PLACEHOLDER/

    # Default: serve decoy page (falls through to DocumentRoot)

    SSLProxyEngine On
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
</VirtualHost>
APACHECONF

# ============================================================================
# REPLACE PLACEHOLDERS WITH ACTUAL VALUES
# ============================================================================

echo "[*] Substituting configuration values..."

# HTTP config
sed -i "s|DOMAIN_PLACEHOLDER|$DOMAIN_NAME|g" /etc/apache2/sites-available/redirector-http.conf
sed -i "s|MYTHIC_IP_PLACEHOLDER|$MYTHIC_PRIVATE_IP|g" /etc/apache2/sites-available/redirector-http.conf
sed -i "s|SLIVER_IP_PLACEHOLDER|$SLIVER_PRIVATE_IP|g" /etc/apache2/sites-available/redirector-http.conf
sed -i "s|HAVOC_IP_PLACEHOLDER|$HAVOC_PRIVATE_IP|g" /etc/apache2/sites-available/redirector-http.conf
sed -i "s|MYTHIC_PREFIX_PLACEHOLDER|$MYTHIC_URI_PREFIX|g" /etc/apache2/sites-available/redirector-http.conf
sed -i "s|SLIVER_PREFIX_PLACEHOLDER|$SLIVER_URI_PREFIX|g" /etc/apache2/sites-available/redirector-http.conf
sed -i "s|HAVOC_PREFIX_PLACEHOLDER|$HAVOC_URI_PREFIX|g" /etc/apache2/sites-available/redirector-http.conf
sed -i "s|HEADER_NAME_PLACEHOLDER|$C2_HEADER_NAME|g" /etc/apache2/sites-available/redirector-http.conf
sed -i "s|HEADER_VALUE_PLACEHOLDER|$C2_HEADER_VALUE|g" /etc/apache2/sites-available/redirector-http.conf

# HTTPS config
sed -i "s|DOMAIN_PLACEHOLDER|$DOMAIN_NAME|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|MYTHIC_IP_PLACEHOLDER|$MYTHIC_PRIVATE_IP|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|SLIVER_IP_PLACEHOLDER|$SLIVER_PRIVATE_IP|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|HAVOC_IP_PLACEHOLDER|$HAVOC_PRIVATE_IP|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|MYTHIC_PREFIX_PLACEHOLDER|$MYTHIC_URI_PREFIX|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|SLIVER_PREFIX_PLACEHOLDER|$SLIVER_URI_PREFIX|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|HAVOC_PREFIX_PLACEHOLDER|$HAVOC_URI_PREFIX|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|HEADER_NAME_PLACEHOLDER|$C2_HEADER_NAME|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|HEADER_VALUE_PLACEHOLDER|$C2_HEADER_VALUE|g" /etc/apache2/sites-available/redirector-https.conf

# Disable default site and enable redirector sites
echo "[*] Enabling VirtualHost sites..."
a2dissite 000-default.conf
a2ensite redirector-http.conf
a2ensite redirector-https.conf

# Harden Apache - hide version info
SECURITY_CONF="/etc/apache2/conf-available/security.conf"
echo "[*] Applying security configurations..."
sed -i "s/ServerSignature On/ServerSignature Off/g" "$SECURITY_CONF"
sed -i "s/ServerTokens OS/ServerTokens Prod/g" "$SECURITY_CONF"

# Validate Apache configuration
apache2ctl configtest

# Restart Apache to apply all changes
echo "[*] Restarting Apache..."
systemctl restart apache2

# ============================================================================
# VPN HELPER SCRIPT (conditional)
# ============================================================================

if [ "$ENABLE_VPN" = "true" ]; then
    echo "[*] Creating VPN helper script..."
    mkdir -p /home/admin/vpn

    cat > /home/admin/vpn.sh << 'VPNSCRIPT'
#!/bin/bash
# vpn.sh - OpenVPN helper for external platform access (HTB/THM)
# Usage:
#   sudo ~/vpn.sh start /path/to/your.ovpn
#   sudo ~/vpn.sh stop
#   sudo ~/vpn.sh status

OVPN_CONFIG="/home/admin/vpn/external.ovpn"
OVPN_PID_FILE="/var/run/openvpn-external.pid"
OVPN_LOG="/var/log/openvpn-external.log"

case "$1" in
    start)
        if [ -z "$2" ] && [ ! -f "$OVPN_CONFIG" ]; then
            echo "Usage: $0 start /path/to/your.ovpn"
            echo ""
            echo "Upload your .ovpn file first:"
            echo "  scp your-lab.ovpn admin@<redirector-ip>:~/vpn/"
            echo "Then run:"
            echo "  sudo ~/vpn.sh start ~/vpn/your-lab.ovpn"
            exit 1
        fi

        # Copy .ovpn to persistent location if a path was provided
        if [ -n "$2" ]; then
            if [ ! -f "$2" ]; then
                echo "[!] File not found: $2"
                exit 1
            fi
            echo "[*] Copying config to $OVPN_CONFIG..."
            cp "$2" "$OVPN_CONFIG"
            chown admin:admin "$OVPN_CONFIG"
        fi

        if [ -f "$OVPN_PID_FILE" ] && kill -0 $(cat "$OVPN_PID_FILE") 2>/dev/null; then
            echo "[!] VPN is already running (PID: $(cat $OVPN_PID_FILE))"
            echo "    Run '$0 stop' first to disconnect."
            exit 1
        fi

        echo "[*] Starting OpenVPN tunnel..."
        openvpn --config "$OVPN_CONFIG" \
            --daemon \
            --log "$OVPN_LOG" \
            --writepid "$OVPN_PID_FILE" \
            --pull-filter ignore "redirect-gateway"

        # Wait for tunnel to establish
        echo "[*] Waiting for tunnel to come up..."
        for i in $(seq 1 30); do
            if ip link show tun0 >/dev/null 2>&1; then
                break
            fi
            sleep 1
        done

        if ! ip link show tun0 >/dev/null 2>&1; then
            echo "[!] Tunnel failed to come up after 30 seconds."
            echo "[!] Check logs: cat $OVPN_LOG"
            exit 1
        fi

        # Get VPN IP
        VPN_IP=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
        echo "[+] VPN tunnel established!"
        echo "    Interface: tun0"
        echo "    VPN IP:    $VPN_IP"

        # Set up NAT masquerade for forwarded traffic
        echo "[*] Configuring NAT masquerade on tun0..."
        iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
        iptables -A FORWARD -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -o tun0 -j ACCEPT

        echo ""
        echo "[+] VPN routing is active. Internal lab machines can now reach"
        echo "    external targets through this redirector's VPN tunnel."
        echo ""
        echo "    To verify from an internal machine:"
        echo "      ping <target-ip>"
        ;;

    stop)
        if [ -f "$OVPN_PID_FILE" ] && kill -0 $(cat "$OVPN_PID_FILE") 2>/dev/null; then
            echo "[*] Stopping OpenVPN tunnel..."
            kill $(cat "$OVPN_PID_FILE")
            rm -f "$OVPN_PID_FILE"

            # Remove NAT rules
            echo "[*] Removing NAT masquerade rules..."
            iptables -t nat -D POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || true
            iptables -D FORWARD -i tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -o tun0 -j ACCEPT 2>/dev/null || true

            echo "[+] VPN tunnel stopped."
            echo "    Config file preserved at: $OVPN_CONFIG"
            echo "    Reconnect with: sudo ~/vpn.sh start"
        else
            echo "[*] VPN is not running."
        fi
        ;;

    status)
        echo "===== OpenVPN External Tunnel Status ====="
        echo ""
        if [ -f "$OVPN_PID_FILE" ] && kill -0 $(cat "$OVPN_PID_FILE") 2>/dev/null; then
            echo "State:     CONNECTED (PID: $(cat $OVPN_PID_FILE))"
            if ip link show tun0 >/dev/null 2>&1; then
                VPN_IP=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
                echo "Interface: tun0"
                echo "VPN IP:    $VPN_IP"
            else
                echo "Interface: tun0 (not found - tunnel may be reconnecting)"
            fi
        else
            echo "State:     DISCONNECTED"
        fi
        echo ""
        if [ -f "$OVPN_CONFIG" ]; then
            echo "Config:    $OVPN_CONFIG"
        else
            echo "Config:    (none - upload an .ovpn file first)"
        fi
        echo ""
        echo "IP Forwarding: $(cat /proc/sys/net/ipv4/ip_forward)"
        echo ""
        echo "NAT rules:"
        iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -E "MASQUERADE|tun" || echo "  (none)"
        echo ""
        echo "Log file: $OVPN_LOG"
        ;;

    *)
        echo "Usage: $0 {start|stop|status}"
        echo ""
        echo "  start /path/to/file.ovpn  - Connect VPN and enable routing"
        echo "  start                      - Reconnect using saved config"
        echo "  stop                       - Disconnect VPN"
        echo "  status                     - Show VPN connection status"
        ;;
esac
VPNSCRIPT
    chmod +x /home/admin/vpn.sh
    chown admin:admin /home/admin/vpn.sh /home/admin/vpn
fi

# Display public IP
IMDS_TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)

echo ""
echo "===== Redirector Setup Complete ====="
echo "===== Public IP: $PUBLIC_IP ====="
echo ""
echo "Installed components:"
echo "  - Apache2 with modules: rewrite, ssl, proxy, proxy_http, headers, deflate, proxy_balancer, proxy_html"
echo "  - Certbot (run: sudo certbot --apache -d $DOMAIN_NAME)"
echo "  - OpenJDK 17"
echo "  - UFW firewall (ports 22, 80, 443)"
echo "  - Self-signed SSL certificate (replace with Certbot)"
echo "  - Decoy page: CloudEdge CDN maintenance page"
echo "  - redirect.rules: curi0usJack OPSEC rules (AV/scanner/TOR blocking)"
echo ""
echo "Header validation (required for C2 proxy):"
echo "  Header:  $C2_HEADER_NAME: $C2_HEADER_VALUE"
echo ""
echo "URI routing (requires correct header, ports 80/443):"
echo "  $MYTHIC_URI_PREFIX/ -> Mythic  ($MYTHIC_PRIVATE_IP)"
echo "  $SLIVER_URI_PREFIX/ -> Sliver  ($SLIVER_PRIVATE_IP)"
echo "  $HAVOC_URI_PREFIX/ -> Havoc   ($HAVOC_PRIVATE_IP)"
echo ""
echo "Requests without the correct header get the decoy page."
echo "Configure each C2 agent's HTTP profile with the URI prefix AND custom header."
echo ""
echo "To obtain a Let's Encrypt SSL certificate, run:"
echo "  sudo certbot --apache -d $DOMAIN_NAME"
echo ""
echo "To verify setup, run:"
echo "  sudo /root/test_redirector.sh"

if [ "$ENABLE_VPN" = "true" ]; then
    echo ""
    echo "External VPN routing (HTB/THM):"
    echo "  1. Upload .ovpn:  scp lab.ovpn admin@<redirector-ip>:~/vpn/"
    echo "  2. Start VPN:     sudo ~/vpn.sh start ~/vpn/lab.ovpn"
    echo "  3. Stop VPN:      sudo ~/vpn.sh stop"
    echo "  4. Check status:  sudo ~/vpn.sh status"
fi
