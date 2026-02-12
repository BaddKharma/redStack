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

# Update package lists
echo "[*] Updating package lists..."
apt-get update

# Install Apache and core utilities
echo "[*] Installing Apache web server and utilities..."
apt-get install -y apache2 openssl curl ufw net-tools

# Install SSL development libraries
echo "[*] Installing SSL packages..."
apt-get install -y libssl-dev ca-certificates

# Install Certbot for SSL certificate management
echo "[*] Installing Certbot for SSL..."
apt-get install -y certbot python3-certbot-apache

# Install OpenJDK 17
echo "[*] Installing OpenJDK 17..."
apt-get install -y openjdk-17-jdk

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
ufw --force enable

# Generate self-signed SSL certificate (placeholder until Certbot is run)
echo "[*] Generating self-signed SSL certificate..."
mkdir -p /etc/apache2/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/apache2/ssl/redirector.key \
    -out /etc/apache2/ssl/redirector.crt \
    -subj "/C=US/ST=State/L=City/O=Company/CN=$DOMAIN_NAME"

# ============================================================================
# CONSOLIDATED VIRTUALHOST - HTTP (port 80)
# All C2 traffic routed via URI prefix matching
# ============================================================================

echo "[*] Configuring consolidated HTTP VirtualHost..."
cat > /etc/apache2/sites-available/redirector-http.conf << 'APACHECONF'
<VirtualHost *:80>
    ServerName DOMAIN_PLACEHOLDER

    RewriteEngine On
    LogLevel warn rewrite:trace3
    ErrorLog /var/log/apache2/redirector-error.log
    CustomLog /var/log/apache2/redirector-access.log combined

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-For "%%{REMOTE_ADDR}e"

    # Mythic C2 - URI prefix routing
    ProxyPass MYTHIC_PREFIX_PLACEHOLDER/ http://MYTHIC_IP_PLACEHOLDER/
    ProxyPassReverse MYTHIC_PREFIX_PLACEHOLDER/ http://MYTHIC_IP_PLACEHOLDER/

    # Sliver C2 - URI prefix routing
    ProxyPass SLIVER_PREFIX_PLACEHOLDER/ http://SLIVER_IP_PLACEHOLDER/
    ProxyPassReverse SLIVER_PREFIX_PLACEHOLDER/ http://SLIVER_IP_PLACEHOLDER/

    # Havoc C2 - URI prefix routing
    ProxyPass HAVOC_PREFIX_PLACEHOLDER/ http://HAVOC_IP_PLACEHOLDER/
    ProxyPassReverse HAVOC_PREFIX_PLACEHOLDER/ http://HAVOC_IP_PLACEHOLDER/
</VirtualHost>
APACHECONF

# ============================================================================
# CONSOLIDATED VIRTUALHOST - HTTPS (port 443)
# All C2 traffic routed via URI prefix matching
# ============================================================================

echo "[*] Configuring consolidated HTTPS VirtualHost..."
cat > /etc/apache2/sites-available/redirector-https.conf << 'APACHECONF'
<VirtualHost *:443>
    ServerName DOMAIN_PLACEHOLDER

    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/redirector.crt
    SSLCertificateKey /etc/apache2/ssl/redirector.key

    RewriteEngine On
    LogLevel warn rewrite:trace3
    ErrorLog /var/log/apache2/redirector-ssl-error.log
    CustomLog /var/log/apache2/redirector-ssl-access.log combined

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-For "%%{REMOTE_ADDR}e"

    # Mythic C2 - URI prefix routing
    ProxyPass MYTHIC_PREFIX_PLACEHOLDER/ https://MYTHIC_IP_PLACEHOLDER/
    ProxyPassReverse MYTHIC_PREFIX_PLACEHOLDER/ https://MYTHIC_IP_PLACEHOLDER/

    # Sliver C2 - URI prefix routing
    ProxyPass SLIVER_PREFIX_PLACEHOLDER/ https://SLIVER_IP_PLACEHOLDER/
    ProxyPassReverse SLIVER_PREFIX_PLACEHOLDER/ https://SLIVER_IP_PLACEHOLDER/

    # Havoc C2 - URI prefix routing
    ProxyPass HAVOC_PREFIX_PLACEHOLDER/ https://HAVOC_IP_PLACEHOLDER/
    ProxyPassReverse HAVOC_PREFIX_PLACEHOLDER/ https://HAVOC_IP_PLACEHOLDER/

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

# HTTPS config
sed -i "s|DOMAIN_PLACEHOLDER|$DOMAIN_NAME|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|MYTHIC_IP_PLACEHOLDER|$MYTHIC_PRIVATE_IP|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|SLIVER_IP_PLACEHOLDER|$SLIVER_PRIVATE_IP|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|HAVOC_IP_PLACEHOLDER|$HAVOC_PRIVATE_IP|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|MYTHIC_PREFIX_PLACEHOLDER|$MYTHIC_URI_PREFIX|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|SLIVER_PREFIX_PLACEHOLDER|$SLIVER_URI_PREFIX|g" /etc/apache2/sites-available/redirector-https.conf
sed -i "s|HAVOC_PREFIX_PLACEHOLDER|$HAVOC_URI_PREFIX|g" /etc/apache2/sites-available/redirector-https.conf

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

# Create connectivity test script
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
echo "[*] Testing connectivity to Mythic (MYTHIC_PREFIX_PLACEHOLDER/):"
curl -I -m 5 http://MYTHIC_IP_PLACEHOLDER/ || echo "Mythic HTTP connection failed"
echo ""
echo "[*] Testing connectivity to Sliver (SLIVER_PREFIX_PLACEHOLDER/):"
curl -I -m 5 http://SLIVER_IP_PLACEHOLDER/ || echo "Sliver HTTP connection failed"
echo ""
echo "[*] Testing connectivity to Havoc (HAVOC_PREFIX_PLACEHOLDER/):"
curl -I -m 5 http://HAVOC_IP_PLACEHOLDER/ || echo "Havoc HTTP connection failed"
echo ""
echo "[*] Testing local URI prefix routing:"
curl -v http://localhost/MYTHIC_PREFIX_PLACEHOLDER/ 2>&1 | head -10
echo ""
echo "[*] UFW status:"
ufw status verbose
echo ""
echo "[*] Java version:"
java -version 2>&1
echo ""
echo "[*] URI routing:"
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
chmod +x /root/test_redirector.sh

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
echo ""
echo "URI routing (all on ports 80/443):"
echo "  $MYTHIC_URI_PREFIX/ -> Mythic  ($MYTHIC_PRIVATE_IP)"
echo "  $SLIVER_URI_PREFIX/ -> Sliver  ($SLIVER_PRIVATE_IP)"
echo "  $HAVOC_URI_PREFIX/ -> Havoc   ($HAVOC_PRIVATE_IP)"
echo ""
echo "Configure each C2 agent's HTTP profile to use its URI prefix."
echo ""
echo "To obtain a Let's Encrypt SSL certificate, run:"
echo "  sudo certbot --apache -d $DOMAIN_NAME"
echo ""
echo "To verify setup, run:"
echo "  sudo /root/test_redirector.sh"
