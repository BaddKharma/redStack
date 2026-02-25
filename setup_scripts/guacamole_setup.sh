#!/bin/bash
# guacamole_setup.sh - User data script for Guacamole server initialization

set -e

# Logging
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "===== Guacamole Server Setup Started $(date) ====="

# Variables from Terraform template
GUAC_ADMIN_PASSWORD="${guac_admin_password}"
WINDOWS_PRIVATE_IP="${windows_private_ip}"
WINDOWS_USERNAME="${windows_username}"
WINDOWS_PASSWORD=$(echo "${windows_password_b64}" | base64 -d)
SSH_PASSWORD="${ssh_password}"
MYTHIC_PRIVATE_IP="${mythic_private_ip}"
REDIRECTOR_PRIVATE_IP="${redirector_private_ip}"
SLIVER_PRIVATE_IP="${sliver_private_ip}"
HAVOC_PRIVATE_IP="${havoc_private_ip}"
GUACAMOLE_PRIVATE_IP="${guacamole_private_ip}"

# Set hostname
echo "[*] Setting hostname..."
hostnamectl set-hostname guac

# Configure /etc/hosts for lab machines
echo "[*] Configuring /etc/hosts..."
cat >> /etc/hosts << HOSTS

# redStack lab hosts
$GUACAMOLE_PRIVATE_IP    guac
$MYTHIC_PRIVATE_IP       mythic
$SLIVER_PRIVATE_IP       sliver
$HAVOC_PRIVATE_IP        havoc
$REDIRECTOR_PRIVATE_IP   redirector
$WINDOWS_PRIVATE_IP      win-operator
HOSTS

# Update system
echo "[*] Updating system packages..."
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install dependencies
echo "[*] Installing Docker, Nginx, and utilities..."
apt-get install -y \
    docker.io \
    docker-compose \
    nginx \
    certbot \
    python3-certbot-nginx \
    curl \
    postgresql-client \
    jq

# Enable Docker
systemctl enable docker
systemctl start docker

# Add admin user to docker group
usermod -aG docker admin

# Configure SSH password authentication for Guacamole access only
# Public IP access still requires SSH keys, only localhost/VPC can use passwords
echo "[*] Configuring SSH authentication (keys for public, passwords for VPC)..."
echo "admin:$SSH_PASSWORD" | chpasswd
mkdir -p /home/admin
chown admin:admin /home/admin
usermod -d /home/admin -s /bin/bash admin

# Configure SSH: default requires keys, localhost/VPC IPs can use passwords
cat >> /etc/ssh/sshd_config << 'SSHCONF'

# Default: require SSH keys
PasswordAuthentication no
PubkeyAuthentication yes

# Allow password auth from localhost, Docker bridge networks, and private VPCs
Match Address 127.0.0.1,::1,172.16.0.0/12,10.0.0.0/8
    PasswordAuthentication yes
SSHCONF

systemctl restart sshd

# Create Guacamole directory structure
echo "[*] Setting up Guacamole directory structure..."
mkdir -p /opt/guacamole/{postgres,config}
cd /opt/guacamole

# Initialize PostgreSQL schema
echo "[*] Generating PostgreSQL initialization script..."
docker run --rm guacamole/guacamole /opt/guacamole/bin/initdb.sh --postgresql > initdb.sql

# Generate random DB password
DB_PASSWORD=$(openssl rand -base64 16)

# Create docker-compose.yml
echo "[*] Creating docker-compose configuration..."
cat > docker-compose.yml <<EOF
version: '3'

services:
  guacd:
    image: guacamole/guacd
    container_name: guacd
    restart: unless-stopped
    volumes:
      - /drive:/drive
    networks:
      - guac-network

  postgres:
    image: postgres:15
    container_name: postgres_guacamole
    restart: unless-stopped
    environment:
      POSTGRES_DB: guacamole_db
      POSTGRES_USER: guacamole_user
      POSTGRES_PASSWORD: $DB_PASSWORD
    volumes:
      - ./postgres:/var/lib/postgresql/data
      - ./initdb.sql:/docker-entrypoint-initdb.d/initdb.sql
    networks:
      - guac-network

  guacamole:
    image: guacamole/guacamole
    container_name: guacamole
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      GUACD_HOSTNAME: guacd
      POSTGRESQL_HOSTNAME: postgres
      POSTGRESQL_DATABASE: guacamole_db
      POSTGRESQL_USER: guacamole_user
      POSTGRESQL_PASSWORD: $DB_PASSWORD
    depends_on:
      - guacd
      - postgres
    networks:
      - guac-network

networks:
  guac-network:
    driver: bridge
EOF

# Create guac drive share directory BEFORE docker-compose so Docker doesn't create it as root
# guacd runs as a non-root user in the container and needs write access to /drive
echo "[*] Creating guac drive share directory..."
mkdir -p /drive
chmod 777 /drive

# Start Guacamole containers
echo "[*] Starting Guacamole containers..."
docker-compose up -d

# Wait for Guacamole to be ready
echo "[*] Waiting for Guacamole containers to start..."
sleep 10

# Configure Nginx reverse proxy with self-signed SSL
echo "[*] Configuring Nginx reverse proxy..."
cat > /etc/nginx/sites-available/guacamole <<EOF
server {
    listen 80;
    server_name _;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name _;

    ssl_certificate /etc/ssl/certs/guacamole-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/guacamole-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_buffering off;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$http_connection;
        proxy_cookie_path /guacamole/ /;
        access_log off;
    }
}
EOF

# Generate self-signed certificate
echo "[*] Generating self-signed SSL certificate..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/guacamole-selfsigned.key \
    -out /etc/ssl/certs/guacamole-selfsigned.crt \
    -subj "/C=US/ST=Training/L=Training/O=RedTeam/CN=guacamole"

# Enable Nginx site
ln -sf /etc/nginx/sites-available/guacamole /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl restart nginx

# Wait for Guacamole API to be fully ready (poll with retries)
echo "[*] Waiting for Guacamole API to become available..."
MAX_RETRIES=30
RETRY_COUNT=0
TOKEN=""
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    RESPONSE=$(curl -s -X POST "http://localhost:8080/guacamole/api/tokens" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=guacadmin&password=guacadmin" 2>/dev/null) || true
    TOKEN=$(printf '%s' "$RESPONSE" | jq -r '.authToken // empty' 2>/dev/null) || TOKEN=""
    if [ -n "$TOKEN" ]; then
        echo "[+] Guacamole API ready after $((RETRY_COUNT * 10)) seconds"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "[*] Guacamole not ready yet, retrying in 10s... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 10
done

# Change default Guacamole admin password using API
echo "[*] Changing default Guacamole admin password..."
IMDS_TOKEN_V2=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
PUBLIC_IP=$(curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN_V2" http://169.254.169.254/latest/meta-data/public-ipv4)

if [ -n "$TOKEN" ]; then
    # Update password and log the response for debugging
    PW_RESP=$(curl -s -X PUT "http://localhost:8080/guacamole/api/session/data/postgresql/users/guacadmin/password?token=$TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"oldPassword\":\"guacadmin\",\"newPassword\":\"$GUAC_ADMIN_PASSWORD\"}") || true
    echo "[*] Password change response: $PW_RESP"

    # Get new token with updated password
    RESPONSE=$(curl -s -X POST "http://localhost:8080/guacamole/api/tokens" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=guacadmin&password=$GUAC_ADMIN_PASSWORD" 2>/dev/null) || true
    TOKEN=$(printf '%s' "$RESPONSE" | jq -r '.authToken // empty' 2>/dev/null) || TOKEN=""

    # If new password token failed, password may already have been set on a prior run
    if [ -z "$TOKEN" ]; then
        echo "[!] Auth with new password failed — password may already be set, continuing with existing token"
        RESPONSE=$(curl -s -X POST "http://localhost:8080/guacamole/api/tokens" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "username=guacadmin&password=guacadmin" 2>/dev/null) || true
        TOKEN=$(printf '%s' "$RESPONSE" | jq -r '.authToken // empty' 2>/dev/null) || TOKEN=""
    fi

    if [ -n "$TOKEN" ]; then
    # Create RDP connection to Windows client (use jq to safely escape password in JSON)
    echo "[*] Creating RDP connection to Windows client..."
    RDP_JSON=$(jq -n \
        --arg host "$WINDOWS_PRIVATE_IP" \
        --arg user "$WINDOWS_USERNAME" \
        --arg pass "$WINDOWS_PASSWORD" \
        '{
            name: "Windows Operator Workstation",
            protocol: "rdp",
            parameters: {
                hostname: $host,
                port: "3389",
                username: $user,
                password: $pass,
                security: "any",
                "ignore-cert": "true",
                "enable-drive": "true",
                "drive-name": "GuacShare",
                "drive-path": "/drive",
                "create-drive-path": "true",
                console: "true",
                "server-layout": "en-us-qwerty"
            },
            attributes: {
                "max-connections": "2",
                "max-connections-per-user": "1"
            }
        }')
    curl -s -X POST "http://localhost:8080/guacamole/api/session/data/postgresql/connections?token=$TOKEN" \
        -H "Content-Type: application/json" \
        -d "$RDP_JSON"

    # Create SSH connection to Mythic Team Server
    echo "[*] Creating SSH connection to Mythic Team Server..."
    curl -s -X POST "http://localhost:8080/guacamole/api/session/data/postgresql/connections?token=$TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"Mythic Team Server (SSH)\",
            \"protocol\": \"ssh\",
            \"parameters\": {
                \"hostname\": \"$MYTHIC_PRIVATE_IP\",
                \"port\": \"22\",
                \"username\": \"admin\",
                \"password\": \"$SSH_PASSWORD\",
                \"color-scheme\": \"green-black\",
                \"font-size\": \"12\"
            },
            \"attributes\": {
                \"max-connections\": \"2\",
                \"max-connections-per-user\": \"1\"
            }
        }"

    # Create SSH connection to Guacamole Server (use private IP, not localhost, because guacd runs in Docker)
    IMDS_TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
    GUAC_PRIVATE_IP=$(curl -s -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/local-ipv4)
    echo "[*] Creating SSH connection to Guacamole Server ($GUAC_PRIVATE_IP)..."
    curl -s -X POST "http://localhost:8080/guacamole/api/session/data/postgresql/connections?token=$TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"Guacamole Server (SSH)\",
            \"protocol\": \"ssh\",
            \"parameters\": {
                \"hostname\": \"$GUAC_PRIVATE_IP\",
                \"port\": \"22\",
                \"username\": \"admin\",
                \"password\": \"$SSH_PASSWORD\",
                \"color-scheme\": \"green-black\",
                \"font-size\": \"12\"
            },
            \"attributes\": {
                \"max-connections\": \"2\",
                \"max-connections-per-user\": \"1\"
            }
        }"

    # Create SSH connection to Redirector Server
    echo "[*] Creating SSH connection to Redirector Server..."
    curl -s -X POST "http://localhost:8080/guacamole/api/session/data/postgresql/connections?token=$TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"Apache Redirector (SSH)\",
            \"protocol\": \"ssh\",
            \"parameters\": {
                \"hostname\": \"$REDIRECTOR_PRIVATE_IP\",
                \"port\": \"22\",
                \"username\": \"admin\",
                \"password\": \"$SSH_PASSWORD\",
                \"color-scheme\": \"green-black\",
                \"font-size\": \"12\"
            },
            \"attributes\": {
                \"max-connections\": \"2\",
                \"max-connections-per-user\": \"1\"
            }
        }"

    # Create SSH connection to Sliver C2 Server
    echo "[*] Creating SSH connection to Sliver C2 Server..."
    curl -s -X POST "http://localhost:8080/guacamole/api/session/data/postgresql/connections?token=$TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"Sliver C2 Server (SSH)\",
            \"protocol\": \"ssh\",
            \"parameters\": {
                \"hostname\": \"$SLIVER_PRIVATE_IP\",
                \"port\": \"22\",
                \"username\": \"admin\",
                \"password\": \"$SSH_PASSWORD\",
                \"color-scheme\": \"green-black\",
                \"font-size\": \"12\"
            },
            \"attributes\": {
                \"max-connections\": \"2\",
                \"max-connections-per-user\": \"1\"
            }
        }"

    # Create SSH connection to Havoc C2 Server
    echo "[*] Creating SSH connection to Havoc C2 Server..."
    curl -s -X POST "http://localhost:8080/guacamole/api/session/data/postgresql/connections?token=$TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"Havoc C2 Server (SSH)\",
            \"protocol\": \"ssh\",
            \"parameters\": {
                \"hostname\": \"$HAVOC_PRIVATE_IP\",
                \"port\": \"22\",
                \"username\": \"admin\",
                \"password\": \"$SSH_PASSWORD\",
                \"color-scheme\": \"green-black\",
                \"font-size\": \"12\"
            },
            \"attributes\": {
                \"max-connections\": \"2\",
                \"max-connections-per-user\": \"1\"
            }
        }"

    # Create VNC connection to Havoc C2 Desktop (GUI client)
    echo "[*] Creating VNC connection to Havoc C2 Desktop..."
    curl -s -X POST "http://localhost:8080/guacamole/api/session/data/postgresql/connections?token=$TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"Havoc C2 Desktop (VNC)\",
            \"protocol\": \"vnc\",
            \"parameters\": {
                \"hostname\": \"$HAVOC_PRIVATE_IP\",
                \"port\": \"5901\",
                \"password\": \"$SSH_PASSWORD\",
                \"color-depth\": \"24\"
            },
            \"attributes\": {
                \"max-connections\": \"2\",
                \"max-connections-per-user\": \"1\"
            }
        }"
    else
        echo "[!] Could not obtain valid token after password change. Skipping connection creation."
    fi
else
    echo "[!] Warning: Could not automatically configure Guacamole. Manual setup required."
fi

echo "===== Guacamole Server Setup Completed $(date) ====="
echo "===== Access Guacamole at https://$PUBLIC_IP/guacamole ====="
echo "===== Default credentials: guacadmin / $GUAC_ADMIN_PASSWORD ====="
