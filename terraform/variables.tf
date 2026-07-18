# variables.tf - Input variables for customization

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name for resource tagging"
  type        = string
  default     = "redStack"
}

variable "localPub_ip" {
  description = "Local public IP for SSH/management access (CIDR format, e.g., 1.2.3.4/32)"
  type        = string
  validation {
    condition     = can(cidrhost(var.localPub_ip, 0))
    error_message = "Must be a valid CIDR block (e.g., 1.2.3.4/32)"
  }
}

variable "ssh_key_name" {
  description = "Name of existing AWS SSH key pair"
  type        = string
}

variable "ssh_private_key_path" {
  description = "Path to the SSH private key file (.pem) for decrypting Windows Administrator password"
  type        = string
}

variable "mythic_instance_type" {
  description = "EC2 instance type for Mythic team server"
  type        = string
  default     = "t3.medium"
}

variable "guacamole_instance_type" {
  description = "EC2 instance type for Guacamole server"
  type        = string
  default     = "t3.small"
}

variable "windows_instance_type" {
  description = "EC2 instance type for Windows client"
  type        = string
  default     = "t3.medium"
}

variable "redirector_instance_type" {
  description = "EC2 instance type for Apache redirector"
  type        = string
  default     = "t3.micro"
}

variable "sliver_instance_type" {
  description = "EC2 instance type for Sliver C2 server"
  type        = string
  default     = "t3.medium"
}

variable "adaptix_instance_type" {
  description = "EC2 instance type for Adaptix C2 server"
  type        = string
  default     = "t3.small"
}

variable "kali_deployment_mode" {
  description = "Kali operator deployment mode: 'headless' (SSH only via Guacamole) or 'gui' (XFCE + XRDP via Guacamole). Headless is faster and cheaper; GUI can be enabled post-deploy via /usr/local/sbin/kali-go-gui."
  type        = string
  default     = "headless"
  validation {
    condition     = contains(["headless", "gui"], var.kali_deployment_mode)
    error_message = "kali_deployment_mode must be 'headless' or 'gui'."
  }
}

variable "kali_instance_type" {
  description = "EC2 instance type for Kali operator. Leave empty to auto-pick by mode (t3.medium for headless, t3.large for gui)."
  type        = string
  default     = ""
}

variable "kali_volume_size" {
  description = "Root volume size in GB for the Kali operator. Leave 0 to auto-pick by mode (30 for headless, 50 for gui)."
  type        = number
  default     = 0
}

variable "use_default_vpc" {
  description = "Use default VPC (true) or create dedicated VPC (false)"
  type        = bool
  default     = false
}

variable "vpc_cidr" {
  description = "CIDR block for dedicated VPC (only used if use_default_vpc = false)"
  type        = string
  default     = "10.50.0.0/16"
}

variable "redirector_vpc_cidr" {
  description = "CIDR block for the redirector VPC. Change when running multiple deployments simultaneously."
  type        = string
  default     = "10.60.0.0/16"
}

variable "enable_mythic_autostart" {
  description = "Automatically start Mythic on instance boot"
  type        = bool
  default     = true
}

variable "redirector_domain" {
  description = "Domain name for redirector (optional, uses example.com if not provided)"
  type        = string
  default     = ""
}

variable "enable_redirector_htaccess_filtering" {
  description = "Enable Apache mod_rewrite filtering on redirector"
  type        = bool
  default     = true
}

variable "enable_vpn_tunnel" {
  description = "vpnTUN routing: OpenVPN client on redirector + WireGuard tunnel from C2 VPC, so internal lab machines can reach cyber range targets. Leave false for normal public-internet operation."
  type        = bool
  default     = false
}

variable "vpn_tunnel_cidrs" {
  description = "Target subnets reachable through the OpenVPN tunnel (cyber range CIDRs). Route only the specific target /16s you need. Do NOT use a supernet that contains the lab VPCs (10.50.0.0/16, 10.60.0.0/16): this list becomes the Guacamole WireGuard AllowedIPs and its tunnel endpoint is the redirector's 10.60.x IP, so a broad range like 10.0.0.0/8 deadlocks the tunnel. See the Supported Platforms wiki section for per-platform CIDRs."
  type        = list(string)
  default     = ["10.10.0.0/16"]
}


variable "mythic_uri_prefix" {
  description = "URI prefix for Mythic C2 callbacks on the redirector"
  type        = string
  default     = "/cdn/media/stream"
}

variable "sliver_uri_prefix" {
  description = "URI prefix for Sliver C2 callbacks on the redirector"
  type        = string
  default     = "/cloud/storage/objects"
}

variable "adaptix_uri_prefix" {
  description = "URI prefix for Adaptix C2 callbacks on the redirector"
  type        = string
  default     = "/edge/cache/assets"
}

variable "c2_header_name" {
  description = "HTTP header name required for C2 traffic to pass through the redirector"
  type        = string
  default     = "X-Request-ID"
}

variable "c2_header_value" {
  description = "HTTP header value required for C2 traffic (leave empty to auto-generate)"
  type        = string
  default     = ""
}

variable "adaptix_version" {
  description = "AdaptixC2 git tag to pin the teamserver build to (reproducible; avoids upstream main drift)"
  type        = string
  default     = "v1.2"
}

variable "adaptix_client_url" {
  description = "URL to the prebuilt AdaptixClient Windows zip (downloaded onto the Windows workstation at deploy)"
  type        = string
  default     = "https://github.com/BaddKharma/redStack/releases/download/adaptix-client-v1.2/AdaptixClient-v1.2-win64.zip"
}

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
