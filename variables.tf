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
  default     = "t3.small"
}

variable "havoc_instance_type" {
  description = "EC2 instance type for Havoc C2 server"
  type        = string
  default     = "t3.medium"
}

variable "use_default_vpc" {
  description = "Use default VPC (true) or create dedicated VPC (false)"
  type        = bool
  default     = true
}

variable "vpc_cidr" {
  description = "CIDR block for dedicated VPC (only used if use_default_vpc = false)"
  type        = string
  default     = "10.50.0.0/16"
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

variable "enable_external_vpn" {
  description = "Enable OpenVPN client on redirector for external platform access (HTB/THM/VulnLabs)"
  type        = bool
  default     = false
}

variable "external_vpn_cidrs" {
  description = "CIDR blocks routable through the redirector's VPN tunnel (e.g., HTB/THM/VulnLabs target ranges)"
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

variable "havoc_uri_prefix" {
  description = "URI prefix for Havoc C2 callbacks on the redirector"
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

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
