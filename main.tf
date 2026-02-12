# main.tf - Main resource definitions

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge({
      Project     = var.project_name
      ManagedBy   = "Terraform"
      Environment = "Training"
    }, var.tags)
  }
}

# Random password for all lab instances
resource "random_password" "lab" {
  length           = 16
  special          = true
  override_special = "!@#%"
}

# Data sources for existing resources
data "aws_vpc" "default" {
  count   = var.use_default_vpc ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.use_default_vpc ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default[0].id]
  }
}

# Get latest Debian 12 AMI
data "aws_ami" "debian12" {
  most_recent = true
  owners      = ["136693071363"] # Debian official

  filter {
    name   = "name"
    values = ["debian-12-amd64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Get latest Ubuntu 22.04 AMI
data "aws_ami" "ubuntu2204" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Get latest Windows Server 2022 AMI (closest to Win11)
data "aws_ami" "windows2022" {
  most_recent = true
  owners      = ["801119661308"] # Amazon

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Optional: Create dedicated VPC
resource "aws_vpc" "training" {
  count                = var.use_default_vpc ? 0 : 1
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_subnet" "training" {
  count                   = var.use_default_vpc ? 0 : 1
  vpc_id                  = aws_vpc.training[0].id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-subnet"
  }
}

resource "aws_internet_gateway" "training" {
  count  = var.use_default_vpc ? 0 : 1
  vpc_id = aws_vpc.training[0].id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

resource "aws_route_table" "training" {
  count  = var.use_default_vpc ? 0 : 1
  vpc_id = aws_vpc.training[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.training[0].id
  }

  tags = {
    Name = "${var.project_name}-rt"
  }
}

resource "aws_route_table_association" "training" {
  count          = var.use_default_vpc ? 0 : 1
  subnet_id      = aws_subnet.training[0].id
  route_table_id = aws_route_table.training[0].id
}

data "aws_availability_zones" "available" {
  state = "available"
}

# Local variables
locals {
  vpc_id    = var.use_default_vpc ? data.aws_vpc.default[0].id : aws_vpc.training[0].id
  subnet_id = var.use_default_vpc ? sort(data.aws_subnets.default[0].ids)[0] : aws_subnet.training[0].id
}

# ============================================================================
# MYTHIC TEAM SERVER
# ============================================================================

resource "aws_instance" "mythic" {
  ami           = data.aws_ami.debian12.id
  instance_type = var.mythic_instance_type
  key_name      = var.ssh_key_name
  subnet_id     = local.subnet_id

  vpc_security_group_ids = [aws_security_group.mythic.id]

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/setup_scripts/mythic_setup.sh", {
    localPub_ip         = var.localPub_ip
    enable_autostart    = var.enable_mythic_autostart
    ssh_password        = random_password.lab.result
    vpc_cidr            = var.use_default_vpc ? data.aws_vpc.default[0].cidr_block : var.vpc_cidr
    redirector_vpc_cidr = aws_vpc.redirector.cidr_block
  })

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2 only
  }

  tags = {
    Name = "${var.project_name}-mythic-server"
    Role = "c2-backend"
  }
}

# ============================================================================
# GUACAMOLE SERVER
# ============================================================================

# Elastic IP for Guacamole (stable access portal address)
resource "aws_eip" "guacamole" {
  domain   = "vpc"
  instance = aws_instance.guacamole.id

  tags = {
    Name = "${var.project_name}-guacamole-eip"
  }
}

resource "aws_instance" "guacamole" {
  ami           = data.aws_ami.ubuntu2204.id
  instance_type = var.guacamole_instance_type
  key_name      = var.ssh_key_name
  subnet_id     = local.subnet_id

  vpc_security_group_ids = [aws_security_group.guacamole.id]

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/setup_scripts/guacamole_setup.sh", {
    guac_admin_password   = random_password.lab.result
    windows_private_ip    = aws_instance.windows.private_ip
    windows_username      = "Administrator"
    ssh_password          = random_password.lab.result
    mythic_private_ip     = aws_instance.mythic.private_ip
    redirector_private_ip = aws_instance.redirector.private_ip
    sliver_private_ip     = aws_instance.sliver.private_ip
    havoc_private_ip      = aws_instance.havoc.private_ip
  })

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  depends_on = [aws_instance.windows, aws_instance.sliver, aws_instance.havoc]

  tags = {
    Name = "${var.project_name}-guacamole-server"
    Role = "attacker-access"
  }
}

# ============================================================================
# WINDOWS 11 CLIENT
# ============================================================================

resource "aws_instance" "windows" {
  ami           = data.aws_ami.windows2022.id
  instance_type = var.windows_instance_type
  key_name      = var.ssh_key_name
  subnet_id     = local.subnet_id

  vpc_security_group_ids = [aws_security_group.windows.id]

  root_block_device {
    volume_size           = 50
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/setup_scripts/windows_setup.ps1", {
    lab_password = random_password.lab.result
  })

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project_name}-windows-client"
    Role = "attacker-workstation"
  }
}
