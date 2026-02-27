# redirector.tf - Apache Redirector infrastructure (simulating external provider)

# ============================================================================
# SEPARATE VPC FOR REDIRECTOR (Simulates external VPS provider)
# ============================================================================

resource "aws_vpc" "redirector" {
  cidr_block           = "10.60.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-redirector-vpc"
    Note = "Simulates external VPS provider network"
  }
}

resource "aws_subnet" "redirector" {
  vpc_id                  = aws_vpc.redirector.id
  cidr_block              = "10.60.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-redirector-subnet"
  }
}

resource "aws_internet_gateway" "redirector" {
  vpc_id = aws_vpc.redirector.id

  tags = {
    Name = "${var.project_name}-redirector-igw"
  }
}

resource "aws_route_table" "redirector" {
  vpc_id = aws_vpc.redirector.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.redirector.id
  }

  tags = {
    Name = "${var.project_name}-redirector-rt"
  }
}

resource "aws_route_table_association" "redirector" {
  subnet_id      = aws_subnet.redirector.id
  route_table_id = aws_route_table.redirector.id
}

# ============================================================================
# VPC PEERING (Redirector VPC -> Team Server VPC)
# ============================================================================

resource "aws_vpc_peering_connection" "redirector_to_teamserver" {
  vpc_id      = aws_vpc.redirector.id
  peer_vpc_id = local.vpc_id
  auto_accept = true

  tags = {
    Name = "${var.project_name}-redirector-peering"
    Note = "Allows redirector to reach team server private IP"
  }
}

# Route from redirector VPC to team server VPC
resource "aws_route" "redirector_to_teamserver" {
  route_table_id            = aws_route_table.redirector.id
  destination_cidr_block    = var.use_default_vpc ? data.aws_vpc.default[0].cidr_block : aws_vpc.training[0].cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.redirector_to_teamserver.id
}

# Route from team server VPC to redirector VPC
resource "aws_route" "teamserver_to_redirector" {
  route_table_id            = var.use_default_vpc ? data.aws_vpc.default[0].main_route_table_id : aws_route_table.training[0].id
  destination_cidr_block    = aws_vpc.redirector.cidr_block
  vpc_peering_connection_id = aws_vpc_peering_connection.redirector_to_teamserver.id
}

# ============================================================================
# EXTERNAL VPN ROUTING (Optional - for HTB/THM/VulnLabs access)
# ============================================================================

# Route VPN target CIDRs to redirector instance ENI (for VPN forwarding)
resource "aws_route" "redirector_vpn_targets" {
  count                  = var.enable_external_vpn ? length(var.external_vpn_cidrs) : 0
  route_table_id         = aws_route_table.redirector.id
  destination_cidr_block = var.external_vpn_cidrs[count.index]
  network_interface_id   = aws_network_interface.redirector.id
}

# Route VPN target CIDRs from main VPC to redirector VPC via peering
resource "aws_route" "teamserver_vpn_targets" {
  count                     = var.enable_external_vpn ? length(var.external_vpn_cidrs) : 0
  route_table_id            = var.use_default_vpc ? data.aws_vpc.default[0].main_route_table_id : aws_route_table.training[0].id
  destination_cidr_block    = var.external_vpn_cidrs[count.index]
  vpc_peering_connection_id = aws_vpc_peering_connection.redirector_to_teamserver.id
}

# ============================================================================
# REDIRECTOR SECURITY GROUP
# ============================================================================

resource "aws_security_group" "redirector" {
  name        = "${var.project_name}-redirector-sg"
  description = "Security group for Apache redirector (simulated external)"
  vpc_id      = aws_vpc.redirector.id

  tags = {
    Name = "${var.project_name}-redirector-sg"
    Note = "Simulates external VPS firewall rules"
  }
}

# SSH from instructor only
resource "aws_security_group_rule" "redirector_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.localPub_ip]
  description       = "SSH access for instructor management"
  security_group_id = aws_security_group.redirector.id
}

# All traffic from main VPC (internal lab connectivity via VPC peering)
resource "aws_security_group_rule" "redirector_all_from_main_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [var.use_default_vpc ? data.aws_vpc.default[0].cidr_block : var.vpc_cidr]
  description       = "All traffic from main VPC for lab connectivity"
  security_group_id = aws_security_group.redirector.id
}

# HTTP from anywhere (public C2 callback endpoint)
resource "aws_security_group_rule" "redirector_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTP C2 callbacks from targets"
  security_group_id = aws_security_group.redirector.id
}

# HTTPS from anywhere (public C2 callback endpoint)
resource "aws_security_group_rule" "redirector_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTPS C2 callbacks from targets"
  security_group_id = aws_security_group.redirector.id
}

# Outbound - allow all
resource "aws_security_group_rule" "redirector_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.redirector.id
}

# ============================================================================
# REDIRECTOR NETWORK INTERFACE
# ============================================================================

resource "aws_network_interface" "redirector" {
  subnet_id         = aws_subnet.redirector.id
  security_groups   = [aws_security_group.redirector.id]
  source_dest_check = var.enable_external_vpn ? false : true
  tags              = { Name = "${var.project_name}-redirector-eni" }
}

# ============================================================================
# VPS REDIRECTOR EC2 INSTANCE
# ============================================================================

# Elastic IP for redirector (stable public IP)
resource "aws_eip" "redirector" {
  domain            = "vpc"
  network_interface = aws_network_interface.redirector.id

  depends_on = [aws_instance.redirector]

  tags = {
    Name = "${var.project_name}-redirector-eip"
  }
}

resource "aws_instance" "redirector" {
  ami           = data.aws_ami.debian12.id
  instance_type = var.redirector_instance_type
  key_name      = var.ssh_key_name

  network_interface {
    network_interface_id = aws_network_interface.redirector.id
    device_index         = 0
  }

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = replace(templatefile("${path.module}/setup_scripts/redirector_userdata.sh", {
    ssh_password          = random_password.lab.result
    redirector_private_ip = aws_network_interface.redirector.private_ip
    guacamole_private_ip  = aws_network_interface.guacamole.private_ip
    mythic_private_ip     = aws_network_interface.mythic.private_ip
    sliver_private_ip     = aws_network_interface.sliver.private_ip
    havoc_private_ip      = aws_network_interface.havoc.private_ip
    windows_private_ip    = aws_network_interface.windows.private_ip
    setup_script_b64 = base64gzip(replace(templatefile("${path.module}/setup_scripts/redirector_setup.sh", {
      mythic_private_ip   = aws_network_interface.mythic.private_ip
      sliver_private_ip   = aws_network_interface.sliver.private_ip
      havoc_private_ip    = aws_network_interface.havoc.private_ip
      domain_name         = var.redirector_domain
      mythic_uri_prefix   = var.mythic_uri_prefix
      sliver_uri_prefix   = var.sliver_uri_prefix
      havoc_uri_prefix    = var.havoc_uri_prefix
      c2_header_name      = var.c2_header_name
      c2_header_value     = local.c2_header_value
      enable_external_vpn  = var.enable_external_vpn
      enable_redirect_rules = var.enable_redirector_htaccess_filtering
      main_vpc_cidr        = var.use_default_vpc ? data.aws_vpc.default[0].cidr_block : var.vpc_cidr
    }), "\r", ""))
  }), "\r", "")

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  depends_on = [
    aws_vpc_peering_connection.redirector_to_teamserver,
    aws_route.redirector_to_teamserver
  ]

  tags = {
    Name = "${var.project_name}-apache-redirector"
    Role = "c2-redirector"
    Note = "Simulates external VPS (separate network)"
  }
}

# ============================================================================
# UPDATE MYTHIC SECURITY GROUP - RESTRICT TO REDIRECTOR ONLY
# ============================================================================

# HTTP C2 from redirector only (via VPC peering, uses private IP)
resource "aws_security_group_rule" "mythic_http_from_redirector" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "HTTP C2 from Apache redirector via VPC peering"
  security_group_id = aws_security_group.mythic.id
}

# HTTPS C2 from redirector only (via VPC peering, uses private IP)
resource "aws_security_group_rule" "mythic_https_from_redirector" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "HTTPS C2 from Apache redirector via VPC peering"
  security_group_id = aws_security_group.mythic.id
}
