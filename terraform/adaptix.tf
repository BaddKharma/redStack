# adaptix.tf - AdaptixC2 server infrastructure (internal only, no public IP)

# ============================================================================
# ADAPTIX C2 SECURITY GROUP
# ============================================================================

resource "aws_security_group" "adaptix" {
  name        = "${var.project_name}-adaptix-sg"
  description = "Security group for AdaptixC2 server (internal only)"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.project_name}-adaptix-sg"
    VPC  = "TeamServer-VPC"
  }
}

# SSH from instructor
resource "aws_security_group_rule" "adaptix_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.localPub_ip]
  description       = "SSH access for instructor"
  security_group_id = aws_security_group.adaptix.id
}

# SSH from Guacamole (web-based SSH access)
resource "aws_security_group_rule" "adaptix_ssh_from_guacamole" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.guacamole.id
  description              = "SSH from Guacamole for web-based access"
  security_group_id        = aws_security_group.adaptix.id
}

# HTTP C2 from redirector only (via VPC peering)
resource "aws_security_group_rule" "adaptix_http_from_redirector" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "HTTP C2 from redirector via VPC peering"
  security_group_id = aws_security_group.adaptix.id
}

# HTTPS C2 from redirector only (via VPC peering)
resource "aws_security_group_rule" "adaptix_https_from_redirector" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "HTTPS C2 from redirector via VPC peering"
  security_group_id = aws_security_group.adaptix.id
}

# Adaptix teamserver from Windows workstation (operator client connections)
resource "aws_security_group_rule" "adaptix_teamserver_from_windows" {
  type                     = "ingress"
  from_port                = 4321
  to_port                  = 4321
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.windows.id
  description              = "Adaptix teamserver from Windows operator workstation"
  security_group_id        = aws_security_group.adaptix.id
}


# All traffic from main VPC (internal lab connectivity)
resource "aws_security_group_rule" "adaptix_all_from_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [var.use_default_vpc ? data.aws_vpc.default[0].cidr_block : var.vpc_cidr]
  description       = "All internal lab traffic from main VPC"
  security_group_id = aws_security_group.adaptix.id
}

# All traffic from redirector VPC (cross-VPC lab connectivity)
resource "aws_security_group_rule" "adaptix_all_from_redirector_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "All traffic from redirector VPC for lab connectivity"
  security_group_id = aws_security_group.adaptix.id
}

# Outbound - allow all
resource "aws_security_group_rule" "adaptix_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.adaptix.id
}

# ============================================================================
# ADAPTIX NETWORK INTERFACE
# ============================================================================

resource "aws_network_interface" "adaptix" {
  subnet_id       = local.subnet_id
  security_groups = [aws_security_group.adaptix.id]
  tags            = { Name = "${var.project_name}-adaptix-eni" }
}

# ============================================================================
# ADAPTIX C2 EC2 INSTANCE (no public IP)
# ============================================================================

resource "aws_instance" "adaptix" {
  ami           = data.aws_ami.debian12.id
  instance_type = var.adaptix_instance_type
  key_name      = var.ssh_key_name

  network_interface {
    network_interface_id = aws_network_interface.adaptix.id
    device_index         = 0
  }

  root_block_device {
    volume_size           = 25
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/setup_scripts/adaptix_setup.sh", {
    ssh_password          = random_password.lab.result
    main_vpc_cidr         = var.use_default_vpc ? data.aws_vpc.default[0].cidr_block : var.vpc_cidr
    redirector_vpc_cidr   = aws_vpc.redirector.cidr_block
    adaptix_private_ip    = aws_network_interface.adaptix.private_ip
    guacamole_private_ip  = aws_network_interface.guacamole.private_ip
    mythic_private_ip     = aws_network_interface.mythic.private_ip
    sliver_private_ip     = aws_network_interface.sliver.private_ip
    redirector_private_ip = aws_network_interface.redirector.private_ip
    redirector_public_ip  = aws_eip.redirector.public_ip
    windows_private_ip    = aws_network_interface.windows.private_ip
    kali_private_ip       = aws_network_interface.kali.private_ip
    adaptix_uri_prefix    = var.adaptix_uri_prefix
    c2_header_name        = var.c2_header_name
    c2_header_value       = local.c2_header_value
    adaptix_version       = var.adaptix_version
  })

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  lifecycle {
    ignore_changes = [user_data]
  }

  tags = {
    Name     = "${var.project_name}-adaptix"
    Role     = "c2"
    Hostname = "adaptix"
  }
}
