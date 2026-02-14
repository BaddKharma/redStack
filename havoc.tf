# havoc.tf - Havoc C2 server infrastructure (internal only, no public IP)

# ============================================================================
# HAVOC C2 SECURITY GROUP
# ============================================================================

resource "aws_security_group" "havoc" {
  name        = "${var.project_name}-havoc-sg"
  description = "Security group for Havoc C2 server (internal only)"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.project_name}-havoc-sg"
  }
}

# SSH from instructor
resource "aws_security_group_rule" "havoc_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.localPub_ip]
  description       = "SSH access for instructor"
  security_group_id = aws_security_group.havoc.id
}

# SSH from Guacamole (web-based SSH access)
resource "aws_security_group_rule" "havoc_ssh_from_guacamole" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.guacamole.id
  description              = "SSH from Guacamole for web-based access"
  security_group_id        = aws_security_group.havoc.id
}

# HTTP C2 from redirector only (via VPC peering)
resource "aws_security_group_rule" "havoc_http_from_redirector" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "HTTP C2 from redirector via VPC peering"
  security_group_id = aws_security_group.havoc.id
}

# HTTPS C2 from redirector only (via VPC peering)
resource "aws_security_group_rule" "havoc_https_from_redirector" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "HTTPS C2 from redirector via VPC peering"
  security_group_id = aws_security_group.havoc.id
}

# Havoc teamserver from Windows workstation (operator UI)
resource "aws_security_group_rule" "havoc_teamserver_from_windows" {
  type                     = "ingress"
  from_port                = 40056
  to_port                  = 40056
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.windows.id
  description              = "Havoc teamserver from Windows operator workstation"
  security_group_id        = aws_security_group.havoc.id
}

# Havoc teamserver from Guacamole (operator access via web)
resource "aws_security_group_rule" "havoc_teamserver_from_guacamole" {
  type                     = "ingress"
  from_port                = 40056
  to_port                  = 40056
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.guacamole.id
  description              = "Havoc teamserver from Guacamole"
  security_group_id        = aws_security_group.havoc.id
}

# All traffic from main VPC (internal lab connectivity)
resource "aws_security_group_rule" "havoc_all_from_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [var.use_default_vpc ? data.aws_vpc.default[0].cidr_block : var.vpc_cidr]
  description       = "All internal lab traffic from main VPC"
  security_group_id = aws_security_group.havoc.id
}

# All traffic from redirector VPC (cross-VPC lab connectivity)
resource "aws_security_group_rule" "havoc_all_from_redirector_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "All traffic from redirector VPC for lab connectivity"
  security_group_id = aws_security_group.havoc.id
}

# Outbound - allow all
resource "aws_security_group_rule" "havoc_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.havoc.id
}

# ============================================================================
# HAVOC NETWORK INTERFACE
# ============================================================================

resource "aws_network_interface" "havoc" {
  subnet_id       = local.subnet_id
  security_groups = [aws_security_group.havoc.id]
  tags            = { Name = "${var.project_name}-havoc-eni" }
}

# ============================================================================
# HAVOC C2 EC2 INSTANCE (no public IP)
# ============================================================================

resource "aws_instance" "havoc" {
  ami           = data.aws_ami.debian12.id
  instance_type = var.havoc_instance_type
  key_name      = var.ssh_key_name

  network_interface {
    network_interface_id = aws_network_interface.havoc.id
    device_index         = 0
  }

  root_block_device {
    volume_size           = 25
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/setup_scripts/havoc_setup.sh", {
    ssh_password          = random_password.lab.result
    redirector_vpc_cidr   = aws_vpc.redirector.cidr_block
    havoc_private_ip      = aws_network_interface.havoc.private_ip
    guacamole_private_ip  = aws_network_interface.guacamole.private_ip
    mythic_private_ip     = aws_network_interface.mythic.private_ip
    sliver_private_ip     = aws_network_interface.sliver.private_ip
    redirector_private_ip = aws_network_interface.redirector.private_ip
    windows_private_ip    = aws_network_interface.windows.private_ip
  })

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project_name}-havoc-server"
    Role = "c2-havoc"
  }
}
