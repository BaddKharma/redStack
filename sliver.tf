# sliver.tf - Sliver C2 server infrastructure (internal only, no public IP)

# ============================================================================
# SLIVER C2 SECURITY GROUP
# ============================================================================

resource "aws_security_group" "sliver" {
  name        = "${var.project_name}-sliver-sg"
  description = "Security group for Sliver C2 server (internal only)"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.project_name}-sliver-sg"
  }
}

# SSH from instructor
resource "aws_security_group_rule" "sliver_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.localPub_ip]
  description       = "SSH access for instructor"
  security_group_id = aws_security_group.sliver.id
}

# SSH from Guacamole (web-based SSH access)
resource "aws_security_group_rule" "sliver_ssh_from_guacamole" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.guacamole.id
  description              = "SSH from Guacamole for web-based access"
  security_group_id        = aws_security_group.sliver.id
}

# HTTP C2 from redirector only (via VPC peering)
resource "aws_security_group_rule" "sliver_http_from_redirector" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "HTTP C2 from redirector via VPC peering"
  security_group_id = aws_security_group.sliver.id
}

# HTTPS C2 from redirector only (via VPC peering)
resource "aws_security_group_rule" "sliver_https_from_redirector" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "HTTPS C2 from redirector via VPC peering"
  security_group_id = aws_security_group.sliver.id
}

# Sliver multiplexer/gRPC from Windows workstation (operator connections)
resource "aws_security_group_rule" "sliver_multiplexer_from_windows" {
  type                     = "ingress"
  from_port                = 31337
  to_port                  = 31337
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.windows.id
  description              = "Sliver multiplexer from Windows operator workstation"
  security_group_id        = aws_security_group.sliver.id
}

# Sliver multiplexer from Guacamole (operator access via web SSH)
resource "aws_security_group_rule" "sliver_multiplexer_from_guacamole" {
  type                     = "ingress"
  from_port                = 31337
  to_port                  = 31337
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.guacamole.id
  description              = "Sliver multiplexer from Guacamole"
  security_group_id        = aws_security_group.sliver.id
}

# Outbound - allow all
resource "aws_security_group_rule" "sliver_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.sliver.id
}

# ============================================================================
# SLIVER C2 EC2 INSTANCE (no public IP)
# ============================================================================

resource "aws_instance" "sliver" {
  ami           = data.aws_ami.ubuntu2204.id
  instance_type = var.sliver_instance_type
  key_name      = var.ssh_key_name
  subnet_id     = local.subnet_id

  vpc_security_group_ids = [aws_security_group.sliver.id]

  root_block_device {
    volume_size           = 25
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/setup_scripts/sliver_setup.sh", {
    ssh_password        = random_password.lab.result
    redirector_vpc_cidr = aws_vpc.redirector.cidr_block
  })

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "${var.project_name}-sliver-server"
    Role = "c2-sliver"
  }
}
