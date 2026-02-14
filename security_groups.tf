# security_groups.tf - Security group definitions

# ============================================================================
# MYTHIC TEAM SERVER SECURITY GROUP
# ============================================================================

resource "aws_security_group" "mythic" {
  name        = "${var.project_name}-mythic-sg"
  description = "Security group for Mythic C2 team server"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.project_name}-mythic-sg"
  }
}

# SSH from instructor only
resource "aws_security_group_rule" "mythic_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.localPub_ip]
  description       = "SSH access for instructor"
  security_group_id = aws_security_group.mythic.id
}

# SSH from Guacamole (for web-based SSH access)
resource "aws_security_group_rule" "mythic_ssh_from_guacamole" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.guacamole.id
  description              = "SSH from Guacamole for web-based access"
  security_group_id        = aws_security_group.mythic.id
}

# Mythic Web UI from Windows client only (not publicly accessible)
resource "aws_security_group_rule" "mythic_web_ui_from_windows" {
  type                     = "ingress"
  from_port                = 7443
  to_port                  = 7444
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.windows.id
  description              = "Mythic Web UI access from Windows client only"
  security_group_id        = aws_security_group.mythic.id
}

# NOTE: HTTP/HTTPS C2 rules are defined in redirector.tf
# They are restricted to redirector IP only for operational security

# All traffic from main VPC (internal lab connectivity)
resource "aws_security_group_rule" "mythic_all_from_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [var.use_default_vpc ? data.aws_vpc.default[0].cidr_block : var.vpc_cidr]
  description       = "All internal lab traffic from main VPC"
  security_group_id = aws_security_group.mythic.id
}

# All traffic from redirector VPC (cross-VPC lab connectivity)
resource "aws_security_group_rule" "mythic_all_from_redirector_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "All traffic from redirector VPC for lab connectivity"
  security_group_id = aws_security_group.mythic.id
}

# Outbound - allow all
resource "aws_security_group_rule" "mythic_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.mythic.id
}

# ============================================================================
# GUACAMOLE SERVER SECURITY GROUP
# ============================================================================

resource "aws_security_group" "guacamole" {
  name        = "${var.project_name}-guacamole-sg"
  description = "Security group for Guacamole attacker access portal"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.project_name}-guacamole-sg"
  }
}

# SSH from instructor only
resource "aws_security_group_rule" "guacamole_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.localPub_ip]
  description       = "SSH access for instructor"
  security_group_id = aws_security_group.guacamole.id
}

# SSH from self (for Guacamole web-based SSH to own host)
resource "aws_security_group_rule" "guacamole_ssh_self" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.guacamole.id
  description              = "SSH from Guacamole containers to host"
  security_group_id        = aws_security_group.guacamole.id
}

# HTTPS from anywhere (attacker access)
resource "aws_security_group_rule" "guacamole_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTPS access for attackers"
  security_group_id = aws_security_group.guacamole.id
}

# HTTP (redirect to HTTPS)
resource "aws_security_group_rule" "guacamole_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTP redirect to HTTPS"
  security_group_id = aws_security_group.guacamole.id
}

# All traffic from main VPC (internal lab connectivity)
resource "aws_security_group_rule" "guacamole_all_from_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [var.use_default_vpc ? data.aws_vpc.default[0].cidr_block : var.vpc_cidr]
  description       = "All internal lab traffic from main VPC"
  security_group_id = aws_security_group.guacamole.id
}

# All traffic from redirector VPC (cross-VPC lab connectivity)
resource "aws_security_group_rule" "guacamole_all_from_redirector_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "All traffic from redirector VPC for lab connectivity"
  security_group_id = aws_security_group.guacamole.id
}

# Outbound - allow all
resource "aws_security_group_rule" "guacamole_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.guacamole.id
}

# ============================================================================
# WINDOWS CLIENT SECURITY GROUP
# ============================================================================

resource "aws_security_group" "windows" {
  name        = "${var.project_name}-windows-sg"
  description = "Security group for Windows 11 attacker workstation"
  vpc_id      = local.vpc_id

  tags = {
    Name = "${var.project_name}-windows-sg"
  }
}

# RDP from Guacamole only
resource "aws_security_group_rule" "windows_rdp" {
  type                     = "ingress"
  from_port                = 3389
  to_port                  = 3389
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.guacamole.id
  description              = "RDP from Guacamole server only"
  security_group_id        = aws_security_group.windows.id
}

# Temporary: RDP from instructor for initial setup (remove after Guacamole config)
resource "aws_security_group_rule" "windows_rdp_instructor" {
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = [var.localPub_ip]
  description       = "TEMPORARY: RDP from instructor for initial setup"
  security_group_id = aws_security_group.windows.id
}

# All traffic from main VPC (internal lab connectivity)
resource "aws_security_group_rule" "windows_all_from_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [var.use_default_vpc ? data.aws_vpc.default[0].cidr_block : var.vpc_cidr]
  description       = "All internal lab traffic from main VPC"
  security_group_id = aws_security_group.windows.id
}

# All traffic from redirector VPC (cross-VPC lab connectivity)
resource "aws_security_group_rule" "windows_all_from_redirector_vpc" {
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [aws_vpc.redirector.cidr_block]
  description       = "All traffic from redirector VPC for lab connectivity"
  security_group_id = aws_security_group.windows.id
}

# Outbound - allow all (attacker needs internet)
resource "aws_security_group_rule" "windows_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.windows.id
}
