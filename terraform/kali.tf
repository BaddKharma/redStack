# kali.tf - Kali Linux operator workstation (headless or GUI mode)

locals {
  # Auto-pick instance type and root volume size from kali_deployment_mode unless
  # the operator explicitly overrides via kali_instance_type / kali_volume_size.
  kali_instance_type = var.kali_instance_type != "" ? var.kali_instance_type : (
    var.kali_deployment_mode == "gui" ? "t3.medium" : "t3.medium"
  )
  kali_volume_size = var.kali_volume_size != 0 ? var.kali_volume_size : (
    var.kali_deployment_mode == "gui" ? 50 : 30
  )
}

# ============================================================================
# KALI NETWORK INTERFACE
# ============================================================================

resource "aws_network_interface" "kali" {
  subnet_id       = local.subnet_id
  security_groups = [aws_security_group.kali.id]
  tags            = { Name = "${var.project_name}-kali-eni" }
}

# ============================================================================
# KALI OPERATOR EC2 INSTANCE (no public IP, accessed via Guacamole)
# ============================================================================

resource "aws_instance" "kali" {
  ami           = data.aws_ami.kali.id
  instance_type = local.kali_instance_type
  key_name      = var.ssh_key_name

  network_interface {
    network_interface_id = aws_network_interface.kali.id
    device_index         = 0
  }

  root_block_device {
    volume_size           = local.kali_volume_size
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = templatefile("${path.module}/setup_scripts/kali_setup.sh", {
    ssh_password          = random_password.lab.result
    kali_deployment_mode  = var.kali_deployment_mode
    redirector_vpc_cidr   = aws_vpc.redirector.cidr_block
    kali_private_ip       = aws_network_interface.kali.private_ip
    guacamole_private_ip  = aws_network_interface.guacamole.private_ip
    mythic_private_ip     = aws_network_interface.mythic.private_ip
    sliver_private_ip     = aws_network_interface.sliver.private_ip
    adaptix_private_ip      = aws_network_interface.adaptix.private_ip
    redirector_private_ip = aws_network_interface.redirector.private_ip
    windows_private_ip    = aws_network_interface.windows.private_ip
  })

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required" # IMDSv2 only
  }

  tags = {
    Name     = "${var.project_name}-kali"
    Role     = "workstation"
    Hostname = "kali"
    Mode     = var.kali_deployment_mode
  }
}
