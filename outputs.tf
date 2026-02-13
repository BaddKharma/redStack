# outputs.tf - Output values after deployment

output "deployment_info" {
  description = "Full deployment details for all lab instances"
  value       = <<-EOT

  +---------------------------------------------------------------------+
  | 1. GUACAMOLE ACCESS PORTAL                                          |
  +---------------------------------------------------------------------+
    URL:          https://${aws_eip.guacamole.public_ip}/guacamole
    Public IP:    ${aws_eip.guacamole.public_ip}
    Private IP:   ${aws_instance.guacamole.private_ip}
    Username:     guacadmin
    Password:     ${nonsensitive(random_password.lab.result)}
    SSH (ext):    ssh -i ${var.ssh_key_name}.pem ubuntu@${aws_eip.guacamole.public_ip}
    SSH (int):    ssh ubuntu@${aws_instance.guacamole.private_ip}

  +---------------------------------------------------------------------+
  | 2. MYTHIC C2 TEAM SERVER (internal only)                            |
  +---------------------------------------------------------------------+
    Web UI:       https://${aws_instance.mythic.private_ip}:7443
    Private IP:   ${aws_instance.mythic.private_ip}
    Username:     admin
    Password:     ${nonsensitive(random_password.lab.result)}
    SSH (int):    ssh admin@${aws_instance.mythic.private_ip}
    Operator:     Port 7443 (Web UI via Windows/Guacamole)
    Guacamole:    Mythic C2 Server (SSH)

  +---------------------------------------------------------------------+
  | 3. SLIVER C2 SERVER (internal only)                                 |
  +---------------------------------------------------------------------+
    Private IP:   ${aws_instance.sliver.private_ip}
    Username:     ubuntu
    Password:     ${nonsensitive(random_password.lab.result)}
    SSH (int):    ssh ubuntu@${aws_instance.sliver.private_ip}
    Operator:     Port 31337 (gRPC multiplexer)
    Guacamole:    Sliver C2 Server (SSH)

  +---------------------------------------------------------------------+
  | 4. HAVOC C2 SERVER (internal only)                                  |
  +---------------------------------------------------------------------+
    Private IP:   ${aws_instance.havoc.private_ip}
    Username:     ubuntu
    Password:     ${nonsensitive(random_password.lab.result)}
    SSH (int):    ssh ubuntu@${aws_instance.havoc.private_ip}
    Operator:     Port 40056 (teamserver UI)
    Guacamole:    Havoc C2 Server (SSH)

  +---------------------------------------------------------------------+
  | 5. APACHE REDIRECTOR                                                |
  +---------------------------------------------------------------------+
    Public IP:    ${aws_eip.redirector.public_ip}
    Private IP:   ${aws_instance.redirector.private_ip}
    Domain:       ${var.redirector_domain != "" ? var.redirector_domain : "c2.example.com"}
    Username:     ubuntu
    Password:     ${nonsensitive(random_password.lab.result)}
    SSH (ext):    ssh -i ${var.ssh_key_name}.pem ubuntu@${aws_eip.redirector.public_ip}
    SSH (int):    ssh ubuntu@${aws_instance.redirector.private_ip}
    URI Routing:  ${var.mythic_uri_prefix}/ -> Mythic
                  ${var.sliver_uri_prefix}/ -> Sliver
                  ${var.havoc_uri_prefix}/ -> Havoc

  +---------------------------------------------------------------------+
  | 6. WINDOWS ATTACKER WORKSTATION                                     |
  +---------------------------------------------------------------------+
    Private IP:   ${aws_instance.windows.private_ip}
    Username:     Administrator
    Password:     ${aws_instance.windows.password_data != "" ? rsadecrypt(aws_instance.windows.password_data, file(var.ssh_private_key_path)) : "(not yet available)"}
    Access:       RDP via Guacamole
    Guacamole:    Windows 11 Attacker Workstation (RDP)

  EOT
}

output "network_architecture" {
  description = "Network architecture diagram with actual IPs"
  value       = <<-EOT

  +---------------------------------------------------------------------+
  |                     NETWORK ARCHITECTURE                            |
  +---------------------------------------------------------------------+

  VPC A - Team Server Infrastructure (${var.use_default_vpc ? "Default VPC" : var.vpc_cidr})
    Mythic Team Server      ${aws_instance.mythic.private_ip} (internal only)
    Sliver C2 Server        ${aws_instance.sliver.private_ip} (internal only)
    Havoc C2 Server         ${aws_instance.havoc.private_ip} (internal only)
    Guacamole Server        ${aws_eip.guacamole.public_ip} (public)
    Windows 11 Workstation  ${aws_instance.windows.private_ip} (internal only)

  VPC B - Redirector Infrastructure (${aws_vpc.redirector.cidr_block})
    Apache Redirector       ${aws_eip.redirector.public_ip} (public)

  VPC Peering: VPC A <-> VPC B

  Traffic Flow (URI Prefix Routing - ports 80/443):
    [Target] -> ${var.mythic_uri_prefix}/  -> ${aws_eip.redirector.public_ip} -> ${aws_instance.mythic.private_ip} (Mythic)
    [Target] -> ${var.sliver_uri_prefix}/  -> ${aws_eip.redirector.public_ip} -> ${aws_instance.sliver.private_ip} (Sliver)
    [Target] -> ${var.havoc_uri_prefix}/   -> ${aws_eip.redirector.public_ip} -> ${aws_instance.havoc.private_ip} (Havoc)

  Security Posture:
    [x] ALL C2 servers have NO public IPs (internal only)
    [x] C2 servers ONLY accept traffic from Redirector VPC (${aws_vpc.redirector.cidr_block})
    [x] Redirector in separate VPC (simulates external provider isolation)
    [x] Windows workstation isolated (RDP only from Guacamole)

  EOT
}
