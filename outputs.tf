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
    Username:     attacker
    Password:     ${nonsensitive(random_password.lab.result)}
    Access:       RDP via Guacamole
    Guacamole:    Windows 11 Attacker Workstation (RDP)

  EOT
}
