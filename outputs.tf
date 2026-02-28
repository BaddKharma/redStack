# outputs.tf - Output values after deployment

output "deployment_info" {
  description = "Full deployment details for all lab instances"
  value = <<-EOT

  +---------------------------------------------------------------------+
  | 1. GUACAMOLE ACCESS PORTAL                                          |
  +---------------------------------------------------------------------+
    URL:          https://${aws_eip.guacamole.public_ip}/guacamole
    Public IP:    ${aws_eip.guacamole.public_ip}
    Private IP:   ${aws_network_interface.guacamole.private_ip}
    Username:     guacadmin
    Password:     ${nonsensitive(random_password.lab.result)}
    SSH (ext):    ssh -i ${var.ssh_key_name}.pem admin@${aws_eip.guacamole.public_ip}
    SSH (int):    ssh admin@${aws_network_interface.guacamole.private_ip}

  +---------------------------------------------------------------------+
  | 2. MYTHIC C2 TEAM SERVER (internal only)                            |
  +---------------------------------------------------------------------+
    Web UI:       https://${aws_network_interface.mythic.private_ip}:7443
    Private IP:   ${aws_network_interface.mythic.private_ip}
    Username:     admin
    Password:     ${nonsensitive(random_password.lab.result)}
    SSH (int):    ssh admin@${aws_network_interface.mythic.private_ip}
    Operator:     Port 7443 (Web UI via Windows/Guacamole)
    Guacamole:    Mythic C2 Server (SSH)

  +---------------------------------------------------------------------+
  | 3. SLIVER C2 SERVER (internal only)                                 |
  +---------------------------------------------------------------------+
    Private IP:   ${aws_network_interface.sliver.private_ip}
    Username:     admin
    Password:     ${nonsensitive(random_password.lab.result)}
    SSH (int):    ssh admin@${aws_network_interface.sliver.private_ip}
    Operator:     Port 31337 (gRPC multiplexer)
    Guacamole:    Sliver C2 Server (SSH)

  +---------------------------------------------------------------------+
  | 4. HAVOC C2 SERVER (internal only)                                  |
  +---------------------------------------------------------------------+
    Private IP:   ${aws_network_interface.havoc.private_ip}
    Username:     admin
    Password:     ${nonsensitive(random_password.lab.result)}
    SSH (int):    ssh admin@${aws_network_interface.havoc.private_ip}
    Op User:      operator
    Op Password:  ${nonsensitive(random_password.lab.result)}
    Guacamole:    Havoc C2 Desktop (VNC) | Havoc C2 Server (SSH)

  +---------------------------------------------------------------------+
  | 5. APACHE REDIRECTOR                                                |
  +---------------------------------------------------------------------+
    Public IP:    ${aws_eip.redirector.public_ip}
    Private IP:   ${aws_network_interface.redirector.private_ip}
    Domain:       ${var.redirector_domain != "" ? var.redirector_domain : "c2.example.com"}
    Username:     admin
    Password:     ${nonsensitive(random_password.lab.result)}
    SSH (ext):    ssh -i ${var.ssh_key_name}.pem admin@${aws_eip.redirector.public_ip}
    SSH (int):    ssh admin@${aws_network_interface.redirector.private_ip}
    C2 Header:    ${var.c2_header_name}: ${local.c2_header_value}
    URI Routing:  ${var.mythic_uri_prefix}/ -> Mythic
                  ${var.sliver_uri_prefix}/ -> Sliver
                  ${var.havoc_uri_prefix}/ -> Havoc
    Decoy Page:   CloudEdge CDN maintenance (no header = decoy)
${var.enable_external_vpn ? <<-VPNINFO

  +---------------------------------------------------------------------+
  | 5b. EXTERNAL VPN ROUTING (OpenVPN + WireGuard)                      |
  +---------------------------------------------------------------------+
    Status:       ENABLED
    WG Server:    ${aws_network_interface.redirector.private_ip} (redirector, wg0: 10.100.0.1)
    WG Client:    ${aws_network_interface.guacamole.private_ip}  (guacamole, wg0: 10.100.0.2)
    Target CIDRs: ${join(", ", var.external_vpn_cidrs)}
    VPN Service:  sudo systemctl {start|stop|status} ext-vpn    (on redirector)
    WG Status:    sudo wg show                                   (on redirector or guacamole)

    NOTE: WireGuard is configured automatically at boot — no pre-deploy key setup needed.

    Traffic path (internal -> CTF target):
      [Teamserver/WIN-OPERATOR]
        -> default VPC route -> guacamole (wg0 gateway, MASQUERADE)
        -> WireGuard tunnel (UDP 51820) -> redirector (wg0 server)
        -> tun0 (OpenVPN, MASQUERADE) -> CTF target

    Quick Start:
      1. Transfer .ovpn to WIN-OPERATOR via Guacamole:
         Guacamole sidebar (Ctrl+Alt+Shift) -> Devices -> upload .ovpn
      2. SCP to redirector from WIN-OPERATOR:
         scp lab.ovpn admin@${aws_network_interface.redirector.private_ip}:~/vpn/
      3. Start VPN service on redirector:
         sudo systemctl start ext-vpn
      4. Verify WireGuard tunnel is up:
         sudo wg show          (redirector: should list guacamole as peer with handshake time)
         sudo wg show          (guacamole: should list redirector as peer with handshake time)
      5. Verify routing from any internal machine:
         ping <ctf-target-ip>
VPNINFO
: ""}
  +---------------------------------------------------------------------+
  | 6. WINDOWS OPERATOR WORKSTATION                                     |
  +---------------------------------------------------------------------+
    Private IP:   ${aws_network_interface.windows.private_ip}
    Username:     Administrator
    Password:     ${try(rsadecrypt(aws_instance.windows.password_data, file(var.ssh_private_key_path)), "(not yet available)")}
    Access:       RDP via Guacamole
    Guacamole:    Windows Operator Workstation (RDP)

  EOT
}

output "network_architecture" {
  description = "Network architecture diagram with actual IPs"
  value = <<-EOT

  +---------------------------------------------------------------------+
  |                     NETWORK ARCHITECTURE                            |
  +---------------------------------------------------------------------+

  VPC A - Team Server Infrastructure (${var.use_default_vpc ? "Default VPC" : var.vpc_cidr})
    Mythic Team Server      ${aws_network_interface.mythic.private_ip} (internal only)
    Sliver C2 Server        ${aws_network_interface.sliver.private_ip} (internal only)
    Havoc C2 Server         ${aws_network_interface.havoc.private_ip} (internal only)
    Guacamole Server        ${aws_eip.guacamole.public_ip} (public)
    Windows Operator        ${aws_network_interface.windows.private_ip} (internal only)

  VPC B - Redirector Infrastructure (${aws_vpc.redirector.cidr_block})
    Apache Redirector       ${aws_eip.redirector.public_ip} (public)

  VPC Peering: VPC A <-> VPC B

  Traffic Flow (Header + URI Validation - ports 80/443):
    [Target] -> ${var.mythic_uri_prefix}/  -> ${aws_eip.redirector.public_ip} -> ${aws_network_interface.mythic.private_ip} (Mythic)
    [Target] -> ${var.sliver_uri_prefix}/  -> ${aws_eip.redirector.public_ip} -> ${aws_network_interface.sliver.private_ip} (Sliver)
    [Target] -> ${var.havoc_uri_prefix}/   -> ${aws_eip.redirector.public_ip} -> ${aws_network_interface.havoc.private_ip} (Havoc)
    Required:   ${var.c2_header_name}: ${local.c2_header_value}
    No header:  Decoy page (CloudEdge CDN maintenance)

${var.enable_external_vpn ? <<-VPNARCH

  External VPN Routing (HTB/THM/VulnLabs):
    [Internal Machine] -> Guacamole (wg0: 10.100.0.2) -> WireGuard (UDP 51820)
                      -> Redirector (wg0: 10.100.0.1) -> tun0 (OpenVPN) -> [CTF Targets]
    Routed CIDRs: ${join(", ", var.external_vpn_cidrs)}

  VPN Security:
    [x] source_dest_check disabled on redirector + guacamole ENIs (packet forwarding)
    [x] Double NAT: guacamole MASQUERADE on wg0 + redirector MASQUERADE on tun0
    [x] IP forwarding enabled on redirector and guacamole
    [x] redirect-gateway filtered on ext-vpn (preserves VPC peering + C2 connectivity)
    [x] WireGuard keys generated on Guacamole at boot — no pre-deploy setup required
VPNARCH
: ""}
  EOT
}
