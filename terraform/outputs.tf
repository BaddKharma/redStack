# outputs.tf - Output values after deployment

locals {
  deployment_info_content = <<-EOT

  +---------------------------------------------------------------------+
  | 1. GUACAMOLE PORTAL                                                 |
  +---------------------------------------------------------------------+
    URL:          https://${aws_eip.guacamole.public_ip}/guacamole
    Public IP:    ${aws_eip.guacamole.public_ip}
    Private IP:   ${aws_network_interface.guacamole.private_ip}
    UI Username:  guacadmin
    UI Password:  ${nonsensitive(random_password.lab.result)}
    SSH Username: admin
    SSH Password: ${nonsensitive(random_password.lab.result)}
    SSH (external): ssh -i ${var.ssh_key_name}.pem admin@${aws_eip.guacamole.public_ip}

  +---------------------------------------------------------------------+
  | 2. MYTHIC C2                                                        |
  +---------------------------------------------------------------------+
    Web UI:       https://mythic:7443  (open from the windows workstation via Guacamole)
    Private IP:   ${aws_network_interface.mythic.private_ip}
    SSH Username: admin
    SSH Password: ${nonsensitive(random_password.lab.result)}
    UI Username:  mythic_admin
    UI Password:  ${nonsensitive(random_password.lab.result)}
    URI Prefix:   ${var.mythic_uri_prefix}/
    C2 Header:    ${var.c2_header_name}: ${local.c2_header_value}
    Operator:     Port 7443 (Web UI via windows + Guacamole)
    Guacamole:    Mythic (SSH)

  +---------------------------------------------------------------------+
  | 3. SLIVER C2                                                        |
  +---------------------------------------------------------------------+
    Private IP:   ${aws_network_interface.sliver.private_ip}
    SSH Username: admin
    SSH Password: ${nonsensitive(random_password.lab.result)}
    Sliver Op:    admin (config at /home/admin/.sliver-client/configs/admin.cfg)
    URI Prefix:   ${var.sliver_uri_prefix}/
    C2 Header:    ${var.c2_header_name}: ${local.c2_header_value}
    Operator:     Port 31337 (gRPC multiplexer)
    Guacamole:    Sliver (SSH)

  +---------------------------------------------------------------------+
  | 4. ADAPTIX C2                                                       |
  +---------------------------------------------------------------------+
    Client URL:   https://adaptix:4321/adaptix  (open in AdaptixClient on the windows workstation)
    Private IP:   ${aws_network_interface.adaptix.private_ip}
    SSH Username: admin
    SSH Password: ${nonsensitive(random_password.lab.result)}
    Login User:   (any nickname)
    Login Pass:   ${nonsensitive(random_password.lab.result)}
    URI Prefix:   ${var.adaptix_uri_prefix}/
    C2 Header:    ${var.c2_header_name}: ${local.c2_header_value}
    Operator:     Port 4321 (AdaptixClient via windows + Guacamole RDP)
    Guacamole:    Adaptix (SSH)

  +---------------------------------------------------------------------+
  | 5. REDIRECTOR                                                       |
  +---------------------------------------------------------------------+
    Public IP:    ${aws_eip.redirector.public_ip}
    Private IP:   ${aws_network_interface.redirector.private_ip}
    Domain:       ${var.redirector_domain != "" ? var.redirector_domain : "(none)"}
    SSH Username: admin
    SSH Password: ${nonsensitive(random_password.lab.result)}
    SSH Access:   Guacamole > "Redirector (SSH)"  (recommended)
                  or: ssh -i ${var.ssh_key_name}.pem -J admin@${aws_eip.guacamole.public_ip} admin@redirector
    Note:         Public SSH on port 22 is NOT exposed; only 80/443 are reachable from the internet
    C2 Header:    ${var.c2_header_name}: ${local.c2_header_value}
    URI Routing:  ${var.mythic_uri_prefix}/ -> Mythic
                  ${var.sliver_uri_prefix}/ -> Sliver
                  ${var.adaptix_uri_prefix}/ -> Adaptix
    Decoy Page:   CloudEdge CDN maintenance (no header = decoy)
${var.enable_vpn_tunnel ? <<VPNINFO

  +---------------------------------------------------------------------+
  | 5b. vpnTUN ROUTING (OpenVPN + WireGuard)                            |
  +---------------------------------------------------------------------+
    Status:       ENABLED
    WG Server:    ${aws_network_interface.redirector.private_ip} (redirector, wg0: 10.100.0.1)
    WG Client:    ${aws_network_interface.guacamole.private_ip}  (guacamole, wg0: 10.100.0.2)
    Target CIDRs: ${join(", ", var.vpn_tunnel_cidrs)}
    VPN Service:  sudo systemctl {start|stop|status} vpn-tunnel    (on redirector)
    WG Status:    sudo wg show                                   (on redirector or guacamole)

    NOTE: WireGuard is configured automatically at boot, no pre-deploy key setup needed.

    Traffic path (internal -> CTF target):
      [internal lab host: windows / kali / mythic / sliver / adaptix]
        -> default VPC route -> guacamole (wg0 gateway, MASQUERADE)
        -> WireGuard tunnel (UDP 51820) -> redirector (wg0 server)
        -> tun0 (OpenVPN, MASQUERADE) -> CTF target

    Quick Start:
      1. Transfer .ovpn to windows via Guacamole:
         Guacamole sidebar (Ctrl+Alt+Shift) -> Devices -> upload .ovpn
      2. SCP to redirector from windows:
         scp lab.ovpn admin@${aws_network_interface.redirector.private_ip}:~/vpn/
      3. Start VPN service on redirector:
         sudo systemctl start vpn-tunnel
      4. Verify WireGuard tunnel is up:
         sudo wg show          (redirector: should list guacamole as peer with handshake time)
         sudo wg show          (guacamole: should list redirector as peer with handshake time)
      5. Verify routing from any internal machine:
         ping <ctf-target-ip>
VPNINFO
: ""}
  +---------------------------------------------------------------------+
  | 6. WINDOWS                                                          |
  +---------------------------------------------------------------------+
    Private IP:   ${aws_network_interface.windows.private_ip}
    Username:     Administrator
    Password:     ${try(rsadecrypt(aws_instance.windows.password_data, file(var.ssh_private_key_path)), "(not yet available)")}
    Access:       RDP via Guacamole
    Guacamole:    Windows (RDP)

  +---------------------------------------------------------------------+
  | 7. KALI                                                             |
  +---------------------------------------------------------------------+
    Private IP:   ${aws_network_interface.kali.private_ip}
    Mode:         ${upper(var.kali_deployment_mode)}
    SSH Username: admin
    SSH Password: ${nonsensitive(random_password.lab.result)}
    Guacamole:    Kali (SSH)${var.kali_deployment_mode == "gui" ? " | Kali (XRDP)" : ""}
    Tools:        AD/enum lineup pre-installed at provision; GUI mode + extra metapackages documented in the wiki

  EOT

network_architecture_content = <<-EOT

  +---------------------------------------------------------------------+
  |                     NETWORK ARCHITECTURE                            |
  +---------------------------------------------------------------------+

  VPC A: Teamserver (${var.use_default_vpc ? "Default VPC" : var.vpc_cidr})
  +-------------------------+-------------------------------------------+
  |  mythic                 |  ${aws_network_interface.mythic.private_ip}
  |  sliver                 |  ${aws_network_interface.sliver.private_ip}
  |  adaptix                |  ${aws_network_interface.adaptix.private_ip}
  |  guacamole              |  ${aws_network_interface.guacamole.private_ip} (priv)  /  ${aws_eip.guacamole.public_ip} (pub)
  |  windows                |  ${aws_network_interface.windows.private_ip}
  |  kali                   |  ${aws_network_interface.kali.private_ip} (${var.kali_deployment_mode})
  +-------------------------+-------------------------------------------+

  VPC B: Redirector (${aws_vpc.redirector.cidr_block})
  +-------------------------+-------------------------------------------+
  |  redirector             |  ${aws_network_interface.redirector.private_ip} (priv)  /  ${aws_eip.redirector.public_ip} (pub)
  +-------------------------+-------------------------------------------+

  VPC Peering: VPC A <-> VPC B

  C2 Traffic Flow  (ports 80/443, header + URI validation):

    [Target]
       |
       v  HTTPS / HTTP
    ${aws_eip.redirector.public_ip}  (redirector)
       |
       |  Required:  ${var.c2_header_name}: ${local.c2_header_value}
       |
       +--  ${format("%-25s", format("%s/", var.mythic_uri_prefix))}-->  ${format("%-15s", aws_network_interface.mythic.private_ip)}  (mythic)
       +--  ${format("%-25s", format("%s/", var.sliver_uri_prefix))}-->  ${format("%-15s", aws_network_interface.sliver.private_ip)}  (sliver)
       +--  ${format("%-25s", format("%s/", var.adaptix_uri_prefix))}-->  ${format("%-15s", aws_network_interface.adaptix.private_ip)}  (adaptix)
       +--  ${format("%-25s", "[no valid header]")}-->  Decoy page (CloudEdge CDN)

${var.enable_vpn_tunnel ? <<VPNARCH

  vpnTUN Routing (Cyber Ranges via OpenVPN + WireGuard):
  +-------------------------+-------------------------------------------+
  |  WG Server (redirector) |  wg0: 10.100.0.1
  |  WG Client (guacamole)  |  wg0: 10.100.0.2
  |  Routed CIDRs           |  ${join(", ", var.vpn_tunnel_cidrs)}
  +-------------------------+-------------------------------------------+

    [Internal Machine]
       |
       v  VPC route (vpnTUN CIDRs) -> guacamole ENI
    guacamole  (wg0: 10.100.0.2, MASQUERADE)
       |
       v  WireGuard tunnel (UDP 51820)
    redirector  (wg0: 10.100.0.1)
       |
       v  tun0 (OpenVPN, MASQUERADE)
    [CTF Target]

VPNARCH
: ""}
  EOT
}

output "deployment_info" {
  description = "Full deployment details for all lab instances"
  value       = local.deployment_info_content
}

output "dedication" {
  value     = "Rm9yIEZldiwgTXkgRm9yZXZlci4="
  sensitive = true
}

output "network_architecture" {
  description = "Network architecture diagram with actual IPs"
  value       = local.network_architecture_content
}

resource "local_file" "deployment_info" {
  filename = "${path.root}/../deployment_info.txt"
  content  = "${local.deployment_info_content}\n${local.network_architecture_content}"
}
