<!-- markdownlint-disable MD001 MD012 MD013 MD028 MD033 MD036 MD040 MD051 MD060 -->
<!-- Lint suppressions: GFM features (alerts, inline HTML, anchor slugs) and table style. -->
<!-- Documented rationale lives at assets/markdownlint.jsonc. -->

# redStack

![redStack Banner](assets/redStack-banner.png)

<p align="center"><strong>Attending DEF CON 34?</strong> <a href="https://github.com/BaddKharma/redStack-defcon34">Click here</a> to see presentation times and the prerequisites needed for the workshop.</p>

<p align="center">
  <img src="https://img.shields.io/badge/DEF%20CON%2034-black?logo=github" alt="DEF CON 34">
  <a href="https://adversaryvillage.org/adversary-events/DEFCON-34/"><img src="https://img.shields.io/badge/Adversary%20Village-purple" alt="Adversary Village"></a>
  <a href="https://redteamvillage.io/"><img src="https://img.shields.io/badge/Red%20Team%20Village-red" alt="Red Team Village"></a>
  <a href="https://www.noobvillage.org/"><img src="https://img.shields.io/badge/Noob%20Village-green" alt="Noob Village"></a>
  <a href="https://github.com/BaddKharma/redStack-defcon34"><img src="https://img.shields.io/badge/Session%20Docs%20%26%20Prereqs-1f6feb?logo=github" alt="Session Docs &amp; Prereqs"></a>
</p>

> A self-contained Boot-to-Breach lab on AWS. Deploy a full red-team training environment in ~45 minutes: three C2 frameworks (Mythic, Sliver, Adaptix), an Apache redirector, a Kali workstation, a Windows workstation, and a Guacamole portal. Two peered VPCs, header + URI gating, scanner blocking, optional OpenVPN routing for cyber ranges (Hack Smarter Labs is the featured partner platform; HTB, VulnLab, and OffSec also supported).

**📖 [Full documentation lives in the redStack Wiki →](https://github.com/BaddKharma/redStack/wiki)**

The wiki is the de facto operator handbook. This README is a thin landing page so you can find your way in. Everything you need to deploy, verify, run the C2 walkthroughs, troubleshoot, or extend the lab lives there.

---

> [!IMPORTANT]
> redStack is not a tutorial on how to use C2 frameworks. It's an environment that removes the infrastructure hurdle so you can focus on learning. **This lab is strictly for authorized training and lab environments only** (cyber ranges, self-hosted environments, personal lab VMs, etc.). Not intended for use in real-world engagements or against targets you do not own and have explicit written permission to test.

> [!CAUTION]
> **AWS TOS: use at your own risk.** Hosting C2 infrastructure on AWS may raise concerns under the [AWS Acceptable Use Policy](https://aws.amazon.com/aup/). Before deploying, review the AUP and submit the [AWS Penetration Testing / Simulated Events request form](https://aws.amazon.com/security/penetration-testing/). As long as you're using redStack exclusively for personal lab work and authorized training platforms, you're generally in the clear. To be safe, run redStack from a dedicated, single-purpose throwaway AWS account.

---

## Deploy in 5 Steps

| # | What | Where |
|---|------|-------|
| 1 | First-time AWS setup (account, IAM, CLI, SSH key, Kali Marketplace subscription) | **[Prerequisites](https://github.com/BaddKharma/redStack/wiki/02.-Prerequisites)** |
| 2 | Pick open or closed environment | **[Deployment Modes](https://github.com/BaddKharma/redStack/wiki/03.-Deployment-Architecture)** |
| 3 | Configure tfvars and `terraform apply` | **[Deploy](https://github.com/BaddKharma/redStack/wiki/04.-Deploying-Terraform)** |
| 4 | Confirm Guacamole + Windows + internal DNS | **[Verify](https://github.com/BaddKharma/redStack/wiki/05.-Verify)** |
| 5 | Land first beacon: pick a C2 | **[Mythic](https://github.com/BaddKharma/redStack/wiki/10.-Mythic)** · **[Sliver](https://github.com/BaddKharma/redStack/wiki/11.-Sliver)** · **[Adaptix](https://github.com/BaddKharma/redStack/wiki/12.-Adaptix)** |

**Total time:** ~30-60 minutes on first deploy. Subsequent deploys: ~20-30 minutes.

**Returning operator?** [Quick-Start](https://github.com/BaddKharma/redStack/wiki/01.-Quick-Start) is the abbreviated path.

---

## What Gets Deployed

Seven EC2 instances across two peered VPCs. Two have public Elastic IPs (Guacamole portal + redirector); everything else is reachable only through Guacamole.

| Hostname | Role | Public IP |
|----------|------|-----------|
| `guac` | Guacamole portal (web SSH/RDP/VNC) | Yes |
| `redirector` | Apache reverse proxy + C2 frontend | EIP exposes 80/443 only |
| `mythic` | Mythic C2 server | No |
| `sliver` | Sliver C2 server | No |
| `adaptix` | Adaptix C2 server + desktop (VNC) | No |
| `windows` | Windows Server 2022 workstation | No |
| `kali` | Kali Linux workstation (AD enum + attack toolset) | No |

Full inventory and sizing details: **[Lab-Inventory](https://github.com/BaddKharma/redStack/wiki/07.-Lab-Inventory)**.
Architecture diagram: **[Lab-Architecture](https://github.com/BaddKharma/redStack/wiki/03.-Deployment-Architecture)**.

---

## Cost

Roughly **$0.27/hour** of compute while running. With `terraform destroy` between sessions (recommended), expected monthly cost is **~$15-20/month** for typical 5-10 hr/wk study cadence. Full breakdown including stop-vs-destroy tradeoffs: **[Cost-Management](https://github.com/BaddKharma/redStack/wiki/16.-Cost-Management)**.

> [!CAUTION]
> Forgetting a deployed lab is the #1 cause of unexpected AWS bills. Set a CloudWatch billing alarm before your first `terraform apply`.

---

## When Something Breaks

**[Troubleshooting](https://github.com/BaddKharma/redStack/wiki/17.-Troubleshooting)** covers the failure modes that actually come up: Mythic SSL cert, Sliver missing, Adaptix build failed, agent not calling back, Marketplace `OptInRequired`, VPC limits, `redirect.rules` download issues, Kali user rename, `ssh -R` binding behavior, and more.

---

## Wiki Page Map

**Getting started:** [Home](https://github.com/BaddKharma/redStack/wiki) · [Quick-Start](https://github.com/BaddKharma/redStack/wiki/01.-Quick-Start) · [Prerequisites](https://github.com/BaddKharma/redStack/wiki/02.-Prerequisites) · [Deployment Modes](https://github.com/BaddKharma/redStack/wiki/03.-Deployment-Architecture) · [Deploy](https://github.com/BaddKharma/redStack/wiki/04.-Deploying-Terraform) · [Verify](https://github.com/BaddKharma/redStack/wiki/05.-Verify) · [First-Run](https://github.com/BaddKharma/redStack/wiki/06.-First-Run)

**Reference:** [Lab-Architecture](https://github.com/BaddKharma/redStack/wiki/03.-Deployment-Architecture) · [Lab-Inventory](https://github.com/BaddKharma/redStack/wiki/07.-Lab-Inventory) · [Guacamole](https://github.com/BaddKharma/redStack/wiki/08.-Guacamole) · [Cost-Management](https://github.com/BaddKharma/redStack/wiki/16.-Cost-Management)

**C2 backends:** [Mythic](https://github.com/BaddKharma/redStack/wiki/10.-Mythic) · [Sliver](https://github.com/BaddKharma/redStack/wiki/11.-Sliver) · [Adaptix](https://github.com/BaddKharma/redStack/wiki/12.-Adaptix)

**Workstations:** [Windows](https://github.com/BaddKharma/redStack/wiki/13.-Windows) · [Kali](https://github.com/BaddKharma/redStack/wiki/14.-Kali)

**Infrastructure:** [Guacamole](https://github.com/BaddKharma/redStack/wiki/08.-Guacamole) · [Redirector](https://github.com/BaddKharma/redStack/wiki/09.-Redirector) · [OpenVPN-Tunnel-Environments](https://github.com/BaddKharma/redStack/wiki/15.-OpenVPN-Tunnel-Environments)

**Help:** [Troubleshooting](https://github.com/BaddKharma/redStack/wiki/17.-Troubleshooting)

---

## Repository Layout

```
redStack/
├── README.md                 This file (the landing page)
├── LICENSE                   MIT + Commons Clause (also inlined below)
├── assets/                   Static images (banner)
├── rs-rsa-key.pem            Your AWS SSH key (gitignored, place here)
└── terraform/                All Terraform code
    ├── main.tf               VPC, subnets, ENIs, Mythic, Guacamole, Windows
    ├── variables.tf          Input variables
    ├── security_groups.tf    Per-host security groups
    ├── sliver.tf             Sliver SG, ENI, instance
    ├── adaptix.tf              Adaptix SG, ENI, instance
    ├── redirector.tf         Redirector VPC, peering, SG, ENI, instance
    ├── kali.tf               Kali SG, ENI, instance
    ├── outputs.tf            deployment_info + network_architecture
    ├── terraform.tfvars      Your local config (gitignored)
    ├── terraform.tfvars.example  Sample config
    └── setup_scripts/        Cloud-init scripts templated by templatefile()
```

The Terraform code is one file per role: Sliver, Adaptix, Redirector, and Kali each own their own `.tf`; Mythic / Guacamole / Windows live in `main.tf` alongside the shared VPC scaffolding. Setup scripts in `terraform/setup_scripts/` are rendered into user-data at apply time.

**Workflow:**

```bash
cd terraform
terraform init
terraform apply
```

The SSH private key (`rs-rsa-key.pem`) lives at the repo root; `terraform.tfvars.example` references it as `../rs-rsa-key.pem` from inside `terraform/`.

---

## License

MIT License with Commons Clause. Free to use, deploy, modify, and share for any purpose.
Commercial use (selling redStack or building a paid product or service on it) requires
written permission.

For commercial licensing: [mike@devzerosecurity.com](mailto:mike@devzerosecurity.com). See [LICENSE](LICENSE) for full terms.
