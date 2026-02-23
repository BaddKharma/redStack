<script>
REM ============================================================================
REM PHASE 1: Disable Windows Defender via batch (bypasses AMSI)
REM AMSI scans PowerShell scripts at parse time and blocks scripts that contain
REM security-disabling commands. Batch scripts are not subject to AMSI scanning.
REM ============================================================================

REM Disable Defender via registry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableIOAVProtection /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScriptScanning /t REG_DWORD /d 1 /f

REM Stop Defender service
sc stop WinDefend
sc config WinDefend start= disabled

REM Disable Windows Firewall
netsh advfirewall set allprofiles state off

REM Enable RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes

echo [*] Phase 1 complete - Defender disabled, firewall off, RDP enabled
</script>
<powershell>
# windows_setup.ps1 - Phase 2: Main setup (runs after Defender is disabled)

# Logging
Start-Transcript -Path "C:\Windows\Temp\user-data.log" -Append

Write-Host "===== Windows Client Setup Started $(Get-Date) ====="

# Set hostname
Write-Host "[*] Setting hostname to WIN-OPERATOR..."
Rename-Computer -NewName "WIN-OPERATOR" -Force

# Configure hosts file for lab machines
Write-Host "[*] Configuring hosts file for lab machines..."
$hostsContent = @"

__HOSTS_ENTRIES__
"@
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value $hostsContent

# Disable IE Enhanced Security (for easier web browsing in training)
Write-Host "[*] Disabling IE Enhanced Security Configuration..."
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force

# Reinforce Defender disable via PowerShell (belt and suspenders)
Write-Host "[*] Reinforcing Defender disable (TRAINING ONLY)..."
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue

Write-Host "[*] RDP setup complete - ready for access!"
Write-Host "[*] Using default Administrator account (AWS-generated password)"

# Install Chocolatey package manager
Write-Host "[*] Installing Chocolatey..."
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
$env:chocolateyUseWindowsCompression = 'true'
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Refresh PATH to include Chocolatey
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")

# ============================================================================
# INSTALL CHROMIUM
# ============================================================================

Write-Host "[*] Installing Chromium..."
& "$env:ProgramData\chocolatey\bin\choco.exe" install chromium -y --no-progress

# ============================================================================
# INSTALL VS CODE
# ============================================================================

Write-Host "[*] Installing Visual Studio Code..."
& "$env:ProgramData\chocolatey\bin\choco.exe" install vscode -y --no-progress

# ============================================================================
# INSTALL MOBAXTERM
# ============================================================================

Write-Host "[*] Installing MobaXterm..."
& "$env:ProgramData\chocolatey\bin\choco.exe" install mobaxterm -y --no-progress

# ============================================================================
# INSTALL 7-ZIP
# ============================================================================

Write-Host "[*] Installing 7-Zip..."
& "$env:ProgramData\chocolatey\bin\choco.exe" install 7zip -y --no-progress

# ============================================================================
# PRE-CONFIGURE MOBAXTERM SESSIONS
# ============================================================================

Write-Host "[*] Pre-configuring MobaXterm SSH sessions..."

$mobaDir = "C:\Users\Administrator\AppData\Roaming\MobaXterm"
New-Item -ItemType Directory -Force -Path $mobaDir | Out-Null

# Session format: Name=#109#ColorScheme%Host%Port%Username%...
# Hostnames resolve via the pre-configured hosts file entries
$mobaIni = @"
[Bookmarks]
SubRep=
ImgNum=41

[Bookmarks_0]
SubRep=redStack Lab
ImgNum=41
Mythic C2 (SSH)=#109#0%mythic%22%admin%-1%-1%%%%%0%-1%-1%0%0%0%%0%0%0%0%0%0%0%0%0%
Sliver C2 (SSH)=#109#0%sliver%22%admin%-1%-1%%%%%0%-1%-1%0%0%0%%0%0%0%0%0%0%0%0%0%
Havoc C2 (SSH)=#109#0%havoc%22%admin%-1%-1%%%%%0%-1%-1%0%0%0%%0%0%0%0%0%0%0%0%0%
Apache Redirector (SSH)=#109#0%redirector%22%admin%-1%-1%%%%%0%-1%-1%0%0%0%%0%0%0%0%0%0%0%0%0%
Guacamole Server (SSH)=#109#0%guac%22%admin%-1%-1%%%%%0%-1%-1%0%0%0%%0%0%0%0%0%0%0%0%0%
"@

Set-Content -Path "$mobaDir\MobaXterm.ini" -Value $mobaIni -Encoding UTF8
Write-Host "[+] MobaXterm sessions written to $mobaDir\MobaXterm.ini"

Write-Host "===== Windows Client Setup Completed $(Get-Date) ====="
Write-Host "===== Use 'aws ec2 get-password-data' to retrieve Administrator password ====="

Stop-Transcript
</powershell>
