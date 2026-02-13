<powershell>
# windows_setup.ps1 - User data script for Windows client initialization

# Logging
Start-Transcript -Path "C:\Windows\Temp\user-data.log" -Append

Write-Host "===== Windows Client Setup Started $(Get-Date) ====="

# Disable IE Enhanced Security (for easier web browsing in training)
Write-Host "[*] Disabling IE Enhanced Security Configuration..."
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force

# Disable Windows Defender (training only - CRITICAL: Explain this to attackers)
Write-Host "[*] Disabling Windows Defender (TRAINING ONLY)..."
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue

# Disable Windows Firewall (training only)
Write-Host "[*] Disabling Windows Firewall (TRAINING ONLY)..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Enable RDP and disable NLA (Network Level Authentication)
Write-Host "[*] Enabling Remote Desktop..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

Write-Host "[*] RDP setup complete - ready for access!"
Write-Host "[*] Using default Administrator account (AWS-generated password)"

# ============================================================================
# INSTALL WSL WITH DEBIAN
# ============================================================================

Write-Host "[*] Installing WSL with Debian distribution..."

# Enable WSL and Virtual Machine Platform features
Write-Host "[*] Enabling WSL Windows features..."
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Download and install WSL2 kernel update
Write-Host "[*] Downloading WSL2 kernel update..."
$wslUpdateUrl = "https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi"
$wslUpdatePath = "$env:TEMP\wsl_update_x64.msi"
Invoke-WebRequest -Uri $wslUpdateUrl -OutFile $wslUpdatePath -UseBasicParsing
Start-Process msiexec.exe -ArgumentList "/i `"$wslUpdatePath`" /quiet /norestart" -Wait -NoNewWindow

# Set WSL 2 as default version
wsl --set-default-version 2 2>$null

# Install Debian via wsl --install (handles download and setup)
Write-Host "[*] Installing Debian WSL distribution..."
wsl --install -d Debian --no-launch 2>$null

# Create a startup task to finalize WSL setup after reboot
Write-Host "[*] Creating post-reboot WSL finalization task..."
$action = New-ScheduledTaskAction -Execute "wsl.exe" -Argument "--install -d Debian --no-launch"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName "WSL-Debian-Setup" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

# ============================================================================
# INSTALL WINDOWS TERMINAL
# ============================================================================

Write-Host "[*] Installing Windows Terminal..."

# Install Chocolatey package manager
Write-Host "[*] Installing Chocolatey..."
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
$env:chocolateyUseWindowsCompression = 'true'
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Refresh PATH to include Chocolatey
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")

# Install Windows Terminal via Chocolatey
Write-Host "[*] Installing Windows Terminal via Chocolatey..."
& "$env:ProgramData\chocolatey\bin\choco.exe" install microsoft-windows-terminal -y --no-progress

# ============================================================================
# INSTALL GOOGLE CHROME
# ============================================================================

Write-Host "[*] Installing Google Chrome..."
& "$env:ProgramData\chocolatey\bin\choco.exe" install googlechrome -y --no-progress

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
# INSTALL VISUAL STUDIO BUILD TOOLS
# ============================================================================

Write-Host "[*] Installing Visual Studio 2022 Build Tools (C/C++, .NET, C#)..."
& "$env:ProgramData\chocolatey\bin\choco.exe" install visualstudio2022buildtools -y --no-progress --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Workload.ManagedDesktopBuildTools --add Microsoft.VisualStudio.Workload.NetCoreBuildTools --passive --norestart"

Write-Host "===== Windows Client Setup Completed $(Get-Date) ====="
Write-Host "===== Use 'aws ec2 get-password-data' to retrieve Administrator password ====="
Write-Host "===== NOTE: A reboot may be required to complete WSL installation ====="

Stop-Transcript
</powershell>
