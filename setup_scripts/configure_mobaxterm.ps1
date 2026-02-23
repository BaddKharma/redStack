# configure_mobaxterm.ps1
# Run as the user who will use MobaXterm (not necessarily Administrator)
# Downloads and sets up pre-configured SSH sessions for the redStack lab

# Kill MobaXterm if running so it doesn't overwrite the config on exit
$moba = Get-Process -Name "MobaXterm*" -ErrorAction SilentlyContinue
if ($moba) {
    Write-Host "[*] Stopping MobaXterm..."
    $moba | Stop-Process -Force
    Start-Sleep -Seconds 2
}

$mobaDir = "$env:APPDATA\MobaXterm"
New-Item -ItemType Directory -Force -Path $mobaDir | Out-Null

# INI structure derived from a fully-initialized MobaXterm installation.
# [Misc] must include LocalShell to suppress the first-run theme/setup wizard.
# Sessions use '= #109#' format (space before #109# required for sessions to be recognized).
$mobaIni = @'
[Misc]
PasswordsInRegistry=1
LocalShell=Bash (64 bit)
SlashDir=_AppDataDir_\MobaXterm\slash
HomeDir=_AppDataDir_\MobaXterm\home
RDMSessionsAlreadyImported=1
SkinSat=80
SkinName3=Windows dark theme
DefTextEditor=<MobaTextEditor>
StorePasswords=Ask
AllowMultiInstances=0

[Bookmarks_0]
SubRep=redStack Lab
ImgNum=41
Mythic C2 (SSH)= #109#0%mythic%22%admin%%-1%-1%%%%%0%-1%0%%%-1%-1%0%0%%1080%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1
Sliver C2 (SSH)= #109#0%sliver%22%admin%%-1%-1%%%%%0%-1%0%%%-1%-1%0%0%%1080%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1
Havoc C2 (SSH)= #109#0%havoc%22%admin%%-1%-1%%%%%0%-1%0%%%-1%-1%0%0%%1080%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1
Apache Redirector (SSH)= #109#0%redirector%22%admin%%-1%-1%%%%%0%-1%0%%%-1%-1%0%0%%1080%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1
Guacamole Server (SSH)= #109#0%guac%22%admin%%-1%-1%%%%%0%-1%0%%%-1%-1%0%0%%1080%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%0%#0# #-1

[SSH]
SFTPShowDotFiles=1
SFTPAsciiMode=0
MonitorHost=1
MonitorCPU=1
MonitorRAM=1
MonitorNetUp=1
MonitorNetDown=1
MonitorProcesses=0
MonitoFDs=0
MonitorUptime=1
MonitorUsers=1
MonitorPartitions=1
MonitorNfsPartitions=0
MonitorNetstat=0
UseInternalMobAgent=0
UseExternalPageant=0
UseExternalWindowsAgent=0
ValidateEachAgentRequest=0
MobAgentKeys=
DisplaySSHBanner=1
UseNewMoTTY=1
StrictHostKeyChecking=1
GwUse2factor=0
AutoStartSSHGUI=1
SSHKeepAlive2=0
EnableSFTP=1
RemoteMonitoring=1
ScpPreservesDates=0
UseGSSAPI=1
KrbDomain=
GSSAPICustomLib=
GSSAPILibNumber=0
DefaultLoginName=

[Display]
SidebarRight=0
C10Checked=1
C11Checked=1
C12Checked=1
C13Checked=0
C14Checked=0
VisibleTabNum=1
VisibleTabClose=1
MenuAndButtons=2
BtnType2=2
S3Checked=0
DisableQuickConnect=0
IconsTheme=0
RoundedTabs=1
GraphicCache=1

[Bookmarks]
SubRep=
ImgNum=41
'@

$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText("$mobaDir\MobaXterm.ini", $mobaIni, $utf8NoBom)
Write-Host "[+] MobaXterm sessions written to $mobaDir\MobaXterm.ini"
Write-Host "[+] Open MobaXterm — redStack Lab sessions should appear in the sidebar."
