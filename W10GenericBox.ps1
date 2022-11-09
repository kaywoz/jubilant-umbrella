
#God mode
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
     $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
     Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
     Exit
    }
   }
#shoutout = expta

#####var begins
$ScriptName = 'W10GenericBox.ps1'
$ScriptPath = $MyInvocation.MyCommand.Path
$CurrentUser = ($env:UserName)
$CurrentHostname = ($env:ComputerName)
$UserDirs = 'c:\apps', 'c:\tools\scripts', 'c:\tmp','d:\hyperv','d:\wsl'
$DefenderExcludeDirs = 'c:\tmp','d:\hyperv','d:\wsl'

#$ScriptLocation = Split-Path $ScriptPath
#$PSScriptRoot # - NOTUSED // the directory where the script exists, not the target directory the script is running in
#$PSCommandPath #- NOTUSED // the full path of the script

#####var ends

 #Start transcript and log
 Start-Transcript -Path .\$ScriptName.txt -NoClobber

 #Start install by splash etc
  Write-Host "`n"
  Write-Host " ____________________________________________________________________________ " -ForegroundColor White 
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "  " -ForegroundColor Green -NoNewline; Write-Host "                                                                         |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "A " -ForegroundColor Green -NoNewline; Write-Host "                                                                         |" -ForegroundColor White  
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ██ ▄█▀▄▄▄     ▓██   ██▓ █     █░ ▒█████  ▒███████▒ " -ForegroundColor Red -NoNewline; Write-Host "              |" -ForegroundColor White  
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ██▄█▒▒████▄    ▒██  ██▒▓█░ █ ░█░▒██▒  ██▒▒ ▒ ▒ ▄▀░ " -ForegroundColor Red -NoNewline; Write-Host "              |" -ForegroundColor White  
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ▓███▄░▒██  ▀█▄   ▒██ ██░▒█░ █ ░█ ▒██░  ██▒░ ▒ ▄▀▒░  " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White  
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ▓██ █▄░██▄▄▄▄██  ░ ▐██▓░░█░ █ ░█ ▒██   ██░  ▄▀▒   ░ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White  
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ▒██▒ █▄▓█   ▓██▒ ░ ██▒▓░░░██▒██▓ ░ ████▓▒░▒███████▒ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ▒██▒ █▄▓█   ▓██▒ ░ ██▒▓░░░██▒██▓ ░ ████▓▒░▒███████▒ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ▒ ▒▒ ▓▒▒▒   ▓▒█░  ██▒▒▒ ░ ▓░▒ ▒  ░ ▒░▒░▒░ ░▒▒ ▓░▒░▒ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ░ ░▒ ▒░ ▒   ▒▒ ░▓██ ░▒░   ▒ ░ ░    ░ ▒ ▒░ ░░▒ ▒ ░ ▒ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ░ ░░ ░  ░   ▒   ▒ ▒ ░░    ░   ░  ░ ░ ░ ▒  ░ ░ ░ ░ ░ " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ░  ░        ░  ░░ ░         ░        ░ ░    ░ ░     " -ForegroundColor Red -NoNewline; Write-Host "             |" -ForegroundColor White   
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "          ░ ░                       ░         " -ForegroundColor Red -NoNewline; Write-Host "                             |" -ForegroundColor White
  Write-Host "|                                                                   "  -ForegroundColor White -NoNewline; Write-Host " PR0j3ct" -ForegroundColor Green -NoNewline; Write-Host " |" -ForegroundColor White   
  Write-Host "|                                                                            |" -ForegroundColor White 
  Write-Host "|____________________________________________________________________________|" -ForegroundColor White 
  Write-Host "|                                                                            |" -ForegroundColor White 
  Write-Host "| "  -ForegroundColor White -NoNewline; Write-Host "                               W10GenericBox" -ForegroundColor Green -NoNewline; Write-Host "                               |" -ForegroundColor White   
  Write-Host "|                                                                            |" -ForegroundColor White 
  Write-Host "|                                  Version x                                 |" -ForegroundColor White 
  Write-Host "|                                  Created by                                |" -ForegroundColor White 
  Write-Host "|                              github.com/kaywoz                             |" -ForegroundColor White 
  Write-Host "|                                                                            |" -ForegroundColor White 
  Write-Host "|____________________________________________________________________________|" -ForegroundColor White 
  Write-Host ""
  


$NewHostname = Read-Host 'Hostname ?'

Write-Host "***Changing hostname from"$CurrentHostname" to: "$NewHostname  -ForegroundColor Green
Rename-Computer -NewName $NewHostname | Out-Null  

$thisPCIconRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$thisPCRegValname = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
$item = Get-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -ErrorAction SilentlyContinue

if ($item) {
Set-ItemProperty  -Path $thisPCIconRegPath -name $thisPCRegValname -Value 0  | Out-Null  
}

else {
New-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -Value 0 -PropertyType DWORD  | Out-Null  
}

Write-Host "***Creating standard DIR's..."  -ForegroundColor Green
try {
    New-Item -Path $UserDirs -ItemType "Directory" -ErrorAction Stop | Out-Null
        }
catch {
    Write-Warning -Message "ERROR: Directories already exist ----> Skipping.";
    }


Write-Host "***Installing containers..."  -ForegroundColor Green
Enable-WindowsOptionalFeature -Online -FeatureName containers –All
Write-Host "***Installing hyper-v..."  -ForegroundColor Green
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V –All
Write-Host "***Installing sandbox..."  -ForegroundColor Green
Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online

Write-Host "***Installing BoxStarter..."  -ForegroundColor Green
. { Invoke-WebRequest -useb https://boxstarter.org/bootstrapper.ps1 } | Invoke-Expression; Get-Boxstarter -Force | Out-Null 

Write-Host "***Re-checking chocolatey..."  -ForegroundColor Green
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) | Out-Null 

Write-Host "***Installing scoop..."  -ForegroundColor Green
iwr -useb get.scoop.sh | iex

Write-Host "***Installing choco packages..."  -ForegroundColor Green

cinst 7zip.install -y | Out-Null 
Write-Host "*** 7zip installed..."  -ForegroundColor Green
cinst vlc -y | Out-Null 
Write-Host "*** vlc installed..."  -ForegroundColor Green
cinst notepadplusplus.install -y | Out-Null 
Write-Host "*** notepadplusplus installed..."  -ForegroundColor Green
cinst powershell -y | Out-Null 
Write-Host "*** powershell installed..."  -ForegroundColor Green
cinst curl -y | Out-Null 
Write-Host "*** curl installed..."  -ForegroundColor Green
cinst wget -y | Out-Null 
Write-Host "*** wget installed..."  -ForegroundColor Green
cinst python3 -y | Out-Null 
Write-Host "*** python3 installed..."  -ForegroundColor Green
cinst python -y | Out-Null 
Write-Host "*** python installed..."  -ForegroundColor Green
cinst sumatrapdf.install -y | Out-Null 
Write-Host "*** sumatrapdf installed..."  -ForegroundColor Green
cinst chromium -y | Out-Null 
Write-Host "*** chromium installed..."  -ForegroundColor Green
cinst winscp.portable -y | Out-Null 
Write-Host "*** winscp installed..."  -ForegroundColor Green
cinst treesizefree -y | Out-Null 
Write-Host "*** treesizefree installed..."  -ForegroundColor Green
cinst microsoft-windows-terminal -y | Out-Null
Write-Host "*** windows terminal installed..."  -ForegroundColor Green
cinst docker-desktop -y | Out-Null
Write-Host "*** docker desktop installed..."  -ForegroundColor Green
cinst duck -y | Out-Null
Write-Host "*** duck installed..."  -ForegroundColor Green
cinst vagrant -y | Out-Null
Write-Host "*** vagrant installed..."  -ForegroundColor Green
cinst packer -y | Out-Null
Write-Host "*** packer installed..."  -ForegroundColor Green
cinst windows-admin-center
Write-Host "*** wac installed..."  -ForegroundColor Green

Write-Host "***Changing Explorer behaviour"  -ForegroundColor Green
# will expand explorer to the actual folder you're in
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1
#adds things back in your left pane like recycle bin
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1
#opens PC to This PC, not quick access
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Value 1

Write-Host "***Changing Taskbar behaviour"  -ForegroundColor Green
# will expand explorer to the actual folder you're in
Set-TaskbarOptions -Size Small -Lock -Dock Bottom -Combine Always

#Cleanup
Write-Host "***Removing stuff..."  -ForegroundColor Green
Get-ChildItem C:\Users\Public\Desktop | Remove-Item
Get-ChildItem C:\Users\$CurrentUser\Desktop | Remove-item
Clear-RecycleBin -Force

Write-Host "***Setting wallpaper...." -ForegroundColor Green
(New-Object System.Net.WebClient).DownloadFile('https://git.io/JfYWM','c:\tools\scripts\Set-Wallpaper.ps1')
Write-Host "***Scheduling wallpaper refresh task...." -ForegroundColor Green
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument "-nologo -noninteractive -WindowStyle Hidden c:\tools\scripts\Set-Wallpaper.ps1 Colour Black"
$trigger =  New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WallpaperRefresh" -Description "Refreshes wallpaper" | Out-Null

Write-Host "***Enabling W10 DevMode..."  -ForegroundColor Green
#Enable developer mode on the system
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock -Name AllowDevelopmentWithoutDevLicense -Value 1

Write-Host "***Showing hidden files and such..."  -ForegroundColor Green
# Show hidden files, Show protected OS files, Show file extensions
Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions

Write-Host "***Excluding dirs from WinDefender..."  -ForegroundColor Green
Add-MpPreference -ExclusionPath $DefenderExcludeDirs

Write-Host "***Setting Networks to Private"  -ForegroundColor Green
try {
Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq "Public"} | Set-NetConnectionProfile -NetworkCategory Private
}
catch {
    Write-Warning -Message "WARNING: No need to set adapters ----> Skipping.";
}

Write-Host "***Enabling PSremoting..."  -ForegroundColor Green
Enable-PSRemoting -Force | Out-Null

Write-Host "***Enabling RDP and Firewall ports for RDP..."  -ForegroundColor Green
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"


Write-Host "***Installing OpenSSH Server..."  -ForegroundColor Green
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'
Get-NetFirewallRule -Name *ssh*
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

Write-Host "***Disabling visual animations and effects..."  -ForegroundColor Green
$path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'
try {
    $s = (Get-ItemProperty -ErrorAction stop -Name visualfxsetting -Path $path).visualfxsetting 
    if ($s -ne 2) {
        Set-ItemProperty -Path $path -Name 'VisualFXSetting' -Value 2  
        }
    }
catch {
    New-ItemProperty -Path $path -Name 'VisualFXSetting' -Value 2 -PropertyType 'DWORD'
    }

Write-Host "***Prepping for WSL..."  -ForegroundColor Green
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
Invoke-WebRequest -Uri https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi -OutFile wsl_update_x64.msi -UseBasicParsing
RefreshEnv
wsl --set-default-version 2
Write-Host "***Downloading WSL distros..."  -ForegroundColor Green
cd d:\wsl
Invoke-WebRequest -Uri https://aka.ms/wslubuntu2004 -OutFile Ubuntu2004.appx -UseBasicParsing
move .\Ubuntu2004.appx .\Ubuntu2004.zip
Expand-Archive .\Ubuntu2004.zip
d:\wsl\Ubuntu2004\ubuntu2004.exe


Write-Host "***Setting a High Performance power plan...."  -ForegroundColor Green
Try {
    $HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
    $CurrPlan = $(powercfg -getactivescheme).split()[3]
    if ($CurrPlan -ne $HighPerf) {powercfg -setactive $HighPerf}
} Catch {
    Write-Warning -Message "***Unable to set power plan to high performance"
}

Write-Host "***Resetting System Install base..."  -ForegroundColor Green
DISM.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase

Write-Host "***Updating Windows...."  -ForegroundColor Green
Install-WindowsUpdate

Write-Host "***Updating PS help...."  -ForegroundColor Green
Update-Help -ErrorAction SilentlyContinue | Out-Null 

Write-Host "***Compacting non-essential and duplicate OS-files..."  -ForegroundColor Green
Compact.exe /CompactOS:always

Write-Host "***Pulling and prepping for debloat...."  -ForegroundColor Green
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Sycnex/Windows10Debloater/master/Windows10SysPrepDebloater.ps1'))
#shoutout = Sycnex

Write-Host "***Restarting..."  -ForegroundColor Green
restart-computer -Force


test




