
Write-Host "Setting ExecutionPolicy..." -ForegroundColor Yellow
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force

#if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

$computerName = Read-Host 'Enter New Computer Name'

Write-Host "Renaming this computer to: " $computerName  -ForegroundColor Red
Rename-Computer -NewName $computerName

$thisPCIconRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$thisPCRegValname = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}"
$item = Get-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -ErrorAction SilentlyContinue

if ($item) {
Set-ItemProperty  -Path $thisPCIconRegPath -name $thisPCRegValname -Value 0  
}

else {
New-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -Value 0 -PropertyType DWORD  | Out-Null  
}

Write-Host "Creating standard DIR's..."  -ForegroundColor Yellow

mkdir c:\apps
mkdir c:\tools
mkdir c:\tmp


Write-Host "Excluding C:\tmp from WinDefender..."  -ForegroundColor Yellow
Add-MpPreference -ExclusionPath "c:\tmp"


Write-Host "Setting Network to Private"  -ForegroundColor Yellow
Set-NetConnectionProfile -Name "Network" -NetworkCategory Private


Write-Host "Enabling PSremoting..."  -ForegroundColor Yellow
Enable-PSRemoting -Force


Write-Host "Enabling RDP and Firewall ports for RDP..."  -ForegroundColor Yellow
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"


Write-Host "Disabling visual animations and effects..."  -ForegroundColor Yellow
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


Write-Host "Installing BoxStarter..."  -ForegroundColor Yellow
. { Invoke-WebRequest -useb https://boxstarter.org/bootstrapper.ps1 } | Invoke-Expression; Get-Boxstarter -Force


Write-Host "Changing Explorer behaviour"  -ForegroundColor Yellow
#--- File Explorer Settings ---
# will expand explorer to the actual folder you're in
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneExpandToCurrentFolder -Value 1
#adds things back in your left pane like recycle bin
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name NavPaneShowAllFolders -Value 1
#opens PC to This PC, not quick access
Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name LaunchTo -Value 1


Write-Host "Enabling W10 DevMode..."  -ForegroundColor Yellow
#--- Enable developer mode on the system ---
Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\AppModelUnlock -Name AllowDevelopmentWithoutDevLicense -Value 1


Write-Host "Showing hidden files and such..."  -ForegroundColor Yellow
#--- Configuring Windows properties ---
#--- Windows Features ---
# Show hidden files, Show protected OS files, Show file extensions
Set-WindowsExplorerOptions -EnableShowHiddenFilesFoldersDrives -EnableShowProtectedOSFiles -EnableShowFileExtensions


Write-Host "Prepping for WSL..."  -ForegroundColor Yellow
, 'n' * 1  | powershell "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux"
cinst -y Microsoft-Windows-Subsystem-Linux --source="'windowsfeatures'"
RefreshEnv


Write-Host "Disabling hibernation...."  -ForegroundColor Yellow
powercfg /h off


Write-Host "Setting a HighPerformance power plan...."  -ForegroundColor Yellow
Try {
    $HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
    $CurrPlan = $(powercfg -getactivescheme).split()[3]
    if ($CurrPlan -ne $HighPerf) {powercfg -setactive $HighPerf}
} Catch {
    Write-Warning -Message "Unable to set power plan to high performance"
}


Write-Host "Re-checking chocolatey..."  -ForegroundColor Yellow
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))


Write-Host "Installing choco packages..."  -ForegroundColor Yellow
cinst 7zip.install -y
cinst vlc -y
cinst notepadplusplus.install -y
cinst powershell -y
cinst curl -y 
cinst wget -y 
cinst python3 -y
cinst python -y
cinst sumatrapdf.install -y
cinst chromium -y


Write-Host "Updating Windows...."  -ForegroundColor Yellow
Install-WindowsUpdate


Write-Host "Updating PS help...."  -ForegroundColor Yellow
Update-Help
#, 'y' * 2  | powershell "Install-Module PSWindowsUpdate"
#Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d
#cmd /c echo y | powershell "Get-WUInstall –MicrosoftUpdate –AcceptAll –AutoReboot"


Write-Host "Resetting System Install base..."  -ForegroundColor Yellow
DISM.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase


Write-Host "Compacting non-essential and duplicate OS-files..."  -ForegroundColor Yellow
Compact.exe /CompactOS:always

#Cleanup


Write-Host "Removing stuff..."  -ForegroundColor Yellow
Get-ChildItem C:\Users\Public\Desktop | Remove-Item
Get-ChildItem C:\Users\joeuser\Desktop | Remove-item
Clear-RecycleBin -Force


Write-Host "Pulling and prepping for debloat...."  -ForegroundColor Yellow
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/Sycnex/Windows10Debloater/master/Windows10SysPrepDebloater.ps1'))


Write-Host "Restarting..."  -ForegroundColor Yellow
restart-computer -Force







