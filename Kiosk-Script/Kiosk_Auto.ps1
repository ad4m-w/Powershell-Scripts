# Created By Adam Waszczyszak
# Version 3.5
$host.ui.RawUI.WindowTitle = “adamwasz.com”

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Admin)) {
    $cmd = 'irm https://raw.githubusercontent.com/ad4m-w/Powershell-Scripts/refs/heads/main/Kiosk_Setup.ps1 | iex'
    $args = "-NoProfile -NoExit -Command `"& { $cmd }`""
    Start-Process powershell.exe -Verb RunAs -ArgumentList $args
    exit
}

# Disable Quick Edit Mode
Set-ItemProperty -Path 'HKCU:\Console\' -Name QuickEdit -Value 0

# Bypass Execution Policy
Set-ExecutionPolicy Bypass

# Clear Screen after admin check
Clear-Host

# Disabling download progress bar increases download speed significantly.
$ProgressPreference = 'SilentlyContinue'

# Test if folders exist and then create if they do not.
if (Test-Path -Path C:\Temp){
    Clear-Host
    "Temp Folder Already Exists"
    }
   
    else{
        New-Item -Path C:\Temp -ItemType Directory
    }
   
if (Test-Path -Path C:\Visitor_Pic){
    "Visitor_Pic Folder Already Exists"
}
   
    else{
        New-Item -Path C:\Visitor_Pic -ItemType Directory
    }
# Set full control access of Temp and Visitor_Pic folders 
$path=Get-Acl -Path C:\Temp
$acl=New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule ('BUILTIN\Users','FullControl','ContainerInherit, ObjectInherit','None','Allow')
$path.setaccessrule($acl)
Set-Acl -Path C:\Temp\ -AclObject $path


$path=Get-Acl -Path C:\Visitor_pic
$acl=New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule ('BUILTIN\Users','FullControl','ContainerInherit, ObjectInherit','None','Allow')
$path.setaccessrule($acl)
Set-Acl -Path C:\Visitor_pic\ -AclObject $path

"Permissions for Temp and Visitor_Pics Set!"

# Install Windows update module and run update check
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PSWindowsUpdate -Force
'Installing all newest Windows Updates'
Import-Module -Name PSWindowsUpdate -Force
Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot -Verbose

# Rotation lock the screen using Registry
'Enabling Rotation Lock using Registry.'
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation -Name Enable -Value 0 -Type DWord
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" /v Enable /t REG_DWORD /d 0 /f
'Done!'

# Disable notifications using the Registry
'Disabling Notifications using Registry.'
New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows" -Name "Explorer" -force
New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -PropertyType "DWord" -Value 1
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -PropertyType "DWord" -Value 0
'Done!'

# Internet Explorer glitch fix
     $regContent = @"
     Windows Registry Editor Version 5.00
     ;Disable IE11 Welcome Screen
     [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main]
     "DisableFirstRunCustomize"=dword:00000001 
"@
$tempFile = New-TemporaryFile 
$tempFile.FullName 
$regContent | Out-File -FilePath $tempFile.FullName -Encoding ASCII
reg.exe import $tempFile.FullName
Remove-Item $tempFile.FullName   
'Done!'

# Adobe download and install
'Parsing download site for Adobe installer...'
# Retrieve the HTML content of the website
$response = Invoke-WebRequest -Uri "https://download.msshift.com/link/5da99203-21ba-4aa2-93e6-a60a8a0b3ae3"
# Extract the text content from the parsed HTML
$text = $response.ParsedHtml.body.innerText 
'Downloading the Adobe Installer...'
$Destination = "C:\Temp\adobe.exe" 
Invoke-WebRequest -Uri $text -OutFile $Destination
'Download Completed.'
"Installing Adobe..."
Start-Process -FilePath "C:\Temp\adobe.exe" -ArgumentList "/sPB" -Wait
"Adobe installer has finished."

# Download DS8108 Scanner driver and PDFs for configuration
'Parsing download site for DS8108 driver and PDFs...'
# Retrieve the HTML content of the website
$response = Invoke-WebRequest -Uri "https://download.msshift.com/link/c862d6fc-fc72-4e77-8347-ab079c8d4fa3"
# Extract the text content from the parsed HTML
$text = $response.ParsedHtml.body.innerText
'Downloading DS8108 driver...'
$Destination = "C:\Temp\Zebra_CoreScanner_Driver.exe" 
Invoke-WebRequest -Uri $text -OutFile $Destination
$Destination = [System.IO.Path]::Combine([System.Environment]::GetFolderPath('MyDocuments'), 'Kiosk Configs.pdf')
$response = Invoke-WebRequest -Uri "https://download.msshift.com/link/0958c824-3f1e-42b3-89d1-c29a88efe9c2"
$text = $response.ParsedHtml.body.innerText
Invoke-WebRequest -Uri $text -OutFile $Destination
'**Kiosk Scanner Config PDF saved in Documents Folder**'

$issContent = @"
[{C96D0CF9-799F-4332-81FF-130C0F58AB0C}-DlgOrder]
Dlg0={C96D0CF9-799F-4332-81FF-130C0F58AB0C}-SdWelcome-0
Count=4
Dlg1={C96D0CF9-799F-4332-81FF-130C0F58AB0C}-SetupType2-0
Dlg2={C96D0CF9-799F-4332-81FF-130C0F58AB0C}-SdStartCopy2-0
Dlg3={C96D0CF9-799F-4332-81FF-130C0F58AB0C}-SdFinish-0
[{C96D0CF9-799F-4332-81FF-130C0F58AB0C}-SdWelcome-0]
Result=1
[{C96D0CF9-799F-4332-81FF-130C0F58AB0C}-SetupType2-0]
Result=304
[{C96D0CF9-799F-4332-81FF-130C0F58AB0C}-SdStartCopy2-0]
Result=1
[{C96D0CF9-799F-4332-81FF-130C0F58AB0C}-SdFinish-0]
Result=1
bOpt1=0
bOpt2=0
"@

$issFilePath = "C:\Temp\custom.iss"
$issContent | Out-File -FilePath $issFilePath -Encoding ascii
"iss Config File created in Temp folder..."
"Launching Hands Free Scanner with silent installer params..."
# Define the path to the executable and the parameters
$exePath = "C:\Temp\Zebra_CoreScanner_Driver.exe"   
$issFilePath = "C:\Temp\custom.iss"
# Launch the CMD and run the zebra.exe with the specified arguments
Write-Host "Launching Zebra Installer using CMD to inject arguments..."
Start-Process "cmd.exe" -ArgumentList "/c", "$exePath -s -f1`"$issFilePath`"" -Wait
"Zebra Installer completed."

# DYMO 550 download and install.
'Parsing download site for DYMO 550 setup...'
# Retrieve the HTML content of the website
$response = Invoke-WebRequest -Uri "https://download.msshift.com/link/1ab37806-4228-4eb1-8178-1ba492b0ea0f"
# Extract the text content from the parsed HTML
$text = $response.ParsedHtml.body.innerText
'Downloading...'
$Destination = "C:\Temp\DCDSetup1.4.5.1.exe" 
Invoke-WebRequest -Uri $text -OutFile $Destination
"Launching DYMO 550 driver with silent installer params..."
Start-Process -FilePath "C:\Temp\DCDSetup1.4.5.1.exe" -ArgumentList "/S", "/v/qn" -Wait
"DYMO 550 Install Finished!"

# Kiosk download, extract and icon setup.
'Parsing download site for Kiosk App...'    
# Retrieve the HTML content of the website
$response = Invoke-WebRequest -Uri "https://download.msshift.com/link/6ffe0dbd-c7cd-4206-a960-b2231fd4bd34"
# Extract the text content from the parsed HTML
$text = $response.ParsedHtml.body.innerText
'Downloading...'
$Destination = "C:\Temp\kiosk.zip"
Invoke-WebRequest -Uri $text -OutFile $Destination
Write-Host 'Uncompressing...'
Expand-Archive -LiteralPath $Destination -DestinationPath "C:\"
"Kiosk zip extracted to C:\"
'Parsing download site for Kiosk.ico...'
# Retrieve the HTML content of the website
$response = Invoke-WebRequest -Uri "https://download.msshift.com/link/c55f283e-e94a-4a21-8b04-4b6cd16574b2"
# Extract the text content from the parsed HTML
$text = $response.ParsedHtml.body.innerText
'Downloading kiosk icon file...'
$Destination = "C:\kiosk.ico"
Invoke-WebRequest -Uri $text -OutFile $Destination
Write-Host 'Adding Kiosk Shortcut to Desktop'
$TargetFile = "C:\v2.4_14vp\ms.Visitors.Kiosk.exe"
$ShortcutFile = "$env:USERPROFILE\Desktop\MS Shift Kiosk.lnk"
if (-Not (Test-Path $TargetFile)) {
    Write-Host "Error: Target file does not exist at $TargetFile"
    return
}
$desktopPath = [System.Environment]::GetFolderPath('Desktop')
if (-Not (Test-Path $desktopPath)) {
    Write-Host "Error: Desktop directory does not exist."
    return
}
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutFile)
$Shortcut.TargetPath = $TargetFile
$Shortcut.IconLocation = "C:\kiosk.ico"
$Shortcut.Save()
Write-Host "Shortcut created at $ShortcutFile"
$shortcutPath = "$env:USERPROFILE\Desktop\MS Shift Kiosk.lnk"
$startupPath = [Environment]::GetFolderPath("Startup")
Copy-Item $shortcutPath -Destination $startupPath
Write-Host 'Added kiosk app to Startup folder.'

'Parsing download site for Teamviewer Setup...'
# Retrieve the HTML content of the website
$response = Invoke-WebRequest -Uri "https://download.msshift.com/link/50a71d63-6535-4343-88dc-f6870af278e2"
# Extract the text content from the parsed HTML
$text = $response.ParsedHtml.body.innerText
'Downloading TeamViewer setup file...'
$Destination = "C:\Temp\Teamviewer.exe"
Invoke-WebRequest -Uri $text -OutFile $Destination
"Launching Teamviewer installer..."
Start-Process -FilePath "C:\Temp\Teamviewer.exe" -Wait
"TeamViewer installer finished!"

Get-PnpDevice -FriendlyName "*Microsoft Camera Rear*" | Disable-PnpDevice -Confirm:$false
'Rear Camera Disabled.'

Powercfg /Change monitor-timeout-ac 0
Powercfg /Change monitor-timeout-dc 0
Powercfg /Change standby-timeout-ac 0
Powercfg /Change standby-timeout-dc 0
'Power plan settings changed.'

    $batchContent = @"
@echo off
net stop spooler
ping -n 4 127.0.0.1 > nul 
echo Deleting Print Queue...
del %systemroot%\System32\spool\printers\* /Q
echo Queue Deleted.
net start spooler
"@

'Removed all scheduled tasks.'
Get-ScheduledTask | Unregister-ScheduledTask -Confirm:$false

$vbsContent = @"
CreateObject("Wscript.Shell").Run "C:\QueueDeletion.bat",0,True
"@

$batchFilePath = "C:\QueueDeletion.bat"
$batchContent | Out-File -FilePath $batchFilePath -Encoding ascii
"Batch File created in C:\..."
"Creating VBS for silent launch..."
$vbsFilePath = "C:\QueueDeletion.vbs"
$vbsContent | Out-File -FilePath $vbsFilePath -Encoding ascii
"VBS File created in Temp folder..."
"Creating Scheduled VBS Task..."
$action = New-ScheduledTaskAction -Execute "C:\QueueDeletion.vbs"
$trigger = New-ScheduledTaskTrigger -Daily -At 11:30AM
Register-ScheduledTask -TaskName "Print Queue Deletion Task" -Action $action -Trigger $trigger -AsJob -Force -RunLevel Highest
# Ensure Edge key exists
$EdgeHome = 'HKCU:\Software\Policies\Microsoft\Edge'
If ( -Not (Test-Path $EdgeHome)) {
New-Item -Path $EdgeHome | Out-Null
}
# Set RestoreOnStartup value entry
$IPHT = @{
Path   = $EdgeHome 
Name   = 'RestoreOnStartup' 
Value  = 4 
Type   = 'DWORD'
}
Set-ItemProperty @IPHT -verbose
# Create Startup URL's registry key
$EdgeSUURL = "$EdgeHome\RestoreOnStartupURLs"
If ( -Not (Test-Path $EdgeSUURL)) {
New-Item -Path $EdgeSUURL | Out-Null
}
# Create a single URL startup page
$HOMEURL = 'https://msshift.webex.com'
Set-ItemProperty -Path $EdgeSUURL -Name '1' -Value $HomeURL

# Windows update block.
sc.exe query wuauserv
sc.exe stop wuauserv
sc.exe config wuauserv start=disabled
REG.exe QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv /v Start
'Windows Updates Blocked'
Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\'  | Disable-ScheduledTask -ErrorAction SilentlyContinue

'Please make sure that all installations are complete, then continue.'
while ($true) {
    $userInput = Read-Host "Type 'C' to continue"
    if ($userInput -eq 'C') {
        Write-Host "Continuing..."
        break
    } 
    else {
        Write-Host "Invalid input. Please type 'C' to continue."
    }
}

New-NetFirewallRule -Program "C:\Program Files (x86)\DYMO\DYMO Connect\DYMOConnect.exe" -Action Block -Profile Domain, Private, Public -DisplayName Block DYMO Connect -Description Block DYMO Connect -Direction Outbound | Format-Table -AutoSize -Property DisplayName, Enabled, Direction, Action  
New-NetFirewallRule -Program "C:\Program Files (x86)\DYMO\DYMO Connect\DYMO.WebApi.Win.Host.exe" -Action Block -Profile Domain, Private, Public -DisplayName Block DYMO WebService -Description Block DYMO WebService -Direction Outbound | Format-Table -AutoSize -Property DisplayName, Enabled, Direction, Action 
'DYMO Services blocked in Firewall.'
Get-ChildItem -Path "C:\Temp" -Recurse -Force | Remove-Item -Recurse -Force -Verbose
'Temp folder cleaned of all files!'

# Steps to kill Explorer, and remove pinned items from Taskbar
Stop-Process -Name explorer -Force
$taskbarPath = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
if (Test-Path $taskbarPath) {
    Get-ChildItem -Path $taskbarPath -Force | Remove-Item -Force -Recurse
}
Start-Process explorer

# Block Adobe updates
sc.exe stop AdobeARMservice
Set-Service -Name "AdobeARMservice" -StartupType Disabled
sc.exe query wuauserv
sc.exe stop wuauserv
sc.exe config wuauserv start=disabled

# Disabled scheduled task
'Disable scheduled task'
Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\'  | Disable-ScheduledTask -ErrorAction SilentlyContinue
'Adobe and Windows Updates blocked in Services.'

# Delete original Msshift User
Remove-LocalUser -Name "msshi"
'Online MS Shift User Account deleted'
      
Add-Type -AssemblyName System.Windows.Forms
    $message = @"
Script has finished executing.                    
Kiosk Scanner Config PDF is saved in the Documents Folder
Please restart the kiosk to complete Windows updates.
"@

[System.Windows.Forms.MessageBox]::Show($message, "Done!", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
exit
