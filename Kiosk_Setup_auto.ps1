# Self-check for admin rights, and ask for perms if launched not as admin (from Superuser.com)
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
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


    if (Test-Path -Path C:\Temp){
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
   
        'Folders Created.'
    
     $path=Get-Acl -Path C:\Temp
     $acl=New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule ('BUILTIN\Users','FullControl','ContainerInherit, ObjectInherit','None','Allow')
     $path.setaccessrule($acl)
     Set-Acl -Path C:\Temp\ -AclObject $path


     $path=Get-Acl -Path C:\Visitor_pic
     $acl=New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule ('BUILTIN\Users','FullControl','ContainerInherit, ObjectInherit','None','Allow')
     $path.setaccessrule($acl)
     Set-Acl -Path C:\Visitor_pic\ -AclObject $path

     "Permissions for Temp and Visitor_Pics Set!"

    'Installing Windows Update PS Module...'
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name PSWindowsUpdate -Force
    'Installing all newest Windows Updates'
    Import-Module -Name PSWindowsUpdate -Force
    Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot -Verbose

     'Done, remember to restart later!'

     'Enabling Rotation Lock using Registry.'
     Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation -Name Enable -Value 0 -Type DWord
     reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AutoRotation" /v Enable /t REG_DWORD /d 0 /f
     'Done!'

     'Disabling Notifications using Registry.'
     New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows" -Name "Explorer" -force
     New-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -PropertyType "DWord" -Value 1
     New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -PropertyType "DWord" -Value 0
     'Done!'

     $regContent = @"
     Windows Registry Editor Version 5.00
     ;Disable IE11 Welcome Screen
     [HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Main]
     "DisableFirstRunCustomize"=dword:00000001 
"@

     # Create a temporary .reg file
     $tempFile = New-TemporaryFile 
     $tempFile.FullName 
     $regContent | Out-File -FilePath $tempFile.FullName -Encoding ASCII

     # Import the registry settings
     reg.exe import $tempFile.FullName

     # Clean up the temporary file
     Remove-Item $tempFile.FullName   

     'Parsing download site...'

     # Retrieve the HTML content of the website
     $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/5da99203-21ba-4aa2-93e6-a60a8a0b3ae3"
     # Extract the text content from the parsed HTML
     $text = $response.ParsedHtml.body.innerText
 
     'Downloading...'

     $Destination = "C:\Temp\adobe.exe" 
     Invoke-WebRequest -Uri $text -OutFile $Destination

     "Launching Adobe with silent installer params..."
     Start-Process -FilePath "C:\Temp\adobe.exe" -ArgumentList "/sPB"
     "Success!"

     'Parsing download site...'
     # Download HF driver
     # Retrieve the HTML content of the website
     $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/c862d6fc-fc72-4e77-8347-ab079c8d4fa3"
     # Extract the text content from the parsed HTML
     $text = $response.ParsedHtml.body.innerText
     'Downloading driver...'

     $Destination = "C:\Temp\Zebra_CoreScanner_Driver.exe" 
     Invoke-WebRequest -Uri $text -OutFile $Destination
     'Downloading Kiosk PDF...'

     $Destination = "C:\Temp\Kiosk Configs.pdf" 
     Invoke-WebRequest -Uri $text -OutFile $Destination
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/0958c824-3f1e-42b3-89d1-c29a88efe9c2"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText

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

     'Giving 180 seconds for processes to catch up...'
     Start-Sleep -Seconds 180

     "Launching Hands Free Scanner with silent installer params..."

	# Define the path to the executable and the parameters
	$exePath = "C:\Temp\Zebra_CoreScanner_Driver.exe"   
	$issFilePath = "C:\Temp\custom.iss"

	# Launch the CMD and run the zebra.exe with the specified arguments
	Start-Process "cmd.exe" -ArgumentList "/c", "$exePath -s -f1`"$issFilePath`""

	Write-Host "CMD launched with Zebra Installer and arguments."

    "Success!"

    'Parsing download site...'

    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/1ab37806-4228-4eb1-8178-1ba492b0ea0f"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText

    'Downloading...'

    $Destination = "C:\Temp\DCDSetup1.4.5.1.exe" 
    Invoke-WebRequest -Uri $text -OutFile $Destination

    'Giving 45 seconds for processes to catch up...'
    Start-Sleep -Seconds 45

    "Launching DYMO 550 driver with silent installer params..."
    Start-Process -FilePath "C:\Temp\DCDSetup1.4.5.1.exe" -ArgumentList "/S", "/v/qn"
    "Success!"

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

    'Parsing download site for Kiosk.ico...'
            
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/c55f283e-e94a-4a21-8b04-4b6cd16574b2"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText

    'Downloading...'

    $Destination = "C:\kiosk.ico"
    Invoke-WebRequest -Uri $text -OutFile $Destination
    Write-Host 'Adding Kiosk Shortcut to Desktop'
    $TargetFile = "C:\v2.4_14vp\ms.Visitors.Kiosk.exe"
    $ShortcutFile = "$env:USERPROFILE\Desktop\MS Shift Kiosk.lnk"

    # Check if the target file exists
    if (-Not (Test-Path $TargetFile)) {
        Write-Host "Error: Target file does not exist at $TargetFile"
        return
    }

    # Ensure the Desktop directory exists
    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    if (-Not (Test-Path $desktopPath)) {
        Write-Host "Error: Desktop directory does not exist."
        return
    }

    # Create a shortcut object
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($ShortcutFile)

    # Set shortcut properties
    $Shortcut.TargetPath = $TargetFile
    $Shortcut.IconLocation = "C:\kiosk.ico"  # Adjust if the icon path is different
    $Shortcut.Save()

    Write-Host "Shortcut created at $ShortcutFile"


    $shortcutPath = "$env:USERPROFILE\Desktop\MS Shift Kiosk.lnk"
    $startupPath = [Environment]::GetFolderPath("Startup")
    Copy-Item $shortcutPath -Destination $startupPath
    Write-Host 'Added to startup!'

    'Parsing download site for Teamviewer Setup...'
            
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/50a71d63-6535-4343-88dc-f6870af278e2"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText

    'Downloading...'

    $Destination = "C:\Temp\Teamviewer.exe"
    Invoke-WebRequest -Uri $text -OutFile $Destination
    "Launching Teamviewer installer..."
    Start-Process -FilePath "C:\Temp\Teamviewer.exe"
    "Success!"

    'Disabling Rear Camera...'
    Get-PnpDevice -FriendlyName "*Microsoft Camera Rear*" | Disable-PnpDevice -Confirm:$false
    'Camera Disabled!'

    'Editing power plan settings...'
    Powercfg /Change monitor-timeout-ac 0
    Powercfg /Change monitor-timeout-dc 0
    Powercfg /Change standby-timeout-ac 0
    Powercfg /Change standby-timeout-dc 0
    'Power plan saved!'

    $batchContent = @"
@echo off
net stop spooler
ping -n 4 127.0.0.1 > nul 
echo Deleting Print Queue...
del %systemroot%\System32\spool\printers\* /Q
echo Queue Deleted.
net start spooler
"@

$vbsContent = @"
CreateObject("Wscript.Shell").Run "C:\Temp\QueueDeletion.bat",0,True
"@

        $batchFilePath = "C:\Temp\QueueDeletion.bat"
        $batchContent | Out-File -FilePath $batchFilePath -Encoding ascii
        "Batch File created in Temp folder..."

        "Creating VBS for silent launch..."
        $vbsFilePath = "C:\Temp\QueueDeletion.vbs"
        $vbsContent | Out-File -FilePath $vbsFilePath -Encoding ascii
        "VBS File created in Temp folder..."

        "Creating Scheduled Task..."
        $action = New-ScheduledTaskAction -Execute "C:\Temp\QueueDeletion.vbs"
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

        'Blocking Windows Updates...'

        # Check service status
        sc.exe query wuauserv

        # Stop process in case it is running

        sc.exe stop wuauserv

        # Set service to disabled
        sc.exe config wuauserv start=disabled

        'Start Value should be 0x4 if really disabled'
        REG.exe QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv /v Start

        # Disabled scheduled task
        'Disable scheduled task'
        Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\'  | Disable-ScheduledTask -ErrorAction SilentlyContinue

        'Make sure that all installation are complete, then continue.'
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

        'Blocking services...'
        New-NetFirewallRule -Program "C:\Program Files (x86)\DYMO\DYMO Connect\DYMOConnect.exe" -Action Block -Profile Domain, Private, Public -DisplayName Block DYMO Connect -Description Block DYMO Connect -Direction Outbound | Format-Table -AutoSize -Property DisplayName, Enabled, Direction, Action  
        New-NetFirewallRule -Program "C:\Program Files (x86)\DYMO\DYMO Connect\DYMO.WebApi.Win.Host.exe" -Action Block -Profile Domain, Private, Public -DisplayName Block DYMO WebService -Description Block DYMO WebService -Direction Outbound | Format-Table -AutoSize -Property DisplayName, Enabled, Direction, Action 
        
        'Removing all files from Temp Folder...'
        Get-ChildItem "C:\Temp\" -Recurse | Remove-Item -Force -Verbose   
        'Temp folder cleaned!'

        # Run Office uninstall command (you need the ODT setup folder with the config.xml file)
        Set-Location "C:\Program Files\Common Files\Microsoft Shared\ClickToRun"
        .\OfficeC2RClient.exe operation Uninstall

        # Steps to kill Explorer, and remove pinned items from Taskbar
        Stop-Process -Name explorer -Force
        Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Recurse -Force
        Start-Process explorer

        sc.exe stop AdobeARMservice
        Set-Service -Name "AdobeARMservice" -StartupType Disabled
        sc.exe query wuauserv
        sc.exe stop wuauserv
        sc.exe config wuauserv start=disabled
        # Disabled scheduled task
        'Disable scheduled task'
        Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\'  | Disable-ScheduledTask -ErrorAction SilentlyContinue
        'Adobe and Windows Updates blocked in Services.'

    Get-ScheduledTask | ForEach-Object {
        $task = $_
        $taskName = $task.TaskName
        
        if ($taskName -eq "Auto Kiosk Script") {
            $runningTask = Get-Process | Where-Object { $_.Path -like "*Auto Kiosk Script*" }

            if ($runningTask) {
                $runningTask | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
            }
            
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
    }

        'Deleting Local MS Shift User'
        Remove-LocalUser -Name "msshi"
