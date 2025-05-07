# Created By Adam Waszczyszak
# Version 1.7
# Lightweight, simple version of the setup script to enable compatiblity on all systems

$host.ui.RawUI.WindowTitle = "Litetouch setup for new PC's by Adam Waszczyszak"
# Scripts Disabled Bypass from CMD: powershell -ExecutionPolicy Bypass -File "C:\Temp\PC_Setup.ps1"
# Update local group policy if the bypass does not work.

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

function Show-Menu {
    $titleColor = "Cyan"
    $borderColor = "Yellow"
    Write-Host ("="*40) -ForegroundColor $borderColor
    Write-Host "|             Toggle Menu              |" -ForegroundColor $titleColor
    Write-Host ("="*40) -ForegroundColor $borderColor
    Write-Host ""

    Write-Host "1. Windows Updates" 
    Write-Host "2. Create Temp + Visitor_Pic Folders (with permissions)"
    Write-Host "3. Microsoft Edge Registry Patch"
    Write-Host "4. API (silent)" 
    Write-Host "5. Adobe (silent)"   
    Write-Host "6. HF Scanner DS8108 (silent)"
    Write-Host "7. DYMO 550 (silent)"
    Write-Host "8. Signature Pad"
    Write-Host "9. LX-500 (must be plugged in)"
    Write-Host "10. GK420D"
    Write-Host "11. ZD-421"
    Write-Host "12. ZXP-7"
    Write-Host "13. Block DYMO Updates"
    Write-Host "14. Block Adobe Updates"
    Write-Host "15. Disable Windows Updates"
    Write-Host "16. Delete Temp Files"
    Write-Host "17. Edit Email Signature"
    Write-Host "18. Success Bookmarks"
    Write-Host "19. Full Package"
    Write-Host "20. CS Default Packages"
    Write-Host "Q. Execute selection and Quit"
}

Show-Menu

# Flags
$windowsUpdate = $false
$createFolders = $false
$msedgePatch = $false
$silentAPI = $false
$silentAdobe = $false
$silentScanner = $false
$silentDymo = $false
$signaturepad = $false
$lx500 = $false
$gk420d = $false
$zd421 = $false
$zxp = $false
$blockDymo = $false
$blockAdobe = $false
$blockWindows = $false
$deleteTemp = $false
$editSignature = $false
$fullPackage = $false
$successBookmarks = $false
$csDefault = $false

do {

    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        "1" {
            if($windowsUpdate -eq $false){
                $windowsUpdate = $true
                Write-Host "Windows Updates  Enabled"                
            }
            elseif($windowsUpdate -eq $true){
                $windowsUpdate = $false
                Write-Host "Windows Updates  Disabled"                
            }           
        }
        "2" {
            if($createFolders -eq $false){
                $createFolders = $true
                Write-Host "Folder Creation  Enabled"                
            }
            elseif($createFolders -eq $true){
                $createFolders = $false
                Write-Host "Folder Creation  Disabled"                
            }
        }
        "3" {
            if($msedgePatch -eq $false){
                $msedgePatch = $true
                Write-Host "MS Edge  Enabled"                
            }
            elseif($msedgePatch -eq $true){
                $msedgePatch = $false
                Write-Host "MS Edge  Disabled"                
            }
            
        }
        "4" {
            if($silentAPI -eq $false){
                $silentAPI = $true
                Write-Host "Silent Install of API  Enabled"                
            }
            elseif($silentAPI -eq $true){
                $silentAPI = $false
                Write-Host "Silent Install of API  Disabled"                
            }
            
        }  
        "5" {
            if($silentAdobe -eq $false){
                $silentAdobe = $true
                Write-Host "Silent Install of Adobe  Enabled"                
            }
            elseif($silentAdobe -eq $true){
                $silentAdobe = $false
                Write-Host "Silent Install of Adobe  Disabled"                
            }
            
        }      
        "6" {
            if($silentScanner -eq $false){
                $silentScanner = $true
                Write-Host "Silent Install of DS8108  Enabled"                
            }
            elseif($silentScanner -eq $true){
                $silentScanner = $false
                Write-Host "Silent Install of DS8108  Disabled"                
            }           
        }
        "7" {
            if($silentDymo -eq $false){
                $silentDymo = $true
                Write-Host "Silent DYMO Driver  Enabled"                
            }
            elseif($silentDymo -eq $true){
                $silentDymo = $false
                Write-Host "Silent DYMO Driver  Disabled"                
            }
        }
        "8" {
            if($signaturepad -eq $false){
                $signaturepad = $true
                Write-Host "Signature Pad Driver  Enabled"                
            }
            elseif($signaturepad -eq $true){
                $signaturepad = $false
                Write-Host "Signature Pad Driver  Disabled"                
            }
        }
        "9" {
            if($lx500 -eq $false){
                $lx500 = $true
                Write-Host "LX-500 Driver  Enabled"                
            }
            elseif($lx500 -eq $true){
                $lx500 = $false
                Write-Host "LX-500 Driver  Disabled"                
            }
            
        }
        "10" {
            if($gk420d -eq $false){
                $gk420d = $true
                Write-Host "GK-420d Driver  Enabled"                
            }
            elseif($gk420d -eq $true){
                $gk420d = $false
                Write-Host "GK-420d Driver  Disabled"                
            }
            
        }  
        "11" {
            if($zd421 -eq $false){
                $zd421 = $true
                Write-Host "ZD421 Driver  Enabled"                
            }
            elseif($zd421 -eq $true){
                $zd421 = $false
                Write-Host "ZD421 Driver  Disabled"                
            }
            
        }  
        "12" {
            if($zxp -eq $false){
                $zxp = $true
                Write-Host "ZXP-7 Driver  Enabled"                
            }
            elseif($zxp -eq $true){
                $zxp = $false
                Write-Host "ZXP-7 Driver  Disabled"                
            }           
        }
        "13" {
            if($blockDymo -eq $false){
                $blockDymo = $true
                Write-Host "Block DYMO Updates  Enabled"                
            }
            elseif($blockDymo -eq $true){
                $blockDymo = $false
                Write-Host "Block DYMO Updates  Disabled"                
            }
        }
        "14" {
            if($blockAdobe -eq $false){
                $blockAdobe = $true
                Write-Host "Block Adobe Updates  Enabled"                
            }
            elseif($blblockAdobeockAdobe -eq $true){
                $blockAdobe = $false
                Write-Host "Block Adobe Updates  Disabled"                
            }
            
        }
        "15" {
            if($blockWindows -eq $false){
                $blockWindows = $true
                Write-Host "Block Windows Updates  Enabled"                
            }
            elseif($blockWindows -eq $true){
                $blockWindows = $false
                Write-Host "Block Windows Updates  Disabled"               
            }
            
        }  
        "16" {
            if($deleteTemp -eq $false){
                $deleteTemp = $true
                Write-Host "Delete files in Temp  Enabled"                
            }
            elseif($deleteTemp -eq $true){
                $deleteTemp = $false
                Write-Host "Delete files in Temp  Disabled"                
            }
            
        }      
        "17" {
            if($editSignature -eq $false){
                $editSignature = $true
                Write-Host "Edit Email Signature  Enabled"                
            }
            elseif($editSignature -eq $true){
                $editSignature = $false
                Write-Host "Edit Email Signature  Disabled"                
            }           
        }
        "18" {
            if($successBookmarks -eq $false){
                $successBookmarks = $true
                Write-Host "Success Bookmarks  Enabled"                
            }
            elseif($successBookmarks -eq $true){
                $successBookmarks = $false
                Write-Host "Success Bookmarks  Disabled"                
            }
        }        
        "19" {
            if($fullPackage -eq $false){
                $fullPackage = $true
                Write-Host "Full Package  Enabled"                
            }
            elseif($fullPackage -eq $true){
                $fullPackage = $false
                Write-Host "Full Package  Disabled"                
            }
        }
        "20" {
            if($csDefault -eq $false){
                $csDefault = $true
                Write-Host "CS Default Package  Enabled"                
            }
            elseif($csDefault -eq $true){
                $csDefault = $false
                Write-Host "CS Default Package  Disabled"                
            }
        }
        "Q" {
            Write-Host "Executing Selected Choices..."
            break
        }
        default {
            Write-Host "Invalid choice."
        }
    }
    Write-Host ""
} while ($choice -ne "Q")

if($fullPackage -eq $true){
    $windowsUpdate = $true
    $createFolders = $true
    $msedgePatch = $true
    $silentAPI = $true
    $silentAdobe = $true
    $silentScanner = $true
    $silentDymo = $true
    $signaturepad = $true
    $lx500 = $true
    $gk420d = $true
    $zd421 = $true
    $zxp = $true
    $blockDymo = $true
    $blockAdobe = $true
    $blockWindows = $true
    $deleteTemp = $true
    $editSignature = $true
    $successBookmarks =$true
}
if($csDefault -eq $true){
    $windowsUpdate = $true
    $createFolders = $true
    $msedgePatch = $true
    $silentAPI = $true
    $silentAdobe = $true
    $silentScanner = $true
    $silentDymo = $true
    $signaturepad = $true
    $zxp = $true
    $blockDymo = $true
    $blockAdobe = $true
    $blockWindows = $true
    $deleteTemp = $true
    $successBookmarks =$true
}

if($windowsUpdate -eq $true){
    'Installing Windows Update PS Module...'
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name PSWindowsUpdate -Force
    'Installing all newest Windows Updates'
    Import-Module -Name PSWindowsUpdate -Force
    Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot -Verbose
    'Done, remember to restart later!'
}
if($createFolders -eq $true){
    if (Test-Path -Path C:\Temp){
        "Temp Folder Already Exists"
        }

        else{
            New-Item -Path C:\Temp -ItemType Directory
        }

        if (Test-Path -Path C:\Visitor_pic){
            "Visitor_Pic Folder Already Exists"
        }

        else{
            New-Item -Path C:\Visitor_pic -ItemType Directory
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
}
if($msedgePatch -eq $true){
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
}
if($silentAPI -eq $true){
    'Parsing download site for API Download Link...'     
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/c8789c47-a01f-452e-8ffc-1a6143eb2c16"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText
    'Downloading...'
    $Destination = "C:\Temp\api.zip" 
    Invoke-WebRequest -Uri $text -OutFile $Destination
    'Uncompressing...'
    Expand-Archive -LiteralPath 'C:\Temp\api.zip' -DestinationPath C:\Temp
    "Launching API with silent installer params..."
    Start-Process -FilePath "C:\Temp\New API\MSShift.DevicesAPI.Setup.1.9.msi" -ArgumentList "/passive", "/norestart"
    "Success!"
    Read-Host -Prompt "Press any key to continue..."
}
if($silentAdobe -eq $true){
    'Parsing download site for Adobe Installer...'
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
    Read-Host -Prompt "Press any key to continue..."    
}
if($silentScanner -eq $true){
    'Parsing download site for DS8108 driver...'
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/c862d6fc-fc72-4e77-8347-ab079c8d4fa3"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText
    'Downloading driver...'

    $Destination = "C:\Temp\Zebra_CoreScanner_Driver.exe" 
    Invoke-WebRequest -Uri $text -OutFile $Destination

    'Parsing download site for PDF downloads...'
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/76cdef97-2774-4b11-9adb-14b0220159f5"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText

    'Downloading Restore Default PDF...'

    $Destination = "C:\Temp\Restore Default.pdf" 
    Invoke-WebRequest -Uri $text -OutFile $Destination

    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/e5a5d996-6a66-400b-a2c7-548627642815"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText

    'Downloading ScanX_Config_Codebar PDF...'

    $Destination = "C:\Temp\ScanX_Config_Codebar.pdf" 
    Invoke-WebRequest -Uri $text -OutFile $Destination

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
   Start-Process "cmd.exe" -ArgumentList "/c", "$exePath -s -f1`"$issFilePath`""

   Read-Host -Prompt "CMD launched with Zebra Installer and arguments. Press any key to continue..." 
}
if($signaturepad -eq $true){
    'Parsing download site for Signature Pad driver...'
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/e43d957b-0b20-4422-a3d0-a114162c5dfe"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText
    'Downloading...'
    $Destination = "C:\Temp\sigplus_.exe" 
    Invoke-WebRequest -Uri $text -OutFile $Destination
    "Launching Signature Pad installer..."
    Start-Process -FilePath "C:\Temp\sigplus_.exe"
    "Success!"
    Read-Host -Prompt "Press any key to continue..." 
}
if($lx500 -eq $true){
    'Parsing download site for LX-500 driver...'
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/7ebdd547-4c3c-4dc4-8639-e0ce88c1f60c"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText
    'Downloading...'
    $Destination = "C:\Temp\Primera.2.3.1.exe" 
    Invoke-WebRequest -Uri $text -OutFile $Destination
    "Launching LX 500 installer..."
    Start-Process -FilePath "C:\Temp\Primera.2.3.1.exe"
    "Success!"
    Read-Host -Prompt "Press any key to continue..."
}
if($gk420d -eq $true){
    'Parsing download site for GK 420d driver...'
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/2923c379-b7a0-4506-9c28-4ea5b2c0e48c"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText
    'Downloading...'
    $Destination = "C:\Temp\zd51.exe" 
    Invoke-WebRequest -Uri $text -OutFile $Destination
    "Launching GK420d driver installer..."
    Start-Process -FilePath "C:\Temp\zd51.exe"
    "Success!"
    Read-Host -Prompt "Press any key to continue..."
}
if($zd421 -eq $true){
    'Parsing download site for ZD421 driver...'
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/75b8f783-51f0-4a8a-9128-bf6957480aa4"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText
    'Downloading...'
    $Destination = "C:\Temp\zd105.exe" 
    Invoke-WebRequest -Uri $text -OutFile $Destination
    "Launching ZD421/420 driver installer..."
    Start-Process -FilePath "C:\Temp\zd105.exe"
    "Success!"
    Read-Host -Prompt "Press any key to continue..."
}
if($zxp -eq $true){
    'Parsing download site for ZXP-7...'
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/7cc7f865-5107-4f8b-9f3e-617b8ca23802"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText
    'Downloading...'
    $Destination = "C:\Temp\ZXP73.0.2.exe" 
    Invoke-WebRequest -Uri $text -OutFile $Destination
    "Launching ZXP-7 driver installer..."
    Start-Process -FilePath "C:\Temp\ZXP73.0.2.exe"
    "Success!"
    Read-Host -Prompt "Press any key to continue..."
}
if($silentDymo -eq $true){
    'Parsing download site for DYMO 550 driver...'
    # Retrieve the HTML content of the website
    $response = Invoke-WebRequest -Uri "https://download.msshift.com/link/1ab37806-4228-4eb1-8178-1ba492b0ea0f"
    # Extract the text content from the parsed HTML
    $text = $response.ParsedHtml.body.innerText
    'Downloading...'
    $Destination = "C:\Temp\DCDSetup1.4.5.1.exe" 
    Invoke-WebRequest -Uri $text -OutFile $Destination
    "Launching DYMO 550 driver with silent installer params..."
    Start-Process -FilePath "C:\Temp\DCDSetup1.4.5.1.exe" -ArgumentList "/S", "/v/qn"
    "Success!"
    Read-Host -Prompt "Press any key to continue..."
}
if($blockDymo -eq $true){
    'Blocking services...'
    New-NetFirewallRule -Program "C:\Program Files (x86)\DYMO\DYMO Connect\DYMOConnect.exe" -Action Block -Profile Domain, Private, Public -DisplayName “Block DYMO Connect” -Description “Block DYMO Connect” -Direction Outbound | Format-Table -AutoSize -Property DisplayName, Enabled, Direction, Action  
    New-NetFirewallRule -Program "C:\Program Files (x86)\DYMO\DYMO Connect\DYMO.WebApi.Win.Host.exe" -Action Block -Profile Domain, Private, Public -DisplayName “Block DYMO WebService” -Description “Block DYMO WebService” -Direction Outbound | Format-Table -AutoSize -Property DisplayName, Enabled, Direction, Action 
}
if($blockAdobe -eq $true){

    sc.exe stop AdobeARMservice
    Set-Service -Name "AdobeARMservice" -StartupType Disabled

    "Adobe Update Services Blocked In Services.msc"
}
if($blockWindows -eq $true){
    sc.exe query wuauserv
    sc.exe stop wuauserv
    sc.exe config wuauserv start=disabled
    'Start Value should be 0x4'
    REG.exe QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv /v Start
    'Disable scheduled task'
    Get-ScheduledTask -TaskPath '\Microsoft\Windows\WindowsUpdate\'  | Disable-ScheduledTask -ErrorAction SilentlyContinue
}
if($deleteTemp -eq $true){
    'Removing all drivers from Temp Folder...'

    Get-ChildItem "C:\Temp\" -Recurse | Remove-Item -Force -Verbose

    'Temp folder cleaned!'
}
if($editSignature -eq $true){
    # Make sure that the new signature is created as their FIRST name.
    # Get new user's first name, last name
    $newFirst = Read-Host "New User's first name"
    $newLast = Read-Host "New User's last name"
    
    # Define the file path to the signature HTML file
    $filePath = "C:\Users\$newFirst$newLast\AppData\Roaming\Microsoft\Signatures\$newFirst ($newFirst.$newLast@msshift-usa.com).htm"
    
    # Read the file content into an array of lines
    $lines = Get-Content $filePath
    
    # Define the regular expression to match the src URL pattern
    $pattern = '(?<=MS_EMAIL_RES/)(.*?)(?=\.png)'
    
    # Loop through the lines and replace the part of the URL between MS_EMAIL_RES/ and .png
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match $pattern) {
            # Replace the template full name with the new one
            $newImageName = "$newFirst$newLast/$newFirst$newLast"
            $lines[$i] = $lines[$i] -replace $pattern, $newImageName
        }
    }
    
    # Write the modified content back to the file
    Set-Content $filePath $lines
    
    'New line written and saved!'    
}

if($successBookmarks -eq $true){

    $csBookContent = @"
{
   "checksum": "5038894737ee701db294d22481f6e742",
   "roots": {
      "bookmark_bar": {
         "children": [ {
            "date_added": "13381607809000000",
            "date_last_used": "0",
            "guid": "de519d2b-c902-42ea-ae91-f272c8ce54d0",
            "id": "26",
            "name": "Hilton Demo",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://msshift-hw.com/default?sk=CdFALM8WDxusEst3Cn38DA%3D%3D",
            "visit_count": 0
         }, {
            "date_added": "13381607837000000",
            "date_last_used": "0",
            "guid": "f48c3c1e-3cf0-42ea-b080-c52a576112f3",
            "id": "27",
            "name": "MS Info",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://msshift.info/Account/login?ReturnUrl=%2F",
            "visit_count": 0
         }, {
            "date_added": "13381607856000000",
            "date_last_used": "0",
            "guid": "c01381ab-d218-4342-b354-ea6162953f17",
            "id": "28",
            "name": "Sec 2 Demo",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://msshift-security-2.com/default?sk=ZQIwnU5zh0W46StJCAxvNg%3D%3D",
            "visit_count": 0
         }, {
            "date_added": "13381607871000000",
            "date_last_used": "0",
            "guid": "acaa35f1-f5dc-47d1-a07b-4594aa410d55",
            "id": "29",
            "name": "RingCentral",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://app.ringcentral.com/login",
            "visit_count": 0
         }, {
            "date_added": "13381607891000000",
            "date_last_used": "0",
            "guid": "69ff0fc3-2a82-4a62-84f3-649070403248",
            "id": "30",
            "name": "Ring Central Analytics",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://analytics.ringcentral.com/",
            "visit_count": 0
         }, {
            "date_added": "13381607934000000",
            "date_last_used": "0",
            "guid": "58ca4233-5053-4538-a8ca-cf64d9ada725",
            "id": "31",
            "name": "Dropbox",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://app.hellosign.com/account/logIn",
            "visit_count": 0
         }, {
            "date_added": "13381607976000000",
            "date_last_used": "0",
            "guid": "952b1a49-e0c1-4d84-a8e4-53198171b759",
            "id": "32",
            "name": "Confluence",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://ms-shift.atlassian.net/wiki/home",
            "visit_count": 0
         }, {
            "date_added": "13381608018000000",
            "date_last_used": "0",
            "guid": "cd43984d-bc65-4361-bab9-f81db6f5250e",
            "id": "33",
            "name": "ADP",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://online.adp.com/signin/v1/?APPID=WFNPortal&productId=80e309c3-7085-bae1-e053-3505430b5495&returnURL=https://workforcenow.adp.com/&callingAppId=WFN&TARGET=-SM-https://workforcenow.adp.com/theme/unified.html",
            "visit_count": 0
         }, {
            "date_added": "13381608067000000",
            "date_last_used": "0",
            "guid": "64ea04c7-4806-434a-8211-7b7cff275199",
            "id": "34",
            "name": "FedEx Shipping Rates ",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://www.fedex.com/en-us/online/rating.html#",
            "visit_count": 0
         }, {
            "date_added": "13381608108000000",
            "date_last_used": "0",
            "guid": "d4a40031-8b61-4f42-b263-f8890e53ec56",
            "id": "35",
            "name": "Bookings",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://outlook.office.com/bookings/homepage",
            "visit_count": 0
         }, {
            "date_added": "13381608131000000",
            "date_last_used": "0",
            "guid": "72397612-22a5-4a11-92b6-9698f3aa0acf",
            "id": "36",
            "name": "Forms",
            "show_icon": false,
            "source": "import_fre",
            "type": "url",
            "url": "https://forms.office.com/Pages/DesignPageV2.aspx?subpage=creationv2",
            "visit_count": 0
         } ],
         "date_added": "13372174174772540",
         "date_last_used": "0",
         "date_modified": "0",
         "guid": "0bc5d13f-2cba-5d74-951f-3f233fe6c908",
         "id": "1",
         "name": "Favorites bar",
         "source": "unknown",
         "type": "folder"
      },
      "other": {
         "children": [  ],
         "date_added": "13372174174772550",
         "date_last_used": "0",
         "date_modified": "0",
         "guid": "82b081ec-3dd3-529c-8475-ab6c344590dd",
         "id": "2",
         "name": "Other favorites",
         "source": "unknown",
         "type": "folder"
      },
      "synced": {
         "children": [  ],
         "date_added": "13372174174772551",
         "date_last_used": "0",
         "date_modified": "0",
         "guid": "4cf2e351-0e85-532b-bb37-df045d8f8d0f",
         "id": "3",
         "name": "Mobile favorites",
         "source": "unknown",
         "type": "folder"
      }
   },
   "version": 1
}

"@

    $EdgeProfilePath = Join-Path $env:USERPROFILE "AppData\Local\Microsoft\Edge\User Data\Default"
    $csBookmarksFilePath = Join-Path $EdgeProfilePath "Bookmarks"
    $csBookContent | Out-File -FilePath $csBookmarksFilePath -Encoding ascii -Force
    'Bookmarks Updated...'

}

'Script Finished. Goodbye!'
Start-Sleep -Seconds 3
[System.Environment]::Exit(1)
