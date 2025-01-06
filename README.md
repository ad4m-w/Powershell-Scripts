# shift_kiosk
Run this in Powershell using:

$ScriptFromGitHub = Invoke-WebRequest https://raw.githubusercontent.com/ad4m-w/shift_kiosk/refs/heads/main/Kiosk_Setup.ps1

Invoke-Expression $($ScriptFromGitHub.Content)
