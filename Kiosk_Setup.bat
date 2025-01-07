:: Launcher for Kiosk_Setup.ps1 Script
powershell -ExecutionPolicy Bypass -File "%~dp0Kiosk_Setup.ps1"

@echo "Path for script execution GPO is:"
@echo "gpedit.msc -> Computer Configuration -> Administrative Templates -> Windows Components -> Windows Powershell -> Turn on Script Execution."
@echo "Remember to run gpupdate /force"

cmd 