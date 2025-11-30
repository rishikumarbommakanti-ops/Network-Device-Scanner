@echo off
REM Personal Antivirus - Windows Autorun Installer
REM Run this as Administrator to setup autorun on system startup

echo.
echo ================================================================================
echo  PERSONAL ANTIVIRUS - AUTORUN SETUP
echo ================================================================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script requires Administrator privileges!
    echo Please run this batch file as Administrator.
    pause
    exit /b 1
)

echo [+] Running with Administrator privileges
echo.

REM Get the script directory
set SCRIPT_DIR=%~dp0
set PYTHON_SCRIPT=%SCRIPT_DIR%personal_antivirus.py
set LOG_DIR=%APPDATA%\PersonalAntivirus
set STARTUP_FOLDER=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup

echo [*] Script location: %PYTHON_SCRIPT%
echo [*] Log directory: %LOG_DIR%
echo.

REM Create log directory if it doesn't exist
if not exist "%LOG_DIR%" (
    mkdir "%LOG_DIR%"
    echo [+] Created log directory
)

REM Create startup shortcut
echo [*] Creating startup shortcut...

REM Using PowerShell to create shortcut (more reliable)
powershell -Command ^
  "$TargetPath = 'C:\Python310\python.exe'; ^
  $Arguments = '"%PYTHON_SCRIPT%" --monitor'; ^
  $LinkLocation = '%STARTUP_FOLDER%\PersonalAntivirus.lnk'; ^
  $WshShell = New-Object -ComObject WScript.Shell; ^
  $Shortcut = $WshShell.CreateShortcut($LinkLocation); ^
  $Shortcut.TargetPath = $TargetPath; ^
  $Shortcut.Arguments = $Arguments; ^
  $Shortcut.WorkingDirectory = '%SCRIPT_DIR%'; ^
  $Shortcut.Description = 'Personal Antivirus - Network & Security Monitor'; ^
  $Shortcut.IconLocation = 'imageres.dll, 105'; ^
  $Shortcut.Save()"

if %errorLevel% equ 0 (
    echo [+] Startup shortcut created successfully
) else (
    echo [-] Failed to create shortcut via PowerShell, trying alternative method...
    REM Alternative: Add to registry for autorun
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "PersonalAntivirus" /t REG_SZ /d ""%PYTHON_SCRIPT%" --monitor" /f
    echo [+] Added to Windows registry autorun
)

echo.
echo [*] Installing Python dependencies...
python -m pip install psutil --quiet
if %errorLevel% equ 0 (
    echo [+] Dependencies installed successfully
) else (
    echo [-] Warning: Could not install dependencies. Please run: python -m pip install psutil
)

echo.
echo ================================================================================
echo  SETUP COMPLETE!
echo ================================================================================
echo.
echo The Personal Antivirus tool is now configured to run on system startup.
echo.
echo Features:
echo  * Monitors running processes for suspicious activity
echo  * Tracks network connections and open ports
echo  * Generates threat reports and logs
echo  * Runs in background during startup
echo.
echo Log files will be saved to: %LOG_DIR%
echo.
echo Press any key to exit...
pause >nul
exit /b 0
