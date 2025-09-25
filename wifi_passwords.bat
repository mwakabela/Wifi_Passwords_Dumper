@echo off
setlocal enabledelayedexpansion

echo.
echo Saved Wi-Fi profiles and passwords:
echo ===================================
echo.

REM Get computer name for the filename
set "PCName=%COMPUTERNAME%"

REM Get the directory where the script is located
set "scriptdir=%~dp0"
if "!scriptdir:~-1!"=="\" set "scriptdir=!scriptdir:~0,-1!"

REM Create filename with full path to script directory
set "filename=%PCName%_Wifi_credentials.txt"
set "fullpath=%scriptdir%\%filename%"

REM Check admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Must run as Administrator!
    echo Right-click -> "Run as administrator"
    pause
    exit /b 1
)

echo Saving WiFi credentials to:
echo !fullpath!
echo.

REM Clear previous file and write header
echo WiFi Credentials for: %PCName% > "!fullpath!"
echo Generated on: %date% %time% >> "!fullpath!"
echo =================================== >> "!fullpath!"
echo. >> "!fullpath!"

set "count=0"

for /f "tokens=2 delims=:" %%i in ('netsh wlan show profiles ^| findstr "All User Profile"') do (
    set "profile=%%i"
    set "profile=!profile:~1!"
    set /a count+=1
    
    REM Display to console
    echo [!count!] Profile: !profile!
    
    REM Write to file
    echo [!count!] Profile: !profile! >> "!fullpath!"
    
    set "password_found=0"
    
    REM Only look for "Key Content" specifically
    for /f "tokens=2 delims=:" %%p in ('netsh wlan show profile name^="!profile!" key^=clear ^| findstr /i /c:"Key Content"') do (
        set "password=%%p"
        set "password=!password:~1!"
        
        REM Only process if it's not empty and not "Present/Absent"
        if not "!password!"=="" (
            if /i not "!password!"=="Present" (
                if /i not "!password!"=="Absent" (
                    REM Display to console
                    echo     Password: !password!
                    
                    REM Write to file
                    echo     Password: !password! >> "!fullpath!"
                    
                    set "password_found=1"
                )
            )
        )
    )
    
    if !password_found! equ 0 (
        REM Display to console
        echo     Password: [Open network or no password]
        
        REM Write to file
        echo     Password: [Open network or no password] >> "!fullpath!"
    )
    
    REM Write empty line to file
    echo. >> "!fullpath!"
    
    REM Display empty line to console
    echo.
)

REM Write footer to file
echo =================================== >> "!fullpath!"
echo Total profiles found: %count% >> "!fullpath!"
echo File location: !fullpath! >> "!fullpath!"

REM Display footer to console
echo ===================================
echo Total profiles found: %count%
echo File successfully saved to:
echo !fullpath!
echo.
echo Note: The file is saved in the same folder as this script.
pause
endlocal