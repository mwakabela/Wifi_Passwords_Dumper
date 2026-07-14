# Check for Admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges. Please run as Admin."
    break
}

$pcName = $env:COMPUTERNAME
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$filePath = Join-Path -Path $scriptDir -ChildPath "$($pcName)_Wifi_credentials.txt"

Write-Host "`nExtracting Wi-Fi profiles and passwords..." -ForegroundColor Cyan

# Get profiles
$profiles = (netsh wlan show profiles) | ForEach-Object {
    if ($_ -match ":\s+(.+)$") { $matches[1].Trim() }
} | Where-Object { $_ -ne "" }

# Create Header
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$header = @"
==================================================
        WI-FI PASSWORDS EXPORT RESULTS            
==================================================
Generated on: $timestamp
Device Name: $pcName
--------------------------------------------------
"@

$output = @($header)
Write-Host $header

$count = 0
foreach ($profile in $profiles) {
    $count++
    
    # Get profile data
    $profileData = netsh wlan show profile name="$profile" key=clear
    
    # Extract Password
    $keyLine = $profileData | Select-String "Key Content" | Select-Object -First 1
    if ($keyLine) {
        $pwdValue = ($keyLine.Line -split ":\s+", 2)[-1].Trim()
    } else {
        $pwdValue = "[None / Open Network]"
    }
    
    # Extract Security Type (Authentication)
    $authLine = $profileData | Select-String "Authentication" | Select-Object -First 1
    if ($authLine) {
        $security = ($authLine.Line -split ":\s+", 2)[-1].Trim()
    } else {
        $security = "Open"
    }
    
    # Format the entry
    $entry = @"

SSID: $profile
Security: $security
Password: $pwdValue
"@
    
    $output += $entry
    Write-Host $entry -ForegroundColor Yellow
}

# Create Footer
$footer = @"

==================================================
Total profiles found: $count
File saved to: $filePath
==================================================
"@

$output += $footer
Write-Host $footer -ForegroundColor Cyan

# Save to file
$output | Out-File -FilePath $filePath -Encoding UTF8

Write-Host "`nDone! File successfully saved to:" -ForegroundColor Green
Write-Host "$filePath`n"