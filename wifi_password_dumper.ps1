# Check for Admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script requires Administrator privileges. Please run as Admin."
    break
}

$pcName = $env:COMPUTERNAME
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$filePath = Join-Path -Path $scriptDir -ChildPath "$($pcName)_Wifi_credentials.txt"

Write-Host "`nSaved Wi-Fi profiles and passwords:" -ForegroundColor Cyan
Write-Host "===================================`n" -ForegroundColor Cyan

# Get profiles (Regex bypasses language localization issues for the profile list)
$profiles = (netsh wlan show profiles) | ForEach-Object {
    if ($_ -match ":\s+(.+)$") { $matches[1].Trim() }
} | Where-Object { $_ -ne "" }

$output = @()
$output += "WiFi Credentials for: $pcName"
$output += "Generated on: $(Get-Date)"
$output += "===================================`n"

$count = 0
foreach ($profile in $profiles) {
    $count++
    Write-Host "[$count] Profile: $profile" -ForegroundColor Yellow
    
    # Get profile data
    $profileData = netsh wlan show profile name="$profile" key=clear
    
    # Extract password by looking specifically for "Key Content"
    $keyLine = $profileData | Select-String "Key Content" | Select-Object -First 1
    
    if ($keyLine) {
        # Split by the first colon and take the value, then trim whitespace
        $pwdValue = ($keyLine.Line -split ":\s+", 2)[-1].Trim()
    } else {
        $pwdValue = "[Open network or no password]"
    }
    
    Write-Host "    Password: $pwdValue" -ForegroundColor Green
    $output += "[$count] Profile: $profile"
    $output += "    Password: $pwdValue`n"
}

$output += "==================================="
$output += "Total profiles found: $count"
$output += "File location: $filePath"

# Save to file
$output | Out-File -FilePath $filePath -Encoding UTF8

Write-Host "`n===================================" -ForegroundColor Cyan
Write-Host "Total profiles found: $count"
Write-Host "File successfully saved to:" -ForegroundColor Cyan
Write-Host "$filePath`n"