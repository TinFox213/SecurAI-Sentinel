# WebSec Ops Endpoint Test Script
# Run after the backend is listening on http://localhost:3001.

$baseUrl = "http://localhost:3001"

function Invoke-JsonPost {
    param(
        [string]$Name,
        [string]$Path,
        [hashtable]$Payload,
        [int]$TimeoutSec = 20
    )

    Write-Host "Testing $Name..." -ForegroundColor Cyan
    try {
        $body = $Payload | ConvertTo-Json -Depth 8
        $response = Invoke-RestMethod -Uri "$baseUrl$Path" -Method Post -Body $body -ContentType "application/json" -TimeoutSec $TimeoutSec
        Write-Host "PASS: $Name" -ForegroundColor Green
        return $response
    } catch {
        Write-Host "FAIL: $Name - $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

Write-Host "Testing WebSec Ops endpoints" -ForegroundColor Cyan
Write-Host ""

$sslResponse = Invoke-JsonPost -Name "SSL Sentinel" -Path "/web/ssl" -Payload @{ domain = "google.com" }
if ($sslResponse) {
    Write-Host "  Domain: $($sslResponse.domain)" -ForegroundColor Gray
    Write-Host "  Valid: $($sslResponse.valid)" -ForegroundColor Gray
    Write-Host "  Days Remaining: $($sslResponse.daysRemaining)" -ForegroundColor Gray
}
Write-Host ""

$headerResponse = Invoke-JsonPost -Name "Security Headers" -Path "/web/headers" -Payload @{ url = "https://google.com" }
if ($headerResponse) {
    Write-Host "  URL: $($headerResponse.url)" -ForegroundColor Gray
    Write-Host "  Status: $($headerResponse.status)" -ForegroundColor Gray
}
Write-Host ""

$dnsResponse = Invoke-JsonPost -Name "DNS Integrity" -Path "/web/dns" -Payload @{ domain = "google.com" }
if ($dnsResponse) {
    Write-Host "  Domain: $($dnsResponse.domain)" -ForegroundColor Gray
    Write-Host "  Status: $($dnsResponse.status)" -ForegroundColor Gray
}
Write-Host ""

$reconResponse = Invoke-JsonPost -Name "Subdomain Recon" -Path "/osint/subdomains" -Payload @{ domain = "google.com" } -TimeoutSec 30
if ($reconResponse) {
    Write-Host "  Domain: $($reconResponse.domain)" -ForegroundColor Gray
    Write-Host "  Subdomains Found: $($reconResponse.count)" -ForegroundColor Gray
    Write-Host "  Source: $($reconResponse.source)" -ForegroundColor Gray
}
Write-Host ""

Write-Host "WebSec Ops endpoint testing complete" -ForegroundColor Cyan
