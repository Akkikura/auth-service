param(
    [string]$BaseUrl = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"
$baseUrl = $BaseUrl.TrimEnd('/')
$email = "demo-$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())@example.com"
$password = "correct-horse-battery-staple"
$credentials = @{ email = $email; password = $password } | ConvertTo-Json

Write-Host "1/6 Checking readiness..." -ForegroundColor Cyan
$health = Invoke-RestMethod -Uri "$baseUrl/health/ready" -TimeoutSec 10
if ($health.status -ne "ok") {
    throw "Readiness endpoint did not return status=ok."
}

Write-Host "2/6 Registering $email..." -ForegroundColor Cyan
$user = Invoke-RestMethod `
    -Method Post `
    -Uri "$baseUrl/register" `
    -ContentType "application/json" `
    -Body $credentials
$user | ConvertTo-Json

Write-Host "3/6 Logging in..." -ForegroundColor Cyan
$session = Invoke-RestMethod `
    -Method Post `
    -Uri "$baseUrl/login" `
    -ContentType "application/json" `
    -Body $credentials

if (-not $session.token) {
    throw "Login response did not contain a token."
}

$headers = @{ Authorization = "Bearer $($session.token)" }
Write-Host "Token received. Expires at: $($session.expires_at)" -ForegroundColor Green

Write-Host "4/6 Reading the current user..." -ForegroundColor Cyan
$currentUser = Invoke-RestMethod -Uri "$baseUrl/me" -Headers $headers -TimeoutSec 10
$currentUser | ConvertTo-Json

if ($currentUser.email -ne $email) {
    throw "GET /me returned an unexpected email address."
}

Write-Host "5/6 Logging out..." -ForegroundColor Cyan
Invoke-RestMethod -Method Post -Uri "$baseUrl/logout" -Headers $headers -TimeoutSec 10

Write-Host "6/6 Verifying token revocation..." -ForegroundColor Cyan
try {
    Invoke-RestMethod -Uri "$baseUrl/me" -Headers $headers -TimeoutSec 10
    throw "The revoked token was unexpectedly accepted."
}
catch {
    $statusCode = $null
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
        $statusCode = [int]$_.Exception.Response.StatusCode
    }

    if ($statusCode -ne 401) {
        throw
    }
}

Write-Host "Smoke test passed." -ForegroundColor Green
