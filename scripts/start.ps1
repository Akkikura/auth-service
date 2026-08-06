$ErrorActionPreference = "Stop"

if (Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$projectRoot = Split-Path -Parent $PSScriptRoot

function Invoke-Docker {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw $FailureMessage
    }
}

function Show-RecentLogs {
    Write-Host ""
    Write-Host "Recent container logs:" -ForegroundColor Yellow
    & docker compose logs --tail 150
}

Push-Location $projectRoot
try {
    Write-Host "Starting Auth Service backend..." -ForegroundColor Cyan

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Docker was not found. Install Docker Desktop, restart PowerShell, and run this script again."
    }

    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Desktop is not running. Start Docker Desktop and wait until the engine is ready."
    }

    & docker compose version *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose v2 is not available. Update Docker Desktop and run this script again."
    }

    if (-not (Test-Path ".env")) {
        if (-not (Test-Path ".env.example")) {
            throw ".env.example was not found in the project root."
        }

        Copy-Item ".env.example" ".env"
        Write-Host "Created .env from .env.example." -ForegroundColor DarkGray
    }

    Write-Host "Building API and migration binaries..." -ForegroundColor Cyan
    Invoke-Docker `
        -Arguments @("compose", "--progress", "plain", "build") `
        -FailureMessage "Docker image build failed. Review the compiler output above."

    Write-Host "Starting PostgreSQL, Redis, migrations, and API..." -ForegroundColor Cyan
    Invoke-Docker `
        -Arguments @("compose", "up", "-d", "--wait") `
        -FailureMessage "Docker Compose failed to start all services."

    $portBinding = $null
    $portDeadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $portDeadline -and -not $portBinding) {
        $portOutput = (& docker compose port api 8080 2>$null)
        if ($LASTEXITCODE -eq 0 -and $portOutput) {
            $portBinding = $portOutput | Select-Object -First 1
            break
        }
        Start-Sleep -Milliseconds 250
    }

    if (-not $portBinding) {
        Show-RecentLogs
        throw "Could not determine the published API port."
    }

    $hostPort = (($portBinding.Trim()) -split ':')[-1]
    if (-not $hostPort) {
        throw "Could not parse the published API port: $portBinding"
    }

    $baseUrl = "http://localhost:$hostPort"
    $deadline = (Get-Date).AddSeconds(120)
    $ready = $false
    $lastError = $null

    while ((Get-Date) -lt $deadline) {
        try {
            $health = Invoke-RestMethod -Uri "$baseUrl/health/ready" -TimeoutSec 5
            if ($health.status -eq "ok") {
                $ready = $true
                break
            }
        }
        catch {
            $lastError = $_.Exception.Message
        }

        Start-Sleep -Seconds 2
    }

    if (-not $ready) {
        Show-RecentLogs
        if ($lastError) {
            throw "The service did not become ready within 120 seconds. Last error: $lastError"
        }
        throw "The service did not become ready within 120 seconds."
    }

    Write-Host ""
    Write-Host "Auth Service backend is running." -ForegroundColor Green
    Write-Host "API base URL: $baseUrl"
    Write-Host "Readiness:    $baseUrl/health/ready"
    Write-Host "Liveness:     $baseUrl/health/live"
    Write-Host "Metrics:      $baseUrl/metrics"
    Write-Host ""
    Write-Host "API endpoints:" -ForegroundColor Cyan
    Write-Host "POST $baseUrl/register"
    Write-Host "POST $baseUrl/login"
    Write-Host "GET  $baseUrl/me"
    Write-Host "POST $baseUrl/logout"
    Write-Host ""
    Write-Host "Run the complete API check:" -ForegroundColor DarkGray
    Write-Host "powershell -ExecutionPolicy Bypass -File .\scripts\smoke-test.ps1"
    Write-Host ""
    Write-Host "Stop services:       powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1" -ForegroundColor DarkGray
    Write-Host "Delete all test data: powershell -ExecutionPolicy Bypass -File .\scripts\reset.ps1" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "The backend-only project has no web page at /. A 404 response there is expected." -ForegroundColor Yellow
}
catch {
    Write-Host ""
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
finally {
    Pop-Location
}
