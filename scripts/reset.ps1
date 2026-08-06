$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

Push-Location $projectRoot
try {
    Write-Host "Stopping containers and deleting local PostgreSQL and Redis data..." -ForegroundColor Yellow
    docker compose down -v --remove-orphans
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose failed to reset the project."
    }
    Write-Host "Local containers and data were removed." -ForegroundColor Green
}
finally {
    Pop-Location
}
