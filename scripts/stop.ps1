$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

Push-Location $projectRoot
try {
    docker compose down
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose failed to stop the project."
    }
    Write-Host "Auth Service stopped." -ForegroundColor Green
}
finally {
    Pop-Location
}
