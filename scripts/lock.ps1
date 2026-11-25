$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$root = (Get-Location).Path
# Generate actual dependency checksums using Docker; no host Go or Node install required.
docker run --rm --mount "type=bind,source=$root\backend,target=/src" -w /src golang:1.27-alpine go mod tidy
if ($LASTEXITCODE -ne 0) { throw 'Go dependency resolution failed' }
docker run --rm --mount "type=bind,source=$root\frontend,target=/src" -w /src node:22-alpine npm install --package-lock-only --no-audit
if ($LASTEXITCODE -ne 0) { throw 'npm dependency resolution failed' }
Write-Host 'Dependency lock files generated. Commit backend/go.sum, backend/go.mod and frontend/package-lock.json.' -ForegroundColor Green
