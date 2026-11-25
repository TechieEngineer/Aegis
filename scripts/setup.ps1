$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if (Test-Path .env) {
    Write-Host '.env already exists; preserving existing credentials.' -ForegroundColor Yellow
    exit 0
}
function New-HexSecret([int]$Length = 32) {
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}
$envText = @"
ADMIN_EMAIL=admin@aegis.local
ADMIN_PASSWORD=$(New-HexSecret 24)
POSTGRES_PASSWORD=$(New-HexSecret)
REDIS_PASSWORD=$(New-HexSecret)
JWT_SECRET=$(New-HexSecret)
MFA_SECRET=$(New-HexSecret)
PUBLIC_ORIGIN=http://localhost:3000
RECON_ALLOWED_HOSTS=
"@
[System.IO.File]::WriteAllText((Join-Path (Get-Location).Path '.env'), $envText + "`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Host 'Created .env with random credentials. View it locally to obtain the admin password; do not commit it.' -ForegroundColor Green
