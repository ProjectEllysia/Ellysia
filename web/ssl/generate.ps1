param(
    [string]$Domain = "ellysia.es"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Find OpenSSL ───────────────────────────────────────────────
$openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source

if (-not $openssl) {
    $gitOpenSSL = "C:\Program Files\Git\usr\bin\openssl.exe"
    if (Test-Path $gitOpenSSL) {
        $openssl = $gitOpenSSL
    }
}

if (-not $openssl) {
    Write-Host "ERROR: OpenSSL not found." -ForegroundColor Red
    Write-Host "Install Git for Windows (https://git-scm.com) or OpenSSL and ensure it is in PATH." -ForegroundColor Yellow
    exit 1
}

Write-Host "Using: $openssl" -ForegroundColor Gray

# ── Generate self-signed certificate ───────────────────────────
$keyFile  = Join-Path $ScriptDir "ellysia.key"
$certFile = Join-Path $ScriptDir "ellysia.crt"

Write-Host "Generating self-signed certificate for $Domain (includes *.${Domain} and api.${Domain})..." -ForegroundColor Cyan

& $openssl req -x509 -nodes -days 365 `
    -subj "/CN=$Domain" `
    -addext "subjectAltName=DNS:${Domain},DNS:*.${Domain},DNS:api.${Domain},DNS:localhost,IP:127.0.0.1" `
    -newkey rsa:2048 `
    -keyout $keyFile `
    -out $certFile

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: OpenSSL failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Certificate generated:" -ForegroundColor Green
Write-Host "  Key : $keyFile" -ForegroundColor White
Write-Host "  Cert: $certFile" -ForegroundColor White
Write-Host ""
Write-Host "Restart the container after generation:" -ForegroundColor Yellow
Write-Host "  docker compose --profile container restart web" -ForegroundColor Gray
