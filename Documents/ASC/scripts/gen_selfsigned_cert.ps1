#Requires -Version 5.1
# ─── ASC PremosCorp — Self-Signed TLS Certificate Generator (Windows) ────────
#
# PURPOSE: Generate a self-signed certificate for dev/staging environments.
#          Requires OpenSSL for Windows (comes with Git for Windows).
#          NOT for production — use Let's Encrypt (see docs/TLS_SETUP.md).
#
# USAGE:
#   .\scripts\gen_selfsigned_cert.ps1
#   .\scripts\gen_selfsigned_cert.ps1 -Domain asc.premoscorp.com
#
# OUTPUT:
#   infra\nginx\certs\fullchain.pem  — self-signed certificate (365 days)
#   infra\nginx\certs\privkey.pem    — RSA 2048-bit private key
#
# SECURITY:
#   These files are gitignored — never committed (see infra/nginx/certs/.gitignore)
# ─────────────────────────────────────────────────────────────────────────────
param(
    [string]$Domain = "localhost"
)

$ErrorActionPreference = "Stop"

$scriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot   = Split-Path -Parent $scriptDir
$certsDir   = Join-Path $repoRoot "infra\nginx\certs"

Write-Host "──────────────────────────────────────────────────────"
Write-Host "  ASC PremosCorp — Self-Signed Certificate Generator  "
Write-Host "──────────────────────────────────────────────────────"
Write-Host "  Domain  : $Domain"
Write-Host "  Certs   : $certsDir"
Write-Host ""

# Locate openssl — Git for Windows bundles it at C:\Program Files\Git\usr\bin\openssl.exe
$opensslCmd = $null
foreach ($candidate in @(
    "openssl",
    "C:\Program Files\Git\usr\bin\openssl.exe",
    "C:\Program Files (x86)\Git\usr\bin\openssl.exe",
    "$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe"
)) {
    try {
        & $candidate version 2>$null | Out-Null
        $opensslCmd = $candidate
        break
    } catch {}
}

if (-not $opensslCmd) {
    Write-Error @"
ERROR: openssl not found.
Install one of:
  • Git for Windows (includes openssl): https://git-scm.com/download/win
  • OpenSSL for Windows: https://slproweb.com/products/Win32OpenSSL.html
  • WSL: run bash scripts/gen_selfsigned_cert.sh instead
"@
    exit 1
}

New-Item -ItemType Directory -Force -Path $certsDir | Out-Null

$keyOut  = Join-Path $certsDir "privkey.pem"
$certOut = Join-Path $certsDir "fullchain.pem"
$san     = "subjectAltName=DNS:$Domain,DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

$opensslArgs = @(
    "req", "-x509",
    "-nodes",
    "-days", "365",
    "-newkey", "rsa:2048",
    "-keyout", $keyOut,
    "-out",    $certOut,
    "-subj",   "/C=US/ST=Security/L=SOC/O=PremosCorp/OU=ASC/CN=$Domain",
    "-addext",  $san
)

Write-Host "Generating certificate..."
& $opensslCmd @opensslArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "openssl failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host ""
Write-Host "Certificate generated successfully:"
Write-Host "    $certOut"
Write-Host "    $keyOut"
Write-Host ""
Write-Host "Certificate details:"
& $opensslCmd x509 -noout -subject -issuer -dates -in $certOut

Write-Host ""
Write-Host "NOTE: Self-signed cert — browsers will show a security warning."
Write-Host "      Accept it in dev or add to Windows certificate store."
Write-Host ""
Write-Host "      For production, use Let's Encrypt: docs/TLS_SETUP.md"
Write-Host "──────────────────────────────────────────────────────"
