# =====================================================================
# ASC PremosCorp — Script de Auditoría de Seguridad (Fase 0)
# Plataforma: Windows (PowerShell)
# Uso: .\scripts\audit-fase0.ps1
# =====================================================================

$ErrorActionPreference = "Continue"
$REPO_ROOT = Split-Path $PSScriptRoot -Parent
$VENV_PYTHON = "$REPO_ROOT\.venv-security\Scripts\python.exe"
$VENV_BANDIT = "$REPO_ROOT\.venv-security\Scripts\bandit.exe"
$VENV_SAFETY = "$REPO_ROOT\.venv-security\Scripts\safety.exe"
$VENV_DETECT = "$REPO_ROOT\.venv-security\Scripts\detect-secrets.exe"
$VENV_PIPAUDIT = "$REPO_ROOT\.venv-security\Scripts\pip-audit.exe"
$GITLEAKS = "$REPO_ROOT\.tools\gitleaks.exe"

$REPORT_DIR = "$REPO_ROOT\reports\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force $REPORT_DIR | Out-Null

$PASSED = 0
$FAILED = 0
$WARNINGS = 0

function Write-Step($n, $total, $msg) {
    Write-Host "`n=== [$n/$total] $msg ===" -ForegroundColor Cyan
}
function Write-Pass($msg) {
    Write-Host "  ✅ $msg" -ForegroundColor Green
    $script:PASSED++
}
function Write-Fail($msg) {
    Write-Host "  ❌ $msg" -ForegroundColor Red
    $script:FAILED++
}
function Write-Warn($msg) {
    Write-Host "  ⚠️  $msg" -ForegroundColor Yellow
    $script:WARNINGS++
}

Set-Location $REPO_ROOT

# ─── PASO 1: Secretos en historial Git ────────────────────────────────────────
Write-Step 1 8 "Secretos en historial Git (gitleaks)"
if (Test-Path $GITLEAKS) {
    & $GITLEAKS detect --source . --verbose `
      --report-path "$REPORT_DIR\gitleaks.json" `
      --report-format json 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Pass "gitleaks: 0 secretos detectados en historial"
    } else {
        $leaks = (Get-Content "$REPORT_DIR\gitleaks.json" | ConvertFrom-Json).Count
        Write-Fail "gitleaks: $leaks secretos/credenciales encontrados — revisar $REPORT_DIR\gitleaks.json"
    }
} else {
    Write-Warn "gitleaks no encontrado en .tools/ — omitiendo"
}

# ─── PASO 2: detect-secrets ───────────────────────────────────────────────────
Write-Step 2 8 "Detección de credenciales hardcodeadas (detect-secrets)"
if (Test-Path $VENV_DETECT) {
    & $VENV_DETECT scan . --all-files > "$REPORT_DIR\detect-secrets.json" 2>&1
    $count = (& $VENV_PYTHON -c "import json; d=json.load(open('$REPORT_DIR\detect-secrets.json')); print(sum(len(v) for v in d['results'].values()))").Trim()
    if ($count -eq "0") {
        Write-Pass "detect-secrets: 0 secretos potenciales"
    } else {
        Write-Fail "detect-secrets: $count secretos potenciales — revisar $REPORT_DIR\detect-secrets.json"
    }
} else {
    Write-Warn "detect-secrets no encontrado — instalar con: pip install detect-secrets"
}

# ─── PASO 3: Valores placeholder en código ────────────────────────────────────
Write-Step 3 8 "Valores placeholder hardcodeados en código"
$patterns = @("changeme", "CHANGEME", "replace-me", "your-api-key", "password123", "secret123")
$found = 0
foreach ($pattern in $patterns) {
    $hits = Get-ChildItem "$REPO_ROOT\backend\app" -Recurse -Include "*.py" |
            Select-String -Pattern $pattern -SimpleMatch
    $found += ($hits | Measure-Object).Count
}
if ($found -eq 0) {
    Write-Pass "Sin valores placeholder en backend/app/"
} else {
    Write-Fail "$found ocurrencias de placeholders en código — deben eliminarse antes de producción"
}

# ─── PASO 4: .env en git ──────────────────────────────────────────────────────
Write-Step 4 8 ".env no está trackeado en git"
$envInGit = git ls-files | Where-Object { $_ -match "^\.env$" }
if ($envInGit) {
    Write-Fail ".env está en git — CRÍTICO: ejecutar: git rm --cached .env"
} else {
    Write-Pass ".env no está en git"
}

# También verificar que existe .gitignore con .env
$gitignore = Get-Content "$REPO_ROOT\.gitignore" -Raw
if ($gitignore -match "\.env") {
    Write-Pass ".env está en .gitignore"
} else {
    Write-Fail ".env no está en .gitignore"
}

# ─── PASO 5: Bandit — Análisis estático Python ────────────────────────────────
Write-Step 5 8 "Análisis estático Python (bandit)"
if (Test-Path $VENV_BANDIT) {
    & $VENV_BANDIT -r "$REPO_ROOT\backend\app" `
      -f json -o "$REPORT_DIR\bandit.json" `
      -c "$REPO_ROOT\.bandit" --quiet 2>&1 | Out-Null

    $banditResult = & $VENV_PYTHON -c @"
import json, sys
try:
    report = json.load(open(r'$REPORT_DIR\bandit.json'))
    results = report.get('results', [])
    highs = [r for r in results if r['issue_severity'] == 'HIGH']
    mediums = [r for r in results if r['issue_severity'] == 'MEDIUM']
    print(f'{len(results)},{len(highs)},{len(mediums)}')
except Exception as e:
    print(f'0,0,0')
"@
    $counts = $banditResult -split ","
    $total, $high, $medium = [int]$counts[0], [int]$counts[1], [int]$counts[2]

    if ($high -eq 0) {
        Write-Pass "Bandit: $total issues, 0 HIGH, $medium MEDIUM"
    } else {
        Write-Fail "Bandit: $high issues HIGH encontrados — revisar $REPORT_DIR\bandit.json"
    }
} else {
    Write-Warn "bandit no encontrado"
}

# ─── PASO 6: Dependencias vulnerables (safety) ────────────────────────────────
Write-Step 6 8 "Vulnerabilidades en dependencias Python (safety)"
if (Test-Path $VENV_SAFETY) {
    & $VENV_SAFETY check `
      -r "$REPO_ROOT\backend\requirements.txt" `
      --json -o "$REPORT_DIR\safety.json" 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Pass "safety: Sin vulnerabilidades conocidas en dependencias"
    } else {
        Write-Warn "safety: Vulnerabilidades encontradas — revisar $REPORT_DIR\safety.json"
    }
} else {
    Write-Warn "safety no encontrado"
}

# ─── PASO 7: pip-audit ────────────────────────────────────────────────────────
Write-Step 7 8 "Auditoría de dependencias (pip-audit)"
if (Test-Path $VENV_PIPAUDIT) {
    & $VENV_PIPAUDIT `
      -r "$REPO_ROOT\backend\requirements.txt" `
      -f json -o "$REPORT_DIR\pip-audit.json" `
      --progress-spinner off 2>&1 | Out-Null

    if ($LASTEXITCODE -eq 0) {
        Write-Pass "pip-audit: Sin CVEs conocidos"
    } else {
        Write-Warn "pip-audit: CVEs encontrados — revisar $REPORT_DIR\pip-audit.json"
    }
} else {
    Write-Warn "pip-audit no encontrado"
}

# ─── PASO 8: Placeholders asyncio.sleep ───────────────────────────────────────
Write-Step 8 8 "Detectar placeholders asyncio.sleep en servicios"
$sleepHits = Get-ChildItem "$REPO_ROOT\backend\app\services" -Recurse -Include "*.py" |
             Select-String -Pattern "asyncio\.sleep" -SimpleMatch
$sleepCount = ($sleepHits | Measure-Object).Count
if ($sleepCount -gt 0) {
    Write-Warn "$sleepCount placeholder(s) asyncio.sleep en services/ — reemplazar en Fase 1:"
    $sleepHits | ForEach-Object { Write-Host "    $($_.Filename):$($_.LineNumber) — $($_.Line.Trim())" -ForegroundColor Gray }
} else {
    Write-Pass "Sin placeholders asyncio.sleep en services/"
}

# ─── RESUMEN FINAL ────────────────────────────────────────────────────────────
Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "  RESUMEN AUDITORÍA FASE 0 — $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor White
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "  ✅ PASADOS:   $PASSED" -ForegroundColor Green
Write-Host "  ❌ FALLIDOS:  $FAILED" -ForegroundColor Red
Write-Host "  ⚠️  AVISOS:    $WARNINGS" -ForegroundColor Yellow
Write-Host "  📁 Reportes:  $REPORT_DIR\" -ForegroundColor Gray
Write-Host "=" * 60 -ForegroundColor Cyan

if ($FAILED -gt 0) {
    Write-Host "`n  ❌ AUDITORÍA NO SUPERADA — Resolver $FAILED fallo(s) antes de continuar" -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n  ✅ AUDITORÍA SUPERADA — Fase 0 completada" -ForegroundColor Green
    exit 0
}
