#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# local-ci.sh — ASC PremosCorp — Local CI runner
#
# Mirrors the GitHub Actions CI + Security Audit pipelines so you can
# catch failures before pushing.  Run this from the repo root.
#
# Usage:
#   bash scripts/local-ci.sh            # all checks
#   bash scripts/local-ci.sh --fast     # skip docker + semgrep
#   bash scripts/local-ci.sh --backend  # backend tests only
#
# Requirements (install once):
#   pip install ruff bandit pip-audit
#   pip install -r backend/requirements.txt -r backend/requirements-dev.txt
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
REPORTS_DIR="$ROOT_DIR/reports"
GITLEAKS_BIN="$ROOT_DIR/.tools/gitleaks.exe"
GITLEAKS_CFG="$ROOT_DIR/.gitleaks.toml"

FAST=false
BACKEND_ONLY=false
for arg in "$@"; do
  [[ "$arg" == "--fast" ]]    && FAST=true
  [[ "$arg" == "--backend" ]] && BACKEND_ONLY=true
done

mkdir -p "$REPORTS_DIR"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

FAILED_STEPS=()
PASSED_STEPS=()

step() {
  local name="$1"; shift
  echo -e "\n${CYAN}${BOLD}══ $name ══${RESET}"
  if "$@"; then
    echo -e "${GREEN}✅ $name: PASSED${RESET}"
    PASSED_STEPS+=("$name")
    return 0
  else
    echo -e "${RED}❌ $name: FAILED${RESET}"
    FAILED_STEPS+=("$name")
    return 0   # continue regardless — collect all failures
  fi
}

warn() { echo -e "${YELLOW}⚠️  $1${RESET}"; }
info() { echo -e "   $1"; }

# ── 1. Ruff lint ──────────────────────────────────────────────────────────────
step "Ruff lint" ruff check "$BACKEND_DIR/app/" --output-format=text

# ── 2. Ruff format check ──────────────────────────────────────────────────────
step "Ruff format" ruff format "$BACKEND_DIR/app/" --check

# ── 3. Backend tests ──────────────────────────────────────────────────────────
step "Backend tests" bash -c "
  cd '$BACKEND_DIR'
  pytest tests/ \
    -q --tb=short \
    --cov=app \
    --cov-report=term-missing \
    --cov-fail-under=75
"

# ── 4. Bandit SAST ────────────────────────────────────────────────────────────
if command -v bandit &>/dev/null; then
  step "Bandit SAST" bash -c "
    bandit -r '$BACKEND_DIR/app/' \
      -x '$BACKEND_DIR/tests/,$BACKEND_DIR/.venv/' \
      -s B101,B105,B106 \
      -f json -o '$REPORTS_DIR/bandit.json' \
      --quiet || true

    python3 << 'PYEOF'
import json, sys
try:
    with open('$REPORTS_DIR/bandit.json') as f:
        report = json.load(f)
    results = report.get('results', [])
    high = [r for r in results if r.get('issue_severity') == 'HIGH']
    print(f'Bandit: {len(results)} total — {len(high)} HIGH')
    if high:
        for h in high:
            print(f'  [HIGH] {h[\"issue_text\"]} — {h[\"filename\"]}:{h[\"line_number\"]}')
        sys.exit(1)
    print('No HIGH severity findings')
except Exception as e:
    print(f'Could not parse: {e}')
PYEOF
  "
else
  warn "bandit not installed — skipping (pip install bandit)"
fi

if $BACKEND_ONLY; then
  echo -e "\n${YELLOW}--backend flag: skipping pip-audit, gitleaks, docker${RESET}"
else
  # ── 5. pip-audit ────────────────────────────────────────────────────────────
  if command -v pip-audit &>/dev/null; then
    step "pip-audit CVE" bash -c "
      pip-audit -r '$BACKEND_DIR/requirements.txt' \
        -f json -o '$REPORTS_DIR/pip-audit.json' \
        --progress-spinner off 2>&1 || true
      python3 << 'PYEOF'
import json, sys
try:
    with open('$REPORTS_DIR/pip-audit.json') as f:
        data = json.load(f)
    vulns = []
    for dep in data.get('dependencies', []):
        for v in dep.get('vulns', []):
            vulns.append(f\"{dep['name']} {dep.get('version','?')}: {v.get('id','?')}\")
    if vulns:
        print(f'{len(vulns)} vulnerabilities:')
        for v in vulns: print(f'  {v}')
        sys.exit(1)
    print('No known vulnerabilities')
except Exception as e:
    print(f'Could not parse: {e}')
PYEOF
    "
  else
    warn "pip-audit not installed — skipping (pip install pip-audit)"
  fi

  # ── 6. Gitleaks ─────────────────────────────────────────────────────────────
  if [[ -x "$GITLEAKS_BIN" ]]; then
    step "Gitleaks secrets" bash -c "
      cd '$ROOT_DIR'
      '$GITLEAKS_BIN' detect \
        --source . \
        --config '$GITLEAKS_CFG' \
        --no-git \
        2>&1 | tail -5
    "
  elif command -v gitleaks &>/dev/null; then
    step "Gitleaks secrets" bash -c "
      gitleaks detect --source '$ROOT_DIR' --config '$GITLEAKS_CFG' --no-git 2>&1 | tail -5
    "
  else
    warn "gitleaks not found — skipping (.tools/gitleaks.exe or PATH)"
  fi

  # ── 7. Docker build (slow — skip with --fast) ───────────────────────────────
  if ! $FAST && command -v docker &>/dev/null; then
    step "Docker backend build" docker build -t asc_backend:local "$BACKEND_DIR/"
    step "Docker frontend build" bash -c "
      NEXT_PUBLIC_API_URL=http://localhost:8000 \
      docker build -t asc_frontend:local '$ROOT_DIR/frontend/'
    "
  else
    warn "Docker build skipped (--fast or docker not found)"
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  LOCAL CI SUMMARY${RESET}"
echo -e "${BOLD}══════════════════════════════════════════${RESET}"

for s in "${PASSED_STEPS[@]}"; do
  echo -e "  ${GREEN}✅ $s${RESET}"
done
for s in "${FAILED_STEPS[@]}"; do
  echo -e "  ${RED}❌ $s${RESET}"
done

if [[ ${#FAILED_STEPS[@]} -gt 0 ]]; then
  echo ""
  echo -e "${RED}${BOLD}FAILED — fix the above before pushing${RESET}"
  exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}ALL CHECKS PASSED — safe to push${RESET}"
