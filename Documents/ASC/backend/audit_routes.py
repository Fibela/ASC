"""
P37-ENDPOINTS: Auditoría estática de routes — auth coverage map.
Lee los archivos de endpoints y extrae: METHOD, PATH, dep de auth, módulo.
"""
import re, os, sys
from pathlib import Path

ENDPOINTS_DIR = Path(__file__).parent / "app" / "api" / "v1" / "endpoints"
ROUTER_FILE   = Path(__file__).parent / "app" / "api" / "v1" / "router.py"

# Auth dep → label
AUTH_LABELS = {
    "get_current_admin":             "admin",
    "get_analyst_or_admin":          "analyst+",
    "get_current_user_allow_reset":  "any_user(reset_ok)",
    "get_current_user":              "any_user",
}

# Known-public endpoints (no JWT required by design)
PUBLIC_KNOWN = {
    ("POST",  "/api/v1/auth/login"),
    ("POST",  "/api/v1/auth/register"),
    ("POST",  "/api/v1/auth/refresh"),
    ("GET",   "/api/v1/health"),
    ("GET",   "/"),
    ("GET",   "/api/v1/metrics/public"),
    ("GET",   "/api/v1/notifications/stream"),  # JWT via query param
    ("POST",  "/api/v1/agents/enroll"),          # HMAC token
    ("GET",   "/api/v1/agents/probe"),           # Honeypot trap
    ("GET",   "/api/v1/agents/dump"),            # Honeypot trap
    ("GET",   "/api/v1/agents/export"),          # Honeypot trap
    ("POST",  "/api/v1/agents/probe"),
    ("POST",  "/api/v1/agents/dump"),
    ("POST",  "/api/v1/agents/export"),
    ("GET",   "/api/v1/change-password"),        # allow_reset bypass
    ("POST",  "/api/v1/auth/change-password"),
}

# Regex patterns
ROUTE_RE   = re.compile(r'@router\.(get|post|put|patch|delete)\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
DEP_RE     = re.compile(r'Depends\((\w+)\)')

def extract_routes(filepath: Path) -> list[tuple]:
    text = filepath.read_text(encoding="utf-8", errors="ignore")
    lines = text.splitlines()
    module = filepath.stem
    results = []

    i = 0
    while i < len(lines):
        line = lines[i]
        m = ROUTE_RE.search(line)
        if m:
            method = m.group(1).upper()
            path_suffix = m.group(2)

            # Collect decorator line + function signature (params may span many lines)
            block = line
            j = i + 1
            # Step 1: skip to the 'async def' / 'def' line
            while j < min(i + 5, len(lines)):
                sl = lines[j].strip()
                block += " " + lines[j]
                j += 1
                if sl.startswith("async def") or sl.startswith("def"):
                    break
            # Step 2: collect function params until balanced parens
            depth = block.count("(") - block.count(")")
            while j < min(i + 25, len(lines)) and depth > 0:
                block += " " + lines[j]
                depth += lines[j].count("(") - lines[j].count(")")
                j += 1

            # Find auth dep
            deps = DEP_RE.findall(block)
            auth_label = "[OPEN]"
            role = "—"
            for dep in deps:
                if dep in AUTH_LABELS:
                    auth_label = f"[AUTH]{AUTH_LABELS[dep]}"
                    role = AUTH_LABELS[dep]
                    break

            results.append((method, path_suffix, auth_label, role, module))
        i += 1
    return results

# Read router prefixes
prefix_map = {}
if ROUTER_FILE.exists():
    router_text = ROUTER_FILE.read_text(encoding="utf-8", errors="ignore")
    # router.include_router(X.router, prefix="/api/v1/something", ...)
    for m in re.finditer(r'include_router\(\s*(\w+)\.router.*?prefix=["\']([^"\']+)["\']', router_text, re.DOTALL):
        mod = m.group(1)
        prefix = m.group(2)
        prefix_map[mod] = prefix

all_routes = []
for ep_file in sorted(ENDPOINTS_DIR.glob("*.py")):
    if ep_file.name == "__init__.py":
        continue
    routes = extract_routes(ep_file)
    mod = ep_file.stem
    prefix = prefix_map.get(mod, f"/api/v1/{mod}")
    for method, path_suffix, auth_label, role, module in routes:
        full_path = prefix + path_suffix if path_suffix != "/" else prefix
        all_routes.append((method, full_path, auth_label, module))

all_routes.sort(key=lambda r: (r[1], r[0]))

# Print
print(f"\n{'METHOD':<8} {'PATH':<65} {'AUTH':<28} MODULE")
print("-" * 120)

open_unexpected = []
for method, path, auth, mod in all_routes:
    is_public_known = (method, path) in PUBLIC_KNOWN
    unexpected = "[OPEN]" in auth and not is_public_known
    if unexpected:
        open_unexpected.append((method, path, mod))
    flag = " *** REVIEW ***" if unexpected else ""
    print(f"{method:<8} {path:<65} {auth:<28} {mod}{flag}")

# Summary
total = len(all_routes)
authed = sum(1 for r in all_routes if "[AUTH]" in r[2])
public = sum(1 for r in all_routes if "[OPEN]" in r[2])

print(f"\n{'='*120}")
print(f"Total routes   : {total}")
print(f"Autenticados   : {authed}  ({authed*100//total if total else 0}%)")
print(f"Públicos/trap  : {public}")
print(f"*** OPEN INESPERADO: {len(open_unexpected)}")
if open_unexpected:
    print()
    for m, p, mod in open_unexpected:
        print(f"  {m:<8} {p}  [{mod}]")
else:
    print("\n[AUTH] Todos los endpoints tienen auth o son public conocidos.")
