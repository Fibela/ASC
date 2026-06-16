"""
FASE 0.3 — Endpoint Auth Audit
Scans all FastAPI endpoint files for @router.METHOD decorators and checks
whether each endpoint function includes an auth dependency.
"""
import re, os, json
from datetime import datetime, timezone

KNOWN_PUBLIC = {
    "login", "refresh", "register", "liveness", "readiness",
    "public_metrics", "canary_callback", "verify_email",
    "register_agent", "poll_commands", "report_command_result",
    "ingest_agent_events", "get_enrollment_token",
    "_honeypot_probe", "_honeypot_dump", "_honeypot_export",
}

AUTH_PATTERNS = [
    "get_current_user",
    "require_role",
    "get_analyst_or_admin",
    "get_current_active",
    "get_admin_user",
    "get_current_superuser",
    "get_current_admin",
    "_rate_limited_user",
    "_get_agent_by_header",
    "get_current_user_allow_reset",
]

# These are legitimately public for non-JWT reasons (Stripe sig, Prometheus, OAuth callback)
KNOWN_PUBLIC.update({"stripe_webhook", "prometheus_metrics", "supabase_sso", "change_password"})

missing_auth = []
auth_ok = []
public_ok = []

endpoint_dir = "app/api/v1/endpoints"

for root, dirs, files in os.walk(endpoint_dir):
    dirs[:] = [d for d in dirs if "__pycache__" not in d]
    for fname in sorted(files):
        if not fname.endswith(".py"):
            continue
        fpath = os.path.join(root, fname)
        src = open(fpath, encoding="utf-8").read()

        # Find all @router.METHOD positions
        for dec_m in re.finditer(r"@router\.(get|post|put|patch|delete)\(", src):
            dec_start = dec_m.start()
            method = dec_m.group(1).upper()

            # Grab everything from the decorator to the closing ): of the function sig
            # We search up to 3000 chars forward which covers even large sigs
            chunk = src[dec_start: dec_start + 3000]

            # Extract the HTTP path from the decorator
            path_m = re.search(r'@router\.\w+\(["\']([^"\']+)["\']', chunk)
            path = path_m.group(1) if path_m else "?"

            # Find function name
            fn_m = re.search(r"async def (\w+)\s*\(", chunk)
            if not fn_m:
                continue
            fn_name = fn_m.group(1)

            # Capture from start of chunk to the closing ): of the function signature
            # A function signature ends at the first "):" that appears after "async def"
            fn_pos = chunk.index("async def")
            sig_tail = chunk[fn_pos:]
            # Find the closing paren+colon that closes the def
            sig_end_m = re.search(r"\):", sig_tail)
            if sig_end_m:
                sig_block = sig_tail[:sig_end_m.end()]
            else:
                sig_block = sig_tail[:500]

            # Check both the decorator block (dependencies=[]) AND function signature
            dec_block = chunk[:fn_pos]
            has_auth = any(p in sig_block for p in AUTH_PATTERNS) or \
                       any(p in dec_block for p in AUTH_PATTERNS)

            entry = {
                "file": fname,
                "fn": fn_name,
                "method": method,
                "path": path,
            }

            if fn_name in KNOWN_PUBLIC:
                public_ok.append(entry)
            elif has_auth:
                auth_ok.append(entry)
            else:
                missing_auth.append(entry)

# ── Report ──────────────────────────────────────────────────────────────────
print("=" * 72)
print("FASE 0.3 — ENDPOINT AUTH AUDIT")
print("Generated:", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
print("=" * 72)
print()

if missing_auth:
    print(f"[CRITICAL] {len(missing_auth)} endpoint(s) WITHOUT detected auth:")
    for e in missing_auth:
        print(f"  {e['method']:7} {e['path']:50} -> {e['fn']} ({e['file']})")
else:
    print("[OK] All non-public endpoints have auth detected.")

print()
print(f"Legitimately public  : {len(public_ok)}")
print(f"Auth confirmed       : {len(auth_ok)}")
print(f"No auth / suspicious : {len(missing_auth)}")

# Save JSON report
os.makedirs("reports", exist_ok=True)
report = {
    "generated": datetime.now(timezone.utc).isoformat(),
    "summary": {
        "public": len(public_ok),
        "auth_ok": len(auth_ok),
        "missing_auth": len(missing_auth),
    },
    "missing_auth": missing_auth,
    "public_ok": public_ok,
    "auth_ok": [e["fn"] for e in auth_ok],
}
rpath = "reports/endpoint_audit_fase03.json"
with open(rpath, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
print()
print("Report saved -> " + rpath)
