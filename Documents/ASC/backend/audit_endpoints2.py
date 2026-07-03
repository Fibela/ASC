import re, os

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
]

missing_auth = []
auth_ok = []
public_ok = []

for root, dirs, files in os.walk("app/api/v1/endpoints"):
    dirs[:] = [d for d in dirs if "__pycache__" not in d]
    for fname in files:
        if not fname.endswith(".py"):
            continue
        src = open(os.path.join(root, fname), encoding="utf-8").read()
        # Check each function definition preceded by a router decorator
        for block_m in re.finditer(r"(@router\.[a-z]+\([^)]+\)[^\n]*\n(?:.*\n){0,30}?async def \w+[^:]+:)", src):
            block = block_m.group(0)
            fn_m = re.search(r"async def (\w+)", block)
            if not fn_m:
                continue
            fn_name = fn_m.group(1)
            has_auth = any(p in block for p in AUTH_PATTERNS)
            if fn_name in KNOWN_PUBLIC:
                public_ok.append(fn_name)
            elif not has_auth:
                missing_auth.append(fname + "  " + fn_name)
            else:
                auth_ok.append(fn_name)

print("=== ENDPOINTS SIN AUTH DETECTADA ===")
for e in sorted(missing_auth):
    print("  MISSING: " + e)
print()
print("Publicos legitimados : " + str(len(public_ok)))
print("Con auth confirmada  : " + str(len(auth_ok)))
print("Sin auth (revisar)   : " + str(len(missing_auth)))
