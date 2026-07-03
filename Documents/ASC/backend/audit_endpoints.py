import re, os

PUBLIC = []
PROTECTED = []

for root, dirs, files in os.walk("app/api"):
    dirs[:] = [d for d in dirs if "__pycache__" not in d]
    for fname in files:
        if not fname.endswith(".py"):
            continue
        fpath = os.path.join(root, fname)
        src = open(fpath, encoding="utf-8").read()
        blocks = re.split(r"(?=@router\.)", src)
        for block in blocks:
            m = re.match(r'@router\.(get|post|put|patch|delete)\(["\']([^"\']+)["\']', block)
            fn = re.search(r"async def (\w+)", block)
            if not m or not fn:
                continue
            method = m.group(1).upper()
            path = m.group(2)
            name = fn.group(1)
            has_auth = bool(re.search(r"get_current_user|require_role|get_current_active", block[:600]))
            tag = "AUTH" if has_auth else "PUBLIC"
            rel = fname
            entry = tag + " | " + method.ljust(6) + " | " + path.ljust(45) + " | " + name + " (" + rel + ")"
            if has_auth:
                PROTECTED.append(entry)
            else:
                PUBLIC.append(entry)

print("=== ENDPOINTS PUBLICOS (sin autenticacion) ===")
for e in sorted(PUBLIC):
    print(e)
print()
print("=== REVISION REQUERIDA (publicos fuera de health/public) ===")
for e in PUBLIC:
    if not any(x in e.lower() for x in ["health", "liveness", "readiness", "public", "login", "register", "refresh", "sso"]):
        print("  !! " + e)
print()
print("Total PUBLIC=" + str(len(PUBLIC)) + "  AUTH=" + str(len(PROTECTED)))
