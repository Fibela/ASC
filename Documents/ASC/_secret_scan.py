import os, re, sys

PATTERNS = [
    re.compile(r'(?i)(secret|password|passwd|api_key|apikey|private_key)\s*=\s*["\'][A-Za-z0-9+/=_\-]{8,}["\']'),
    re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*\S+'),
]
EXCLUDE_DIRS = {
    '.git', '__pycache__', 'node_modules', 'htmlcov', '.next', 'migrations',
    '.venv-security', '.venv', 'venv',
    'tests',  # test fixtures intentionally use dummy secrets
}
SKIP_TOKENS = [
    'os.getenv', 'environ', 'settings.', 'getenv', 'placeholder', 'example',
    'your-', 'mock', 'MagicMock', 'AsyncMock', 'stub', 'REPLACE_ME', 'changeme',
    'localhost', 'test_', '_test', 'YOUR_', 'os.environ', 'Field(', 'default=',
    'env=', 'SecretStr', '${', 'field.default',
    '# nosec',  # bandit/nosec annotation — explicitly reviewed and accepted
    'PEGA_', 'REEMPLAZA', 'EJEMPLO',  # placeholders en español (no aparecen en secretos reales)
]
TARGET_EXT = {'.py', '.ts', '.tsx', '.env', '.yaml', '.yml', '.toml'}

hits = []
for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for f in files:
        ext = os.path.splitext(f)[1].lower()
        if ext not in TARGET_EXT:
            continue
        path = os.path.join(root, f)
        try:
            with open(path, encoding='utf-8', errors='ignore') as fh:
                for i, line in enumerate(fh, 1):
                    l = line.strip()
                    if any(p.search(l) for p in PATTERNS):
                        if any(x in l for x in SKIP_TOKENS):
                            continue
                        hits.append(f'{path}:{i}: {l[:120]}')
        except Exception:
            pass

if hits:
    print('POTENTIAL SECRETS:')
    for h in hits[:20]:
        print(h)
    sys.exit(1)
else:
    print('CLEAN — no hardcoded secrets detected')
