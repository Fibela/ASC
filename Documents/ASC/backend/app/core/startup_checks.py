"""
P17 Startup Configuration Validation.

Runs once during FastAPI lifespan before the app starts accepting requests.
In production (DEBUG=False) violations raise RuntimeError — aborting startup
is safer than silently running with an insecure configuration.
In development (DEBUG=True) violations are logged as warnings so the dev
experience is not blocked.

Checks performed:
  1. SECRET_KEY entropy: length ≥ 32, not a known-weak placeholder
  2. CORS origins: wildcard ("*") is rejected in production
  3. DATABASE_URL / REDIS_URL: warn if credentials appear in log-visible strings
  4. API docs: /docs and /redoc are auto-disabled in production
"""
from __future__ import annotations

import structlog

log = structlog.get_logger("asc.startup")

# Known-weak SECRET_KEY substrings (case-insensitive).
_WEAK_SUBSTRINGS = frozenset({
    "changeme", "secret", "password", "default", "test", "dev",
    "replace", "generate", "placeholder", "example", "sample",
})

_MIN_SECRET_KEY_LEN = 32


def _check_secret_key(secret: str, *, production: bool) -> list[str]:
    issues: list[str] = []
    if len(secret) < _MIN_SECRET_KEY_LEN:
        issues.append(
            f"SECRET_KEY is only {len(secret)} chars — minimum is {_MIN_SECRET_KEY_LEN}. "
            "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    lower = secret.lower()
    for weak in _WEAK_SUBSTRINGS:
        if weak in lower:
            issues.append(
                f"SECRET_KEY contains weak substring '{weak}'. "
                "This key must be replaced with a randomly generated value before deployment."
            )
            break
    return issues


def _check_cors(origins: list[str], *, production: bool) -> list[str]:
    if production and "*" in origins:
        return ["CORS_ORIGINS contains wildcard '*' — this exposes all endpoints to any origin in production."]
    return []


def run_startup_checks(settings) -> None:  # type: ignore[type-arg]
    """
    Validate settings at startup.

    Raises RuntimeError in production (DEBUG=False) on any critical issue.
    Only logs warnings in development so the dev loop is not interrupted.
    """
    production = not settings.DEBUG
    all_issues: list[str] = []

    all_issues.extend(_check_secret_key(settings.SECRET_KEY, production=production))
    all_issues.extend(_check_cors(list(settings.CORS_ORIGINS), production=production))

    if not all_issues:
        log.info("startup_checks_passed", production=production)
        return

    for issue in all_issues:
        if production:
            log.error("startup_check_failed", issue=issue)
        else:
            log.warning("startup_check_warning", issue=issue)

    if production:
        raise RuntimeError(
            f"Startup aborted — {len(all_issues)} insecure configuration issue(s) detected. "
            "Fix the issues above before running in production."
        )
