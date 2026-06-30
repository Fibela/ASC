from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from functools import lru_cache
from typing import Any, List
import json


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

    # App
    APP_NAME: str = "ASC PremosCorp"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = "changeme-generate-a-strong-key-in-production"  # nosec B105
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://asc_user:asc_pass@localhost:5432/asc_db"  # nosec B105,B106

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS — include all production frontend origins.
    # Override via CORS_ORIGINS env var (JSON array) in Render for additional domains.
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "https://premoscorp.com",
        "https://asc.premoscorp.com",           # custom domain (production)
        "https://asc-frontend-delta.vercel.app", # Vercel frontend project
    ]

    # SOC Thresholds
    ALERT_CRITICAL_THRESHOLD: float = 0.85
    ALERT_HIGH_THRESHOLD: float = 0.65
    ALERT_MEDIUM_THRESHOLD: float = 0.40

    # Analysis
    MAX_FILE_SIZE_MB: int = 50
    SANDBOX_TIMEOUT_SECONDS: int = 120
    IOC_FEEDS_UPDATE_HOURS: int = 6

    # Reports
    REPORT_COMPANY_NAME: str = "PremosCorp"
    REPORT_LOGO_PATH: str = "assets/logo.png"

    # External feeds (optional)
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    OTXALIEN_API_KEY: str = ""

    # ── SIEM/EDR/SOAR Adapter credentials (all optional — empty = adapter disabled) ──

    # ELK / Elasticsearch
    ELASTICSEARCH_URL: str = ""              # e.g. https://elastic.premoscorp.local:9200
    ELASTICSEARCH_API_KEY: str = ""          # base64(id:api_key) from Kibana → API Keys
    ELASTICSEARCH_INDEX_ALERTS: str = "asc-alerts"
    ELASTICSEARCH_INDEX_EVENTS: str = "asc-events"

    # Wazuh Manager REST API
    WAZUH_URL: str = ""                      # e.g. https://wazuh.premoscorp.local:55000
    WAZUH_USERNAME: str = ""                 # Wazuh API user
    WAZUH_PASSWORD: str = ""                 # Wazuh API password
    WAZUH_VERIFY_SSL: bool = True

    # TheHive SOAR
    THEHIVE_URL: str = ""                    # e.g. https://thehive.premoscorp.local:9000
    THEHIVE_API_KEY: str = ""                # TheHive API key (user profile → API Keys)
    THEHIVE_ORGANISATION: str = "PremosCorp"

    # ── SPECTER Agent (P13) ────────────────────────────────────────────────────
    # Ed25519 keypair for signing commands sent to SPECTER agents.
    # Generate with: python -c "from app.core.signing import generate_keypair; p,q=generate_keypair(); print('PRIVATE:',p); print('PUBLIC:',q)"
    SPECTER_SIGNING_PRIVATE_KEY: str = ""    # base64 raw Ed25519 private key (32 bytes)
    SPECTER_SIGNING_PUBLIC_KEY: str = ""     # base64 raw Ed25519 public key  (32 bytes)
    SPECTER_AGENT_VERSION: str = "1.0.0"    # minimum accepted agent version
    SPECTER_MAX_EVENTS_PER_BATCH: int = 200  # max events in a single telemetry POST
    SPECTER_INACTIVE_THRESHOLD_SECONDS: int = 120  # seconds without heartbeat → inactive

    # ── P16.3 IAM ─────────────────────────────────────────────────────────────
    # Failed login attempts before the account is auto-locked.
    ACCOUNT_LOCK_THRESHOLD: int = 5
    # Duration of the auto-lock (and manual lock default) in minutes.
    ACCOUNT_LOCK_MINUTES: int = 15

    # ── P16.3 Celery Escalation ───────────────────────────────────────────────
    # How often Celery Beat runs the proactive escalation scan (seconds).
    ESCALATION_CHECK_INTERVAL_SECONDS: int = 60
    # How often Celery Beat runs the PIIL SLA breach escalation scan (seconds).
    SLA_ESCALATION_CHECK_INTERVAL_SECONDS: int = 120

    # ── P17 Rate Limiting ─────────────────────────────────────────────────────
    # SlowAPI throttle strings — format: "N/period" (period: second/minute/hour)
    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_REGISTER: str = "3/minute"
    RATE_LIMIT_REFRESH: str = "30/minute"
    RATE_LIMIT_CHANGE_PASSWORD: str = "10/minute"
    # General API rate limits (P21-F2)
    RATE_LIMIT_ANALYZE_FILE: str = "20/minute"
    RATE_LIMIT_ANALYZE_LOOKUP: str = "60/minute"
    RATE_LIMIT_ALERTS: str = "120/minute"
    RATE_LIMIT_IOCS: str = "120/minute"
    RATE_LIMIT_OPS: str = "60/minute"
    RATE_LIMIT_FORENSIC: str = "60/minute"
    RATE_LIMIT_AGENTS_WRITE: str = "60/minute"
    # Optional Redis URI for multi-worker rate-limit sharing. Empty = in-memory.
    SLOWAPI_STORAGE_URI: str = ""

    # ── P17 Request Hardening ─────────────────────────────────────────────────
    # Maximum allowed request body in bytes (default 10 MB).
    REQUEST_MAX_BODY_BYTES: int = 10 * 1024 * 1024

    # ── F1 — Palo Alto Networks PAN-OS ───────────────────────────────────────
    # PALOALTO_HOST: hostname or IP of Panorama/firewall (no https:// prefix).
    # PALOALTO_API_KEY: generated via Device → Administrators → API Key.
    PALOALTO_HOST: str = ""
    PALOALTO_API_KEY: str = ""                      # nosec B105 — from env/Vault
    PALOALTO_VSYS: str = "vsys1"
    PALOALTO_BLOCKED_IP_GROUP: str = "ASC-Blocked-IPs"
    PALOALTO_BLOCKED_URL_CATEGORY: str = "ASC-Blocked-Domains"

    # ── F1 — Fortinet FortiGate ───────────────────────────────────────────────
    # FORTINET_HOST: hostname or IP of FortiGate (no https:// prefix).
    # FORTINET_API_TOKEN: generated via System → Administrators → REST API Admin.
    FORTINET_HOST: str = ""
    FORTINET_API_TOKEN: str = ""                    # nosec B105 — from env/Vault
    FORTINET_VDOM: str = "root"
    FORTINET_BLOCKED_IP_GROUP: str = "ASC-Blocked-IPs"
    FORTINET_BLOCKED_DOMAIN_GROUP: str = "ASC-Blocked-Domains"

    # ── F1 — Active Directory / LDAP ─────────────────────────────────────────
    # AD_SERVER_URL: LDAPS URL of domain controller (ldaps://dc.corp.local:636).
    # AD_BIND_DN: Service account full DN — use minimum-privilege account.
    # AD_BIND_PASSWORD: Service account password — MUST come from Vault in prod.
    AD_SERVER_URL: str = ""                         # ldaps://dc.premoscorp.local:636
    AD_BIND_DN: str = ""                            # CN=svc-asc,OU=Service Accounts,DC=corp,DC=local
    AD_BIND_PASSWORD: str = ""                      # nosec B105 — from env/Vault
    AD_BASE_DN: str = ""                            # DC=corp,DC=local
    AD_QUARANTINE_OU: str = ""                      # OU=Quarantine,DC=corp,DC=local
    AD_USE_SSL: bool = True                         # Always True in production
    AD_VERIFY_CERT: bool = True                     # Set False only for self-signed dev certs

    # ── P41 Rate Limiting — Per API Key ──────────────────────────────────────
    # Sliding window limits enforced by ApiKeyRateLimitMiddleware.
    # Per-minute limit controls burst; per-hour limit controls sustained throughput.
    # Both windows are enforced simultaneously — the stricter one governs.
    RATE_LIMIT_API_KEY_PER_MINUTE: int = 60    # requests/minute per key (burst)
    RATE_LIMIT_API_KEY_PER_HOUR: int = 1000    # requests/hour per key (throughput)

    # ── P39 Observability ─────────────────────────────────────────────────────
    # Static bearer token for Prometheus scraper (no JWT login required).
    # Empty = scrape token disabled; only analyst+ JWT works.
    # Generate: python -c "import secrets; print(secrets.token_hex(32))"
    METRICS_SCRAPE_TOKEN: str = ""   # nosec B105 — from env/Vault

    # ── P53 Email Verification ────────────────────────────────────────────────
    # Number of hours before the email verification token expires.
    EMAIL_VERIFICATION_EXPIRE_HOURS: int = 24

    # ── P55 Stripe Billing ────────────────────────────────────────────────────
    # Empty = Stripe integration disabled (default for dev/test).
    # In production set these via env/Vault. Never hard-code.
    STRIPE_SECRET_KEY: str = ""           # nosec B105 — sk_live_… or sk_test_…
    STRIPE_WEBHOOK_SECRET: str = ""       # nosec B105 — whsec_…

    # ── SPECTER Security Hardening (P14) ──────────────────────────────────────
    # Enrollment token: HMAC-SHA256 shared secret. Empty = dev mode (skip check).
    # Generate a token with: python -c "from app.core.specter_security import generate_enrollment_token; print(generate_enrollment_token('your-secret'))"
    SPECTER_ENROLLMENT_SECRET: str = ""      # nosec B105 — empty means dev mode
    # Strict signature mode: reject telemetry events whose Ed25519 signature is invalid.
    # In dev/test mode keep False; enable in production for zero-trust enforcement.
    SPECTER_STRICT_SIGNATURE_MODE: bool = False
    # Rate limiting for telemetry ingestion (per agent, sliding window).
    SPECTER_MAX_EVENTS_PER_WINDOW: int = 200
    SPECTER_RATE_WINDOW_SECONDS: int = 30

    # ── P60 Stripe Checkout Auto-Provisioning ────────────────────────────────
    # Plan assigned to tenants when a Stripe checkout.session.completed fires.
    # Typically "pro" or "enterprise" — must be a valid plan slug.
    STRIPE_PROVISIONING_PLAN: str = "pro"
    # Optional: restrict checkout provisioning to a specific Stripe product ID.
    # Empty = provision on ALL checkout.session.completed events (safe when the
    # ASC webhook URL is dedicated to this Stripe account / product line).
    STRIPE_SEGURIDAD_PRODUCT_ID: str = ""

    # ── P59 SSO Bridge — Supabase → ASC JWT Exchange ─────────────────────────
    # SUPABASE_URL: your project URL (e.g. https://xyz.supabase.co)
    # SUPABASE_ANON_KEY: public anon key — optional, reserved for future use.
    #   The JWKS endpoint (/auth/v1/.well-known/jwks.json) is public — no apikey required.
    #   Safe to expose: same key used in browser clients.
    # SUPABASE_JWT_SECRET: legacy HS256 secret (only needed if still using HS256 tokens)
    # SUPABASE_JWT_AUDIENCE: expected "aud" claim in Supabase JWTs (default: "authenticated")
    # Empty SUPABASE_URL disables SSO bridge (returns 503).
    SUPABASE_URL: str = ""                   # https://xyz.supabase.co
    SUPABASE_ANON_KEY: str = ""              # nosec B105 — public anon key, safe to expose
    SUPABASE_JWT_SECRET: str = ""            # nosec B105 — legacy HS256 secret
    SUPABASE_JWT_PUBLIC_KEY: str = ""        # PEM public key (Settings → API → JWT Signing Keys)
    SUPABASE_JWT_AUDIENCE: str = "authenticated"
    # ASC plan assigned to new SSO-provisioned tenants: free | pro | enterprise
    SSO_DEFAULT_PLAN: str = "free"
    # CORS: add *.premoscorp.com for SSO cross-origin requests from premoscorp.com
    CORS_ORIGINS_EXTRA: List[str] = []       # additional origins (merged with CORS_ORIGINS)

    @field_validator("CORS_ORIGINS", "CORS_ORIGINS_EXTRA", mode="before")
    @classmethod
    def _parse_str_list(cls, v: Any) -> Any:
        if isinstance(v, list):
            return v
        if not v:
            return []
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                return json.loads(v)
            return [item.strip() for item in v.split(",") if item.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
