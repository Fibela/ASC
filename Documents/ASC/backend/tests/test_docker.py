"""
test_docker.py — Priority 9+10: Docker Compose + Nginx + TLS + Container Security
===================================================================================

Validates the entire container infrastructure WITHOUT running Docker.
All tests are file-based (parse YAML/configs) and run in the standard
pytest suite alongside unit tests.

Test classes:
    TestDockerCompose         (15) — docker-compose.yml security + structure
    TestDockerComposeOverride  (6) — docker-compose.override.yml dev conveniences
    TestNginxConfig           (21) — nginx.conf security headers + rate limiting
    TestDockerfiles           (12) — non-root users, HEALTHCHECK, multi-stage
    TestEnvConfig              (9) — .env.example completeness + .gitignore
    TestPortExposure           (6) — internal services MUST NOT expose host ports
    TestTLS                   (23) — P10: TLS config, HSTS, ciphers, certs, scripts
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

# ── Path helpers ──────────────────────────────────────────────────────────────
ROOT = Path(__file__).parents[2]   # repo root (ASC/)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _load_yaml(rel: str) -> dict:
    return yaml.safe_load(_read(rel)) or {}


def _exists(rel: str) -> bool:
    return (ROOT / rel).exists()


# ══════════════════════════════════════════════════════════════════════════════
# 1. docker-compose.yml
# ══════════════════════════════════════════════════════════════════════════════
class TestDockerCompose:
    """Security and structure checks for docker-compose.yml."""

    @pytest.fixture(autouse=True)
    def compose(self):
        self.doc = _load_yaml("docker-compose.yml")
        self.services = self.doc.get("services", {})
        self.raw = _read("docker-compose.yml")

    # ── Structure ──────────────────────────────────────────────────────────────
    def test_compose_is_valid_yaml(self):
        assert isinstance(self.doc, dict)

    def test_all_required_services_present(self):
        required = {"postgres", "redis", "backend", "frontend", "nginx"}
        missing = required - set(self.services)
        assert not missing, f"Missing services: {missing}"

    def test_networks_defined(self):
        assert "networks" in self.doc, "docker-compose.yml must define networks"
        assert self.doc["networks"], "At least one network must be defined"

    def test_volumes_defined(self):
        assert "volumes" in self.doc
        volumes = self.doc["volumes"]
        assert "postgres_data" in volumes

    def test_all_services_have_healthcheck(self):
        for name, svc in self.services.items():
            assert "healthcheck" in svc, f"Service '{name}' is missing a healthcheck"

    def test_all_services_have_restart_policy(self):
        for name, svc in self.services.items():
            assert "restart" in svc, f"Service '{name}' has no restart policy"

    # ── Secrets — all credentials from .env ───────────────────────────────────
    def test_no_hardcoded_postgres_password(self):
        assert "asc_pass" not in self.raw, "Hardcoded password 'asc_pass' found"
        assert "postgres" not in self.raw.lower().split("postgres_password")[1][:50] or \
               "${POSTGRES_PASSWORD}" in self.raw, \
               "POSTGRES_PASSWORD must use env var substitution"

    def test_no_hardcoded_secret_key(self):
        # Allowed: ${SECRET_KEY} — forbidden: changeme or any bare string
        assert "changeme" not in self.raw, "Hardcoded SECRET_KEY placeholder found"
        assert "${SECRET_KEY}" in self.raw, "SECRET_KEY must use ${SECRET_KEY} (no fallback)"

    def test_secret_key_has_no_fallback(self):
        # ${SECRET_KEY:-anything} provides a fallback — dangerous
        assert "SECRET_KEY:-" not in self.raw, \
            "SECRET_KEY must NOT have a default fallback. Use ${SECRET_KEY} only."

    def test_redis_password_used(self):
        assert "${REDIS_PASSWORD}" in self.raw, \
            "Redis must use password from .env (REDIS_PASSWORD)"

    def test_redis_requirepass_set(self):
        redis_svc = self.services.get("redis", {})
        command = redis_svc.get("command", "")
        cmd_str = " ".join(command) if isinstance(command, list) else str(command)
        assert "--requirepass" in cmd_str, \
            "Redis must be started with --requirepass for authentication"

    def test_postgres_credentials_from_env(self):
        pg = self.services.get("postgres", {})
        env = pg.get("environment", {})
        env_str = str(env)
        assert "${POSTGRES_PASSWORD}" in env_str or "POSTGRES_PASSWORD}" in env_str, \
            "POSTGRES_PASSWORD must use env var substitution"

    def test_backend_no_bind_mount_in_production(self):
        backend = self.services.get("backend", {})
        volumes = backend.get("volumes", [])
        for v in volumes:
            v_str = str(v)
            assert "./backend:/app" not in v_str, \
                "Production compose must NOT bind-mount source into backend container"

    def test_frontend_build_has_next_public_api_url_arg(self):
        frontend = self.services.get("frontend", {})
        build = frontend.get("build", {})
        args = build.get("args", {})
        assert "NEXT_PUBLIC_API_URL" in args, \
            "Frontend build must pass NEXT_PUBLIC_API_URL as build arg"

    def test_frontend_next_public_api_url_is_empty_or_relative(self):
        frontend = self.services.get("frontend", {})
        build = frontend.get("build", {})
        args = build.get("args", {})
        url = str(args.get("NEXT_PUBLIC_API_URL", ""))
        # Must be empty (relative URLs) or not point to exposed backend port
        assert url == "" or not url.startswith("http://localhost:8000"), \
            "Production compose: NEXT_PUBLIC_API_URL must be empty (relative via nginx)"


# ══════════════════════════════════════════════════════════════════════════════
# 2. docker-compose.override.yml
# ══════════════════════════════════════════════════════════════════════════════
class TestDockerComposeOverride:
    """Override file provides dev conveniences without affecting production."""

    @pytest.fixture(autouse=True)
    def override(self):
        assert _exists("docker-compose.override.yml"), \
            "docker-compose.override.yml must exist (dev conveniences)"
        self.doc = _load_yaml("docker-compose.override.yml")
        self.services = self.doc.get("services", {})
        self.raw = _read("docker-compose.override.yml")

    def test_override_is_valid_yaml(self):
        assert isinstance(self.doc, dict)

    def test_override_exposes_backend_for_dev(self):
        backend = self.services.get("backend", {})
        ports = backend.get("ports", [])
        assert any("8000" in str(p) for p in ports), \
            "Override must expose backend:8000 so developers can access /docs"

    def test_override_has_hot_reload(self):
        backend = self.services.get("backend", {})
        command = backend.get("command", [])
        cmd_str = " ".join(str(c) for c in command) if isinstance(command, list) else str(command)
        assert "--reload" in cmd_str, "Override must enable uvicorn --reload for hot-reload"

    def test_override_has_backend_bind_mount(self):
        backend = self.services.get("backend", {})
        volumes = backend.get("volumes", [])
        assert any("./backend:/app" in str(v) for v in volumes), \
            "Override must bind-mount ./backend:/app for hot-reload"

    def test_override_has_dev_warning_comment(self):
        assert "NOT" in self.raw.upper() or "DEV" in self.raw.upper(), \
            "Override must contain a warning that it is for dev only"

    def test_override_exposes_postgres_for_dev(self):
        pg = self.services.get("postgres", {})
        ports = pg.get("ports", [])
        assert any("5432" in str(p) for p in ports), \
            "Override should expose postgres:5432 for DB clients"


# ══════════════════════════════════════════════════════════════════════════════
# 3. nginx.conf — Security Headers
# ══════════════════════════════════════════════════════════════════════════════
class TestNginxConfig:
    """Validates nginx security headers, rate limiting, and path blocking."""

    @pytest.fixture(autouse=True)
    def nginx(self):
        self.raw = _read("infra/nginx/nginx.conf")

    # ── Basic hardening ────────────────────────────────────────────────────────
    def test_server_tokens_off(self):
        assert "server_tokens off" in self.raw, \
            "server_tokens must be 'off' to hide nginx version"

    def test_has_upstream_backend(self):
        assert "upstream backend" in self.raw

    def test_has_upstream_frontend(self):
        assert "upstream frontend" in self.raw

    # ── Security headers ───────────────────────────────────────────────────────
    def test_has_content_security_policy(self):
        assert "Content-Security-Policy" in self.raw

    def test_csp_has_default_src_self(self):
        assert "default-src 'self'" in self.raw

    def test_csp_has_connect_src_self(self):
        # Critical: prevents browser from making API calls to external hosts
        assert "connect-src 'self'" in self.raw, \
            "CSP must include connect-src 'self' to prevent data exfiltration"

    def test_csp_has_frame_ancestors_none(self):
        assert "frame-ancestors 'none'" in self.raw, \
            "CSP must include frame-ancestors 'none' (clickjacking protection)"

    def test_csp_has_object_src_none(self):
        assert "object-src 'none'" in self.raw, \
            "CSP must disable plugins/Flash with object-src 'none'"

    def test_has_x_frame_options_deny(self):
        assert "X-Frame-Options" in self.raw and "DENY" in self.raw, \
            "X-Frame-Options: DENY must be set (clickjacking protection)"

    def test_has_x_content_type_options(self):
        assert "X-Content-Type-Options" in self.raw and "nosniff" in self.raw

    def test_has_referrer_policy(self):
        assert "Referrer-Policy" in self.raw

    def test_has_permissions_policy(self):
        assert "Permissions-Policy" in self.raw

    def test_permissions_policy_disables_camera(self):
        assert "camera=()" in self.raw

    def test_permissions_policy_disables_microphone(self):
        assert "microphone=()" in self.raw

    # ── Rate limiting ──────────────────────────────────────────────────────────
    def test_has_api_rate_limit_zone(self):
        assert "api_limit" in self.raw or "api:" in self.raw, \
            "nginx must define a rate limit zone for API endpoints"

    def test_has_auth_rate_limit_zone(self):
        assert "auth_limit" in self.raw or "auth:" in self.raw, \
            "nginx must define a stricter rate limit zone for auth endpoints"

    def test_rate_limit_applied_to_auth(self):
        assert re.search(r"limit_req\s+zone=auth", self.raw), \
            "Auth endpoints must have limit_req applied"

    # ── Path blocking ──────────────────────────────────────────────────────────
    def test_blocks_dotenv_access(self):
        assert ".env" in self.raw and "deny all" in self.raw, \
            "nginx must block access to .env files"

    def test_blocks_docs_and_redoc(self):
        assert "docs" in self.raw and "deny all" in self.raw, \
            "nginx must block /docs and /redoc to prevent API schema exposure"

    # ── Size limits ────────────────────────────────────────────────────────────
    def test_has_client_max_body_size(self):
        assert "client_max_body_size" in self.raw

    def test_has_client_timeouts(self):
        assert "client_body_timeout" in self.raw and "client_header_timeout" in self.raw


# ══════════════════════════════════════════════════════════════════════════════
# 4. Dockerfiles
# ══════════════════════════════════════════════════════════════════════════════
class TestDockerfiles:
    """Validates security properties of backend and frontend Dockerfiles."""

    @pytest.fixture(autouse=True)
    def dockerfiles(self):
        self.backend = _read("backend/Dockerfile")
        self.frontend = _read("frontend/Dockerfile")

    # ── Non-root users ─────────────────────────────────────────────────────────
    def test_backend_has_non_root_user(self):
        assert "USER " in self.backend and "root" not in self.backend.split("USER ")[-1].split("\n")[0], \
            "Backend Dockerfile must switch to a non-root USER"

    def test_frontend_has_non_root_user(self):
        assert "USER " in self.frontend, \
            "Frontend Dockerfile must switch to a non-root USER"

    # ── HEALTHCHECK ────────────────────────────────────────────────────────────
    def test_backend_has_healthcheck(self):
        assert "HEALTHCHECK" in self.backend

    def test_frontend_has_healthcheck(self):
        assert "HEALTHCHECK" in self.frontend

    # ── Multi-stage build ──────────────────────────────────────────────────────
    def test_frontend_uses_multistage_build(self):
        stages = [line for line in self.frontend.splitlines() if line.strip().upper().startswith("FROM")]
        assert len(stages) >= 2, \
            "Frontend Dockerfile must use multi-stage build (builder + runner)"

    def test_frontend_runner_stage_is_minimal(self):
        assert "AS runner" in self.frontend or "AS production" in self.frontend.lower(), \
            "Frontend must have a dedicated runner stage"

    # ── No secrets in Dockerfiles ──────────────────────────────────────────────
    def test_backend_dockerfile_no_hardcoded_secrets(self):
        bad_patterns = ["SECRET_KEY=", "POSTGRES_PASSWORD=", "password="]
        for pat in bad_patterns:
            assert pat not in self.backend, f"Backend Dockerfile must not contain '{pat}'"

    def test_frontend_dockerfile_no_hardcoded_secrets(self):
        bad_patterns = ["SECRET_KEY=", "API_KEY="]
        for pat in bad_patterns:
            assert pat not in self.frontend, f"Frontend Dockerfile must not contain '{pat}'"

    # ── curl/wget for healthchecks ─────────────────────────────────────────────
    def test_backend_installs_curl_for_healthcheck(self):
        assert "curl" in self.backend, \
            "Backend Dockerfile must install curl (used in HEALTHCHECK)"

    def test_frontend_has_wget_in_healthcheck(self):
        assert "wget" in self.frontend, \
            "Frontend HEALTHCHECK must use wget (available in node:alpine)"

    # ── .dockerignore ─────────────────────────────────────────────────────────
    def test_backend_dockerignore_exists(self):
        assert _exists("backend/.dockerignore"), \
            "backend/.dockerignore must exist to exclude .venv, tests, .env from image"

    def test_frontend_dockerignore_exists(self):
        assert _exists("frontend/.dockerignore"), \
            "frontend/.dockerignore must exist to exclude node_modules, .env from image"


# ══════════════════════════════════════════════════════════════════════════════
# 5. .env.example + .gitignore
# ══════════════════════════════════════════════════════════════════════════════
class TestEnvConfig:
    """.env.example completeness and gitignore protection."""

    @pytest.fixture(autouse=True)
    def env(self):
        self.example = _read(".env.example")
        self.gitignore = _read(".gitignore")

    def test_env_example_exists(self):
        assert _exists(".env.example")

    def test_env_has_secret_key_field(self):
        assert "SECRET_KEY=" in self.example

    def test_env_has_postgres_password_field(self):
        assert "POSTGRES_PASSWORD=" in self.example

    def test_env_has_redis_password_field(self):
        assert "REDIS_PASSWORD=" in self.example, \
            ".env.example must document REDIS_PASSWORD (Redis now requires auth)"

    def test_env_has_key_generation_instructions(self):
        # Users must know HOW to generate secrets, not just that they need them
        assert "secrets.token" in self.example or "openssl" in self.example, \
            ".env.example must show how to generate SECRET_KEY (python secrets or openssl)"

    def test_env_example_has_no_real_secrets(self):
        # All sensitive fields must contain placeholder text, not real values
        lines = {
            line.split("=")[0]: line.split("=", 1)[1]
            for line in self.example.splitlines()
            if "=" in line and not line.strip().startswith("#")
        }
        for field in ("SECRET_KEY", "POSTGRES_PASSWORD", "REDIS_PASSWORD"):
            if field in lines:
                val = lines[field].strip()
                # Placeholder values are safe; real secrets are not
                assert len(val) < 10 or "REPLACE" in val or "generate" in val.lower(), \
                    f".env.example field {field} looks like a real secret: '{val[:20]}...'"

    def test_dot_env_in_gitignore(self):
        assert ".env" in self.gitignore, ".env must be in .gitignore"

    def test_env_local_in_gitignore(self):
        assert ".env.local" in self.gitignore or "*.env" in self.gitignore, \
            ".env.local must be excluded from git"

    def test_env_production_in_gitignore(self):
        assert ".env.production" in self.gitignore or "*.env" in self.gitignore, \
            ".env.production must be excluded from git"


# ══════════════════════════════════════════════════════════════════════════════
# 6. Port Exposure — Internal services MUST NOT expose host ports
# ══════════════════════════════════════════════════════════════════════════════
class TestPortExposure:
    """
    Production docker-compose.yml must expose ONLY nginx (port 80).
    postgres, redis, backend, frontend must have NO host port mapping.

    The override.yml adds ports for dev — that is verified separately.
    """

    @pytest.fixture(autouse=True)
    def compose(self):
        self.services = _load_yaml("docker-compose.yml").get("services", {})

    def test_nginx_exposes_port_80(self):
        nginx = self.services.get("nginx", {})
        ports = nginx.get("ports", [])
        assert any("80" in str(p) for p in ports), \
            "nginx must expose port 80 to the host"

    def test_postgres_has_no_host_port(self):
        pg = self.services.get("postgres", {})
        ports = pg.get("ports", [])
        assert not ports, \
            f"postgres MUST NOT expose host ports in production. Found: {ports}"

    def test_redis_has_no_host_port(self):
        redis = self.services.get("redis", {})
        ports = redis.get("ports", [])
        assert not ports, \
            f"redis MUST NOT expose host ports in production. Found: {ports}"

    def test_backend_has_no_host_port(self):
        backend = self.services.get("backend", {})
        ports = backend.get("ports", [])
        assert not ports, \
            f"backend MUST NOT expose host ports in production. Found: {ports}"

    def test_frontend_has_no_host_port(self):
        frontend = self.services.get("frontend", {})
        ports = frontend.get("ports", [])
        assert not ports, \
            f"frontend MUST NOT expose host ports in production. Found: {ports}"

    def test_only_nginx_is_public_gateway(self):
        # Count total exposed ports across all services
        total_ports = sum(
            len(svc.get("ports", []))
            for svc in self.services.values()
        )
        # Only nginx should have ports (port 80 + 443 after P10)
        nginx_ports = len(self.services.get("nginx", {}).get("ports", []))
        assert total_ports == nginx_ports, \
            f"Only nginx should expose ports. Total: {total_ports}, nginx: {nginx_ports}"


# ══════════════════════════════════════════════════════════════════════════════
# 7. TLS — Priority 10: HTTPS hardening
# ══════════════════════════════════════════════════════════════════════════════
class TestTLS:
    """
    Validates the full TLS stack:
      - docker-compose.yml: port 443 exposed, certs volume mounted
      - nginx.conf: TLS 1.2/1.3 only, strong ciphers, HSTS, HTTP→HTTPS redirect
      - infra/nginx/certs/.gitignore: cert files never committed
      - scripts/gen_selfsigned_cert.sh + .ps1: dev cert generation scripts
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        self.nginx = _read("infra/nginx/nginx.conf")
        self.compose = _load_yaml("docker-compose.yml")
        self.compose_raw = _read("docker-compose.yml")

    # ── docker-compose.yml: port 443 + certs volume ───────────────────────────

    def test_nginx_exposes_port_443(self):
        nginx_svc = self.compose.get("services", {}).get("nginx", {})
        ports = nginx_svc.get("ports", [])
        assert any("443" in str(p) for p in ports), \
            "nginx must expose port 443 (HTTPS) in docker-compose.yml"

    def test_certs_volume_mounted_in_nginx(self):
        nginx_svc = self.compose.get("services", {}).get("nginx", {})
        volumes = nginx_svc.get("volumes", [])
        assert any("certs" in str(v) for v in volumes), \
            "nginx must mount the certs directory for TLS certificates"

    def test_certs_volume_is_readonly(self):
        nginx_svc = self.compose.get("services", {}).get("nginx", {})
        volumes = nginx_svc.get("volumes", [])
        certs_vols = [str(v) for v in volumes if "certs" in str(v)]
        assert certs_vols, "Certs volume not found in nginx service"
        assert any(":ro" in v for v in certs_vols), \
            "Certs volume must be mounted read-only (:ro) — key files must not be writable"

    # ── nginx.conf: TLS server block ─────────────────────────────────────────

    def test_nginx_listens_443_ssl(self):
        assert re.search(r"listen\s+443\s+ssl", self.nginx), \
            "nginx.conf must have 'listen 443 ssl' for HTTPS"

    def test_http2_enabled(self):
        assert "http2  on" in self.nginx or "http2 on" in self.nginx, \
            "HTTP/2 must be enabled via 'http2 on' directive (nginx 1.25.1+)"

    def test_ssl_certificate_path_under_certs(self):
        assert "/etc/nginx/certs/fullchain.pem" in self.nginx, \
            "ssl_certificate must point to /etc/nginx/certs/fullchain.pem"

    def test_ssl_certificate_key_path_under_certs(self):
        assert "/etc/nginx/certs/privkey.pem" in self.nginx, \
            "ssl_certificate_key must point to /etc/nginx/certs/privkey.pem"

    # ── Protocol restriction ──────────────────────────────────────────────────

    def test_tls_protocols_v12_and_v13_present(self):
        assert "TLSv1.2" in self.nginx and "TLSv1.3" in self.nginx, \
            "ssl_protocols must include both TLSv1.2 and TLSv1.3"

    def test_tls_v10_not_allowed(self):
        # TLSv1.2 contains 'TLSv1' as a substring — match the ssl_protocols line
        # and verify it does not contain a bare 'TLSv1' (v1.0) token.
        proto_match = re.search(r"ssl_protocols\s+([^;]+);", self.nginx)
        if proto_match:
            proto_line = proto_match.group(1)
            # Remove TLSv1.2 and TLSv1.3 from consideration, then check for bare TLSv1
            cleaned = proto_line.replace("TLSv1.2", "").replace("TLSv1.3", "")
            assert "TLSv1" not in cleaned, \
                "TLS 1.0 must be disabled — ssl_protocols must NOT include bare TLSv1"

    def test_tls_v11_not_allowed(self):
        assert "TLSv1.1" not in self.nginx, \
            "TLS 1.1 must be disabled — ssl_protocols must NOT include TLSv1.1"

    # ── Cipher suite hardening ────────────────────────────────────────────────

    def test_ssl_prefer_server_ciphers_on(self):
        assert "ssl_prefer_server_ciphers on" in self.nginx, \
            "ssl_prefer_server_ciphers must be 'on' — server controls cipher selection"

    def test_ecdhe_ciphers_present(self):
        assert "ECDHE" in self.nginx, \
            "Cipher suite must include ECDHE for forward secrecy"

    def test_chacha20_cipher_present(self):
        assert "CHACHA20" in self.nginx, \
            "Cipher suite must include CHACHA20-POLY1305 for mobile/low-power clients"

    def test_aes_gcm_cipher_present(self):
        assert "AES128-GCM-SHA256" in self.nginx or "AES256-GCM-SHA384" in self.nginx, \
            "Cipher suite must include AES-GCM (AEAD, authenticated encryption)"

    def test_weak_cipher_rc4_absent(self):
        # Check only the ssl_ciphers directive line, not comments
        ciphers_match = re.search(r"ssl_ciphers\s+'?([^;']+)'?;", self.nginx)
        if ciphers_match:
            ciphers_line = ciphers_match.group(1)
            assert "RC4" not in ciphers_line, \
                "RC4 is broken and must NOT appear in ssl_ciphers directive"

    def test_weak_cipher_3des_absent(self):
        # Check only the ssl_ciphers directive line, not comments
        ciphers_match = re.search(r"ssl_ciphers\s+'?([^;']+)'?;", self.nginx)
        if ciphers_match:
            ciphers_line = ciphers_match.group(1)
            assert "3DES" not in ciphers_line and "DES-CBC3" not in ciphers_line, \
                "3DES is deprecated and must NOT appear in ssl_ciphers directive"

    # ── Session security ──────────────────────────────────────────────────────

    def test_ssl_session_tickets_off(self):
        assert "ssl_session_tickets off" in self.nginx, \
            "ssl_session_tickets must be 'off' — session tickets break per-session forward secrecy"

    def test_ssl_session_cache_configured(self):
        assert "ssl_session_cache" in self.nginx, \
            "ssl_session_cache must be configured for performance without session tickets"

    # ── HSTS ─────────────────────────────────────────────────────────────────

    def test_hsts_header_active_not_commented(self):
        for line in self.nginx.splitlines():
            stripped = line.strip()
            if "Strict-Transport-Security" in stripped:
                assert not stripped.startswith("#"), \
                    "HSTS header must NOT be commented out — P10 activates TLS"
                return
        pytest.fail("Strict-Transport-Security (HSTS) header not found in nginx.conf")

    def test_hsts_max_age_one_year(self):
        assert "max-age=31536000" in self.nginx, \
            "HSTS max-age must be 31536000 (1 year) — minimum for preload eligibility"

    def test_hsts_include_subdomains(self):
        assert "includeSubDomains" in self.nginx, \
            "HSTS must include 'includeSubDomains' to protect all subdomains"

    def test_hsts_preload(self):
        assert "preload" in self.nginx, \
            "HSTS must include 'preload' for hstspreload.org submission readiness"

    # ── HTTP → HTTPS redirect ─────────────────────────────────────────────────

    def test_http_redirects_to_https(self):
        assert re.search(r"return\s+301\s+https://", self.nginx), \
            "Port 80 server block must redirect all traffic to HTTPS with 301"

    # ── Certs directory + scripts ─────────────────────────────────────────────

    def test_certs_gitignore_exists(self):
        assert _exists("infra/nginx/certs/.gitignore"), \
            "infra/nginx/certs/.gitignore must exist to prevent accidental cert commits"

    def test_certs_gitignore_ignores_pem_files(self):
        gitignore = _read("infra/nginx/certs/.gitignore")
        assert "*.pem" in gitignore, \
            "certs/.gitignore must exclude *.pem files (private keys and certificates)"

    def test_gen_selfsigned_sh_exists(self):
        assert _exists("scripts/gen_selfsigned_cert.sh"), \
            "scripts/gen_selfsigned_cert.sh must exist for Linux/WSL dev cert generation"

    def test_gen_selfsigned_ps1_exists(self):
        assert _exists("scripts/gen_selfsigned_cert.ps1"), \
            "scripts/gen_selfsigned_cert.ps1 must exist for Windows dev cert generation"
