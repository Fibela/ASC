# ASC PremosCorp — TLS Setup Guide

> TLS terminates at nginx. Backend and frontend containers are never exposed directly.
> All certificates go in `infra/nginx/certs/` (gitignored — never committed).

---

## Quick Reference

| Scenario | Certificate | Command |
|----------|-------------|---------|
| Local dev | Self-signed | `bash scripts/gen_selfsigned_cert.sh` |
| Staging | Self-signed | Same script, different domain |
| Production | Let's Encrypt | certbot (see below) |

---

## Local / Dev: Self-Signed Certificate

```bash
# Generates fullchain.pem + privkey.pem in infra/nginx/certs/
bash scripts/gen_selfsigned_cert.sh

# Windows PowerShell alternative:
pwsh scripts/gen_selfsigned_cert.ps1
```

The self-signed cert triggers browser warnings — acceptable for development.
Add `infra/nginx/certs/fullchain.pem` to your OS trust store to suppress them.

---

## Production: Let's Encrypt with Certbot

### Prerequisites

- Public domain pointing to your server IP (DNS A record)
- Ports 80 and 443 open in firewall
- Docker Compose running (nginx must be up for ACME challenge)

### Step 1 — Install certbot

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y certbot

# Or via snap (recommended for auto-renewal):
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
```

### Step 2 — Stop nginx temporarily (standalone mode)

```bash
# Stop only nginx (backend and postgres can stay up)
docker compose stop nginx

# Issue certificate (certbot uses port 80 directly)
sudo certbot certonly \
  --standalone \
  --preferred-challenges http \
  -d asc.premoscorp.com \
  --email security@premoscorp.com \
  --agree-tos \
  --non-interactive
```

Certificates are written to `/etc/letsencrypt/live/asc.premoscorp.com/`.

### Step 3 — Copy certs to nginx volume

```bash
sudo cp /etc/letsencrypt/live/asc.premoscorp.com/fullchain.pem infra/nginx/certs/
sudo cp /etc/letsencrypt/live/asc.premoscorp.com/privkey.pem   infra/nginx/certs/
sudo chown $(whoami):$(whoami) infra/nginx/certs/*.pem
sudo chmod 600 infra/nginx/certs/privkey.pem
sudo chmod 644 infra/nginx/certs/fullchain.pem
```

### Step 4 — Restart nginx

```bash
docker compose start nginx
```

Verify TLS:
```bash
curl -v https://asc.premoscorp.com/health 2>&1 | grep -E "SSL|TLS|certificate"
```

---

## Production: Let's Encrypt with Webroot (zero-downtime renewal)

Preferred for automated renewal — nginx stays up during cert renewal.

### Setup

Uncomment the certbot webroot volume in `docker-compose.yml`:

```yaml
# nginx service — volumes section:
- ./infra/nginx/certbot-webroot:/var/www/certbot:ro
```

```bash
# Issue with webroot (nginx must be running):
sudo certbot certonly \
  --webroot \
  --webroot-path /path/to/infra/nginx/certbot-webroot \
  -d asc.premoscorp.com \
  --email security@premoscorp.com \
  --agree-tos \
  --non-interactive
```

### Automated Renewal

```bash
# Test renewal (dry run — no cert issued)
sudo certbot renew --dry-run

# Add to crontab for automatic renewal twice daily (Let's Encrypt recommendation):
# sudo crontab -e
0 0,12 * * * certbot renew --quiet \
  --deploy-hook "cp /etc/letsencrypt/live/asc.premoscorp.com/fullchain.pem /opt/asc/infra/nginx/certs/ && \
                 cp /etc/letsencrypt/live/asc.premoscorp.com/privkey.pem /opt/asc/infra/nginx/certs/ && \
                 docker compose -f /opt/asc/docker-compose.yml exec nginx nginx -s reload"
```

---

## Certificate Verification

```bash
# Check cert expiry
openssl x509 -in infra/nginx/certs/fullchain.pem -noout -dates

# Check TLS config (from external host)
openssl s_client -connect asc.premoscorp.com:443 -servername asc.premoscorp.com < /dev/null 2>&1 \
  | grep -E "Protocol|Cipher|Verify"

# Online scanner (full TLS grade):
# https://www.ssllabs.com/ssltest/analyze.html?d=asc.premoscorp.com
```

Expected SSL Labs grade: **A** (TLS 1.2+, ECDHE, no weak ciphers, HSTS).

---

## Certificate Storage Security

```
infra/nginx/certs/
├── .gitignore          ← blocks all *.pem from git (already in place)
├── fullchain.pem       ← certificate chain (public — safe to share)
└── privkey.pem         ← private key (SECRET — never commit, never share)
```

`infra/nginx/certs/.gitignore` already blocks `*.pem` from being committed.
The `privkey.pem` must be backed up securely (password manager or Vault).

---

## Fase 1 (Render) — No TLS Config Needed

Render provides TLS automatically for `.onrender.com` domains and custom domains.
No nginx, no certbot, no manual cert management required in Fase 1.

For the frontend on Vercel: TLS is also automatic.

TLS manual setup is only needed for **Fase 2 (Docker Compose self-hosting)**.
