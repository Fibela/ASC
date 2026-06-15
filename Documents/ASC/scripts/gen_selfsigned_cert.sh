#!/usr/bin/env bash
# ─── ASC PremosCorp — Self-Signed TLS Certificate Generator ──────────────────
#
# PURPOSE: Generate a self-signed certificate for dev/staging environments.
#          NOT for production — use Let's Encrypt (see docs/TLS_SETUP.md).
#
# USAGE:
#   bash scripts/gen_selfsigned_cert.sh [DOMAIN]
#
# EXAMPLES:
#   bash scripts/gen_selfsigned_cert.sh                   # defaults to 'localhost'
#   bash scripts/gen_selfsigned_cert.sh asc.premoscorp.com
#
# OUTPUT:
#   infra/nginx/certs/fullchain.pem  — self-signed certificate (365 days)
#   infra/nginx/certs/privkey.pem    — RSA 2048-bit private key
#
# SECURITY:
#   • These files are gitignored — never committed (see infra/nginx/certs/.gitignore)
#   • Browsers will show a security warning for self-signed certs (expected in dev)
#   • Private key is set to 600 permissions (owner read-only)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DOMAIN="${1:-localhost}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CERTS_DIR="$REPO_ROOT/infra/nginx/certs"

echo "──────────────────────────────────────────────────────"
echo "  ASC PremosCorp — Self-Signed Certificate Generator  "
echo "──────────────────────────────────────────────────────"
echo "  Domain  : $DOMAIN"
echo "  Certs   : $CERTS_DIR"
echo ""

# Verify openssl is available
if ! command -v openssl &>/dev/null; then
    echo "ERROR: openssl not found. Install it with:"
    echo "  Ubuntu/Debian: sudo apt-get install openssl"
    echo "  macOS:         brew install openssl"
    exit 1
fi

mkdir -p "$CERTS_DIR"

# Generate private key + self-signed certificate
# -x509      : output a self-signed cert (not a CSR)
# -nodes     : no passphrase on private key (needed for nginx auto-start)
# -days 365  : validity period
# -newkey    : generate new private key
# -addext    : Subject Alternative Names (required by modern browsers)
openssl req -x509 \
    -nodes \
    -days 365 \
    -newkey rsa:2048 \
    -keyout "$CERTS_DIR/privkey.pem" \
    -out    "$CERTS_DIR/fullchain.pem" \
    -subj   "/C=US/ST=Security/L=SOC/O=PremosCorp/OU=ASC/CN=$DOMAIN" \
    -addext "subjectAltName=DNS:$DOMAIN,DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

# Restrict private key permissions
chmod 600 "$CERTS_DIR/privkey.pem"
chmod 644 "$CERTS_DIR/fullchain.pem"

echo ""
echo "✓ Certificate generated successfully:"
echo "    $CERTS_DIR/fullchain.pem"
echo "    $CERTS_DIR/privkey.pem"
echo ""
echo "Certificate details:"
openssl x509 -noout -subject -issuer -dates -in "$CERTS_DIR/fullchain.pem"
echo ""
echo "⚠  Self-signed: browsers will show a security warning."
echo "   Accept it manually in dev or add to system trust store."
echo ""
echo "   For production, use Let's Encrypt: docs/TLS_SETUP.md"
echo "──────────────────────────────────────────────────────"
