#!/usr/bin/env bash
# Generate a self-signed cert for local HTTPS testing
set -euo pipefail
DIR="${1:-./certs}"
DOMAIN="${2:-cdn.example.com}"
mkdir -p "$DIR"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$DIR/key.pem" \
  -out "$DIR/cert.pem" \
  -days 365 \
  -subj "/CN=${DOMAIN}/O=Lagran Dev"
echo "Wrote $DIR/cert.pem and $DIR/key.pem"
echo "Upload via control API or set:"
echo "  EDGE_TLS_CERT=$DIR/cert.pem EDGE_TLS_KEY=$DIR/key.pem"
echo "  EDGE_HTTPS_LISTEN=0.0.0.0:8443"
