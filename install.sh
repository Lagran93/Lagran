#!/usr/bin/env bash
#
# Lagran CDN component installer.
#
# Usage:
#   install.sh control
#   install.sh edge
#   install.sh dns
#   install.sh frontend
#
# Remote one-line:
#   curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
#     | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- control
#
# Each component is installed independently. A release bundle is downloaded
# once, but only the selected binary/config/service is installed.
set -Eeuo pipefail

REPO="${LAGRAN_REPO:-${GITHUB_REPOSITORY:-Lagran93/Lagran}}"
VERSION="${LAGRAN_VERSION:-latest}"
PREFIX="${LAGRAN_PREFIX:-/opt/lagran}"
BIN_DIR="${LAGRAN_BIN_DIR:-$PREFIX/bin}"
WEB_DIR="${LAGRAN_WEB_DIR:-$PREFIX/web}"
CONF_DIR="${LAGRAN_CONF_DIR:-/etc/lagran}"
DATA_DIR="${LAGRAN_DATA_DIR:-/var/lib/lagran}"
LOG_DIR="${LAGRAN_LOG_DIR:-/var/log/lagran}"
START_SERVICE=1
WITH_CADDY=0
COMPONENT=""
STAGE=""
TMP=""

usage() {
  cat <<'EOF'
Usage: install.sh <control|edge|dns|frontend> [options]

Components:
  control    install lagran-control, database bootstrap, systemd service
  edge       install lagran-edge and edge.env, systemd service
  dns        install lagran-dns and dns.env, systemd service
  frontend   install static Nuxt output into /opt/lagran/web

Options:
  --repo <owner/repo>   GitHub repository (or LAGRAN_REPO)
  --version <tag>       Release tag, e.g. v1.2.3; default: latest
  --prefix <dir>        Install prefix; default: /opt/lagran
  --with-caddy          frontend only: write a Caddyfile example
  --no-start            install files/units but do not start systemd
  -h, --help

Environment:
  LAGRAN_REPO=<owner/repo>       GitHub repository
  LAGRAN_VERSION=v1.2.3          Release tag
  LAGRAN_PREFIX=/opt/lagran      Install prefix
  LAGRAN_DATABASE_URL=...        control: existing PostgreSQL URL
  LAGRAN_DB_PASSWORD=...         control: password for new lagran role
  LAGRAN_DB_NAME=lagran          control: database name
  LAGRAN_DB_USER=lagran          control: role name
  LAGRAN_JWT_SECRET=...          control: override generated JWT secret
  LAGRAN_AGENT_TOKEN=...         control: global DNS/agent token
  LAGRAN_REDIS_URL=...           control: optional Redis URL
  LAGRAN_SEED_DEMO=true|false    control: seed demo account (default true)
  LAGRAN_CONTROL_BIND=...        control: default 0.0.0.0:8080
  LAGRAN_CONTROL_PUBLIC_URL=...  control: public HTTPS URL

  AGENT_TOKEN=...                edge/dns: required node/global token
  NODE_ID=...                    edge: node id, default hostname
  CONTROL_URL=...                edge/dns: default http://127.0.0.1:8080
  AGENT_URL=...                  edge: control callback URL
  EDGE_LISTEN=...                edge: default 0.0.0.0:8081
  EDGE_ADMIN_LISTEN=...          edge: default 127.0.0.1:8082
  REDIS_URL=...                  edge: optional shared CC sliding-window Redis
  CC_REDIS_PREFIX=...            edge: default lagran:cc
  LARGE_CACHE_ENABLED=true|false edge: large-object disk cache (default false)
  LARGE_CACHE_DIR=...            edge: default /var/lib/lagran/large-cache
  LARGE_CACHE_MAX_OBJECT_BYTES=  edge: default 1 GiB
  PUBLIC_IP=...                  edge: public IP for GeoDNS
  NODE_REGION=...                edge: region label
  DNS_ZONE=...                   dns: default edge.lagran.net
  DNS_NS_NAME=...                dns: NS names
  DNS_NS_IP=...                  dns: glue IPs
  DNS_LISTEN=...                 dns: default 0.0.0.0:53
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
log() { printf '\n==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

parse_args() {
  [[ $# -ge 1 ]] || { usage; exit 1; }
  case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    control|edge|dns|frontend) COMPONENT="$1"; shift ;;
    *) die "expected one of: control, edge, dns, frontend" ;;
  esac
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) REPO="${2:-}"; shift 2 ;;
      --repo=*) REPO="${1#*=}"; shift ;;
      --version) VERSION="${2:-}"; shift 2 ;;
      --version=*) VERSION="${1#*=}"; shift ;;
      --prefix) PREFIX="${2:-}"; shift 2 ;;
      --prefix=*) PREFIX="${1#*=}"; shift ;;
      --with-caddy) WITH_CADDY=1; shift ;;
      --no-start) START_SERVICE=0; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
  BIN_DIR="${LAGRAN_BIN_DIR:-$PREFIX/bin}"
  WEB_DIR="${LAGRAN_WEB_DIR:-$PREFIX/web}"
}

rand_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$1"
  else
    od -An -N "$1" -tx1 /dev/urandom | tr -d ' \n'
  fi
}

psql_admin() {
  if command -v runuser >/dev/null 2>&1; then
    runuser -u postgres -- "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo -u postgres "$@"
  else
    return 1
  fi
}

setup_database() {
  if [[ -n "${LAGRAN_DATABASE_URL:-}" ]]; then
    printf '%s' "$LAGRAN_DATABASE_URL"
    return
  fi
  command -v psql >/dev/null 2>&1 || die "psql not found; install PostgreSQL or set LAGRAN_DATABASE_URL"
  command -v runuser >/dev/null 2>&1 || command -v sudo >/dev/null 2>&1 || \
    die "cannot access postgres user; set LAGRAN_DATABASE_URL"

  local db_user="${LAGRAN_DB_USER:-lagran}"
  local db_name="${LAGRAN_DB_NAME:-lagran}"
  [[ "$db_user" =~ ^[a-zA-Z0-9_]+$ ]] || die "invalid LAGRAN_DB_USER"
  [[ "$db_name" =~ ^[a-zA-Z0-9_]+$ ]] || die "invalid LAGRAN_DB_NAME"
  local db_pass="${LAGRAN_DB_PASSWORD:-$(rand_hex 24)}"

  printf '\n==> Configuring PostgreSQL role/database\n' >&2
  psql_admin psql -v ON_ERROR_STOP=1 -q <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${db_user}') THEN
    CREATE ROLE ${db_user} LOGIN PASSWORD '${db_pass}';
  ELSE
    ALTER ROLE ${db_user} WITH LOGIN PASSWORD '${db_pass}';
  END IF;
END
\$\$;
SQL
  if ! psql_admin psql -tAc "SELECT 1 FROM pg_database WHERE datname='${db_name}'" | grep -q 1; then
    psql_admin createdb -O "$db_user" "$db_name"
  fi
  printf 'postgres://%s:%s@127.0.0.1:5432/%s' "$db_user" "$db_pass" "$db_name"
}

ensure_dirs() {
  install -d -m 0755 "$PREFIX" "$BIN_DIR" "$CONF_DIR" "$DATA_DIR" "$LOG_DIR"
}

ensure_user() {
  getent group lagran >/dev/null 2>&1 || groupadd --system lagran
  id -u lagran >/dev/null 2>&1 || \
    useradd --system --gid lagran --home-dir "$DATA_DIR" --shell /usr/sbin/nologin lagran
  chown -R lagran:lagran "$DATA_DIR" "$LOG_DIR" 2>/dev/null || true
}

install_env_example() {
  local name=$1
  if [[ -f "$STAGE/$name" ]]; then
    install -m 0644 "$STAGE/$name" "$CONF_DIR/$name"
  fi
}

install_binary() {
  local name=$1
  [[ -x "$STAGE/bin/$name" ]] || die "release does not contain bin/$name"
  install -m 0755 "$STAGE/bin/$name" "$BIN_DIR/$name"
}

resolve_release() {
  log "Resolving release"
  if [[ "$VERSION" == "latest" ]]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
    [[ -n "$VERSION" ]] || die "could not resolve latest release for $REPO"
  fi
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) die "prebuilt arm64 bundle is not published; build locally" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
  local asset="lagran-cdn-${VERSION#v}-linux-${ARCH}.tar.gz"
  local base="https://github.com/${REPO}/releases/download/${VERSION}"
  log "Downloading ${asset}"
  TMP="$(mktemp -d)"
  trap 'rm -rf "${TMP:-}"' EXIT
  curl -fL --retry 3 --retry-delay 2 "$base/$asset" -o "$TMP/$asset"
  if curl -fsSL "$base/SHA256SUMS" -o "$TMP/SHA256SUMS"; then
    (cd "$TMP" && grep "  ${asset}\$" SHA256SUMS | sha256sum -c -)
  else
    warn "SHA256SUMS not found; continuing without checksum verification"
  fi
  STAGE="$TMP/stage"
  mkdir -p "$STAGE"
  tar -xzf "$TMP/$asset" -C "$STAGE"
}

write_control_env() {
  local env_file="$CONF_DIR/control.env"
  if [[ -f "$env_file" ]]; then
    log "Keeping existing $env_file"
    return
  fi
  local database_url
  database_url="$(setup_database)"
  local jwt_secret="${LAGRAN_JWT_SECRET:-$(rand_hex 32)}"
  local agent_token="${LAGRAN_AGENT_TOKEN:-$(rand_hex 24)}"
  local bind="${LAGRAN_CONTROL_BIND:-0.0.0.0:8080}"
  local seed_demo="${LAGRAN_SEED_DEMO:-true}"
  local public_url="${LAGRAN_CONTROL_PUBLIC_URL:-}"
  umask 077
  cat > "$env_file" <<EOF
CONTROL_BIND=${bind}
CONTROL_PUBLIC_URL=${public_url}
DATABASE_URL=${database_url}
DATABASE_MAX_CONNECTIONS=20
DATABASE_MIN_CONNECTIONS=2
DATABASE_ACQUIRE_TIMEOUT_SECS=5
JWT_SECRET=${jwt_secret}
REQUIRE_SECURE_SECRETS=true
AGENT_TOKEN=${agent_token}
SEED_DEMO=${seed_demo}
ALLOW_REGISTER=false
CAPTCHA_ENABLED=true
REDIS_URL=${LAGRAN_REDIS_URL:-}
REDIS_SESSION_TTL_SECS=30
CONFIG_CACHE_TTL_SECS=3
LOG_RETENTION_DAYS=14
ALERT_EVAL_SECS=30
LAGRAN_UPDATE_REPO=${REPO}
LAGRAN_UPDATE_HELPER=${BIN_DIR}/lagran-update
LAGRAN_UPDATE_REQUEST_PATH=${DATA_DIR}/update.request
LAGRAN_UPDATE_STATUS_PATH=${DATA_DIR}/update.status
EOF
  chown root:lagran "$env_file"
  chmod 0640 "$env_file"
  if [[ "$seed_demo" == "true" ]]; then
    warn "SEED_DEMO=true creates demo@lagran.dev / demo123; change it immediately"
  fi
}

write_control_unit() {
  cat > /etc/systemd/system/lagran-control.service <<EOF
[Unit]
Description=Lagran CDN Control Plane
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=lagran
Group=lagran
EnvironmentFile=${CONF_DIR}/control.env
ExecStart=${BIN_DIR}/lagran-control
WorkingDirectory=${DATA_DIR}
Restart=always
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
}

install_update_helper() {
  [[ -f "$STAGE/update.sh" ]] || return 0
  install -m 0755 "$STAGE/update.sh" "$BIN_DIR/lagran-update"
  cat > "$CONF_DIR/update.env" <<EOF
LAGRAN_PREFIX=${PREFIX}
LAGRAN_DATA_DIR=${DATA_DIR}
LAGRAN_UPDATE_REPO=${REPO}
LAGRAN_UPDATE_REQUEST_PATH=${DATA_DIR}/update.request
LAGRAN_UPDATE_STATUS_PATH=${DATA_DIR}/update.status
EOF
  chmod 0644 "$CONF_DIR/update.env"
  cat > /etc/systemd/system/lagran-update.service <<EOF
[Unit]
Description=Lagran CDN privileged updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${BIN_DIR}/lagran-update
TimeoutStartSec=600
EOF
  cat > /etc/systemd/system/lagran-update.path <<EOF
[Unit]
Description=Watch for Lagran CDN update requests

[Path]
PathExists=${DATA_DIR}/update.request
Unit=lagran-update.service

[Install]
WantedBy=multi-user.target
EOF
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    if [[ "$START_SERVICE" == "1" ]]; then
      systemctl enable --now lagran-update.path
    else
      systemctl enable lagran-update.path
    fi
  fi
}

write_edge_env() {
  local env_file="$CONF_DIR/edge.env"
  if [[ -f "$env_file" ]]; then
    log "Keeping existing $env_file"
    return
  fi
  [[ -n "${AGENT_TOKEN:-}" ]] || die "edge install requires AGENT_TOKEN (create a node in the console first)"
  local node_id="${NODE_ID:-$(hostname -s)}"
  local control_url="${CONTROL_URL:-http://127.0.0.1:8080}"
  local edge_listen="${EDGE_LISTEN:-0.0.0.0:8081}"
  local admin_listen="${EDGE_ADMIN_LISTEN:-127.0.0.1:8082}"
  local agent_url="${AGENT_URL:-http://127.0.0.1:8082}"
  umask 077
  cat > "$env_file" <<EOF
EDGE_LISTEN=${edge_listen}
EDGE_ADMIN_LISTEN=${admin_listen}
NODE_ID=${node_id}
NODE_REGION=${NODE_REGION:-local}
PUBLIC_IP=${PUBLIC_IP:-}
CONTROL_URL=${control_url}
AGENT_URL=${agent_url}
AGENT_TOKEN=${AGENT_TOKEN}
CACHE_BACKEND=memory
CACHE_TTL=60
REDIS_URL=${REDIS_URL:-}
CC_REDIS_PREFIX=${CC_REDIS_PREFIX:-lagran:cc}
CC_STATIC_MULTIPLIER=${CC_STATIC_MULTIPLIER:-8}
CC_AUTH_DIVISOR=${CC_AUTH_DIVISOR:-2}
CC_DOWNLOAD_MULTIPLIER=${CC_DOWNLOAD_MULTIPLIER:-2}
CC_BEHAVIOR_ENABLED=${CC_BEHAVIOR_ENABLED:-false}
CC_BEHAVIOR_SCORE=${CC_BEHAVIOR_SCORE:-4}
LARGE_CACHE_ENABLED=${LARGE_CACHE_ENABLED:-false}
LARGE_CACHE_DIR=${LARGE_CACHE_DIR:-${DATA_DIR}/large-cache}
LARGE_CACHE_MIN_OBJECT_BYTES=${LARGE_CACHE_MIN_OBJECT_BYTES:-8388608}
LARGE_CACHE_MAX_OBJECT_BYTES=${LARGE_CACHE_MAX_OBJECT_BYTES:-1073741824}
LARGE_CACHE_MAX_BYTES=${LARGE_CACHE_MAX_BYTES:-21474836480}
CHALLENGE_SECRET=${CHALLENGE_SECRET:-}
EOF
  chown root:lagran "$env_file"
  chmod 0640 "$env_file"
}

write_edge_unit() {
  cat > /etc/systemd/system/lagran-edge.service <<EOF
[Unit]
Description=Lagran CDN Edge Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=lagran
Group=lagran
EnvironmentFile=${CONF_DIR}/edge.env
ExecStart=${BIN_DIR}/lagran-edge
WorkingDirectory=${DATA_DIR}
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
}

write_dns_env() {
  local env_file="$CONF_DIR/dns.env"
  if [[ -f "$env_file" ]]; then
    log "Keeping existing $env_file"
    return
  fi
  local agent_token="${AGENT_TOKEN:-}"
  if [[ -z "$agent_token" && -f "$CONF_DIR/control.env" ]]; then
    agent_token="$(sed -n 's/^AGENT_TOKEN=//p' "$CONF_DIR/control.env" | tail -1)"
  fi
  [[ -n "$agent_token" ]] || warn "AGENT_TOKEN is empty; DNS /schedule requests may be rejected"
  umask 077
  cat > "$env_file" <<EOF
DNS_LISTEN=${DNS_LISTEN:-0.0.0.0:53}
DNS_ZONE=${DNS_ZONE:-edge.lagran.net}
DNS_NS_NAME=${DNS_NS_NAME:-ns1.edge.lagran.net}
DNS_NS_IP=${DNS_NS_IP:-127.0.0.1}
DNS_TTL=${DNS_TTL:-30}
DNS_TCP=${DNS_TCP:-true}
DNS_WORKERS=${DNS_WORKERS:-8}
CONTROL_URL=${CONTROL_URL:-http://127.0.0.1:8080}
AGENT_TOKEN=${agent_token}
DNS_CACHE_SECS=${DNS_CACHE_SECS:-5}
DNS_STALE_SECS=${DNS_STALE_SECS:-300}
DNS_CONTROL_TIMEOUT_MS=${DNS_CONTROL_TIMEOUT_MS:-800}
DNS_FALLBACK_IP=${DNS_FALLBACK_IP:-}
EOF
  chown root:lagran "$env_file"
  chmod 0640 "$env_file"
}

write_dns_unit() {
  cat > /etc/systemd/system/lagran-dns.service <<EOF
[Unit]
Description=Lagran CDN Authoritative DNS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=lagran
Group=lagran
EnvironmentFile=${CONF_DIR}/dns.env
ExecStart=${BIN_DIR}/lagran-dns
WorkingDirectory=${DATA_DIR}
Restart=always
RestartSec=3
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
}

install_frontend() {
  [[ -f "$STAGE/web/index.html" ]] || die "release does not contain web/index.html"
  install -d -m 0755 "$WEB_DIR"
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete "$STAGE/web/" "$WEB_DIR/"
  else
    cp -a "$STAGE/web/." "$WEB_DIR/"
  fi
  chmod -R a+rX "$WEB_DIR"
  install_env_example frontend.env.example
  if [[ "$WITH_CADDY" == "1" ]]; then
    cat > "$CONF_DIR/Caddyfile.lagran" <<EOF
:80 {
    root * ${WEB_DIR}
    encode gzip
    @api path /api/* /health /ready
    handle @api {
        reverse_proxy 127.0.0.1:8080
    }
    handle {
        try_files {path} /index.html
        file_server
    }
}
EOF
    log "Wrote ${CONF_DIR}/Caddyfile.lagran"
  fi
}

enable_service() {
  local service=$1
  if [[ "$START_SERVICE" != "1" ]]; then
    log "Installed ${service}.service; start with: systemctl enable --now ${service}"
    return
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemd not available; start ${BIN_DIR}/${service} manually"
    return
  fi
  systemctl daemon-reload
  systemctl enable --now "${service}.service"
}

main_control() {
  install_binary lagran-control
  ensure_user
  install_env_example control.env.example
  write_control_env
  write_control_unit
  install_update_helper
  enable_service lagran-control
  local control_port
  control_port="$(sed -n 's/^CONTROL_BIND=//p' "$CONF_DIR/control.env" | tail -1)"
  control_port="${control_port##*:}"
  control_port="${control_port:-8080}"
  if command -v systemctl >/dev/null 2>&1 && [[ "$START_SERVICE" == "1" ]]; then
    for _ in $(seq 1 30); do
      if curl -fsS "http://127.0.0.1:${control_port}/health" >/dev/null 2>&1; then break; fi
      sleep 1
    done
    curl -fsS "http://127.0.0.1:${control_port}/health" || warn "control health check failed; see journalctl -u lagran-control"
  fi
  cat <<EOF

Control installed.
  binary : ${BIN_DIR}/lagran-control
  env    : ${CONF_DIR}/control.env
  health : http://127.0.0.1:${control_port}/health
  demo   : demo@lagran.dev / demo123 (if SEED_DEMO=true)
EOF
}

main_edge() {
  install_binary lagran-edge
  ensure_user
  install_env_example edge.env.example
  write_edge_env
  write_edge_unit
  enable_service lagran-edge
  cat <<EOF

Edge installed.
  binary : ${BIN_DIR}/lagran-edge
  env    : ${CONF_DIR}/edge.env
  health : http://127.0.0.1:8082/__lagran/health
EOF
}

main_dns() {
  install_binary lagran-dns
  ensure_user
  install_env_example dns.env.example
  write_dns_env
  write_dns_unit
  enable_service lagran-dns
  cat <<EOF

DNS installed.
  binary : ${BIN_DIR}/lagran-dns
  env    : ${CONF_DIR}/dns.env
  test   : dig @127.0.0.1 -p 53 <domain> A
EOF
}

main_frontend() {
  install_frontend
  cat <<EOF

Frontend installed.
  web    : ${WEB_DIR}
  caddy  : ${CONF_DIR}/Caddyfile.lagran (if --with-caddy)

Serve it with Caddy/Nginx and proxy /api/*, /health, /ready
to the control plane at 127.0.0.1:8080.
EOF
}

main() {
  parse_args "$@"
  [[ "$EUID" -eq 0 ]] || die "run as root (use sudo)"
  command -v curl >/dev/null 2>&1 || die "curl is required"
  command -v tar >/dev/null 2>&1 || die "tar is required"
  if [[ "$WITH_CADDY" == "1" && "$COMPONENT" != "frontend" ]]; then
    die "--with-caddy is only valid for frontend"
  fi

  resolve_release
  ensure_dirs
  if [[ -f "$STAGE/LICENSE" ]]; then
    install -m 0644 "$STAGE/LICENSE" "$PREFIX/LICENSE"
  fi
  case "$COMPONENT" in
    control) main_control ;;
    edge) main_edge ;;
    dns) main_dns ;;
    frontend) main_frontend ;;
    *) die "unknown component: $COMPONENT" ;;
  esac
}

main "$@"
