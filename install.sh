#!/usr/bin/env bash
#
# Lagran CDN one-click installer / deployment bootstrap.
#
# Examples:
#   curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
#     | LAGRAN_REPO=Lagran93/Lagran bash
#
#   sudo LAGRAN_REPO=Lagran93/Lagran bash install.sh --version v1.2.3
#   sudo LAGRAN_REPO=Lagran93/Lagran bash install.sh --with-edge
#
# The script downloads a release bundle from GitHub, installs the control
# binary and static frontend, creates a local PostgreSQL database if needed,
# and starts the control plane under systemd.
set -Eeuo pipefail

REPO="${LAGRAN_REPO:-${GITHUB_REPOSITORY:-Lagran93/Lagran}}"
VERSION="${LAGRAN_VERSION:-latest}"
PREFIX="${LAGRAN_PREFIX:-/opt/lagran}"
CONF_DIR="${LAGRAN_CONF_DIR:-/etc/lagran}"
DATA_DIR="${LAGRAN_DATA_DIR:-/var/lib/lagran}"
LOG_DIR="${LAGRAN_LOG_DIR:-/var/log/lagran}"
WITH_EDGE=0
START_SERVICE=1

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Options:
  --repo <owner/repo>   GitHub repository (or LAGRAN_REPO)
  --version <tag>       Release tag, e.g. v1.2.3; default: latest
  --prefix <dir>        Install prefix; default: /opt/lagran
  --with-edge           Install and start lagran-edge (requires AGENT_TOKEN)
  --no-start            Install files/units but do not start services
  -h, --help

Environment:
  LAGRAN_REPO=<owner/repo>       GitHub repository
  LAGRAN_VERSION=v1.2.3          Release tag
  LAGRAN_DATABASE_URL=...        Existing PostgreSQL URL
  LAGRAN_DB_PASSWORD=...         Password for a newly created lagran DB role
  LAGRAN_REDIS_URL=...           Optional Redis URL
  LAGRAN_SEED_DEMO=true|false    Seed demo account on first boot (default true)
  LAGRAN_CONTROL_BIND=...        Default 0.0.0.0:8080
  LAGRAN_JWT_SECRET=...          Override generated JWT secret
  AGENT_TOKEN=...                Edge node token for --with-edge
  NODE_ID=...                    Edge node id; default hostname
  CONTROL_URL=...                Edge control URL; default http://127.0.0.1:8080
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
log() { printf '\n==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) REPO="${2:-}"; shift 2 ;;
      --repo=*) REPO="${1#*=}"; shift ;;
      --version) VERSION="${2:-}"; shift 2 ;;
      --version=*) VERSION="${1#*=}"; shift ;;
      --prefix) PREFIX="${2:-}"; shift 2 ;;
      --prefix=*) PREFIX="${1#*=}"; shift ;;
      --with-edge) WITH_EDGE=1; shift ;;
      --no-start) START_SERVICE=0; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $1" ;;
    esac
  done
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

install_files() {
  local stage=$1
  [[ -x "$stage/bin/lagran-control" ]] || die "bundle does not contain lagran-control"
  install -d -m 0755 "$PREFIX/bin" "$PREFIX/web" "$DATA_DIR" "$LOG_DIR" "$CONF_DIR"
  for binary in lagran-control lagran-edge lagran-dns; do
    if [[ -f "$stage/bin/$binary" ]]; then
      install -m 0755 "$stage/bin/$binary" "$PREFIX/bin/$binary"
    fi
  done
  if [[ -d "$stage/web" ]]; then
    if command -v rsync >/dev/null 2>&1; then
      rsync -a --delete "$stage/web/" "$PREFIX/web/"
    else
      cp -a "$stage/web/." "$PREFIX/web/"
    fi
  fi
  for file in control.env.example edge.env.example dns.env.example; do
    [[ -f "$stage/$file" ]] && cp -n "$stage/$file" "$CONF_DIR/"
  done
  install -m 0755 "$stage/install.sh" "$PREFIX/install.sh" 2>/dev/null || true
}

create_user() {
  getent group lagran >/dev/null 2>&1 || groupadd --system lagran
  id -u lagran >/dev/null 2>&1 || \
    useradd --system --gid lagran --home-dir "$DATA_DIR" --shell /usr/sbin/nologin lagran
  chown -R lagran:lagran "$DATA_DIR" "$LOG_DIR" "$PREFIX/web" 2>/dev/null || true
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
  local bind="${LAGRAN_CONTROL_BIND:-0.0.0.0:8080}"
  local seed_demo="${LAGRAN_SEED_DEMO:-true}"
  umask 077
  cat > "$env_file" <<EOF
CONTROL_BIND=${bind}
DATABASE_URL=${database_url}
JWT_SECRET=${jwt_secret}
SEED_DEMO=${seed_demo}
LOG_RETENTION_DAYS=14
DATABASE_MAX_CONNECTIONS=20
CONFIG_CACHE_TTL_SECS=3
REDIS_URL=${LAGRAN_REDIS_URL:-}
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
EnvironmentFile=/etc/lagran/control.env
ExecStart=${PREFIX}/bin/lagran-control
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

write_edge_env() {
  [[ "$WITH_EDGE" == "1" ]] || return 0
  [[ -n "${AGENT_TOKEN:-}" ]] || die "--with-edge requires AGENT_TOKEN (create a node in the console first)"
  local env_file="$CONF_DIR/edge.env"
  if [[ -f "$env_file" ]]; then
    log "Keeping existing $env_file"
    return
  fi
  local node_id="${NODE_ID:-$(hostname -s)}"
  local control_url="${CONTROL_URL:-http://127.0.0.1:8080}"
  umask 077
  cat > "$env_file" <<EOF
EDGE_LISTEN=0.0.0.0:8081
CONTROL_URL=${control_url}
AGENT_URL=http://127.0.0.1:8081
NODE_ID=${node_id}
AGENT_TOKEN=${AGENT_TOKEN}
CACHE_BACKEND=memory
EOF
  chown root:lagran "$env_file"
  chmod 0640 "$env_file"
}

write_edge_unit() {
  [[ "$WITH_EDGE" == "1" ]] || return 0
  cat > /etc/systemd/system/lagran-edge.service <<EOF
[Unit]
Description=Lagran CDN Edge Node
After=network-online.target lagran-control.service
Wants=network-online.target

[Service]
Type=simple
User=lagran
Group=lagran
EnvironmentFile=/etc/lagran/edge.env
ExecStart=${PREFIX}/bin/lagran-edge
WorkingDirectory=${DATA_DIR}
Restart=always
RestartSec=3
LimitNOFILE=1048576
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
}

main() {
  parse_args "$@"
  [[ "$EUID" -eq 0 ]] || die "run as root (use sudo)"
  command -v curl >/dev/null 2>&1 || die "curl is required"
  command -v tar >/dev/null 2>&1 || die "tar is required"

  local arch
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) die "prebuilt arm64 bundle is not published; build locally" ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac

  log "Resolving release"
  if [[ "$VERSION" == "latest" ]]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
    [[ -n "$VERSION" ]] || die "could not resolve latest release for $REPO"
  fi
  local asset="lagran-cdn-${VERSION#v}-linux-${arch}.tar.gz"
  local base="https://github.com/${REPO}/releases/download/${VERSION}"
  log "Downloading ${asset}"
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -fL --retry 3 --retry-delay 2 "$base/$asset" -o "$tmp/$asset"
  if curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"; then
    (cd "$tmp" && grep "  ${asset}\$" SHA256SUMS | sha256sum -c -)
  else
    warn "SHA256SUMS not found; continuing without checksum verification"
  fi
  mkdir -p "$tmp/stage"
  tar -xzf "$tmp/$asset" -C "$tmp/stage"

  install_files "$tmp/stage"
  create_user
  write_control_env
  write_control_unit
  write_edge_env
  write_edge_unit

  if [[ "$START_SERVICE" == "1" ]] && command -v systemctl >/dev/null 2>&1; then
    log "Enabling services"
    systemctl daemon-reload
    systemctl enable --now lagran-control
    [[ "$WITH_EDGE" == "1" ]] && systemctl enable --now lagran-edge
    for _ in $(seq 1 30); do
      if curl -fsS "http://127.0.0.1:8080/health" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    curl -fsS "http://127.0.0.1:8080/health" || warn "control health check failed; see journalctl -u lagran-control"
  else
    log "Files installed; start with: systemctl enable --now lagran-control"
  fi

  cat <<EOF

Lagran CDN installed.

  version : ${VERSION}
  binaries: ${PREFIX}/bin
  config  : ${CONF_DIR}/control.env
  web     : ${PREFIX}/web
  health  : http://127.0.0.1:8080/health

Frontend static files are in ${PREFIX}/web. Serve them with Caddy/Nginx and
reverse proxy /api/* and /health to 127.0.0.1:8080.

If SEED_DEMO=true, sign in with demo@lagran.dev / demo123 and change it now.
EOF
}

main "$@"
