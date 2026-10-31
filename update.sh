#!/usr/bin/env bash
# Root-only updater triggered by /var/lib/lagran/update.request through the
# lagran-update.path systemd unit. The control plane only writes the request;
# this script performs the privileged download, verification and restart.
set -Eeuo pipefail
umask 077

PREFIX="${LAGRAN_PREFIX:-/opt/lagran}"
CONF_DIR="/etc/lagran"
REPO="${LAGRAN_UPDATE_REPO:-Lagran93/Lagran}"
REQUEST="${LAGRAN_UPDATE_REQUEST_PATH:-/var/lib/lagran/update.request}"
STATUS="${LAGRAN_UPDATE_STATUS_PATH:-/var/lib/lagran/update.status}"
DATA_DIR="${LAGRAN_DATA_DIR:-/var/lib/lagran}"
WORK=""

# update.env is written by install.sh and may override the defaults above.
if [[ -f "${CONF_DIR}/update.env" ]]; then
  # shellcheck disable=SC1091
  source "${CONF_DIR}/update.env"
fi
PREFIX="${LAGRAN_PREFIX:-$PREFIX}"
DATA_DIR="${LAGRAN_DATA_DIR:-$DATA_DIR}"
REPO="${LAGRAN_UPDATE_REPO:-$REPO}"
REQUEST="${LAGRAN_UPDATE_REQUEST_PATH:-$REQUEST}"
STATUS="${LAGRAN_UPDATE_STATUS_PATH:-$STATUS}"

cleanup() {
  if [[ -n "${WORK:-}" ]]; then rm -rf "${WORK}"; fi
}
trap cleanup EXIT

status() {
  local state="$1" tag="${2:-}" message="${3:-}"
  mkdir -p "$(dirname "${STATUS}")"
  printf '%s|%s|%s|%s\n' "${state}" "${tag}" "${message}" "$(date -u +%FT%TZ)" \
    > "${STATUS}.tmp.$$"
  mv -f "${STATUS}.tmp.$$" "${STATUS}"
  chmod 0644 "${STATUS}" 2>/dev/null || true
}

fail() {
  status "failed" "${TAG:-}" "$1"
  rm -f "${REQUEST}"
  exit 1
}

[[ -f "${REQUEST}" ]] || exit 0
TAG="$(head -n 1 "${REQUEST}" | tr -d '[:space:]')"
[[ "${TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+.][A-Za-z0-9._+-]+)?$ ]] || fail "invalid release tag"
[[ "$(uname -m)" == "x86_64" || "$(uname -m)" == "amd64" ]] || fail "only amd64 releases are published"

VERSION="${TAG#v}"
ASSET="lagran-cdn-${VERSION}-linux-amd64.tar.gz"
BASE="${LAGRAN_UPDATE_BASE:-https://github.com/${REPO}/releases/download/${TAG}}"
WORK="$(mktemp -d "${DATA_DIR}/update.XXXXXX")"
status "running" "${TAG}" "downloading ${ASSET}"

curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 "${BASE}/${ASSET}" \
  -o "${WORK}/${ASSET}" || fail "download release failed"
curl -fsSL --retry 3 --connect-timeout 15 "${BASE}/SHA256SUMS" \
  -o "${WORK}/SHA256SUMS" || fail "download SHA256SUMS failed"
(
  cd "${WORK}"
  grep -F "  ${ASSET}" SHA256SUMS | sha256sum -c - >/dev/null
) || fail "checksum verification failed"

mkdir -p "${WORK}/stage"
tar -xzf "${WORK}/${ASSET}" -C "${WORK}/stage" || fail "extract release failed"
[[ -x "${WORK}/stage/bin/lagran-control" ]] || fail "release has no control binary"

BACKUP="${DATA_DIR}/update-backup/${TAG}-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${BACKUP}/bin"
for bin in lagran-control lagran-edge lagran-dns; do
  if [[ -f "${PREFIX}/bin/${bin}" ]]; then
    cp -a "${PREFIX}/bin/${bin}" "${BACKUP}/bin/"
  fi
done
if [[ -d "${PREFIX}/web" ]]; then
  cp -a "${PREFIX}/web" "${BACKUP}/web"
fi
status "running" "${TAG}" "backup saved to ${BACKUP}"

for bin in lagran-control lagran-edge lagran-dns; do
  src="${WORK}/stage/bin/${bin}"
  [[ -x "${src}" ]] || continue
  tmp="${PREFIX}/bin/.${bin}.new"
  install -m 0755 "${src}" "${tmp}" || fail "install ${bin} failed"
  mv -f "${tmp}" "${PREFIX}/bin/${bin}" || fail "replace ${bin} failed"
done
if [[ -d "${WORK}/stage/web" && -d "${PREFIX}/web" ]]; then
  cp -a "${WORK}/stage/web/." "${PREFIX}/web/" || fail "update web failed"
fi
if [[ -f "${WORK}/stage/update.sh" ]]; then
  install -m 0755 "${WORK}/stage/update.sh" "${PREFIX}/bin/.lagran-update.new" \
    && mv -f "${PREFIX}/bin/.lagran-update.new" "${PREFIX}/bin/lagran-update" \
    || fail "update helper failed"
fi
install -m 0644 "${WORK}/stage/LICENSE" "${PREFIX}/LICENSE" 2>/dev/null || true
install -m 0644 "${WORK}/stage/README.md" "${PREFIX}/README.md" 2>/dev/null || true

for service in lagran-control lagran-edge lagran-dns; do
  if systemctl is-enabled --quiet "${service}.service" 2>/dev/null; then
    systemctl restart "${service}.service" || fail "restart ${service} failed"
  fi
done
status "success" "${TAG}" "updated successfully"
rm -f "${REQUEST}"
