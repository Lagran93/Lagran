#!/usr/bin/env bash
# Root-only edge updater. Triggered by lagran-edge-update.path when the edge
# control endpoint writes a release tag to edge-update.request.
set -Eeuo pipefail
umask 077

PREFIX="${LAGRAN_PREFIX:-/opt/lagran}"
DATA_DIR="${LAGRAN_DATA_DIR:-/var/lib/lagran}"
REPO="${LAGRAN_UPDATE_REPO:-Lagran93/Lagran}"
REQUEST="${EDGE_UPDATE_REQUEST_PATH:-${DATA_DIR}/edge-update.request}"
STATUS="${EDGE_UPDATE_STATUS_PATH:-${DATA_DIR}/edge-update.status}"
WORK=""
TAG=""

if [[ -f /etc/lagran/edge-update.env ]]; then
  # shellcheck disable=SC1091
  source /etc/lagran/edge-update.env
fi
PREFIX="${LAGRAN_PREFIX:-$PREFIX}"
DATA_DIR="${LAGRAN_DATA_DIR:-$DATA_DIR}"
REPO="${LAGRAN_UPDATE_REPO:-$REPO}"
REQUEST="${EDGE_UPDATE_REQUEST_PATH:-$REQUEST}"
STATUS="${EDGE_UPDATE_STATUS_PATH:-$STATUS}"

cleanup() {
  [[ -n "${WORK:-}" ]] && rm -rf "${WORK}"
}
trap cleanup EXIT

status() {
  local state="$1" message="${2:-}"
  mkdir -p "$(dirname "${STATUS}")"
  printf '%s|%s|%s|%s\n' "${state}" "${TAG:-}" "${message}" "$(date -u +%FT%TZ)" \
    > "${STATUS}.tmp.$$"
  mv -f "${STATUS}.tmp.$$" "${STATUS}"
  chmod 0644 "${STATUS}" 2>/dev/null || true
}

# Extract a release tarball, rejecting entries that would escape the target.
#
# `tar -xzf` honours absolute paths and `../` components, so a tampered archive
# can overwrite arbitrary files as root even when its checksum matches (a bundle
# built by a compromised CI runner sums correctly too). Only plain relative paths
# are accepted, and any link member is refused: a release bundle needs neither.
safe_extract() {
  local archive="$1" dest="$2" names verbose line found_link=0
  names="$(tar -tzf "${archive}" 2>/dev/null)" || { die "cannot list archive ${archive}"; return 1; }
  case "${names}" in
    /*) die "archive contains an absolute path; refusing to extract ${archive}"; return 1 ;;
  esac
  if grep -qE '(^|/)[.][.](/|$)' <<< "${names}"; then
    die "archive contains an entry that escapes its destination"
    return 1
  fi
  verbose="$(tar -tvzf "${archive}" 2>/dev/null)" || { die "cannot inspect archive ${archive}"; return 1; }
  # The first character of each verbose line is the member type: `-` file,
  # `d` directory, `l` symlink, `h` hardlink. Reject the link kinds. `die` only
  # exits the process in production, but return explicitly so the extract below
  # can never run after a rejection.
  while IFS= read -r line; do
    case "${line}" in
      l*|h*) found_link=1; break ;;
    esac
  done <<< "${verbose}"
  if [[ "${found_link}" -eq 1 ]]; then
    die "archive contains link entries; refusing to extract ${archive}"
    return 1
  fi
  tar --no-same-owner --no-same-permissions -xzf "${archive}" -C "${dest}"
}

fail() {
  status "failed" "$1"
  rm -f "${REQUEST}"
  exit 1
}

[[ -f "${REQUEST}" ]] || exit 0
TAG="$(head -n 1 "${REQUEST}" | tr -d '[:space:]')"
[[ "${TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+.][A-Za-z0-9._+-]+)?$ ]] || fail "invalid release tag"
[[ "$(uname -m)" == "x86_64" || "$(uname -m)" == "amd64" ]] || fail "only amd64 releases are published"

REPORTED=0
on_error() {
  local rc=$? line=${1:-?}
  [[ "${REPORTED}" == "1" ]] && exit "${rc}"
  REPORTED=1
  status "failed" "updater failed at line ${line}"
  rm -f "${REQUEST}"
  exit "${rc}"
}
trap 'on_error $LINENO' ERR

VERSION="${TAG#v}"
ASSET="lagran-cdn-${VERSION}-linux-amd64.tar.gz"
BASE="${LAGRAN_UPDATE_BASE:-https://github.com/${REPO}/releases/download/${TAG}}"
WORK="$(mktemp -d "${DATA_DIR}/edge-update.XXXXXX")"
status "running" "downloading ${ASSET}"

curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 "${BASE}/${ASSET}" \
  -o "${WORK}/${ASSET}" || fail "download release failed"
curl -fsSL --retry 3 --connect-timeout 15 "${BASE}/SHA256SUMS" \
  -o "${WORK}/SHA256SUMS" || fail "download SHA256SUMS failed"
(
  cd "${WORK}"
  grep -F "  ${ASSET}" SHA256SUMS | sha256sum -c - >/dev/null
) || fail "checksum verification failed"

mkdir -p "${WORK}/stage"
safe_extract "${WORK}/${ASSET}" "${WORK}/stage" || fail "extract release failed"
STAGE_ROOT="${WORK}/stage"
if [[ ! -d "${STAGE_ROOT}/bin" && ! -f "${STAGE_ROOT}/lagran-edge" ]]; then
  nested="$(find "${STAGE_ROOT}" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null || true)"
  if [[ -n "${nested}" && ( -d "${nested}/bin" || -f "${nested}/lagran-edge" ) ]]; then
    STAGE_ROOT="${nested}"
  fi
fi
EDGE_SRC="$(find "${STAGE_ROOT}" -maxdepth 3 -type f -name lagran-edge -print -quit 2>/dev/null || true)"
[[ -n "${EDGE_SRC}" ]] || fail "release has no edge binary"

BACKUP="${DATA_DIR}/edge-update-backup/${TAG}-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${BACKUP}/bin"
if [[ -f "${PREFIX}/bin/lagran-edge" ]]; then
  cp -a "${PREFIX}/bin/lagran-edge" "${BACKUP}/bin/"
fi
status "running" "backup saved to ${BACKUP}"

tmp="${PREFIX}/bin/.lagran-edge.new"
install -m 0755 "${EDGE_SRC}" "${tmp}" || fail "install lagran-edge failed"
mv -f "${tmp}" "${PREFIX}/bin/lagran-edge" || fail "replace lagran-edge failed"
status "running" "restarting lagran-edge"
if ! timeout 90 systemctl restart lagran-edge.service; then
  fail "restart lagran-edge failed or timed out"
fi
if ! timeout 30 systemctl is-active --quiet lagran-edge.service; then
  fail "lagran-edge is not active after restart"
fi
status "success" "updated to ${TAG}"
rm -f "${REQUEST}"
