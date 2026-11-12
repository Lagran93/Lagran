#!/usr/bin/env bash
# updater-schema: 2
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
  status "failed" "${TAG:-}" "$1"
  rm -f "${REQUEST}"
  exit 1
}

warn() {
  printf 'warning: %s\n' "$*" >&2
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
  status "failed" "${TAG:-}" "updater failed at line ${line}" || true
  rm -f "${REQUEST}"
  exit "${rc}"
}
trap 'on_error $LINENO' ERR

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
safe_extract "${WORK}/${ASSET}" "${WORK}/stage" || fail "extract release failed"
STAGE_ROOT="${WORK}/stage"
# Older bundles may wrap everything in a top-level directory. Resolve the real
# stage root before looking for binaries.
if [[ ! -d "${STAGE_ROOT}/bin" && ! -f "${STAGE_ROOT}/lagran-control" ]]; then
  nested="$(find "${STAGE_ROOT}" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null || true)"
  if [[ -n "${nested}" && ( -d "${nested}/bin" || -f "${nested}/lagran-control" ) ]]; then
    STAGE_ROOT="${nested}"
  fi
fi
CONTROL_SRC="$(find "${STAGE_ROOT}" -maxdepth 3 -type f -name lagran-control -print -quit 2>/dev/null || true)"
if [[ -z "${CONTROL_SRC}" ]]; then
  entries="$(find "${STAGE_ROOT}" -maxdepth 2 -type f -printf '%P ' 2>/dev/null | cut -c1-400)"
  fail "release has no control binary${entries:+ (found: ${entries})}"
fi

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

status "running" "${TAG}" "installing binaries"
for bin in lagran-control lagran-edge lagran-dns; do
  src="$(find "${STAGE_ROOT}" -maxdepth 3 -type f -name "${bin}" -print -quit 2>/dev/null || true)"
  [[ -n "${src}" ]] || continue
  tmp="${PREFIX}/bin/.${bin}.new"
  install -m 0755 "${src}" "${tmp}" || fail "install ${bin} failed"
  mv -f "${tmp}" "${PREFIX}/bin/${bin}" || fail "replace ${bin} failed"
done
WEB_SRC="$(find "${STAGE_ROOT}" -maxdepth 3 -type d -name web -print -quit 2>/dev/null || true)"
if [[ -n "${WEB_SRC}" && -d "${PREFIX}/web" ]]; then
  status "running" "${TAG}" "updating web assets"
  cp -a "${WEB_SRC}/." "${PREFIX}/web/" || fail "update web failed"
  # `cp -a` preserves the archive's modes, and the release tarball is built with
  # a restrictive umask, so the SPA arrived as 0700/0600 owned by root. The
  # reverse proxy runs as its own user and cannot traverse or read that, and
  # `file_server` answers 403 rather than 404 — the console became unreachable
  # after an upgrade even though the control plane was healthy. `install.sh`
  # already normalises these; the update path did not.
  chmod -R a+rX "${PREFIX}/web" || fail "fix web permissions failed"
  # Verify from an unprivileged account, the way the reverse proxy sees it. A
  # root-side `test -r` succeeds regardless of the mode, so it would not have
  # caught the original 403. Skipped (not failed) when this process cannot drop
  # privileges: a missing probe must not abort an otherwise correct update.
  if command -v setpriv >/dev/null 2>&1 \
     && setpriv --reuid=65534 --regid=65534 --clear-groups true 2>/dev/null; then
    if ! setpriv --reuid=65534 --regid=65534 --clear-groups \
        test -r "${PREFIX}/web/index.html" 2>/dev/null; then
      fail "web assets are not readable by an unprivileged user (the proxy would answer 403); fix: chmod -R a+rX ${PREFIX}/web"
    fi
    if ! setpriv --reuid=65534 --regid=65534 --clear-groups \
        test -x "${PREFIX}/web" 2>/dev/null; then
      fail "web root ${PREFIX}/web is not traversable by an unprivileged user (the proxy would answer 403); fix: chmod a+x ${PREFIX}/web"
    fi
  else
    warn "cannot drop privileges to verify ${PREFIX}/web; skipping the readability check"
  fi
fi
HELPER_SRC="$(find "${STAGE_ROOT}" -maxdepth 3 -type f -name update.sh -print -quit 2>/dev/null || true)"
if [[ -n "${HELPER_SRC}" ]]; then
  if grep -q 'updater-schema: 2' "${HELPER_SRC}"; then
    status "running" "${TAG}" "installing update helper"
    install -m 0755 "${HELPER_SRC}" "${PREFIX}/bin/.lagran-update.new" \
      && mv -f "${PREFIX}/bin/.lagran-update.new" "${PREFIX}/bin/lagran-update" \
      || fail "update helper failed"
  else
    warn "release contains an older update helper; keeping the installed helper"
  fi
fi
LICENSE_SRC="$(find "${STAGE_ROOT}" -maxdepth 3 -type f -name LICENSE -print -quit 2>/dev/null || true)"
[[ -n "${LICENSE_SRC}" ]] && install -m 0644 "${LICENSE_SRC}" "${PREFIX}/LICENSE" 2>/dev/null || true
README_SRC="$(find "${STAGE_ROOT}" -maxdepth 3 -type f -name README.md -print -quit 2>/dev/null || true)"
[[ -n "${README_SRC}" ]] && install -m 0644 "${README_SRC}" "${PREFIX}/README.md" 2>/dev/null || true

for service in lagran-control lagran-edge lagran-dns; do
  if systemctl is-enabled --quiet "${service}.service" 2>/dev/null; then
    status "running" "${TAG}" "restarting ${service}"
    if ! timeout 90 systemctl restart "${service}.service"; then
      fail "restart ${service} failed or timed out"
    fi
    if ! timeout 30 systemctl is-active --quiet "${service}.service"; then
      fail "${service} is not active after restart"
    fi
  fi
done
status "success" "${TAG}" "updated successfully"
rm -f "${REQUEST}"
