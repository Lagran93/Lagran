#!/usr/bin/env bash
#
# 本地编译 Lagran 二进制或前端，上传到远程服务器并重启/重载对应服务。
#
# 用法：
#   ./deployed.sh <远程服务器> <lagran-control|lagran-edge|lagran-dns|lagran-web>
#
# 示例：
#   ./deployed.sh 203.0.113.10 lagran-control
#   ./deployed.sh 203.0.113.21 lagran-edge
#   ./deployed.sh 203.0.113.53 lagran-dns
#   ./deployed.sh 203.0.113.10 lagran-web
#
# 可选环境变量：
#   SSH_USER=root                  SSH 用户（host 未写 user@ 时使用）
#   SSH_PORT=22                    SSH 端口
#   SSH_KEY=~/.ssh/id_ed25519      SSH 私钥
#   REMOTE_BIN=/opt/lagran/bin     后端二进制安装目录
#   REMOTE_WEB=/opt/lagran/web     前端静态目录
#   WEB_USER=caddy                 Caddy 运行用户
#   WEB_GROUP=caddy                Caddy 运行组
#   REMOTE_SUDO=                   非 root 用户时设为 sudo
#   SERVICE=                       覆盖 systemd 服务名
#   TARGET=x86_64-unknown-linux-musl
#                                  交叉/静态编译目标；不设置则本机 release
#   USE_MUSL=1                     未设置 TARGET 时使用 musl 静态构建
#   PROFILE=release                编译 profile
#   SKIP_NPM_CI=1                  前端部署跳过 npm ci
#   NUXT_PUBLIC_API_BASE=...       前端构建时 API 地址（默认同源）
#   DRY_RUN=1                      只打印命令，不执行
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
用法: ./deployed.sh <远程服务器> <lagran-control|lagran-edge|lagran-dns|lagran-web>

示例:
  ./deployed.sh 203.0.113.10 lagran-control
  SSH_PORT=2027 ./deployed.sh root@203.0.113.21 lagran-edge
  USE_MUSL=1 ./deployed.sh 203.0.113.53 lagran-dns
  ./deployed.sh 203.0.113.10 lagran-web

环境变量:
  SSH_USER=root  SSH_PORT=22  SSH_KEY=...
  REMOTE_BIN=/opt/lagran/bin  REMOTE_WEB=/opt/lagran/web
  WEB_USER=caddy  WEB_GROUP=caddy
  REMOTE_SUDO=sudo  SERVICE=lagran-control
  TARGET=x86_64-unknown-linux-musl  USE_MUSL=1
  SKIP_NPM_CI=1  NUXT_PUBLIC_API_BASE=...  DRY_RUN=1
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -ne 2 ]]; then
  usage
  exit 0
fi

REMOTE_INPUT="$1"
BINARY="$2"

case "$BINARY" in
  lagran-control)
    KIND="binary"
    PACKAGE="control"
    DEFAULT_SERVICE="lagran-control"
    ;;
  lagran-edge)
    KIND="binary"
    PACKAGE="edge"
    DEFAULT_SERVICE="lagran-edge"
    ;;
  lagran-dns)
    KIND="binary"
    PACKAGE="lagran-dns"
    DEFAULT_SERVICE="lagran-dns"
    ;;
  lagran-web)
    KIND="web"
    PACKAGE=""
    DEFAULT_SERVICE="caddy"
    ;;
  *)
    echo "错误: 不支持的目标 '$BINARY'" >&2
    echo "只支持 lagran-control / lagran-edge / lagran-dns / lagran-web" >&2
    exit 2
    ;;
esac

SSH_USER="${SSH_USER:-root}"
SSH_PORT="${SSH_PORT:-22}"
SSH_KEY="${SSH_KEY:-}"
REMOTE_BIN="${REMOTE_BIN:-/opt/lagran/bin}"
REMOTE_WEB="${REMOTE_WEB:-/opt/lagran/web}"
WEB_USER="${WEB_USER:-caddy}"
WEB_GROUP="${WEB_GROUP:-caddy}"
REMOTE_SUDO="${REMOTE_SUDO:-}"
SERVICE="${SERVICE:-$DEFAULT_SERVICE}"
PROFILE="${PROFILE:-release}"
DRY_RUN="${DRY_RUN:-0}"

if [[ "$REMOTE_INPUT" == *"@"* ]]; then
  REMOTE="$REMOTE_INPUT"
else
  REMOTE="${SSH_USER}@${REMOTE_INPUT}"
fi

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -p "$SSH_PORT")
SCP_OPTS=(-P "$SSH_PORT")
SSH_CMD="ssh -p $SSH_PORT -o StrictHostKeyChecking=accept-new"
if [[ -n "$SSH_KEY" ]]; then
  SSH_OPTS+=(-i "$SSH_KEY")
  SCP_OPTS+=(-i "$SSH_KEY")
  SSH_CMD="$SSH_CMD -i $SSH_KEY"
fi

SUDO_PREFIX=""
if [[ -n "$REMOTE_SUDO" ]]; then
  SUDO_PREFIX="$REMOTE_SUDO "
fi

run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

remote_run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '+ ssh'
    printf ' %q' "${SSH_OPTS[@]}" "$REMOTE" "$1"
    printf '\n'
  else
    ssh "${SSH_OPTS[@]}" "$REMOTE" "$1"
  fi
}

# ---------------------------------------------------------------------------
# 前端部署
# ---------------------------------------------------------------------------
deploy_web() {
  local frontend="$ROOT/apps/frontend"
  local public_dir="$frontend/.output/public"
  local remote_tmp="/tmp/lagran-web.$$"
  local backup="${REMOTE_WEB}.bak"
  local remote_parent
  remote_parent="$(dirname "$REMOTE_WEB")"

  echo "==> 项目: $ROOT"
  echo "==> 目标: $BINARY -> $REMOTE:$REMOTE_WEB"
  echo "==> 服务: $SERVICE (reload)"

  if [[ ! -d "$frontend" ]]; then
    echo "错误: 找不到前端目录 $frontend" >&2
    exit 1
  fi

  if [[ "${SKIP_NPM_CI:-0}" != "1" ]]; then
    echo "==> npm ci"
    run npm --prefix "$frontend" ci
  else
    echo "==> 跳过 npm ci (SKIP_NPM_CI=1)"
  fi

  echo "==> npm run generate"
  if [[ -n "${NUXT_PUBLIC_API_BASE:-}" ]]; then
    run env NUXT_PUBLIC_API_BASE="$NUXT_PUBLIC_API_BASE" \
      npm --prefix "$frontend" run generate
  else
    run npm --prefix "$frontend" run generate
  fi

  if [[ ! -f "$public_dir/index.html" && "$DRY_RUN" != "1" ]]; then
    echo "错误: 前端构建产物不存在: $public_dir/index.html" >&2
    exit 1
  fi

  if [[ "$DRY_RUN" != "1" ]]; then
    echo "==> 产物: $public_dir"
  fi

  echo "==> 上传前端..."
  remote_run "mkdir -p '$remote_tmp'"
  run rsync -az --delete -e "$SSH_CMD" \
    "$public_dir/" "$REMOTE:$remote_tmp/"

  local remote_script
  remote_script=$(cat <<EOF
set -e
${SUDO_PREFIX}mkdir -p '$remote_parent'
if [ -d '$REMOTE_WEB' ]; then
  ${SUDO_PREFIX}rm -rf '$backup'
  ${SUDO_PREFIX}mv '$REMOTE_WEB' '$backup'
fi
${SUDO_PREFIX}mv '$remote_tmp' '$REMOTE_WEB'
${SUDO_PREFIX}chown -R '$WEB_USER:$WEB_GROUP' '$REMOTE_WEB'
${SUDO_PREFIX}chmod -R a+rX '$REMOTE_WEB'
if ! ${SUDO_PREFIX}systemctl reload '$SERVICE'; then
  echo 'caddy reload failed; rolling back' >&2
  if [ -d '$backup' ]; then
    ${SUDO_PREFIX}rm -rf '$REMOTE_WEB'
    ${SUDO_PREFIX}mv '$backup' '$REMOTE_WEB'
    ${SUDO_PREFIX}systemctl reload '$SERVICE' || true
  fi
  exit 1
fi
${SUDO_PREFIX}systemctl is-active --quiet '$SERVICE'
${SUDO_PREFIX}systemctl --no-pager --full status '$SERVICE' | head -20
EOF
)

  echo "==> 安装并 reload $SERVICE ..."
  remote_run "$remote_script"

  echo "==> 完成: $BINARY"
  echo "    备份: $backup"
  echo "    状态: ssh ${SSH_OPTS[*]} $REMOTE 'systemctl status $SERVICE'"
}

# ---------------------------------------------------------------------------
# 后端二进制部署
# ---------------------------------------------------------------------------
deploy_binary() {
  local target="${TARGET:-}"
  local bin remote_tmp backup remote_new remote_rollback
  if [[ -z "$target" && "${USE_MUSL:-0}" == "1" ]]; then
    target="x86_64-unknown-linux-musl"
  fi

  if [[ -n "$target" ]]; then
    bin="$ROOT/target/$target/$PROFILE/$BINARY"
  else
    bin="$ROOT/target/$PROFILE/$BINARY"
  fi

  remote_tmp="/tmp/${BINARY}.$$"
  backup="${REMOTE_BIN}/${BINARY}.bak"
  remote_new="${REMOTE_BIN}/.${BINARY}.new.$$"
  remote_rollback="${REMOTE_BIN}/.${BINARY}.rollback.$$"

  echo "==> 项目: $ROOT"
  echo "==> 目标: $BINARY ($PACKAGE) -> $REMOTE:$REMOTE_BIN"
  echo "==> 服务: $SERVICE"

  local build_args=(build --profile "$PROFILE" -p "$PACKAGE" --bin "$BINARY")
  if [[ -n "$target" ]]; then
    build_args+=(--target "$target")
  fi

  echo "==> 编译: cargo ${build_args[*]}"
  run cargo "${build_args[@]}"

  if [[ ! -f "$bin" && "$DRY_RUN" != "1" ]]; then
    echo "错误: 找不到编译产物 $bin" >&2
    exit 1
  fi

  if [[ "$DRY_RUN" != "1" ]]; then
    echo "==> 产物: $bin ($(du -h "$bin" | cut -f1))"
  fi

  echo "==> 上传..."
  run scp "${SCP_OPTS[@]}" "$bin" "$REMOTE:$remote_tmp"

  local remote_script
  remote_script=$(cat <<EOF
set -e
${SUDO_PREFIX}mkdir -p '$REMOTE_BIN'
if [ -f '$REMOTE_BIN/$BINARY' ]; then
  ${SUDO_PREFIX}cp -p '$REMOTE_BIN/$BINARY' '$backup'
fi
${SUDO_PREFIX}install -m 755 '$remote_tmp' '$remote_new'
${SUDO_PREFIX}mv -f '$remote_new' '$REMOTE_BIN/$BINARY'
rm -f '$remote_tmp'
if ! ${SUDO_PREFIX}systemctl restart '$SERVICE'; then
  echo 'service restart failed; rolling back' >&2
  if [ -f '$backup' ]; then
    ${SUDO_PREFIX}install -m 755 '$backup' '$remote_rollback'
    ${SUDO_PREFIX}mv -f '$remote_rollback' '$REMOTE_BIN/$BINARY'
    ${SUDO_PREFIX}systemctl restart '$SERVICE' || true
  fi
  exit 1
fi
sleep 1
if ! ${SUDO_PREFIX}systemctl is-active --quiet '$SERVICE'; then
  echo 'service is not active; rolling back' >&2
  if [ -f '$backup' ]; then
    ${SUDO_PREFIX}install -m 755 '$backup' '$remote_rollback'
    ${SUDO_PREFIX}mv -f '$remote_rollback' '$REMOTE_BIN/$BINARY'
    ${SUDO_PREFIX}systemctl restart '$SERVICE' || true
  fi
  exit 1
fi
${SUDO_PREFIX}systemctl --no-pager --full status '$SERVICE' | head -20
EOF
)

  echo "==> 安装并重启 $SERVICE ..."
  remote_run "$remote_script"

  echo "==> 完成: $BINARY"
  echo "    备份: $backup"
  echo "    状态: ssh ${SSH_OPTS[*]} $REMOTE 'systemctl status $SERVICE'"
}

if [[ "$KIND" == "web" ]]; then
  deploy_web
else
  deploy_binary
fi
