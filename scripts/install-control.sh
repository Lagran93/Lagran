#!/usr/bin/env bash
#
# Lagran CDN 控制面（lagran-control）交互式安装脚本。
#
# 交互约定：
#   * 逐项询问：版本、监听与对外访问、PostgreSQL、Redis、密钥、账号、
#     GeoDNS 与调度、服务与收尾；每项都有默认值，直接回车即采用；
#   * 安装位置与 ACME/运行参数不提问，固定用默认值；
#   * 密钥类参数（JWT / Agent / WAF）自动生成随机值；
#   * 已存在的 control.env 默认保留，避免误覆盖生产配置；
#   * 写入系统前先汇总全部生效参数并确认一次；
#   * 写入后用 `lagran-control check-config` 校验，再启动并做健康检查。
#
# 二进制来源：
#   始终从 GitHub Release 下载（默认最新版本），校验 SHA256SUMS 后安装；
#   用 --version 指定版本，用 --binary 在离线环境直接使用本地文件。
#
# 常用用法：
#   sudo scripts/install-control.sh                          # 安装最新版本
#   sudo scripts/install-control.sh --version v0.1.13-rc     # 安装指定版本
#   sudo scripts/install-control.sh -y --database-url 'postgres://u:p@127.0.0.1:5432/lagran'
#   sudo scripts/install-control.sh --binary /tmp/lagran-control   # 离线安装
#   scripts/install-control.sh --dry-run                     # 非 root 也可预览
#
set -Eeuo pipefail

# 脚本不读取本地工作区：lagran-control 与 update.sh 都来自下载并校验过的 Release 包，
# 离线安装时才用 --binary / --update-helper 显式指定本地文件。

# =============================================================================
# 默认值
# =============================================================================

SERVICE="lagran-control"
SERVICE_USER="${LAGRAN_CONTROL_USER:-lagran-control}"
SERVICE_GROUP="${LAGRAN_CONTROL_GROUP:-lagran}"

PREFIX="${LAGRAN_PREFIX:-/opt/lagran}"
BIN_DIR="${LAGRAN_BIN_DIR:-}"
CONF_DIR="${LAGRAN_CONF_DIR:-/etc/lagran}"
DATA_DIR="${LAGRAN_DATA_DIR:-/var/lib/lagran}"
LOG_DIR="${LAGRAN_LOG_DIR:-/var/log/lagran}"
UNIT_DIR="${LAGRAN_UNIT_DIR:-/etc/systemd/system}"

REPO="${LAGRAN_REPO:-Lagran93/Lagran}"
VERSION="${LAGRAN_VERSION:-latest}"
RESOLVED_TAG=""
RELEASE_STAGE=""
RELEASE_BINARY=""
BINARY_SRC="${LAGRAN_BINARY:-}"
UPDATE_HELPER_SRC="${LAGRAN_UPDATE_HELPER_SRC:-}"

INTERACTIVE_MODE="auto"   # auto | yes | no
DRY_RUN=0
FORCE_RECONF=0
KEEP_CONFIG=0
START_NOW="true"
SYSTEMD_MANAGE=1
INSTALL_UPDATER="auto"
SKIP_DB_CHECK=0
COLOR_MODE="auto"

# 写入 control.env 的取值；环境变量可预置（见 --help）。
CONTROL_BIND="${CONTROL_BIND:-}"
CONTROL_PUBLIC_URL="${CONTROL_PUBLIC_URL:-}"
TRUSTED_PROXIES="${TRUSTED_PROXIES:-}"
DATABASE_URL="${LAGRAN_DATABASE_URL:-${DATABASE_URL:-}}"
REDIS_URL="${REDIS_URL:-}"
JWT_SECRET="${JWT_SECRET:-}"
AGENT_TOKEN="${AGENT_TOKEN:-}"
WAF_RULEPACK_SECRET="${WAF_RULEPACK_SECRET:-}"
REQUIRE_SECURE_SECRETS="${REQUIRE_SECURE_SECRETS:-}"
ALLOW_REGISTER="${ALLOW_REGISTER:-}"
CAPTCHA_ENABLED="${CAPTCHA_ENABLED:-}"
SEED_DEMO="${SEED_DEMO:-}"
GEOIP_PATH="${GEOIP_PATH:-}"
GEOIP_IPV6_PATH="${GEOIP_IPV6_PATH:-}"
ACME_CONTACT_EMAIL="${ACME_CONTACT_EMAIL:-}"
RUST_LOG="${RUST_LOG:-}"
CORS_ALLOWED_ORIGINS="${CORS_ALLOWED_ORIGINS:-}"

# 其余参数在向导里赋默认值（此处先置空以满足 set -u）。
DATABASE_MAX_CONNECTIONS="${DATABASE_MAX_CONNECTIONS:-}"
DATABASE_MIN_CONNECTIONS="${DATABASE_MIN_CONNECTIONS:-}"
DATABASE_ACQUIRE_TIMEOUT_SECS="${DATABASE_ACQUIRE_TIMEOUT_SECS:-}"
REDIS_SESSION_TTL_SECS="${REDIS_SESSION_TTL_SECS:-}"
CONFIG_CACHE_TTL_SECS="${CONFIG_CACHE_TTL_SECS:-}"
JWT_EXPIRE_HOURS="${JWT_EXPIRE_HOURS:-}"
METRICS_TOKEN="${METRICS_TOKEN:-}"
AGENT_TLS_CA_FILE="${AGENT_TLS_CA_FILE:-}"
EDGE_CNAME="${EDGE_CNAME:-}"
SCHEDULE_TTL="${SCHEDULE_TTL:-}"
SCHEDULE_NODE_CACHE_SECS="${SCHEDULE_NODE_CACHE_SECS:-}"
DNS_TEST_SERVER="${DNS_TEST_SERVER:-}"
ACME_DIRECTORY_URL="${ACME_DIRECTORY_URL:-}"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-}"
ALERT_EVAL_SECS="${ALERT_EVAL_SECS:-}"
OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-}"
DB_MODE=""
DB_HOST="${LAGRAN_DB_HOST:-}"
DB_PORT="${LAGRAN_DB_PORT:-}"
DB_NAME="${LAGRAN_DB_NAME:-}"
DB_USER="${LAGRAN_DB_USER:-}"
DB_PASSWORD="${LAGRAN_DB_PASSWORD:-}"

# 运行时状态
READ_FD=0
HAVE_SYSTEMD=0
SERVICE_STARTED=0
TMP_DIRS=()

# =============================================================================
# 输出与错误处理
# =============================================================================

C_RESET=""
C_BOLD=""
C_DIM=""
C_RED=""
C_GREEN=""
C_YELLOW=""
C_CYAN=""

setup_colors() {
  local enabled=0
  case "$COLOR_MODE" in
    yes) enabled=1 ;;
    no) enabled=0 ;;
    *) [[ -t 1 && -z "${NO_COLOR:-}" ]] && enabled=1 ;;
  esac
  if [[ "$enabled" -eq 1 ]]; then
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'
    C_YELLOW=$'\033[33m'
    C_CYAN=$'\033[36m'
  fi
}

ok() { printf '%s  ok%s  %s\n' "$C_GREEN" "$C_RESET" "$*"; }
note() { printf '      %s\n' "$*"; }
step() { printf '\n%s==>%s %s\n' "$C_CYAN$C_BOLD" "$C_RESET" "$*"; }
warn() { printf '%s警告:%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die() { printf '%s错误:%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

section() {
  printf '\n%s--------------------------------------------------------------------%s\n' "$C_DIM" "$C_RESET"
  printf '%s[%s]%s %s%s%s\n' "$C_BOLD" "$1" "$C_RESET" "$C_BOLD" "$2" "$C_RESET"
}

have() { command -v "$1" >/dev/null 2>&1; }

cleanup_tmp() {
  local dir
  for dir in "${TMP_DIRS[@]:-}"; do
    if [[ -n "$dir" ]]; then
      rm -rf "$dir"
    fi
  done
  return 0
}
trap cleanup_tmp EXIT
trap 'printf "\n%s错误:%s 安装在第 %s 行中止（退出码 %s）\n" "$C_RED" "$C_RESET" "$LINENO" "$?" >&2' ERR
trap 'printf "\n已取消。\n" >&2; exit 130' INT

# 打印并执行（dry-run 时只打印）。仅用于修改系统状态的命令。
run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '      [dry-run] %s\n' "$*"
    return 0
  fi
  "$@"
}

usage() {
  cat <<'EOF'
用法: scripts/install-control.sh [选项]

交互模式：
  逐项询问：版本、监听与对外访问、PostgreSQL、Redis、密钥、账号、GeoDNS、
  服务与收尾；每项都给出默认值，直接回车即采用。
  安装位置与 ACME/运行参数使用默认值；密钥自动生成；其余项可用环境变量预置。
  最后汇总全部生效参数，确认一次后写入。

选项:
  -y, --yes, --non-interactive   不提问，全部使用默认值（适合自动化）
  -i, --interactive              强制交互（标准输入为管道时也逐项提问）
      --version <tag|latest>     安装的 Release 版本（默认 latest = 最新版本）
      --repo <owner/repo>        GitHub 仓库（默认 Lagran93/Lagran）
      --binary <路径>            离线安装：直接使用本地二进制（默认从 Release 下载）
      --update-helper <路径>     指定 update.sh 源文件（默认取自 GitHub Release 包）
      --prefix <目录>            安装前缀（默认 /opt/lagran）
      --bin-dir <目录>           二进制目录（默认 <prefix>/bin）
      --conf-dir <目录>          配置目录（默认 /etc/lagran）
      --data-dir <目录>          数据目录（默认 /var/lib/lagran）
      --log-dir <目录>           日志目录（默认 /var/log/lagran）
      --unit-dir <目录>          systemd 单元目录（默认 /etc/systemd/system）
      --database-url <url>       使用已有 PostgreSQL 连接串（跳过本机建库）
      --user <用户>              服务运行用户（默认 lagran-control）
      --group <组>               服务运行组（默认 lagran）
      --no-start                 写入并启用单元，但不立即启动服务
      --no-systemd               不调用 systemctl（容器/chroot 内只写单元文件）
      --no-updater               不安装控制台“系统升级”助手 lagran-update
      --skip-db-check            跳过数据库连通性检查
      --force, --reconfigure     备份并按向导重写已有 control.env
      --keep-config              保留已有 control.env，只更新二进制与单元
      --dry-run                  只打印将要写入的文件和执行的命令
      --no-color                 关闭彩色输出
  -h, --help

可预置的环境变量:
  LAGRAN_PREFIX / LAGRAN_BIN_DIR / LAGRAN_CONF_DIR / LAGRAN_DATA_DIR
  LAGRAN_LOG_DIR / LAGRAN_UNIT_DIR
  LAGRAN_REPO / LAGRAN_VERSION（默认 latest）/ LAGRAN_BINARY
  LAGRAN_UPDATE_HELPER_SRC
  LAGRAN_CONTROL_USER / LAGRAN_CONTROL_GROUP
  LAGRAN_DATABASE_URL
  LAGRAN_DB_HOST / LAGRAN_DB_PORT / LAGRAN_DB_NAME / LAGRAN_DB_USER / LAGRAN_DB_PASSWORD
  LAGRAN_CONTROL_BIND / LAGRAN_CONTROL_PUBLIC_URL
  DATABASE_URL / CONTROL_BIND / CONTROL_PUBLIC_URL / TRUSTED_PROXIES
  JWT_SECRET / AGENT_TOKEN / WAF_RULEPACK_SECRET / REDIS_URL
  ALLOW_REGISTER / CAPTCHA_ENABLED / SEED_DEMO / REQUIRE_SECURE_SECRETS
  GEOIP_PATH / GEOIP_IPV6_PATH / RUST_LOG / ACME_CONTACT_EMAIL

安装结果:
  <prefix>/bin/lagran-control        二进制（来自 GitHub Release，默认最新版本）
  <conf-dir>/control.env             运行时配置（0640 root:lagran-control）
  <unit-dir>/lagran-control.service  systemd 单元
  <data-dir>                         缓存、证书、更新请求
EOF
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -y|--yes|--non-interactive) INTERACTIVE_MODE="no"; shift ;;
      -i|--interactive) INTERACTIVE_MODE="yes"; shift ;;
      --binary) BINARY_SRC="${2:-}"; shift 2 ;;
      --binary=*) BINARY_SRC="${1#*=}"; shift ;;
      --update-helper) UPDATE_HELPER_SRC="${2:-}"; shift 2 ;;
      --update-helper=*) UPDATE_HELPER_SRC="${1#*=}"; shift ;;
      --version)
        if [[ -z "${2:-}" ]]; then
          printf '错误: --version 需要版本号（latest 或 v1.2.3）\n\n' >&2
          usage >&2
          exit 2
        fi
        VERSION="$2"
        shift 2
        ;;
      --version=*) VERSION="${1#*=}"; shift ;;
      --repo)
        if [[ -z "${2:-}" ]]; then
          printf '错误: --repo 需要 owner/repo\n\n' >&2
          usage >&2
          exit 2
        fi
        REPO="$2"
        shift 2
        ;;
      --repo=*) REPO="${1#*=}"; shift ;;
      --prefix) PREFIX="${2:-}"; shift 2 ;;
      --prefix=*) PREFIX="${1#*=}"; shift ;;
      --bin-dir) BIN_DIR="${2:-}"; shift 2 ;;
      --bin-dir=*) BIN_DIR="${1#*=}"; shift ;;
      --conf-dir) CONF_DIR="${2:-}"; shift 2 ;;
      --conf-dir=*) CONF_DIR="${1#*=}"; shift ;;
      --data-dir) DATA_DIR="${2:-}"; shift 2 ;;
      --data-dir=*) DATA_DIR="${1#*=}"; shift ;;
      --log-dir) LOG_DIR="${2:-}"; shift 2 ;;
      --log-dir=*) LOG_DIR="${1#*=}"; shift ;;
      --unit-dir) UNIT_DIR="${2:-}"; shift 2 ;;
      --unit-dir=*) UNIT_DIR="${1#*=}"; shift ;;
      --database-url) DATABASE_URL="${2:-}"; shift 2 ;;
      --database-url=*) DATABASE_URL="${1#*=}"; shift ;;
      --user) SERVICE_USER="${2:-}"; shift 2 ;;
      --user=*) SERVICE_USER="${1#*=}"; shift ;;
      --group) SERVICE_GROUP="${2:-}"; shift 2 ;;
      --group=*) SERVICE_GROUP="${1#*=}"; shift ;;
      --no-start) START_NOW="false"; shift ;;
      --no-systemd) SYSTEMD_MANAGE=0; shift ;;
      --no-updater) INSTALL_UPDATER="false"; shift ;;
      --skip-db-check) SKIP_DB_CHECK=1; shift ;;
      --force|--reconfigure) FORCE_RECONF=1; shift ;;
      --keep-config) KEEP_CONFIG=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --no-color) COLOR_MODE="no"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) printf '错误: 未知选项 %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
  done
  if [[ -z "$BIN_DIR" ]]; then
    BIN_DIR="$PREFIX/bin"
  fi
}

# =============================================================================
# 交互读取
# =============================================================================

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

resolve_interactive() {
  READ_FD=0
  case "$INTERACTIVE_MODE" in
    yes)
      # 显式交互：始终从标准输入读（便于 `printf ... | script -i` 预演）。
      READ_FD=0
      ;;
    no)
      ;;
    auto)
      if [[ -t 0 ]]; then
        READ_FD=0
      elif exec 9</dev/tty 2>/dev/null; then
        # curl | bash 场景：脚本占用标准输入，答案从控制终端读。
        READ_FD=9
      else
        INTERACTIVE_MODE="no"
      fi
      ;;
  esac
}

is_interactive() { [[ "$INTERACTIVE_MODE" != "no" ]]; }

# 读取一行到全局 REPLY；EOF 时降级为非交互（后续问题用默认值），避免死循环。
read_line() {
  local line=""
  if ! IFS= read -r -u "$READ_FD" line; then
    # 最后一行没有换行符时 read 也返回非 0，但内容仍然有效。
    if [[ -n "$line" ]]; then
      REPLY="$(trim "$line")"
      return 0
    fi
    printf '\n'
    warn "标准输入已结束，后续问题改用默认值"
    INTERACTIVE_MODE="no"
    REPLY=""
    return 1
  fi
  REPLY="$(trim "$line")"
  return 0
}

# ask <变量> <问题> <默认值> [校验函数]
ask() {
  local var="$1" question="$2" default="${3:-}" validator="${4:-}" line=""
  if ! is_interactive; then
    printf -v "$var" '%s' "$default"
    return 0
  fi
  while :; do
    if [[ -n "$default" ]]; then
      printf '%s [%s]: ' "$question" "$default"
    else
      printf '%s（留空表示不设置）: ' "$question"
    fi
    if ! read_line; then
      printf -v "$var" '%s' "$default"
      return 0
    fi
    line="$REPLY"
    [[ -z "$line" ]] && line="$default"
    if [[ -n "$validator" ]] && ! "$validator" "$line"; then
      printf '  ! 输入无效，请重新输入\n'
      continue
    fi
    printf -v "$var" '%s' "$line"
    return 0
  done
}

# ask_secret <变量> <问题> <候选值>：回车采用候选值，否则静默输入自定义值。
ask_secret() {
  local var="$1" question="$2" candidate="$3" line="" len=0
  if ! is_interactive; then
    printf -v "$var" '%s' "$candidate"
    return 0
  fi
  while :; do
    printf '%s\n' "$question"
    printf '  候选值: %s\n' "$candidate"
    printf '  回车采用候选值，或粘贴自定义值（输入不回显）: '
    if ! read_line; then
      printf -v "$var" '%s' "$candidate"
      return 0
    fi
    line="$REPLY"
    [[ -z "$line" ]] && line="$candidate"
    if ! valid_secret_value "$line"; then
      continue
    fi
    len=${#line}
    if [[ "$len" -lt 16 ]]; then
      printf '  ! 至少需要 16 个字符（当前 %d），请重新输入\n' "$len"
      continue
    fi
    printf -v "$var" '%s' "$line"
    return 0
  done
}

# ask_bool <变量> <问题> <true|false>
ask_bool() {
  local var="$1" question="$2" default="${3:-true}" hint="Y/n" line=""
  [[ "$default" == "false" ]] && hint="y/N"
  if ! is_interactive; then
    printf -v "$var" '%s' "$default"
    return 0
  fi
  while :; do
    printf '%s [%s]: ' "$question" "$hint"
    if ! read_line; then
      printf -v "$var" '%s' "$default"
      return 0
    fi
    line="$REPLY"
    [[ -z "$line" ]] && line="$default"
    case "${line,,}" in
      y|yes|true|1|on) printf -v "$var" 'true'; return 0 ;;
      n|no|false|0|off) printf -v "$var" 'false'; return 0 ;;
    esac
    printf '  ! 请输入 y 或 n\n'
  done
}

# ask_int <变量> <问题> <默认值> <最小值> <最大值>
ask_int() {
  local var="$1" question="$2" default="$3" min="$4" max="$5" line=""
  if ! is_interactive; then
    printf -v "$var" '%s' "$default"
    return 0
  fi
  while :; do
    printf '%s（%s-%s）[%s]: ' "$question" "$min" "$max" "$default"
    if ! read_line; then
      printf -v "$var" '%s' "$default"
      return 0
    fi
    line="$REPLY"
    [[ -z "$line" ]] && line="$default"
    if [[ "$line" =~ ^[0-9]+$ ]] && (( 10#$line >= min && 10#$line <= max )); then
      printf -v "$var" '%s' "$((10#$line))"
      return 0
    fi
    printf '  ! 请输入 %s 到 %s 之间的整数\n' "$min" "$max"
  done
}

# ask_choice <变量> <问题> <默认键> <"键|说明" ...>
ask_choice() {
  local var="$1" question="$2" default="$3"; shift 3
  local -a entries=("$@") keys=() labels=()
  local i line
  for i in "${!entries[@]}"; do
    keys+=("${entries[$i]%%|*}")
    labels+=("${entries[$i]#*|}")
  done
  if ! is_interactive; then
    printf -v "$var" '%s' "$default"
    return 0
  fi
  while :; do
    printf '\n%s\n' "$question"
    for i in "${!entries[@]}"; do
      if [[ "${keys[$i]}" == "$default" ]]; then
        printf '  * %d) %s\n' "$((i + 1))" "${labels[$i]}"
      else
        printf '    %d) %s\n' "$((i + 1))" "${labels[$i]}"
      fi
    done
    printf '  选择 [%s]: ' "$default"
    if ! read_line; then
      printf -v "$var" '%s' "$default"
      return 0
    fi
    line="$REPLY"
    if [[ -z "$line" ]]; then
      printf -v "$var" '%s' "$default"
      return 0
    fi
    if [[ "$line" =~ ^[0-9]+$ ]]; then
      i=$((10#$line - 1))
      if (( i >= 0 && i < ${#keys[@]} )); then
        printf -v "$var" '%s' "${keys[$i]}"
        return 0
      fi
    fi
    for i in "${!keys[@]}"; do
      if [[ "${keys[$i]}" == "$line" ]]; then
        printf -v "$var" '%s' "$line"
        return 0
      fi
    done
    printf '  ! 无效选择，请输入序号或选项名\n'
  done
}

# confirm <问题> <yes|no>：非交互时直接返回默认值。
confirm() {
  local answer="true"
  if [[ "${2:-yes}" == "no" ]]; then
    answer="false"
  fi
  ask_bool answer "$1" "$answer"
  [[ "$answer" == "true" ]]
}

# =============================================================================
# 校验函数（打印原因并返回非 0 表示无效）
# =============================================================================

valid_secret_value() {
  local value="$1"
  if [[ -z "$value" ]]; then
    printf '  ! 不能为空\n'
    return 1
  fi
  if [[ "$value" =~ [[:space:]] ]]; then
    printf '  ! 不能包含空白字符\n'
    return 1
  fi
  if [[ "$value" == *"#"* ]]; then
    printf '  ! 不能包含 #（EnvironmentFile 会截断）\n'
    return 1
  fi
  return 0
}

valid_dir_path() {
  local path="$1"
  if [[ -z "$path" ]]; then
    printf '  ! 路径不能为空\n'
    return 1
  fi
  if [[ "$path" != /* ]]; then
    printf '  ! 必须使用绝对路径\n'
    return 1
  fi
  if [[ "$path" =~ [[:space:]] ]]; then
    printf '  ! 路径不能包含空白字符\n'
    return 1
  fi
  if [[ "/${path}/" == */../* ]]; then
    printf '  ! 路径不能包含 ..\n'
    return 1
  fi
  return 0
}

valid_optional_path() {
  local path="$1"
  [[ -z "$path" ]] && return 0
  valid_dir_path "$path"
}

valid_existing_file() {
  local path="$1"
  [[ -z "$path" ]] && return 0
  valid_dir_path "$path" || return 1
  if [[ ! -f "$path" ]]; then
    printf '  ! 文件不存在：%s\n' "$path"
    return 1
  fi
  return 0
}

valid_bind() {
  local value="$1" host port
  if [[ -z "$value" ]]; then
    printf '  ! 不能为空\n'
    return 1
  fi
  if [[ "$value" != *:* ]]; then
    printf '  ! 需要 host:port 形式\n'
    return 1
  fi
  host="${value%:*}"
  port="${value##*:}"
  if [[ -z "$host" ]]; then
    printf '  ! 缺少主机部分\n'
    return 1
  fi
  if [[ "$host" =~ [[:space:]] ]]; then
    printf '  ! 主机不能包含空白字符\n'
    return 1
  fi
  if ! [[ "$port" =~ ^[0-9]+$ ]] || (( 10#$port < 1 || 10#$port > 65535 )); then
    printf '  ! 端口必须是 1-65535\n'
    return 1
  fi
  return 0
}

valid_http_url() {
  local value="$1"
  if [[ ! "$value" =~ ^https?://[^[:space:]]+$ ]]; then
    printf '  ! 需要以 http:// 或 https:// 开头且不含空格\n'
    return 1
  fi
  return 0
}

valid_http_url_or_empty() {
  local value="$1"
  [[ -z "$value" ]] && return 0
  valid_http_url "$value"
}

valid_pg_url() {
  local value="$1"
  if [[ ! "$value" =~ ^postgres(ql)?://[^[:space:]]+$ ]]; then
    printf '  ! 需要 postgres:// 或 postgresql:// 开头的连接串\n'
    return 1
  fi
  return 0
}

valid_redis_url() {
  local value="$1"
  if [[ ! "$value" =~ ^rediss?://[^[:space:]]+$ ]]; then
    printf '  ! 需要 redis:// 或 rediss:// 开头的连接串\n'
    return 1
  fi
  return 0
}

valid_db_ident() {
  local value="$1"
  if [[ ! "$value" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    printf '  ! 只能使用字母、数字和下划线，且不能以数字开头\n'
    return 1
  fi
  return 0
}

valid_username() {
  local value="$1"
  if [[ ! "$value" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
    printf '  ! 只能使用小写字母、数字、下划线和短横线\n'
    return 1
  fi
  return 0
}

valid_repo() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]
}

valid_release_tag() {
  local value="$1"
  [[ "$value" == "latest" ]] && return 0
  [[ "$value" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-.+][A-Za-z0-9._+-]+)?$ ]]
}

# 交互输入用：校验失败时打印原因，ask() 随后会重新提问。
valid_release_tag_input() {
  if valid_release_tag "$1"; then
    return 0
  fi
  printf '  ! 需要 latest 或形如 v1.2.3 / v1.2.3-rc 的版本号\n'
  return 1
}

valid_ip_list() {
  local value="$1" item
  [[ -z "$value" ]] && return 0
  local IFS=','
  for item in $value; do
    item="$(trim "$item")"
    [[ -z "$item" ]] && continue
    if [[ ! "$item" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]]; then
      printf '  ! 非法地址：%s\n' "$item"
      return 1
    fi
  done
  return 0
}

valid_origin_list() {
  local value="$1" item
  [[ -z "$value" ]] && return 0
  local IFS=','
  for item in $value; do
    item="$(trim "$item")"
    [[ -z "$item" ]] && continue
    if [[ ! "$item" =~ ^https?://[^[:space:]]+$ ]]; then
      printf '  ! 非法来源（需带 http:// 或 https://）：%s\n' "$item"
      return 1
    fi
  done
  return 0
}

valid_email_or_empty() {
  local value="$1"
  [[ -z "$value" ]] && return 0
  if [[ ! "$value" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
    printf '  ! 邮箱格式不正确\n'
    return 1
  fi
  return 0
}

valid_no_space() {
  local value="$1"
  if [[ -z "$value" ]]; then
    printf '  ! 不能为空\n'
    return 1
  fi
  if [[ "$value" =~ [[:space:]] ]]; then
    printf '  ! 不能包含空白字符\n'
    return 1
  fi
  return 0
}

valid_local_db_host() {
  local value="$1"
  case "$value" in
    127.0.0.1|localhost|::1)
      return 0
      ;;
  esac
  printf '  ! 本机建库只支持 127.0.0.1 / localhost / ::1\n'
  printf '    远程或托管数据库请改用“使用已有连接串”模式\n'
  return 1
}

# =============================================================================
# 工具函数
# =============================================================================

rand_hex() {
  local bytes="$1"
  if have openssl; then
    openssl rand -hex "$bytes"
  else
    od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n'
  fi
}

# 把密码编码进 URL：只保留 RFC 3986 unreserved 字符，其余按字节转 %XX。
urlencode() {
  local value="$1" out="" i char hex
  for (( i = 0; i < ${#value}; i++ )); do
    char="${value:i:1}"
    case "$char" in
      [A-Za-z0-9.~_-]) out+="$char" ;;
      *)
        hex="$(printf '%s' "$char" | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')"
        out+="$(printf '%s' "$hex" | sed 's/../%&/g')"
        ;;
    esac
  done
  printf '%s' "$out"
}

# 从已有 control.env 读取一个键的值（不做 shell 求值）。
env_get() {
  local key="$1" file="$2" line
  [[ -f "$file" ]] || return 0
  line="$(grep -E "^${key}=" "$file" 2>/dev/null | tail -n 1 || true)"
  [[ -z "$line" ]] && return 0
  printf '%s' "${line#*=}"
}

mask_secret() {
  local value="$1"
  if [[ ${#value} -le 8 ]]; then
    printf '********'
  else
    printf '%s…（%d 字符）' "${value:0:4}" "${#value}"
  fi
}

mask_db_url() {
  local url="$1"
  if [[ "$url" =~ ^(postgres(ql)?://)([^:/@]+):([^@]*)@(.*)$ ]]; then
    printf '%s%s:***@%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[5]}"
  else
    printf '%s' "$url"
  fi
}

bind_host_of() {
  local bind="$1"
  printf '%s' "${bind%:*}"
}

bind_port_of() {
  local bind="$1" port
  port="${bind##*:}"
  if [[ "$port" =~ ^[0-9]+$ ]]; then
    printf '%s' "$port"
  else
    printf '8080'
  fi
}

# 探活与反代示例使用的地址：通配监听回落环，IPv6 字面量补方括号。
probe_host_of() {
  local host="$1"
  host="${host#[}"
  host="${host%]}"
  case "$host" in
    ""|0.0.0.0|"::") printf '127.0.0.1' ;;
    *:*) printf '[%s]' "$host" ;;
    *) printf '%s' "$host" ;;
  esac
}

is_binary_usable() {
  local src="$1" dest="$2"
  [[ -n "$src" ]] || return 1
  [[ "$(readlink -f "$src")" == "$(readlink -f "$dest" 2>/dev/null || true)" ]] && return 1
  return 0
}

psql_admin() {
  if have runuser; then
    runuser -u postgres -- "$@"
  elif have sudo; then
    sudo -u postgres "$@"
  else
    return 1
  fi
}

# 以系统单元相同的“干净环境”加载 env 文件后执行 check-config。
validate_env_file() {
  local bin="$BIN_DIR/lagran-control" env_file="$CONF_DIR/control.env" out=""
  if [[ ! -x "$bin" ]]; then
    warn "未找到可执行文件 $bin，跳过配置校验"
    return 0
  fi
  if [[ ! -f "$env_file" ]]; then
    warn "未找到配置文件 $env_file，跳过配置校验"
    return 0
  fi
  # 逐行把 KEY=VALUE 交给 env，不 source 配置文件：既不会执行文件里的内容，
  # 也与 systemd EnvironmentFile 的“干净环境”更接近。
  local -a env_args=()
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ -z "${line//[[:space:]]/}" || "$line" =~ ^[[:space:]]*# ]]; then
      continue
    fi
    env_args+=("$line")
  done < "$env_file"
  if out="$( env -i PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
      "${env_args[@]}" "$bin" check-config 2>&1 )"; then
    ok "配置校验通过"
    printf '%s\n' "$out" | sed 's/^/      /'
    return 0
  fi
  warn "配置校验失败："
  printf '%s\n' "$out" | sed 's/^/      /' >&2
  return 1
}

# write_file <路径> <权限> [属主]：内容从标准输入读取；dry-run 时只打印。
write_file() {
  local dest="$1" mode="$2" owner="${3:-}" tmp
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '      [dry-run] 将写入 %s（权限 %s）:\n' "$dest" "$mode"
    sed 's/^/      | /'
    return 0
  fi
  tmp="$(dirname "$dest")/.$(basename "$dest").$$"
  ( umask 077; cat > "$tmp" )
  chmod "$mode" "$tmp"
  if [[ -n "$owner" ]]; then
    chown "$owner" "$tmp"
  fi
  mv -f "$tmp" "$dest"
}

# =============================================================================
# 预检
# =============================================================================

preflight() {
  if [[ "$EUID" -ne 0 ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      warn "当前不是 root：--dry-run 只做预览，不会修改系统"
    else
      die "请用 root 运行：sudo $0"
    fi
  fi
  local cmd
  for cmd in install mktemp sed grep awk date; do
    have "$cmd" || die "缺少命令：$cmd"
  done
  VERSION="${VERSION:-latest}"
  if ! valid_repo "$REPO"; then
    die "GitHub 仓库格式无效：${REPO}（需要 owner/repo，例如 Lagran93/Lagran）"
  fi
  if ! valid_release_tag "$VERSION"; then
    die "安装版本格式无效：${VERSION}（latest 或 v1.2.3 / v1.2.3-rc）"
  fi
  PREFIX="${PREFIX%/}"
  CONF_DIR="${CONF_DIR%/}"
  DATA_DIR="${DATA_DIR%/}"
  LOG_DIR="${LOG_DIR%/}"
  UNIT_DIR="${UNIT_DIR%/}"

  HAVE_SYSTEMD=0
  if have systemctl && [[ -d /run/systemd/system ]]; then
    HAVE_SYSTEMD=1
  fi
  if [[ "$SYSTEMD_MANAGE" -eq 1 && "$HAVE_SYSTEMD" -eq 0 ]]; then
    warn "未检测到运行中的 systemd：只写入单元文件，不执行 systemctl"
    SYSTEMD_MANAGE=0
  fi
  if [[ "$EUID" -eq 0 && "$SYSTEMD_MANAGE" -eq 1 ]]; then
    if ! systemctl show-environment >/dev/null 2>&1; then
      warn "systemctl 不可用（容器或 chroot？）：改为只写单元文件"
      SYSTEMD_MANAGE=0
    fi
  fi
}

print_banner() {
  printf '%s\n' "================================================================"
  printf ' %sLagran CDN 控制面安装向导%s（lagran-control）\n' "$C_BOLD" "$C_RESET"
  printf '%s\n' "================================================================"
  printf '  安装前缀 : %s\n' "$PREFIX"
  printf '  二进制   : %s/lagran-control\n' "${BIN_DIR:-$PREFIX/bin}"
  printf '  配置     : %s/control.env\n' "$CONF_DIR"
  printf '  数据目录 : %s\n' "$DATA_DIR"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '  模式     : %s--dry-run（只预览，不修改系统）%s\n' "$C_YELLOW" "$C_RESET"
  fi
  if ! is_interactive; then
    printf '  模式     : %s非交互（全部使用默认值）%s\n' "$C_YELLOW" "$C_RESET"
  fi
  printf '\n每个问题都带默认值：直接回车采用默认值，Ctrl-C 可随时退出。\n'
}

# =============================================================================
# 已有配置处理
# =============================================================================

# 用已有 control.env 的值作为向导默认值（重写模式）。
seed_from_existing_env() {
  local file="$CONF_DIR/control.env" key
  [[ -f "$file" ]] || return 0
  local -a keys=(
    CONTROL_BIND CONTROL_PUBLIC_URL TRUSTED_PROXIES DATABASE_URL
    DATABASE_MAX_CONNECTIONS DATABASE_MIN_CONNECTIONS DATABASE_ACQUIRE_TIMEOUT_SECS
    REDIS_URL REDIS_SESSION_TTL_SECS CONFIG_CACHE_TTL_SECS
    JWT_SECRET JWT_EXPIRE_HOURS REQUIRE_SECURE_SECRETS ALLOW_REGISTER CAPTCHA_ENABLED
    SEED_DEMO CORS_ALLOWED_ORIGINS AGENT_TOKEN METRICS_TOKEN WAF_RULEPACK_SECRET
    AGENT_TLS_CA_FILE GEOIP_PATH GEOIP_IPV6_PATH SCHEDULE_TTL SCHEDULE_NODE_CACHE_SECS
    DNS_TEST_SERVER EDGE_CNAME ACME_DIRECTORY_URL ACME_CONTACT_EMAIL
    LOG_RETENTION_DAYS ALERT_EVAL_SECS OTEL_EXPORTER_OTLP_ENDPOINT RUST_LOG
  )
  for key in "${keys[@]}"; do
    if [[ -z "${!key:-}" ]]; then
      local value
      value="$(env_get "$key" "$file")"
      if [[ -n "$value" ]]; then
        printf -v "$key" '%s' "$value"
      fi
    fi
  done
  return 0
}

decide_existing_config() {
  if [[ "$KEEP_CONFIG" -eq 1 ]]; then
    EXISTING_MODE="keep"
    note "已指定 --keep-config：保留现有配置"
    return 0
  fi
  if [[ "$FORCE_RECONF" -eq 1 ]]; then
    EXISTING_MODE="rewrite"
    note "已指定 --force：将备份并按向导重写配置"
    return 0
  fi
  if ! is_interactive; then
    EXISTING_MODE="keep"
    note "非交互模式：保留现有配置（需要重写请加 --reconfigure）"
    return 0
  fi
  local choice
  ask_choice choice "检测到已有配置 $CONF_DIR/control.env，如何处理？" "keep" \
    "keep|保留现有配置，只更新二进制/单元并重启服务" \
    "rewrite|备份后按向导重新生成配置（默认值取自现有配置）" \
    "abort|退出，不做任何修改"
  case "$choice" in
    keep) EXISTING_MODE="keep" ;;
    rewrite) EXISTING_MODE="rewrite" ;;
    *) die "已取消，未做任何修改" ;;
  esac
}

# =============================================================================
# 向导
# =============================================================================

# 安装位置与二进制来源不提问：直接用默认值或 CLI/环境变量，只提示一次。
install_target_note() {
  printf '\n'
  if [[ -n "$BINARY_SRC" ]]; then
    note "二进制来源：本地二进制 ${BINARY_SRC}（离线模式）"
  else
    note "二进制来源：github.com/${REPO}（版本 ${VERSION}）"
  fi
  note "安装位置：${PREFIX}（二进制 ${BIN_DIR}、配置 ${CONF_DIR}、数据 ${DATA_DIR}）"
}

ask_version() {
  section "1/8" "安装版本"
  note "控制面二进制从 GitHub Release（github.com/${REPO}）下载，默认安装最新版本。"
  ask VERSION "安装版本（latest=最新版本，或指定 tag 如 v0.1.13-rc）" "$VERSION" valid_release_tag_input
}

ask_listen() {
  section "2/8" "监听与对外访问"
  local scope_host="" default_scope="loopback" current_host current_port default_port
  current_host="$(bind_host_of "${CONTROL_BIND:-}")"
  current_port="$(bind_port_of "${CONTROL_BIND:-}")"
  default_port="$current_port"
  case "$current_host" in
    ""|127.0.0.1|localhost|::1|"[::1]") default_scope="loopback" ;;
    0.0.0.0|"::"|"[::]") default_scope="all" ;;
    *) default_scope="custom" ;;
  esac
  ask_choice CONTROL_SCOPE "控制面监听范围" "$default_scope" \
    "loopback|仅本机 127.0.0.1（推荐：前置 Caddy/Nginx 反向代理）" \
    "all|所有网卡 0.0.0.0（直接对外，需自行提供 HTTPS）" \
    "custom|自定义监听地址（例如 [::]:8080）"
  case "$CONTROL_SCOPE" in
    loopback) scope_host="127.0.0.1" ;;
    all) scope_host="0.0.0.0" ;;
    custom)
      ask CONTROL_BIND "监听地址（host:port）" "${CONTROL_BIND:-0.0.0.0:8080}" valid_bind
      ;;
  esac
  if [[ "$CONTROL_SCOPE" != "custom" ]]; then
    ask_int CONTROL_PORT "监听端口" "$default_port" 1 65535
    CONTROL_BIND="${scope_host}:${CONTROL_PORT}"
    CONTROL_PORT="$((10#${CONTROL_PORT}))"
  else
    CONTROL_PORT="$(bind_port_of "$CONTROL_BIND")"
  fi

  ask CONTROL_PUBLIC_URL "控制台公网地址（用于生成节点安装命令；留空=按请求 Host 推断）" "${CONTROL_PUBLIC_URL:-}" valid_http_url_or_empty
  CONTROL_PUBLIC_URL="${CONTROL_PUBLIC_URL%/}"
  ask TRUSTED_PROXIES "可信反向代理 IP/CIDR（逗号分隔）" "${TRUSTED_PROXIES:-127.0.0.1,::1}" valid_ip_list

  if [[ "$CONTROL_SCOPE" == "all" ]]; then
    warn "控制面监听所有网卡：请确保 ${CONTROL_PORT} 端口有防火墙或 HTTPS 反代，否则 API 将明文暴露"
  fi
  if [[ "$CONTROL_SCOPE" == "loopback" && -z "$CONTROL_PUBLIC_URL" ]]; then
    note "仅监听回环且未设置公网地址：节点安装命令会使用控制台请求的 Host。"
  fi
}

ask_database() {
  section "3/8" "PostgreSQL 数据库"
  note "控制面所有数据存放在 PostgreSQL；服务启动时自动执行 migrations。"
  local default_mode="create"
  [[ -n "$DATABASE_URL" ]] && default_mode="existing"
  ask_choice DB_MODE "数据库配置方式" "$default_mode" \
    "create|在本机创建/更新角色与数据库（首次安装推荐）" \
    "existing|使用已有连接串（远程/托管数据库，或已建好的账号）"
  if [[ "$DB_MODE" == "create" ]]; then
    ask DB_HOST "数据库主机" "${DB_HOST:-127.0.0.1}" valid_local_db_host
    ask_int DB_PORT "数据库端口" "${DB_PORT:-5432}" 1 65535
    ask DB_NAME "数据库名" "${DB_NAME:-lagran}" valid_db_ident
    ask DB_USER "角色名" "${DB_USER:-lagran}" valid_db_ident
    ask_secret DB_PASSWORD "数据库角色密码（会写入连接串，自动 URL 编码）" "${DB_PASSWORD:-$(rand_hex 24)}"
    local host_part="$DB_HOST"
    [[ "$DB_HOST" == *:* ]] && host_part="[$DB_HOST]"
    DATABASE_URL="postgres://${DB_USER}:$(urlencode "$DB_PASSWORD")@${host_part}:${DB_PORT}/${DB_NAME}"
  else
    ask DATABASE_URL "PostgreSQL 连接串" "${DATABASE_URL:-postgres://lagran:lagran@127.0.0.1:5432/lagran}" valid_pg_url
  fi

  ask_int DATABASE_MAX_CONNECTIONS "连接池上限（每个 control 进程）" "${DATABASE_MAX_CONNECTIONS:-32}" 2 200
  ask_int DATABASE_MIN_CONNECTIONS "连接池常驻连接数" "${DATABASE_MIN_CONNECTIONS:-2}" 0 200
  if (( DATABASE_MIN_CONNECTIONS > DATABASE_MAX_CONNECTIONS )); then
    warn "常驻连接数大于上限，已调整为 $DATABASE_MAX_CONNECTIONS"
    DATABASE_MIN_CONNECTIONS="$DATABASE_MAX_CONNECTIONS"
  fi
  ask_int DATABASE_ACQUIRE_TIMEOUT_SECS "获取连接超时（秒）" "${DATABASE_ACQUIRE_TIMEOUT_SECS:-5}" 1 60

  check_database_reachable
}

check_database_reachable() {
  if [[ "$SKIP_DB_CHECK" -eq 1 ]]; then
    note "已跳过数据库连通性检查（--skip-db-check）"
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    note "[dry-run] 跳过数据库连通性检查"
    return 0
  fi
  if ! have psql; then
    warn "未找到 psql：跳过数据库连通性检查"
    return 0
  fi
  note "测试数据库连接：$(mask_db_url "$DATABASE_URL")"
  if psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -tAc 'select 1' >/dev/null 2>&1; then
    ok "数据库连接正常"
    return 0
  fi
  warn "无法连接数据库（$(mask_db_url "$DATABASE_URL")）"
  if [[ "$DB_MODE" == "create" ]]; then
    warn "本机建库需要 PostgreSQL 已启动：systemctl start postgresql"
  fi
  if ! confirm "仍然按当前参数继续安装（稍后自行修复数据库）？" "no"; then
    die "已取消，未做任何修改"
  fi
}

valid_secret_value_or_empty() {
  local value="$1"
  [[ -z "$value" ]] && return 0
  valid_secret_value "$value"
}

valid_no_space_or_empty() {
  local value="$1"
  [[ -z "$value" ]] && return 0
  if [[ "$value" =~ [[:space:]] ]]; then
    printf '  ! 不能包含空白字符\n'
    return 1
  fi
  return 0
}

ask_redis() {
  section "4/8" "Redis（可选）"
  note "不启用时，登录限流/验证码/会话缓存/实时统计回退到进程内或 PostgreSQL。"
  local default_enabled="false"
  [[ -n "$REDIS_URL" ]] && default_enabled="true"
  local enabled
  ask_bool enabled "是否配置 Redis" "$default_enabled"
  if [[ "$enabled" == "true" ]]; then
    ask REDIS_URL "Redis 连接串" "${REDIS_URL:-redis://127.0.0.1:6379/0}" valid_redis_url
    ask_int REDIS_SESSION_TTL_SECS "会话缓存 TTL（秒）" "${REDIS_SESSION_TTL_SECS:-30}" 5 300
  else
    REDIS_URL=""
    REDIS_SESSION_TTL_SECS="${REDIS_SESSION_TTL_SECS:-30}"
  fi
}

ask_secrets() {
  section "5/8" "密钥"
  note "三项密钥都会自动生成随机值：直接回车采用即可；也可粘贴自己的值。"
  ask_secret JWT_SECRET "JWT 会话签名密钥（修改后所有登录会话失效）" "${JWT_SECRET:-$(rand_hex 32)}"
  ask_secret AGENT_TOKEN "全局 Agent 令牌（DNS 调度接口使用，所有 DNS 共用一个）" "${AGENT_TOKEN:-$(rand_hex 24)}"
  ask_secret WAF_RULEPACK_SECRET "WAF 规则包签名密钥（必须与每一台 Edge 完全一致）" "${WAF_RULEPACK_SECRET:-$(rand_hex 32)}"
  ask_bool REQUIRE_SECURE_SECRETS "严格密钥校验（密钥为默认值或过短时拒绝启动）" "${REQUIRE_SECURE_SECRETS:-true}"
  ask_int JWT_EXPIRE_HOURS "登录会话有效期（小时）" "${JWT_EXPIRE_HOURS:-24}" 1 8760
  ask METRICS_TOKEN "（可选）/metrics 专用令牌；留空则复用 Agent 令牌" "${METRICS_TOKEN:-}" valid_secret_value_or_empty
}

ask_accounts() {
  section "6/8" "账号与首次登录"
  local default_mode="register"
  # 重写配置时沿用旧值作为默认：演示账号 / 已关闭自助注册。
  if [[ "$SEED_DEMO" == "true" ]]; then
    default_mode="demo"
  elif [[ "$ALLOW_REGISTER" == "false" ]]; then
    default_mode="skip"
  fi
  ask_choice ADMIN_MODE "如何获得第一个管理员账号" "$default_mode" \
    "register|临时开启自助注册（第一个注册账号自动成为 admin，之后关闭）" \
    "demo|使用内置演示账号 demo@lagran.dev / demo123（仅本地体验）" \
    "skip|不处理（数据库已有账号，或稍后手动开启注册）"
  case "$ADMIN_MODE" in
    register)
      ALLOW_REGISTER="true"
      SEED_DEMO="false"
      ;;
    demo)
      ALLOW_REGISTER="false"
      SEED_DEMO="true"
      if [[ "$REQUIRE_SECURE_SECRETS" == "true" ]]; then
        warn "演示账号与 REQUIRE_SECURE_SECRETS=true 冲突，已改为 false（仅限本地体验）"
        REQUIRE_SECURE_SECRETS="false"
      fi
      ;;
    *)
      ALLOW_REGISTER="false"
      SEED_DEMO="false"
      note "稍后需要首个账号时可临时设置 ALLOW_REGISTER=true 并重启服务。"
      ;;
  esac
  ask_bool CAPTCHA_ENABLED "登录/注册启用图片验证码" "${CAPTCHA_ENABLED:-true}"
}

ask_geoip() {
  section "7/8" "GeoDNS 与调度"
  local default_geo="${GEOIP_PATH:-$DATA_DIR/ip2region_v4.xdb}"
  ask GEOIP_PATH "ip2region IPv4 XDB 路径" "$default_geo" valid_dir_path
  if [[ ! -f "$GEOIP_PATH" ]]; then
    warn "文件不存在：$GEOIP_PATH"
    note "调度会退化为按权重/负载；可在服务启动前放入 ip2region_v4.xdb 并重启。"
  fi
  ask GEOIP_IPV6_PATH "ip2region IPv6 XDB 路径（留空禁用 IPv6 地理调度）" "${GEOIP_IPV6_PATH:-}" valid_optional_path
  ask_int SCHEDULE_TTL "调度接口返回的 DNS TTL（秒）" "${SCHEDULE_TTL:-30}" 5 3600
  ask_int SCHEDULE_NODE_CACHE_SECS "节点表缓存（秒，0=不缓存）" "${SCHEDULE_NODE_CACHE_SECS:-5}" 0 300
  ask DNS_TEST_SERVER "控制台「DNS 测试」目标（host:port）" "${DNS_TEST_SERVER:-127.0.0.1:53}" valid_bind
  ask EDGE_CNAME "统一边缘接入域名（可选，用于展示 CNAME）" "${EDGE_CNAME:-}" valid_no_space_or_empty
}

ask_service_options() {
  section "8/8" "服务与收尾"
  ask SERVICE_USER "服务运行用户" "$SERVICE_USER" valid_username
  ask SERVICE_GROUP "服务运行组（与 Edge/DNS 共享数据目录）" "$SERVICE_GROUP" valid_username
  ask_bool START_NOW "安装完成后立即启动服务" "$START_NOW"

  # 升级助手只有两种来源：Release 包里的 update.sh，或 --update-helper 指定的文件。
  if [[ "$INSTALL_UPDATER" == "false" ]]; then
    note "已指定 --no-updater：不安装升级助手（控制台「系统升级」不可用）"
  elif [[ -n "$BINARY_SRC" && -z "$UPDATE_HELPER_SRC" ]]; then
    INSTALL_UPDATER="false"
    note "离线安装且未提供 --update-helper：跳过升级助手（控制台「系统升级」不可用）"
  elif [[ -n "$BINARY_SRC" ]]; then
    INSTALL_UPDATER="true"
    note "离线安装：升级助手使用 --update-helper 指定的 update.sh"
  else
    ask_bool INSTALL_UPDATER "安装控制台一键升级助手（update.sh 取自 Release 包）" "true"
  fi

  if [[ "$SYSTEMD_MANAGE" -eq 0 ]]; then
    note "未启用 systemd 管理：只会写入单元文件，不会执行 systemctl。"
  fi
}

# 安装位置与 ACME/运行参数不提问：这里补齐默认值（已有预置值保持不变）。
apply_defaults() {
  printf '\n'
  : "${ACME_DIRECTORY_URL:=https://acme-v02.api.letsencrypt.org/directory}"
  : "${ACME_CONTACT_EMAIL:=}"
  : "${LOG_RETENTION_DAYS:=30}"
  : "${ALERT_EVAL_SECS:=30}"
  : "${CONFIG_CACHE_TTL_SECS:=3}"
  : "${RUST_LOG:=control=info,tower_http=warn,sqlx=warn}"
  : "${CORS_ALLOWED_ORIGINS:=}"
  : "${OTEL_EXPORTER_OTLP_ENDPOINT:=}"
  : "${AGENT_TLS_CA_FILE:=}"
}

# 对最终生效值做一次校验：预置值写错时立刻报错，而不是等服务启动失败。
validate_defaults() {
  valid_pg_url "$DATABASE_URL" >/dev/null || die "DATABASE_URL 无效：$(mask_db_url "$DATABASE_URL")"
  valid_http_url_or_empty "$CONTROL_PUBLIC_URL" >/dev/null \
    || die "CONTROL_PUBLIC_URL 无效：${CONTROL_PUBLIC_URL}（留空或 http(s):// 地址）"
  valid_ip_list "$TRUSTED_PROXIES" >/dev/null \
    || die "TRUSTED_PROXIES 无效：${TRUSTED_PROXIES}（逗号分隔的 IP/CIDR）"
  if [[ -n "$REDIS_URL" ]] && ! valid_redis_url "$REDIS_URL" >/dev/null; then
    die "REDIS_URL 无效：${REDIS_URL}（redis:// 或 rediss://）"
  fi
  valid_origin_list "$CORS_ALLOWED_ORIGINS" >/dev/null \
    || die "CORS_ALLOWED_ORIGINS 无效：${CORS_ALLOWED_ORIGINS}"
  valid_http_url "$ACME_DIRECTORY_URL" >/dev/null \
    || die "ACME_DIRECTORY_URL 无效：${ACME_DIRECTORY_URL}"
  valid_email_or_empty "$ACME_CONTACT_EMAIL" >/dev/null \
    || die "ACME_CONTACT_EMAIL 无效：${ACME_CONTACT_EMAIL}"
  valid_existing_file "$AGENT_TLS_CA_FILE" >/dev/null \
    || die "AGENT_TLS_CA_FILE 无效：${AGENT_TLS_CA_FILE}"
  valid_dir_path "$GEOIP_PATH" >/dev/null || die "GEOIP_PATH 需要绝对路径：${GEOIP_PATH}"
  valid_optional_path "$GEOIP_IPV6_PATH" >/dev/null \
    || die "GEOIP_IPV6_PATH 需要绝对路径：${GEOIP_IPV6_PATH}"
  valid_no_space "$RUST_LOG" >/dev/null || die "RUST_LOG 不能包含空白字符"
  valid_no_space_or_empty "$EDGE_CNAME" >/dev/null || die "EDGE_CNAME 不能包含空白字符"
  valid_username "$SERVICE_USER" >/dev/null || die "服务运行用户无效：${SERVICE_USER}"
  valid_username "$SERVICE_GROUP" >/dev/null || die "服务运行组无效：${SERVICE_GROUP}"
  valid_secret_value "$JWT_SECRET" >/dev/null || die "JWT_SECRET 无效（不能为空、含空白或 #）"
  valid_secret_value "$AGENT_TOKEN" >/dev/null || die "AGENT_TOKEN 无效（不能为空、含空白或 #）"
  valid_secret_value "$WAF_RULEPACK_SECRET" >/dev/null \
    || die "WAF_RULEPACK_SECRET 无效（不能为空、含空白或 #）"
  valid_secret_value_or_empty "$METRICS_TOKEN" >/dev/null \
    || die "METRICS_TOKEN 无效（不能含空白或 #）"

  if [[ ! -f "$GEOIP_PATH" ]]; then
    warn "GeoIP 文件不存在：$GEOIP_PATH"
    note "调度会退化为按权重/负载；可在服务启动前放入 ip2region_v4.xdb 并重启。"
  fi
}

# =============================================================================
# 汇总与确认
# =============================================================================

summary() {
  step "安装参数汇总"
  resolve_release_tag || true
  printf '  %s: %s\n' "安装前缀" "$PREFIX"
  if [[ -n "$BINARY_SRC" ]]; then
    printf '  %s: %s\n' "安装来源" "本地二进制（离线）"
  else
    printf '  %s: %s\n' "安装来源" "github.com/${REPO}"
  fi
  printf '  %s: %s\n' "安装版本" "$(install_version_label)"
  printf '  %s: %s\n' "二进制" "$BIN_DIR/lagran-control"
  printf '  %s: %s\n' "配置文件" "$CONF_DIR/control.env"
  printf '  %s: %s\n' "数据目录" "$DATA_DIR"
  printf '  %s: %s\n' "systemd 单元" "$UNIT_DIR/$SERVICE.service"
  printf '  %s: %s\n' "服务账号" "$SERVICE_USER:$SERVICE_GROUP"
  printf '  %s: %s\n' "监听地址" "$CONTROL_BIND"
  printf '  %s: %s\n' "公网地址" "${CONTROL_PUBLIC_URL:-（按请求 Host 推断）}"
  printf '  %s: %s\n' "数据库" "$(mask_db_url "$DATABASE_URL")"
  if [[ "$DB_MODE" == "create" ]]; then
    printf '  %s: %s\n' "建库方式" "本机创建/更新角色 ${DB_USER} 与数据库 ${DB_NAME}"
  fi
  printf '  %s: %s\n' "Redis" "${REDIS_URL:-（未启用）}"
  printf '  %s: %s\n' "JWT_SECRET" "$(mask_secret "$JWT_SECRET")"
  printf '  %s: %s\n' "AGENT_TOKEN" "$(mask_secret "$AGENT_TOKEN")"
  printf '  %s: %s\n' "WAF_RULEPACK_SECRET" "$(mask_secret "$WAF_RULEPACK_SECRET")"
  printf '  %s: %s\n' "严格密钥校验" "$REQUIRE_SECURE_SECRETS"
  printf '  %s: %s\n' "自助注册" "$ALLOW_REGISTER"
  printf '  %s: %s\n' "演示账号" "$SEED_DEMO"
  printf '  %s: %s\n' "GeoIP" "$GEOIP_PATH"
  printf '  %s: %s\n' "ACME" "$ACME_DIRECTORY_URL"
  printf '  %s: %s\n' "立即启动" "$START_NOW"
  printf '  %s: %s\n' "升级助手" "$INSTALL_UPDATER"
}

# =============================================================================
# 渲染配置 / 单元文件
# =============================================================================

render_env() {
  cat <<EOF
################################################################################
# Lagran CDN 控制面（Control Plane）运行时配置
# 由 scripts/install-control.sh 于 $(date -u '+%Y-%m-%dT%H:%M:%SZ') 生成
# 应用：apps/control → 二进制 lagran-control
#
# 权限：root 所有、属组 ${SERVICE_USER}（0640）；组不存在时为 0600 root:root。
# systemd 以 root 读取 EnvironmentFile 后再降权运行服务。
# 修改后：systemctl restart ${SERVICE}
# 注意：本文件包含 JWT / 数据库 / Agent / WAF 密钥，不要提交到版本库。
#
# 全部参数说明见仓库根目录 control.env.example。
################################################################################


# =============================================================================
# 1. 监听与对外地址
# =============================================================================

# 控制面 HTTP 监听地址；前面有反向代理时只监听回环。
CONTROL_BIND=${CONTROL_BIND}

# 控制台公网根地址（不带末尾 /），用于生成节点安装命令；留空按请求 Host 推断。
CONTROL_PUBLIC_URL=${CONTROL_PUBLIC_URL}

# 可信反向代理（IP/CIDR，逗号分隔）；只有这些来源的 X-Forwarded-For 会被采信。
TRUSTED_PROXIES=${TRUSTED_PROXIES}

# 边缘批量配置的进程内缓存 TTL（秒）。
CONFIG_CACHE_TTL_SECS=${CONFIG_CACHE_TTL_SECS}


# =============================================================================
# 2. PostgreSQL
# =============================================================================

# 密码中的特殊字符已做 URL 编码；远程数据库建议追加 ?sslmode=require。
DATABASE_URL=${DATABASE_URL}
DATABASE_MAX_CONNECTIONS=${DATABASE_MAX_CONNECTIONS}
DATABASE_MIN_CONNECTIONS=${DATABASE_MIN_CONNECTIONS}
DATABASE_ACQUIRE_TIMEOUT_SECS=${DATABASE_ACQUIRE_TIMEOUT_SECS}


# =============================================================================
# 3. Redis（可选）
# =============================================================================

# 留空时登录限流/验证码/会话缓存/实时统计回退到进程内或 PostgreSQL。
REDIS_URL=${REDIS_URL}
REDIS_SESSION_TTL_SECS=${REDIS_SESSION_TTL_SECS}


# =============================================================================
# 4. 认证、会话与注册
# =============================================================================

JWT_SECRET=${JWT_SECRET}
JWT_EXPIRE_HOURS=${JWT_EXPIRE_HOURS}

# true：JWT_SECRET 为内置默认值或长度 <16 时拒绝启动。
REQUIRE_SECURE_SECRETS=${REQUIRE_SECURE_SECRETS}

# 首次部署可临时设为 true，注册第一个账号（自动成为 admin）后改回 false。
ALLOW_REGISTER=${ALLOW_REGISTER}
CAPTCHA_ENABLED=${CAPTCHA_ENABLED}

# 仅本地体验；与 REQUIRE_SECURE_SECRETS=true 同时开启会拒绝启动。
SEED_DEMO=${SEED_DEMO}

# 允许跨域的浏览器来源（逗号分隔，需带 scheme）；留空=宽松回显任意 Origin。
CORS_ALLOWED_ORIGINS=${CORS_ALLOWED_ORIGINS}


# =============================================================================
# 5. 节点令牌与签名
# =============================================================================

# 全局 Agent 令牌：DNS 调度接口使用；Edge 心跳必须使用各自的节点令牌。
AGENT_TOKEN=${AGENT_TOKEN}

# /metrics 专用令牌；留空则回退到 AGENT_TOKEN。
METRICS_TOKEN=${METRICS_TOKEN}

# WAF 规则包签名密钥：必须与所有 Edge 完全一致，轮换需同步全部节点。
WAF_RULEPACK_SECRET=${WAF_RULEPACK_SECRET}

# Edge 管理面使用自签/内部 CA 时，额外信任的 CA PEM。
AGENT_TLS_CA_FILE=${AGENT_TLS_CA_FILE}


# =============================================================================
# 6. GeoDNS 与节点调度
# =============================================================================

# ip2region XDB（v2/v3）；缺失时调度退化为按权重/负载。
GEOIP_PATH=${GEOIP_PATH}
GEOIP_IPV6_PATH=${GEOIP_IPV6_PATH}
SCHEDULE_TTL=${SCHEDULE_TTL}
SCHEDULE_NODE_CACHE_SECS=${SCHEDULE_NODE_CACHE_SECS}
DNS_TEST_SERVER=${DNS_TEST_SERVER}
EDGE_CNAME=${EDGE_CNAME}


# =============================================================================
# 7. ACME / Let's Encrypt
# =============================================================================

# 生产签发与自动续期只用这一项；换成私有/自建 ACME（step-ca、ZeroSSL、企业 CA）时改这里。
# 注意：写成空值不会回退到内置默认值，会导致签发失败、接口返回 503。
ACME_DIRECTORY_URL=${ACME_DIRECTORY_URL}

# 仅当控制台选择「Let's Encrypt（预发布校验）」时才使用；日常签发不读它。
# 不需要预发布目录时保持默认即可；留空会让你在控制台选到该选项时返回 503。
ACME_STAGING_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory

ACME_CONTACT_EMAIL=${ACME_CONTACT_EMAIL}


# =============================================================================
# 8. 数据保留与告警
# =============================================================================

# access_logs / edge_metrics / waf_events / login_logs 保留天数；0=不清理。
LOG_RETENTION_DAYS=${LOG_RETENTION_DAYS}

# 告警规则评估间隔（秒）。
ALERT_EVAL_SECS=${ALERT_EVAL_SECS}


# =============================================================================
# 9. 可观测性
# =============================================================================

# OTLP/HTTP Trace 导出地址；留空关闭。
OTEL_EXPORTER_OTLP_ENDPOINT=${OTEL_EXPORTER_OTLP_ENDPOINT}
OTEL_SERVICE_NAME=lagran-control
OTEL_TRACES_SAMPLER_ARG=1.0


# =============================================================================
# 10. 日志
# =============================================================================

RUST_LOG=${RUST_LOG}


# =============================================================================
# 11. 控制台「系统升级」
# =============================================================================

LAGRAN_UPDATE_REPO=${REPO}
EOF
  render_env_updater
}

render_env_updater() {
  if [[ "$INSTALL_UPDATER" == "true" ]]; then
    cat <<EOF
LAGRAN_UPDATE_HELPER=${BIN_DIR}/lagran-update
LAGRAN_UPDATE_REQUEST_PATH=${DATA_DIR}/update.request
LAGRAN_UPDATE_STATUS_PATH=${DATA_DIR}/update.status
EOF
  else
    cat <<EOF
# 未安装升级助手：以下路径保持注释，控制台「系统升级」不可用。
# LAGRAN_UPDATE_HELPER=${BIN_DIR}/lagran-update
# LAGRAN_UPDATE_REQUEST_PATH=${DATA_DIR}/update.request
# LAGRAN_UPDATE_STATUS_PATH=${DATA_DIR}/update.status
EOF
  fi
}

render_unit() {
  cat <<EOF
[Unit]
Description=Lagran CDN Control Plane
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
EnvironmentFile=${CONF_DIR}/control.env
# 修复共享数据目录权限后再降权：旧版单用户布局可能是 root:lagran 0755，
# 拆分后的 lagran-control 账号无法在其中创建 update.request。
# ExecStartPre 前缀 + 表示这些命令仍以 root 执行。
ExecStartPre=+/bin/mkdir -p ${DATA_DIR}
ExecStartPre=+/bin/chgrp ${SERVICE_GROUP} ${DATA_DIR}
ExecStartPre=+/bin/chmod g+rwxs ${DATA_DIR}
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

render_update_env() {
  cat <<EOF
LAGRAN_PREFIX=${PREFIX}
LAGRAN_DATA_DIR=${DATA_DIR}
LAGRAN_UPDATE_REPO=${REPO}
LAGRAN_UPDATE_REQUEST_PATH=${DATA_DIR}/update.request
LAGRAN_UPDATE_STATUS_PATH=${DATA_DIR}/update.status
EOF
}

render_update_unit() {
  cat <<EOF
[Unit]
Description=Lagran CDN privileged updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${BIN_DIR}/lagran-update
TimeoutStartSec=600
EOF
}

render_update_path_unit() {
  cat <<EOF
[Unit]
Description=Watch for Lagran CDN update requests

[Path]
PathExists=${DATA_DIR}/update.request
Unit=lagran-update.service

[Install]
WantedBy=multi-user.target
EOF
}

# =============================================================================
# 安装步骤
# =============================================================================

ensure_dirs() {
  run install -d -m 0755 "$PREFIX" "$BIN_DIR" "$CONF_DIR" "$DATA_DIR" "$LOG_DIR"
  run install -d -m 0755 "$UNIT_DIR"
  run rm -f "$DATA_DIR"/update.request.tmp "$DATA_DIR"/update.request.tmp.* 2>/dev/null || true
}

ensure_users() {
  if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    run groupadd --system "$SERVICE_GROUP"
  fi
  if ! getent group "$SERVICE_USER" >/dev/null 2>&1; then
    run groupadd --system "$SERVICE_USER"
  fi
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    run useradd --system --gid "$SERVICE_GROUP" --home-dir "$DATA_DIR" \
      --shell /usr/sbin/nologin "$SERVICE_USER"
  fi
  run chown -R "root:$SERVICE_GROUP" "$DATA_DIR" "$LOG_DIR"
  run chmod -R g+rwX "$DATA_DIR" "$LOG_DIR"
  run chgrp "$SERVICE_GROUP" "$DATA_DIR"
  run chmod g+rwxs "$DATA_DIR"
  # 同机还装了 Edge 时，证书/缓存目录必须还给 lagran-edge。
  local sub
  for sub in certs cache large-cache; do
    if [[ -d "$DATA_DIR/$sub" ]]; then
      run chown -R "lagran-edge:$SERVICE_GROUP" "$DATA_DIR/$sub" 2>/dev/null || true
    fi
  done
}

# SQL 从标准输入送入 psql，避免密码出现在进程参数（ps 可见）中。
run_sql_stdin() {
  local sql="$1"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '      [dry-run] psql <<< %s\n' "$sql"
    return 0
  fi
  printf '%s\n' "$sql" | psql_admin psql -v ON_ERROR_STOP=1 -q
}

ensure_database() {
  step "初始化 PostgreSQL 角色与数据库"
  have psql || die "缺少 psql：请安装 postgresql-client，或改用 --database-url 指定已有数据库"
  if ! have runuser && ! have sudo; then
    die "无法以 postgres 用户执行命令：请安装 runuser 或改用 --database-url"
  fi
  if ! psql_admin psql -tAc 'select 1' >/dev/null 2>&1; then
    die "无法以 postgres 用户连接本机 PostgreSQL：请先 systemctl start postgresql"
  fi
  local pass_sql exists
  pass_sql="${DB_PASSWORD//\'/\'\'}"
  exists="$(psql_admin psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" 2>/dev/null | tr -d '[:space:]')"
  if [[ "$exists" == "1" ]]; then
    run_sql_stdin "ALTER ROLE \"${DB_USER}\" WITH LOGIN PASSWORD '${pass_sql}'"
    ok "已更新角色 ${DB_USER} 的密码"
  else
    run_sql_stdin "CREATE ROLE \"${DB_USER}\" WITH LOGIN PASSWORD '${pass_sql}'"
    ok "已创建角色 ${DB_USER}"
  fi
  exists="$(psql_admin psql -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" 2>/dev/null | tr -d '[:space:]')"
  if [[ "$exists" == "1" ]]; then
    ok "数据库 ${DB_NAME} 已存在（迁移由服务启动时执行）"
  else
    run psql_admin createdb -O "$DB_USER" "$DB_NAME"
    ok "已创建数据库 ${DB_NAME}（owner=${DB_USER}）"
  fi
}

# 查询仓库最新 Release 的 tag（资产名与 tag 同名）。
github_latest_tag() {
  have curl || return 1
  local json tag
  json="$(curl -fsSL --retry 2 --max-time 20 \
    "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null)" || return 1
  tag="$(printf '%s' "$json" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  [[ -n "$tag" ]] || return 1
  printf '%s' "$tag"
}

# 确定要安装的 tag：latest 查询最新版本；显式 tag 允许省略 v 前缀。
resolve_release_tag() {
  [[ -n "$BINARY_SRC" ]] && return 0
  [[ -n "$RESOLVED_TAG" ]] && return 0
  local tag="${VERSION:-latest}"
  if [[ "$tag" == "latest" ]]; then
    if ! tag="$(github_latest_tag)"; then
      warn "无法解析 ${REPO} 的最新版本（检查网络或改用 --version <tag>）"
      if [[ "$DRY_RUN" -eq 1 ]]; then
        RESOLVED_TAG="latest"
        return 0
      fi
      return 1
    fi
  fi
  case "$tag" in
    v*) ;;
    [0-9]*) tag="v${tag}" ;;
  esac
  RESOLVED_TAG="$tag"
  return 0
}

# 供汇总/结尾输出：说明本次安装的版本（或离线二进制）。
install_version_label() {
  if [[ -n "$BINARY_SRC" ]]; then
    printf '本地二进制（%s）' "$BINARY_SRC"
  else
    printf '%s' "${RESOLVED_TAG:-latest}"
  fi
}

download_release() {
  have curl || die "未找到 curl：无法从 GitHub Release 下载；离线环境请用 --binary"
  local arch asset base tmp found nested
  [[ -n "$RESOLVED_TAG" && "$RESOLVED_TAG" != "latest" ]] \
    || die "尚未解析出要安装的版本：检查网络或改用 --version <tag>"
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    *) die "官方 Release 只提供 amd64 包（当前 $(uname -m)）；请用 --binary 指定本地构建的二进制" ;;
  esac
  asset="lagran-cdn-${RESOLVED_TAG#v}-linux-${arch}.tar.gz"
  base="https://github.com/${REPO}/releases/download/${RESOLVED_TAG}"
  RELEASE_STAGE=""
  RELEASE_BINARY=""
  tmp="$(mktemp -d)"
  TMP_DIRS+=("$tmp")
  printf '==> 下载 %s（%s）\n' "$asset" "$REPO" >&2
  # 终端上显示进度条；被重定向到日志时保持安静，避免刷屏。
  # --retry-all-errors：TLS 中途断开这类传输错误也要重试，否则偶发抖动会让安装失败。
  local -a curl_flags=(-fL --retry 3 --retry-delay 2 --retry-all-errors --connect-timeout 15)
  if [[ -t 2 ]]; then
    curl_flags+=(--progress-bar)
  else
    curl_flags+=(-sS)
  fi
  curl "${curl_flags[@]}" "${base}/${asset}" -o "${tmp}/${asset}" \
    || die "下载 ${asset} 失败（curl 退出码 $?）：可能是网络问题；离线环境可用 --binary，版本不存在请检查 --version/--repo"
  curl -fsSL "${base}/SHA256SUMS" -o "${tmp}/SHA256SUMS" \
    || die "缺少 SHA256SUMS，拒绝安装未校验的 Release"
  ( cd "$tmp" && grep -F "  ${asset}" SHA256SUMS | sha256sum -c - >/dev/null 2>&1 ) \
    || die "校验失败：${asset}"
  mkdir -p "${tmp}/stage"
  safe_extract "${tmp}/${asset}" "${tmp}/stage"
  # 老版本包可能多套一层目录；先确定真正的包根目录（与 install.sh 一致），
  # 后面的 update.sh 也从同一个目录里取。
  RELEASE_STAGE="${tmp}/stage"
  if [[ ! -d "${RELEASE_STAGE}/bin" && ! -f "${RELEASE_STAGE}/lagran-control" ]]; then
    nested="$(find "${RELEASE_STAGE}" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null || true)"
    if [[ -n "$nested" && ( -d "$nested/bin" || -f "$nested/lagran-control" ) ]]; then
      RELEASE_STAGE="$nested"
    fi
  fi
  found="$(find "${RELEASE_STAGE}" -maxdepth 3 -type f -name lagran-control -print -quit 2>/dev/null || true)"
  [[ -n "$found" ]] || die "Release 包中缺少 lagran-control"
  RELEASE_BINARY="$found"
}

# 拒绝绝对路径、.. 和链接成员的解包（与根目录 install.sh 保持一致）。
safe_extract() {
  local archive="$1" dest="$2" names verbose line found_link=0
  names="$(tar -tzf "${archive}" 2>/dev/null)" || die "无法读取压缩包 ${archive}"
  case "${names}" in
    /*) die "压缩包包含绝对路径，拒绝解包" ;;
  esac
  if grep -qE '(^|/)[.][.](/|$)' <<< "${names}"; then
    die "压缩包包含越界路径，拒绝解包"
  fi
  verbose="$(tar -tvzf "${archive}" 2>/dev/null)" || die "无法检查压缩包 ${archive}"
  while IFS= read -r line; do
    case "${line}" in
      l*|h*) found_link=1; break ;;
    esac
  done <<< "${verbose}"
  if [[ "${found_link}" -eq 1 ]]; then
    die "压缩包包含链接成员，拒绝解包"
  fi
  tar --no-same-owner --no-same-permissions -xzf "${archive}" -C "${dest}"
}

install_binary() {
  local dest="$BIN_DIR/lagran-control" src="" out="" installed=""
  if [[ -n "$BINARY_SRC" ]]; then
    [[ -f "$BINARY_SRC" ]] || die "--binary 指定的文件不存在：$BINARY_SRC"
    src="$BINARY_SRC"
    note "离线安装：使用本地二进制 $src"
  else
    resolve_release_tag \
      || die "无法解析 ${REPO} 的最新版本：检查网络、--repo 或改用 --version <tag>"
    # 幂等：已安装同一版本、且升级助手也已在位时不再重新下载；
    # 升级/换版本时版本号不同，仍会下载。
    if [[ -x "$dest" && -n "$RESOLVED_TAG" ]]; then
      installed="$("$dest" version 2>/dev/null || true)"
      case "$installed" in
        *"${RESOLVED_TAG#v}"*)
          if [[ "$INSTALL_UPDATER" != "true" || -x "$BIN_DIR/lagran-update" ]]; then
            ok "已安装 ${RESOLVED_TAG}，跳过下载：$dest"
            return 0
          fi
          note "已安装 ${RESOLVED_TAG}，但缺少升级助手，重新下载安装包"
          ;;
      esac
    fi
    note "安装版本：${RESOLVED_TAG}（github.com/${REPO}）"
    if [[ "$DRY_RUN" -eq 1 ]]; then
      note "[dry-run] 将下载 https://github.com/${REPO}/releases/download/${RESOLVED_TAG}/lagran-cdn-${RESOLVED_TAG#v}-linux-amd64.tar.gz"
      note "[dry-run] install -m 0755 <解包后的 lagran-control> $dest"
      return 0
    fi
    # 不用 $(...)：命令替换是子 shell，RELEASE_STAGE 会丢，升级助手就取不到包内 update.sh。
    download_release
    src="$RELEASE_BINARY"
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    note "[dry-run] install -m 0755 ${src} $dest"
    return 0
  fi
  [[ -n "$src" ]] || die "无法获取 lagran-control"
  if ! is_binary_usable "$src" "$dest"; then
    note "源与目标相同，跳过复制：$dest"
    return 0
  fi
  # 先按 0755 落到临时文件再自检：Release 包里的二进制可能没有可执行位，
  # 临时解包目录也可能挂在 noexec 分区上，直接执行会被拒绝。
  install -m 0755 "$src" "$BIN_DIR/.lagran-control.new"
  if out="$("$BIN_DIR/.lagran-control.new" version 2>&1)"; then
    ok "二进制可用：${out}"
  else
    rm -f "$BIN_DIR/.lagran-control.new"
    die "无法执行 ${src}（架构不匹配或文件损坏）：${out}"
  fi
  mv -f "$BIN_DIR/.lagran-control.new" "$dest"
  ok "已安装 $dest"
  # 校验下载到的版本与请求的 tag 一致（仅对 Release 安装生效）。
  if [[ -z "$BINARY_SRC" && -n "$RESOLVED_TAG" && "$RESOLVED_TAG" != "latest" ]]; then
    case "$out" in
      *"${RESOLVED_TAG#v}"*) ;;
      *) warn "二进制自报版本与请求的 ${RESOLVED_TAG} 不一致：${out}" ;;
    esac
  fi
}

write_control_env() {
  local env_file="$CONF_DIR/control.env" mode="0600" owner="root:root" backup
  if getent group "$SERVICE_USER" >/dev/null 2>&1; then
    mode="0640"
    owner="root:$SERVICE_USER"
  fi
  if [[ -f "$env_file" ]]; then
    backup="${env_file}.bak.$(date -u '+%Y%m%dT%H%M%SZ')"
    run cp -a "$env_file" "$backup"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      note "旧配置已备份：$backup"
    fi
  fi
  render_env | write_file "$env_file" "$mode" "$owner"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    ok "已写入 $env_file（$mode $owner）"
  fi
}

write_units() {
  render_unit | write_file "$UNIT_DIR/$SERVICE.service" "0644"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    ok "已写入 $UNIT_DIR/$SERVICE.service"
  fi
}

install_updater() {
  local helper="" label=""
  if [[ -n "$UPDATE_HELPER_SRC" ]]; then
    [[ -f "$UPDATE_HELPER_SRC" ]] || die "--update-helper 指定的文件不存在：$UPDATE_HELPER_SRC"
    helper="$UPDATE_HELPER_SRC"
    label="$helper"
  elif [[ -n "$RELEASE_STAGE" ]]; then
    # 与二进制同源：update.sh 取自本次下载并校验过的 Release 包。
    helper="$(find "$RELEASE_STAGE" -maxdepth 3 -type f -name update.sh -print -quit 2>/dev/null || true)"
    label="Release 包中的 update.sh"
  elif [[ "$DRY_RUN" -eq 1 && -z "$BINARY_SRC" ]]; then
    label="<下载的 Release 包中的 update.sh>"
  fi

  if [[ -z "$helper" && -z "$label" ]]; then
    if [[ -x "$BIN_DIR/lagran-update" ]]; then
      note "未取到新的 update.sh，保留已安装的 $BIN_DIR/lagran-update"
      return 0
    fi
    if [[ -n "$BINARY_SRC" ]]; then
      warn "离线安装未提供 --update-helper，跳过升级助手（控制台「系统升级」不可用）"
    else
      warn "Release 包中没有 update.sh，跳过升级助手（控制台「系统升级」不可用）"
    fi
    return 0
  fi
  if [[ -n "$helper" ]] && ! grep -q 'updater-schema: 2' "$helper"; then
    warn "update.sh 版本过旧（缺少 updater-schema: 2），跳过安装"
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    note "[dry-run] install -m 0755 ${label} $BIN_DIR/lagran-update"
  else
    install -m 0755 "$helper" "$BIN_DIR/lagran-update"
    ok "已安装 $BIN_DIR/lagran-update（${label}）"
  fi
  render_update_env | write_file "$CONF_DIR/update.env" "0644"
  render_update_unit | write_file "$UNIT_DIR/lagran-update.service" "0644"
  render_update_path_unit | write_file "$UNIT_DIR/lagran-update.path" "0644"
  if [[ "$SYSTEMD_MANAGE" -eq 1 ]]; then
    run systemctl daemon-reload
    if [[ "$START_NOW" == "true" ]]; then
      run systemctl enable --now lagran-update.path
    else
      run systemctl enable lagran-update.path
    fi
  fi
}

enable_and_start() {
  if [[ "$SYSTEMD_MANAGE" -ne 1 ]]; then
    note "未启用 systemd 管理：跳过 daemon-reload/enable/start"
    note "手动启动： $BIN_DIR/lagran-control"
    return 0
  fi
  run systemctl daemon-reload
  run systemctl enable "$SERVICE.service"
  if [[ "$START_NOW" != "true" ]]; then
    note "已安装，稍后用 systemctl enable --now $SERVICE 启动"
    return 0
  fi
  if [[ "$DRY_RUN" -eq 1 ]]; then
    note "[dry-run] systemctl restart $SERVICE.service"
  elif ! systemctl restart "$SERVICE.service"; then
    warn "systemctl restart $SERVICE.service 失败，最近日志："
    if have journalctl; then
      journalctl -u "$SERVICE.service" -n 40 --no-pager 2>/dev/null | sed 's/^/      /' || true
    fi
    die "服务启动失败：journalctl -u ${SERVICE} -n 50 --no-pager"
  else
    ok "已启动 $SERVICE.service"
  fi
  SERVICE_STARTED=1
}

health_check() {
  if [[ "$SERVICE_STARTED" -ne 1 || "$DRY_RUN" -eq 1 ]]; then
    note "跳过健康检查（本次没有启动服务）"
    return 0
  fi
  local port url i
  port="$(bind_port_of "$CONTROL_BIND")"
  url="http://$(probe_host_of "$(bind_host_of "$CONTROL_BIND")"):${port}/health"
  note "等待控制面就绪：$url"
  for (( i = 0; i < 30; i++ )); do
    if have curl; then
      if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
        ok "健康检查通过：$url"
        return 0
      fi
    elif env CONTROL_HEALTH_URL="$url" "$BIN_DIR/lagran-control" health >/dev/null 2>&1; then
      ok "健康检查通过：$url"
      return 0
    fi
    sleep 1
  done
  warn "健康检查未通过（30 秒）"
  if have journalctl; then
    printf '\n最近日志：\n'
    journalctl -u "$SERVICE.service" -n 40 --no-pager 2>/dev/null | sed 's/^/      /' || true
  fi
  die "服务未就绪：journalctl -u ${SERVICE} -n 50 --no-pager"
}

print_footer() {
  local port probe
  port="$(bind_port_of "$CONTROL_BIND")"
  probe="$(probe_host_of "$(bind_host_of "$CONTROL_BIND")")"
  printf '\n%s================================================================%s\n' "$C_GREEN" "$C_RESET"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf ' %s预览完成（未修改系统）%s\n' "$C_BOLD" "$C_RESET"
  else
    printf ' %s安装完成%s\n' "$C_BOLD" "$C_RESET"
  fi
  printf '%s================================================================%s\n' "$C_GREEN" "$C_RESET"
  printf '  %s: %s\n' "二进制" "$BIN_DIR/lagran-control"
  printf '  %s: %s\n' "版本" "$(install_version_label)"
  printf '  %s: %s\n' "配置" "$CONF_DIR/control.env"
  printf '  %s: %s\n' "健康检查" "curl http://${probe}:${port}/health"
  printf '  %s: %s\n' "实时日志" "journalctl -u $SERVICE -f"
  printf '  %s: %s\n' "服务状态" "systemctl status $SERVICE"
  printf '\n下一步：\n'
  printf '  1) 反向代理：把 /api/* /health /ready 转发到 %s:%s，\n' "$probe" "$port"
  printf '     站点根目录指向前端静态目录（默认 /opt/lagran/web）。\n'
  if [[ "$ALLOW_REGISTER" == "true" ]]; then
    printf '  2) 首次登录：打开控制台注册第一个账号（自动成为 admin），随后执行：\n'
    printf "       sudo sed -i 's/^ALLOW_REGISTER=.*/ALLOW_REGISTER=false/' %s/control.env\n" "$CONF_DIR"
    printf '       sudo systemctl restart %s\n' "$SERVICE"
  elif [[ "$SEED_DEMO" == "true" ]]; then
    printf '  2) 首次登录：demo@lagran.dev / demo123（演示账号，请尽快修改密码）。\n'
  else
    printf '  2) 首个账号：数据库为空时可临时设置 ALLOW_REGISTER=true 并重启服务。\n'
  fi
  printf '  3) 接入边缘节点：控制台「边缘节点」创建节点后，用节点令牌安装：\n'
  printf "       sudo AGENT_TOKEN='<节点令牌>' NODE_ID='edge-01' ./install.sh edge\n"
  printf '  4) 所有 Edge 的 WAF_RULEPACK_SECRET 必须与本机 control.env 完全一致。\n'
  printf '  5) 备份 %s/control.env：JWT_SECRET 丢失会使全部会话失效。\n' "$CONF_DIR"
}

# =============================================================================
# 流程
# =============================================================================

apply_from_scratch() {
  step "创建目录"
  ensure_dirs
  step "创建服务账号"
  ensure_users
  if [[ "$DB_MODE" == "create" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      note "[dry-run] 跳过 PostgreSQL 角色/数据库创建"
    else
      ensure_database
    fi
  fi
  step "安装二进制"
  install_binary
  step "写入配置文件"
  write_control_env
  step "校验配置"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    note "[dry-run] 跳过 check-config 校验"
  else
    validate_env_file || die "生成的配置未通过校验，未启动服务"
  fi
  step "写入 systemd 单元"
  write_units
  if [[ "$INSTALL_UPDATER" == "true" ]]; then
    step "安装升级助手"
    install_updater
  fi
  step "启动服务"
  enable_and_start
  step "健康检查"
  health_check
  print_footer
}

run_keep_config() {
  local existing="$CONF_DIR/control.env"
  step "保留现有配置：$existing"
  CONTROL_BIND="$(env_get CONTROL_BIND "$existing")"
  CONTROL_BIND="${CONTROL_BIND:-0.0.0.0:8080}"
  CONTROL_PORT="$(bind_port_of "$CONTROL_BIND")"
  ensure_dirs
  ensure_users
  install_binary
  if [[ -f "$UNIT_DIR/$SERVICE.service" ]]; then
    note "保留现有单元：$UNIT_DIR/$SERVICE.service"
  else
    write_units
  fi
  if [[ "$DRY_RUN" -eq 0 ]]; then
    if ! validate_env_file; then
      if ! confirm "现有配置校验失败，仍然重启服务？" "no"; then
        die "已停止：请先修正 $existing"
      fi
    fi
  fi
  ALLOW_REGISTER="$(env_get ALLOW_REGISTER "$existing")"
  ALLOW_REGISTER="${ALLOW_REGISTER:-false}"
  SEED_DEMO="$(env_get SEED_DEMO "$existing")"
  SEED_DEMO="${SEED_DEMO:-false}"
  enable_and_start
  health_check
  print_footer
}

main() {
  parse_args "$@"
  setup_colors
  preflight
  resolve_interactive
  print_banner

  EXISTING_MODE="rewrite"

  ask_version
  install_target_note
  if [[ ! -f "$CONF_DIR/control.env" && "$KEEP_CONFIG" -eq 1 ]]; then
    warn "未找到 $CONF_DIR/control.env，--keep-config 不生效，按全新安装处理"
  fi
  if [[ -f "$CONF_DIR/control.env" ]]; then
    decide_existing_config
    if [[ "$EXISTING_MODE" == "keep" ]]; then
      run_keep_config
      return 0
    fi
    seed_from_existing_env
  fi

  ask_listen
  ask_database
  ask_redis
  ask_secrets
  ask_accounts
  ask_geoip
  ask_service_options

  # 安装位置与 ACME/运行参数不提问：补齐默认值后统一校验。
  apply_defaults
  validate_defaults

  note "安装位置与 ACME/运行参数使用默认值（见下方汇总）；覆盖同名环境变量或直接编辑 ${CONF_DIR}/control.env 即可调整。"

  summary
  printf '\n'
  if ! confirm "确认按以上参数写入并安装？" "yes"; then
    die "已取消，未做任何修改"
  fi
  apply_from_scratch
}

main "$@"
