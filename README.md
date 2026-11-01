# Lagran CDN

高性能、可自托管的 CDN 系统。

> 完整部署步骤见 [docs/deployment.md](docs/deployment.md)。  

## 从 GitHub 一键安装

安装器现在按组件独立执行：

```bash
# 控制面（含数据库初始化、systemd、首次启动）
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- control

# 边缘节点（需要先在控制台创建节点并取得节点令牌）
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran \
      AGENT_TOKEN=<节点令牌> NODE_ID=edge-01 \
      bash -s -- edge

# 权威 DNS
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- dns

# 前端静态文件（可选 --with-caddy 生成 Caddyfile 示例）
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- frontend --with-caddy
```

每个组件只安装自己的二进制、env 和 systemd 服务：

- `control`：创建/复用 PostgreSQL 数据库，生成 `control.env`，启动 `lagran-control`。
- `edge`：必须提供节点 `AGENT_TOKEN`，写入 `edge.env`，启动 `lagran-edge`。
- `dns`：写入 `dns.env`，启动 `lagran-dns`；同机安装时会自动复用 `control.env` 的全局 `AGENT_TOKEN`。
- `frontend`：安装静态产物到 `/opt/lagran/web`，不启动后端服务。

需要缓存 100MB～1GB 大文件时，在 edge 安装或 `edge.env` 中启用：

```env
LARGE_CACHE_ENABLED=true
LARGE_CACHE_DIR=/var/lib/lagran/large-cache
LARGE_CACHE_MAX_OBJECT_BYTES=1073741824
```

详细参数：

```bash
./install.sh --help
```

前端产物会安装到 `/opt/lagran/web`，使用 Caddy/Nginx 托管并把 `/api/*`、`/health`、`/ready` 反向代理到 `127.0.0.1:8080`。

## 版本与 CI

- 构建时由 `build.rs` 注入短 Git hash，版本格式为 `0.1.0+4a5f39b`。
- `/health`、`/ready`、Prometheus `lagran_control_info`、控制台「系统设置 → 控制面版本」和节点心跳都会显示该版本。
- [.github/workflows/ci.yml](.github/workflows/ci.yml) 在 push/PR 时执行 Rust 测试和前端静态构建，并始终产出可下载的 `Release bundle artifact`。
- 后端 Release 使用 `x86_64-unknown-linux-musl` 静态编译，生成的 `lagran-control` / `lagran-edge` / `lagran-dns` 不依赖目标机 glibc 版本。
- 真正发布 GitHub Release 需要推送版本 Tag，或在 Actions 页面手动 run workflow 并填写 tag：

```bash
git tag v0.1.0
git push origin v0.1.0
```

普通分支 push 只构建 artifact，不会自动创建不可审核的 Release，这是有意设计。

> GeoDNS 边缘节点调度流程见 [docs/geodns.md](docs/geodns.md)。  
> 本地编译、上传并重启服务的脚本见 [deployed.sh](deployed.sh)。

- **控制端（Control Plane）**：Rust + Axum + PostgreSQL（sqlx）
- **边缘端（Edge Plane）**：Rust 反向代理 + 内存/磁盘缓存
- **前端**：Nuxt 4 管理后台

## 功能概览

### 控制端 (`apps/control`)
- 健康检查 `GET /health` / `GET /ready`
- 注册 / 登录（bcrypt + JWT）、图片验证码（`CAPTCHA_ENABLED`，默认开启）、`GET /api/v1/auth/me`、个人资料与改密（`PUT /auth/me`、`PUT /auth/me/password`）
- 用户管理（admin）：`/api/v1/users` 创建、角色调整、启用/禁用、重置密码、删除；禁止自降权/自禁用并保护最后一个管理员
- 项目与成员（多租户）：`/api/v1/projects`、`/projects/{id}/members`，支持成员角色调整
- 域名接入与管理：多源站池（权重/优先级/启用状态）、SSL、限流、CORS、防盗链、回源超时、自定义头
- 缓存规则：路径通配 / **正则匹配（按 .css/.js 等后缀）**、**请求方法 / 查询串 / 响应 Content-Type 条件**、TTL、优先级、SWR、
  **动作（cache/bypass/no_store）**、**浏览器 TTL 覆盖**、**按规则忽略 Query / Cookie**、启用/停用与**规则测试器**
- 域名支持多源站池：按优先级分组，同优先级按权重加权轮询；健康检查失败的源站自动跳过，
  全部异常时仍尝试可用源站；连接失败/读超时按顺序重试，兼容原有主备源站配置
- 域名 HTTPS：开启后 HTTP 请求 301/308 跳转到 HTTPS（`EDGE_HTTPS_REDIRECT_PORT` 控制端口）
- 证书：上传、SNI 下发、**Let's Encrypt（ACME v2 / HTTP-01）生产签发**、Staging 调试、自动续期
- 节点管理：预注册节点 + 一键生成安装命令（二进制/Docker）、单节点令牌、启用/停用（下发边缘立即 503）、删除吊销、心跳与 CPU/内存/版本
- 节点调度（Geo/ISP Phase 1）：节点公网 IP / 省份 / 城市 / 运营商 / 权重，`/api/v1/schedule` 按客户端 IP 与
  **V2Ray/Loyalsoldier `geoip.dat` 或旧版 JSON** 打分返回主备节点；附 PowerDNS pipe backend 接入示例
- 自研权威 DNS（`apps/dns`）：UDP/TCP 53、SOA/NS/A/AAAA、EDNS0 + ECS、调度结果缓存、控制面故障时
  用旧结果兜底；可直接作为 `edge.lagran.net` 的权威服务器
- WAF：按域名开启，托管规则（SQL 注入 / XSS / 路径穿越 / 扫描器与敏感文件 / RCE / SSRF / XXE / Log4Shell / CRLF / SSTI / NoSQL / LDAP / Java 反序列化 / WebShell / 协议异常）、
  自定义规则（含**请求头匹配**，拦截/放行/记录/浏览器质询）、IP 黑白名单、观察/拦截模式、
  **安全级别（低/中/高/攻击中）**、事件日志与**统计概览**
- CC 防御：按域名 + 客户端聚合组限速（IPv4 /24、IPv6 /64）、突发额度、**连续超限自动封禁**、CIDR 白名单、
  观察模式与 429 限流响应；配置 `REDIS_URL` 后使用 Redis 滑动窗口在多个 Edge 间共享计数，未配置时回退到
  进程内固定窗口；登录/API/静态/下载路径使用独立预算（静态 8x、下载 2x、登录 1/2，API 与动态 1x）；
  **域名全局限流 RPS** 触发 60 秒自动攻击模式，客户端限额减半；HTML 浏览器首次超限返回 PoW 挑战，
  通过 clearance 后获得 2x 临时预算，持续超限才 429/封禁；
  **控制面统一封禁库与跨节点同步**，支持管理员手动添加 IP/CIDR 封禁、解封、审计记录，
  控制台「WAF 防护 → 共享封禁」展示 24h 限流/挑战/封禁统计与当前封禁列表；
  可选 `CC_BEHAVIOR_ENABLED=true` 启用轻量行为评分（UA / Accept-Language / Sec-CH-UA /
  Sec-Fetch-Mode / Cookie），可疑 HTML 请求先进入 PoW 挑战而不是直接封禁
- 缓存刷新（purge 扇出到在线边缘），支持按 URL / 路径前缀 / **缓存标签（Surrogate-Key / Cache-Tag）** 批量刷新；
  **预热任务**与**定时预热**（控制面按间隔创建任务并分发到在线边缘）
- 缓存诊断：响应头 `X-Lagran-Cache-Reason` 给出 cookie / authorization / no-store / no-cache /
  vary:user-agent / rule-bypass / content-type-bypass 等原因；控制台「缓存诊断」优先让在线边缘本地执行真实请求
  （避免控制面到公网域名的 DNS/回环/TLS 依赖），并返回原因与处理建议；大视频/流媒体诊断自动使用
  `Range: bytes=0-0` 探测，不会整包下载。域名诊断在服务器漏发中间证书时会通过 AIA 自动补全证书链
- **Range 缓存**：完整对象已缓存时按小段 Range 切片返回 206 / `Content-Range`；开放范围（`bytes=0-`）
  和大范围 Range 由 Pingora 流式透传，避免视频被整包下载导致回源超时
- **大对象流式缓存（Phase 2/3，可选）**：`LARGE_CACHE_ENABLED=true` 后，带 `Content-Length` 的
  200 响应会以分块方式直接写入独立磁盘目录，命中时按块流式读回，不再把 100MB～1GB 对象整体放进
  `Bytes`/`BytesMut`。首次 Range 请求会落盘实际请求的 segment，后续被已缓存 segment 覆盖的 Range
  直接命中；segment 合并覆盖完整对象后自动转为完整缓存。
- **Origin Shield / 分层缓存**：可选 `shield_url` 优先回源并保留域名 Host，Shield 异常自动回退；边缘支持
  `memory` / `disk` / `hybrid`（L1 内存 + L2 磁盘）分层存储
- **配置版本与灰度发布**：域名/规则/WAF/高级设置变更自动生成版本快照与字段级 Diff；支持一键回滚、
  发布单审批、按域名选择版本、按节点灰度、发布前 Dry-run；目标节点全部上报成功后才全量生效，
  上报失败或 120 秒未上报自动回滚。域名首次发布后会进入“发布版本”模式：后续编辑只产生新版本，
  需要新的发布单才会切换，避免未审批变更直接生效
- **控制台体验**：统一分页与批量操作（域名批量启停/删除）、CSV 导出、深色模式、中英文导航切换、
  PWA 安装/离线壳；新增域名接入向导和域名诊断（DNS/证书/回源/缓存）
- **流量观测**：实时流量曲线（15 秒刷新）、请求数/流量/命中率切换、上一时间段对比、
  7 天/24 小时/1 小时范围，以及全屏大屏监控模式
- 统计：总览 / 分域名（24h）、访问日志、操作审计、源站健康
- 写入与读取优化：访问日志、WAF 事件、边缘指标使用 PostgreSQL `UNNEST` 单语句批量写入；
  批量配置文档带进程内短 TTL 缓存和 ETag；连接池大小、预热连接数、获取超时可配置
  （`DATABASE_MAX_CONNECTIONS` / `DATABASE_MIN_CONNECTIONS` / `DATABASE_ACQUIRE_TIMEOUT_SECS`）
- 可选 Redis P1（`REDIS_URL`）：共享登录限流、验证码、Actor 会话缓存、批量配置缓存、
  告警/预热/发布扫描分布式锁，以及边缘指标实时计数器（`GET /stats/realtime`）。
  Redis 不可用时自动回退到进程内状态/PostgreSQL，不影响主流程
- 可观测性：`GET /metrics` Prometheus 文本指标（控制面/数据库/域名/节点/源站健康/证书到期/告警）、
  可选 OTLP/HTTP Trace 导出；边缘 `GET /__lagran/metrics` 输出请求/命中/回源/流量指标
- 告警中心：源站健康、证书到期、节点离线、缓存命中率、WAF 事件突增规则；邮件 SMTP、Webhook（可选 HMAC-SHA256 签名）、
  Telegram 通知；事件去重、恢复通知、冷却时间与历史记录。普通用户只能查看和管理自己创建项目下的
  告警渠道、规则与事件，「边缘节点离线」规则仍仅管理员可见可管。Telegram 渠道支持自定义 API 反代地址和
  HTTP(S)/SOCKS5 代理，也会读取 `HTTPS_PROXY` / `ALL_PROXY`，适合无法直连 Telegram 的服务器

### 边缘端 (`apps/edge`)
- **Pingora 公共网络层**：HTTP/1.1 + HTTP/2、HTTP/HTTPS 监听、SNI 动态证书、连接管理；
  所有域名请求先做 WAF/CC/限流/防盗链/HTTPS 预检；可缓存 GET 走 `pingora-cache` + `upstream_peer`，BYPASS/动态请求和 WebSocket 直接 `upstream_peer` 流式转发；HEAD 由同进程引擎回源 GET 并复用 GET cache key（HTTP/2 返回真实 Content-Length，HTTP/1.1 使用 0 兼容 Pingora H1 编码器）；health/ACME/challenge verify/管理接口由 Pingora 直接响应；未知/旧模式域名在进程内调用旧引擎，无 loopback 监听
- 多域名反向代理（按 Host/SNI 路由）+ 多源站加权负载均衡
- 缓存：`memory`（DashMap + LRU）/ `disk`（文件缓存，按 mtime 淘汰）/ `hybrid`
- 缓存语义：规则 TTL → `Cache-Control`(`s-maxage`/`max-age`) → `Expires` → 默认 TTL；
  `no-store`/`private`/无规则 TTL 的 `no-cache`/复杂 `Vary` 不写入；显式规则 TTL 可覆盖源站 `no-cache`；
  `ignore_cookie` 同时放行 `Vary: Cookie`；`lagran_clearance` 是 Edge 内部 Cookie，
  不参与缓存绕过，也不会转发给可缓存请求的源站；`Vary: Accept-Language` 的 key 含语言哈希；
  ETag 基于响应 body；SWR + single-flight 合并回源
- 条件请求（304）、`Age`、`X-Cache` / `X-Cache-Status`、`X-Lagran-Cache-Reason`、每域名限流、防盗链
- WAF：托管特征匹配 + 自定义规则 + IP 白/黑名单，支持观察模式；命中后返回 403 拦截页并上报事件
- WAF 安全级别：低/中/高/攻击中，按 UA 与请求类型自动下发浏览器质询；静态资源不受影响
- WAF Challenge：规则动作为「质询」时返回 JS 工作量证明页面，通过后签发 HMAC 签名的免质询 Cookie
- 源站故障（宕机/超时/健康检查失败）且无可用缓存时，返回本地 HTML 提示页
  （502/504/503，`no-store` + `X-Lagran-Error`），不会把裸文本或空响应给访客
- POST/PUT 等请求完整透传 method/body/headers；WebSocket 隧道（HTTP/1.1）
- HTTPS 终结：SNI 多证书热加载、ACME HTTP-01 challenge
- 访问日志（异步写入 + 批量上报）

### 前端 (`apps/frontend`)
- 浅色管理控制台（Ant Design 风格、主色 `#1677ff`）：分组侧边栏 + 面包屑 + 表格/筛选/分页
- 仪表盘 / 项目（含成员管理）/ 域名 / 域名详情 / 规则 / WAF 防护 / 节点管理（安装、启停、删除）/ 刷新 / 统计 / 告警中心 / 访问日志 / 审计 / 证书 / 设置
- SPA 模式，登录态存 localStorage；告警中心对普通用户开放（节点离线规则除外），管理员额外可见「边缘节点」「操作审计」

## 快速启动

```bash
# 依赖（PostgreSQL）
docker compose -f deploy/docker-compose.yml up -d

# 控制端（默认 0.0.0.0:8080；自动执行 migrations 并写入演示账号）
cargo run -p control
# 演示账号: demo@lagran.dev / demo123（迁移后为 admin）

# 边缘端（默认 0.0.0.0:8081）
ORIGIN_URL=http://example.com cargo run -p edge

# 前端
cd apps/frontend && npm install && npm run dev
```

### 验证

```bash
curl -s http://127.0.0.1:8080/health
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r .token)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/domains | jq

curl -i http://127.0.0.1:8081/            # 第一次 MISS
curl -i http://127.0.0.1:8081/            # 第二次 HIT（源站可达时）
```

## 测试

```bash
cargo test --workspace          # 单元/契约测试（含 TTL 优先级矩阵）
cargo clippy --workspace --all-targets
bash tests/integration/smoke.sh # 端到端：控制面+边缘+模拟源站（需 Postgres）
bash tests/integration/users.sh # 端到端：注册、用户管理、禁用、改密、项目成员角色
bash tests/integration/head-h2.sh # 端到端：HTTP/2 HEAD 真实长度、HTTP/1.1 HEAD 0、GET 不污染
bash tests/integration/multi-origin.sh # 端到端：多源站权重/优先级/故障接管/逐源站健康
bash tests/integration/alerting.sh # 端到端：告警渠道/规则/触发/恢复/Webhook 通知/Prometheus
bash tests/integration/backup-origin.sh # 端到端：备用源站创建/读取/修改/清空与配置下发
bash tests/integration/failover-https.sh # 端到端：主源站宕机切换备用 + HTTPS 跳转开关
bash tests/integration/origin-health.sh # 端到端：健康探测标记 down/恢复后主备选择
bash tests/integration/ws-echo.sh # 端到端：WebSocket 101 + text/binary/ping/close 帧回显（需 perl）
bash tests/integration/http-optimizations.sh # config/cert ETag/304、metrics 批量、access/WAF gzip
bash tests/integration/schedule.sh # 端到端：节点 Geo/ISP 元数据、调度打分、admin 测试与 PowerDNS 示例
bash tests/integration/dns.sh # 端到端：自研权威 DNS 的 ECS 调度、SOA/NS、TCP、缓存降级
bash tests/integration/nodes.sh # 端到端：节点预注册→安装命令→单节点令牌→上下线→删除
bash tests/integration/cache-rules.sh # 端到端：方法/Query 条件、禁用规则、浏览器 TTL、规则测试器
bash tests/integration/cache-diagnostics.sh # 端到端：缓存原因头、标签刷新、Range 切片、预热/定时预热、Origin Shield
bash tests/integration/config-releases.sh # 端到端：版本历史/Diff/回滚、审批、节点灰度、Dry-run、失败自动回滚
bash tests/integration/waf.sh   # 端到端：WAF 规则、IP 名单、观察/拦截模式与事件
bash tests/integration/waf-advanced.sh # 端到端：新托管类别、请求头规则、安全级别与统计
bash tests/integration/ttl.sh   # 端到端：TTL 优先级（规则→s-maxage→max-age→Expires→默认）
PGPASS=... bash tests/integration/fresh-db.sh   # 全新库迁移 + demo admin 引导
```

`smoke.sh` 覆盖登录/鉴权、缓存命中、304、no-store/private、Expires、规则 bypass、
POST 透传、purge、按域名规则隔离与多租户隔离。模拟源站见 `tools/mock-origin/origin.rs`。

## 环境变量

环境变量按应用拆分，完整默认值、取值范围、安全说明均写在对应文件中：

| 文件 | 应用 | 内容 |
|---|---|---|
| [control.env.example](control.env.example) | control | 监听、PostgreSQL、Redis、JWT、ACME、GeoIP、OTel、告警、Telegram |
| [edge.env.example](edge.env.example) | edge | 监听、节点令牌、回源/缓存、TLS、WAF、限流、健康检查、访问日志 |
| [dns.env.example](dns.env.example) | dns | 监听、权威 Zone/NS/SOA、控制面调度、缓存与兜底 |
| [frontend.env.example](frontend.env.example) | frontend | Nuxt API 地址、构建期/运行时说明 |

使用原则：

- 每个进程只加载自己对应的 env 文件；
- 生产环境不要沿用示例中的开发密码、JWT 密钥和节点令牌；
- `NUXT_PUBLIC_API_BASE` 是构建期公开变量，修改后必须重新 generate/build；
- Redis 未配置时，P1 功能自动回退到进程内状态/PostgreSQL；
- 完整变量说明以四份 env 文件为准，本文不再维护重复表格。

## 角色与多租户

- `users.role`: `admin` | `user`；`demo@lagran.dev` 为 `admin`
- `users.is_active=false` 的账号不能登录，已有 JWT 也会被 `Actor`/`/auth/me` 拒绝
- 密码修改 / 管理员重置密码会递增 `users.token_version`，旧 JWT 立即失效；自助改密返回新 token
- `ALLOW_REGISTER=true` 时开放 `/register`；新用户默认 `user` 并自动创建个人 `Default` 项目
- admin 可管理全部用户；不能禁用/降权/删除自己，且不能移除最后一个启用中的 admin
- 项目成员：`owner` / `admin`（读写）、`member`（只读）；owner 不可被改角色或移除
- 非 admin 只能看到自己项目内的域名、规则、证书、统计、访问日志、源站健康
- 非 admin 新建域名且未指定项目时，自动归入其个人 `Default` 项目
- 节点列表与审计日志仅 admin 可见

## 系统升级与捐赠

管理员可在「系统设置 → 系统升级」检测 GitHub 最新 Release。检测到新版本后点击「立即更新」：

1. 控制面写入更新请求；
2. root 权限的 `lagran-update.path` 触发更新助手；
3. 下载 Release、校验 `SHA256SUMS`、备份旧二进制；
4. 替换控制面 / Edge / DNS 二进制和 Web 静态文件；
5. 重启已启用的服务。

更新助手由 `install.sh control` 安装；旧版本需重新执行一次安装命令以启用该功能。

捐赠地址已经内置在控制面代码中，无需额外配置环境变量，会在「系统设置 → 加密货币捐赠」中直接展示。

## 已知限制

- 带 `Cookie` 的请求默认绕过缓存（偏保守）；缓存响应不保存 `Set-Cookie`
- Range 缓存以完整对象为存储单位（命中完整对象时切片）；未命中 Range 直接透传源站，多段 Range 同样透传
- 大对象缓存按 Range 覆盖区间记录已缓存 segment；首次 Range 只缓存实际请求范围，不会补齐未请求部分；多段 Range 仍回源
- 普通域名限流为单进程内存态，多实例不共享；CC 防御配置 `REDIS_URL` 后可跨 Edge 共享滑动窗口计数
- CC 为 L7 请求层防护；SYN/UDP/连接耗尽等 L4 流量型攻击仍需云清洗、上游清洗或 nftables/运营商联动
- `CC_BEHAVIOR_ENABLED` 为轻量启发式评分，不是完整设备指纹；默认关闭，需按业务验证误报
- `crates/lagran-proto` / `proto/` 仍是 gRPC 占位；Redis 已可选接入，未配置时自动回退到进程内状态/PostgreSQL

## 加密货币捐赠

Lagran CDN 的持续开发、测试基础设施和节点运维接受加密货币捐赠。捐赠完全自愿，不影响软件许可，也不附带服务等级或商业承诺。

> **维护者提示：跨链或错误网络转账可能永久丢失。**

| 网络 | 资产 | 地址 |
|---|---|---|
| Bitcoin | BTC | `bc1qgh9dvqa4d0skn82n7t423jnxy7mh3prgxcxc0z` |
| Ethereum | ETH / ERC-20 USDT / USDC | `0xCFf627A0D499e898b209300cA7192F55f01bAB2F` |
| TRON | TRX / TRC-20 USDT | `TFRZmHNyp54fg9BsCXaJH2UVq1B2yUNN8S` |
| Solana | SOL / SPL USDC | `AkpkuUTaReYb4QSgwFfbHZv6CwoesqfGAKPodDxa6x3T` |
| BNB Smart Chain | BNB / BEP-20 USDT | `0xCFf627A0D499e898b209300cA7192F55f01bAB2F` |
| Polygon | POL / polygon USDT | `0xCFf627A0D499e898b209300cA7192F55f01bAB2F` |

注意事项：

- 请只向对应网络转账；ERC-20、TRC-20、BEP-20 等资产必须使用匹配的网络。
- 捐赠地址仅从本仓库 README 或官方发布页获取，谨防仿冒地址。
- 加密货币交易不可逆，转错网络或地址无法退款。
- 如捐赠用于特定目标，请在转账备注/邮件中说明；链上交易本身无法备注。

## 获取技术支持

Telegram Group: https://t.me/lagranedge

## 免责声明

> 本免责声明适用于本仓库中的源代码、文档、脚本、配置示例、安装包及发布产物。使用、部署或分发本项目前，请仔细阅读并理解以下内容。

Lagran CDN 是一个自托管的 CDN 控制面、边缘节点、权威 DNS 与安全防护项目。本项目按 **“现状”（AS IS）** 提供，不附带任何明示或默示的保证，包括但不限于适销性、特定用途适用性、不侵权、无错误、不中断或满足特定合规要求的保证。

1. **使用风险自担**
   使用者应自行评估本项目是否适合其业务、网络环境、数据规模和合规要求。因使用或无法使用本项目导致的任何直接、间接、附带、特殊、惩罚性或后果性损失，包括但不限于业务中断、流量损失、数据丢失、数据泄露、利润损失、商誉损失或第三方索赔，均由使用者自行承担。

2. **合法合规责任**
   使用者应确保其部署和使用行为符合所在地及服务对象所在地适用的法律法规、行业规范和第三方协议，包括但不限于网络安全、数据保护、个人信息保护、内容版权、ICP/备案、跨境数据传输、密码管理、日志留存和出口管制要求。本项目不构成对任何特定司法辖区合规性的承诺或保证。

3. **安全与配置责任**
   CDN、WAF、DNS、证书、限流、CC 防护和访问控制均不能保证拦截所有攻击或避免所有故障。使用者应自行负责：
   - 密钥、令牌、数据库和管理接口的安全保管与轮换；
   - 源站、边缘节点、DNS 和证书配置的正确性；
   - 容量规划、备份、灾备、监控和应急响应；
   - 及时安装安全更新并审计配置变更。

4. **数据与隐私**
   本项目可能处理访问日志、客户端 IP、请求路径、WAF 事件、源站健康数据和账号信息。使用者应自行确定数据处理的法律依据、保留期限、访问权限和删除机制，不得将本项目用于未经授权的监控、追踪或数据收集。

5. **第三方服务**
   本项目可能集成 PostgreSQL、Redis、Let's Encrypt/ACME、Telegram、Webhook、云厂商、DNS 注册商及其他第三方服务。第三方服务的可用性、价格、接口变更、限流、封禁、数据政策和法律责任由对应服务提供方承担。维护者不对第三方服务的中断、变更或数据损失负责。

6. **CDN、WAF 与 DNS 效果**
   CDN 加速效果、缓存命中率、WAF 拦截率、DNS 解析结果和源站可用性受网络、运营商、源站、配置、攻击流量和第三方因素影响，不构成任何性能指标（SLA）承诺。WAF 规则可能存在误报或漏报，使用者应先在观察模式验证，并保留人工处置流程。

7. **责任限制**
   在适用法律允许的最大范围内，本项目维护者、贡献者、版权持有人及相关人员不对因使用或无法使用本项目产生的任何索赔、损害、损失或费用承担责任，无论其基于合同、侵权、严格责任或其他法律理论，也无论是否已被告知发生此类损害的可能性。

8. **捐赠**
   加密货币捐赠完全自愿，不构成购买服务、投资、股权、收益承诺或任何形式的商业对价，也不附带技术支持、服务等级、发票、退款或特定功能承诺。

9. **非法律意见**
   本文档不构成法律、税务、会计或安全合规建议。涉及合规、隐私、内容责任或商业部署时，请咨询具备相应资质的专业顾问。

10. **与开源许可证的关系**
    本免责声明不修改、不限制也不替代 [AGPL-3.0-only](LICENSE) 授予的权利与义务。若本声明与 AGPL 许可证条款存在冲突，以 AGPL 许可证条款为准；AGPL 中关于无担保和责任限制的条款同样适用。

继续使用、部署或分发本项目，即表示你已阅读、理解并同意自行承担相关风险。

## License

Lagran CDN 使用 **GNU Affero General Public License v3.0 only**（`AGPL-3.0-only`）。

- 完整许可文本：[LICENSE](LICENSE)
- 允许商业使用、修改和分发；
- 如果修改后通过网络向用户提供服务，必须按 AGPL 第 13 条向这些用户提供对应的完整源代码；
- 分发时必须保留版权与许可声明，并以 AGPL-3.0-only 授权整个衍生作品；
- 本软件不提供任何明示或默示担保。

Copyright (C) 2026 Lagran CDN contributors.

> 在本次许可变更前已经按 MIT 发布的版本，仍适用其当时附带的 MIT 许可；本次变更不影响那些历史副本的既有授权。
