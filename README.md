# Lagran CDN

高性能、可自托管的 CDN 系统。

> 完整部署步骤见 [docs/deployment.md](docs/deployment.md)。

- **控制端（Control Plane）**：Rust + Axum + PostgreSQL（sqlx）
- **边缘端（Edge Plane）**：Rust 反向代理 + 内存/磁盘缓存
- **前端**：Nuxt 4 管理后台

## 功能概览

### 控制端 (`apps/control`)
- 健康检查 `GET /health` / `GET /ready`
- 注册 / 登录（bcrypt + JWT）、`GET /api/v1/auth/me`（含角色）
- 项目与成员（多租户）：`/api/v1/projects`、`/projects/{id}/members`
- 域名接入与管理：源站/备源、SSL、限流、CORS、防盗链、回源超时、自定义头
- 缓存规则：路径通配、**请求方法 / 查询串条件**、TTL、优先级、SWR、**动作（cache/bypass/no_store）**、
  **浏览器 TTL 覆盖**、**按规则忽略 Query**、启用/停用与**规则测试器**
- 域名源站支持主备：备用源站可随时启用/修改/清空，端口留空按协议默认 80/443；
  主源站不可用时自动回源到备用源站（含 bypass/动态请求）
- 域名 HTTPS：开启后 HTTP 请求 301/308 跳转到 HTTPS（`EDGE_HTTPS_REDIRECT_PORT` 控制端口）
- 证书：上传、SNI 下发、开发用自动签发（rcgen + ACME challenge 下发）
- 节点管理：预注册节点 + 一键生成安装命令（二进制/Docker）、单节点令牌、启用/停用（下发边缘立即 503）、删除吊销、心跳与 CPU/内存/版本
- 节点调度（Geo/ISP Phase 1）：节点公网 IP / 省份 / 城市 / 运营商 / 权重，`/api/v1/schedule` 按客户端 IP 与
  GeoIP CIDR 表打分返回主备节点；附 PowerDNS pipe backend 接入示例
- 自研权威 DNS（`apps/dns`）：UDP/TCP 53、SOA/NS/A/AAAA、EDNS0 + ECS、调度结果缓存、控制面故障时
  用旧结果兜底；可直接作为 `edge.lagran.net` 的权威服务器
- WAF：按域名开启，托管规则（SQL 注入 / XSS / 路径穿越 / 扫描器 / **RCE / SSRF / XXE / Log4Shell / CRLF**）、
  自定义规则（含**请求头匹配**，拦截/放行/记录/浏览器质询）、IP 黑白名单、观察/拦截模式、
  **安全级别（低/中/高/攻击中）**、事件日志与**统计概览**
- 缓存刷新（purge 扇出到在线边缘）、预热任务
- 统计：总览 / 分域名（24h）、访问日志、操作审计、源站健康

### 边缘端 (`apps/edge`)
- 多域名反向代理（按 Host/SNI 路由）+ 主备源站
- 缓存：`memory`（DashMap + LRU）/ `disk`（文件缓存，按 mtime 淘汰）/ `hybrid`
- 缓存语义：规则 TTL → `Cache-Control`(`s-maxage`/`max-age`) → `Expires` → 默认 TTL；
  `no-store`/`private`/`no-cache`/复杂 `Vary` 不写入；SWR + single-flight 合并回源
- 条件请求（304）、`Age`、`X-Cache` / `X-Cache-Status`、每域名限流、防盗链
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
- 仪表盘 / 项目（含成员管理）/ 域名 / 域名详情 / 规则 / WAF 防护 / 节点管理（安装、启停、删除）/ 刷新 / 统计 / 访问日志 / 审计 / 证书 / 设置
- SPA 模式，登录态存 localStorage；管理员额外可见「边缘节点」「操作审计」

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
bash tests/integration/backup-origin.sh # 端到端：备用源站创建/读取/修改/清空与配置下发
bash tests/integration/failover-https.sh # 端到端：主源站宕机切换备用 + HTTPS 跳转开关
bash tests/integration/schedule.sh # 端到端：节点 Geo/ISP 元数据、调度打分、admin 测试与 PowerDNS 示例
bash tests/integration/dns.sh # 端到端：自研权威 DNS 的 ECS 调度、SOA/NS、TCP、缓存降级
bash tests/integration/nodes.sh # 端到端：节点预注册→安装命令→单节点令牌→上下线→删除
bash tests/integration/cache-rules.sh # 端到端：方法/Query 条件、禁用规则、浏览器 TTL、规则测试器
bash tests/integration/waf.sh   # 端到端：WAF 规则、IP 名单、观察/拦截模式与事件
bash tests/integration/waf-advanced.sh # 端到端：新托管类别、请求头规则、安全级别与统计
bash tests/integration/ttl.sh   # 端到端：TTL 优先级（规则→s-maxage→max-age→Expires→默认）
PGPASS=... bash tests/integration/fresh-db.sh   # 全新库迁移 + demo admin 引导
```

`smoke.sh` 覆盖登录/鉴权、缓存命中、304、no-store/private、Expires、规则 bypass、
POST 透传、purge、按域名规则隔离与多租户隔离。模拟源站见 `tools/mock-origin/origin.rs`。

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| DATABASE_URL | postgres://lagran:lagran@127.0.0.1:5432/lagran | 控制面数据库 |
| CONTROL_BIND | 0.0.0.0:8080 | 控制面监听（兼容 CONTROL_HOST/CONTROL_PORT） |
| JWT_SECRET | lagran-dev-secret-change-me | JWT 签名密钥，生产必须修改 |
| JWT_EXPIRE_HOURS | 72 | Token 有效期（兼容 JWT_EXPIRES_SECS） |
| AGENT_TOKEN | 空 | 边缘 ↔ 控制面共享密钥；配置/证书接口要求携带 |
| CONTROL_PUBLIC_URL | 空 | 控制面公网地址，用于生成节点安装命令；留空按请求 Host 推导 |
| GEOIP_JSON_PATH | ./data/geoip.json | 调度用 CIDR → 国家/省/市/运营商 JSON 表；缺失时按权重/负载调度 |
| SCHEDULE_TTL | 30 | `/api/v1/schedule` 返回的 DNS TTL（秒） |
| EDGE_LISTEN | 0.0.0.0:8081 | 边缘 HTTP 监听 |
| EDGE_HTTPS_LISTEN | 空 | 边缘 HTTPS 监听（需证书） |
| ORIGIN_URL | https://example.com | 默认源站（未接入域名时兜底） |
| CONTROL_URL | http://127.0.0.1:8080 | 控制面地址，支持 https |
| CACHE_TTL | 60 | 未命中规则时的默认 TTL |
| CACHE_CAPACITY | 10000 | 内存缓存条目上限（0=不限） |
| CACHE_BACKEND | memory | memory / disk / hybrid |
| TRUST_PROXY_HEADERS | false | 是否信任 `X-Forwarded-For` 作为客户端 IP（WAF 用；仅前置可信代理时开启） |
| EDGE_HTTPS_REDIRECT_PORT | 空 | 域名开启 HTTPS 后，HTTP→HTTPS 跳转使用的端口；留空取 HTTPS 监听端口，443 时省略 |
| PUBLIC_IP | 空 | 节点公网 IP，随心跳上报给控制面用于 GeoDNS 调度 |
| DNS_LISTEN | 0.0.0.0:53 | 权威 DNS 监听地址（UDP/TCP 同端口） |
| DNS_ZONE | edge.lagran.net | 权威 Zone（客户域名 CNAME 到这里） |
| DNS_TTL | 30 | 调度 A 记录的 TTL（秒） |
| DNS_CACHE_SECS / DNS_STALE_SECS | 5 / 300 | 调度结果缓存与故障时允许的旧结果时间 |
| DNS_FALLBACK_IP | 空 | 控制面不可用且无缓存时返回的兜底 IP |
| DNS_TEST_SERVER | 127.0.0.1:53 | 控制台「DNS 测试」查询的权威 DNS 地址 |
| WAF_REPORT_INTERVAL | 5 | WAF 事件上报间隔（秒），`WAF_REPORT=false` 可关闭 |
| CHALLENGE_SECRET | 空 | 质询 nonce / 免质询 Cookie 的 HMAC 密钥；多节点部署必须一致，留空用 AGENT_TOKEN 派生或随机 |
| RATE_LIMIT_RPS / BURST | 0 | 全局默认限流（0=不限） |

完整列表见 `.env.example`。

## 角色与多租户

- `users.role`: `admin` | `user`；`demo@lagran.dev` 为 `admin`
- 项目成员：`owner` / `admin`（读写）、`member`（只读）
- 非 admin 只能看到自己项目内的域名、规则、证书、统计、访问日志、源站健康
- 非 admin 新建域名且未指定项目时，自动归入其个人 `Default` 项目
- 节点列表与审计日志仅 admin 可见

## 已知限制

- 带 `Cookie` 的请求默认绕过缓存（偏保守）；缓存响应不保存 `Set-Cookie`
- 未实现 Range 分片缓存（Range 请求直接透传）
- 限流为单进程内存态，多实例不共享
- `crates/lagran-proto` / `proto/` 仍是 gRPC 占位，Redis 未接入

## License

MIT
