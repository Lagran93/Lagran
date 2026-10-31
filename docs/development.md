# Development Guide

## Prerequisites

- Rust 1.75+ (推荐 1.82+)
- Node.js 20+ & npm
- Docker（PostgreSQL / Redis）

## Local Setup

```bash
# 1. 启动依赖
./scripts/dev-up.sh
# 或: docker compose -f deploy/docker-compose.yml up -d

# 2. 控制端（会自动 migrate + 写入演示账号）
export DATABASE_URL=postgres://lagran:lagran@127.0.0.1:5432/lagran
cargo run -p control
# 演示账号: demo@lagran.dev / demo123

# 3. 边缘端（支持 HTTPS 回源）
ORIGIN_URL=https://example.com cargo run -p edge

# 4. 前端
cd apps/frontend
npm install
NUXT_PUBLIC_API_BASE=http://localhost:8080 npm run dev
```

## Auth

- 登录 `POST /api/v1/auth/login` → JWT
- 受保护接口需 Header: `Authorization: Bearer <token>`
- 前端 token 存 localStorage，全局路由中间件校验登录态

## Edge HTTPS

`OriginClient` 使用 `hyper-rustls`，`ORIGIN_URL` 可为 `http://` 或 `https://`。

## Heartbeat & Purge

边缘启动后会按 `HEARTBEAT_INTERVAL`（默认 15s）向控制端上报：

```http
POST /api/v1/nodes/heartbeat
{ "region", "ip", "agent_url" }
```

控制端收到 purge 后，向所有 `status=online` 且 `agent_url` 非空的节点请求：

```http
POST {agent_url}/__lagran/purge
```

本地验证：

```bash
# 登录拿 token
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r .token)

# 等边缘心跳后查看节点
curl -s http://127.0.0.1:8080/api/v1/nodes | jq

# 下发 purge
curl -s -X POST http://127.0.0.1:8080/api/v1/purge \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"domain":"cdn.example.com","prefixes":["/"]}' | jq
```

## 新增能力（功能完善）

### 域名
- `PUT /api/v1/domains/{id}` 更新源站 / SSL / 状态

### 缓存规则
- `GET  /api/v1/rules`
- `POST /api/v1/rules`  body: `{ domain_id, path_pattern, ttl_seconds, priority }`
- `DELETE /api/v1/rules/{id}`

### 节点健康
- 控制端每 30s 将超过 60s 未心跳的节点标为 `offline`
- 仪表盘 `online_nodes` / `domain_count` 来自数据库实时统计

### 边缘配置同步
```bash
EDGE_DOMAIN=cdn.example.com \
CONTROL_URL=http://127.0.0.1:8080 \
cargo run -p edge
```
每 30s 拉取 `GET /api/v1/config/{domain}`，自动更新回源地址。

## 边缘指标 / 规则 / 证书

### 指标上报
边缘每 15s `POST /api/v1/metrics/report`：
```json
{ "node_id", "domain", "requests", "cache_hits", "cache_misses", "bytes_sent" }
```
控制端聚合近 24h 写入仪表盘。

### 规则下发
`GET /api/v1/config/{domain}` 返回 `rules[]`。边缘匹配路径通配（`/static/*`）决定 TTL。

### 证书
- `GET/POST /api/v1/certs`
- `DELETE /api/v1/certs/{id}`
- 边缘可读 `GET /api/v1/certs/by-domain/{domain}`（含 PEM，后续用于 HTTPS 终结）

## 边缘 HTTPS 终结

Pingora 负责公共 HTTPS 监听和 TLS 握手，证书回调从 `CERT_DIR` 的
`<domain>.crt` / `<domain>.key` 读取，支持 SNI 热加载和通配符。

```bash
# 1) 本地自签证书
./scripts/gen-dev-cert.sh ./certs cdn.example.com
mkdir -p ./data/certs
cp ./certs/cert.pem ./data/certs/cdn.example.com.crt
cp ./certs/key.pem ./data/certs/cdn.example.com.key

# 2) 启动边缘（HTTP + HTTPS）
EDGE_LISTEN=0.0.0.0:8081 \
EDGE_ADMIN_LISTEN=127.0.0.1:8082 \
AGENT_URL=http://127.0.0.1:8082 \
EDGE_HTTPS_LISTEN=0.0.0.0:8443 \
CERT_DIR=./data/certs \
cargo run -p edge

# 3) 或上传到控制端后由边缘拉取
curl -X POST http://127.0.0.1:8080/api/v1/certs \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d "{\"domain_name\":\"cdn.example.com\",\"cert_pem\":\"$(awk '{printf "%s\\n", $0}' certs/cert.pem)\",\"key_pem\":\"$(awk '{printf "%s\\n", $0}' certs/key.pem)\"}"

curl -k https://127.0.0.1:8443/
```

证书来源优先级：本地 `EDGE_TLS_*` 文件 → 控制端 `GET /api/v1/certs/by-domain/{domain}`（每 60s 热更新）。

## 证书热更新 / SNI / ACME

### 热更新（不重启）
- 边缘使用 `CertStore` + rustls `ResolvesServerCert`
- **新连接**在握手时读取最新证书，无需重启进程
- 推送：`POST {agent}/__lagran/certs/load` 或控制端拉取

### SNI 多证书
- `CertStore` 按 server_name 映射多本证书
- 自动签发 / 上传时以域名名为 SNI 键

### 自动签发（Let's Encrypt）
```bash
curl -X POST http://127.0.0.1:8080/api/v1/certs/issue \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"domain_name":"cdn.example.com","provider":"letsencrypt","push_to_edges":true}'
```

- `provider`：`letsencrypt`（默认，生产）、`letsencrypt-staging`、`dev`
- 生产使用 ACME v2 + HTTP-01：控制面把 token 下发到在线边缘，Let's Encrypt 从公网校验
- ACME 账户密钥持久化在 `acme_accounts` 表（按 directory 区分）
- 控制面每 6 小时检查 `auto_renew` 且在 30 天内到期的 Let's Encrypt 证书并自动续期
- 泛域名 HTTP-01 不支持；泛域名需 DNS-01（未实现）
- 开发可用 `provider: "dev"` 生成本地 rcgen 自签证书

## 域名高级设置 / 预热 / 分域统计

- `GET/PUT /api/v1/domains/{id}/settings` — 忽略 Query、CORS、防盗链、回源超时、自定义头、限流
- `POST /api/v1/prefetch` `{ domain, paths: [] }` — 预热任务入队
- `GET /api/v1/stats/by-domain` — 近 24h 分域名指标

边缘同步配置后生效：忽略 Query 影响缓存键；防盗链校验 Referer；CORS / 自定义头写入响应；回源超时返回 504。

## Agent 鉴权 / WebSocket / 主备源站

### Agent 鉴权
边缘与 DNS 使用不同的凭据：

- **边缘 → 控制**：心跳、指标、源站健康、配置、证书、WAF、访问日志等接口使用 `AgentAuth`，只接受 `edge_nodes.auth_token` 中的**节点 token**。
  - 节点必须先在控制台预注册
  - `NODE_ID` 必须等于该 token 所属节点名
  - 全局 `AGENT_TOKEN` 不能用在这些接口
  - 未知节点不会自动创建
- **DNS → 控制**：`/api/v1/schedule` 使用 `ScheduleAuth`，接受全局 `AGENT_TOKEN` 或合法的节点 token；DNS 不是节点，通常用全局 token。
- **控制 → 边缘**：Purge、证书下发、ACME challenge 使用该节点的 `auth_token`（为空时才回退全局 token）。

升级前自动注册、`auth_token` 为空的旧节点需要重新创建，或手工生成 token 并更新 `edge.env`。

### WebSocket
边缘识别 `Upgrade: websocket` 后，与源站建立隧道转发（简易 TCP 实现）。

### 主备源站
域名可配置 `backup_origin_*`；主源失败或超时后自动尝试备用源。

## 缓存策略（本次增强）

- 规则动作：`cache`（缓存）/ `bypass`（不读不写缓存）/ `no_store`（回源但不写入）
- 规则按**域名**生效，规则表新增 `action`、`swr_seconds`
- TTL 优先级：规则 `ttl_seconds` > 源站 `Cache-Control: s-maxage` > `max-age` > `Expires` > 域名默认 `CACHE_TTL`
- `no-store` / `private` / `no-cache` / 非简单 `Vary` → 永不写入
- `stale-while-revalidate`：规则 `swr_seconds` 或源站指令；过期后先返回 `STALE`，后台单飞刷新
- 同一缓存键的并发未命中由 single-flight 合并，只回源一次
- 条件请求 `If-None-Match` 命中缓存返回 `304`，ETag 优先使用源站值
- 带 `Authorization` / `Cookie` / `Range` 的请求、客户端 `no-cache` 一律绕过共享缓存
- 非缓存方法（POST/PUT/...）完整转发 method/body/headers，响应标 `DYNAMIC`
- 内存缓存按条目 LRU 淘汰；磁盘缓存超过上限按文件 mtime 淘汰最旧部分，且按 key 前缀精确 purge

## 源站故障与错误页

当边缘需要回源、但源站不可用时（且没有可用的缓存副本），返回本地 HTML 提示页：

| 场景 | 状态码 | `X-Lagran-Error` |
|---|---|---|
| 连接被拒绝 / DNS / TLS 失败 | 502 | `ORIGIN_UNREACHABLE` |
| 回源超时 | 504 | `ORIGIN_TIMEOUT` |
| 健康检查已标记源站宕机 | 503 | `ORIGIN_UNHEALTHY` |

- 页面带 `Cache-Control: no-store` 与 `Retry-After: 30`，不会被浏览器/CDN 缓存；
- 页面包含域名、请求路径、错误码与排查建议；
- **缓存仍可用时照常返回 HIT**：健康闸门只作用于"需要回源"的路径，不再拦截缓存命中；
- 后台 SWR 刷新失败只记日志，不影响已经返回的 `STALE` 响应；
- 非缓存方法（POST 等）回源失败同样返回该页面。

覆盖脚本：`tests/integration/ttl.sh` 最后会杀掉 mock 源站，验证"缓存仍新 → HIT"和
"缓存过期 → 502/503 错误页"；`smoke.sh` 用一个关闭端口的域名验证页面内容与响应头。

## 前端控制台

- 设计语言：浅色 Ant Design 风格，主色 `#1677ff`、背景 `#f5f7fa`、白卡片 + 14px 中文排版；
  设计变量与通用样式集中在 `apps/frontend/assets/css/main.css`。
- 布局：左侧按「概览 / 加速服务 / 运维监控 / 系统」分组导航，顶部面包屑 + 运行状态 + 用户菜单。
- 通用组件：`AppIcon`、`BaseModal`、`BaseDrawer`、`AppPagination`、`StatusTag`、`StatCard`、
  `EmptyState`、`ToastHost`（顶部轻提示）、`ConfirmHost`（危险操作二次确认）。
- 交互约定：列表页 = 筛选栏 + 表格 + 分页；新建/编辑用弹窗，详情/高级设置用右侧抽屉；
  删除、停用、全站刷新等走确认弹窗；所有接口反馈用 Toast，不再使用 `alert/confirm/prompt`。
- 模式：SPA（`ssr: false`）。JWT 存在 localStorage，服务端没有可渲染的登录态，关闭 SSR
  可避免水合不一致。

```bash
# Node 由 nvm 管理，非交互 shell 先补 PATH
export PATH="$HOME/.nvm/versions/node/v24.21.0/bin:$PATH"
cd apps/frontend

npm run dev      # http://localhost:3000
npm run build    # 产物在 .output
npm run preview  # 本地预览构建产物
```

## 多租户与角色

- `users.role`: `admin` | `user`（`demo@lagran.dev` 迁移后为 admin）
- 项目成员角色：`owner` / `admin`（读写）、`member`（只读）
- 非 admin 的域名、规则、证书、统计、访问日志、源站健康均按其项目过滤
- 节点列表、审计日志仅 admin 可见
- 新增成员：`POST /api/v1/projects/{id}/members` body `{"email":"a@b.c","role":"member"}`
- 移出成员：`DELETE /api/v1/projects/{id}/members/{user_id}`

## 边缘配置同步与鉴权

- 边缘 `AGENT_TOKEN` 必须等于控制台预注册节点的 `edge_nodes.auth_token`；
  `/api/v1/config`、`/api/v1/certs/edge-sync`、心跳、指标、日志等边缘接口使用 `X-Lagran-Agent-Token`
- 控制面全局 `AGENT_TOKEN` 只用于 DNS `/api/v1/schedule` 调度接口和旧节点回调兜底，不能用于边缘接口
- 未预注册节点不会自动创建；心跳 `NODE_ID` 必须与 token 所属节点一致
- `CONTROL_URL` 支持 `https://`（共享 hyper-rustls 客户端 + 连接复用）
- 配置拉取失败会保留上一次配置，不会清空域名表

## 集成测试

```bash
# 需要 Postgres 与已编译二进制（cargo build -p control -p edge）
bash tests/integration/smoke.sh
```

覆盖：登录/节点接口鉴权、域名接入、MISS→HIT、304、no-store/private、Expires TTL、
规则 bypass、POST 透传、purge、**按域名规则隔离**、多租户隔离。
`tools/mock-origin/origin.rs` 是测试源站（仅标准库，无需 Python）。

```bash
# 全新数据库校验：所有迁移 + demo admin 引导 + 种子数据（需要 postgres 容器）
PG_CONTAINER=postgresql bash tests/integration/fresh-db.sh

# TTL 优先级：规则 → s-maxage → max-age → Expires → 默认（约 15 秒）
bash tests/integration/ttl.sh
```

TTL 优先级同时有契约测试（`apps/edge/tests/ttl_policy.rs`），直接断言
`decide_storage` 的返回值，无需起服务。注意 `Expires` 必须是合法的 HTTP 日期
（星期几也要对），否则 `httpdate` 解析失败会退回默认 TTL。

## 节点调度（Phase 1）

控制面 `/api/v1/schedule` 根据客户端 IP 的 Geo/ISP 信息为域名选择主备节点，供 PowerDNS/CoreDNS
或 App SDK 调用。节点在「边缘节点」中维护 `public_ip / country / province / city / isp / weight`
（安装命令会带上 `PUBLIC_IP`，心跳也会上报）。

### GeoIP 数据

`GEOIP_PATH`（默认 `./data/geoip.dat`）支持两种格式，最长前缀匹配：

1. **V2Ray `geoip.dat`**：来自
   [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)，按国家代码提供 CIDR。
2. **旧版 JSON**：CIDR → 国家/省/市/运营商。

```bash
wget -O data/geoip.dat \
  https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat

GEOIP_PATH=./data/geoip.dat
```

解析规则：

- `.dat` 按 V2Ray `GeoIPList` protobuf 解析（`country_code` / `cidr` / `inverse_match`）
- `.json` 或 `GEOIP_JSON_PATH` 按旧 JSON 解析
- 未知扩展名自动探测内容
- DAT 只保留两个字母的国家代码（`cn` → `CN`），忽略 `private`、`telegram` 等分类
- DAT 没有省/市/运营商，`GeoInfo` 中这些字段为空，只参与国家加分

旧 JSON 示例（需要省/市/运营商时使用）：

```json
[
  {"cidr":"203.0.113.0/24","country":"CN","province":"广东","city":"深圳","isp":"电信"},
  {"cidr":"198.51.100.0/24","country":"CN","province":"北京","city":"北京","isp":"电信"}
]
```

```bash
GEOIP_JSON_PATH=./data/geoip.json
```

文件缺失或为空时退化为按节点权重与负载调度。

### 打分规则

硬过滤：`status=online` 且 `public_ip` 非空。

```
score = weight
      + 5   (同国家)
      + 80  (同省)
      + 20  (同城)
      + 40  (同运营商)
      - cpu% * 0.3
      - mem% * 0.2
```

返回 `primary` / `backup` / `candidates`（前 5）与 `ttl`（`SCHEDULE_TTL`，默认 30s）。
客户端省份/运营商可通过查询参数覆盖，适合 DNS 插件已经解析好 ECS 的场景。

### 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/api/v1/schedule?domain=&ip=&subnet=&province=&isp=` | agent token | DNS 插件/SDK 调用 |
| POST | `/api/v1/schedule/test` | 登录 admin | 控制台「调度测试」 |

`tools/dns/powerdns-pipe.sh` 是最小 PowerDNS pipe backend 示例，配置见
`tools/dns/README.md`。

```bash
bash tests/integration/schedule.sh
```

覆盖：节点元数据、广东/北京/联通打分、显式 Geo 覆盖、admin 测试、停用节点排除、pipe backend 输出。

限制（Phase 1）：无 ECS 解析、无实测 RTT/丢包、无 Anycast；DNS 缓存期内节点切换有延迟。

## 自研权威 DNS（apps/dns）

`apps/dns` 是一个最小权威 DNS 服务，作为 `edge.lagran.net` 的 NS 使用；客户域名 CNAME 到该 Zone。

启动：

```bash
DNS_LISTEN=0.0.0.0:53 \
DNS_ZONE=edge.lagran.net \
CONTROL_URL=http://127.0.0.1:8080 \
AGENT_TOKEN=<agent token> \
DNS_NS_NAME=ns1.edge.lagran.net,ns2.edge.lagran.net \
DNS_NS_IP=203.0.113.53,203.0.113.54 \
./target/debug/lagran-dns
```

行为：

- 支持 UDP/TCP 53；`A / AAAA / SOA / NS`；`ANY` 与递归请求拒绝；越界域名 REFUSED
- 解析 EDNS0 OPT 与 ECS；有 ECS 时按子网查调度，无 ECS 用客户端 IP
- 每次查询调 `/api/v1/schedule`，结果缓存 `DNS_CACHE_SECS`；控制面失败时在
  `DNS_STALE_SECS` 内继续返回旧结果，仍无结果则用 `DNS_FALLBACK_IP`（或 SERVFAIL）
- 响应带 ECS scope，超过 UDP 限制时置 TC 让客户端走 TCP
- TTL 取调度返回的 TTL（默认 30s）；SOA/NS 300s，negative SOA 60s
- 控制台「边缘节点 → DNS 测试」通过控制面 `POST /api/v1/dns/test` 发起真实 DNS 查询，
  目标地址由 `DNS_TEST_SERVER` 指定（默认 `127.0.0.1:53`）

部署要点：

- 注册商把 `edge.lagran.net` 的 NS 指向 `ns1`/`ns2`，并分别配置 glue A
- 至少两台 DNS（不同网络/地域），53 UDP+TCP 放行
- 不建议单机承载生产；Anycast/DNSSEC 属于后续阶段
- 客户域名用 CNAME 接入；apex 域名需要 ALIAS/ANAME 或独立 Zone

测试：

```bash
bash tests/integration/dns.sh
```

覆盖 ECS 分流、TTL、SOA/NS、越界 REFUSED、ANY、AAAA NODATA、TCP、控制面停机后的缓存兜底。

## 域名源站与 HTTPS

- **主/备源站**：域名可配置备用源站（协议 + 主机 + 端口）。主源站连接失败、超时或健康检查
  不通过时，缓存回源与 bypass/动态请求都会自动切到备用源站；备用源站不可用时才返回错误页。
  备用端口留空按协议默认 80/443，主机留空表示不启用。
- **启用 HTTPS**：域名设置 `ssl_enabled=true` 后，边缘对 HTTP 请求返回
  `301`（GET/HEAD）或 `308`（其他方法）跳转到 `https://<host>[:port]<path?query>`，
  跳转发生在 WAF/缓存之前。端口优先级：
  `EDGE_HTTPS_REDIRECT_PORT` → `EDGE_HTTPS_LISTEN` 的端口（443 省略）→ 443。
  HTTPS 本身仍需要边缘已加载对应域名的证书（证书管理/SNI）。
- 若边缘前置了 TLS 终止代理，需设置 `TRUST_PROXY_HEADERS=true` 才会信任
  `X-Forwarded-Proto: https`，否则会被误判为 HTTP 并重定向。

```bash
bash tests/integration/failover-https.sh
```

覆盖：主源站停止后自动切备用、API/bypass 请求同样切换、HTTPS 开关 301/308 跳转与关闭生效。

## 缓存规则

控制台「缓存规则」页支持按域名配置，规则按 `priority` 从高到低匹配，命中即停止：

- **匹配方式**：`glob`（默认）或 `regex`
- **路径/正则**：
  - glob：`/static/*` 前缀、`/img*` 通配、精确路径、`/*` 全部
  - regex：Rust regex 语法，例如 `\\.(css|js)$` 按后缀匹配、`^/assets/` 匹配目录前缀
- **请求方法**：可多选；不选表示全部方法（方法不在缓存键里，仅用于匹配）
- **查询串**：不区分大小写的子串条件（如 `debug=1`）；留空不限制
- **动作**：`cache`（按 TTL 缓存）、`bypass`（不读不写缓存直接回源）、`no_store`（回源但不写缓存）
- **边缘 TTL / SWR**：仅 `cache` 生效；TTL 优先于源站 `s-maxage`/`max-age`/`Expires`
- **浏览器 TTL**：覆盖返回给客户端的 `Cache-Control: max-age`，不影响边缘存储时长；0 = 跟随源站
- **Query 缓存键**：可继承域名设置、强制忽略（`?x=1` 与 `?x=2` 共用缓存）或强制区分
- **Cookie**：默认带 Cookie 的请求绕过共享缓存；规则可勾选 `ignore_cookie`，仅建议用于 CSS/JS/图片等公共静态资源
- **Chrome 重载**：`Cache-Control: max-age=0` 不再直接 BYPASS；边缘用缓存 ETag 校验并返回 `304 REVALIDATED`，不会回源
- **启用/停用**：停用后边缘立即忽略该规则（配置版本号包含此字段，约 15 秒同步）
- **规则测试器**：输入域名 + 路径 + 方法 + 查询串，返回命中的规则和最终生效策略

匹配实现分别在边缘 `apps/edge/src/cache/policy.rs` 与控制面的测试器
（`apps/control/src/api/rule.rs`），字段与优先级语义保持一致。

```bash
bash tests/integration/cache-rules.sh
```

覆盖：方法条件（GET 命中 / HEAD 不命中）、查询串条件、停用规则、浏览器 TTL、
按规则忽略 Query、规则测试器、修改规则下发、启停下发。

## 边缘节点管理

控制台「边缘节点」页（仅 admin）覆盖节点的完整生命周期：

1. **预注册**：填写名称/区域/Agent 地址 → 生成 64 位十六进制单节点令牌，状态 `pending`。
   同时可复制二进制或 Docker 安装命令（含 `CONTROL_URL/NODE_ID/NODE_REGION/AGENT_URL/AGENT_TOKEN/EDGE_LISTEN`）。
2. **接入**：节点启动后每 15 秒（`HEARTBEAT_INTERVAL`）上报心跳，首次心跳把状态从 `pending` 置为 `online`，
   并上报版本、CPU、内存。
3. **启停**：停用 → 控制面把状态置为 `disabled`；下一次心跳响应 `enabled=false`，边缘本地开关关闭，
   代理请求统一返回 **503 节点已停用**页（`X-Lagran-Error: NODE_DISABLED`）。
   健康检查、心跳、刷新、证书等管理接口不受影响，所以节点仍可被重新启用。
4. **编辑**：可改名称/区域/Agent 地址；区域与 Agent 地址一旦非空，心跳不会覆盖（以控制台为准）。
5. **删除**：删除记录并吊销令牌；节点若仍在运行，心跳会被 401 拒绝，不会自动重新注册。

令牌与鉴权：

- `AgentAuth` 接受全局 `AGENT_TOKEN` **或** `edge_nodes.auth_token` 中的任意一个。
- 控制面下发刷新、证书、ACME challenge 时优先使用节点自己的令牌，没有才回退到全局令牌。
- 因此每个节点可以在安装时使用独立令牌；删除节点即撤销其访问权限。

相关 API：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/api/v1/nodes` | 列表 / 预注册 |
| GET/PUT/DELETE | `/api/v1/nodes/{id}` | 详情（含令牌与命令）/ 编辑 / 删除 |
| POST | `/api/v1/nodes/{id}/status` | `{"enabled":false}` 停用，`true` 启用 |
| POST | `/api/v1/nodes/heartbeat` | 边缘心跳（agent token） |

`CONTROL_PUBLIC_URL` 用于生成安装命令；未配置时按请求 Host 推导（反向代理场景建议显式配置）。

```bash
bash tests/integration/nodes.sh
```

覆盖：预注册 → 命令内容 → 单节点令牌鉴权（全局令牌不同）→ 上线 → 停用 503 → 启用恢复 →
编辑区域不被心跳覆盖 → 删除后令牌吊销。

## WAF 防护

控制台「WAF 防护」页按域名配置，默认关闭；开启后默认拦截模式。

- **托管规则**：SQL 注入、XSS、路径穿越、扫描器/敏感路径、命令执行（RCE）、SSRF/云元数据、
  XXE、Log4Shell、CRLF/头注入，每类可单独开关
- **安全级别**：`off | low | medium | high | under_attack`
  - 低：空 User-Agent 的 GET/HEAD 质询
  - 中：低 + 扫描器 UA
  - 高：文档类 GET/HEAD（HTML 导航）质询
  - 攻击中：所有 GET/HEAD 质询，静态资源（css/js/图片/字体/视频）除外
  安全级别在显式规则之后生效，因此放行规则可以豁免；观察模式下只记录不质询。
- **自定义规则**：字段 `path|query|user_agent|referer|method|ip|header:<name>`，
  操作符 `contains|equals|prefix|suffix`，动作 `block|allow|log|challenge`，按 `priority` 从高到低
- **IP 名单**：`allow` 优先于一切检查；`deny` 直接拦截；支持 IPv4/IPv6 与 CIDR
- **浏览器质询**：动作为 `challenge` 时，GET/HEAD 且无有效免质询 Cookie 的客户端会收到一个
  JS 工作量证明页面；浏览器算出满足难度（前导十六进制 0）的 `sha256(nonce:counter)` 后回调
  `/__lagran/challenge/verify`，边缘校验 nonce 签名与 PoW，签发 HttpOnly 的
  `lagran_clearance` Cookie 并 302 回原地址。难度与 Cookie 有效期在域名的「浏览器质询」设置里调整
  （默认难度 4、有效期 1800 秒）。只有 **GET/HEAD 且 Accept 包含 text/html** 的文档导航才会质询；
  API/XHR/POST（如 `POST /api/v1/login`）会跳过质询直接放行，避免登录接口返回 403。
- **模式**：`monitor` 只记录事件不拦截（灰度验证，质询规则也只记录）；`block` 返回 403 拦截页
  （`X-Lagran-WAF: blocked`）或质询页（`X-Lagran-Challenge: 1`），均为 `no-store`

执行顺序：域名解析 → CC 防御 → 限流 → WAF（白名单 → 黑名单 → 托管规则 → 自定义规则）→ 缓存/回源。
被拦截的请求不会到达源站，也不会进入缓存。

配置通过 `/api/v1/config` 随域名下发（版本号包含 WAF 内容，修改后约 15 秒生效）。
事件由边缘缓冲后每 `WAF_REPORT_INTERVAL`（默认 5 秒）`POST /api/v1/waf/events`，
控制台可在事件日志中按域名/动作查询；`GET /api/v1/waf/stats?domain=&days=7` 提供
按动作/类型/天、Top IP/规则/路径的聚合，用于「数据概览」。

```bash
bash tests/integration/waf.sh
```

覆盖：SQLi/XSS/路径穿越/扫描器、自定义规则、IP 黑名单拦截、白名单绕过、
观察模式放行并记录、关闭 WAF 后恢复放行，以及质询页 → PoW → 免质询 Cookie 的完整流程。

```bash
bash tests/integration/waf-advanced.sh
```

## CC 防御（L7 洪水 / 自动封禁）

控制台「域名 → 高级设置」中的 CC 防御按 **客户端 IP + 域名** 统计，默认关闭。

- 每 IP 每秒请求数 `cc_rps` + 突发额度 `cc_burst`，1 秒固定窗口
- 连续 `cc_ban_after` 个窗口超限后，自动封禁该 IP `cc_ban_seconds` 秒
- 封禁期间返回 `429 Too Many Requests`，带 `Retry-After` 和 `X-Lagran-CC: banned`
- `cc_mode=monitor` 只记录事件、不返回 429，适合先观察
- `cc_allow_ips` 支持 IPv4/IPv6 与 CIDR，白名单 IP 不计数、不受已有封禁影响
- 配置随 `/api/v1/config` 下发，约 15 秒生效；限速计数在边缘内存中，自动封禁通过控制面跨节点共享

执行位置在 WAF 之前，避免攻击流量消耗 WAF 匹配和缓存逻辑。客户端 IP 来源受
`TRUST_PROXY_HEADERS` 控制，前置 CDN/反代时需开启并确保只信任可信代理。

```bash
bash tests/integration/cc.sh
```

覆盖：首请求放行、超限自动封禁、429/`X-Lagran-CC`/`Retry-After`、封禁持续、
白名单绕过封禁、monitor 模式只记录不拦截，以及 **跨节点共享封禁**。

### 跨节点共享封禁

边缘检测到自动封禁后：

1. 立即写本地内存封禁，当前节点立刻返回 429
2. 异步上报控制面：`POST /api/v1/cc/bans`（节点 token）
3. 控制面写入 PostgreSQL `cc_bans`，按 `(domain, ip)` 幂等 upsert，并延长到期时间
4. 所有边缘每 `CC_SYNC_INTERVAL` 秒（默认 5）拉取一次 `GET /api/v1/cc/bans`
5. 边缘用共享封禁列表覆盖本地共享层；新节点启动后也会立即拉取，无需等待攻击再次发生

控制面是唯一共享状态，不依赖 Redis。封禁记录带 `expires_at`，过期后控制面查询过滤，
边缘端也会在拉取时移除。上报使用异步任务，不阻塞用户请求；失败只影响本次上报，
本地封禁仍然生效。

控制面接口：

```text
GET    /api/v1/cc/bans         边缘拉取（AgentAuth 节点 token）
POST   /api/v1/cc/bans         边缘上报（AgentAuth 节点 token）
GET    /api/v1/cc/bans/all     控制台查看（Actor 管理员）
DELETE /api/v1/cc/bans/:domain/:ip  手动解封（Actor 管理员）
```

控制台「WAF 防护 → 共享封禁」页可直接查看并解封，支持按域名筛选、查看来源节点和到期时间。

手动 API 查看/解封：

```bash
curl -H "Authorization: Bearer $TOKEN" \
  'https://console.example.com/api/v1/cc/bans/all?domain=cdn.example.com'

curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  'https://console.example.com/api/v1/cc/bans/cdn.example.com/203.0.113.7'
```

边缘环境变量：

```bash
CC_SYNC_INTERVAL=5   # 共享封禁拉取间隔（秒），最小 2
```

注意：

- 限速计数仍是每节点本地统计，跨节点共享的是**封禁结果**，不是每请求计数。
- 控制面不可用时，新封禁只在本节点生效；控制面恢复后，新封禁会继续共享。
- 控制台手动解封后，各节点在下一轮同步时移除共享封禁；已上报过封禁的节点
  会同步清除本地对应封禁（未上报成功的本地封禁仍按本地计时到期）。

覆盖：RCE/SSRF/XXE/Log4Shell/CRLF 新类别、请求头规则、安全级别（攻击中质询文档页、
静态资源豁免、观察模式不质询）与统计聚合。

注意：

- 质询 Cookie 与 nonce 用 `CHALLENGE_SECRET` 做 HMAC 签名；多节点部署必须配置相同值，
  否则 A 节点签发的 Cookie 在 B 节点无效。留空时优先用 `AGENT_TOKEN` 派生，再退化为进程随机值。

- `TRUST_PROXY_HEADERS=true` 时 WAF 信任 `X-Forwarded-For` 的第一个地址。
  只有边缘前面是可信代理（SLB/网关）时才可开启，否则攻击者可以伪造白名单 IP。
- 当前不做请求体检查（WAF 在读取 body 之前执行），不支持正则，也没有 IP 信誉库/地域封禁。
- 安全级别「攻击中」会质询所有非静态资源的 GET/HEAD，包括 API 请求；这类客户端无法执行 JS 时会收到 403，
  建议仅在应急时开启，或配合放行规则豁免 API 路径。

## 已知限制

- 缓存响应不保存 `Set-Cookie`；带 `Cookie` 的请求默认绕过缓存（偏保守，后续可按域名放开）
- 未实现 Range 分片缓存（带 `Range` 的请求直接透传给源站）
- 限流为单进程内存态，多实例不共享
- WebSocket 仅支持 HTTP/1.1，且做纯字节隧道、不解帧
- `crates/lagran-proto`、`proto/` 仍是 gRPC 占位；Redis 未接入



## 安全开关（生产必读）

| 变量 | 默认 | 说明 |
|------|------|------|
| `ALLOW_REGISTER` | `false` | 是否开放 `POST /api/v1/auth/register` |
| `SEED_DEMO` | `true` | 是否写入 demo@lagran.dev / demo123 |
| `REQUIRE_SECURE_SECRETS` | `false` | 为 true 时拒绝默认 JWT_SECRET |
| `LOG_RETENTION_DAYS` | `30` | 访问日志/指标保留天数，0=不清理 |
| `ALLOW_INSECURE_AGENT` | `false` | 边缘 `AGENT_TOKEN` 为空时仍放行管理接口（仅本地） |
| `AGENT_TOKEN` / 节点令牌 | — | 生产必须配置；空 token 时管理接口返回 401 |

密码策略：注册至少 8 位且含字母与数字。登录/注册按邮箱约 60 秒内最多 20 次。


## 边缘数据面路径说明

| 请求类型 | 路径 |
|----------|------|
| 可缓存 GET/HEAD（内存策略命中） | Pingora + `pingora-cache` → 源站 `upstream_peer` |
| BYPASS / 动态 / WebSocket / 磁盘混合等 | 进程内 legacy `handler`（仍经 Pingora 入口） |
| 管理接口 `/__lagran/*`、ACME | Pingora 直接响应 |

Chrome 强制刷新会带 `Cache-Control: max-age=0`；对**可缓存 GET**，Pingora 路径会剥离该头以便 ETag/304 仍可用。若需严格尊重客户端 no-cache，请用规则 `action=bypass`。

可调：`MAX_CACHEABLE_BODY`、`CONFIG_SYNC_INTERVAL_SECS`、`ORIGIN_HEALTH_*`。
