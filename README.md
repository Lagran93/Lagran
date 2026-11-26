# Lagran CDN

高性能、可自托管的 CDN 系统，包含控制面、边缘节点、权威 DNS 与管理控制台。

- 边缘：Rust + Pingora，HTTP/1.1/2、TLS/SNI、反向代理
- 控制面：Rust + Axum + PostgreSQL
- 控制台：Nuxt 4 + Pinia
- 许可：AGPL-3.0-only

## Demo

- 在线演示：https://console.lagrancdn.com
- 演示账号：`demo@lagrancdn.com` / `demo123456`
- 管理员账号：由部署初始化或首个账号创建，项目不提供公开管理员密码


## 快速导航

| 内容 | 文档 |
|---|---|
| 使用、缓存/Range/CC/WAF 调试 | [docs/manual.md](docs/manual.md) |
| 完整部署步骤 | [docs/deployment.md](docs/deployment.md) |
| 本地开发与测试 | [docs/development.md](docs/development.md) |
| 架构与数据流 | [docs/architecture.md](docs/architecture.md) |
| GeoDNS 调度 | [docs/geodns.md](docs/geodns.md) |
| Origin Shield 配置 | [docs/Origin Shield配置.md](<docs/Origin Shield配置.md>) |

---

## 功能概览

### 边缘节点

- Pingora HTTP/HTTPS/HTTP2、SNI 动态证书、Host 路由
- 多源站池：优先级、权重、健康检查、故障切换、Origin Shield
- 内存 / 磁盘 / 混合缓存；ETag、304、SWR、single-flight
- 大对象流式缓存与固定分片 Range：
  - 默认 1 MiB 分片，只有完整覆盖的分片才算已缓存
  - 首次 Range 对齐到分片边界，后续只回源缺失分片
  - 单段、后缀和 16 段以内的多段 `multipart/byteranges`
  - 逻辑容量硬上限、文件系统空闲下限、LRU 驱逐和 active writer pin
  - 填充队列预算、多源站 failover、容量/丢弃/回源指标
- WAF：托管规则、自定义规则、IP/CIDR 黑白名单、Geo/ASN 黑白名单（MaxMind GeoLite2）、观察/拦截/质询
- CC：IPv4 `/24`、IPv6 `/64` 聚合，路径预算，全局阈值 + 自动攻击模式，PoW 挑战
- 共享封禁、CIDR 封禁、跨 Edge 同步、可选行为评分
- WebSocket、防盗链、CORS、自定义头、访问日志、源站错误页

### 控制面

- JWT 登录、图片验证码、用户/项目/多租户权限
- 域名、源站池、缓存规则、高级设置
- 证书上传、Let's Encrypt ACME HTTP-01、自动续期
- 边缘节点预注册、节点令牌、心跳、启停、Geo/ISP 调度
- 缓存刷新、预热任务、定时预热
- 配置版本、Diff、审批、灰度发布、自动回滚
- 统计、访问日志、操作审计、源站健康
- 告警：SMTP / Webhook / Telegram
- 系统升级（GitHub Release + SHA256 校验）

### DNS

- 自研权威 DNS：UDP/TCP、SOA/NS/A/AAAA
- EDNS0 + ECS 地理调度
- 调度缓存、控制面故障降级、兜底 IP

### 控制台

- Nuxt 4 SPA，浅色/深色模式，中英文导航
- 仪表盘、域名、规则、WAF、节点、证书、刷新、统计、告警、日志
- 域名接入向导、缓存诊断、域名诊断
- 全屏大屏监控、PWA

---

## 一键安装

安装器按组件独立执行：

```bash
# 控制面（含 PostgreSQL 初始化、systemd、首次启动）
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- control

# 边缘节点（AGENT_TOKEN 需先在控制台创建节点后获取）
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran \
      AGENT_TOKEN='<节点令牌>' NODE_ID='edge-01' \
      bash -s -- edge

# 权威 DNS
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- dns

# 前端静态文件（可选生成 Caddyfile 示例）
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- frontend --with-caddy
```

默认路径：

```text
/opt/lagran/bin       二进制
/opt/lagran/web       前端静态文件
/etc/lagran           control.env / edge.env / dns.env
/var/lib/lagran       缓存、证书、运行数据
```

查看全部参数：

```bash
./install.sh --help
```

### 大文件缓存

需要缓存大对象（默认 8 MiB～1 GiB）时，在 `/etc/lagran/edge.env` 启用：

```env
LARGE_CACHE_ENABLED=true
LARGE_CACHE_DIR=/var/lib/lagran/large-cache
LARGE_CACHE_MIN_OBJECT_BYTES=8388608
LARGE_CACHE_MAX_OBJECT_BYTES=1073741824
# 逻辑容量硬上限；writer 还会检查 LARGE_CACHE_MIN_FREE_BYTES
LARGE_CACHE_MAX_BYTES=21474836480
# 0 = 使用 LARGE_CACHE_MAX_OBJECT_BYTES；可设 268435456 限制单对象
LARGE_CACHE_FILL_MAX_BYTES=0
# Range 固定分片；只有缺失分片才回源
LARGE_CACHE_CHUNK_BYTES=1048576
# 单 fill 队列 / 进程总预算
LARGE_CACHE_FILL_QUEUE_BYTES=134217728
LARGE_CACHE_FILL_QUEUE_TOTAL_BYTES=268435456
# 缓存盘必须保留的空闲空间
LARGE_CACHE_MIN_FREE_BYTES=1073741824
```

修改后重启：

```bash
systemctl restart lagran-edge
```

Range 行为：

- 只有完整覆盖分片才进入缓存；
- 首次请求从分片边界开始填充，客户端只收到自己请求的字节；
- 后续请求按 `ChunkPlan` 只回源缺失分片；
- 多段 `bytes=0-1,4-5` 会返回 `multipart/byteranges`，冷请求按首尾包络填充；
- writer 开始前同时检查逻辑上限和 `LARGE_CACHE_MIN_FREE_BYTES`；
- 空间不足时先 LRU 驱逐；仍不足则放弃 fill，客户端响应不受影响。

大缓存是**节点本地**缓存；不同 Edge 节点各自维护分片状态，不做跨节点合并。

### Origin Shield

推荐把区域内的一个大缓存 Edge 作为 Origin Shield：

```text
普通 Edge
  → 本地 L3 命中则直接返回
  → 本地没有则向 Origin Shield 请求
  → Shield 命中则返回
  → Shield 没有才回源
```

Shield 节点配置：

```env
LARGE_CACHE_ENABLED=true
LARGE_CACHE_DIR=/var/lib/lagran/large-cache
LARGE_CACHE_MAX_BYTES=21474836480
LARGE_CACHE_MIN_FREE_BYTES=1073741824

# 仅专用 Shield 节点开启，避免 Shield 自己回源到自己
EDGE_SHIELD_DISABLED=true
```

普通 Edge 保持：

```env
EDGE_SHIELD_DISABLED=false
```

管理员配置：

```text
系统 → Shield 节点 → 新增 Shield
```

填写平台信任的 Shield 内部地址，例如：

```text
https://shield-s1.internal.example.com
```

域名配置：

```text
域名列表 → 目标域名 → 高级设置 → Origin Shield 地址
```

这里现在是从管理员配置的 Shield 节点中**下拉选择**，普通用户不能直接输入任意 URL。后端也会再次校验：

- 只能选择启用中的 Shield 节点；
- 已停用/未登记的地址不能保存；
- 仍被域名使用的节点不能停用或删除。

注意：

- Shield 地址必须能被普通 Edge 访问，但不要暴露公网；
- Shield 节点的 `EDGE_SHIELD_DISABLED=true` 只对自身生效，其他 Edge 仍会使用 Shield；
- Shield 仍接收公开业务域名 Host，因此必须能按该域名路由；
- Shield 的证书/SNI 要匹配内部地址；
- Shield 自身不要再把 `shield_url` 指回自己；
- Shield 故障后，普通 Edge 会按既有源站池回退；
- Shield 是区域汇聚点，建议按区域部署并监控磁盘、带宽和 fill drop。

> 如果 `shield_url` 指向的是同一个 Lagran Edge 集群，而 Shield 节点没有设置 `EDGE_SHIELD_DISABLED=true`，Shield 的 cache miss 可能再次请求自己，形成回源环。这是必须避免的配置。

完整步骤、TLS/Host 要求、部署顺序、验证、高可用和故障排查见
[docs/Origin Shield配置.md](<docs/Origin Shield配置.md>)。

---

## 本地启动

```bash
# 依赖（PostgreSQL，可选 Redis）
docker compose -f deploy/docker-compose.yml up -d

# 控制面：自动迁移，默认 0.0.0.0:8080
cargo run -p control

# 需要本地演示账号时（默认不创建）
SEED_DEMO=true cargo run -p control

# 边缘节点：默认 0.0.0.0:8081
ORIGIN_URL=http://example.com cargo run -p edge

# 前端
cd apps/frontend
npm install
NUXT_PUBLIC_API_BASE=http://localhost:8080 npm run dev
```

演示账号（仅 `SEED_DEMO=true`）：

```text
demo@lagran.dev / demo123
```

该账号是普通用户，不自动获得管理员权限。

> 生产环境必须设置 `SEED_DEMO=false`，并更换 `JWT_SECRET`、数据库密码和节点令牌。

---

## 验证

```bash
# 控制面健康检查
curl -fsS http://127.0.0.1:8080/health

# 登录（需要 SEED_DEMO=true 创建 demo 账号）
TOKEN=$(curl -sS -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}' | jq -r .token)

curl -sS -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8080/api/v1/domains | jq

# 边缘缓存：第一次 MISS，第二次 HIT（源站可达时）
curl -i http://127.0.0.1:8081/
curl -i http://127.0.0.1:8081/
```

> 若控制面 `CAPTCHA_ENABLED=true`，登录需先请求 `/api/v1/auth/captcha`，并在登录 body 中带 `captcha_id`、`captcha_code`；本地调试可临时设置 `CAPTCHA_ENABLED=false`。

关键响应头：

```text
X-Powered-By: lagran-edge
X-Cache: HIT | MISS | BYPASS | STALE
X-Lagran-Cache-Source: l1 | l2 | l3 | l3+origin | origin
X-Lagran-Cache-Reason: <缓存原因>
X-Lagran-Cache-TTL: <剩余新鲜秒数>
Age: <缓存年龄>
```

大对象 Range 常见 reason：

```text
range-large-cache   完整大缓存命中
range-chunk-fill   首次缺失分片填充
range-chunks       部分缓存 + 缺失分片回源
range-multipart    多段 Range multipart 命中
```

多段 Range 示例：

```bash
curl -i -H 'Range: bytes=0-1,4-5' http://127.0.0.1:8081/
```

---

## 配置

每个进程只加载自己的配置文件，完整默认值见示例：

| 文件 | 应用 | 内容 |
|---|---|---|
| [control.env.example](control.env.example) | control | 监听、PostgreSQL、Redis、JWT、ACME、GeoIP、OTel、告警 |
| [edge.env.example](edge.env.example) | edge | 监听、节点令牌、缓存、大对象、CC、WAF、TLS、日志 |
| [dns.env.example](dns.env.example) | dns | 监听、Zone/NS/SOA、调度、缓存、兜底 |
| [frontend.env.example](frontend.env.example) | frontend | Nuxt API 地址与构建说明 |

原则：

- 生产不要使用示例密码、默认 JWT 密钥或空节点令牌
- `EDGE_ADMIN_LISTEN` 不要暴露公网
- `NUXT_PUBLIC_API_BASE` 是构建期公开变量，修改后必须重新 `npm run generate`
- Redis 未配置时，相关能力回退到进程内状态/PostgreSQL

> `CONTROL_PUBLIC_URL` 只由 Control 读取，用于生成节点安装命令；Edge/DNS 访问控制面使用 `CONTROL_URL`，两者不可混用。

---

## 测试

```bash
cargo test --workspace
cargo clippy --workspace --all-targets

# 端到端（需要 PostgreSQL 和本地模拟源站）
bash tests/integration/smoke.sh
bash tests/integration/cache-diagnostics.sh
bash tests/integration/multi-origin.sh
bash tests/integration/cert-jobs.sh
bash tests/integration/p2-hardening.sh
bash tests/integration/waf.sh
bash tests/integration/ttl.sh
bash tests/integration/dns.sh
```

全部集成脚本位于：

```text
tests/integration/
```

CI 在 push/PR 时执行 Rust 测试、前端静态构建，并产出 musl 静态二进制 Release bundle。发布 GitHub Release 需要推送版本 Tag：

```bash
git tag v0.1.0
git push origin v0.1.0
```

---

## 运维

### 服务

```bash
systemctl status lagran-control
systemctl status lagran-edge
systemctl status lagran-dns

journalctl -u lagran-edge -f
```

### 健康检查

```bash
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/ready
curl -fsS http://127.0.0.1:8082/__lagran/health
```

### 指标

```bash
# 指标包含逐域名流量，必须带节点 token 或 METRICS_TOKEN；否则返回 401
curl -fsS -H "X-Lagran-Agent-Token: $AGENT_TOKEN" \
  http://127.0.0.1:8082/__lagran/metrics
```

重点指标：

```text
lagran_edge_requests_total
lagran_edge_cache_hits_total
lagran_edge_cache_misses_total
lagran_edge_bytes_sent_total
lagran_edge_chunk_requests_total
lagran_edge_chunk_origin_attempts_total
lagran_edge_chunk_origin_failures_total
lagran_edge_chunk_fill_drops_total
lagran_edge_chunk_fill_dropped_bytes_total
lagran_edge_chunk_fill_drop_queue_total
lagran_edge_chunk_fill_drop_budget_total
lagran_edge_chunk_fill_drop_send_total
lagran_edge_chunk_fill_rejects_total
lagran_edge_chunk_fill_rejected_bytes_total
lagran_large_cache_used_bytes
lagran_large_cache_available_bytes
lagran_large_cache_fs_available_bytes
lagran_large_cache_fs_reserved_bytes
lagran_large_cache_fs_admission_headroom_bytes
lagran_large_cache_min_free_bytes
```

`fill_dropped_bytes` 是实际进入队列后又被丢弃的字节；`fill_rejected_bytes` 是 writer 创建前就被拒绝的**计划填充量**，不代表已经读取/浪费了这些源站字节。

### 升级

优先使用控制台：

```text
系统设置 → 系统升级
```

更新助手会下载 Release、校验 `SHA256SUMS`、备份旧二进制、替换文件并重启服务。

旧版 Edge 缺少 `/__lagran/update` 或 update helper 时，在每个边缘节点重新执行：

```bash
./install.sh edge
```

旧版控制面缺少更新助手时，重新执行：

```bash
./install.sh control
```

### 备份

```bash
sudo -u postgres pg_dump lagran > /backup/lagran-$(date +%F).sql
sudo tar czf /backup/lagran-config-$(date +%F).tgz /etc/lagran
```

---

## 已知限制

- 带普通 Cookie 的请求默认绕过缓存；缓存响应不保存 `Set-Cookie`
- 大对象完整 GET 需要对象 `complete=true`；partial 对象只响应已覆盖的 Range
- 大对象多段 Range 支持 multipart 缓存响应；冷请求按首尾包络填充，跨度超过单对象填充上限、逻辑上限或文件系统空闲下限时回退源站透传
- `If-Range` 请求不参与大对象多段缓存拼接，交给源站处理
- 大对象 fill 可能因单 fill 队列、全局 fill 预算、逻辑容量或 `LARGE_CACHE_MIN_FREE_BYTES` 被丢弃；客户端响应不受影响，缓存保持 partial
- 大缓存是节点本地状态；同一 partial 对象在不同 Edge 节点上的补全进度独立
- 元数据预留按 sidecar 实际大小/保守上界计算；极端大响应头在缓存接近上限时可能让 fill 被拒绝而不是超限写入
- 浏览器 `no-cache`/`max-age=0`/`Pragma: no-cache` 请求走条件回源：有 ETag/Last-Modified 时源站 304 复用缓存；响应 `no-cache` 不写入共享缓存
- CC 是 L7 防护；SYN/UDP/连接耗尽等 L4 攻击仍需云清洗或上游联动
- 普通域名限流配置 `REDIS_URL` 后跨 Edge 共享；Redis 故障时回退单进程 bucket
- 行为评分是启发式，默认关闭，需验证误报
- gRPC/proto 仍是占位，当前 Edge-Control 使用 HTTP + JSON

---

## 支持与捐赠

Telegram：<https://t.me/lagranedge>

捐赠完全自愿，不影响许可，也不附带 SLA。请只使用对应网络转账：

| 网络 | 资产 | 地址 |
|---|---|---|
| Bitcoin | BTC | `bc1qgh9dvqa4d0skn82n7t423jnxy7mh3prgxcxc0z` |
| Ethereum | ETH / ERC-20 USDT / USDC | `0xCFf627A0D499e898b209300cA7192F55f01bAB2F` |
| TRON | TRX / TRC-20 USDT | `TFRZmHNyp54fg9BsCXaJH2UVq1B2yUNN8S` |
| Solana | SOL / SPL USDC | `AkpkuUTaReYb4QSgwFfbHZv6CwoesqfGAKPodDxa6x3T` |
| BNB Smart Chain | BNB / BEP-20 USDT | `0xCFf627A0D499e898b209300cA7192F55f01bAB2F` |
| Polygon | POL / polygon USDT | `0xCFf627A0D499e898b209300cA7192F55f01bAB2F` |

捐赠地址仅以本仓库或官方发布页为准。链上交易不可逆，转错网络/地址无法退款。

---

## 免责声明

本项目按 **“现状”（AS IS）** 提供，不附带任何明示或默示担保，也不承诺 CDN 加速、WAF 拦截率、DNS 解析或可用性达到特定指标。

使用者需自行确保：

- 部署和使用符合当地法律法规
- 密钥、令牌、数据库、管理接口和证书安全
- 源站、DNS、缓存、WAF、CC 与容量配置正确
- 做好备份、监控、应急响应和安全更新
- 不将本项目用于未经授权的监控、追踪或数据收集

因使用或无法使用本项目产生的损失，由使用者自行承担。第三方服务（PostgreSQL、Redis、Let's Encrypt、Telegram、云厂商等）由其提供方负责。

完整条款以 [AGPL-3.0-only](LICENSE) 为准；本免责声明不修改或限制许可证授予的权利与义务。

---

## License

GNU Affero General Public License v3.0 only（`AGPL-3.0-only`）。

- 允许商业使用、修改和分发
- 通过网络向用户提供服务时，需按 AGPL 第 13 条提供对应完整源代码
- 分发时保留版权与许可声明
- 不提供任何担保

Copyright (C) 2026 Lagran CDN contributors.
