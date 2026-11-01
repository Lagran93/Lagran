# Lagran CDN 使用与调试手册

> 适用版本：当前 `main` 分支  
> 适用组件：`lagran-control`、`lagran-edge`、`lagran-dns`、Nuxt 控制台  
> 更新日期：2026-11-01

本文是面向部署、日常使用、排障和二次开发的综合手册。环境变量完整默认值仍以仓库根目录的四份示例文件为准：

- [`control.env.example`](../control.env.example)
- [`edge.env.example`](../edge.env.example)
- [`dns.env.example`](../dns.env.example)
- [`frontend.env.example`](../frontend.env.example)

其他专题文档：

- [架构说明](architecture.md)
- [部署手册](deployment.md)
- [开发指南](development.md)
- [GeoDNS 说明](geodns.md)

---

## 目录

1. [系统组成与端口](#1-系统组成与端口)
2. [安装与首次启动](#2-安装与首次启动)
3. [控制台使用流程](#3-控制台使用流程)
4. [运行配置参考](#4-运行配置参考)
5. [缓存机制与验证](#5-缓存机制与验证)
6. [WAF、CC 与共享封禁](#6-wafcc-与共享封禁)
7. [可观测性与健康检查](#7-可观测性与健康检查)
8. [常用运维操作](#8-常用运维操作)
9. [调试手册](#9-调试手册)
10. [开发与测试](#10-开发与测试)
11. [安全清单](#11-安全清单)
12. [已知限制](#12-已知限制)
13. [附录：常用命令与响应头](#13-附录常用命令与响应头)

---

## 1. 系统组成与端口

### 1.1 组件

```text
浏览器 / 访客
    │
    ├── console.example.com ── Caddy/Nginx ── /opt/lagran/web（Nuxt 静态站）
    │                                      └── /api/* → lagran-control:8080
    │
    └── cdn.example.com ── lagran-edge:80/443 ── 源站
                              │
                              ├── /__lagran/* 管理接口（建议仅内网/本机）
                              └── 缓存 / WAF / CC / 限流 / 多源站

lagran-dns:53（权威 DNS）── /api/v1/schedule → lagran-control
```

| 组件 | 二进制 | 主要职责 |
|---|---|---|
| Control Plane | `lagran-control` | 登录、用户/项目、域名、缓存规则、证书、节点、刷新、预热、统计、告警、审计、配置发布 |
| Edge Plane | `lagran-edge` | Pingora HTTP/HTTPS/HTTP2、TLS、反向代理、缓存、WAF、CC、限流、访问日志 |
| DNS | `lagran-dns` | 权威 DNS、ECS/GeoDNS、调度缓存、降级 |
| Console | Nuxt 静态文件 | 管理控制台 |
| Shared cache | `crates/lagran-cache` | 内存/磁盘缓存抽象 |

### 1.2 默认端口

| 端口 | 进程 | 说明 |
|---|---|---|
| `8080/tcp` | control | 控制面 API；生产只应通过反向代理暴露 |
| `8081/tcp` | edge | 公共 HTTP 数据面 |
| `443/tcp` | edge | 公共 HTTPS 数据面（配置后） |
| `8082/tcp` | edge | 管理/Agent 接口，建议 `127.0.0.1` 或内网 |
| `5432/tcp` | PostgreSQL | 仅内网 |
| `6379/tcp` | Redis（可选） | 仅内网 |
| `53/udp,tcp` | dns | 权威 DNS |

> **重要**：`EDGE_ADMIN_LISTEN` 绝对不能暴露到公网。控制面的 `AGENT_URL` 必须指向 Edge 的管理端口，而不是公共数据端口。

### 1.3 默认目录

| 路径 | 内容 |
|---|---|
| `/opt/lagran/bin` | `lagran-control`、`lagran-edge`、`lagran-dns`、更新助手 |
| `/opt/lagran/web` | 前端静态文件 |
| `/etc/lagran` | `control.env`、`edge.env`、`dns.env` |
| `/var/lib/lagran` | 工作目录、证书、普通缓存、大对象缓存 |
| `/var/lib/lagran/certs` | 边缘证书 |
| `/var/lib/lagran/cache` | 普通磁盘缓存（`CACHE_BACKEND=disk/hybrid`） |
| `/var/lib/lagran/large-cache` | 大对象缓存 |

systemd 服务：

```bash
lagran-control.service
lagran-edge.service
lagran-dns.service
lagran-update.path
lagran-update.service
```

---

## 2. 安装与首次启动

### 2.1 一键安装

控制面：

```bash
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- control
```

边缘节点必须先登录控制台创建节点并取得节点令牌：

```bash
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran \
      AGENT_TOKEN='<节点令牌>' NODE_ID='edge-01' \
      bash -s -- edge
```

DNS：

```bash
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- dns
```

前端：

```bash
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- frontend --with-caddy
```

安装器选项：

```bash
./install.sh --help
```

### 2.2 手动编译

```bash
cargo build --release -p control -p edge -p lagran-dns
```

旧系统 glibc 不兼容时使用 musl：

```bash
sudo apt install -y musl-tools build-essential perl
rustup target add x86_64-unknown-linux-musl

export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc

cargo build --release --target x86_64-unknown-linux-musl \
  -p control -p edge -p lagran-dns
```

前端：

```bash
cd apps/frontend
npm ci
npm run generate
```

### 2.3 首次登录

默认演示账号由 `SEED_DEMO=true` 创建：

```text
demo@lagran.dev / demo123
```

生产环境必须：

```env
SEED_DEMO=false
REQUIRE_SECURE_SECRETS=true
JWT_SECRET=<至少 32 字节随机值>
```

### 2.4 安装后验收

```bash
# Control
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/ready

# Edge 管理口
curl -fsS http://127.0.0.1:8082/__lagran/health

# Edge 数据面（替换 Host）
curl -fsS -H 'Host: cdn.example.com' http://127.0.0.1:8081/

# systemd
systemctl status lagran-control --no-pager
systemctl status lagran-edge --no-pager
systemctl status lagran-dns --no-pager
```

---

## 3. 控制台使用流程

### 3.1 项目与权限

- `admin`：全部项目、域名、节点、审计、用户管理。
- 项目 `owner/admin`：项目内读写。
- 项目 `member`：只读。
- 普通用户只能看到自己所属项目的域名、规则、统计和日志。
- 普通用户新建域名未指定项目时，自动使用个人 `Default` 项目。

### 3.2 接入域名

1. 在「域名管理 → 新增域名」填写：
   - 域名，例如 `cdn.example.com`
   - 源站协议、Host、端口
   - 可选备用源站、源站池
   - 所属项目
2. 配置 DNS：
   - 客户域名 CNAME 到统一边缘接入域名，或
   - 直接 A/AAAA 记录到 Edge 公网 IP。
3. 开启 HTTPS：
   - 使用控制台 ACME 申请，或
   - 上传证书。
4. 在「缓存规则」配置路径 TTL 和动作。
5. 在「域名 → 诊断」检查 DNS、TLS、源站 TCP 和真实缓存路径。
6. 访问 `https://cdn.example.com/...` 验证响应头。

### 3.3 缓存规则

每个域名独立规则，按优先级从高到低匹配：

| 字段 | 说明 |
|---|---|
| 路径模式 | 支持通配符，例如 `/static/*` |
| 匹配方式 | 通配/正则等 |
| 请求方法 | 可选 GET/HEAD 等 |
| 查询串匹配 | 可选 |
| 动作 | `cache` / `bypass` / `no_store` |
| TTL | 规则覆盖源站缓存时间 |
| SWR | `stale-while-revalidate` 秒数 |
| 浏览器 TTL | 下发给浏览器的 `Cache-Control` |
| 忽略 Query | 缓存 key 不含查询串 |
| 忽略 Cookie | 允许带 Cookie 的请求共享缓存 |
| Content-Type | 可按响应类型匹配，响应头到达后判定 |

动作语义：

```text
cache     读取并写入缓存
bypass    不读不写，直接回源
no_store  可读已有缓存，但本次响应不写入
```

> 修改规则不会自动删除已有缓存对象。需要配合缓存刷新/purge，或等待 TTL 过期。

### 3.4 高级设置

域名高级设置包括：

- 回源超时
- 全局限流 RPS / 突发
- 忽略 Query
- CORS 允许来源
- 防盗链 Referer
- 自定义响应头
- Origin Shield 地址
- CC 防御
- 源站池/备用源站

开启 CC 后：

- 域名全局限流 RPS/突发同时作为 CC 全局攻击阈值。
- 超过阈值自动进入 60 秒攻击模式，客户端限额减半。
- HTML 首次超限进入 PoW 挑战，通过 clearance 后获得临时 2x 预算。
- 持续超限才封禁。

### 3.5 WAF 防护

页面包括：

- 总开关、拦截/观察模式
- 托管规则：SQLi、XSS、路径穿越、扫描器、RCE、SSRF、XXE、Log4Shell、CRLF、SSTI、NoSQL、LDAP 等
- 自定义规则：路径、Query、UA、Referer、Method、请求头、IP
- IP 黑白名单：支持单 IP 与 CIDR
- 安全级别：低/中/高/攻击中
- 共享封禁：跨 Edge 自动封禁、手动 IP/CIDR 封禁、解封、24h 统计
- 事件列表：block/challenge/monitor/log

模式：

```text
block    命中后拦截或挑战
monitor  只记录，不拦截
```

### 3.6 缓存刷新与预热

#### 缓存刷新

「缓存刷新」支持：

- 按 URL
- 按前缀
- 按域名
- 按 `Surrogate-Key` / `Cache-Tag`
- 全量清理（谨慎）

控制面会把 purge 请求下发到在线 Edge；Edge 同时清理普通缓存和大对象缓存。

#### 缓存预热

「缓存预热」支持：

- 手动添加路径
- 一次性任务
- 定时任务 `prefetch_schedules`
- 查看任务状态和每个节点的 warmed/failed 信息

预热是 Edge 本地执行的真实 GET，不是只写元数据。

### 3.7 证书

- 手动上传证书/私钥
- ACME HTTP-01 申请 Let's Encrypt
- Staging 用于调试，避免生产 rate limit
- 自动续期
- 推送到 Edge，SNI 热加载
- 泛域名需要 DNS-01，当前未实现

### 3.8 节点管理

1. 「边缘节点 → 新增节点」，记录只展示一次的节点令牌。
2. 在 Edge 服务器配置：

```env
NODE_ID=edge-01
AGENT_TOKEN=<节点令牌>
CONTROL_URL=https://control.example.com
AGENT_URL=http://<内网IP>:8082
EDGE_ADMIN_LISTEN=0.0.0.0:8082
PUBLIC_IP=<公网IP>
```

3. 启动后观察心跳、版本、CPU/内存。
4. 确保控制面能访问 `AGENT_URL`，否则 purge/config/cert/challenge 会失败。

### 3.9 配置发布

启用配置发布后：

```text
编辑域名/规则/WAF
  → 生成 config_version
  → 创建 release
  → 审批
  → 灰度到目标节点
  → 节点 apply-report
  → 全部成功后 published
```

失败或超时自动回滚。  
一旦域名绑定发布版本，后续编辑只生成新版本，不会立即影响线上。

### 3.10 统计、监控、告警

- 仪表盘：请求、命中率、流量、节点数。
- 按域名统计。
- 大屏监控：独立布局，10 秒刷新。
- 告警中心：源站健康、证书到期、节点离线、命中率、WAF 突增。
- 通知渠道：SMTP、Webhook（可选 HMAC）、Telegram。
- 访问日志：按域名过滤。
- 操作审计：管理员可见。

### 3.11 系统升级

管理员在「系统设置 → 系统升级」：

1. 检测 GitHub Release。
2. 写入更新请求。
3. root 的 `lagran-update.path` 触发更新助手。
4. 下载 release、校验 `SHA256SUMS`、备份旧二进制。
5. 替换 control/edge/dns 与 Web。
6. 重启已启用服务。

旧部署需要重新执行一次：

```bash
./install.sh control
```

以安装 `lagran-update.path`、`lagran-update.service` 和更新助手。

---

## 4. 运行配置参考

### 4.1 配置文件位置

```text
/etc/lagran/control.env
/etc/lagran/edge.env
/etc/lagran/dns.env
```

修改后：

```bash
systemctl restart lagran-control
systemctl restart lagran-edge
systemctl restart lagran-dns
```

### 4.1.1 `CONTROL_PUBLIC_URL` 与 `CONTROL_URL` 的关系

这两个变量属于不同进程，不能混用：

| 变量 | 读取进程 | 作用 |
|---|---|---|
| `CONTROL_PUBLIC_URL` | `lagran-control` | 控制面公网根地址，用于生成节点安装命令中的 `CONTROL_URL` |
| `CONTROL_URL` | `lagran-edge` / `lagran-dns` | Edge/DNS 访问控制面的 API 根地址 |

关系：

```text
Control 的 CONTROL_PUBLIC_URL
  → 生成节点安装命令
  → 写入 Edge/DNS 的 CONTROL_URL
```

注意：

- 两个变量都必须以 `http://` 或 `https://` 开头，末尾 `/` 会自动去除。
- `CONTROL_PUBLIC_URL` 留空时，Control 按安装请求的 `Host` / `X-Forwarded-Proto` 推断。
- `CONTROL_URL` 留空时，Edge/DNS 使用默认 `http://127.0.0.1:8080`。
- Control 进程不会读取 `CONTROL_URL`；Edge/DNS 不会读取 `CONTROL_PUBLIC_URL`。
- 控制面回调 Edge 使用的是节点自己的 `AGENT_URL`，不是 `CONTROL_PUBLIC_URL`。
- 如果控制面在反向代理的子路径下，`CONTROL_URL` 可以带路径；Edge/DNS 会在后面追加 `/api/v1/...`。

### 4.2 Control 关键变量

| 变量 | 说明 |
|---|---|
| `CONTROL_BIND` | 控制面监听，默认 `0.0.0.0:8080` |
| `CONTROL_PUBLIC_URL` | 对外 HTTPS 根地址，用于生成节点安装命令中的 `CONTROL_URL`；为空时按请求 Host 推断 |
| `DATABASE_URL` | PostgreSQL 连接串，必填 |
| `DATABASE_MAX_CONNECTIONS` | 连接池上限 |
| `REDIS_URL` | 可选，Redis 共享状态 |
| `JWT_SECRET` | JWT 签名密钥，生产必须随机 |
| `JWT_EXPIRE_HOURS` / `JWT_EXPIRES_SECS` | Token 有效期 |
| `REQUIRE_SECURE_SECRETS` | 拒绝弱/默认密钥 |
| `ALLOW_REGISTER` | 是否允许自助注册 |
| `CAPTCHA_ENABLED` | 登录/注册验证码 |
| `SEED_DEMO` | 是否创建演示账号，生产设为 false |
| `AGENT_TOKEN` | 全局 DNS/调度 Agent Token |
| `GEOIP_PATH` | GeoIP 数据路径 |
| `DNS_TEST_SERVER` | 控制台 DNS 测试上游 |
| `LOG_RETENTION_DAYS` | 日志保留天数 |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP Trace 导出 |
| `RUST_LOG` | 日志级别 |

### 4.3 Edge 关键变量

| 变量 | 说明 |
|---|---|
| `EDGE_LISTEN` | 公共 HTTP，默认 `0.0.0.0:8081` |
| `EDGE_HTTPS_LISTEN` | 公共 HTTPS，留空关闭 |
| `EDGE_ADMIN_LISTEN` | 管理/Agent，默认 `127.0.0.1:8082` |
| `NODE_ID` | 必须与控制台节点一致 |
| `AGENT_TOKEN` | 节点独立 token，不是全局 token |
| `CONTROL_URL` | 控制面地址 |
| `AGENT_URL` | 控制面回调 Edge 的地址，必须是管理端口 |
| `PUBLIC_IP` | GeoDNS 使用 |
| `CC_SYNC_INTERVAL` | 共享封禁同步间隔 |
| `REDIS_URL` | CC 滑动窗口共享 |
| `CC_REDIS_PREFIX` | Redis key 前缀 |
| `CACHE_TTL` | 默认缓存 TTL |
| `CACHE_BACKEND` | `memory` / `disk` / `hybrid` |
| `DISK_CACHE_DIR` | 普通磁盘缓存目录 |
| `MAX_CACHEABLE_BODY` | 普通缓存单对象上限，8 MiB 默认 |
| `LARGE_CACHE_ENABLED` | 大对象缓存开关 |
| `LARGE_CACHE_DIR` | 大对象目录 |
| `LARGE_CACHE_MIN_OBJECT_BYTES` | 大对象最小字节数 |
| `LARGE_CACHE_MAX_OBJECT_BYTES` | 大对象最大字节数 |
| `LARGE_CACHE_MAX_BYTES` | 大对象总容量 |
| `CHALLENGE_SECRET` | PoW/clearance HMAC，多节点必须一致 |
| `CC_STATIC_MULTIPLIER` | 静态路径预算倍率 |
| `CC_AUTH_DIVISOR` | 登录路径预算除数 |
| `CC_DOWNLOAD_MULTIPLIER` | 下载路径预算倍率 |
| `CC_BEHAVIOR_ENABLED` | 行为评分开关 |
| `CC_BEHAVIOR_SCORE` | 行为评分阈值 |
| `TRUST_PROXY_HEADERS` | 是否信任前置代理 XFF |
| `ACCESS_LOG_*` | 访问日志路径/JSON/缓冲/上报 |
| `RUST_LOG` | 日志级别 |

### 4.4 DNS 关键变量

| 变量 | 说明 |
|---|---|
| `DNS_LISTEN` | 默认 `0.0.0.0:53` |
| `DNS_ZONE` | 权威 Zone |
| `DNS_NS_NAME` / `DNS_NS_IP` | NS 与 glue |
| `CONTROL_URL` | 调度 API 地址 |
| `AGENT_TOKEN` | 全局调度 token |
| `DNS_TTL` | A 记录 TTL |
| `DNS_CACHE_SECS` | 调度缓存 |
| `DNS_STALE_SECS` | 控制面故障时旧结果可用时间 |
| `DNS_FALLBACK_IP` | 兜底 IP |

### 4.5 前端

```env
NUXT_PUBLIC_API_BASE=
```

- 同域反代推荐留空。
- 跨域 API 填完整地址，且必须重新 `npm run generate`。
- 该变量会进入浏览器 JS，不能放密钥。

---

## 5. 缓存机制与验证

### 5.1 缓存 key

基础格式：

```text
METHOD:host:path[?query]
```

追加变体：

```text
|lang=<hash>       Vary: Accept-Language
|origin=<hash>     Vary: Origin / CORS
|acrm=<hash>       Access-Control-Request-Method
|acrh=<hash>       Access-Control-Request-Headers
|acrpn=<hash>      Access-Control-Request-Private-Network
```

规则开启 `ignore_query` 时 key 不含查询串。

### 5.2 TTL 优先级

```text
规则 ttl_seconds
  → 源站 Cache-Control: s-maxage
  → 源站 max-age
  → Expires
  → 域名/全局 CACHE_TTL
```

SWR：

```text
规则 swr_seconds > 源站 stale-while-revalidate > 0
```

### 5.3 哪些响应可缓存

必须满足：

- `GET`（HEAD 复用 GET 缓存）
- 规则动作 `cache`
- 状态码可缓存（常见 200/203/204/300/301/308）
- 无 `Set-Cookie`
- 无 `no-store`
- 无 `private`
- `no-cache` 且没有规则 TTL 时通常不写入
- `Vary` 字段受支持，或没有 `Vary`
- 请求无 `Authorization`
- 请求无普通 Cookie（规则 `ignore_cookie` 例外）
- 请求无 `no-store`

### 5.4 支持的 Vary

当前支持：

- `Accept-Encoding`
- `Accept-Language`
- `Origin`
- `Access-Control-Request-Method`
- `Access-Control-Request-Headers`
- `Access-Control-Request-Private-Network`
- `Cookie`（仅 `ignore_cookie=true`）

其他字段（例如 `User-Agent`）会拒绝缓存。

CORS `Vary` 会被哈希进 cache key，避免不同 Origin 串缓存。

### 5.5 浏览器 no-cache 的真实行为

当前实现：

```text
完整可缓存 GET/HEAD：
  Cache-Control: no-cache / Pragma: no-cache
  → Edge 删除请求头
  → 完整缓存命中时直接 HIT
```

因此：

- 小文件完整对象：no-cache 仍可能 HIT
- 大文件完整对象：no-cache 仍可能 HIT
- 大文件只有 partial Range 段：完整 GET 仍 MISS
- 请求相同且已覆盖的 Range：可能 HIT

`no-store` 是例外，会 bypass：

```text
Cache-Control: no-store → 不读不写
```

> 如果业务要求严格遵循 RFC 的 `no-cache = 每次回源校验`，需要统一修改普通缓存和 Range 缓存策略，而不是按文件大小分支。

### 5.6 普通缓存与大对象缓存

| 项目 | 普通缓存 | 大对象缓存 |
|---|---|---|
| 存储 | 内存/磁盘 | 独立磁盘流式 |
| 单对象上限 | `MAX_CACHEABLE_BODY` | `LARGE_CACHE_MAX_OBJECT_BYTES` |
| 最小阈值 | 无 | `LARGE_CACHE_MIN_OBJECT_BYTES` |
| 完整 GET | 是 | 需要 `complete=true` |
| Range | 完整对象切片 | partial segment |
| 目录 | `DISK_CACHE_DIR` | `LARGE_CACHE_DIR` |
| 文件 | `.bin` / `.meta` | `.data` / `.meta.json` |

启用大缓存：

```env
LARGE_CACHE_ENABLED=true
LARGE_CACHE_DIR=/var/lib/lagran/large-cache
LARGE_CACHE_MIN_OBJECT_BYTES=8388608
LARGE_CACHE_MAX_OBJECT_BYTES=1073741824
LARGE_CACHE_MAX_BYTES=21474836480
```

大缓存写入要求：

- 完整对象：状态码 `200`、存在 `Content-Length`、对象大小在阈值范围内
- Partial Range：源站返回 `206`、`Content-Range`、`Content-Length`
- 响应可缓存：无 `Set-Cookie`、无 `no-store/private`、`Vary` 受支持
- 请求没有触发 Cookie/Authorization/no-store bypass
- 磁盘目录可写、容量足够

### 5.7 Partial Range

流程：

```text
Range 请求
  → 大缓存有覆盖该区间的 segment？
      ├─ 有：HIT，直接读磁盘返回 206
      └─ 无：透传源站 206
             → 后台把该区间写入 .data
             → 更新 segments
```

第一次通常：

```http
HTTP/1.1 206 Partial Content
X-Cache: BYPASS
X-Lagran-Cache-Reason: range-fill
```

等待后台提交后第二次相同 Range：

```http
HTTP/1.1 206 Partial Content
X-Cache: HIT
```

元数据：

```json
{
  "content_length": 35800956,
  "complete": false,
  "segments": [[0, 1023]]
}
```

要求：

- 源站返回 `206 + Content-Range`
- 单段 Range
- 对象大小满足大缓存阈值
- 响应可缓存（Vary/Cache-Control/Set-Cookie 等通过）
- 请求无 `If-Range`、无普通 Cookie/Authorization/no-store

Partial 对象不能响应完整 GET。完整 GET 需要：

```json
"complete": true
```

### 5.8 缓存预热

预热接口：

```text
POST /api/v1/prefetch
{ "domain": "cdn.example.com", "paths": ["/file.mp4"] }
```

预热行为：

- 控制面任务队列
- 下发到在线 Edge
- Edge 执行真实 GET
- 大对象会写入大缓存
- 普通对象写入普通缓存
- Control → Edge 的预热回调超时为 60 秒
- 任务记录 warmed/failed

常见预热失败：

- 域名 `ssl_enabled=true`，但 Edge 收到 HTTP 请求返回 301
- 域名配置未同步
- 源站不可达
- 路径返回 404
- 大缓存关闭或超过最大对象限制
- 控制面回调 Edge 超时/`agent_url` 错误

### 5.9 缓存诊断

控制台「缓存诊断」会：

1. 优先让在线 Edge 真正执行一次请求。
2. 对下载/大文件路径自动使用 `Range: bytes=0-0`。
3. 返回状态、`X-Cache`、`X-Lagran-Cache-Reason`、preview。
4. Edge 内部 10 秒超时，Control 回调 20 秒超时。

注意：

- 诊断本身可能写入一个 1 字节 segment。
- 大文件诊断通常返回 `BYPASS / range-bypass`，这不代表不能缓存。
- `agent_url` 指向数据端口会得到 405 或 timeout。

---

## 6. WAF、CC 与共享封禁

### 6.1 CC 客户端聚合

- IPv4 按 `/24`
- IPv6 按 `/64`
- IPv4-mapped IPv6 归一化为 IPv4

同一个 `/24` 或 `/64` 共享限额。

### 6.2 路径预算

| 路径 | 预算 |
|---|---|
| 静态资源 | 基础限额 × 8 |
| 登录/认证 | 基础限额 ÷ 2，至少 1 |
| 下载/媒体 | 基础限额 × 2 |
| API/动态 | 基础限额 |

阈值由环境变量调整：

```env
CC_STATIC_MULTIPLIER=8
CC_AUTH_DIVISOR=2
CC_DOWNLOAD_MULTIPLIER=2
```

### 6.3 滑动窗口与 Redis

- 未配置 `REDIS_URL`：进程内固定窗口。
- 配置 Redis：跨 Edge 共享排序集合滑动窗口。
- Redis key 前缀：`CC_REDIS_PREFIX`，默认 `lagran:cc`。
- Redis 超时会回退本地。

### 6.4 全局阈值与攻击模式

开启 CC 且 `cc_mode=block` 时，域名全局限流 RPS/突发作为全局阈值：

```text
超过全局阈值
  → 进入 60 秒 attack mode
  → 单客户端限额减半
  → HTML 首次超限进入 PoW 挑战
  → clearance 后 2x 临时预算
  → 持续超限才封禁
```

`cc_ban_after=1` 会立刻封禁，无法先挑战；挑战优先应设置 `>=2`。

### 6.5 挑战

- 使用现有 PoW 页面。
- `CHALLENGE_SECRET` 多节点必须一致。
- 挑战通过写 clearance cookie。
- 挑战日志进入 WAF 事件，category 常见为 `cc` 或 `bot`。

### 6.6 共享封禁

- Edge 自动封禁上报控制面。
- 控制面统一封禁库。
- 所有 Edge 定时拉取并合并。
- 手动封禁支持单 IP 和 CIDR：

```text
203.0.113.10
203.0.113.0/24
2001:db8::/64
```

- 管理员操作写入审计。
- 手动解封后 Edge 约 5 秒内同步。

### 6.7 行为评分

```env
CC_BEHAVIOR_ENABLED=true
CC_BEHAVIOR_SCORE=4
```

只对 HTML 动态/登录页面生效，根据 UA、Accept-Language、Sec-CH-UA、Sec-Fetch-Mode、Cookie 等评分；达到阈值先挑战。默认关闭。

### 6.8 CC 统计

控制台「WAF 防护 → 共享封禁」显示：

- 活动封禁数
- 24h 限流
- 24h 挑战
- 24h 封禁

API：

```text
GET /api/v1/cc/stats?domain=cdn.example.com
```

---

## 7. 可观测性与健康检查

### 7.1 Control

```bash
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/ready
curl -fsS http://127.0.0.1:8080/metrics
```

Prometheus 指标包含：

- 进程/数据库状态
- 域名与节点分组
- 源站健康
- 证书到期
- 24h 请求/命中率/WAF 事件
- 当前告警与通知渠道

### 7.2 Edge

```bash
# 管理口
curl -fsS http://127.0.0.1:8082/__lagran/health
curl -fsS http://127.0.0.1:8082/__lagran/metrics

# 数据面健康
curl -fsS -H 'Host: cdn.example.com' http://127.0.0.1:8081/__lagran/health
```

管理接口需要节点 token 的端点：

```http
X-Lagran-Agent-Token: <节点 token>
```

### 7.3 日志

```bash
journalctl -u lagran-control -f
journalctl -u lagran-edge -f
journalctl -u lagran-dns -f
```

Edge 访问日志：

```env
ACCESS_LOG_PATH=/var/lib/lagran/access.log
ACCESS_LOG_JSON=false
ACCESS_LOG_REPORT=true
```

如果 `ACCESS_LOG_PATH` 留空，只写 tracing。

### 7.4 关键响应头

| 头 | 含义 |
|---|---|
| `X-Powered-By: lagran-edge` | 确认请求由 Lagran Edge 处理 |
| `X-Cache` | `HIT` / `MISS` / `BYPASS` / `STALE` / `DYNAMIC` / `REVALIDATED` |
| `X-Cache-Status` | 同 `X-Cache` |
| `X-Lagran-Cache-Reason` | 未命中/绕过/填充原因 |
| `Age` | 缓存对象年龄 |
| `ETag` | 源站或 Edge 生成 |
| `X-Lagran-Error` | 源站错误类型 |

常见 reason：

| reason | 说明 |
|---|---|
| `hit` | 命中 |
| `stale` | SWR 窗口返回旧内容 |
| `cookie` | Cookie 绕过 |
| `authorization` | Authorization 绕过 |
| `no-store` | 请求 no-store |
| `no-cache` | 响应 no-cache 且无规则 TTL |
| `vary` | Vary 不受支持 |
| `vary:user-agent` | Vary User-Agent |
| `vary:cookie` | Vary Cookie 且未 ignore |
| `rule-bypass` | 规则 bypass |
| `content-type-bypass` | 响应 Content-Type 规则 bypass |
| `set-cookie` | 响应 Set-Cookie |
| `status` | 状态码不可缓存 |
| `ttl-zero` | TTL 为 0 |
| `body-too-large` | 超过普通缓存上限且未写入大缓存 |
| `range-bypass` | Range 透传源站 |
| `range-fill` | 正在后台填充 Range |
| `range-large-cache` | 大对象 Range 命中 |
| `https-redirect` | 域名强制 HTTPS，先 301/308 |

---

## 8. 常用运维操作

### 8.1 健康检查

```bash
systemctl status lagran-control --no-pager
systemctl status lagran-edge --no-pager
ss -lntup | grep -E '8080|8081|8082|5432|6379|:53'
```

### 8.2 备份

数据库：

```bash
sudo -u postgres pg_dump lagran > /backup/lagran-$(date +%F).sql
```

配置：

```bash
sudo tar czf /backup/lagran-config-$(date +%F).tgz /etc/lagran
```

证书/缓存：

```bash
sudo tar czf /backup/lagran-data-$(date +%F).tgz \
  /var/lib/lagran/certs
```

缓存通常不需要备份，可在灾难后重新预热。

### 8.3 升级

优先使用控制台「系统升级」。手动：

```bash
cargo build --release -p control -p edge -p lagran-dns
sudo systemctl stop lagran-edge lagran-control lagran-dns
sudo install -m 755 target/release/lagran-control /opt/lagran/bin/
sudo install -m 755 target/release/lagran-edge /opt/lagran/bin/
sudo install -m 755 target/release/lagran-dns /opt/lagran/bin/
sudo systemctl start lagran-control
sudo systemctl start lagran-edge
sudo systemctl start lagran-dns
```

前端：

```bash
cd apps/frontend && npm run generate
sudo rsync -a --delete .output/public/ /opt/lagran/web/
sudo systemctl reload caddy
```

升级前备份数据库和 `/etc/lagran`。

### 8.4 清理缓存

- 控制台「缓存刷新」
- API purge
- 全量清理会同时删除普通缓存和大缓存

大对象目录手动确认：

```bash
du -sh /var/lib/lagran/large-cache
find /var/lib/lagran/large-cache -name '*.meta.json' | wc -l
```

不要在运行中直接 `rm` 大量缓存，优先用 purge，避免元数据不一致。

---

## 9. 调试手册

### 9.1 推荐排查顺序

```text
1. DNS 是否解析到预期 Edge
2. TCP/TLS 是否能连接
3. 请求是否到达 Edge（X-Powered-By）
4. Host 是否命中已接入域名
5. 是否 HTTPS 301
6. WAF/CC 是否拦截
7. 缓存规则/TTL/Vary 是否允许缓存
8. 源站响应是否正确
9. Edge 管理接口/控制面回调是否可达
```

### 9.2 确认请求是否经过 Edge

```bash
curl -sS -D - -o /dev/null https://cdn.example.com/test \
  | grep -Ei 'HTTP/|server|x-powered-by|x-cache|x-lagran-cache-reason|age|content-length'
```

如果 `X-Powered-By` 不是 `lagran-edge`：

- DNS 可能仍指向旧 CDN/源站
- 请求打到了前置 Caddy/Nginx
- 测试 Host 与域名不一致

### 9.3 缓存不命中

```bash
curl -sS -D - -o /dev/null https://cdn.example.com/file
```

重点看：

```text
X-Cache
X-Lagran-Cache-Reason
Cache-Control
Vary
Set-Cookie
Age
```

常见：

| 现象 | 排查 |
|---|---|
| `BYPASS` + `cookie` | 请求带 Cookie；规则加 `ignore_cookie` 或清理 Cookie |
| `BYPASS` + `authorization` | 请求带 Authorization |
| `MISS` + `rule-bypass` | 规则是 bypass |
| `MISS` + `content-type-bypass` | 响应类型规则 |
| `MISS` + `vary` | 不支持的 Vary |
| `MISS` + `no-store`/`private` | 源站禁止缓存 |
| `MISS` + `set-cookie` | 源站写 Cookie |
| `MISS` + `status` | 状态码不可缓存 |
| `MISS` + `ttl-zero` | TTL 为 0 |
| `HIT` 但内容旧 | purge 或检查 TTL/SWR |
| `STALE` | SWR 窗口，后台刷新中 |

### 9.4 大文件缓存没有文件

检查配置：

```bash
grep -E 'LARGE_CACHE|MAX_CACHEABLE_BODY' /etc/lagran/edge.env
journalctl -u lagran-edge | grep 'large object cache ready'
```

检查目录：

```bash
LARGE_CACHE_DIR=$(grep '^LARGE_CACHE_DIR=' /etc/lagran/edge.env | cut -d= -f2)
find "$LARGE_CACHE_DIR" -name '*.data' -size +1M -printf '%p %s\n'
find "$LARGE_CACHE_DIR" -name '*.meta.json' \
  -exec jq -c '{key,content_length,complete,segments}' {} \;
```

常见原因：

- `LARGE_CACHE_ENABLED=false`
- 对象小于 `LARGE_CACHE_MIN_OBJECT_BYTES`
- 对象大于 `LARGE_CACHE_MAX_OBJECT_BYTES`
- `Content-Length` 缺失
- 状态码不是 200
- 响应带 `Set-Cookie`
- `no-store` / `private`
- `Vary` 不受支持
- 磁盘权限/容量
- 客户端中断，Writer 未 commit
- 只缓存了 partial Range，文件存在但 `complete=false`

### 9.5 CORS Vary 导致 Range 永远不缓存

响应：

```http
vary: origin, access-control-request-method, access-control-request-headers
```

旧版本会拒绝，表现为：

```text
每次 X-Cache: BYPASS
X-Lagran-Cache-Reason: range-fill
但 large-cache 目录没有文件
```

新版本已允许这些字段，并把 Origin/ACRM/ACRH/ACRPN 哈希进 cache key。

验证要求：

- Edge 更新到包含该修复的版本
- 两次请求使用相同的 `Origin` 头
- `Vary` 中没有 `User-Agent` 等未支持字段

### 9.6 Range 不命中

检查源站：

```bash
curl -sS -D - -o /dev/null \
  -H 'Range: bytes=0-1023' \
  -H 'Accept-Encoding: identity' \
  https://cdn.example.com/file.mp4
```

必须：

```text
206 Partial Content
Content-Range: bytes 0-1023/<total>
Accept-Ranges: bytes
```

如果源站返回 200，Edge 无法填充 partial segment。

检查是否：

- 请求带 `If-Range`
- 多段 Range
- 对象低于大缓存阈值
- 规则 bypass
- 带 Cookie/Authorization/no-store
- 两次 Range 不同
- 第一次 fill 尚未 commit

### 9.7 no-cache 小文件命中、大文件不命中

确认：

```bash
find /var/lib/lagran/large-cache -name '*.meta.json' \
  -exec jq -c '{key,complete,segments}' {} \; | grep file
```

- 小文件通常是完整对象，`complete=true`。
- 大文件如果只有 partial Range，`complete=false`，完整 GET 必然 MISS。
- 相同且已覆盖的 Range 应 HIT。
- `no-cache` 不是 bypass 条件；只有 `no-store` 等会 bypass。

如果要求严格 RFC 语义，应统一修改策略，不要只让大文件绕过。

### 9.8 预热失败

查看任务：

- 控制台「缓存预热」任务详情
- `warmed/failed` 消息
- Edge 访问日志

常见：

| 现象 | 原因 |
|---|---|
| `warmed=0 failed=1`，状态 301 | 域名 SSL=true，预热请求先跳 HTTPS |
| `agent_url` 连接失败 | Edge 管理口不可达/端口错误 |
| 回调超时 | Edge 管理口被防火墙阻断；网络抖动 |
| 大文件无文件 | 大缓存关闭/超限/响应不可缓存 |
| 预热 404 | 路径错误或源站返回 404 |
| 预热后仍 MISS | 预热只影响对应 Edge；检查节点/缓存 key |

### 9.9 缓存诊断超时 / client error Connect

错误：

```text
callback timeout after 5s: http://<edge>:8081/__lagran/cache-diagnose
```

检查：

1. `AGENT_URL` 是否指向管理端口（通常 8082）。
2. 管理口防火墙是否放通控制面。
3. `EDGE_ADMIN_LISTEN` 是否监听在控制面可达地址。
4. 大文件是否被识别为下载流并使用 `Range`。
5. 源站是否忽略 Range 并返回完整大文件。

如果 `agent_url` 指向数据端口，可能得到：

```text
405 management port required
```

修正：

```env
EDGE_ADMIN_LISTEN=0.0.0.0:8082
AGENT_URL=http://<内网IP>:8082
```

然后重启 Edge，并更新控制台节点 `agent_url`。

### 9.10 边缘 Agent 401

```text
401 unauthorized agent
```

检查：

- `NODE_ID` 是否与控制台节点名一致
- `AGENT_TOKEN` 是否是该节点的 `auth_token`
- 是否误用了控制面全局 `AGENT_TOKEN`
- 节点是否被删除/禁用
- 控制面数据库是否已迁移

管理接口测试：

```bash
curl -i -H "X-Lagran-Agent-Token: $AGENT_TOKEN" \
  http://127.0.0.1:8082/__lagran/metrics
```

### 9.11 HTTPS/TLS 诊断失败

控制台域名诊断可能显示：

```text
invalid peer certificate: UnknownIssuer
```

但浏览器正常，通常是：

- 自签证书
- 中间证书链未发送
- 诊断使用系统根证书校验
- SNI 不匹配
- 证书已过期
- 前置代理终止 TLS

检查：

```bash
openssl s_client -connect cdn.example.com:443 -servername cdn.example.com \
  -showcerts </dev/null
```

证书链应完整，叶子证书 CN/SAN 匹配域名。

### 9.12 JWT 失效/前端不退出

当前前端行为：

- API 返回 401：清除 token，跳转 `/login?expired=1`
- 控制台每 60 秒调用 `/auth/me`
- 登录页会清除死 token 并提示过期
- 修改密码/禁用用户会使旧 token 的 token_version 失效

如果仍不退出：

1. 清理浏览器 localStorage：
   ```js
   localStorage.removeItem('lagran_token')
   localStorage.removeItem('lagran_user')
   ```
2. 硬刷新。
3. 检查 `NUXT_PUBLIC_API_BASE` 是否指向错误后端。
4. 检查浏览器时间/时区。
5. 检查控制面 `JWT_SECRET` 是否变化导致旧 token 全失效（应表现为 401）。

### 9.13 403 权限问题

普通用户请求管理员接口会返回 403：

- `/api/v1/nodes`
- `/api/v1/audit`
- 节点离线告警
- 全局节点/用户管理

控制台会按角色隐藏入口，但 API 仍会校验。

### 9.14 数据库/迁移

```bash
set -a
. /etc/lagran/control.env
set +a

psql "$DATABASE_URL" -c 'select version();'
psql "$DATABASE_URL" -c 'select count(*) from _sqlx_migrations;'
journalctl -u lagran-control -n 100 --no-pager
```

控制面启动自动执行 migrations。升级前备份。

### 9.15 DNS

```bash
dig @127.0.0.1 -p 53 cdn.example.com A
dig @127.0.0.1 -p 53 edge.lagran.net NS
dig @127.0.0.1 -p 53 edge.lagran.net SOA
```

检查：

- `DNS_LISTEN`
- `DNS_ZONE`
- `DNS_NS_NAME` / `DNS_NS_IP`
- `CONTROL_URL` / `AGENT_TOKEN`
- `GEOIP_PATH`
- 53 端口是否被 systemd-resolved 占用
- 防火墙 UDP/TCP 53

### 9.16 端口/防火墙

```bash
ss -lntup
ufw status
iptables -S
```

生产建议：

- 公网：80/443（Edge）、53（DNS）、443（控制台反代）
- 内网：8080、8082、5432、6379
- 不开放 Edge 管理口

---

## 10. 开发与测试

### 10.1 本地依赖

```bash
docker compose -f deploy/docker-compose.yml up -d
```

或：

```bash
./scripts/dev-up.sh
```

### 10.2 启动

```bash
export DATABASE_URL=postgres://lagran:lagran@127.0.0.1:5432/lagran
cargo run -p control
```

另一个终端：

```bash
ORIGIN_URL=https://example.com cargo run -p edge
```

前端：

```bash
cd apps/frontend
npm install
NUXT_PUBLIC_API_BASE=http://localhost:8080 npm run dev
```

### 10.3 测试

```bash
cargo test --workspace
cargo clippy --workspace --all-targets

bash tests/integration/smoke.sh
bash tests/integration/cache-diagnostics.sh
bash tests/integration/waf.sh
bash tests/integration/ttl.sh
```

端到端脚本通常需要 PostgreSQL、控制面和本地模拟源站；先看脚本头部环境变量。

### 10.4 前端构建

```bash
cd apps/frontend
npm run generate
```

产物：

```text
apps/frontend/.output/public
```

### 10.5 代码格式化

```bash
cargo fmt --all
cd apps/frontend && npm run generate
```

---

## 11. 安全清单

- [ ] `JWT_SECRET` 随机且 >= 32 字节，不使用默认值
- [ ] `REQUIRE_SECURE_SECRETS=true`
- [ ] `SEED_DEMO=false`
- [ ] `ALLOW_REGISTER` 按需关闭
- [ ] 管理员使用强密码，启用验证码
- [ ] PostgreSQL 不对公网开放，使用强密码
- [ ] Redis 仅内网，配置 ACL/TLS
- [ ] Edge 管理端口仅内网/本机
- [ ] `AGENT_TOKEN` 每节点独立，定期轮换
- [ ] `CHALLENGE_SECRET` 多节点一致且保密
- [ ] `TRUST_PROXY_HEADERS` 只在前置可信代理时开启
- [ ] 控制台强制 HTTPS
- [ ] 证书私钥权限最小化
- [ ] 备份数据库和 `/etc/lagran`
- [ ] 不在仓库提交 `.env`、私钥、token
- [ ] 定期清理日志/审计数据
- [ ] 关注 GitHub Release 安全更新

---

## 12. 已知限制

- 普通缓存以完整对象为单位；大对象支持 partial Range segment，但仅覆盖已请求区间。
- 大对象完整 GET 需要 `complete=true`；partial 不能拼接为完整响应。
- 单段 Range 才支持 partial 填充；多段 Range 透传。
- `no-cache` 当前对完整可缓存 GET 被忽略；不是严格 RFC 的每次 revalidate。
- 修改缓存规则/配置不会自动删除旧缓存。
- 普通域名限流为单进程；CC 配置 Redis 后才跨 Edge 共享。
- L4/SYN/UDP/连接耗尽防护需要云清洗或 nftables/运营商联动。
- 行为评分是启发式，不是完整设备指纹，默认关闭。
- 泛域名 ACME DNS-01 未实现。
- gRPC/proto 仍是占位，当前 Edge-Control 使用 HTTP+JSON。
- 配置发布失败会回滚，但极端网络分区下以节点最后一次成功配置为准。
- 缓存目录手动删除可能留下统计偏差，优先使用 purge。

---

## 13. 附录：常用命令与响应头

### 13.1 登录拿 token

```bash
TOKEN=$(curl -sS -X POST https://console.example.com/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"admin@example.com","password":"********"}' | jq -r .token)

AUTH="authorization: Bearer $TOKEN"
```

如果开启验证码，需要先取 `/api/v1/auth/captcha` 并提交 `captcha_id`/`captcha_code`。

### 13.2 查询域名

```bash
curl -sS -H "$AUTH" https://console.example.com/api/v1/domains | jq
```

### 13.3 刷新缓存

```bash
curl -sS -X POST https://console.example.com/api/v1/purge \
  -H "$AUTH" -H 'content-type: application/json' \
  -d '{"domain":"cdn.example.com","urls":["https://cdn.example.com/file.mp4"]}' | jq
```

### 13.4 预热

```bash
curl -sS -X POST https://console.example.com/api/v1/prefetch \
  -H "$AUTH" -H 'content-type: application/json' \
  -d '{"domain":"cdn.example.com","paths":["/file.mp4"]}' | jq
```

### 13.5 查看大缓存 meta

```bash
find /var/lib/lagran/large-cache -name '*.meta.json' \
  -exec jq -c '{key,content_length,complete,segments}' {} \; \
  | grep 'file.mp4'
```

### 13.6 查看普通缓存

```bash
find /var/lib/lagran/cache -name '*.bin' -printf '%p %s\n' | head
```

### 13.7 Range 验证

```bash
URL='https://cdn.example.com/file.mp4'

# 第一次
curl -sS -D /tmp/r1.h -o /dev/null \
  -H 'Range: bytes=0-1023' \
  -H 'Accept-Encoding: identity' "$URL"
grep -Ei 'HTTP/|content-range|x-cache|x-lagran-cache-reason' /tmp/r1.h

sleep 2

# 第二次
curl -sS -D /tmp/r2.h -o /dev/null \
  -H 'Range: bytes=0-1023' \
  -H 'Accept-Encoding: identity' "$URL"
grep -Ei 'HTTP/|content-range|x-cache' /tmp/r2.h
```

### 13.8 检查 Edge 配置

```bash
systemctl show lagran-edge -p EnvironmentFiles -p ExecStart -p WorkingDirectory
tr '\0' '\n' < /proc/$(pgrep -f lagran-edge | head -1)/environ \
  | sort | grep -E '^(EDGE_|LARGE_|CACHE_|CC_|REDIS_)' \
  | grep -vE 'TOKEN|SECRET|PASSWORD'
```

注意不要在不安全终端打印 token 等敏感值。

### 13.9 常用 systemd

```bash
systemctl restart lagran-control
systemctl restart lagran-edge
systemctl restart lagran-dns

journalctl -u lagran-edge -f
journalctl -u lagran-control -n 200 --no-pager
journalctl -u lagran-dns -n 200 --no-pager
```

### 13.10 前端发布

```bash
cd apps/frontend
npm run generate
sudo rsync -a --delete .output/public/ /opt/lagran/web/
sudo chown -R caddy:caddy /opt/lagran/web
sudo systemctl reload caddy
```

---

如需进一步排查，请同时提供：

- `curl -D -` 完整响应头
- Edge `journalctl` 最近 100 行
- 域名配置/规则截图
- `LARGE_CACHE_*` 配置
- `find ... -name '*.meta.json'` 输出
- 控制面 `/metrics` 相关指标

这样可以快速定位是 DNS、TLS、WAF、缓存规则、源站还是大缓存写入问题。
