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

### 2.3.1 登录日志

控制台会记录每次账号认证结果，包含：

```text
时间
账号邮箱
结果（成功 / 失败）
来源 IP
User-Agent
原因
```

记录入口：

```text
运维监控 → 登录日志
```

管理员可查看全部账号的登录记录；普通用户只能查看与自己邮箱关联的记录。

失败原因包括：

```text
invalid_credentials  账号或密码错误
invalid_password     密码错误
account_disabled     账号已禁用
captcha_failed       验证码错误
rate_limited         尝试过于频繁
db_error             数据库错误
token_error          令牌签发失败
```

登录日志保存于 `login_logs` 表，默认保留 30 天。调整：

```env
LOG_RETENTION_DAYS=90
```

后会与访问日志、指标一起按保留天数清理；设为 `0` 表示不自动清理。

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

用户组（`系统 → 用户组`）：

- 一个用户可加入多个组，权限取并集
- 权限按模块读写划分：`domain:read/write`、`cache:read/write`、`waf:read/write`、`cert:read/write`、`prefetch:read/write`、`project:read/write`、`node:read/write`、`analytics:read`、`config:read/write`、`alert:read/write`、`audit:read`、`settings:read/write`、`user:read/write`
- 模块权限只决定“能否进入该功能”，项目和域名范围仍由项目成员关系决定
- 未加入任何用户组的用户沿用原有项目角色权限
- 全局 `admin` 不受用户组限制
- 用户组变更最多约 30 秒生效（会话缓存 TTL）

示例：

```text
只读运维组：domain:read, cache:read, waf:read, analytics:read
WAF 值班组：domain:read, waf:read, waf:write
缓存管理员：domain:read, cache:read, cache:write, prefetch:read, prefetch:write
```


### 3.2 接入域名

1. 在「域名管理 → 新增域名」填写：
   - 域名，例如 `cdn.example.com`
   - 源站协议、Host、端口
   - 可选备用源站、源站池
   - 可选「源站 TLS SNI」和「回源 Host」
   - 所属项目

源站主机支持域名或 IP。源站填 IP 且使用 HTTPS 时，证书通常只包含域名 SAN，需要填写：

```text
源站主机：45.63.84.225
源站协议：HTTPS
源站端口：443
源站 TLS SNI：test-origin.akgo.net
回源 Host：test-origin.akgo.net
```

Edge 会用 SNI 建立 TLS 并校验证书，用回源 Host 访问虚拟主机；回源 Host 留空时回退到 SNI，再回退到源站主机。
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

> **Content-Type 规则只在响应阶段生效。**
>
> 请求阶段先按路径/方法/Query 选择规则；如果此时命中了 `bypass` 或 `no_store` 兜底规则，
> 即使响应是 `video/mp4`，也不会读写缓存。
>
> 需要让视频可缓存时，必须额外添加一条**不带 Content-Type 条件**的路径 `cache` 规则，并给予高于兜底规则
> 的优先级。规则测试可清空 Content-Type 字段来查看请求阶段实际命中的规则。

动作语义：

```text
cache     读取并写入缓存
bypass    不读不写，直接回源
no_store  当前实现按请求阶段非 cache 处理：回源且不写入缓存
```

> 修改规则不会自动删除已有缓存对象。需要配合缓存刷新/purge，或等待 TTL 过期。

#### 请求阶段与响应阶段

规则匹配分两个阶段，可以理解为两道门：

```text
请求阶段（已知 URL / Method / Query / Headers）
  是否允许进入缓存系统？
        │
        ├─ bypass / no_store → 不读缓存，直接回源
        └─ cache → 查缓存 / 回源

响应阶段（源站返回后，已知 Content-Type 等响应头）
  这个响应是否允许保存？
        │
        ├─ cache → 保存，使用该规则 TTL/SWR
        └─ bypass / no_store → 不保存
```

关键区别：

| 阶段 | 已知信息 | 是否会考虑 Content-Type 规则 |
|---|---|---|
| 请求阶段 | 域名、路径、方法、Query、请求头 | **不会** |
| 响应阶段 | 再加上源站状态码和响应头 | 会 |

因此：

- Content-Type 规则不能决定“是否读取缓存”。
- 请求阶段命中 bypass 后，响应阶段再命中 cache，也不能恢复缓存。
- 路径 cache 规则是“总开关”，Content-Type 规则只是响应阶段的细化。
- 缓存命中后，响应 Content-Type 仍可让 Edge 强制 miss，避免类型不符的旧对象继续被使用。

示例：

```text
规则 A: /*                    bypass  priority 0
规则 B: /api/file/stream*     cache   priority 20   （无 Content-Type）
规则 C: /api/file/stream*     cache   priority 30   Content-Type=video/mp4
规则 D: /api/file/stream*     bypass  priority 30   Content-Type=text/html
```

请求 `/api/file/stream?code=x`：

```text
请求阶段：A 和 B 可参与，B 优先级更高 → B cache
响应 video/mp4：C 优先级最高 → cache，使用 C 的 TTL
响应 text/html：D 优先级最高 → bypass，不保存
```

如果删除 B：

```text
请求阶段：只有 A 可参与 → A bypass
响应 video/mp4：C 命中，但请求阶段已经 bypass
→ 不会读缓存，也不会保存
```

这就是“规则测试显示 priority 30 Content-Type cache，但实际不缓存”的原因。

设计规则时建议：

1. 先配置一条**不带 Content-Type**的路径规则，确保请求阶段是 `cache`。
2. 再用 Content-Type 规则细化 TTL、SWR 或特殊类型 bypass。
3. 请求阶段路径规则的优先级必须高于路径兜底 bypass 规则。
4. 规则测试清空 Content-Type 看请求阶段，再填入 Content-Type 看响应阶段。

### 3.4 高级设置

域名高级设置包括：

- 回源超时
- 全局限流 RPS / 突发（配置 Edge `REDIS_URL` 后跨节点共享 token bucket）
- 忽略 Query
- CORS 允许来源
- 防盗链 Referer
- 自定义响应头
- Origin Shield 地址
- CC 防御
- 源站池/备用源站
- 每个源站可独立配置 TLS SNI、回源 Host

开启 CC 后：

- 域名全局限流 RPS/突发同时作为 CC 全局攻击阈值。
- 超过阈值自动进入 60 秒攻击模式，客户端限额减半。
- HTML 首次超限进入 PoW 挑战，通过 clearance 后获得临时 2x 预算。
- 持续超限才封禁。

### 3.5 WAF 防护

页面包括：

- 总开关、拦截/观察模式
- 托管规则：SQLi、XSS、路径穿越、扫描器、RCE、SSRF、XXE、Log4Shell、CRLF、SSTI、NoSQL、LDAP 等
- 托管规则集：OWASP 核心防护、注入扩展防护、SSRF/XXE 防护、扫描器与协议基线
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

WAF 检查会先做最多两次百分号解码，`%2527`、`%253Cscript%253E` 等双层编码不能绕过。
同时检测：

- `Transfer-Encoding` 与 `Content-Length` 同时出现
- `X-Original-URL` / `X-Rewrite-URL` 路径覆盖头
- 空字节、超长 path/query
- 扫描器 UA、敏感路径、SQLi/XSS/路径穿越/RCE/SSRF/XXE/Log4Shell/SSTI/NoSQL/LDAP/Java 反序列化/WebShell 等托管规则

WAF 目前不读取请求体（在代理读取 body 前执行），GET/HEAD 的 path/query/header 是主要检查面。

托管规则集是**增量启用**：

```text
选中规则集 = 启用该规则集包含的全部签名类别
不会关闭下方单独开启的规则
规则集版本由控制面统一维护
```

可用接口：

```http
GET  /api/v1/waf/rulesets
GET  /api/v1/domains/{id}/waf
PUT  /api/v1/domains/{id}/waf
```

`PUT` 请求新增：

```json
{
  "managed_rulesets": ["owasp-core", "injection-extended"]
}
```

控制面保存选择后生成 Edge 有效配置：

```text
explicit category switches OR ruleset categories
```

因此规则集升级时，只要新增类别，域名会自动获得新增签名，不需要重新保存设置。
因此规则集升级时，只要新增类别，域名会自动获得新增签名，不需要重新保存设置。

### 签名规则包、缓存与灰度

规则包是确定性的 JSON 文档，由 Control 使用 HMAC-SHA256 签名：

```text
WAF_RULEPACK_SECRET
```

未设置时使用内置开发默认值：

```text
lagran-dev-waf-rulepack-secret
```

生产必须显式设置 `WAF_RULEPACK_SECRET`，且 Control 与所有 Edge 完全一致；否则 Edge 会拒绝规则包并回退到配置中的有效布尔值。

#### 发布与回滚

```http
GET  /api/v1/waf/rulepacks
POST /api/v1/waf/rulepacks/publish
POST /api/v1/waf/rulepacks/{version}/rollback
GET  /api/v1/waf/rulepack/{version}
```

发布后：

```text
新版本 slot = active
旧 active  = previous
旧 previous = retired
```

回滚只切换 slot，不重新构建历史包。

#### 发布不同 catalog 的快照

管理员可以在发布时直接提供规则集目录覆盖：

```http
POST /api/v1/waf/rulepacks/publish
```

```json
{
  "version": "2026.13-custom",
  "rulesets": [
    {
      "id": "owasp-core",
      "name": "OWASP core (custom)",
      "version": "2026.13",
      "categories": ["xss", "traversal", "scanners", "rce", "crlf", "protocol"]
    },
    {
      "id": "injection-extended",
      "name": "Injection extended",
      "version": "2026.13",
      "categories": ["ssti", "nosql", "ldap", "java", "webshell"]
    }
  ]
}
```

不传 `rulesets` 时使用编译内置 catalog。

Control 会先比较新规则包与 active 的语义指纹：

```text
id + 排序后的 categories
```

如果完全相同，默认返回：

```http
409 Conflict
catalog unchanged (active 2026.12); deploy a new catalog or pass force=true
```

这是为了避免生成“只有版本号变化、规则内容完全相同”的无意义版本。

确实需要保留同内容的版本标签时：

```json
{
  "force": true,
  "version": "2026.12-snapshot"
}
```

覆盖目录的限制：

```text
只能使用已有的类别名：
sqli xss traversal scanners rce ssrf xxe log4shell crlf
ssti nosql ldap java webshell protocol
只能覆盖已有规则集 id：
owasp-core injection-extended ssrf-xxe scanner-guard
不能上传任意正则
```

用途：

```text
灰度验证不同类别组合
临时关闭某个高风险类别
自定义规则集成员关系
发布可签名、可回滚的 catalog 快照
```

Edge 仍然只接收合并后的类别布尔值；是否生效不依赖 Edge 理解 catalog 结构。

#### 删除历史规则包

```http
POST   /api/v1/waf/rulepacks/{version}/retire
DELETE /api/v1/waf/rulepacks/{version}
```

删除限制：

```text
active   不能删除，也不能直接 retire
previous 不能删除，必须先 retire
retired  可以删除
仍有域名 pin 该版本时不能删除
```

推荐顺序：

```text
1. 先确认没有域名固定该版本
2. previous -> retire
3. delete retired
```

删除只移除 Control 数据库记录。Edge 本地缓存文件不会自动删除：

```text
WAF_RULEPACK_CACHE_DIR/<version>.json
WAF_RULEPACK_CACHE_DIR/<version>.sig
```

如需彻底清理，可在确认没有配置引用后手动删除这些缓存文件。

#### 按域名固定版本

WAF 设置新增：

```json
{
  "waf_rulepack_version": "2026.11",
  "waf_gray_percent": 0
}
```

- `waf_rulepack_version` 非空：该域名固定使用此版本。
- 为空：跟随 Control 的 active 版本。
- `waf_gray_percent`：1~99 时按 `hash(domain, active.version) % 100` 稳定切分到 active/previous。

#### Edge 缓存

Edge 从配置同步中获得：

```text
waf.rulepack.payload
waf.rulepack.signature
waf.rulepack.checksum
```

处理流程：

```text
校验 SHA-256 checksum
校验 HMAC-SHA256 signature
解析规则包版本
写入本地缓存：
  WAF_RULEPACK_CACHE_DIR/<version>.json
  WAF_RULEPACK_CACHE_DIR/<version>.sig
```

默认目录：

```text
./data/waf-rulepacks
```

验签失败不会阻止域名继续使用 Control 已下发的有效托管布尔值，但不会写入缓存，并会记录告警日志。


### 3.5.1 自定义 WAF 规则 DSL

自定义规则支持可选布尔表达式：

```json
{
  "name": "后台接口缺少内部密钥",
  "field": "path",
  "operator": "contains",
  "value": "",
  "action": "block",
  "priority": 100,
  "enabled": true,
  "expr": "path prefix \"/admin\" AND NOT header:x-api-key equals \"ok\""
}
```

`expr` 非空时，忽略 `field/operator/value` 单条件，使用表达式。

## 语法

```text
expr    := or
or      := and ("OR" and)*
and     := unary ("AND" unary)*
unary   := "NOT" unary | "(" expr ")" | condition
condition := field operator "string"
```

字段：

```text
path
query
user_agent / ua
referer
method
ip
header:<name>
```

操作符：

```text
contains
equals / eq
prefix / starts_with
suffix / ends_with
in                 仅用于 ip，值为 CIDR 或 IP
```

示例：

```text
path prefix "/admin"
method equals "POST" AND query contains "debug"
path prefix "/api" AND NOT header:x-api-key equals "ok"
(path prefix "/admin" OR path prefix "/internal") AND ip in "10.0.0.0/8"

ip in "10.0.0.0/8,2001:db8::/32"
ip in "203.0.113.7"
NOT ip in "10.0.0.0/8"
```

关键字、字段名和值匹配不区分大小写。

## 限制

```text
最大长度 2048
最大嵌套深度 16
最大 AST 节点数 64
字符串最大 256
不允许正则
不允许代码执行
```

表达式由控制面校验，Edge 在配置同步时再次解析；无效表达式会导致该规则被跳过并记录日志。

DSL 仍然只检查 path/query/UA/Referer/Method/Header/IP，不读取请求体。

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

预热是 Edge 本地通过 Pingora 数据面执行的真实 GET，不是只写元数据；会经过与普通客户端相同的普通缓存、Range 和大对象缓存路径。

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
5. 在节点列表点击「升级」：控制面解析 GitHub Release，调用节点 `/__lagran/update`；Edge 写入更新请求，由 root 的 `lagran-edge-update.path/service` 下载、校验 SHA256、替换二进制并重启。
   - 需要 `install.sh edge` 安装 `lagran-edge-update` helper 与 systemd path 单元。
   - 首次启用该功能时，旧版 Edge 没有 `/__lagran/update` 端点，需要在节点上重新执行一次新版 `install.sh edge`；之后即可在控制台点击升级。
   - Docker 部署没有宿主机 root helper，升级按钮会返回 503。
   - 升级期间节点短暂停止代理；失败时旧二进制仍保留在 `edge-update-backup/`。

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

升级请求是单实例的：存在 update.request 或状态为 queued/running/downloading/installing/restarting 时，Control 返回 409 update already in progress，前端按钮保持禁用，避免重复排队。页面刷新后会从 update.status 恢复禁用状态。

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
| `GEOIP_PATH` | 地理位置库路径，推荐 ip2region `ip2region_v4.xdb` |
| `GEOIP_IPV6_PATH` | 可选 ip2region IPv6 `ip2region_v6.xdb` |
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
| `REDIS_URL` | CC 滑动窗口与普通域名限流共享 |
| `CC_REDIS_PREFIX` | CC Redis key 前缀 |
| `RATE_LIMIT_REDIS_PREFIX` | 普通限流 Redis key 前缀 |
| `CACHE_TTL` | 默认缓存 TTL |
| `CACHE_BACKEND` | `memory` / `disk` / `hybrid` / `redis` / `l2`；`redis` 与 `l2` 当前等价，均启用本地 MemoryCache + Redis L2 |
| `DISK_CACHE_DIR` | 普通磁盘缓存目录 |
| `MAX_CACHEABLE_BODY` | 普通缓存单对象上限，8 MiB 默认 |
| `CACHE_KEY_IGNORE_HEADERS` | 从 cache key 排除的请求头，如 `accept-language,origin` |
| `CACHE_MAX_BYTES` | 内存缓存近似字节上限，默认 512 MiB；超限按 LRU 淘汰 |
| `CACHE_REDIS_URL` | 所有 Edge 共享的 Redis L2 地址；为空复用 `REDIS_URL`。不是节点本地 Redis |
| `CACHE_REDIS_PREFIX` | Redis L2 key 前缀 |
| `CACHE_L2_MAX_BODY` | 写入 Redis L2 的最大序列化 body |
| `CACHE_L2_WRITE_TIMEOUT_MS` | Redis L2 写超时，默认 3000ms；跨区域时适当增大 |
| `CACHE_L2_READ_TIMEOUT_MS` | Redis L2 读超时，默认 250ms；跨区域时适当增大 |
| `ORIGIN_READ_TIMEOUT_MS` | 回源读取空闲超时，默认 30000；流媒体不会因总时长被中断 |
| `ORIGIN_STREAM_READ_TIMEOUT_MS` | Range/流媒体的回源读取空闲超时，默认 120000；避免视频首字节慢导致 504 |
| `RANGE_FILL_MAX_BYTES` | 单次 Range 写入大缓存的上限，默认 32 MiB；开放式缓存前缀，后缀缓存尾部 |
| `DOWNSTREAM_KEEPALIVE_SECS` | 下游 HTTP/1.1 keepalive 空闲超时，默认 60 |
| `DOWNSTREAM_H2_IDLE_SECS` | 下游 HTTP/2 空闲超时，默认 120 |
| `DOWNSTREAM_KEEPALIVE_REQUESTS` | 单连接最大请求数，默认 1000 |
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

### 4.3.1 Redis 部署位置与 L2 架构

`CACHE_REDIS_URL` 是每个 Edge 节点上的客户端连接地址，指向一个**所有目标 Edge 都能访问的共享 Redis**。它不是“必须和 Control 部署在同一台机器”，也不是“每台 Edge 各连自己的 Redis”。

典型拓扑：

```text
edge-kr-01 ─┐
edge-kr-02 ─┼──> redis-l2.internal:6379
edge-kr-03 ─┘
```

#### 三种部署方式

| 方式 | 适用场景 | 说明 |
|---|---|---|
| 独立 Redis / 云 Redis 主从 | 生产推荐 | 所有 Edge 共享，不占用节点资源，可独立扩容、备份、监控 |
| Control 服务器上的 Redis | 小规模、同区域 | 可用，但 Control 故障会导致 L2 不可用，且与 Control 抢内存 |
| 某一台 Edge 节点上的 Redis | 仅测试 | 单点故障；该节点故障会让全站 L2 丢失，并影响该节点代理性能 |

生产环境推荐：

```text
独立 Redis 实例
或 Redis Sentinel / 云 Redis 主从
与 Edge 同私有网络
低 RTT
只允许内网访问
```

不要把 L2 Redis 放在某一台 Edge 节点上作为长期方案。

#### 多区域部署

如果 Edge 分布在多个区域，推荐每个区域一个 Redis：

```text
韩国 Edge → redis-kr.internal
美国 Edge → redis-us.internal
欧洲 Edge → redis-eu.internal
```

特点：

```text
区域内共享 L2
跨区域不共享
```

优点：

- 低延迟
- 不受跨洲 RTT 影响
- 单区域 Redis 故障只影响该区域

缺点：

- 跨区域节点之间不共享缓存
- 缓存一致性依赖 Control 的 purge fan-out 与配置版本失效

不建议全球所有 Edge 共用一个远端 Redis：

```text
全球 Edge → 一个跨洲 Redis
```

原因：

- 跨洲延迟高
- 可能超过 L2 访问超时
- Redis 成为全球单点
- 带宽成本高

#### 与 REDIS_URL 的关系

`REDIS_URL` 与 `CACHE_REDIS_URL` 用途不同：

```text
REDIS_URL
  CC 滑动窗口
  普通域名限流
  配置缓存 / 告警锁

CACHE_REDIS_URL
  L2 共享缓存
  跨节点 single-flight
  purge L2 清理
```

两者可以指向同一个 Redis，但生产建议分开：

- 缓存对象可能较大
- 缓存内存压力会触发淘汰
- 限流 key 被淘汰会导致限流失效
- 缓存更适合独立实例或独立淘汰策略

如果必须共用一个实例，至少使用不同前缀，并确认 `maxmemory-policy` 不会错误淘汰限流/锁 key。

#### 不同逻辑库不能替代资源隔离

可以使用不同 Redis 逻辑库：

```env
REDIS_URL=redis://10.0.0.20:6379/0
CACHE_REDIS_URL=redis://10.0.0.20:6379/1
```

这只能隔离 key 命名空间，不能隔离：

- `maxmemory`
- `maxmemory-policy`
- CPU
- 网络带宽
- 持久化 / AOF / RDB
- 慢查询和阻塞

Redis 的 `maxmemory` 和淘汰策略是**实例级**的，不是 DB 级。缓存把实例内存打满时，`allkeys-lru` 仍可能淘汰限流 key；`volatile-lru` 也可能淘汰任何带 TTL 的限流或锁 key。

因此：

- 小规模、非关键环境可以接受同实例不同 DB + 不同前缀；
- 生产环境仍建议缓存与限流使用独立实例；
- 如果只能共用一个实例，应设置足够内存、监控 eviction，并评估限流 key 被淘汰的影响；
- Redis Cluster 通常只支持 DB 0，`/1` 在集群模式下不可用。

#### 配置示例

```env
CACHE_BACKEND=redis
CACHE_REDIS_URL=redis://10.0.0.20:6379/0
CACHE_REDIS_PREFIX=lagran:cache
CACHE_L2_MAX_BODY=8388608
# 跨区域或大对象写入时增大写超时；默认 3000ms
CACHE_L2_WRITE_TIMEOUT_MS=3000
CACHE_L2_READ_TIMEOUT_MS=250
```

`CACHE_REDIS_URL` 末尾的 `/0` 是 Redis 逻辑数据库编号；排查 L2 key 时必须连接同一个数据库，`redis-cli SCAN 0` 默认只扫描 DB 0。

TLS / 密码：

```env
CACHE_REDIS_URL=rediss://:password@redis-l2.internal:6379/0
```

#### 容量与安全建议

```text
仅内网访问
启用 ACL / 密码 / TLS
独立 Redis 实例或独立逻辑库
设置 maxmemory
设置合理的 maxmemory-policy
监控内存、命中率、延迟、淘汰数
```

Redis L2 只保存普通缓存对象。大文件仍走 LargeCache 本地磁盘，不写入 Redis。

当 Redis 不可用时，Edge 自动降级为本地缓存；跨节点 single-flight 也会跳过等待，避免 Redis 故障拖慢请求。

### 4.3.2 签名 URL

域名高级设置可开启：

```text
signed_url_mode
signed_url_paths
signed_url_enabled
signed_url_secret
signed_url_previous_secret
signed_url_ttl_secs
```

`mode`：

```text
off     关闭
all     整个域名要求签名
paths   仅 signed_url_paths 匹配的路径要求签名
```

`paths` 每行一个规则：

```text
/private/*
/downloads/*
/vip/exact-file.mp4
```

仅支持精确路径或 `/prefix/*`；路径会先规范化并拒绝 `..`、`%2e`、`%2f`、反斜杠和控制字符。`/private/*` 不会匹配 `/private2/*`。

启用后，受保护请求必须携带：

```text
expires=<unix 秒>
sig=<hex HMAC-SHA256>
```

也接受 `signature=` 作为 `sig` 的别名。

规范字符串：

```text
METHOD
host
path
按字典序排序后的 query（剔除 expires/signature/sig）
expires
```

各字段以换行符分隔。HMAC 密钥为当前 `signed_url_secret`；轮换期间也会尝试 `signed_url_previous_secret`。

示例生成：

```bash
curl -X POST https://console.example.com/api/v1/domains/<id>/signed-url \
  -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' \
  -d '{"path":"/private/file.mp4","expires_in":600}'
```

返回：

```json
{
  "path_and_query": "/private/file.mp4?expires=...&sig=...",
  "expires": 1794000000
}
```

Edge 验签成功后会从 URI 中移除：

```text
expires
signature
sig
```

因此这些参数不会进入：

```text
缓存 key
源站请求
访问日志的 path 查询串
```

签名失败返回 `403`，不会回源。

密钥轮换：

```bash
curl -X POST https://console.example.com/api/v1/domains/<id>/signed-url/rotate \
  -H "Authorization: Bearer <token>"
```

旧密钥会移动到 `signed_url_previous_secret`，旧链接在配置同步后仍可通过校验；再次轮换会替换旧密钥。

注意：

- 签名 URL 的 query 参数顺序在签名时会被排序，但清理后保留原始顺序作为缓存 key；客户端应保持稳定参数顺序。
- 域名开启签名后，管理接口、健康检查和 ACME 不受影响。
- Edge 必须与控制面配置版本同步后生效；密钥变更会触发该域名缓存失效。

### 4.3.3 Header 规范化与请求走私防护

Edge 在进入 WAF、缓存和源站之前会校验原始请求头，异常请求直接返回 `400`，不会回源。

拒绝的条件：

```text
Content-Length 与 Transfer-Encoding 同时存在
多个 Content-Length
Content-Length 包含逗号、符号、空白或非数字
多个 Transfer-Encoding
Transfer-Encoding 不是唯一的 chunked
多个 Host
Host 为空、含空白/控制字符或非法字符
绝对 URI 的 authority 与 Host 不一致
Connection 头把 content-length / transfer-encoding 列为 hop-by-hop
HTTP/2 出现 connection / proxy-connection / keep-alive / upgrade / transfer-encoding
请求头数量超过 128
请求头总字节超过 64 KiB
Header 值包含 CR/LF、NUL 或其他非法控制字符
```

请求头名称由 `http::HeaderMap` 统一规范化；危险重复头直接拒绝，避免不同跳对 header 的合并/解释差异被利用。

日志会记录：

```text
status=400
cache_status=BYPASS
reason=cl-...
```

具体 reason 不包含攻击者可控内容。

适用于：

```text
Pingora 公共入口
legacy 兜底入口
```

### 4.3.4 Origin 鉴权与防盗链签名

域名高级设置支持：

```text
origin_auth_header
origin_auth_value
hotlink_signature_enabled
```

## Origin 鉴权

配置：

```text
origin_auth_header = x-origin-token
origin_auth_value  = 仅 Edge 与源站知道的密钥
```

Edge 在回源请求中自动注入该 Header：

```text
x-origin-token: <value>
```

该 Header：

```text
不返回给客户端
不进入缓存 key
适用于 Pingora 原生回源、legacy 回源、条件回源、大对象回源和源站健康探测
```

源站需要校验该 Header 后才返回内容，避免绕过 CDN 直连源站。

## 防盗链签名

开启：

```text
hotlink_signature_enabled = true
```

复用签名 URL 的：

```text
signed_url_secret
expires
sig / signature
```

判定顺序：

```text
Referer 命中 hotlink_allow_referers
→ 直接放行

Referer 未命中或为空
→ 要求 expires + sig 有效

签名有效
→ 放行

签名缺失或无效
→ 403
```

生成方式与控制面签名 URL 相同：

```http
POST /api/v1/domains/{id}/signed-url
```

即使 `signed_url_mode=off`，开启防盗链签名后仍可生成签名 URL。

签名参数在验签后移除，不进入缓存 key 或源站请求。

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

### 4.5 常用子命令

三个服务都支持 `version`、`check-config`、`help`，默认无参数启动服务。

## Control

```bash
lagran-control serve
lagran-control check-config
lagran-control migrate
lagran-control health
lagran-control version
lagran-control help
```

`check-config` 只校验环境变量和关键安全项，不连接数据库。

`migrate` 连接 PostgreSQL 并执行 `apps/control/migrations`。

`health` 请求 `CONTROL_HEALTH_URL`，未设置时自动使用本机监听地址的 `/health`。

## Edge

```bash
lagran-edge serve
lagran-edge check-config
lagran-edge health
lagran-edge version
lagran-edge help
```

`health` 请求管理监听地址：

```text
/__lagran/health
```

## DNS

```bash
lagran-dns serve
lagran-dns check-config
lagran-dns version
lagran-dns help
```

`check-config` 校验：

```text
DNS_LISTEN 格式
DNS_NS_NAME / DNS_NS_IP 数量
DNS_ZONE
CONTROL_URL
```

## 说明

```text
version 不连接数据库、不启动监听
check-config 不改变运行状态
health 只做只读探测
```
## 5. 缓存机制与验证

### 5.1 缓存 key

基础格式：

```text
METHOD:host:path[?query]
```

追加变体：

```text
|lang=<hash>       Accept-Language
|origin=<hash>     Origin / CORS
```

`Access-Control-Request-*` 只属于 OPTIONS 预检。当前 GET/HEAD key 不包含它们，OPTIONS 预检缓存启用后再按请求方法加入。

规则开启 `ignore_query` 时 key 不含查询串。

### 5.1.1 按域名/规则忽略 Cache Key 请求头

域名高级设置提供：

```text
Cache Key 忽略请求头
[ ] Origin
[ ] Accept-Language
```

缓存规则提供三行独立三态：

```text
Cache Key 组成
Query            [继承域名] [忽略] [区分]
Origin           [继承域名] [忽略 Origin] [区分]
Accept-Language  [继承域名] [忽略语言] [区分]
```

每一行：

```text
继承域名 → 使用域名设置
忽略     → 该头不进入 key
区分     → 该头进入 key
```

优先级：

```text
规则按请求头逐项覆盖域名
  > 域名默认
  > 全局 CACHE_KEY_IGNORE_HEADERS
```

语义：

- `origin` 被忽略后，请求 `Origin` 不进入 cache key；
- `accept-language` 被忽略后，`Accept-Language` 不进入 cache key；
- 对 GET/HEAD，`Vary: Origin` / `Vary: Accept-Language` 也按忽略处理，否则源站 CORS 中间件的 Vary 会阻止缓存；
- OPTIONS 预检缓存尚未启用，不受该配置影响；
- Content-Type 规则不能配置该字段，因为 Content-Type 在响应阶段才知道，不能参与请求阶段的 key。

规则 API 的 `ignore_key_headers` 使用三态编码：

```text
origin=inherit,accept-language=inherit
origin=ignore,accept-language=keep
origin=keep,accept-language=ignore
```

兼容旧值：

```text
null                  → 两项都继承域名
""                    → 两项都区分
"origin"              → Origin 忽略，语言区分
"origin,accept-language" → 两项都忽略
```

只建议在响应内容确实不随该头变化时使用。忽略 Origin 前必须确认 `Access-Control-Allow-Origin` 固定；忽略 Accept-Language 前必须确认站点不是多语言变体。

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

但源站返回 `s-maxage`、`must-revalidate` 或 `proxy-revalidate` 时，共享缓存不会在过期后继续返回旧内容，SWR 被抑制。

### 5.3 哪些响应可缓存

必须满足：

- `GET`（HEAD 复用 GET 缓存）
- 规则动作 `cache`
- 状态码可缓存（常见 200/203/204/300/301/308）
- 无 `Set-Cookie`
- 无 `no-store`
- 无 `private`
- 无 `no-cache`（即使存在规则 TTL 也不写入；本实现不保存“只能校验后使用”的条目）
- 无 `max-age=0` / `s-maxage=0`
- `Vary` 字段受支持，或没有 `Vary`
- 请求无 `Authorization`
- 请求无普通 Cookie（规则 `ignore_cookie` 例外）
- 请求带 `no-cache`/`max-age=0`/`Pragma: no-cache` 时走条件回源，不直接使用旧缓存

多个 `Cache-Control` 响应头会按逗号合并后解析；多个 `Vary` 头同理。

### 5.4 支持的 Vary

当前支持：

- `Accept-Encoding`
- `Accept-Language`
- `Origin`
- `Access-Control-Request-*`：GET/HEAD 忽略，不参与 key，也不因此拒绝缓存
- `Cookie`：拒绝缓存（Cookie 不在 cache key 中）

其他字段（例如 `User-Agent`）和 `Vary: *` 会拒绝缓存。

CORS `Vary` 会被哈希进 cache key，避免不同 Origin 串缓存。

### 5.5 请求 no-cache 的真实行为

请求带有以下任一项时，Edge 不直接使用旧缓存，而是走条件回源：

```text
Cache-Control: no-cache
Cache-Control: max-age=0
Pragma: no-cache
```

如果缓存对象有 `ETag` 或 `Last-Modified`：

- Edge 向源站发送 `If-None-Match` / `If-Modified-Since`
- 源站 `304 Not Modified`：复用缓存 body，刷新缓存头/存活时间
- 源站 `200`：用新响应替换缓存
- 响应头 `X-Lagran-Cache: REVALIDATED`
- 响应头 `X-Lagran-Cache-Reason: origin-304`（或 `origin-200`）

如果缓存对象没有 validator，或缓存不存在：

- 按普通回源处理

注意：

- 该过程仍会向源站发起一次条件请求，节省的是响应 body 和缓存重建，不是完全的本地 HIT
- `Cache-Control: no-store` 仍然是不读不写

这是本实现选择的保守 RFC 语义：不把请求的 `no-cache` 删除后直接 HIT。

### 5.6 响应头语义

缓存命中时：

- `Age` 按对象年龄生成
- 缺少 `Date` 时生成当前 `Date`
- 304 响应保留 `Cache-Control`、`Vary`、`Expires`、`Content-Location`、`Last-Modified`、`ETag`、`Age`
- `Set-Cookie` 不会从缓存回放
- `no-store`/`private` 的对象不会进入共享缓存

### 5.7 普通缓存与大对象缓存

| 项目 | 普通缓存 | 大对象缓存 |
|---|---|---|
| 存储 | 内存/磁盘 | 独立磁盘流式 |
| 单对象上限 | `MAX_CACHEABLE_BODY` | `LARGE_CACHE_MAX_OBJECT_BYTES`（完整对象；Range 片段可例外） |
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

- 完整对象：状态码 `200`、存在 `Content-Length`、对象大小在 `LARGE_CACHE_MIN_OBJECT_BYTES .. LARGE_CACHE_MAX_OBJECT_BYTES` 范围内
- Partial Range：源站返回 `206`、`Content-Range`、`Content-Length`；对象总大小可以超过 `LARGE_CACHE_MAX_OBJECT_BYTES`，只要单次缓存窗口不超过 `RANGE_FILL_MAX_BYTES`
- 响应可缓存：无 `Set-Cookie`、无 `no-store/private`、`Vary` 受支持
- 请求没有触发 Cookie/Authorization/no-store bypass
- 磁盘目录可写、容量足够

### 5.8 Partial Range

流程：

```text
Range 请求
  → 大缓存有覆盖该区间的 segment？
      ├─ 有：HIT，直接读磁盘返回 206
      └─ 无：透传源站 206
             → 后台按分段写入稀疏 .data
             → 只提交完整收到的字节段
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
  "content_length": 748814277,
  "complete": false,
  "segments": [[0, 33554431], [734003200, 748814276]]
}
```

这里表示：

```text
已缓存前 32 MiB
已缓存最后约 14 MiB
中间未缓存
```

开放式 Range 只缓存前缀，后缀 Range 只缓存尾部；带明确范围且不超过 `RANGE_FILL_MAX_BYTES` 的 Range 会缓存完整区间。客户端断开时，已经完整落盘的前缀仍会保留，但 `complete` 保持 `false`。

同一对象同时只允许一个 Range 写入者，避免多个请求并发写同一个稀疏 `.data` 文件导致元数据交错。

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

#### 稀疏文件与 `ls` 显示大小

大缓存 `.data` 文件使用稀疏文件：

```text
逻辑长度 = content_length
实际磁盘块 = 已写入 segment 覆盖的字节
```

因此：

```bash
ls -la 27557ef1a93d2e85.data
```

显示的：

```text
748814277
```

是**逻辑长度**，不是实际磁盘占用。

目录中的 `total` 更能反映实际块占用，例如：

```text
total 4768
```

约等于：

```text
segments 覆盖的字节数
+ 文件系统块开销
```

检查实际占用：

```bash
du -h 27557ef1a93d2e85.data
du -h --apparent-size 27557ef1a93d2e85.data
ls -lsh 27557ef1a93d2e85.data
stat -c 'size=%s blocks=%b block_size=%B' 27557ef1a93d2e85.data
```

示例：

```text
size     = 748814277   逻辑大小
blocks   = 已分配的 512B 块数量
实际字节 ≈ blocks × 512
```

不要把 `.data` 文件复制成非稀疏文件；备份时使用：

```bash
cp --sparse=always
rsync --sparse
tar --sparse
```

否则会实际占用完整逻辑大小。

### 5.9 视频 Range 与 504 优化

Chrome、DPlayer 等播放器常见的请求：

```http
Range: bytes=0-
```

这种开放式 Range 表示“从 0 到文件末尾”。

Edge 的策略：

```text
开放式 Range
  → 客户端继续从源站边下边播
  → 同时只把前 N 字节写入大缓存
  → 不等待整个视频下载完成
```

例如：

```http
Range: bytes=0-
```

不会缓存完整 700 MB 视频，而是缓存前：

```text
RANGE_FILL_MAX_BYTES
```

个字节。客户端仍会收到完整响应，不受缓存上限影响。

后续播放器如果请求：

```http
Range: bytes=1048576-2097151
```

且该区间已在前缀片段内，则直接命中大缓存。

`RANGE_FILL_MAX_BYTES` 是单次写入的**上限**，不是每次都会缓存这么多。实际 segment 大小取决于：

```text
客户端实际请求的 Range
源站实际返回的 Content-Range
客户端是否在达到上限前停止读取或断开
```

因此看到：

```json
"segments": [[0, 83746]]
```

是正常现象：播放器可能只请求了前 83,747 字节作为 MP4 头部，或在 32 MiB 前就断开了。它不会为了凑满 32 MiB 继续向源站读取。

带明确结束位置且不超过上限的 Range 会完整缓存：

```http
Range: bytes=0-1048575
```

后缀 Range 只缓存尾部：

```http
Range: bytes=-1048576
```

上限：

```env
RANGE_FILL_MAX_BYTES=33554432
```

大缓存使用稀疏文件保存对象，并在 sidecar 元数据中记录已完成的字节段：

```json
{
  "content_length": 748814277,
  "complete": false,
  "segments": [[0, 33554431]]
}
```

只有完整落盘的片段才会出现在 `segments` 中；客户端中断时，已完成的前缀仍会保留，不会被标记为完整对象。

说明：

```text
开放式 Range 本身仍需要源站补齐剩余区间
因为缓存中只有前缀
但前缀部分不再重复从源站下载
```

## 前缀 + 源站剩余区间拼接

当同一对象已有可用的连续前缀时，Edge 会把请求拆成两段：

```text
客户端 Range: bytes=0-

  [0 .. cached_end]      从 L3 大缓存读取
  [cached_end+1 .. end]  向源站请求剩余区间
  → 合并为一个 206 响应
```

响应头示例：

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-748814276/748814277
X-Cache: HIT
X-Lagran-Cache-Source: l3+origin
X-Lagran-Cache-Reason: range-splice
```

特点：

```text
前缀从磁盘读取，降低源站回源字节数
剩余区间按流式转发，不把完整对象读入内存
如果缓存前缀带 ETag / Last-Modified，会带 If-Range 校验对象未变化
源站返回 200（对象已变化）时回退普通回源
缓存内容带非 identity Content-Encoding 时不做拼接
```

拼接仍有源站请求，因此不是“纯缓存命中”；它优化的是：

```text
已经缓存的前缀不再重复下载
播放器 seek 回到开头时首段从磁盘返回，不再重复下载
```

仍需注意：

```text
多段 Range 不拼接
源站不支持 Range 时不拼接
```

原因：

```text
视频文件可能数百 MB
首次播放就写入完整大缓存会与客户端读取竞争磁盘
还可能写满缓存目录或拖慢其他请求
```

流媒体读取超时单独配置：

```env
ORIGIN_STREAM_READ_TIMEOUT_MS=120000
```

这样：

```text
普通 API 回源仍使用 30 秒空闲超时
视频 Range 使用更长超时
```

如果 Caddy 在 Edge 前面，建议关闭响应缓冲：

```caddyfile
reverse_proxy 127.0.0.1:8081 {
    flush_interval -1
}
```

`flush_interval -1` 让 Caddy 尽快把字节刷给播放器，避免中间层缓冲导致播放器等待。

### 5.9.1 回源超时体系

Edge 的“回源超时”不是一个单一值，而是按阶段和路径分开控制。

## 配置对照

| 配置 | 作用域 | 默认值 | 生效阶段 |
|---|---|---:|---|
| `origin_timeout_ms` | 单域名 | 10000 ms | Pingora 建连/连接超时；legacy 普通回源单次总超时 |
| `ORIGIN_READ_TIMEOUT_MS` | 整个 Edge | 30000 ms | Pingora 普通请求连接建立后的读空闲超时 |
| `ORIGIN_STREAM_READ_TIMEOUT_MS` | 整个 Edge | 120000 ms | Range/流式回源读空闲超时 |

`origin_timeout_ms = 0` 时按 10000 ms 处理。

## 域名“回源连接超时”

域名高级设置中的字段现在显示为：

```text
回源连接超时（毫秒）
```

对应：

```text
domains.origin_timeout_ms
```

Pingora 数据面：

```rust
peer.options.connection_timeout = Some(domain_timeout);
```

主要覆盖：

```text
TCP 建连
TLS 握手
源站连接建立阶段
```

它不负责：

```text
连接建立后等待响应头的空闲时间
视频持续传输的总时长
```

Legacy 普通回源：

```rust
tokio::time::timeout(domain_timeout, origin.request(...))
```

这里它是单次回源的总超时，包含：

```text
连接
发送请求
等待响应头
读取响应体
```

Legacy 流式回源现在使用 `ORIGIN_STREAM_READ_TIMEOUT_MS`，不再使用域名的连接超时。

## ORIGIN_READ_TIMEOUT_MS

Pingora 普通请求：

```rust
peer.options.read_timeout = Some(ORIGIN_READ_TIMEOUT_MS);
```

含义：

```text
连接建立后，等待/读取上游数据的空闲超时
```

它通常是空闲超时，而不是整个请求总时长：

```text
源站持续返回数据
→ 可以传输数小时
源站超过 30 秒没有任何数据
→ ReadTimedout
→ 504
```

它不覆盖：

```text
Range/视频流请求
Legacy 流式请求
```

## ORIGIN_STREAM_READ_TIMEOUT_MS

Range 请求和 legacy 流式回源使用：

```text
ORIGIN_STREAM_READ_TIMEOUT_MS
```

默认 120 秒，范围 5000–1800000 ms。

适用：

```text
Range: bytes=0-
Range: bytes=0-1048575
视频/音频流
legacy request_stream_with_sni
```

Pingora 仍使用域名的 `origin_timeout_ms` 建立连接；连接建立后使用 stream read timeout 等待数据。

## 选择原则

```text
源站 IP/端口不通、TLS 握手慢
→ 调整域名“回源连接超时”

连接成功，但普通 API 响应头/数据迟迟不来
→ 调整 ORIGIN_READ_TIMEOUT_MS

视频 Range 首字节慢
→ 调整 ORIGIN_STREAM_READ_TIMEOUT_MS

源站持续有数据但传输很久
→ 不需要调大；这是空闲超时，不是总时长
```

## 504 排查

500/504 响应头：

```http
x-lagran-error: ORIGIN_TIMEOUT
x-lagran-datapath: pingora
```

说明 Edge 到源站超时。

Edge 日志：

```text
proxy error while reading upstream
ReadTimedout
```

根据耗时判断：

| 现象 | 更可能的原因 |
|---|---|
| 约 10 秒失败 | 域名连接超时 |
| 约 30 秒失败 | 普通读空闲超时 |
| 约 120 秒失败 | 视频流读空闲超时 |
| 无 `x-lagran-*` 头、Caddy 报 upstream timeout | Caddy → Edge 层超时 |

Caddy 在 Edge 前面时，建议：

```caddyfile
reverse_proxy 127.0.0.1:8081 {
    flush_interval -1
}
```

并根据 Caddy 版本检查其上游超时配置。

## 推荐值

普通站点：

```env
ORIGIN_READ_TIMEOUT_MS=30000
ORIGIN_STREAM_READ_TIMEOUT_MS=120000
```

跨区域对象存储、冷启动视频：

```env
ORIGIN_READ_TIMEOUT_MS=60000
ORIGIN_STREAM_READ_TIMEOUT_MS=300000
```

源站连接本身较慢时，再单独调大域名的回源连接超时。
#### Age、TTL 与 SWR

`Age` 表示对象从写入缓存到现在的时间，不是剩余 TTL：

```text
Age = now - stored_at
```

缓存生命周期：

```text
fresh_until = stored_at + TTL
stale_until = stored_at + TTL + SWR
```

例如：

```text
规则 TTL = 10 秒
源站 Cache-Control: stale-while-revalidate=60
```

实际生命周期：

```text
0–10 秒：fresh
10–70 秒：stale，可在 SWR 窗口继续返回
>70 秒：删除并重新回源/填充
```

因此看到：

```http
Age: 63
X-Cache: STALE
```

并不矛盾：对象已经过期，但仍处于 SWR 窗口。

当前大对象 Range 命中会区分：

```text
Age <= TTL      → X-Cache: HIT
Age > TTL       → X-Cache: STALE
                 X-Lagran-Cache-Reason: stale-range
```

旧版本可能把 stale 的大对象 Range 也标成 `HIT`，此时只能通过 `Age` 和 `TTL` 判断。

如果希望视频严格只保留 10 秒，需要：

- 不继承源站 SWR（当前规则 SWR=0 表示继承，不能强制关闭）
- 或把 TTL 设置得覆盖实际播放会话
- 修改后 purge 旧 segment

对 700MB 级视频，TTL=10 通常过短，会在播放过程中不断失效。

### 5.9 缓存预热

预热接口：

```text
POST /api/v1/prefetch
{
  "domain": "cdn.example.com",
  "paths": ["/file.mp4"],
  "headers": {
    "accept-language": "zh-CN,zh;q=0.9",
    "origin": "https://www.example.com"
  }
}
```

`headers` 只接受 `accept-language` 和 `origin`。`Access-Control-Request-*` 属于 OPTIONS 预检，当前预热固定 GET 且预检缓存未启用，因此不接受。

预热行为：

- 控制面任务队列
- 下发到在线 Edge
- Edge 执行真实 GET
- 大对象会写入大缓存
- 普通对象写入普通缓存
- 预热请求可携带 `Accept-Language` / `Origin`，用于命中源站 `Vary` 变体
- 大对象超过 `RANGE_FILL_MAX_BYTES`（默认 32 MiB）时自动按 `Range: bytes=0-...` 预热前缀，避免完整下载导致回调超时
- Control → Edge 的预热回调默认 300 秒，可用 `PREFETCH_TIMEOUT_SECS` 调整
- 任务记录 warmed/failed

常见预热失败：

- 域名配置未同步
- 源站不可达
- 路径返回 404
- 普通对象超过 `MAX_CACHEABLE_BODY`，且大缓存关闭或超限
- 控制面回调 Edge 超时/`agent_url` 错误

预热路径必须与真实用户的 **cache key** 一致。默认 cache key 包含完整 query string，因此：

```text
用户请求：/app.js?lang=zh&label=prod
预热路径：/app.js
→ 两个不同的 cache key，预热无效
```

处理方式：

1. 预热时填写与用户完全一致的 URL，包括 `lang`、`label`、`code` 等参数；
2. 如果这些参数不影响内容，在域名高级设置中开启“忽略 Query”；
3. 或为有限的语言/标签组合分别创建预热任务。

不要对包含 `code`、`token`、签名参数的动态 URL 开启“忽略 Query”，否则不同用户会命中同一份缓存。

cache key 还可能包含请求头：

```text
Accept-Language → |lang=<hash>
Origin          → |origin=<hash>
```

如果这些头不影响响应体（例如单语言站点、固定的 CORS Origin），可以在 Edge 配置：

```env
CACHE_KEY_IGNORE_HEADERS=accept-language,origin
```

这样预热请求（不带这些头）与浏览器请求会命中同一个对象。

如果响应确实随语言或 Origin 变化，不能忽略；需要按实际请求头分别预热，或改用 `Vary` 响应头配合支持变体的缓存层。

### 5.9.1 源站 `Vary`

当前 Edge 对 `Vary` 的处理：

| Vary 字段 | 行为 |
|---|---|
| `Accept-Encoding` | 允许；只缓存 identity 表示 |
| `Accept-Language` | 参与 cache key |
| `Origin` | 参与 cache key |
| `Access-Control-Request-*` | GET/HEAD 兼容忽略；不参与 key；OPTIONS 预检缓存启用后再按方法处理 |
| `Cookie` | 拒绝缓存（key 不包含 Cookie） |
| `User-Agent` / 其它字段 | 拒绝缓存 |
| `*` | 拒绝缓存 |

同时：

- 部分 CORS 中间件会把 `Access-Control-Request-*` 加到所有响应的 `Vary`；GET/HEAD 会忽略这些字段，避免误拒绝缓存；
- 响应 `Vary` 会原样返回给客户端；
- 如果运维通过域名/规则或 `CACHE_KEY_IGNORE_HEADERS` 把某个头移出 key，对该头的 `Vary` 也按忽略处理；
- HEAD 复用 GET 的表示；
- 预热请求携带的 `headers` 会进入同一套 key 计算。

因此预热一个变体时，必须让 `headers` 与真实用户请求一致，或者确认该头已被配置为不参与 key。

### 5.10 缓存诊断

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

- 未配置 `REDIS_URL`：CC 使用进程内固定窗口，普通域名限流使用进程内 token bucket。
- 配置 Redis：CC 跨 Edge 共享排序集合滑动窗口，普通域名限流跨 Edge 共享 token bucket。
- CC Redis key 前缀：`CC_REDIS_PREFIX`，默认 `lagran:cc`。
- 普通限流 Redis key 前缀：`RATE_LIMIT_REDIS_PREFIX`，默认 `lagran:rate`。
- Redis 超时会回退本地。
- 多 Edge 必须使用相同 `REDIS_URL` 和相同前缀，才能共享同一预算。

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
- 管理端保留封禁历史，状态分为：

```text
active    生效中
expired   已过期
revoked   已解封
```

- 手动解封采用软撤销（记录 revoked_at/revoked_by），不再删除历史行。
- Edge 只同步 `active` 记录；过期和已解封记录只用于控制台审计。
- 历史接口：

```text
GET /api/v1/cc/bans/history?domain=cdn.example.com&limit=500
```

- 单次最多返回 1000 条，按创建时间倒序。
- 普通用户可以查看自己项目域名下的封禁历史，并对自己项目下有写权限的域名添加/解封。
- 管理员可以查看全部历史并执行添加、解封。
- 「共享封禁」页面直接使用当前「防护域名」的数据，不再单独选择域名。

### 6.7 行为评分

```env
CC_BEHAVIOR_ENABLED=true
CC_BEHAVIOR_SCORE=4
```

只对 HTML 动态/登录页面生效，根据 UA、Accept/Accept-Language/Accept-Encoding、Sec-CH-UA、Sec-Fetch-Mode/Dest、Cookie、Header 数量等评分；达到阈值先挑战。默认关闭。

新增信号：

- `HeadlessChrome`、Playwright、Puppeteer、Selenium、PhantomJS
- curl/wget/python/go/httpclient 等自动化 UA
- Chrome 类 UA 缺少 Sec-CH-UA
- `Sec-Fetch-Mode` 非法值
- `navigate` 但 `Sec-Fetch-Dest` 不是 document
- UA 同时包含 Chrome 与 Firefox
- 缺少 Accept/Accept-Language/Accept-Encoding/Cookie 或 Header 过少

命中后 WAF 事件的 `rule_name` 会带上原因，例如：

```text
behavior-score:headless-ua,navigate-dest-mismatch
```


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

`__lagran/metrics` 额外包含回源超时与流式转发指标：

- `lagran_edge_origin_timeouts_total`：连接/首字节/读取超时
- `lagran_edge_origin_errors_total`：其他回源错误
- `lagran_edge_origin_stream_requests_total`：legacy 流式回源请求
- `lagran_edge_origin_stream_bytes_total`：流式转发字节数
- `lagran_edge_origin_stream_errors_total`：流式 body 读取错误/空闲超时
- `lagran_edge_datapath_pingora_total`：由 Pingora 数据面处理的请求数
- `lagran_edge_datapath_legacy_total`：由 legacy 处理的请求数（WebSocket/兜底）

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

访问日志使用有界队列 + 反压：队列满时请求会等待写入完成，不再直接丢弃记录。磁盘长期阻塞会相应增加请求延迟；若需要“磁盘故障也不丢”，应再配置独立 spool。

访问日志中的 `cache_status` 只表示 Edge 缓存结果：

```text
HIT / MISS / EXPIRED / STALE / BYPASS / REVALIDATED / DYNAMIC / NONE
```

安全或特殊处理动作放在独立的 `action` 字段：

```text
WAF
CHALLENGE
CC
CC-BAN
CC-CHALLENGE
BOT-CHALLENGE
WS
HTTPS_REDIRECT
NODE_DISABLED
```

因此：

```text
status=304 + cache_status=BYPASS
```

表示客户端带了条件请求，但 Edge 没有可复用的缓存对象，直接把条件请求转发给源站；源站返回 304。
这并不表示 Edge 缓存命中。

如果是：

```text
status=304 + cache_status=REVALIDATED
```

才表示 Edge 有缓存对象，并向源站完成了条件校验。

### 7.4 关键响应头

| 头 | 含义 |
|---|---|
| `X-Powered-By: lagran-edge` | 确认请求由 Lagran Edge 处理 |
| `X-Cache` | `HIT` / `MISS` / `BYPASS` / `STALE` / `DYNAMIC` / `REVALIDATED` |
| `X-Cache-Status` | 同 `X-Cache` |
| `X-Lagran-Cache-Reason` | 未命中/绕过/填充原因 |
| `X-Lagran-Cache-Source` | 缓存来源：`l1` 本地内存、`l2` Redis、`l3` 大对象磁盘、`origin` 回源 |
| `X-Lagran-Cache-Lookup-MS` | 缓存查找耗时（毫秒）；回源 miss 记录为 0 |
| `Server-Timing` | `cache;dur=<毫秒>`，与缓存查找耗时对应 |
| `Age` | 缓存对象年龄 |
| `X-Lagran-Cache-TTL` | 缓存对象剩余新鲜寿命（秒）；`Age` 是已存活时间，两者互补 |
| `X-Lagran-Datapath` | `pingora` / `legacy`，标识本次请求实际走的数据面 |
| `ETag` | 源站或 Edge 生成 |
| `X-Lagran-Error` | 源站错误类型 |

常见 reason：

| reason | 说明 |
|---|---|
| `hit` | 命中 |
| `stale` | SWR 窗口返回旧内容 |
| `cookie` | Cookie 绕过 |
| `authorization` | Authorization 绕过 |
| `no-store` | 请求/响应 no-store |
| `no-cache` | 响应 no-cache，未写入共享缓存 |
| `request-no-cache` | 请求 no-cache 条件回源 |
| `request-max-age-0` | 请求 max-age=0 条件回源 |
| `request-pragma-no-cache` | 请求 Pragma: no-cache 条件回源 |
| `origin-304` | 条件回源命中 304，复用缓存 |
| `origin-200` | 条件回源返回 200，更新缓存 |
| `origin-empty-fallback` | 条件回源返回异常空 200，改为使用缓存 body |
| `vary` | Vary 不受支持 |
| `vary:user-agent` | Vary User-Agent |
| `vary:cookie` | Vary Cookie（Cookie 不参与 key） |
| `vary:*` | Vary: * |
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

### 9.7 no-cache 行为

请求带 `Cache-Control: no-cache`、`max-age=0` 或 `Pragma: no-cache`：

- 有 `ETag`/`Last-Modified` 时向源站发条件请求
- 源站 `304`：复用缓存 body，`X-Lagran-Cache: REVALIDATED`，`X-Lagran-Cache-Reason: origin-304`
- 源站 `200`：新响应覆盖缓存
- 没有 validator 时退回普通全量回源

响应带 `Cache-Control: no-cache`：

- 不写入共享缓存，即使命中路径规则也不覆盖
- 日志中的 `X-Lagran-Cache-Reason` 为 `no-cache`

如果要求“保存后每次条件请求 304 复用”，当前已由独立的条件校验路径处理；304 时不会重新下载 body。

### 9.8 预热失败

查看任务：

- 控制台「缓存预热」任务详情
- `warmed/failed` 消息
- Edge 访问日志

常见：

| 现象 | 原因 |
|---|---|
| `agent_url` 连接失败 | Edge 管理口不可达/端口错误 |
| 回调超时 | Edge 管理口被防火墙阻断；网络抖动 |
| 大文件无文件 | `MAX_CACHEABLE_BODY` 不足且大缓存关闭/超限 |
| 预热 404 | 路径错误或源站返回 404 |
| 预热后仍 MISS | 预热只影响对应 Edge；检查节点/cache key/query 参数 |
| 小文件预热后仍 MISS | 检查 `MAX_CACHEABLE_BODY`、响应 cache-control/Vary |

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

#### CNAME 配错

如果客户域名 CNAME 指向了源站、其他 CDN 或旧 Edge，域名诊断会显示类似：

```text
DNS 未解析出任何地址
解析到 203.0.113.10，但不在当前在线 Edge 地址 198.51.100.20 中
```

或：

```text
解析到 ...；当前没有在线 Edge 节点
```

处理：

1. 在控制台确认统一接入地址。
2. 检查客户 DNS 是否还有冲突的 A/AAAA/CNAME 记录。
3. 检查 CNAME 链是否最终指向当前在线 Edge IP。
4. 等待 DNS TTL 生效。
5. 确认节点 `status=online` 且 `public_ip` 非空。

诊断接口现在会并发执行 DNS/TLS/回源/缓存检查，并对每项设置超时，避免错误 CNAME 导致接口长时间挂起或直接返回“诊断失败”。

#### TLS 证书错误

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
- `GEOIP_PATH`（推荐 `ip2region_v4.xdb`）
- `GEOIP_IPV6_PATH`（可选 `ip2region_v6.xdb`）
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
- `no-cache` 响应不进入共享缓存；请求 no-cache、`max-age=0` 有 validator 时走条件请求 304 复用，无 validator 时回源。
- `only-if-cached`、`min-fresh`、`max-stale`、`stale-if-error` 尚未完整实现；请求 no-cache 选择直接回源。
- 修改缓存规则/配置不会自动删除旧缓存。
- 普通域名限流在配置 `REDIS_URL` 后由 Redis token bucket 跨 Edge 共享；未配置或 Redis 故障时回退进程内 bucket。
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

### 13.6 查询登录日志

```bash
curl -sS -H "$AUTH" 'https://console.example.com/api/v1/login-logs?limit=200' | jq
```

管理员调用时返回全部账号记录；普通用户调用时仅返回本人邮箱关联的记录。返回字段包含邮箱、来源 IP、User-Agent 与失败原因。

### 13.7 查看普通缓存

```bash
find /var/lib/lagran/cache -name '*.bin' -printf '%p %s\n' | head
```

### 13.8 Range 验证

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

### 13.9 检查 Edge 配置

```bash
systemctl show lagran-edge -p EnvironmentFiles -p ExecStart -p WorkingDirectory
tr '\0' '\n' < /proc/$(pgrep -f lagran-edge | head -1)/environ \
  | sort | grep -E '^(EDGE_|LARGE_|CACHE_|CC_|REDIS_)' \
  | grep -vE 'TOKEN|SECRET|PASSWORD'
```

注意不要在不安全终端打印 token 等敏感值。

### 13.10 常用 systemd

```bash
systemctl restart lagran-control
systemctl restart lagran-edge
systemctl restart lagran-dns

journalctl -u lagran-edge -f
journalctl -u lagran-control -n 200 --no-pager
journalctl -u lagran-dns -n 200 --no-pager
```

### 13.11 前端发布

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
