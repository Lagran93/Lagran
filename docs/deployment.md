# Lagran CDN 部署手册（Control → Edge → DNS）

> 适用版本：当前仓库 `main` 分支（`apps/control`、`apps/edge`、`apps/dns`、`apps/frontend`）
>
> 部署顺序：**先控制面（Control），再边缘（Edge），最后权威 DNS（DNS）**。
> 控制面提供配置/调度/证书；边缘依赖控制面；DNS 依赖控制面的调度接口。

---

## 目录

1. [架构与部署顺序](#1-架构与部署顺序)
2. [部署前准备](#2-部署前准备)
3. [构建与安装](#3-构建与安装)
4. [部署 Control](#4-部署-control)
5. [部署 Edge](#5-部署-edge)
6. [部署 DNS](#6-部署-dns)
7. [调度数据维护](#7-调度数据维护)
8. [防火墙](#8-防火墙)
9. [验收清单](#9-验收清单)
10. [日常运维](#10-日常运维)
11. [故障排查](#11-故障排查)
12. [安全清单](#12-安全清单)

---

## 1. 架构与部署顺序

```
                    ┌──────────────────────────────┐
 console.example.com│  Caddy :443                   │
                    │  /opt/lagran/web 静态前端      │
                    └──────────────┬───────────────┘
                                   │ /api/* 反代
                    ┌──────────────▼───────────────┐
                    │  lagran-control :8080        │
                    │  PostgreSQL :5432            │
                    └───────┬─────────────┬─────────┘
                            │             │
                    ┌───────▼──────┐ ┌────▼─────────┐
                    │ lagran-edge  │ │ lagran-dns   │
                    │ 80/443       │ │ 53 UDP/TCP   │
                    └──────────────┘ └──────────────┘
```

部署顺序的原因：

1. **Control**：数据库、管理员、控制台、证书、调度接口
2. **Edge**：需要控制台预注册节点、拿 `AGENT_TOKEN`、拉配置/证书
3. **DNS**：需要控制面 `/api/v1/schedule` 和在线节点数据

---

## 2. 部署前准备

### 2.1 域名与 IP 规划

示例：

| 用途 | 域名 | 指向 |
|---|---|---|
| 控制台 | `console.example.com` | 控制台服务器公网 IP |
| DNS Zone | `edge.lagran.net` | 权威 DNS |
| DNS NS | `ns1.edge.lagran.net`、`ns2.edge.lagran.net` | 两台 DNS 的 glue A |
| 客户 CDN | `cdn.example.com` | CNAME 到 `edge.lagran.net` |

IP 示例：

```
控制台: 203.0.113.10 / 内网 10.0.0.10
边缘:   203.0.113.21、203.0.113.22
DNS:    203.0.113.53、203.0.113.54
```

### 2.2 端口规划

| 机器 | 对公网开放 | 仅内网/本机 |
|---|---|---|
| 控制台 | 80、443（Caddy） | 8080（控制面） |
| 边缘 | 80、443 | Agent 端口（如果独立） |
| DNS | 53 UDP、53 TCP | — |
| PostgreSQL | — | 5432 |

### 2.3 系统依赖

Debian/Ubuntu：

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev perl \
  postgresql postgresql-contrib curl jq git rsync
```

构建机安装 Rust：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

前端构建需要 Node 20+。

### 2.4 用户与目录

推荐直接创建用户和同名组：

```bash
sudo useradd -r -U -m -d /var/lib/lagran -s /usr/sbin/nologin lagran
```

如果组已存在：

```bash
sudo groupadd --system lagran 2>/dev/null || true
getent passwd lagran >/dev/null || \
  sudo useradd -r -m -g lagran -d /var/lib/lagran -s /usr/sbin/nologin lagran
```

创建目录：

```bash
sudo mkdir -p /opt/lagran/{bin,web} /var/lib/lagran/{cache,certs}
sudo chown -R lagran:lagran /var/lib/lagran /opt/lagran
```

Caddy 日志目录（控制台机器）：

```bash
sudo mkdir -p /var/log/caddy
sudo chown -R caddy:caddy /var/log/caddy
```

---

## 3. 构建与安装

### 3.1 后端

```bash
cd /opt/src/lagran
cargo build --release -p control -p edge -p lagran-dns
```

安装：

```bash
sudo install -m 755 target/release/lagran-control /opt/lagran/bin/
sudo install -m 755 target/release/lagran-edge    /opt/lagran/bin/
sudo install -m 755 target/release/lagran-dns     /opt/lagran/bin/
```

### 3.2 旧版服务器 glibc 兼容

如果运行时报：

```text
GLIBC_2.29 not found
```

使用 musl 静态构建：

```bash
sudo apt install -y musl-tools build-essential perl
rustup target add x86_64-unknown-linux-musl

export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc

cargo build --release --target x86_64-unknown-linux-musl \
  -p control -p edge -p lagran-dns
```

验证：

```bash
file target/x86_64-unknown-linux-musl/release/lagran-edge
# 期望：statically linked / not a dynamic executable
```

### 3.3 前端

```bash
cd apps/frontend
npm ci
npm run generate
```

产物在 `.output/public/`。控制台安装到 Caddy：

```bash
sudo rsync -a --delete .output/public/ /opt/lagran/web/
sudo chown -R caddy:caddy /opt/lagran/web
sudo chmod -R a+rX /opt/lagran/web
```

---

## 4. 部署 Control

### 4.1 数据库

```bash
sudo -u postgres psql <<'SQL'
CREATE USER lagran WITH PASSWORD '替换成强密码';
CREATE DATABASE lagran OWNER lagran;
SQL
```

验证：

```bash
psql "postgres://lagran:替换成强密码@127.0.0.1:5432/lagran" -c 'select 1;'
```

控制面启动时自动执行 `apps/control/migrations`。

### 4.2 `control.env` 参数详解

`/etc/lagran/control.env`：

```bash
DATABASE_URL=postgres://lagran:强密码@127.0.0.1:5432/lagran
JWT_SECRET=替换成至少32字节随机串
CONTROL_BIND=127.0.0.1:8080
AGENT_TOKEN=替换成强随机串
CONTROL_PUBLIC_URL=https://console.example.com

GEOIP_PATH=/var/lib/lagran/geoip.dat
SCHEDULE_TTL=30
DNS_TEST_SERVER=203.0.113.53:53

# Let's Encrypt（生产默认；调试可切 staging）
ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
ACME_STAGING_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory
ACME_CONTACT_EMAIL=admin@lagran.dev

RUST_LOG=control=info,tower_http=warn,sqlx=warn
```

| 参数 | 必填 | 默认 | 详细说明 |
|---|---|---|---|
| `DATABASE_URL` | 是 | 无 | PostgreSQL 连接串。控制面所有域名、规则、节点、WAF、证书、审计数据都在这里。密码含特殊字符时要 URL 编码。 |
| `JWT_SECRET` | 生产必填 | 开发默认值 | 登录 JWT 的签名密钥。修改后所有已登录会话失效。建议 `openssl rand -base64 48`。 |
| `CONTROL_BIND` | 是 | `0.0.0.0:8080` | 控制面监听地址。生产放在 Caddy 后面时用 `127.0.0.1:8080`，只让本机访问。 |
| `AGENT_TOKEN` | 生产必填 | 空 | DNS 调度接口的全局令牌，也是旧节点回调的兜底令牌。**边缘心跳/配置必须使用节点 `auth_token`，不能使用该全局令牌**；为空只影响调度接口，不会放行未注册边缘。详见 4.3。 |
| `CONTROL_PUBLIC_URL` | 推荐 | 空 | 控制台公网地址，用于生成节点安装命令。为空时按请求 Host 推导；反向代理场景建议显式设置。 |
| `GEOIP_PATH` | 调度必填 | `./data/geoip.dat` | GeoIP 文件：支持 V2Ray/Loyalsoldier `geoip.dat` 或旧版 CIDR JSON。缺失时按权重/负载调度；启动时加载，修改后需重启。 |
| `GEOIP_JSON_PATH` | 否 | 空 | 兼容旧配置的 JSON 路径别名；设置了 `GEOIP_PATH` 时以 `GEOIP_PATH` 为准。 |
| `SCHEDULE_TTL` | 否 | `30` | `/api/v1/schedule` 返回的 TTL（秒），范围 5–3600。DNS 最终还会受 `DNS_TTL` 限制。 |
| `DNS_TEST_SERVER` | 否 | `127.0.0.1:53` | 控制台「DNS 测试」发起真实查询的目标 DNS 地址。应指向一台 `lagran-dns`。 |
| `ACME_DIRECTORY_URL` | 否 | Let's Encrypt 生产 | ACME v2 目录地址。生产默认 `https://acme-v02.api.letsencrypt.org/directory`。 |
| `ACME_STAGING_DIRECTORY_URL` | 否 | Let's Encrypt Staging | 测试目录地址；控制台选择「Staging」时使用，避免生产速率限制。 |
| `ACME_CONTACT_EMAIL` | 否 | 空 | ACME 账户联系邮箱，用于证书到期通知。建议填写。 |
| `RUST_LOG` | 否 | 见示例 | 日志级别。控制面用 `control=info`。 |

权限：

```bash
sudo chmod 640 /etc/lagran/control.env
sudo chown root:lagran /etc/lagran/control.env
```

如果 `lagran` 组不存在，见 2.4；也可以 `chown root:root` + `chmod 600`，systemd 以 root 读取 EnvironmentFile。

### 4.3 Agent Token 关系（重要）

边缘路由和 DNS 调度路由使用不同的鉴权策略：

| 凭据 | 使用位置 | 作用 |
|---|---|---|
| `edge_nodes.auth_token` | 数据库 | 预注册节点时生成，每个节点唯一 |
| `AGENT_TOKEN` | `edge.env` | 该节点自己的 token，必须等于 `edge_nodes.auth_token` |
| `AGENT_TOKEN` | `dns.env` | DNS 调用 `/api/v1/schedule` 的全局 token |
| `AGENT_TOKEN` | `control.env` | 全局 token；仅用于 DNS 调度，以及旧节点回调的兜底 |

### 边缘 → 控制面

边缘的配置上报、心跳、指标、日志、WAF、证书同步等接口使用
`AgentAuth`，只接受 **`edge_nodes.auth_token` 中的节点 token**：

```text
请求头 x-lagran-agent-token 必须存在于 edge_nodes.auth_token
并且节点必须已经在控制台预注册
```

- **全局 `AGENT_TOKEN` 不能用于边缘心跳/配置等接口**
- 未在控制台添加节点，即使知道其他节点的 token，也不能注册新节点
- 心跳里的 `NODE_ID` 必须等于该 token 所属节点名，否则返回 403
- 控制面不再自动创建未知节点

### DNS → 控制面

DNS 只调用 `/api/v1/schedule`，使用 `ScheduleAuth`：

```text
请求 token == control.AGENT_TOKEN
或
请求 token 存在于 edge_nodes.auth_token
```

DNS 不是边缘节点，推荐 DNS 使用全局 `AGENT_TOKEN`。  
如果 `control.AGENT_TOKEN` 为空，调度接口在开发环境下不校验。

### 控制面 → 边缘

控制面下发 purge、证书、ACME challenge 时：

```text
如果节点 auth_token 非空：使用该节点的 auth_token
否则：使用 control.AGENT_TOKEN
边缘校验：请求 token == edge.AGENT_TOKEN
```

推荐组合：

```text
control.AGENT_TOKEN = 全局强随机串 G
dns.AGENT_TOKEN     = G
edge.AGENT_TOKEN    = 该节点的 auth_token（安装命令自动带）
```

### 升级顺序（重要）

该版本开始，边缘接口不再接受全局 `AGENT_TOKEN`，也不会自动创建未知节点。升级时建议按以下顺序：

1. 在**旧控制面**中为每台边缘创建/确认节点，拿到节点 `auth_token`
2. 把节点 `auth_token` 写入对应 `/etc/lagran/edge.env` 的 `AGENT_TOKEN`
3. 重启所有 edge，确认仍能正常心跳
4. 最后再升级并重启 control

如果先升级 control，旧 edge 会立即 401，直到改为节点 token。

### 常见问题

**未预注册节点，直接用全局 token 启动 edge**

现在会失败：`401 invalid or missing agent token`。  
必须先在控制台「边缘节点」中创建节点，使用返回的节点 token。

**使用另一个节点的 token，但 NODE_ID 写成新名字**

会返回：

```json
{"error":"node_id does not match the agent token"}
```

不会创建新节点。

**升级前自动注册的旧节点 `auth_token` 为空**

这类节点需要重新在控制台创建并更换 `edge.env` 的 `AGENT_TOKEN`，或者手工为节点生成 token：

```sql
UPDATE edge_nodes
SET auth_token =
  replace(gen_random_uuid()::text, '-', '') ||
  replace(gen_random_uuid()::text, '-', '')
WHERE name = 'edge-kr-01'
RETURNING name, auth_token;
```

然后把返回的 token 写入该节点的 `/etc/lagran/edge.env` 并重启 edge。

排查：

```bash
psql "$DATABASE_URL" -c \
  "select name,status,public_ip,auth_token <> '' as has_token from edge_nodes;"
```

所有运行中的 edge 都必须是 `has_token = true`，且 `edge.env` 的 `AGENT_TOKEN` 与数据库一致。

### 4.4 systemd

`/etc/systemd/system/lagran-control.service`：

```ini
[Unit]
Description=Lagran Control Plane
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=lagran
Group=lagran
WorkingDirectory=/var/lib/lagran
EnvironmentFile=/etc/lagran/control.env
ExecStart=/opt/lagran/bin/lagran-control
Restart=always
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/lagran

[Install]
WantedBy=multi-user.target
```

启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lagran-control
sudo systemctl status lagran-control --no-pager
curl -s http://127.0.0.1:8080/health
```

首次启动会：

- 执行迁移
- 创建 demo 管理员 `demo@lagran.dev / demo123`
- 创建示例域名 `cdn.example.com`

### 4.5 Caddy 控制台

安装 Caddy：

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list

sudo apt update
sudo apt install -y caddy
```

如果之前装过 Nginx：

```bash
sudo systemctl disable --now nginx 2>/dev/null || true
```

`/etc/caddy/Caddyfile`：

```caddyfile
{
    email admin@lagran.dev
}

console.example.com {
    encode zstd gzip

    @api path /api/* /health
    handle @api {
        reverse_proxy 127.0.0.1:8080 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
        }
    }

    handle {
        root * /opt/lagran/web
        try_files {path} /index.html
        file_server
    }

    header {
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        Referrer-Policy strict-origin-when-cross-origin
        -Server
    }

    log {
        output file /var/log/caddy/console-access.log {
            roll_size 50MiB
            roll_keep 5
        }
    }
}
```

Caddyfile 参数说明：

| 指令/参数 | 详细说明 |
|---|---|
| `email` | Caddy 控制台证书的 ACME 账号邮箱；与「证书管理」里的 Let's Encrypt 证书无关。可省略。 |
| `console.example.com` | 站点地址；Caddy 自动申请/续期 HTTPS 证书。域名必须先解析到本机，80/443 可访问。 |
| `encode zstd gzip` | 对静态资源做压缩。 |
| `@api path /api/* /health` | 命名匹配器：API 与健康检查。 |
| `handle @api` | API 请求走反代；`handle` 之间互斥，顺序影响匹配。 |
| `reverse_proxy 127.0.0.1:8080` | 转发到控制面。 |
| `header_up Host {host}` | 保留原始 Host；`CONTROL_PUBLIC_URL` 未设置时安装命令依赖它。 |
| `header_up X-Real-IP {remote_host}` | 传真实客户端 IP；Caddy 会自动设置 `X-Forwarded-For`/`X-Forwarded-Proto`。 |
| `root * /opt/lagran/web` | 前端静态文件根目录。 |
| `try_files {path} /index.html` | SPA 路由回退；避免刷新 `/domains` 等路径 404。 |
| `file_server` | 提供静态文件。 |
| `header` | 安全响应头；`-Server` 移除 Caddy 版本标识。 |
| `log` | 访问日志与滚动策略。 |

校验并启动：

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy
curl -I https://console.example.com/
curl -s https://console.example.com/health
```

### 4.6 前端 API 地址

生产构建默认走同源：

```text
POST https://console.example.com/api/v1/auth/login
```

由 Caddy 反代到控制面。一般不需要设置 `NUXT_PUBLIC_API_BASE`。

如果旧构建出现：

```text
[POST] "http://localhost:8080/api/v1/auth/login": Failed to fetch
```

重新构建：

```bash
cd apps/frontend
rm -rf .output
npm run generate
```

上传后浏览器 **Ctrl + Shift + R** 硬刷新。

`NUXT_PUBLIC_API_BASE` 说明：

| 值 | 行为 |
|---|---|
| 不设置（生产） | 空字符串，同源请求 `/api/v1/...` |
| 不设置（`nuxt dev`） | 默认 `http://localhost:8080` |
| 设置 `https://console.example.com` | 使用绝对地址；需要控制面允许 CORS |
| 设置其他地址 | 构建时写入静态文件，修改后必须重新 `generate` |

### 4.7 创建管理员

登录控制台后注册自己的账号，然后提权：

```bash
psql "$DATABASE_URL" -c \
  "UPDATE users SET role='admin' WHERE email='you@example.com';"
```

确认新管理员可登录后，删除示例域名 `cdn.example.com`，并限制/删除 demo 账号。

### 4.8 Let's Encrypt 证书签发

控制台「证书管理」→「自动签发」支持三种方式：

| 方式 | 用途 |
|---|---|
| Let's Encrypt（生产） | 正式证书，90 天有效，控制面自动续期 |
| Let's Encrypt（Staging） | 调试 ACME 流程，浏览器不信任，避免生产速率限制 |
| 本地开发 CA | 无公网环境测试，自签证书 |

前置条件：

1. 控制面能访问 `https://acme-v02.api.letsencrypt.org`（出站 443）
2. 域名已接入控制台，并解析到**在线边缘节点**
3. 边缘 80 端口对公网开放（HTTP-01）
4. 边缘的 `AGENT_URL`、`AGENT_TOKEN` 正确，控制面能推送 challenge
5. 域名不能是泛域名（`*.example.com`）；HTTP-01 不支持

签发流程：

```text
控制台选择 Let's Encrypt
→ 控制面创建/复用 ACME 账户（acme_accounts 表）
→ newOrder
→ 生成 http-01 token + keyAuthorization
→ 推送到所有在线边缘节点的 /.well-known/acme-challenge/<token>
→ Let's Encrypt 从公网访问域名校验
→ finalize + 下载 PEM 证书链
→ 写入 certificates 表并推送到边缘
```

账户密钥持久化在 PostgreSQL 的 `acme_accounts` 表（按 ACME directory 区分），控制面重启/多实例无需重新注册。生产与 Staging 账户相互独立。

自动续期：

- 控制面每 6 小时检查一次
- `issuer = Let's Encrypt`、`auto_renew = true`、`status = active`
- 到期前 30 天内自动重新签发并更新原证书记录
- 续期失败只记录日志，不会删除旧证书

调试建议：

```bash
# 先在控制台选择 Staging 签发
# 成功后再用生产；Let's Encrypt 生产有速率限制
```

API 示例：

```bash
curl -X POST https://console.example.com/api/v1/certs/issue \
  -H "Authorization: Bearer <admin-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"domain_name":"cdn.example.com","provider":"letsencrypt","push_to_edges":true}'
```

常见失败原因：

- `DNS` 未指向边缘 / 边缘未 online
- 边缘 80 被防火墙拦截
- `AGENT_URL` 端口错误，challenge 没推送到边缘
- 域名开启了 Cloudflare 橙色云代理，HTTP-01 被代理拦截（改为 DNS only，或放行 `/.well-known/acme-challenge/`）
- 域名有 CAA 记录禁止 Let's Encrypt
- 触发 Let's Encrypt 速率限制（换 Staging 或等待）


---

## 5. 部署 Edge

### 5.1 控制台预注册节点

控制台 →「边缘节点」→「添加节点」：

| 字段 | 说明 |
|---|---|
| 名称 | 全局唯一，对应边缘 `NODE_ID`，如 `edge-gz-01` |
| 区域 | 展示/调度用，如 `guangdong` |
| 公网 IP | DNS 返回给用户的 IP；必须是真实边缘公网 IP |
| 国家/地区代码 | ISO 3166-1 两位代码，如 `CN` / `HK` / `US`；需与 GeoIP 的 country 一致，DAT 模式主要靠它加分 |
| 省份/城市 | 调度同省/同城加分（DAT 无省/市，需 JSON 才有） |
| 运营商 | `电信` / `联通` / `移动` / `BGP`，同运营商加分 |
| 权重 | 默认 100，越大越优先 |
| Agent 地址 | 控制面回调地址，指向管理面端口，如 `http://203.0.113.21:8081` |

创建后得到：

- 节点令牌 `auth_token`
- 二进制/Docker 安装命令
- 节点状态 `pending`

### 5.2 `edge.env` 参数详解

> 边缘公共网络层由 **Pingora** 负责：HTTP/1.1 + HTTP/2、HTTP/HTTPS 监听、SNI 动态证书
> 和连接管理。所有域名请求先做 WAF/CC/限流/防盗链/HTTPS 预检；
> 可缓存 GET 使用 `pingora-cache` + `upstream_peer`，缓存后端沿用 `SharedCache`；
> BYPASS/动态请求和 WebSocket 直接 `upstream_peer` 流式转发；GET Range 返回 206。
> HEAD 由同进程引擎处理并复用 GET cache key；health/ACME/challenge verify 和管理接口
> 由 Pingora 直接响应；未知/旧模式域名在进程内调用旧引擎，不再启动 loopback 监听。
> `EDGE_ADMIN_LISTEN` 设置时管理接口只在该端口接受，数据口返回 405。
> 公共 TLS 只由 Pingora 终止；旧 `EDGE_TLS_CERT` / `EDGE_TLS_KEY` 配置已移除。
> 编译使用 vendored OpenSSL，构建机需要 `perl`/`make`；musl 静态构建仍可用。

`/etc/lagran/edge.env`：

```bash
CONTROL_URL=http://10.0.0.10:8080
AGENT_TOKEN=该节点的 auth_token
NODE_ID=edge-gz-01
NODE_REGION=guangdong
PUBLIC_IP=203.0.113.21
AGENT_URL=http://203.0.113.21:8081

# 数据面：CDN 用户流量（80/443）
EDGE_LISTEN=0.0.0.0:80
EDGE_HTTPS_LISTEN=0.0.0.0:443
# 管理面：控制面回调 purge/cert/challenge，不暴露给公网用户
EDGE_ADMIN_LISTEN=0.0.0.0:8081
# EDGE_HTTPS_REDIRECT_PORT=443

CACHE_BACKEND=hybrid
CACHE_TTL=60
CACHE_CAPACITY=10000
DISK_CACHE_DIR=/var/lib/lagran/cache
DISK_CACHE_MAX_BYTES=1073741824
CERT_DIR=/var/lib/lagran/certs

TRUST_PROXY_HEADERS=false
CHALLENGE_SECRET=替换成随机串
WAF_REPORT=true
WAF_REPORT_INTERVAL=5
HEARTBEAT_INTERVAL=15
CC_SYNC_INTERVAL=5
RUST_LOG=edge=info,tower_http=warn
```

| 参数 | 必填 | 默认 | 详细说明 |
|---|---|---|---|
| `CONTROL_URL` | 是 | `http://127.0.0.1:8080` | 控制面地址。边缘用它拉配置、证书、上报心跳/指标/日志/WAF。生产建议内网 HTTP 或有效 HTTPS。 |
| `AGENT_TOKEN` | 生产必填 | 空 | 必须是该节点在控制台预注册时生成的 `auth_token`。边缘配置/心跳只接受节点 token，**不能用控制面全局 `AGENT_TOKEN`**；节点 token 为空时请重新创建节点。 |
| `NODE_ID` | 是 | `edge-001` | 节点唯一标识，对应控制台预注册名称。改名后需同步修改，否则会注册成新节点。 |
| `NODE_REGION` | 否 | `local` | 区域标签，首次心跳写入；控制台已填非空区域时不会被心跳覆盖。 |
| `PUBLIC_IP` | 调度必填 | 空 | 节点公网 IP，随心跳上报，DNS 调度返回这个地址。必须是对用户可访问的 IP。 |
| `AGENT_URL` | 是 | 根据 `EDGE_ADMIN_LISTEN` / `EDGE_LISTEN` 推导 | 控制面回调边缘的地址（purge、证书、ACME）。应指向 **`EDGE_ADMIN_LISTEN` 管理端口**，例如 `http://IP:8081`；控制面必须能访问。 |
| `EDGE_LISTEN` | 是 | `0.0.0.0:8081` | Pingora 公共 HTTP 监听：CDN 用户流量、WAF challenge verify、ACME HTTP-01 challenge。生产用 80。 |
| `EDGE_ADMIN_LISTEN` | 推荐 | 空 | 管理面监听：purge、证书加载、ACME challenge 下发、access-log。与控制面通信使用此端口；**不要对公网开放**，只允许控制面来源 IP。为空时兼容旧模式，管理接口仍留在数据面。 |
| `EDGE_HTTPS_LISTEN` | 否 | 空 | Pingora 公共 HTTPS 监听。生产用 `0.0.0.0:443`，需要已同步证书。为空表示不启用 TLS。 |
| `EDGE_HTTPS_REDIRECT_PORT` | 否 | 从 HTTPS 监听推导 | 域名开启 HTTPS 后，HTTP→HTTPS 跳转使用的端口。`443` 可省略；开发 8443 时写 8443。它只影响跳转 URL，不改变监听。 |
| `CACHE_BACKEND` | 否 | `memory` | `memory`：内存；`disk`：磁盘；`hybrid`：内存+磁盘。生产大文件建议 `hybrid`。 |
| `CACHE_TTL` | 否 | `60` | 默认缓存 TTL（秒）。规则 TTL 优先；否则依次用源站 `s-maxage`/`max-age`/`Expires`，最后用它。 |
| `CACHE_CAPACITY` | 否 | `10000` | 内存缓存最大对象数；`memory`/`hybrid` 使用。 |
| `DISK_CACHE_DIR` | 磁盘缓存必填 | `./data/cache` | 磁盘缓存目录；`disk`/`hybrid` 使用，需可写。 |
| `DISK_CACHE_MAX_BYTES` | 否 | 1 GiB | 磁盘缓存上限；超出按 mtime 淘汰。 |
| `CERT_DIR` | 否 | `./data/certs` | 证书持久化目录；边缘从控制面 `/certs/edge-sync` 拉取并落盘。 |
| `TRUST_PROXY_HEADERS` | 否 | `false` | 是否信任前置可信代理的 `X-Forwarded-For` / `X-Forwarded-Proto`。为 `false` 时 Pingora 用真实对端 IP 覆盖客户端伪造值；只有边缘前面还有 SLB/Cloudflare 时才开启。 |
| `CHALLENGE_SECRET` | 多节点必填 | 空 | WAF 质询 nonce/免质询 Cookie 的 HMAC 密钥。多节点必须一致；为空时用 `AGENT_TOKEN` 派生或进程随机（重启失效）。 |
| `WAF_REPORT` | 否 | `true` | 是否上报 WAF 事件。 |
| `WAF_REPORT_INTERVAL` | 否 | `5` | WAF 事件上报间隔（秒）。 |
| `HEARTBEAT_INTERVAL` | 否 | `15` | 心跳间隔（秒）。控制面约 60 秒无心跳标记离线。 |
| `CC_SYNC_INTERVAL` | 否 | `5` | 跨节点共享 CC 封禁拉取间隔（秒，最小 2）。 |
| `RUST_LOG` | 否 | `info` | 日志级别。 |

### 5.3 systemd

`/etc/systemd/system/lagran-edge.service`：

```ini
[Unit]
Description=Lagran Edge Node
After=network.target

[Service]
Type=simple
User=lagran
Group=lagran
WorkingDirectory=/var/lib/lagran
EnvironmentFile=/etc/lagran/edge.env
ExecStart=/opt/lagran/bin/lagran-edge
Restart=always
RestartSec=3
LimitNOFILE=100000
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/lagran

[Install]
WantedBy=multi-user.target
```

启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lagran-edge
curl -s http://127.0.0.1/__lagran/health
```

如果设置了 `EDGE_ADMIN_LISTEN`，健康检查走管理端口：

```bash
curl -s http://127.0.0.1:8081/__lagran/health
```

未设置 `EDGE_ADMIN_LISTEN` 时为兼容模式，使用 `http://127.0.0.1:<EDGE_LISTEN端口>/__lagran/health`。

控制台节点状态应变为 **online**。

### 5.4 证书与 HTTPS

证书有两种来源：

1. 控制台「证书管理」上传已有证书/私钥
2. 控制台「证书管理」→「自动签发」使用 Let's Encrypt（见 4.8）

步骤：

1. 控制台 →「证书管理」上传证书/私钥，或自动签发
2. 域名 → 编辑源站配置 → 勾选「启用 HTTPS」
3. 边缘从控制面同步证书到 `CERT_DIR`

验证：

```bash
curl -I http://cdn.example.com/
curl -I https://cdn.example.com/
```

如果 HTTP 不跳转：

- 检查 `ssl_enabled`
- 等待约 15 秒配置同步
- 检查 `EDGE_HTTPS_LISTEN` 与证书是否加载

### 5.5 同机部署冲突

Caddy 在控制台机器占用 443，边缘不能同时用 443。生产建议分机；同机时使用不同 IP 的 `bind`，或让边缘使用其他端口。

---

## 6. 部署 DNS

### 6.1 GeoIP 数据

控制面支持两种格式：

1. **V2Ray `geoip.dat`（推荐）**：来自
   [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)，按国家代码提供 CIDR。
2. **旧版 JSON**：CIDR → 国家/省/市/运营商，适合需要省市运营商打分的场景。

下载 `geoip.dat`：

```bash
sudo mkdir -p /var/lib/lagran
sudo wget -O /var/lib/lagran/geoip.dat \
  https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat
```

控制面：

```bash
GEOIP_PATH=/var/lib/lagran/geoip.dat
```

修改后重启控制面：

```bash
sudo systemctl restart lagran-control
```

`geoip.dat` 是 V2Ray `GeoIPList` protobuf；控制面只取 **两个字母的国家代码**
（如 `cn` → `CN`），会忽略 `private`、`telegram`、`cloudflare` 等非国家分类。
DAT 不包含省/市/运营商，因此调度只能按 `country` 匹配；节点库里的 `province`、
`city`、`isp` 字段会保持为空，节点打分只剩国家加分、权重和负载。

如果确实需要省/市/运营商，继续用旧 JSON：

```json
[
  {"cidr":"203.0.113.0/24","country":"CN","province":"广东","city":"深圳","isp":"电信"},
  {"cidr":"198.51.100.0/24","country":"CN","province":"北京","city":"北京","isp":"联通"}
]
```

```bash
GEOIP_PATH=/var/lib/lagran/geoip.dat
# 或 GEOIP_PATH=/var/lib/lagran/geoip.json
```

文件按扩展名识别：`.dat` 走 protobuf，`.json` 走 JSON；未知扩展名按内容探测。
文件不存在或解析失败时不会阻止控制面启动，调度退化为按权重/负载。

### 6.2 `dns.env` 参数详解

两台 DNS 使用**完全相同**的 Zone/NS 配置：

```bash
DNS_LISTEN=0.0.0.0:53
DNS_ZONE=edge.lagran.net

DNS_NS_NAME=ns1.edge.lagran.net,ns2.edge.lagran.net
DNS_NS_IP=203.0.113.53,203.0.113.54

DNS_SOA_MNAME=ns1.edge.lagran.net
DNS_SOA_RNAME=hostmaster.edge.lagran.net

DNS_TTL=30
DNS_CACHE_SECS=30
DNS_STALE_SECS=300
DNS_FALLBACK_IP=203.0.113.21

DNS_WORKERS=8
DNS_TCP=1
DNS_CONTROL_TIMEOUT_MS=800

CONTROL_URL=http://10.0.0.10:8080
AGENT_TOKEN=与控制面相同的全局令牌
RUST_LOG=lagran_dns=info
```

| 参数 | 必填 | 默认 | 详细说明 |
|---|---|---|---|
| `DNS_LISTEN` | 是 | `0.0.0.0:53` | UDP 与 TCP 监听地址。53 需要 root 或 `CAP_NET_BIND_SERVICE`。测试可用 `127.0.0.1:15353`。 |
| `DNS_ZONE` | 是 | `edge.lagran.net` | 权威 Zone，客户 CNAME 到这里。小写、不带末尾点。 |
| `DNS_NS_NAME` | 是 | `ns1.$zone` | NS 名称列表，逗号分隔。必须与父 Zone 的 NS 记录一致。 |
| `DNS_NS_IP` | 是 | `127.0.0.1` | 与 `DNS_NS_NAME` **按顺序一一对应**的 glue IP，逗号分隔。两台 DNS 必须配同一个列表，不能各自填自己。 |
| `DNS_SOA_MNAME` | 否 | 第一个 NS | SOA 主 NS 名。 |
| `DNS_SOA_RNAME` | 否 | `hostmaster.$zone` | SOA 管理员邮箱，格式用点代替 `@`。 |
| `DNS_TTL` | 否 | `30` | 调度 A 记录 TTL，范围 5–300。最终 TTL 取 `min(调度 TTL, DNS_TTL)`。 |
| `DNS_CACHE_SECS` | 否 | `5` | 调度结果本地缓存时间。每次缓存过期才调控制面；建议 10–30，降低 A 查询延迟。 |
| `DNS_STALE_SECS` | 否 | `300` | 控制面故障时允许使用旧缓存的最长时间。 |
| `DNS_FALLBACK_IP` | 否 | 空 | 控制面不可用且无缓存时返回的兜底 IP；为空则 SERVFAIL。应填一个可用边缘 IP。 |
| `DNS_WORKERS` | 否 | `8` | UDP 工作线程数。 |
| `DNS_TCP` | 否 | `1` | 是否启用 TCP 53（截断回退）。建议开启。 |
| `DNS_CONTROL_TIMEOUT_MS` | 否 | `800` | 调控制面 `/api/v1/schedule` 的超时（毫秒）。 |
| `CONTROL_URL` | 是 | `http://127.0.0.1:8080` | 控制面地址，DNS 用它查调度。 |
| `AGENT_TOKEN` | 生产必填 | 空 | DNS 出站令牌。DNS 不是节点，建议使用控制面全局 `AGENT_TOKEN`；用节点令牌也能通过，但删除该节点后会失效。 |
| `RUST_LOG` | 否 | `lagran_dns=info` | 日志级别。程序会确保 `lagran_dns` 至少 info，避免共享 `.env` 的 RUST_LOG 把 DNS 日志过滤掉。 |

NS 顺序示例：

```text
DNS_NS_NAME=ns1,ns2
DNS_NS_IP=203.0.113.53,203.0.113.54
→ ns1 = 203.0.113.53
→ ns2 = 203.0.113.54
```

### 6.3 systemd

`/etc/systemd/system/lagran-dns.service`：

```ini
[Unit]
Description=Lagran Authoritative DNS
After=network.target

[Service]
Type=simple
User=lagran
Group=lagran
WorkingDirectory=/var/lib/lagran
EnvironmentFile=/etc/lagran/dns.env
ExecStart=/opt/lagran/bin/lagran-dns
Restart=always
RestartSec=3
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/lagran

[Install]
WantedBy=multi-user.target
```

启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now lagran-dns
sudo systemctl status lagran-dns --no-pager
```

### 6.4 双 NS 与注册商

两台 DNS 都使用上面的 `DNS_NS_NAME` / `DNS_NS_IP` 列表。父 Zone 配置：

```dns
edge.lagran.net.      NS  ns1.edge.lagran.net.
edge.lagran.net.      NS  ns2.edge.lagran.net.
ns1.edge.lagran.net.  A   203.0.113.53
ns2.edge.lagran.net.  A   203.0.113.54
```

注意：

- `ns1`/`ns2` 的 A 记录必须是 **DNS only**（Cloudflare 灰色云），不能走代理
- 不要在两台服务器上分别把 `DNS_NS_IP` 改成自己；必须使用同一个列表
- 如果父 Zone 有旧 AAAA glue 但 DNS 没有 IPv6，删除 AAAA 或给 DNS 配 IPv6
- `edge.akgo.net` 的 NS 必须同时包含 ns1、ns2

### 6.5 DNS 测试

```bash
dig @203.0.113.53 edge.lagran.net SOA
dig @203.0.113.53 edge.lagran.net NS
dig @203.0.113.53 cdn.edge.lagran.net A +subnet=203.0.113.0/24
dig @203.0.113.53 cdn.edge.lagran.net A +tcp
```

两台分别执行，期望一致：

- NS 返回 2 条
- ADDITIONAL 返回 2 条 glue A
- cdn A 返回同一个边缘 IP
- TCP 正常

控制台「DNS 测试」需要控制面：

```bash
DNS_TEST_SERVER=203.0.113.53:53
```

---

## 7. 调度数据维护

控制台「边缘节点」字段：

| 字段 | 说明 |
|---|---|
| 公网 IP | 必须填写，DNS 返回它 |
| 国家/地区代码 | ISO 两位代码，如 `CN` / `HK` / `US`；需与 GeoIP 一致 |
| 省份/城市 | 同省/同城加分（DAT 模式无省/市） |
| 运营商 | 同运营商加分 |
| 权重 | 默认 100，越大越优先 |
| 状态 | 只有 online 参与调度 |

心跳会更新在线状态、CPU/内存、版本、`PUBLIC_IP`；省份/城市/运营商/权重由控制台维护。

调度测试：

- 「调度测试」：输入 IP/省份/运营商，查看主备节点与得分
- 「DNS 测试」：控制面向 `DNS_TEST_SERVER` 发起真实查询

---

## 8. 防火墙

控制台：

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

8080/5432 只允许本机/内网。

边缘：

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
# 管理面只允许控制面来源 IP；不要对公网开放 8081
sudo ufw allow from 10.0.0.10 to any port 8081 proto tcp
```

DNS：

```bash
sudo ufw allow 53/udp
sudo ufw allow 53/tcp
```

---

## 9. 验收清单

### Control

```bash
curl -s http://127.0.0.1:8080/health
curl -s https://console.example.com/health
```

### Edge

```bash
curl -s http://EDGE_IP/__lagran/health
curl -H 'Host: cdn.example.com' http://EDGE_IP/
```

### HTTPS

```bash
curl -I http://cdn.example.com/
curl -I https://cdn.example.com/
```

### DNS

```bash
dig @DNS1_IP cdn.edge.lagran.net A
dig @DNS1_IP cdn.edge.lagran.net A +subnet=203.0.113.0/24
dig @DNS1_IP cdn.edge.lagran.net A +tcp
dig @DNS2_IP cdn.edge.lagran.net A
```

### 调度

- 调度测试主节点符合预期
- 停用节点后不再返
- 控制面停机后 DNS 仍能返回缓存结果

---

## 10. 日常运维

### 升级

```bash
cd /opt/src/lagran
git pull
cargo build --release -p control -p edge -p lagran-dns

sudo systemctl stop lagran-edge
sudo install -m 755 target/release/lagran-edge /opt/lagran/bin/
sudo systemctl start lagran-edge

sudo systemctl stop lagran-control
sudo install -m 755 target/release/lagran-control /opt/lagran/bin/
sudo systemctl start lagran-control

sudo systemctl stop lagran-dns
sudo install -m 755 target/release/lagran-dns /opt/lagran/bin/
sudo systemctl start lagran-dns
```

前端：

```bash
cd apps/frontend
npm ci
npm run generate
sudo rsync -a --delete .output/public/ /opt/lagran/web/
sudo chown -R caddy:caddy /opt/lagran/web
sudo systemctl reload caddy
```

### 备份

```bash
pg_dump "$DATABASE_URL" > /var/backups/lagran-$(date +%F).sql
```

同时备份：

- `/etc/lagran/*.env`
- `/var/lib/lagran/certs`
- `/var/lib/lagran/geoip.dat`（或旧版 `geoip.json`）
- `/var/lib/caddy`（Caddy 证书）
- `/opt/lagran/web`

### 日志

```bash
journalctl -u lagran-control -f
journalctl -u lagran-edge -f
journalctl -u lagran-dns -f
journalctl -u caddy -f
tail -f /var/log/caddy/console-access.log
```

---

## 11. 故障排查

### 登录请求打到 localhost:8080

```text
[POST] "http://localhost:8080/api/v1/auth/login": Failed to fetch
```

前端构建时写死了 API 地址。重新 `npm run generate`，上传后硬刷新。确认 Caddy `/api/*` 反代生效：

```bash
curl -i https://console.example.com/api/v1/auth/login \
  -X POST -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo123"}'
```

### DNS 启动无输出

```bash
ss -lunp | grep ':53'
ss -ltnp | grep ':53'
id -u
```

- 非 root 绑定 53 → `Permission denied`
- 53 被 systemd-resolved 占用 → 关闭 stub 或改端口
- 测试用 `DNS_LISTEN=127.0.0.1:15353`

### `GLIBC_2.29 not found`

使用 musl 静态构建，见 3.2。

### `scp: not a regular file`

`scp` 递归是小写 `-r`：

```bash
scp -P 2027 -r ./* root@host:/opt/lagran/web/
```

推荐 `rsync -avz --delete`。

### `chown: invalid group: root:lagran`

```bash
sudo groupadd --system lagran
sudo usermod -aG lagran lagran
sudo chown root:lagran /etc/lagran/control.env
```

或 `chown root:root` + `chmod 600`。

### 心跳正常但 purge/证书 401

`edge.AGENT_TOKEN` 与 `edge_nodes.auth_token` 不一致。见 4.3。

### Caddy 证书失败

```bash
journalctl -u caddy -f
```

检查域名解析、80/443、Cloudflare 代理状态。

### Caddy 页面 404

```bash
ls /opt/lagran/web/index.html
sudo -u caddy ls /opt/lagran/web
```

Caddyfile 必须有 `try_files {path} /index.html` + `file_server`。

### API 502

```bash
curl -s http://127.0.0.1:8080/health
```

### DNS 双机不一致

检查两台：

```bash
DNS_NS_NAME
DNS_NS_IP
DNS_ZONE
CONTROL_URL
AGENT_TOKEN
```

两台必须相同；`DNS_NS_IP` 不能各自写自己。

### NS/glue 不一致

```bash
dig @rob.ns.cloudflare.com ns1.example.com A +short
dig @DNS1 ns1.example.com A +short
```

父 Zone 与子 Zone 必须一致。

### A 记录指向 DNS 而不是边缘

检查控制台节点 `public_ip`；`cdn` A 必须是边缘公网 IP，不是 DNS 服务器 IP。

### A 查询 0.5 秒

调大 `DNS_CACHE_SECS`，并检查控制面调度接口延迟。

---

## 12. 安全清单

- 修改 `JWT_SECRET`、`AGENT_TOKEN`、`CHALLENGE_SECRET`、数据库密码
- 控制台只开放 443；8080/Agent/5432 不暴露公网
- 限制控制台来源 IP 或加 VPN
- 删除/禁用 demo 管理员
- 定期备份数据库、证书、GeoIP、配置
- DNS 53 端口做限速/清洗
- 监控证书、节点心跳、DNS 解析
- 生产建议边缘与 DNS 多节点、异地域部署

---

## 附：部署顺序速查

```text
1. 准备系统/用户/目录/数据库
2. 构建 control/edge/lagran-dns + 前端 generate
3. 启动 lagran-control
4. 配置 Caddy + 上传前端
5. 登录控制台，创建管理员
6. 控制台添加节点，得到 auth_token
7. 配置 edge.env，启动 lagran-edge
8. 上传证书，开启域名 HTTPS
9. 配置 geoip.dat（或 geoip.json）、dns.env
10. 启动两台 lagran-dns
11. Cloudflare/注册商配置 ns1/ns2 + glue
12. 验证 NS/A/TCP/ECS/调度
```
