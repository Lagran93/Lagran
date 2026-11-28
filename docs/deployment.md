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
 console.example.com│  Caddy/Nginx :443              │
                    │  /opt/lagran/web 静态前端      │
                    └──────────────┬───────────────┘
                                   │ /api/* 反代
                    ┌──────────────▼───────────────┐
                    │  lagran-control :8080        │
                    │  PostgreSQL :5432            │
                    │  Redis :6379（可选）          │
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
| 控制台 | 80、443（Caddy/Nginx） | 8080（控制面） |
| 边缘 | 80、443 | Agent 端口（如果独立） |
| DNS | 53 UDP、53 TCP | — |
| PostgreSQL | — | 5432 |
| Redis（可选） | — | 6379 |

### 2.3 系统依赖

Debian/Ubuntu：

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev perl \
  postgresql postgresql-contrib curl jq git rsync
```

> Redis、Caddy/Nginx、Certbot 都是可选组件，分别在 4.2、4.6 安装；
> 只部署单机最小环境时可以先只装上面的 PostgreSQL。

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

反向代理日志目录：

- Caddy：安装后在 4.6.1 创建 `/var/log/caddy`；
- Nginx：软件包会自动创建 `/var/log/nginx`，无需手工建。


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

产物在 `.output/public/`。控制台安装到反向代理静态目录：

```bash
sudo mkdir -p /opt/lagran/web
sudo rsync -a --delete .output/public/ /opt/lagran/web/
sudo chown -R root:root /opt/lagran/web
sudo chmod -R a+rX /opt/lagran/web
```

静态文件只需要可读，不依赖 Caddy/Nginx 的运行用户；这样两种反代都能直接使用。

---

## 4. 部署 Control

推荐按下面的顺序完成 Control：

```text
4.1 PostgreSQL → 4.2 Redis（可选）→ 4.3 control.env → 4.5 systemd
→ 4.6 反向代理（Caddy/Nginx）→ 4.7 前端 → 4.8 管理员 → 4.9 证书
```

### 4.1 PostgreSQL（数据库）

控制面把域名、规则、节点、WAF、证书、审计等数据全部保存在 PostgreSQL。
`lagran-control` 启动时会自动执行 `apps/control/migrations`，不需要手工建表。

推荐 PostgreSQL 14+：

| 系统 | 默认版本 | 说明 |
|---|---|---|
| Ubuntu 24.04 LTS | PostgreSQL 16 | 推荐 |
| Ubuntu 22.04 LTS | PostgreSQL 14 | 满足要求 |
| Debian 12 | PostgreSQL 15 | 满足要求 |

> 已有托管 PostgreSQL（RDS、Cloud SQL、自建主从）时，跳过 4.1.1 的安装，
> 直接从 4.1.3 创建库和用户，并按 4.1.5 配置 TLS/网络。

#### 4.1.1 安装 PostgreSQL

Debian/Ubuntu：

```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

确认版本、集群和服务状态：

```bash
psql --version
pg_lsclusters
sudo systemctl status postgresql --no-pager
pg_isready -h 127.0.0.1 -p 5432
```

`pg_lsclusters` 会显示版本、端口、数据目录和状态，例如：

```text
Ver Cluster Port Status Owner    Data directory              Log file
16  main    5432 online postgres /var/lib/postgresql/16/main /var/log/postgresql/postgresql-16-main.log
```

下面的 `16/main` 要替换成实际的版本/集群名。

#### 4.1.2 本地认证与监听

先确认配置文件位置：

```bash
sudo -u postgres psql -c "SHOW hba_file;"
sudo -u postgres psql -c "SHOW config_file;"
```

Debian/Ubuntu 默认的 `pg_hba.conf` 通常已经包含：

```text
local   all             postgres                                peer
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
```

控制面走 TCP 连接 `127.0.0.1:5432`，所以必须保留两行 `host ... scram-sha-256`。
不要为了省事改成 `trust`。修改后 reload：

```bash
sudo systemctl reload postgresql
```

确认密码加密方式：

```bash
sudo -u postgres psql -c "SHOW password_encryption;"
# 期望：scram-sha-256
```

如果数据库只给本机控制面使用，确认 `postgresql.conf`：

```conf
listen_addresses = 'localhost'
port = 5432
```

修改后：

```bash
sudo systemctl restart postgresql
sudo ss -lntp | grep 5432
# 期望只看到 127.0.0.1:5432 / [::1]:5432，而不是 0.0.0.0:5432
```

> 不要把 5432 暴露到公网。远程数据库必须走内网/VPC、防火墙白名单，
> 并启用 TLS（见 4.1.5）。

#### 4.1.3 创建数据库用户与库

生成一个只含十六进制的随机密码，避免 `@ : / ? #` 等字符破坏连接串：

```bash
PGPASSWORD="$(openssl rand -hex 24)"
echo "$PGPASSWORD"
```

创建角色和数据库（在 `postgres` 系统用户下执行）：

```bash
sudo -u postgres psql <<SQL
CREATE ROLE lagran LOGIN PASSWORD '$PGPASSWORD';
CREATE DATABASE lagran
    OWNER lagran
    ENCODING 'UTF8'
    TEMPLATE template0;
REVOKE ALL ON DATABASE lagran FROM PUBLIC;
GRANT CONNECT ON DATABASE lagran TO lagran;
SQL
```

说明：

- `OWNER lagran` 让 `lagran` 拥有库并可在 `public` schema 建表；
- `TEMPLATE template0` 避免从模板库继承意外的编码/扩展；
- 不要用 PostgreSQL 超级用户 `postgres` 跑控制面；
- 若角色已存在，先确认是否要改密码：
  `ALTER ROLE lagran WITH PASSWORD '...';`

验证角色和库：

```bash
sudo -u postgres psql -c "\du lagran"
sudo -u postgres psql -c "\l lagran"
```

#### 4.1.4 用 TCP 验证连接

```bash
PGPASSWORD="$PGPASSWORD" psql \
  "host=127.0.0.1 port=5432 user=lagran dbname=lagran sslmode=disable" \
  -c "select current_user, current_database(), version();"
```

期望返回 `lagran | lagran | PostgreSQL 16...`。

生成并导出 `DATABASE_URL`：

```bash
export DATABASE_URL="postgres://lagran:${PGPASSWORD}@127.0.0.1:5432/lagran?sslmode=disable"
echo "$DATABASE_URL"
```

将结果写入 `/etc/lagran/control.env` 的 `DATABASE_URL=`。
注意：`/etc/lagran/control.env` 由 systemd 直接读取，**不会展开 `${PGPASSWORD}`**，
必须写入展开后的完整连接串。

如果密码不是十六进制（手工设置、包含特殊字符），必须 URL 编码：

```bash
python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$PGPASSWORD"
```

例如 `p@ss/word` 要写成 `p%40ss%2Fword`。

#### 4.1.5 生产参数与远程数据库

控制面每个进程默认最多 32 个连接。多副本部署时先算总连接数：

```text
总连接数 ≈ control 副本数 × DATABASE_MAX_CONNECTIONS + 运维/备份预留
```

例如 3 个 control 副本、每进程 32 个连接，至少给 PostgreSQL 预留 120–150，
再确认 `max_connections` 足够。连接不够时控制面日志会出现
`pool timed out while waiting for an open connection`。

单机小规模部署可从下面的保守值开始（以 4 GB+ 内存为例），按实际内存和并发调整：

```conf
# /etc/postgresql/16/main/postgresql.conf
max_connections = 200
shared_buffers = 1GB              # 约物理内存的 25%
effective_cache_size = 3GB        # 约物理内存的 50%–75%
work_mem = 8MB                    # 复杂查询多时再调大
maintenance_work_mem = 256MB
```

修改后重启 PostgreSQL，并用 `pg_stat_activity` 观察连接数。

远程数据库（RDS/Cloud SQL/独立数据库机）：

1. 只允许控制面所在内网/VPC 的出口 IP 访问 5432；
2. 数据库启用 TLS，连接串使用 `sslmode=verify-full`（或至少 `require`）；
3. 应用账号只拥有业务库权限，不使用超级用户；
4. 把云厂商 CA 放到控制面机器，例如 `/etc/lagran/rds-ca.pem`；
5. 连接串示例：

```text
postgres://lagran:密码@db.internal:5432/lagran?sslmode=verify-full&sslrootcert=/etc/lagran/rds-ca.pem
```

#### 4.1.6 迁移、备份与升级

- 首次启动 `lagran-control` 会自动执行 migrations；
- 升级前先备份，并确认迁移日志没有失败；
- 大表升级前请先读 4.4.1「升级前预建索引」；
- 查看迁移状态：

```bash
PGPASSWORD="$PGPASSWORD" psql "$DATABASE_URL" \
  -c "select version, description, success from _sqlx_migrations order by version;"
```

日常备份见第 10 章「备份」；最低要求是每天一次 `pg_dump`，并定期做恢复演练。

#### 4.1.7 常见错误

| 现象 | 原因 | 处理 |
|---|---|---|
| `password authentication failed` | `pg_hba.conf` 仍是 peer/ident，或密码不一致 | 确认有 `host ... scram-sha-256`，reload 后重试 |
| `database "lagran" does not exist` | 库名写错或没建库 | 用 `\l` 确认，重新执行 4.1.3 |
| `too many connections` | 连接池总和超过 `max_connections` | 调大 `max_connections` 或降低每进程池上限 |
| `invalid URL` / 认证串解析失败 | 密码含 `@ : /` 等未编码 | 用 4.1.4 的 URL 编码 |
| 启动时报 migration 失败 | 数据库权限不足/磁盘满/锁等待 | 看 `journalctl -u lagran-control` 和 PostgreSQL 日志 |


### 4.2 Redis（可选，生产建议启用）

Redis 不是控制面的权威数据库，但启用后可以把以下状态从单进程提升为跨副本共享：

- 登录限流、验证码、会话缓存；
- 配置缓存与分布式锁；
- 实时统计/CC 计数；
- Edge 的跨节点 CC 与普通限流。

不配置 Redis 时，控制面会回退到进程内状态或 PostgreSQL，单机可用；
多副本控制面、或希望重启后少打数据库时，建议部署 Redis 6+（ACL 需要 Redis 6）。

#### 4.2.1 安装

Debian/Ubuntu：

```bash
sudo apt update
sudo apt install -y redis-server
sudo systemctl enable --now redis-server
redis-cli ping
# 期望：PONG
```

确认版本：

```bash
redis-server --version
# 需要 6.0+，推荐 7.x
```

#### 4.2.2 基础配置

编辑 `/etc/redis/redis.conf`，至少确认：

```conf
bind 127.0.0.1 ::1
protected-mode yes
port 6379
timeout 0
tcp-keepalive 300
```

容量和淘汰策略按用途选择：

```conf
# 只作为缓存/会话/限流状态时，给一个明确上限，避免吃满内存
maxmemory 1gb
maxmemory-policy noeviction
```

- `noeviction`：内存满时写失败，应用会走降级路径；适合不想静默丢锁/限流状态的场景。
- `allkeys-lru`：只建议把 Redis 当纯缓存、且能接受会话/限流状态被淘汰时使用。
- 不要把 Redis 当唯一数据源；控制面的权威数据始终在 PostgreSQL。

本项目的 Redis 数据可以丢失，是否持久化取决于你是否希望重启后保留限流/会话：

```conf
# 推荐：临时状态不落盘，降低 I/O
# 先注释掉原有的 save 3600 1 / save 300 10 等行，再写：
appendonly no
save ""

# 如果希望重启后保留短时间状态，可改为：
# appendonly yes
# appendfsync everysec
```

重启并确认只监听回环：

```bash
sudo systemctl restart redis-server
sudo ss -lntp | grep 6379
# 期望只有 127.0.0.1:6379 / [::1]:6379
```

> 远程 Redis 必须走内网/VPC、防火墙白名单，并启用 TLS（`rediss://`）。
> 不要把 6379 暴露到公网；Redis 未授权访问是常见入侵入口。

#### 4.2.3 创建 ACL 用户

不要直接把 `requirepass` 的 default 用户交给应用。使用 Redis ACL 限制
key 前缀和危险命令：

```bash
REDIS_PASSWORD="$(openssl rand -hex 24)"
echo "$REDIS_PASSWORD"
```

生成 ACL 文件 `/etc/redis/users.acl`：

```bash
sudo tee /etc/redis/users.acl >/dev/null <<EOF
user default off
user lagran on >$REDIS_PASSWORD ~lagran:* +@all -@admin -@dangerous
EOF
sudo chown redis:redis /etc/redis/users.acl
sudo chmod 640 /etc/redis/users.acl
```

启用 ACL 文件：

```bash
# 如果 redis.conf 里已有 aclfile 行，改成下面这行；没有就追加
sudo sed -i 's|^[# ]*aclfile .*|aclfile /etc/redis/users.acl|' /etc/redis/redis.conf
grep -q '^aclfile ' /etc/redis/redis.conf || \
  echo 'aclfile /etc/redis/users.acl' | sudo tee -a /etc/redis/redis.conf

sudo systemctl restart redis-server
```

ACL 说明：

| 规则 | 作用 |
|---|---|
| `user default off` | 关闭无密码的默认用户，避免空认证 |
| `~lagran:*` | 只允许读写 `lagran:` 开头的 key；控制面/Edge 的 key 都使用该前缀 |
| `+@all -@admin -@dangerous` | 允许业务命令，禁止 ACL/CONFIG/FLUSHALL 等管理与危险命令 |
| `>密码` | 设置该用户密码 |

如果你修改了 `CACHE_REDIS_PREFIX`、`CC_REDIS_PREFIX` 或 `RATE_LIMIT_REDIS_PREFIX`，
必须同步调整 ACL 的 `~lagran:*` 模式，否则会出现 `NOPERM`。建议保持默认前缀。


验证：

```bash
redis-cli --user lagran --pass "$REDIS_PASSWORD" --no-auth-warning ping
# PONG

redis-cli --user lagran --pass "$REDIS_PASSWORD" --no-auth-warning \
  set lagran:test ok
redis-cli --user lagran --pass "$REDIS_PASSWORD" --no-auth-warning \
  get lagran:test
# ok

# 越界 key 必须被拒绝（NOPERM）
redis-cli --user lagran --pass "$REDIS_PASSWORD" --no-auth-warning \
  set other:test nope
```

如果后续要在线调整 ACL，使用本机 root 编辑 `/etc/redis/users.acl` 后
`systemctl restart redis-server`；应用用户没有 `@admin`，不能自己改 ACL。
修改 ACL 后不要忘记验证 `REDIS_URL` 仍能连接。

#### 4.2.4 接入 control.env

十六进制密码不需要 URL 编码。把密码替换成 4.2.3 生成的实际值：

```env
REDIS_URL=redis://lagran:替换成上面生成的密码@127.0.0.1:6379/0
```

> systemd 的 `EnvironmentFile` 不会展开 shell 变量。不要写成
> `${REDIS_PASSWORD}`，否则控制面会拿这个字面量去认证并得到 `WRONGPASS`。

写入 `/etc/lagran/control.env` 后重启控制面，检查：

```bash
sudo systemctl restart lagran-control
sudo journalctl -u lagran-control -n 50 --no-pager | grep -i redis
# 期望看到 Redis 连接/会话缓存启用；没有 Redis 也不影响启动
redis-cli --user lagran --pass "$REDIS_PASSWORD" --no-auth-warning info keyspace
```

多副本控制面必须使用同一个 Redis；不同副本的 `REDIS_URL` 指向不同库会导致
限流和锁各算各的。

#### 4.2.5 常见错误

| 现象 | 原因 | 处理 |
|---|---|---|
| `NOAUTH Authentication required` | 应用没带密码/仍用 default | 检查 `REDIS_URL` 是否含用户和密码 |
| `WRONGPASS` | 密码错误或 ACL 未加载 | 用 4.2.3 的 `redis-cli --user ...` 验证 |
| `NOPERM ...` | key 前缀不在 `~lagran:*` 内 | 检查 `REDIS_URL` 的库/前缀配置 |
| `OOM command not allowed` | `maxmemory` 满且 `noeviction` | 扩容、清理无用 key，或评估改用 `allkeys-lru` |
| 控制面正常但多副本限流不准 | 副本连了不同 Redis/DB | 统一 `REDIS_URL` 和 DB 编号 |

### 4.3 `control.env` 参数详解

`/etc/lagran/control.env`：

```bash
DATABASE_URL=postgres://lagran:强密码@127.0.0.1:5432/lagran
JWT_SECRET=替换成至少32字节随机串
CONTROL_BIND=127.0.0.1:8080
CONTROL_PUBLIC_URL=https://console.example.com
REQUIRE_SECURE_SECRETS=true

# 节点/DNS 调度令牌
AGENT_TOKEN=替换成强随机串
# 指标抓取令牌；留空回退 AGENT_TOKEN
METRICS_TOKEN=替换成另一条强随机串
# 必须与所有 Edge 的 WAF_RULEPACK_SECRET 完全一致
WAF_RULEPACK_SECRET=替换成与Edge一致的强随机串

# 可选共享状态；不启用 Redis 时留空
REDIS_URL=redis://lagran:密码@127.0.0.1:6379/0
# 反向代理与控制面同机时保持默认；异机部署时改成代理回源网段
# TRUSTED_PROXIES=127.0.0.1,::1

GEOIP_PATH=/var/lib/lagran/ip2region_v4.xdb
# 可选：IPv6 客户端
# GEOIP_IPV6_PATH=/var/lib/lagran/ip2region_v6.xdb
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
| `CONTROL_BIND` | 是 | `0.0.0.0:8080` | 控制面监听地址。生产放在 Caddy/Nginx 后面时用 `127.0.0.1:8080`，只让本机访问。 |
| `AGENT_TOKEN` | 生产必填 | 空 | DNS 调度接口的全局令牌，也是旧节点回调的兜底令牌。**边缘心跳/配置必须使用节点 `auth_token`，不能使用该全局令牌**；为空只影响调度接口，不会放行未注册边缘。详见 4.4。 |
| `AGENT_TLS_CA_FILE` | 否 | 空 | 控制面回调 `https://` 管理面时额外信任的私有 CA PEM。WebPKI 根证书始终可用；边缘管理面使用自签/内部 CA 时填写。 |
| `CONTROL_PUBLIC_URL` | 推荐 | 空 | 控制台公网地址，用于生成节点安装命令。为空时按请求 Host 推导；反向代理场景建议显式设置。 |
| `TRUSTED_PROXIES` | 否 | `127.0.0.1,::1` | 可信反向代理 IP/CIDR，逗号分隔。只有来自这些地址的 `X-Forwarded-For` / `X-Real-IP` 才会被登录限流和登录日志采信；直连请求使用 TCP 对端地址。Caddy/Nginx 不在本机或前面还有 CDN 时，把对应回源网段加入这里。 |
| `DATABASE_MAX_CONNECTIONS` | 否 | `32` | 每个控制面进程的连接池上限，代码钳制 2–200。多副本时用「副本数 × 本值」核算 PostgreSQL `max_connections`。 |
| `REDIS_URL` | 否 | 空 | 可选共享状态；配置后登录限流、会话缓存、锁、实时统计走 Redis。详见 4.2。 |
| `REQUIRE_SECURE_SECRETS` | 推荐 | 代码 `false`，示例 `true` | 为 true 时拒绝默认/过短的 JWT 密钥，以及缺失 `WAF_RULEPACK_SECRET` 的启动。生产建议 true。 |
| `METRICS_TOKEN` | 推荐 | 空 | `/metrics` 的 Bearer 令牌；为空回退 `AGENT_TOKEN`，两者都空返回 401。 |
| `WAF_RULEPACK_SECRET` | 生产必填 | 空 | 规则包签名密钥，必须与所有 Edge 完全一致；为空时发布接口 503、Edge 拒绝签名规则包。 |
| `ALLOW_REGISTER` | 否 | `false` | 是否开放自助注册；首次管理员通过临时开启后立即关闭，见 4.8。 |
| `CAPTCHA_ENABLED` | 否 | `true` | 登录/注册图片验证码；集成测试或纯内网可关闭。 |
| `CORS_ALLOWED_ORIGINS` | 否 | 空 | 控制台与 API 不同源时填写允许的 Origin；同源部署留空即可。 |
| `SEED_DEMO` | 否 | `false` | 仅本地体验；生产禁止与 `REQUIRE_SECURE_SECRETS=true` 同时开启。 |
| `GEOIP_PATH` | 调度必填 | `./data/ip2region_v4.xdb` | 地理位置库：推荐 ip2region XDB；兼容 V2Ray/Loyalsoldier `geoip.dat` 与旧版 CIDR JSON。缺失时按权重/负载调度；启动时加载，修改后需重启。 |
| `GEOIP_IPV6_PATH` | 否 | 空 | 可选 ip2region IPv6 XDB（`ip2region_v6.xdb`）。 |
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

### 4.4 Agent Token 关系（重要）

边缘路由和 DNS 调度路由使用不同的鉴权策略：

| 凭据 | 使用位置 | 作用 |
|---|---|---|
| `edge_nodes.auth_token` | 数据库 | 预注册节点时生成，每个节点唯一 |
| `AGENT_TOKEN` | `edge.env` | 该节点自己的 token，必须等于 `edge_nodes.auth_token` |
| `AGENT_TOKEN` | `dns.env` | DNS 调用 `/api/v1/schedule` 的全局 token |
| `AGENT_TOKEN` | `control.env` | 全局 token；仅用于 DNS 调度，以及旧节点回调的兜底 |

#### 边缘 → 控制面

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
- 节点 token 验证带 30 秒正向缓存（进程内 + 可选 Redis）：同一控制面在节点改名/禁用/删除时立即失效；其他控制副本最多延迟 30 秒。缓存键使用 token 的 SHA-256，不把原始 token 写入 Redis。

#### DNS → 控制面

DNS 只调用 `/api/v1/schedule`，使用 `ScheduleAuth`：

```text
请求 token == control.AGENT_TOKEN
或
请求 token 存在于 edge_nodes.auth_token
```

DNS 不是边缘节点，推荐 DNS 使用全局 `AGENT_TOKEN`。  
如果 `control.AGENT_TOKEN` 为空，调度接口仅在显式设置
`ALLOW_UNAUTHENTICATED_SCHEDULE=true` 时放行（仅限本地开发）。  
Agent 调度接口只按 `ip` / `subnet` 推导地理信息，忽略 `country` / `province` / `city` /
`isp` 覆盖；这些覆盖只用于管理员预览 `/api/v1/schedule/test`。响应的
`candidates[].public_ip` 对 agent 为空，避免任一节点令牌枚举全部节点公网 IP。

#### 控制面 → 边缘

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

#### 4.4.1 升级前预建索引（大表必读）

新版本为遥测表和节点表增加了索引。迁移本身可以正常运行，但 `CREATE INDEX` 会在
`access_logs` / `waf_events` 上持写锁直到建完；这两张表在长期运行的环境里通常是全库最大的，
千万级数据下可能阻塞写入数分钟到数十分钟。

迁移脚本用的是 `CREATE INDEX IF NOT EXISTS`，所以**先在低峰期用 `CONCURRENTLY` 手工建好，
迁移执行时就会直接跳过**，不产生锁。

```bash
psql "$DATABASE_URL" <<'SQL'
-- 不阻塞读写；失败会留下 invalid 索引，见下方清理
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_logs_status_ts
    ON access_logs (status, ts DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_waf_events_action_ts
    ON waf_events (action, ts DESC);
SQL
```

`CONCURRENTLY` 不能在事务块内运行，所以这里用 `psql` 直接执行，而不是包在 `BEGIN/COMMIT` 里。

**如果中途失败**，会残留一个 `INVALID` 状态的索引，它不会被查询使用，但会阻塞后续 `IF NOT EXISTS`：

```sql
-- 检查
SELECT indexrelid::regclass AS index, indisvalid
FROM pg_index
WHERE indexrelid::regclass::text IN ('idx_access_logs_status_ts','idx_waf_events_action_ts');

-- 有 indisvalid = false 时先删掉再重建
DROP INDEX CONCURRENTLY IF EXISTS idx_access_logs_status_ts;
DROP INDEX CONCURRENTLY IF EXISTS idx_waf_events_action_ts;
```

##### `edge_nodes.name` 唯一索引

这条**不建议预建**，因为迁移需要先把可能存在的重名节点改名，预建唯一索引会在有重名时失败。
先确认没有重名即可（正常情况下不会有）：

```bash
psql "$DATABASE_URL" -c \
  "select name, count(*) from edge_nodes group by name having count(*) > 1;"
```

若查询为空，迁移会顺利完成；若有结果，迁移会自动把较晚的节点改名为 `<name>~<n>`，
升级后请到控制台确认并清理这些节点。

> 提示：即使要预建，也**不要**用 `CONCURRENTLY` 建这个唯一索引。按 PostgreSQL 文档，
> 唯一索引在并发构建的第二次扫描开始时就会对其他事务生效，构建若失败还会留下一个
> 仍在强制唯一性的 `INVALID` 索引，清理起来比普通构建更麻烦。

#### 升级顺序（重要）

该版本开始，边缘接口不再接受全局 `AGENT_TOKEN`，也不会自动创建未知节点。升级时建议按以下顺序：

1. 在**旧控制面**中为每台边缘创建/确认节点，拿到节点 `auth_token`
2. 把节点 `auth_token` 写入对应 `/etc/lagran/edge.env` 的 `AGENT_TOKEN`
3. 重启所有 edge，确认仍能正常心跳
4. 最后再升级并重启 control

如果先升级 control，旧 edge 会立即 401，直到改为节点 token。

#### 常见问题

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

### 4.5 systemd

`/etc/systemd/system/lagran-control.service`：

```ini
[Unit]
Description=Lagran Control Plane
After=network.target postgresql.service
Wants=postgresql.service
# 本机 Redis 建议再加：
# After=redis-server.service
# Wants=redis-server.service

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

- 执行数据库迁移；
- **仅当 `SEED_DEMO=true`** 时创建 demo 账号 `demo@lagran.dev / demo123` 和示例域名
  `cdn.example.com`；生产默认 `SEED_DEMO=false`，不会创建任何账号，需按 4.8 初始化管理员。

### 4.6 反向代理与控制台

控制台静态文件与 `/api/*` 由同一个域名提供：

```text
浏览器
  ├── /            → /opt/lagran/web 静态文件（SPA）
  └── /api/*       → 127.0.0.1:8080（lagran-control）
```

反向代理二选一即可：**Caddy（推荐，自动 HTTPS）** 或 **Nginx（已有 Nginx 体系时）**。
不要同时让 Caddy 和 Nginx 监听 80/443。

无论选哪个，先确认：

- `console.example.com` 的 A/AAAA 记录已指向本机；
- 公网 80/443 可访问（80 用于 ACME/重定向，443 用于控制台）；
- 控制面只监听 `127.0.0.1:8080`（`CONTROL_BIND=127.0.0.1:8080`）；
- 前端已构建到 `/opt/lagran/web`（见第 3.3 节）；
- 反向代理与控制面同机时，控制面默认信任 `127.0.0.1/::1` 的转发头。

#### 4.6.1 Caddy（推荐）

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

创建 Caddy 日志目录（Caddyfile 示例会写 `/var/log/caddy/console-access.log`）：

```bash
sudo mkdir -p /var/log/caddy
sudo chown -R caddy:caddy /var/log/caddy
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

    @api path /api/* /health /ready
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
| `@api path /api/* /health /ready` | 命名匹配器：API、健康检查与就绪检查。 |
| `handle @api` | API 请求走反代；`handle` 之间互斥，顺序影响匹配。 |
| `reverse_proxy 127.0.0.1:8080` | 转发到控制面。 |
| `header_up Host {host}` | 保留原始 Host；`CONTROL_PUBLIC_URL` 未设置时安装命令依赖它。 |
| `header_up X-Real-IP {remote_host}` | 传真实客户端 IP；Caddy 会自动设置 `X-Forwarded-For`/`X-Forwarded-Proto`。控制面默认信任本机回环代理；Caddy 不在本机时需设置 `TRUSTED_PROXIES`。 |
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
curl -s https://console.example.com/ready
```

> 如果域名在 Cloudflare 橙色云后面，Caddy 的 HTTP-01 校验可能被代理拦截；
> 先把记录改为 DNS only，或改用 DNS-01。控制台登录也应确认
> `TRUSTED_PROXIES` 包含实际回源网段。

#### 4.6.2 Nginx（替代 Caddy）

已有 Nginx 资产或团队统一使用 Nginx 时，可以用下面的配置替代 Caddy。
如果机器上已经装了 Caddy，先停掉，避免争抢 80/443：

```bash
sudo systemctl disable --now caddy 2>/dev/null || true
```

##### 安装 Nginx 与 Certbot

Debian/Ubuntu：

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
sudo systemctl enable --now nginx
nginx -v
```

确认 80 端口可用：

```bash
sudo ss -lntp | grep ':80 '
```

##### 申请证书（webroot 方式）

先在 DNS 服务商把 `console.example.com` 指向本机，并放行 80/443。
创建 ACME 挑战目录：

```bash
sudo mkdir -p /var/www/html
```

写入一个只用于签发的临时 HTTP 站点：

```nginx
# /etc/nginx/sites-available/lagran-console
server {
    listen 80;
    listen [::]:80;
    server_name console.example.com;
    root /var/www/html;

    location /.well-known/acme-challenge/ {
        try_files $uri =404;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}
```

启用并校验：

```bash
sudo ln -sf /etc/nginx/sites-available/lagran-console \
  /etc/nginx/sites-enabled/lagran-console
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

申请证书：

```bash
sudo certbot certonly --webroot -w /var/www/html \
  -d console.example.com \
  --agree-tos --no-eff-email \
  -m admin@lagran.dev
```

成功后证书位于：

```text
/etc/letsencrypt/live/console.example.com/fullchain.pem
/etc/letsencrypt/live/console.example.com/privkey.pem
```

增加续期后的 Nginx reload hook（`certonly` 不会自动改 Nginx 配置）：

```bash
sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh >/dev/null <<'EOF'
#!/bin/sh
systemctl reload nginx
EOF
sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

如果使用其他 CA/已有证书，替换下面配置里的证书路径即可。

##### 完整 HTTPS 配置

用下面的内容覆盖 `/etc/nginx/sites-available/lagran-console`：

```nginx
# /etc/nginx/sites-available/lagran-console
server {
    listen 80;
    listen [::]:80;
    server_name console.example.com;

    # 续期时仍然放行 ACME challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        try_files $uri =404;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name console.example.com;

    ssl_certificate     /etc/letsencrypt/live/console.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/console.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # 可选：确认全站 HTTPS 后再启用 HSTS
    # add_header Strict-Transport-Security "max-age=31536000" always;

    server_tokens off;
    root /opt/lagran/web;
    index index.html;
    client_max_body_size 20m;

    # 可选：压缩静态资源与 API JSON
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript
               application/xml image/svg+xml;

    # 安全响应头
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    # 控制面 API 与健康检查
    location ^~ /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }

    location = /health {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location = /ready {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # SPA 路由回退：刷新 /domains、/waf 等路径不能 404
    location / {
        try_files $uri $uri/ /index.html;
    }

    # 静态资源缓存（不带 hash 的入口文件仍走上面的 location /）
    location ~* \.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff2?)$ {
        expires 1h;
        access_log off;
    }
}
```

校验、重载并测试：

```bash
sudo nginx -t
sudo systemctl reload nginx

curl -I https://console.example.com/
curl -s https://console.example.com/health
curl -s -o /dev/null -w '%{http_code}\n' https://console.example.com/api/v1/auth/login
# 405（方法不允许）说明请求已经到达控制面，而不是被静态文件吞掉
```

续期检查：

```bash
sudo certbot renew --dry-run
systemctl list-timers | grep -i certbot
```

Nginx 配置要点：

| 配置 | 说明 |
|---|---|
| `listen 443 ssl http2` | 启用 HTTPS 与 HTTP/2；旧版 Nginx 也兼容这种写法。 |
| `proxy_pass http://127.0.0.1:8080` | 只反代到本机回环，不要把 8080 暴露到公网。 |
| `X-Real-IP` / `X-Forwarded-For` / `X-Forwarded-Proto` | 控制面需要真实客户端 IP 与协议；同机代理默认被 `TRUSTED_PROXIES=127.0.0.1,::1` 信任。 |
| `location ^~ /api/` | `^~` 让 API 前缀优先于静态资源正则，避免 `/api/*.js` 被当成静态文件。 |
| `try_files $uri $uri/ /index.html` | 前端 SPA 路由回退。 |
| `client_max_body_size 20m` | 给 WAF 规则包/资源上传留余量；按实际需求调整。 |
| `ssl_certificate` | 指向 Certbot 的 `fullchain.pem`/`privkey.pem`；证书路径换了要同步修改。 |

> Nginx 在另一台机器或前面还有 Cloudflare/SLB 时，控制面的
> `TRUSTED_PROXIES` 必须加入 Nginx 的回源网段；否则控制面看到的是代理 IP。
> 同时把真实客户端 IP 头配置正确，避免登录限流把所有用户算成同一个 IP。

### 4.7 前端 API 地址

生产构建默认走同源：

```text
POST https://console.example.com/api/v1/auth/login
```

由 Caddy 或 Nginx 反代到控制面。一般不需要设置 `NUXT_PUBLIC_API_BASE`。

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

### 4.8 创建管理员

**这一步不能跳过。** `SEED_DEMO` 在 `REQUIRE_SECURE_SECRETS=true` 时会被拒绝启动，
若库中没有任何账户，控制台将无人可登录。

首次部署取账户的流程：**第一个注册的账号自动成为管理员**。

```bash
# 1. 临时打开注册开关并重启
sudo sed -i 's/^ALLOW_REGISTER=.*/ALLOW_REGISTER=true/' /etc/lagran/control.env
sudo systemctl restart lagran-control

# 2. 打开控制台注册你的账号（此时 captcha 若开启需一并完成）
#    日志会打印：first account registered and granted admin; disable ALLOW_REGISTER now

# 3. 立刻关掉注册开关并重启
sudo sed -i 's/^ALLOW_REGISTER=.*/ALLOW_REGISTER=false/' /etc/lagran/control.env
sudo systemctl restart lagran-control
```

规则：

- **只在 `users` 表为空时生效**。库中已有任何账号时，新注册一律是普通 `user`，
  不会覆盖或提权。
- 判定与插入在同一条 SQL 内完成，多请求并发注册也只有一个成为管理员。
- 第 3 步不能省：注册接口对外开放期间，任何能访问到端口的人都能抢先注册。

**验证结果**：

```bash
psql "$DATABASE_URL" -c "SELECT email, role FROM users;"
# 你的账号应为 admin
```

确认新管理员可登录后，删除示例域名 `cdn.example.com`，并限制/删除 demo 账号。

### 4.9 Let's Encrypt 证书签发

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

API 示例（签发是异步任务：接口返回 `202` 与 `job_id`，再轮询结果）：

```bash
# 1) 提交签发任务
curl -X POST https://console.example.com/api/v1/certs/issue \
  -H "Authorization: Bearer <admin-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"domain_name":"cdn.example.com","provider":"letsencrypt","push_to_edges":true}'
# => 202 {"job_id":"...","status":"pending","poll_url":"/api/v1/certs/jobs/<id>"}

# 2) 轮询直到 status 为 succeeded / failed
curl https://console.example.com/api/v1/certs/jobs/<job_id> \
  -H "Authorization: Bearer <admin-jwt>"

# 3) 查看当前仍在进行的签发任务（控制台刷新后恢复进度用）
curl https://console.example.com/api/v1/certs/jobs \
  -H "Authorization: Bearer <admin-jwt>"
```

同一域名 + 同一 `provider` 的重复提交会复用进行中的任务（返回相同 `job_id`，`reused: true`），
不会重复创建 ACME 订单；同时最多 8 个签发任务，超出返回 `429`。

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
> **管理面默认是明文 HTTP**：节点令牌与 `/certs/load` 的证书私钥都会明文过网。生产
> 建议配置 `EDGE_ADMIN_TLS_CERT`/`EDGE_ADMIN_TLS_KEY`（并用 `AGENT_TLS_CA_FILE`
> 让控制面信任内部 CA），或至少把端口限制在控制面来源 IP/内网；非 loopback 的明文
> 管理面会在 Edge 启动时打印 WARN。
> 公共 TLS 只由 Pingora 终止；旧 `EDGE_TLS_CERT` / `EDGE_TLS_KEY` 配置已移除。
> 编译使用 vendored OpenSSL，构建机需要 `perl`/`make`；musl 静态构建仍可用。

`/etc/lagran/edge.env`：

```bash
CONTROL_URL=http://10.0.0.10:8080
AGENT_TOKEN=该节点的 auth_token
# Prometheus 抓取 /__lagran/metrics 的专用令牌；留空回退 AGENT_TOKEN
# METRICS_TOKEN=
NODE_ID=edge-gz-01
NODE_REGION=guangdong
PUBLIC_IP=203.0.113.21
AGENT_URL=http://203.0.113.21:8081

# 数据面：CDN 用户流量（80/443）
EDGE_LISTEN=0.0.0.0:80
EDGE_HTTPS_LISTEN=0.0.0.0:443
# 管理面：控制面回调 purge/cert/challenge/metrics，不暴露给公网用户；
# 所有管理端点（含 /__lagran/metrics）都要求节点 token，禁止匿名访问
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
| `ORIGIN_URL` | 仅单源模式 | `https://example.com` | 仅当边缘**没有**从控制面拿到任何域名时使用的兜底源站（如本地开发直接 `cargo run -p edge`）。此模式下任意 `Host` 都由它服务，且自阶段 3 起走 Pingora 原生路径；正常部署以控制面下发的域名配置为准，此值不生效。 |
| `AGENT_TOKEN` | 生产必填 | 空 | 必须是该节点在控制台预注册时生成的 `auth_token`。边缘配置/心跳只接受节点 token，**不能用控制面全局 `AGENT_TOKEN`**；节点 token 为空时请重新创建节点。 |
| `METRICS_TOKEN` | 否 | 空（回退 `AGENT_TOKEN`） | Prometheus 抓取 `/__lagran/metrics` 的专用令牌（`X-Lagran-Metrics-Token` 或 `Authorization: Bearer`）。留空时回退 `AGENT_TOKEN`；两者都为空时该端点返回 401（`ALLOW_INSECURE_AGENT=true` 仅限本地）。 |
| `NODE_ID` | 是 | `edge-001` | 节点唯一标识，对应控制台预注册名称。改名后需同步修改，否则会注册成新节点。 |
| `NODE_REGION` | 否 | `local` | 区域标签，首次心跳写入；控制台已填非空区域时不会被心跳覆盖。 |
| `PUBLIC_IP` | 调度必填 | 空 | 节点公网 IP，随心跳上报，DNS 调度返回这个地址。必须是对用户可访问的 IP。 |
| `AGENT_URL` | 是 | 根据 `EDGE_ADMIN_LISTEN` / `EDGE_LISTEN` 推导 | 控制面回调边缘的地址（purge、证书、ACME）。应指向 **`EDGE_ADMIN_LISTEN` 管理端口**，例如 `http://IP:8081`；控制面必须能访问。 |
| `EDGE_LISTEN` | 是 | `0.0.0.0:8081` | Pingora 公共 HTTP 监听：CDN 用户流量、WAF challenge verify、ACME HTTP-01 challenge。生产用 80。绑定具体 IP 时，Edge 会额外监听同端口的 loopback 地址，供内部缓存预热使用。 |
| `EDGE_ADMIN_LISTEN` | 推荐 | 空 | 管理面监听：purge、证书加载、ACME challenge 下发、access-log、metrics。与控制面通信使用此端口；**不要对公网开放**，只允许控制面来源 IP（见「防火墙」）。为空时兼容旧模式，管理接口仍留在数据面。所有管理端点都要求节点 token；metrics 也可用 `METRICS_TOKEN`。 |
| `EDGE_ADMIN_TLS_CERT` / `EDGE_ADMIN_TLS_KEY` | 否 | 空 | 管理端口的 TLS 证书链/私钥 PEM 路径，必须同时设置。设置后管理面只接受 HTTPS，控制面需配置 `AGENT_TLS_CA_FILE`（自签/内部 CA 时）。 |
| `EDGE_ADMIN_REQUIRE_TLS` | 否 | `false` | 为 `true` 时，明文管理面会拒绝 `/certs/load`（证书私钥推送），启动时要求同时配置管理面 TLS。 |
| `EDGE_HTTPS_LISTEN` | 否 | 空 | Pingora 公共 HTTPS 监听。生产用 `0.0.0.0:443`，需要已同步证书。为空表示不启用 TLS。 |
| `EDGE_HTTPS_REDIRECT_PORT` | 否 | 从 HTTPS 监听推导 | 域名开启 HTTPS 后，HTTP→HTTPS 跳转使用的端口。`443` 可省略；开发 8443 时写 8443。它只影响跳转 URL，不改变监听。 |
| `CACHE_BACKEND` | 否 | `memory` | `memory`：内存；`disk`：磁盘；`hybrid`：内存+磁盘。生产大文件建议 `hybrid`。 |
| `CACHE_TTL` | 否 | `60` | 默认缓存 TTL（秒）。规则 TTL 优先；否则依次用源站 `s-maxage`/`max-age`/`Expires`，最后用它。 |
| `CACHE_CAPACITY` | 否 | `10000` | 内存缓存最大对象数；`memory`/`hybrid` 使用。 |
| `DISK_CACHE_DIR` | 磁盘缓存必填 | `./data/cache` | 磁盘缓存目录；`disk`/`hybrid` 使用，需可写。 |
| `DISK_CACHE_MAX_BYTES` | 否 | 1 GiB | 磁盘缓存上限；超出按 mtime 淘汰。 |
| `CERT_DIR` | 否 | `./data/certs` | 证书持久化目录；边缘从控制面 `/certs/edge-sync` 拉取并落盘。 |
| `TRUST_PROXY_HEADERS` | 否 | `false` | 是否信任前置可信代理的 `X-Forwarded-For` / `X-Forwarded-Proto`。为 `false` 时 Pingora 用真实对端 IP 覆盖客户端伪造值；只有边缘前面还有 SLB/Cloudflare 时才开启。 |
| `CACHE_FLIGHT_TIMEOUT_MS` | 否 | `250` | 跨节点请求合并的单次 Redis 往返超时（毫秒），涵盖抢锁 `SET NX`、等锁 `EXISTS`、释放 `EVAL`。钳制 50–5000。Redis 不在本机时应调大；超时后降级为各节点独立回源并打印 `flight lock unavailable` 的 WARN。 |
| `GEOIP_COUNTRY_DB` | Geo/ASN 名单必填 | `./data/maxmind/GeoLite2-Country.mmdb` | WAF 国家/地区名单使用的 MaxMind GeoLite2-Country 文件。需自行下载并定期更新；缺失时黑名单不生效、白名单 fail-closed（拦截全部流量）。启动时加载，更新后需重启 Edge。 |
| `GEOIP_ASN_DB` | Geo/ASN 名单必填 | `./data/maxmind/GeoLite2-ASN.mmdb` | WAF ASN 名单使用的 GeoLite2-ASN 文件，行为同上。分发需遵守 MaxMind GeoLite2 EULA。 |
| `CHALLENGE_SECRET` | 多节点必填 | 空 | WAF 质询 nonce/免质询 Cookie 的 HMAC 密钥。多节点必须一致；为空时用 `AGENT_TOKEN` 派生或进程随机（重启失效）。 |
| `WAF_REPORT` | 否 | `true` | 是否上报 WAF 事件。 |
| `WAF_REPORT_INTERVAL` | 否 | `5` | WAF 事件上报间隔（秒）。 |
| `WAF_BODY_INSPECTION` | 否 | `false` | 运维覆盖：为所有已启用 WAF 的域名强制开启请求体检查；按域名配置在控制面 WAF 设置。只检查带 `Content-Length` 的 `POST/PUT/PATCH` JSON/form/text body，硬上限 64 KiB。 |
| `WAF_BODY_MAX_BYTES` | 否 | `32768` | 请求体检查上限，范围 1024–65536；超过后按 `WAF_BODY_OVERSIZE_POLICY` 处理。 |
| `WAF_BODY_OVERSIZE_POLICY` | 否 | `log` | 超限策略：`log`（放行并记录）/ `block`（413）/ `allow`。 |
| `WAF_BODY_UNINSPECTABLE_POLICY` | 否 | `log` | chunked/无长度、压缩、multipart、`Expect: 100-continue` 等无法检查时的策略。 |
| `WAF_BODY_TIMEOUT_MS` | 否 | `1000` | 读取完整 body 的总超时，范围 100–5000ms；超时返回 408。 |
| `WAF_BODY_MAX_CONCURRENT` | 否 | `256` | 同时读取 body 的请求上限（1–4096）；超过的请求按跳过策略处理。 |
| `HEARTBEAT_INTERVAL` | 否 | `15` | 心跳间隔（秒）。控制面约 60 秒无心跳标记离线。 |
| `CC_SYNC_INTERVAL` | 否 | `5` | 跨节点共享 CC 封禁拉取间隔（秒，最小 2）。 |
| `RUST_LOG` | 否 | `edge=debug,tower_http=info` | 日志级别。注意二进制自身的目标是 `lagran_edge`，只写 `edge=...` 会过滤掉它（启动摘要、CC 跨节点状态、优雅关闭都会消失，而 `edge::cache` 等库日志照常输出）。要看到全部，用 `lagran_edge=info,edge=info,tower_http=info`。 |

### 5.2.1 用「新增 Edge 向导」生成 edge.env

控制台左侧「边缘节点 → 新增节点」提供五步向导，按节点硬件生成一份可直接落地的
`edge.env`，适合不想手算缓存容量和超时参数的运维者：

1. **节点身份**：节点名称、区域、公网 IP 与部署方式。选择「控制面在另一台机器」时，
   向导把 `AGENT_URL` 设为 `http://<公网IP>:8081`，并让 `EDGE_ADMIN_LISTEN` 跟随它
   绑定到该 IP 的 8081（不会生成 `0.0.0.0`）；选择「同机」时两者都使用
   `127.0.0.1:8081`。管理端口仍需用防火墙限制到控制面来源。
2. **硬件画像**：CPU / 内存 / 磁盘 / 磁盘类型 / 出口带宽 / 业务类型，以及节点角色
   （普通边缘或 Origin Shield）。Shield 会自动写入 `EDGE_SHIELD_DISABLED=true`。
3. **容量规划**：展示每个容量参数的推导依据（L1/L2/L3 缓存、分片、回源超时等）。
   双击「取值」列可直接修改数值参数或大对象缓存开关；字节类参数支持 `1M` / `4M` / `1G`
   写法（1M = 1024×1024 字节）。点击输入框外部或按 Enter 确认，Esc 取消。修改值会随
   节点画像保存，详情页和后续生成的配置都会沿用。
4. **生成配置**：注册节点并展示节点令牌。`CONTROL_URL` 由控制面按
   `CONTROL_PUBLIC_URL`（或请求 Host）解析，不会再误用浏览器地址。该步骤只保留
   一个「一键安装命令」和「下载 edge.env」按钮：命令用节点令牌从
   `GET /api/v1/edge/config?edge=<NODE_ID>` 拉取配置到 `/etc/lagran/edge.env`，
   再执行 `install.sh edge` 并重启；令牌和节点名已经替换成本节点的值。
5. **上线验证**：轮询节点状态，并给出节点侧 `check-config` / 健康检查 / journalctl 命令。

向导会：
- 把每个值钳制到 `apps/edge/src/config/mod.rs` 接受的范围，避免 Edge 启动时静默改写；
- 自动生成 `CHALLENGE_SECRET` 并写入节点画像，后续节点会复用它，避免跨节点质询失败；
- 从已有节点复用 `REDIS_URL` / `CHALLENGE_SECRET` / `WAF_RULEPACK_SECRET`；
- 在控制面没有配置 `WAF_RULEPACK_SECRET` 时给出明确警告（此时 Edge 会拒绝签名规则包）。

生成的文件可以直接替换 `/etc/lagran/edge.env`：

```bash
sudo install -m 600 ./edge-<节点名>.env /etc/lagran/edge.env
sudo sh -c 'set -a; . /etc/lagran/edge.env; set +a; exec /opt/lagran/bin/lagran-edge check-config'
sudo systemctl restart lagran-edge
```

> 向导只负责生成文件；`install.sh edge` 在发现 `/etc/lagran/edge.env` 已存在时不会覆盖它，
> 因此也可以先放配置再补装二进制。

#### 节点拉取自身配置

向导保存节点画像时，会把渲染好的 `edge.env` 一并存入该节点的 `edge_profile`。
节点可以用自己的令牌拉取：

```bash
curl -fsSL   -H "X-Lagran-Agent-Token: <节点令牌>"   "https://console.example.com/api/v1/edge/config?edge=<NODE_ID>"   -o /etc/lagran/edge.env
```

接口行为：

| 情况 | 返回 |
|---|---|
| 令牌有效且 `edge` 与令牌绑定的节点一致 | `200 text/plain`，响应带 `Cache-Control: no-store` |
| 缺少/无效令牌 | `401` |
| `edge` 与令牌绑定的节点不一致 | `403` |
| 节点不存在 | `404` |
| 节点没有保存过渲染后的配置文件 | `409`（重新保存一次节点画像即可） |

返回内容包含节点令牌和共享 WAF/质询密钥，必须只通过受控通道传输。控制台的节点
列表/详情接口不再返回渲染后的 `env`，只有这个按节点令牌鉴权的接口会返回，且响应带
`Cache-Control: no-store`；节点侧安装命令用 `umask 077` 写文件，避免配置文件短暂
处于全局可读状态。旧节点如果没有保存过渲染配置，在控制台节点详情里点一次
「保存画像」，或重新走一遍向导即可补齐。

### 5.2.2 管理面 TLS（自签证书示例）

管理面承载节点令牌与 `/__lagran/certs/load` 的证书私钥，默认是明文 HTTP。推荐用**私有
CA + 每节点服务端证书**：控制面只信任这个 CA，节点之间互不共享私钥。`AGENT_URL` 的
主机名/IP 必须出现在证书 SAN 中。

以 `edge-01`、内网地址 `10.0.0.21`、DNS 名 `edge-01.internal` 为例：

```bash
# 1) 私有 CA（10 年；CA 私钥离线保存或严格限权，不要拷到节点）
mkdir -p ~/lagran-admin-tls && cd ~/lagran-admin-tls
openssl genrsa -out edge-admin-ca.key 4096
openssl req -x509 -new -nodes -sha256 -days 3650 \
  -key edge-admin-ca.key -out edge-admin-ca.crt \
  -subj "/CN=Lagran Edge Admin CA"

# 2) 节点私钥 + CSR
openssl genrsa -out edge-01.key 2048
openssl req -new -key edge-01.key -out edge-01.csr -subj "/CN=edge-01.internal"

# 3) SAN 与用途（AGENT_URL 用 IP 就写 IP，用域名就写 DNS，可同时写）
cat > edge-01.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:edge-01.internal,IP:10.0.0.21
EOF

# 4) CA 签发服务端证书（825 天，到期前轮换叶子证书即可）
openssl x509 -req -in edge-01.csr \
  -CA edge-admin-ca.crt -CAkey edge-admin-ca.key -CAcreateserial \
  -out edge-01.crt -days 825 -sha256 -extfile edge-01.ext

openssl x509 -in edge-01.crt -noout -text | grep -A1 "Subject Alternative Name"
```

节点侧部署（默认服务用户/组为 `lagran-edge`；如改过用户请同步）：

```bash
sudo mkdir -p /etc/lagran/admin
sudo install -m 0644 edge-01.crt /etc/lagran/admin/edge-01.crt
sudo install -m 0640 edge-01.key /etc/lagran/admin/edge-01.key
sudo chown root:lagran-edge /etc/lagran/admin/edge-01.key
# 若叶子证书带中间证书：把“叶子 + 中间证书”按顺序拼接成一个 crt 文件
```

`/etc/lagran/edge.env` 增加：

```env
# 管理面绑定控制面可达的内网地址；不要 0.0.0.0
EDGE_ADMIN_LISTEN=10.0.0.21:8082
EDGE_ADMIN_TLS_CERT=/etc/lagran/admin/edge-01.crt
EDGE_ADMIN_TLS_KEY=/etc/lagran/admin/edge-01.key
# 证书/私钥未配置时启动直接失败；同时拒绝明文管理面的证书推送
EDGE_ADMIN_REQUIRE_TLS=true
AGENT_URL=https://10.0.0.21:8082
```

控制面侧只需要 CA 证书（**不要**拷 CA/节点私钥）：

```bash
sudo install -m 0644 edge-admin-ca.crt /etc/lagran/edge-admin-ca.pem
```

`/etc/lagran/control.env` 增加：

```env
AGENT_TLS_CA_FILE=/etc/lagran/edge-admin-ca.pem
```

控制台创建/编辑该节点时，`Agent URL` 填 `https://10.0.0.21:8082`。如果 `AGENT_URL`
用域名而不是 IP，必须**显式**设置 `EDGE_ADMIN_LISTEN` 为控制面可达地址（不要让控制面
从域名推导，否则会退化为 `127.0.0.1:<port>`），并确保 DNS 在控制面可解析。

重启并验证：

```bash
sudo systemctl restart lagran-edge
sudo journalctl -u lagran-edge -n 20 | grep -i "management listener"
# 期望：management listener uses TLS

# 在 Edge 本机：证书链与健康检查
curl --cacert /etc/lagran/admin/edge-admin-ca.crt \
  https://10.0.0.21:8082/__lagran/health
echo | openssl s_client -connect 10.0.0.21:8082 -servername edge-01.internal \
  -CAfile /etc/lagran/admin/edge-admin-ca.crt 2>/dev/null \
  | grep "Verify return code"
# 期望：Verify return code: 0 (ok)

sudo systemctl restart lagran-control
sudo journalctl -u lagran-control -n 20 | grep -i "private CA"
# 期望：trusting private CA for edge agent callbacks ... certs=1 rejected=0
#
# 这条日志在启动阶段就会打印，不需要等到第一次 purge/证书回调。
# 如果完全没有这条日志：AGENT_TLS_CA_FILE 为空、变量没进 EnvironmentFile，
# 或进程没重启（CA 只在启动时读取一次）。
# 如果打印的是 "contains no usable PEM certificate"：文件存在但不是 PEM 证书。

# 在控制面机器上：模拟一次真实回调（节点令牌从控制台/节点 env 获取）
curl --cacert /etc/lagran/edge-admin-ca.pem \
  -H "X-Lagran-Agent-Token: $AGENT_TOKEN" \
  -X POST https://10.0.0.21:8082/__lagran/config/reload
# 期望：{"ok":true,"reloading":true}
```

#### 通配证书（多节点共享）

如果节点使用固定的内部域名（如 `*.edge.internal`），可以让同一个私有 CA 签发一张
通配证书，所有节点共享同一份证书/私钥（或按区域拆分成 `*.gz.edge.internal`）。证书
生成方式与上面的单节点示例相同，只换 CN/SAN：

```bash
openssl genrsa -out wildcard-edge.key 2048
openssl req -new -key wildcard-edge.key -out wildcard-edge.csr \
  -subj "/CN=*.edge.internal"

cat > wildcard-edge.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
# 通配符不覆盖裸域；若 AGENT_URL 可能写成 edge.internal，必须一起加进 SAN
subjectAltName=DNS:*.edge.internal,DNS:edge.internal
EOF

openssl x509 -req -in wildcard-edge.csr \
  -CA edge-admin-ca.crt -CAkey edge-admin-ca.key -CAcreateserial \
  -out wildcard-edge.crt -days 825 -sha256 -extfile wildcard-edge.ext
```

各节点 `edge.env`：

```env
AGENT_URL=https://edge-01.edge.internal:8082
# 域名形式的 AGENT_URL 无法被控制面推导成绑定地址，必须显式绑定节点内网 IP
EDGE_ADMIN_LISTEN=10.0.0.21:8082
EDGE_ADMIN_TLS_CERT=/etc/lagran/admin/wildcard-edge.crt
EDGE_ADMIN_TLS_KEY=/etc/lagran/admin/wildcard-edge.key
EDGE_ADMIN_REQUIRE_TLS=true
```

控制面仍只信任 CA（`AGENT_TLS_CA_FILE=/etc/lagran/edge-admin-ca.pem`），并且必须能
解析 `edge-01.edge.internal`（内部 DNS 或 `/etc/hosts`）。验证：

```bash
# 控制面机器（有内部 DNS）
curl --cacert /etc/lagran/edge-admin-ca.pem \
  https://edge-01.edge.internal:8082/__lagran/health

# 没有 DNS 时临时指定解析
curl --cacert /etc/lagran/edge-admin-ca.pem \
  --resolve edge-01.edge.internal:8082:10.0.0.21 \
  https://edge-01.edge.internal:8082/__lagran/health
```

通配证书的约束：

- 只匹配**一级**标签：`*.edge.internal` 匹配 `edge-01.edge.internal`，不匹配
  `a.edge-01.edge.internal`；
- 不匹配裸域：需要显式加入 SAN `DNS:edge.internal`；
- 不匹配 IP：`AGENT_URL` 不能用 IP；只有 IP 的节点仍需单独签发带 `IP:` SAN 的证书；
- 私钥共享范围扩大：一张通配证书泄露会影响整批节点，生产更推荐每节点叶子证书，或按
  区域拆分通配证书，并严格限制私钥权限（`0640 root:lagran-edge`）；
- 续期时要更新所有使用该证书的节点并重启。

可用 `WILDCARD=1 bash tests/integration/admin-tls.sh` 回归：脚本会生成 `*.edge.test`
证书，验证 `edge-01.edge.test` 通过、裸域通过（SAN 显式包含）、二级子域与 IP 访问被
拒绝。

说明：

- `AGENT_TLS_CA_FILE` 在控制面启动时读取并立即解析，**修改后必须重启
  `lagran-control`**；该文件可以包含多个 CA PEM。
  启动日志三种结果：
  - `trusting private CA for edge agent callbacks ... certs=N`：已加载 N 张证书；
  - `contains no usable PEM certificate`：文件可读但没有可用证书，私有 CA **未** 生效；
  - `cannot read AGENT_TLS_CA_FILE`：路径不存在/无权限，回退为只用 WebPKI 根。
  也可以用 `lagran-control check-config` 单独检查，它会打印
  `agent_tls_ca_file: <path>: N certificate(s) trusted`。
- 轮换：只换叶子证书时重启 Edge 即可，控制面 CA 不变；轮换 CA 时需同时更新各节点证书
  与控制面 `AGENT_TLS_CA_FILE`。
- 不要复用公共数据面的证书/私钥；管理面私钥只用于管理端口。
- 回归测试：`tests/integration/admin-tls.sh` 会用临时私有 CA 启动管理面 HTTPS，验证
  `curl --cacert` 成功、错误 CA 被拒、明文连接失败、metrics 鉴权仍生效；
  `WILDCARD=1` 模式额外验证通配证书的一级匹配、裸域 SAN、二级子域/IP 拒绝。

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
2. 控制台「证书管理」→「自动签发」使用 Let's Encrypt（见 4.9）

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

Caddy/Nginx 在控制台机器占用 443，边缘不能同时用 443。生产建议分机；同机时使用不同 IP 的 `bind`，或让边缘使用其他端口。

---

## 6. 部署 DNS

### 6.1 地理位置库（ip2region）

控制面推荐使用 [ip2region](https://ip2region.net/) XDB：

- `ip2region_v4.xdb`：IPv4 客户端
- `ip2region_v6.xdb`：IPv6 客户端（可选）

数据字段：

```text
Country|Province|City|ISP|ISO-alpha2
```

下载：

```bash
sudo mkdir -p /var/lib/lagran

# IPv4
sudo wget -O /var/lib/lagran/ip2region_v4.xdb \
  https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb

# IPv6（可选）
sudo wget -O /var/lib/lagran/ip2region_v6.xdb \
  https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb
```

控制面：

```bash
GEOIP_PATH=/var/lib/lagran/ip2region_v4.xdb
GEOIP_IPV6_PATH=/var/lib/lagran/ip2region_v6.xdb
```

修改后重启：

```bash
sudo systemctl restart lagran-control
```

匹配后用于调度：

```text
country  = ISO-alpha2（例如 CN）
province = 广东省
city     = 深圳市
isp      = 电信
```

兼容格式：

- V2Ray/Loyalsoldier `geoip.dat`（仅国家代码）
- 旧版 CIDR JSON

`.xdb` 优先按 ip2region 解析；`.dat` 走 protobuf；`.json` 走 JSON。
文件不存在或解析失败不会阻止控制面启动，调度退化为按权重/负载。

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
| `DNS_CACHE_SECS` | 否 | `30` | 调度结果本地缓存时间。每次缓存过期才调控制面；建议 10–30，降低 A 查询延迟。 |
| `DNS_STALE_SECS` | 否 | `300` | 控制面故障时允许使用旧缓存的最长时间。 |
| `DNS_FALLBACK_IP` | 否 | 空 | 控制面不可用且无缓存时返回的兜底 IP；为空则 SERVFAIL。应填一个可用边缘 IP。 |
| `DNS_WORKERS` | 否 | `8` | UDP 工作线程数。 |
| `DNS_TCP` | 否 | `1` | 是否启用 TCP 53（截断回退）。建议开启。 |
| `DNS_MAX_TCP_CONNECTIONS` | 否 | `512` | TCP 最大并发连接数（每连接一个异步任务，不是 OS 线程），范围 16–65536。超出后新连接直接关闭。 |
| `DNS_TCP_IDLE_SECS` | 否 | `5` | TCP 连接空闲超时（秒），范围 1–300。RFC 7766 要求应答后保持连接以便复用，空闲超过该值才关闭。 |
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

多个节点得分并列最高时，控制面按调度请求轮询主节点，备份取并列组中的下一个；
DNS 侧缓存过期后再次请求即可轮到下一个 IP，避免流量长期固定在名字排序最前的节点。

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

8080/5432/6379 只允许本机/内网；Redis 不要对公网开放。

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
sudo chown -R root:root /opt/lagran/web
sudo chmod -R a+rX /opt/lagran/web
sudo systemctl reload caddy 2>/dev/null || sudo systemctl reload nginx
```

#### 升级按钮报 `cannot write update request`

如果控制台点升级后返回：

```text
cannot write update request /var/lib/lagran/update.request.tmp.xxx:
Permission denied (os error 13)
(the control service user must be able to write ...)
```

说明控制面服务账号 `lagran-control` 无法在数据目录里创建更新请求。旧版本曾把
`/var/lib/lagran` 留成 `root:lagran 0755`（或 `lagran:lagran 0755`），而当前服务以
`lagran-control`、组 `lagran` 运行，只能读不能写。先修复权限并重启：

```bash
sudo chgrp lagran /var/lib/lagran
sudo chmod g+rwxs /var/lib/lagran
sudo systemctl restart lagran-control
```

这里关键是**属组**：`lagran-control` 由系统单元以 `Group=lagran` 运行，所以只要目录
属组是 `lagran` 且组可写就够了；不需要把属主改成 `lagran-control`。如果目录属主也
异常（例如仍是旧 `lagran` 用户），可以额外执行
`sudo chown root:lagran /var/lib/lagran` 做一次归一化，让共享数据目录不属于任何
单个服务账号；这不是权限修复的必需步骤。

然后重新点击升级即可。若使用了自定义 `LAGRAN_DATA_DIR`，把上面的
`/var/lib/lagran` 换成实际目录。

永久修复：重新执行一次控制面安装器，它会重新生成带数据目录权限自修复
（`ExecStartPre`）的 systemd 单元，并把数据目录设为组可写：

```bash
curl -fsSL https://raw.githubusercontent.com/Lagran93/Lagran/main/install.sh \
  | sudo env LAGRAN_REPO=Lagran93/Lagran bash -s -- control
```

`lagran-update.path` / `lagran-update.service` 也必须已安装；旧部署重跑上面的命令
即可一并补齐。

### 备份

```bash
pg_dump "$DATABASE_URL" > /var/backups/lagran-$(date +%F).sql
```

同时备份：

- `/etc/lagran/*.env`
- `/var/lib/lagran/certs`
- `/var/lib/lagran/ip2region_v4.xdb`（可选 `ip2region_v6.xdb`）
- `/var/lib/caddy`（Caddy 自动证书）
- `/etc/letsencrypt`（Nginx/Certbot 证书与续期配置）
- `/opt/lagran/web`

### 日志

```bash
journalctl -u lagran-control -f
journalctl -u lagran-edge -f
journalctl -u lagran-dns -f
journalctl -u caddy -f          # Caddy
journalctl -u nginx -f          # Nginx
tail -f /var/log/caddy/console-access.log
tail -f /var/log/nginx/access.log
```

---

## 11. 故障排查

### 登录请求打到 localhost:8080

```text
[POST] "http://localhost:8080/api/v1/auth/login": Failed to fetch
```

前端构建时写死了 API 地址。重新 `npm run generate`，上传后硬刷新。确认反向代理 `/api/*` 生效：

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

`edge.AGENT_TOKEN` 与 `edge_nodes.auth_token` 不一致。见 4.4。

### 反向代理证书失败（Caddy / Nginx）

```bash
# Caddy
journalctl -u caddy -f

# Nginx + Certbot
sudo nginx -t
sudo certbot certificates
sudo tail -n 100 /var/log/letsencrypt/letsencrypt.log
```

检查域名解析、80/443、Cloudflare 代理状态；Nginx 还需确认
`/.well-known/acme-challenge/` 没有被 SPA 的 `try_files` 吞掉。

### 反向代理页面 404

```bash
ls -l /opt/lagran/web/index.html
sudo -u caddy ls /opt/lagran/web      # Caddy
sudo -u www-data ls /opt/lagran/web   # Nginx
```

Caddyfile 必须有 `try_files {path} /index.html` + `file_server`；
Nginx 必须有 `try_files $uri $uri/ /index.html`，并且 API 使用
`location ^~ /api/`（`^~` 可避免被静态资源正则截走）。

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
4. 配置 Caddy/Nginx + 上传前端
5. 登录控制台，创建管理员
6. 控制台添加节点，得到 auth_token
7. 配置 edge.env，启动 lagran-edge
8. 上传证书，开启域名 HTTPS
9. 配置 ip2region_v4.xdb（可选 v6 xdb）、dns.env
10. 启动两台 lagran-dns
11. Cloudflare/注册商配置 ns1/ns2 + glue
12. 验证 NS/A/TCP/ECS/调度
```
