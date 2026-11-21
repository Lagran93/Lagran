# Origin Shield 配置

本文说明如何在 Lagran CDN 中部署和配置 Origin Shield。

Origin Shield 是一个区域级大缓存层：

```text
普通 Edge
  → 本地 L3 命中则直接返回
  → 本地未命中则请求 Origin Shield
  → Shield 命中则返回
  → Shield 未命中才回源
```

适用于：

- 多台 Edge 反复回源同一个大对象；
- 源站带宽或连接数成为瓶颈；
- 希望把源站请求集中到少数区域节点；
- 需要降低跨节点重复回源，但暂时不实现全互联 P2P。

Origin Shield 不是“任意节点互相取对象”。它是一台指定的缓存节点或一组 Shield 节点。

### 循环防护

每个 Edge 向源站或 Shield 转发请求时会追加：

```text
CDN-Loop: lagran; id=<本节点 NODE_ID>
X-Lagran-Shield-Hops: <跳数>
```

接收端如果发现 `CDN-Loop` 已包含自己的 `NODE_ID`，或 `X-Lagran-Shield-Hops` 已达到 3，
会直接返回 `508 Loop Detected`，避免 Shield A → Shield B → Shield A 这类误配置无限回源。
该防护同时覆盖 native Pingora、legacy 回退、条件回源和 Range 流式回源。

---

## 1. 架构

```text
              ┌──────────────┐
              │   源站/Origin │
              └──────┬───────┘
                     │
                     │ 仅 Shield 回源
                     ▼
              ┌──────────────┐
              │ Origin Shield │
              │ 大缓存 + Range │
              └──────┬───────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
   Edge A        Edge B        Edge C
   本地 L3       本地 L3       本地 L3
```

工作方式：

1. 普通 Edge 先查本地大缓存；
2. 本地没有完整分片时，向 Shield 请求缺失分片；
3. Shield 查自己的本地大缓存；
4. Shield 命中则返回 Range；
5. Shield 未命中才向真实源站回源；
6. 普通 Edge 把 Shield 返回的 Range 写入本地大缓存。

---

## 2. 前置条件

- 所有节点使用同一控制面；
- Shield 节点已经加入控制面，并能正常同步域名配置；
- Shield 节点有独立、充足的磁盘空间；
- 普通 Edge 能访问 Shield 的内部地址；
- Shield 不能被公网直接访问；
- Shield 节点运行包含 `EDGE_SHIELD_DISABLED` 支持的新版 Edge；
- 业务域名已配置证书；
- Shield 的内部地址有公网 CA 签发的证书（当前 OriginClient 不信任自签/内部 CA）。

> `EDGE_SHIELD_DISABLED` 是后加的保护开关。旧版 Edge 不认识它，直接配置 `shield_url` 可能导致 Shield 自环。

---

## 3. 部署步骤

### 3.1 准备 Shield 节点

选择一台区域内部带宽和磁盘较好的 Edge 作为 Shield。

建议：

- 独立 SSD/NVMe；
- 独立于普通业务 Edge；
- 不暴露公网；
- 只允许 Edge 网段访问；
- 磁盘容量能容纳热点大对象的 working set；
- 有足够出向带宽。

### 3.2 配置 Shield 的 edge.env

在 Shield 节点编辑：

```bash
sudo vi /etc/lagran/edge.env
```

大缓存配置示例：

```env
NODE_ID=shield-01
NODE_REGION=cn-east

LARGE_CACHE_ENABLED=true
LARGE_CACHE_DIR=/var/lib/lagran/large-cache

LARGE_CACHE_MIN_OBJECT_BYTES=8388608
LARGE_CACHE_MAX_OBJECT_BYTES=1073741824
LARGE_CACHE_MAX_BYTES=21474836480

LARGE_CACHE_FILL_MAX_BYTES=0
LARGE_CACHE_CHUNK_BYTES=1048576

LARGE_CACHE_FILL_QUEUE_BYTES=134217728
LARGE_CACHE_FILL_QUEUE_TOTAL_BYTES=268435456

LARGE_CACHE_MIN_FREE_BYTES=1073741824
```

关键开关：

```env
# 仅专用 Origin Shield 节点开启
EDGE_SHIELD_DISABLED=true
```

设置后，Shield 节点会忽略域名配置里的 `shield_url`，避免自己的 cache miss 再次请求自己。

### 3.3 普通 Edge 配置

普通 Edge 保持：

```env
EDGE_SHIELD_DISABLED=false
```

默认就是 `false`，可以显式写出以便审计。

不要把普通 Edge 设置为 `true`，否则它们会忽略 Shield，直接回源。

### 3.4 重启 Shield

```bash
sudo systemctl restart lagran-edge
sudo systemctl status lagran-edge
```

验证配置：

```bash
/opt/lagran/bin/lagran-edge --check-config
```

应看到：

```text
origin_shield_disabled: true
```

同时确认日志中没有 Shield 自环或大量 5xx。

### 3.5 配置 Control 中的 Shield 地址

进入控制台：

```text
系统 → Shield 节点 → 新增 Shield
```

管理员填写平台信任的 Shield 内部地址：

```text
https://shield-s1.internal.example.com
```

然后业务域名在：

```text
域名列表 → 目标域名 → 高级设置 → Origin Shield 地址
```

从管理员配置的 Shield 节点中下拉选择；普通用户不能直接输入任意 URL。

保存后，普通 Edge 约 15 秒内同步。

如果该域名启用了配置发布，需要创建并审批发布单后才会下发到 Edge。

### 3.6 Shield 节点也要配置同一个业务域名

Shield 是 Edge 节点，必须能按公开业务域名路由。

要求：

- Shields 节点收到同样的域名配置；
- 域名状态为启用；
- 证书可用；
- 缓存规则与大缓存配置一致；
- Shield 自身不要再把 `shield_url` 指回自己。

由于 `EDGE_SHIELD_DISABLED=true` 只影响 Shield 节点自身，其他 Edge 仍然会使用域名配置中的 `shield_url`。

---

## 4. 防止自环

### 4.1 为什么需要 `EDGE_SHIELD_DISABLED`

控制面下发的域名配置对所有节点相同：

```text
域名 cdn.example.com
shield_url = https://shield-s1.internal.example.com
```

Shield 节点也会收到这份配置。

如果 Shield 节点没有设置：

```env
EDGE_SHIELD_DISABLED=true
```

则 Shield 缓存 miss 时会发生：

```text
Shield miss
  → 读取到 shield_url
  → 请求自己
  → 再次 miss
  → 循环
```

### 4.2 开启后的行为

```text
Shield 节点：
  忽略 shield_url
  → 直接走真实源站池

普通 Edge：
  使用 shield_url
  → 请求 Shield
```

### 4.3 注意

- `EDGE_SHIELD_DISABLED` 是节点级开关；
- 只对专用 Shield 节点开启；
- Shield 节点如果承载多个域名，会全部忽略 Shield 地址；
- 不要把 Shield 节点同时作为普通公网 Edge 的共享出口；
- 旧版 Edge 不识别该变量，升级前不要配置 shield_url。

---

## 5. 地址、Host、TLS

### 5.1 两种证书方案

#### 方案 A：复用业务域名 + split DNS（推荐）

Shield 地址直接使用业务域名：

```text
https://cdn.example.com
```

在**普通 Edge 节点**的内部 DNS 或 `/etc/hosts` 中，把该业务域名解析到 Shield：

```text
10.0.0.10  cdn.example.com
```

Shield 已经有了 `cdn.example.com` 的公网证书，因此：

- TLS SNI 是 `cdn.example.com`；
- HTTP Host 也是 `cdn.example.com`；
- 证书不需要新增；
- 公网 DNS 仍然解析到普通 Edge，客户端不会直接访问 Shield；
- Edge 节点的出站请求通过内部解析命中 Shield。

要求：

- 只修改普通 Edge 的解析，不要修改公网 DNS；
- Shield 节点不要把自己的业务域名也解析到自己，否则仍可能形成自环；
- 所有需要 Shield 的域名都要在 Edge 节点配置内部解析；
- 适合已经有公网证书的业务域名。

这是最简单的证书配置方式。

#### 方案 B：专用 Shield 主机名

例如：

```text
https://shield-s1.example.com
```

要求：

- 证书必须是公网 CA 签发；
- 证书 SAN/DNS 必须匹配 `shield-s1.example.com`；
- 普通 Edge 内部 DNS 将 `shield-s1.example.com` 解析到 Shield；
- Shield 的证书存储中安装该证书；
- 业务域名的 Host 仍然发送公开域名，因此 Shield 还要有业务域名的域名配置；
- 控制台上传证书前，需要先创建对应的域名条目。

不建议使用：

```text
shield-s1.internal.example.com
```

除非你确实为这个内部名称申请到了公网 CA 证书。当前 OriginClient 使用 webpki 公共根证书，不信任自签证书或普通内部 CA。

### 5.2 Host 和 SNI

Edge 请求 Shield 时：

```text
TLS SNI   = shield_url 的主机名
HTTP Host = 公开业务域名
```

如果使用方案 A：

```text
shield_url = https://cdn.example.com
SNI        = cdn.example.com
Host       = cdn.example.com
```

如果使用方案 B：

```text
shield_url = https://shield-s1.example.com
SNI        = shield-s1.example.com
Host       = cdn.example.com
```

因此：

- Shield 的证书必须匹配 SNI，即 `shield_url` 的主机名；
- Shield 的域名注册表要包含公开业务域名；
- Shield 必须能按公开 Host 路由；
- 不要只给 Shield 配置专用主机名而忘记业务域名。

### 5.3 网络

建议：

```text
普通 Edge 出站 IP → Shield:443 允许
公网 → Shield:443 拒绝
```

Shield 前面可以放内部 L4/L7 负载均衡，但不要放公网 CDN 域名解析。

#### 5.3.1 内部 DNS 解析

“普通 Edge 内部 DNS 将 `shield-s1.example.com` 解析到 Shield”不是修改公网 DNS，而是让**普通 Edge 节点自己**在发起回源连接时，把这个主机名解析到 Shield 的内网 IP。

需要区分三件事：

```text
DNS 解析  → Edge 实际连接哪个 IP
TLS SNI   → 使用哪个主机名做证书校验
HTTP Host → Shield 按哪个业务域名路由
```

例如：

```text
shield_url = https://shield-s1.example.com
DNS        = 10.0.0.10
TLS SNI    = shield-s1.example.com
HTTP Host  = cdn.example.com
```

Edge 会：

1. 解析 `shield-s1.example.com`；
2. 连接解析结果 `10.0.0.10:443`；
3. TLS 握手时发送 SNI `shield-s1.example.com`；
4. HTTP 请求中发送 `Host: cdn.example.com`；
5. Shield 用 Host 找到业务域名配置，用 SNI 选择证书。

#### 方式一：`/etc/hosts`（最简单）

在每台**普通 Edge** 节点上添加：

```text
10.0.0.10  shield-s1.example.com
```

不要在公网客户端、办公电脑或控制面上添加。

检查：

```bash
getent hosts shield-s1.example.com
```

应返回：

```text
10.0.0.10  shield-s1.example.com
```

如果同时存在公网 AAAA：

```text
2001:db8::10  shield-s1.example.com
```

也要添加内网 IPv6，否则 Edge 可能优先走 IPv6 到公网地址。

修改 hosts 后建议：

```bash
resolvectl flush-caches 2>/dev/null || true
systemctl restart lagran-edge
```

重启 Edge 是为了清掉已缓存的到旧 IP 的连接池。

#### 方式二：内部 DNS / split-horizon

生产环境更推荐内部 DNS：

```text
公网 DNS:
  cdn.example.com      → 普通 Edge
  shield-s1.example.com → NXDOMAIN 或不解析

普通 Edge 使用的内部 DNS:
  shield-s1.example.com → 10.0.0.10
```

这样：

- 公网客户端不会解析到 Shield；
- 只有 Edge 的出站解析会命中内网地址；
- 不需要在每台机器维护 hosts；
- 新增 Edge 时自动生效。

云上可以使用：

- 私有 DNS Zone；
- 内部 Route 53 / Cloud DNS / DNSPod 私有域；
- 自建 dnsmasq / CoreDNS / BIND；
- Kubernetes CoreDNS + 自定义 hosts；
- 内部 L4/L7 负载均衡 VIP。

如果使用 systemd-resolved，可以只对特定域名走内部 DNS：

```bash
resolvectl dns eth0 10.0.0.53
resolvectl domain eth0 '~shield-s1.example.com'
```

具体接口名和内部 DNS 地址按环境替换。

#### 方式三：内部负载均衡

多个 Shield 时：

```text
shield-s1.example.com
  → 内部 LB VIP 10.0.0.100
  → Shield-1 / Shield-2
```

DNS 只需要把 `shield-s1.example.com` 指向内部 LB VIP；证书放在 LB 或 Shield 上，必须匹配 `shield-s1.example.com`。

#### 方式四：公网 DNS 指向内网 IP（不推荐）

也可以让公网 DNS 直接把 `shield-s1.example.com` 解析到 RFC1918 地址：

```text
shield-s1.example.com → 10.0.0.10
```

外部客户端无法路由该地址，但这种方式会暴露内网地址，且依赖公网 DNS 可被修改；不如 split-horizon 或 hosts 安全。

#### 用业务域名复用证书时

如果使用文中的方案 A：

```text
shield_url = https://cdn.example.com
```

则在普通 Edge 的 hosts 或内部 DNS 中，把 `cdn.example.com` 指向 Shield：

```text
10.0.0.10  cdn.example.com
```

公网 `cdn.example.com` 仍然指向普通 Edge，只有 Edge 节点的出站解析命中 Shield。

#### 常见错误

- 在控制面或公网 DNS 上修改，而不是 Edge 节点的解析；
- 只改了其中一台 Edge；
- 公网 AAAA 优先于内网 IPv4，导致连接公网；
- Edge 进程有旧连接池，修改 DNS 后没有重启；
- DNS 解析到了 Shield，但证书是另一个主机名；
- 把 `shield-s1.example.com` 解析到 Shield 后，Shield 自己又使用 `shield_url` 形成自环，忘记 `EDGE_SHIELD_DISABLED=true`；
- 用 `/etc/hosts` 测试时，测试的是办公电脑而不是 Edge 节点。

#### 验证

在普通 Edge 节点：

```bash
getent hosts shield-s1.example.com
```

直接测试 TLS：

```bash
openssl s_client \
  -connect shield-s1.example.com:443 \
  -servername shield-s1.example.com \
  -verify_return_error
```

测试 HTTP：

```bash
curl -v \
  -H 'Host: cdn.example.com' \
  -H 'Range: bytes=0-1023' \
  https://shield-s1.example.com/test.bin
```

如果 DNS 尚未生效，可临时用 `--resolve` 验证 Shield 是否正常：

```bash
curl --resolve shield-s1.example.com:443:10.0.0.10 \
  -H 'Host: cdn.example.com' \
  -H 'Range: bytes=0-1023' \
  https://shield-s1.example.com/test.bin
```

但 `--resolve` 只用于测试，Edge 本身仍必须通过系统 DNS/hosts 解析。

### 5.4 证书要求

当前 [OriginClient](../apps/edge/src/origin/mod.rs) 使用：

```rust
.with_webpki_roots()
```

因此只信任 webpki 公共根证书。

要求：

- 使用 Let's Encrypt、ZeroSSL 等公网 CA 证书；
- 证书 SAN 必须匹配 `shield_url` 的主机名；
- 必须提供完整证书链；
- 证书未过期；
- 普通 Edge 能通过系统时间/根证书验证；
- 不要使用自签证书；
- 不要把内部 CA 证书直接放到系统 trust store 后期待生效；当前 OriginClient 不读取系统 trust store；
- 不要使用 `curl -k` 这种方式绕过；Edge 代码没有跳过证书校验的开关。

如果必须使用内部 CA，需要先扩展 OriginClient 的 rustls root store，增加自定义 CA 配置；当前版本不支持。

验证证书：

```bash
openssl s_client   -connect <shield-ip>:443   -servername shield-s1.example.com   -verify_return_error
```

应看到：

```text
Verify return code: 0 (ok)
```

### 5.5 专用主机名证书的签发

如果使用方案 B：

1. 在控制台先创建 `shield-s1.example.com` 域名条目；
2. 通过公网 CA 签发证书：
   - Shield 可公网访问 80 端口时，可用 HTTP-01；
   - 不能暴露公网时，使用 DNS-01 签发后手工上传；
3. 在控制台证书管理上传证书和私钥；
4. 等待证书同步到 Shield；
5. 验证 Shield 的 SNI 握手；
6. 再配置业务域名的 `shield_url`。

如果使用方案 A，直接复用业务域名现有证书，不需要新增证书。

### 5.6 专用 Shield 域名的 CNAME 和源站

如果使用方案 B，创建：

```text
shield-s1.example.com
```

这个域名是否需要 CNAME、源站怎么填，取决于目的。

#### 是否需要 CNAME 到 edge.example.com

**Shield 本身工作不需要这个 CNAME。**

普通 Edge 访问 Shield 使用的是节点内部 DNS 或 `/etc/hosts`：

```text
shield-s1.example.com → 10.0.0.10
```

这个解析覆盖了公网 CNAME。CNAME 只影响公网客户端和证书验证流程，不影响 Edge 的内部回源。

只有以下情况才可能需要公网 CNAME/A：

- 通过 HTTP-01 申请证书；
- 需要公网访问该主机名；
- 需要让公网 DNS 验证该域名归属。

如果不需要公网解析：

- 不创建公网 CNAME；
- 使用 DNS-01 签发证书后上传；
- 普通 Edge 用内部 DNS/hosts 解析。

不要把 `shield-s1.example.com` 直接 CNAME 到 Shield 公网地址，否则 Shield 会被公网暴露。

#### 源站主机填什么

创建 `shield-s1.example.com` 域名条目时，源站建议填写**业务域名使用的真实源站**：

```text
源站主机 = origin.example.com
源站端口 = 443
源站协议 = https
```

不要填写：

```text
shield-s1.example.com
edge.example.com
Shield 自己的地址
```

否则可能形成回源环。

说明：

- Shield 请求实际使用的是业务域名的 Host，不是 `shield-s1` 的 Host；
- `shield-s1` 域名条目主要用于证书管理和配置存在性；
- 如果该域名没有公网解析，通常不会有真实客户端请求；
- 如果配置了公网 CNAME，访问 `shield-s1` 会按该域名的源站配置处理，因此源站应填真实源站或专用占位源站。

#### CNAME 到 edge.example.com 的情况

如果为了 HTTP-01 把：

```text
shield-s1.example.com → CNAME → edge.example.com
```

需要注意：

- 公网访问 `shield-s1` 会到 Edge；
- Edge 必须能按 `shield-s1` 的 Host 路由；
- Edge 的普通域名配置会把这些请求当普通流量处理；
- 这会额外暴露一个公网域名；
- 证书仍然要单独安装到 Shield；
- Edge 节点内部仍要通过内部 DNS 覆盖到 Shield。

因此：

- 仅为证书验证可以临时使用；
- 生产环境更推荐 DNS-01 + 手工上传；
- 或直接使用方案 A，复用业务域名。

#### 常见选择

| 目标 | 是否需要公网 CNAME | 源站 |
|---|---|---|
| 仅内部 Shield | 不需要 | 真实源站 |
| HTTP-01 证书 | 需要指向 Edge | 真实源站 |
| DNS-01 证书 | 不需要 | 真实源站 |
| 复用业务域名证书 | 不需要 | 不新增域名 |

**推荐**：如果只是内部 Shield，优先方案 A，不创建 `shield-s1` 域名，也不配置公网 CNAME。

### 5.7 多业务域名共用一台 Shield

可以。`shield_url` 是**每个业务域名**的配置项，但它的值可以都指向同一个 Shield：

```text
cdn-a.example.com  → shield_url = https://shield-s1.example.com
cdn-b.example.com  → shield_url = https://shield-s1.example.com
cdn-c.example.com  → shield_url = https://shield-s1.example.com
```

不需要为每个业务域名部署一台 Shield，也不需要为每个业务域名申请一张 Shield 主机名证书。

#### 工作方式

普通 Edge 请求 Shield 时：

```text
TLS SNI   = shield-s1.example.com
HTTP Host = cdn-a.example.com / cdn-b.example.com / ...
```

Shield 根据 HTTP Host 选择对应业务域名的：

- 源站池；
- 缓存规则；
- WAF/CC/限流策略；
- 证书（只在 Shield 直接对外服务时需要）。

Shield 的 TLS 证书只需要覆盖：

```text
shield-s1.example.com
```

不需要覆盖所有业务域名。业务域名证书仍然由普通 Edge 对外提供。

#### 缓存隔离

大缓存 key 包含业务域名 Host，例如：

```text
GET:cdn-a.example.com:/video/1.mp4
GET:cdn-b.example.com:/video/1.mp4
```

不同业务域名的对象不会互相命中。

但要注意：

- 所有域名共享 Shield 的同一个磁盘容量；
- 所有域名共享同一个全局 LRU；
- 一个热点大客户可能驱逐其他客户的缓存；
- 当前没有按域名/租户的磁盘配额；
- 所有域名共享同一个全局 fill 队列预算；
- 大客户的并发 fill 可能影响其他客户。

如果客户之间需要强隔离，建议：

- 按区域/租户分组部署多个 Shield；
- 或增加 per-domain 容量配额和公平驱逐（当前版本未实现）。

#### 证书

只需要一张：

```text
shield-s1.example.com 的公网 CA 证书
```

安装到 Shield。

不需要：

```text
cdn-a.example.com 的证书装到 Shield
cdn-b.example.com 的证书装到 Shield
```

除非 Shield 也直接对公网客户端提供这些业务域名。

#### 控制台配置

1. 只创建一个 Shield 主机名域名条目，例如 `shield-s1.example.com`；
2. 为它上传一张公网 CA 证书；
3. 在所有普通 Edge 上配置内部解析：

```text
10.0.0.10  shield-s1.example.com
```

4. 在所有业务域名的「高级设置 → Origin Shield 地址」下拉选择同一个 Shield 节点：
```text
https://shield-s1.example.com
```

5. 确认这些业务域名在 Shield 节点上都有配置；
6. 普通 Edge 的 `EDGE_SHIELD_DISABLED=false`；
7. Shield 节点 `EDGE_SHIELD_DISABLED=true`。

#### Shield 域名条目的源站

`shield-s1.example.com` 这个域名条目不会被普通 Edge 用作 HTTP Host（普通 Edge 发的是业务 Host），它主要用于：

- 证书上传；
- 配置存在性；
- 如果该域名被直接访问时的路由。

源站可以填一个真实的内部占位源站，或业务源站；不要填 Shield 自己或普通 Edge，否则可能形成环。

#### 监控和容量

多域名共用后，Shield 的指标是聚合值，当前没有按业务域名拆分的 large-cache 指标。

建议额外使用访问日志按 Host 统计：

```text
每个域名的请求量
每个域名的命中率
每个域名的回源字节
每个域名的 5xx
```

容量规划：

- 共享 Shield 的 working set 是所有域名热点对象之和；
- 不能按单个域名估算；
- 热点集中时，一个域名可能占满 20 GiB；
- 需要给 Shield 留出足够磁盘和带宽；
- 大规模场景建议按区域/租户分片。

#### 高可用

一台 Shield 是单点。多域名共用时，建议：

```text
所有业务域名
  → 同一个 shield-vip.internal.example.com
  → 内部负载均衡
  → Shield-1 / Shield-2 / Shield-3
```

所有业务域名继续使用同一个 `shield_url`，由内部 LB 负责高可用。

注意：

- 多个 Shield 的本地磁盘缓存不共享；
- LB 可能把同一对象分到不同 Shield，造成重复回源；
- 可用 URL 一致性哈希降低重复；
- 单台 Shield 故障时，LB 摘除即可。

#### 什么时候不要共用

以下情况建议拆成多个 Shield：

- 客户要求物理/磁盘隔离；
- 单客户流量足以占满 Shield；
- 不同客户 WAF/CC 策略差异很大；
- 不同区域访问同一 Shield 延迟过高；
- 需要按客户单独计量和配额。

### 5.8 Shield 如何识别业务域名和源站

Shield 不需要为每个业务域名单独配置。它使用的是控制面下发的域名配置。

#### 获取业务域名

Shield 节点和普通 Edge 一样运行配置同步循环：

```text
GET /api/v1/config
```

控制面返回所有加速域名，包括：

- 域名；
- 源站池；
- 缓存规则；
- WAF/CC/限流；
- 证书状态；
- 域名版本。

Edge 侧处理后写入：

```text
DomainRegistry
```

Shield 节点也执行同一套同步，因此它知道：

```text
cdn-a.example.com 的源站、规则
cdn-b.example.com 的源站、规则
cdn-c.example.com 的源站、规则
```

#### 按 Host 选择业务域名

普通 Edge 请求 Shield 时，HTTP Host 是业务域名，不是 Shield 主机名：

```text
TLS SNI: shield-s1.example.com
HTTP Host: cdn-a.example.com
```

Shield 的请求处理流程：

```text
读取 Host
  → normalized_authority_host
  → DomainRegistry.lookup(host)
  → 找到 cdn-a.example.com 的 DomainEntry
```

如果 Host 没有配置：

- 返回域名未接入/404；
- 不会回退到某个默认业务域名；
- 不会因为 SNI 是 Shield 主机名就使用 Shield 域名的配置。

#### 选择源站

找到 DomainEntry 后，Shield 使用该业务域名的 `origins`：

```text
origin.host
origin.port
origin.protocol
origin.weight
origin.priority
origin.sni
origin.host_header
```

回源选择：

```text
健康检查
  → 可用源站
  → 最低 priority
  → 权重随机/轮询
  → 失败后 failover
```

Range/分片路径使用同一套源站列表：

```text
chunk_origin_targets
```

因此：

- `cdn-a.example.com` 回源到 A 的源站；
- `cdn-b.example.com` 回源到 B 的源站；
- `cdn-c.example.com` 回源到 C 的源站；
- 不需要在 Shield 上写死某个源站。

#### 为什么不会串源站

请求的缓存 key 和域名配置都包含 Host：

```text
GET:cdn-a.example.com:/video/1.mp4
GET:cdn-b.example.com:/video/1.mp4
```

Shield 根据 Host 查找 DomainEntry，而不是根据：

- Shield 主机名；
- 客户端 IP；
- SNI；
- 全局默认域名。

所以不同业务域名不会串缓存/串源站。

#### Shield 自身域名的作用

`shield-s1.example.com` 这个域名条目主要用于：

- 证书上传；
- 配置存在性；
- Shield 被直接访问时的路由。

普通 Edge 请求 Shield 时使用的 Host 是业务域名，不是 `shield-s1.example.com`。

#### EDGE_SHIELD_DISABLED 的作用

Shield 节点也收到了业务域名的配置，包括：

```text
cdn-a.example.com.shield_url = https://shield-s1.example.com
```

如果 Shield 不忽略它，就会把自己作为源站：

```text
Shield miss
  → 读取 shield_url
  → 请求自己
  → 循环
```

设置：

```env
EDGE_SHIELD_DISABLED=true
```

后，Shield 节点在处理所有业务域名时都跳过 `shield_url`，直接使用该域名的真实源站池。

普通 Edge 保持：

```env
EDGE_SHIELD_DISABLED=false
```

所以普通 Edge 仍然会用 `shield_url`。

#### 示例

配置：

```text
cdn-a.example.com
  shield_url = https://shield-s1.example.com
  origins    = origin-a.example.com:443

cdn-b.example.com
  shield_url = https://shield-s1.example.com
  origins    = origin-b.example.com:443
```

普通 Edge 请求 Shield：

```text
TLS SNI: shield-s1.example.com
Host: cdn-a.example.com
Range: bytes=...
```

Shield：

```text
1. 用 Host 找到 cdn-a.example.com
2. 检查 cdn-a 的本地大缓存
3. miss 时选择 origin-a.example.com
4. 回源并写 cdn-a 的缓存 key
```

另一个请求：

```text
TLS SNI: shield-s1.example.com
Host: cdn-b.example.com
```

Shield：

```text
1. 用 Host 找到 cdn-b.example.com
2. 检查 cdn-b 的本地大缓存
3. miss 时选择 origin-b.example.com
```

两台业务域名共用同一个 Shield、同一张 Shield 证书、同一组 Edge 内部 DNS，但缓存和源站按 Host 隔离。

### 5.9 Shield URL 的权限和 SSRF 防护

Shield URL 现在由管理员维护白名单：

```text
系统 → Shield 节点
```

只有管理员可以：

- 新增 Shield 节点；
- 修改名称/URL/启用状态；
- 删除 Shield 节点。

普通域名用户只能从启用中的 Shield 节点下拉选择，不能提交任意 URL。

后端校验：

- `shield_url` 必须对应 `shield_nodes` 表中的已启用记录；
- 未登记/已停用的 URL 不能保存；
- 被域名引用的 Shield 节点不能停用或删除；
- 被引用的 URL 不能直接改掉，必须先迁移域名；
- URL 只接受 http(s) origin，不能带路径、查询串、fragment 或账号密码。

限制的目的：

- 防止普通用户把 Edge 回源指向 `127.0.0.1`、metadata、内网服务或任意外部地址；
- 防止 SSRF/内网探测；
- 让 Shield 地址变更可审计、可统一治理。

仍需要注意：

- 管理员添加的 URL 本身必须是可信的；
- 私有/内网 Shield 地址由管理员负责审核；
- 旧版本遗留的 `shield_url` 如果不在白名单，保存其他设置时仍可保留原值，但不能改成新的任意地址；
- 共享 Shield 还需要 per-domain 容量配额，当前版本没有实现；
- 普通用户仍可选择一个已启用的共享 Shield，因此管理员需要控制共享 Shield 的容量和租户范围。

如果未来要完全隐藏 URL，可以进一步改为“Shield 组”模型；当前实现已经是 URL allowlist。

---

## 6. 部署顺序

必须按以下顺序，避免回源环：

1. 升级 Shield 节点到包含 `EDGE_SHIELD_DISABLED` 的新版 Edge；
2. 在 Shield 的 `edge.env` 设置 `EDGE_SHIELD_DISABLED=true`；
3. 重启 Shield；
4. 用 `--check-config` 确认 `origin_shield_disabled: true`；
5. 确认 Shield 的 `LARGE_CACHE_ENABLED=true`；
6. 确认 Shield 可以按业务 Host 正常响应；
7. 管理员在「Shield 节点」中登记 Shield URL；
8. 在业务域名高级设置中下拉选择该 Shield；
9. 等待普通 Edge 同步；
10. 做冷 Range 验证；
11. 观察 Shield 和源站流量。

不要在 Shield 还没启用保护开关时先配置 `shield_url`。

---

## 7. 验证

### 7.1 普通 Edge 冷请求

固定一台普通 Edge：

```bash
curl --resolve cdn.example.com:443:<普通EdgeIP> -k \
  -D - -o /dev/null \
  -H 'Range: bytes=0-1048575' \
  https://cdn.example.com/test.bin
```

第一次预期：

```text
x-cache: MISS
x-lagran-cache-source: origin
x-lagran-cache-reason: range-chunk-fill
```

第二次预期：

```text
x-cache: HIT
x-lagran-cache-source: l3
```

### 7.2 Shield 本地缓存

在 Shield 节点直接请求：

```bash
curl -k \
  -H 'Host: cdn.example.com' \
  -H 'Range: bytes=0-1048575' \
  https://shield-s1.internal.example.com/test.bin
```

第二次应命中 Shield 本地大缓存。

### 7.3 源站日志

冷对象首次请求时，源站应只看到 Shield 的一次 Range 请求，而不是每台 Edge 各一次。

如果源站仍然看到多台 Edge 的请求，检查：

- 普通 Edge 是否同步到 `shield_url`；
- Shield 是否健康；
- Shield 是否在回源时忽略了自己的 Shield 地址；
- 是否有请求绕过 Shield（规则 bypass、If-Range、WAF 等）。

### 7.4 自环检查

如果 Shield 日志出现大量：

- 同一 Host 的循环请求；
- Shield 自己访问自己的地址；
- 508/502/504；
- 回源连接数异常翻倍；

优先检查：

```env
EDGE_SHIELD_DISABLED=true
```

以及版本是否包含该开关。

---

## 8. 高可用

当前 `shield_url` 是单个地址。建议：

```text
普通 Edge
  → https://shield-vip.internal.example.com
  → 内部 L4/L7 负载均衡
  → Shield-1 / Shield-2
```

要求：

- LB 做健康检查；
- Shield 节点使用相同业务域名配置；
- 证书统一；
- Shield 的本地大缓存不共享；
- 冷对象可能在不同 Shield 上重复回源；
- 可以用 URL 一致性哈希降低重复率；
- Shield 故障时普通 Edge 回退普通源站。

不要把所有区域的 Edge 指向同一个跨地域 Shield。

---

## 9. 容量和监控

Shield 是汇聚点，建议重点监控：

```text
lagran_large_cache_used_bytes
lagran_large_cache_available_bytes
lagran_large_cache_capacity_bytes
lagran_large_cache_fs_available_bytes
lagran_large_cache_fs_reserved_bytes
lagran_large_cache_fs_admission_headroom_bytes
lagran_large_cache_min_free_bytes
```

Range/回源：

```text
lagran_edge_chunk_requests_total
lagran_edge_chunk_origin_runs_total
lagran_edge_chunk_origin_attempts_total
lagran_edge_chunk_origin_failures_total
lagran_edge_chunk_fill_drops_total
lagran_edge_chunk_fill_dropped_bytes_total
lagran_edge_chunk_fill_drop_queue_total
lagran_edge_chunk_fill_drop_budget_total
lagran_edge_chunk_fill_rejects_total
lagran_edge_chunk_fill_rejected_bytes_total
```

建议告警：

```promql
# 文件系统准入余量过低
lagran_large_cache_fs_admission_headroom_bytes
  < 2 * lagran_large_cache_min_free_bytes

# 逻辑容量接近上限
lagran_large_cache_available_bytes
  < 0.1 * lagran_large_cache_capacity_bytes

# fill 预算/队列开始丢弃
rate(lagran_edge_chunk_fill_drop_budget_total[5m]) > 0
or
rate(lagran_edge_chunk_fill_drop_queue_total[5m]) > 0

# 源站失败率
rate(lagran_edge_chunk_origin_failures_total[5m])
  /
rate(lagran_edge_chunk_origin_attempts_total[5m])
  > 0.05
```

---

## 10. 容量规划

Shield 的缓存容量要覆盖区域热点 working set。

示例：

```env
LARGE_CACHE_MAX_BYTES=21474836480
LARGE_CACHE_MIN_FREE_BYTES=1073741824
```

含义：

- 逻辑缓存上限 20 GiB；
- 文件系统至少保留 1 GiB；
- 如果文件系统总空闲 36 GiB，实际给缓存和其他数据留有余量。

注意：

- `LARGE_CACHE_MAX_BYTES` 不是 Shield 内存；
- `LARGE_CACHE_FILL_QUEUE_*` 是内存队列预算；
- `LARGE_CACHE_MIN_FREE_BYTES` 是文件系统下限，不是在途预留；
- Shield 磁盘带宽比 CPU 更容易成为瓶颈；
- Shield 出向带宽要按“普通 Edge 数量 × 热点对象大小”估算。

---

## 11. 与 WAF/CC/限流的关系

Shield 节点本身也是 Edge，会再次执行该域名的：

- WAF；
- CC；
- 域名限流；
- 防盗链；
- 签名 URL；
- 缓存规则。

这可能带来：

- 双重 WAF 检查；
- 双重 CC 计数；
- 域名 RPS 被计算两次；
- Edge 节点 IP 被当作客户端；
- 防盗链/签名校验重复。

部署前必须验证 Shield 的访问控制策略不会拦截普通 Edge。

如果无法按节点区分 WAF/CC 策略，建议：

- 使用独立的外部 Shield 缓存层；或
- 为 Shield 使用独立域名/独立策略；或
- 在 Shield 上关闭重复的安全检查。

不要假设 Shield 会自动跳过 WAF/CC。

---

## 12. 故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| Shield 自己不断请求自己 | 未设置 `EDGE_SHIELD_DISABLED=true`，或旧版二进制 | 升级 Shield，设置开关，重启 |
| 普通 Edge 仍直接回源 | `shield_url` 未同步，Shield 不健康，规则 bypass | 检查配置同步、Shield 健康、请求规则 |
| TLS 握手失败 | Shield 证书不是公网 CA、SAN/SNI 不匹配或证书链不完整 | 使用匹配 shield_url 主机名的公网证书；当前不支持内部 CA |
| Shield 返回 404/421 | Host 未配置或 Shield 无法按业务域名路由 | 确认 Shield 同步了业务域名 |
| Shield 一直 MISS | 大缓存未启用、对象低于阈值、请求 bypass | 检查 Shield 的 `LARGE_CACHE_*` 和规则 |
| Shield 频繁 fill drop | 磁盘/文件系统/队列预算不足 | 查看 Shield 的容量和 fill drop 指标 |
| 源站仍收到很多请求 | Shield 冷、LB 分散、缓存未命中 | 预热、调整 Shield 容量、检查 LB 一致性 |
| 普通 Edge 出现 5xx | Shield 故障或回退源站失败 | 检查 Shield、源站池和超时 |

---

## 13. 回滚

如果 Shield 异常：

1. 在控制台清空该域名的 `shield_url`；
2. 等待普通 Edge 同步；
3. 确认普通 Edge 恢复直接回源；
4. Shield 节点可保留 `EDGE_SHIELD_DISABLED=true`，但不再被使用；
5. 如需把 Shield 改回普通 Edge，设置 `EDGE_SHIELD_DISABLED=false` 并重启。

回滚不会自动删除 Shield 本地大缓存；需要时单独清理。

---

## 14. 相关环境变量

| 变量 | 作用 | 建议 |
|---|---|---|
| `EDGE_SHIELD_DISABLED` | Shield 节点忽略域名 `shield_url` | 仅 Shield 节点 `true` |
| `LARGE_CACHE_ENABLED` | 启用大缓存 | Shield `true` |
| `LARGE_CACHE_DIR` | 大缓存目录 | 独立 SSD |
| `LARGE_CACHE_MAX_BYTES` | 逻辑容量硬上限 | 按磁盘和热点 working set |
| `LARGE_CACHE_MIN_FREE_BYTES` | 文件系统空闲下限 | 1 GiB 起 |
| `LARGE_CACHE_CHUNK_BYTES` | Range 分片大小 | 默认 1 MiB |
| `LARGE_CACHE_FILL_QUEUE_BYTES` | 单 fill 队列 | 默认 128 MiB |
| `LARGE_CACHE_FILL_QUEUE_TOTAL_BYTES` | 全局 fill 预算 | 默认 256 MiB |
| `LARGE_CACHE_FILL_MAX_BYTES` | 单对象填充上限 | 0 = 使用对象上限 |

---

## 15. 限制

- Origin Shield 是集中式层级缓存，不是任意节点 P2P；
- `shield_url` 每个域名一个地址，高可用需要内部 LB；
- Shield 不共享其他 Edge 的本地大缓存；
- Shield 自己的 miss 会回源，不会向普通 Edge 反向请求；
- Shield 仍会执行 WAF/CC/限流等 Edge 逻辑；
- Shield 故障时依赖普通源站池回退；
- 跨地域 Shield 可能增加延迟；
- 配置 `EDGE_SHIELD_DISABLED` 需要新版 Edge 二进制。

---

## 16. 最小检查清单

```text
[ ] Shield 节点已升级到包含 EDGE_SHIELD_DISABLED 的版本
[ ] Shield 节点 EDGE_SHIELD_DISABLED=true
[ ] Shield 节点 LARGE_CACHE_ENABLED=true
[ ] Shield 节点大缓存目录、容量、文件系统下限已配置
[ ] Shield 节点能按业务域名 Host 路由
[ ] Shield 证书由公网 CA 签发，SAN 匹配 shield_url 主机名
[ ] 公网不能访问 Shield
[ ] 普通 Edge EDGE_SHIELD_DISABLED=false
[ ] 控制台域名已配置 shield_url
[ ] 已确认没有自环
[ ] 冷 Range 请求源站只看到 Shield 的请求
[ ] Shield 的 fill drop、磁盘、带宽指标已接入监控
```

---

## 17. 相关文档

- [README](../README.md)
- [使用手册](manual.md)
- [架构说明](architecture.md)
