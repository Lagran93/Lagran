# GeoDNS 边缘节点调度流程

> 本文说明用户访问接入 Lagran CDN 的域名时，GeoDNS 如何选择并返回边缘节点 IP。
>
> 相关代码：
>
> - `apps/dns/src/server.rs`：权威 DNS、缓存、stale/fallback
> - `apps/dns/src/control.rs`：调用控制面 `/api/v1/schedule`
> - `apps/control/src/scheduler/mod.rs`：GeoIP 解析与节点打分
> - `apps/control/src/api/mod.rs`：`/api/v1/schedule` 路由
> - `apps/edge/src/server/handler.rs`：边缘按 Host/SNI 处理请求

---

## 1. 参与组件

| 组件 | 作用 |
|---|---|
| 客户域名 | 例如 `cdn.example.com`、`test.akgo.net` |
| 客户 DNS / Cloudflare | 保存 `cdn.example.com CNAME edge.lagran.net` |
| 权威 DNS `lagran-dns` | 对 `edge.lagran.net` 提供 A/NS/SOA，执行 Geo 调度 |
| 控制面 `lagran-control` | 提供 `/api/v1/schedule`，读取节点与 GeoIP 并打分 |
| PostgreSQL | 保存节点、域名、规则、证书等 |
| GeoIP DAT / JSON | `geoip.dat`（国家代码）或旧版 CIDR JSON（省/市/运营商） |
| 边缘节点 `lagran-edge` | 实际提供缓存、回源、HTTPS、WAF |

关键点：

> GeoDNS 只负责“返回哪个边缘 IP”，不代理流量。  
> 用户最终直接连接到选中的边缘节点。

---

## 2. 前置配置

### 2.1 客户域名 CNAME 到 Zone

```dns
cdn.example.com.  CNAME  edge.lagran.net.
```

`test.akgo.net` 同理：

```dns
test.akgo.net.  CNAME  edge.akgo.net.
```

### 2.2 Zone 委派给 lagran-dns

```dns
edge.akgo.net.      NS  ns1.edge.akgo.net.
edge.akgo.net.      NS  ns2.edge.akgo.net.

ns1.edge.akgo.net.  A   146.56.187.190
ns2.edge.akgo.net.  A   129.154.202.52
```

两台 `lagran-dns` 保存同一份 Zone 数据，并返回相同的 NS/glue。

### 2.3 控制面维护节点数据

`edge_nodes` 表中每个节点包含：

```text
name
status          online / offline / disabled
public_ip       返回给用户的边缘 IP
country
province
city
isp
weight
cpu_usage
memory_usage
agent_url
```

只有满足以下条件的节点才会参与调度：

```text
status = online
public_ip 非空
```

---

## 3. 完整业务链路

### 步骤 1：用户发起访问

用户访问：

```text
https://cdn.example.com/file.js
```

浏览器先向本地 DNS 查询 `cdn.example.com`。

### 步骤 2：本地 DNS 拿到 CNAME

客户域名配置：

```dns
cdn.example.com. CNAME edge.lagran.net.
```

递归 DNS 得到：

```text
cdn.example.com → edge.lagran.net
```

然后继续查询：

```text
edge.lagran.net A
```

### 步骤 3：递归 DNS 查询权威 NS

父 Zone 已将 `edge.lagran.net` 委派给：

```text
ns1.edge.lagran.net
ns2.edge.lagran.net
```

递归 DNS 从两台 NS 中选择一台查询，可能携带 **EDNS Client Subnet（ECS）**：

```text
edge.lagran.net A
+ ECS 1.2.3.0/24
```

ECS 表示 LocalDNS 告诉权威 DNS：

> 这个查询大致来自 `1.2.3.0/24` 网段。

没有 ECS 时，权威 DNS 只能看到 **LocalDNS 的出口 IP**，不一定是用户真实 IP。

### 步骤 4：lagran-dns 判断是否在 Zone 内

`lagran-dns` 收到查询后：

1. 检查 qclass 是否为 IN
2. 检查 qname 是否属于 `edge.lagran.net`
3. 检查 qtype
4. `ANY` 直接 REFUSED
5. 查询 NS 主机名本身时返回 glue A
6. 其他不支持的类型返回 NODATA + SOA

对于 `edge.lagran.net A`，进入调度逻辑。

### 步骤 5：构造缓存 Key

DNS 优先使用 ECS 子网：

```text
subnet = 1.2.3.0/24
```

缓存 key：

```text
edge.lagran.net|A|1.2.3.0/24
```

没有 ECS 时：

```text
edge.lagran.net|A|LocalDNS出口IP
```

然后查本地缓存。缓存命中且未超过 `DNS_CACHE_SECS` 时，直接返回缓存 IP，不调用控制面。

### 步骤 6：缓存未命中，调用控制面

DNS 向控制面发起：

```http
GET /api/v1/schedule?domain=edge.lagran.net&subnet=1.2.3.0/24
x-lagran-agent-token: <全局 AGENT_TOKEN>
```

只有客户端 IP 时：

```http
GET /api/v1/schedule?domain=edge.lagran.net&ip=1.2.3.4
```

控制面 `AgentAuth` 校验 token：

- 全局 `AGENT_TOKEN`
- 或某个节点的 `auth_token`

DNS 不是节点，通常使用全局 token。

### 步骤 7：控制面做 Geo 解析

控制面从请求中取：

```text
subnet = 1.2.3.0/24
或
ip = 1.2.3.4
```

然后查 `GEOIP_PATH` 指向的 GeoIP 表。推荐使用
[Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) 的 `geoip.dat`：

```bash
wget -O /var/lib/lagran/geoip.dat \
  https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat

GEOIP_PATH=/var/lib/lagran/geoip.dat
```

`geoip.dat` 是 V2Ray `GeoIPList` protobuf，只提供国家代码（如 `cn` → `CN`），
不包含省/市/运营商。匹配后：

```text
country  = CN
province = ""
city     = ""
isp      = ""
```

如果仍需要省/市/运营商，可使用旧版 JSON（`GEOIP_JSON_PATH` 或 `GEOIP_PATH=.json`）：

```json
[
  {
    "cidr": "1.2.3.0/24",
    "country": "CN",
    "province": "广东",
    "city": "深圳",
    "isp": "电信"
  }
]
```

匹配规则：

- 按 CIDR 前缀长度从长到短
- **最长前缀优先**
- 例如 `/24` 优先于 `/16`
- DAT 中 `private`、`telegram` 等非国家分类会被忽略

GeoIP 文件不存在时不会报错，会退化为只按权重和负载调度。使用 DAT 时
`province/city/isp` 为空，调度只会有国家加分。

请求中也可以显式覆盖：

```text
country / province / city / isp
```

主要用于 DNS 插件或管理端测试。

### 步骤 8：筛选可用节点

控制面查询所有节点，过滤：

```text
status == online
public_ip 非空
```

假设有：

| 节点 | 地区 | 运营商 | 权重 | CPU | 内存 |
|---|---|---|---|---|---|
| gz-01 | 广东深圳 | 电信 | 100 | 20% | 30% |
| hk-01 | 香港 | BGP | 120 | 10% | 10% |
| kr-01 | 韩国 | BGP | 100 | 10% | 20% |

### 步骤 9：节点打分

当前评分公式：

```text
score = clamp(weight, 0, 1000)
      + 5   如果 country 相同
      + 80  如果 province 相同
      + 20  如果 city 相同
      + 40  如果 isp 相同
      - floor(cpu_usage * 0.3)
      - floor(memory_usage * 0.2)
```

以深圳电信用户为例。

#### gz-01

```text
weight 100
country 相同 +5
province 相同 +80
city 相同 +20
isp 相同 +40
CPU 20% → -6
内存 30% → -6
```

总分：

```text
100 + 5 + 80 + 20 + 40 - 6 - 6 = 233
```

#### hk-01

```text
weight 120
country 不同 +0
province 不同 +0
city 不同 +0
isp 不同 +0
CPU 10% → -3
内存 10% → -2
```

总分：

```text
120 - 3 - 2 = 115
```

#### kr-01

```text
100 - 3 - 4 = 93
```

排序结果：

```text
gz-01 233
hk-01 115
kr-01 93
```

返回：

```text
primary = gz-01
backup  = hk-01
```

同分时按节点名称排序。

---

## 4. 控制面返回结构

```json
{
  "domain": "edge.lagran.net",
  "ttl": 30,
  "client": {
    "country": "CN",
    "province": "广东",
    "city": "深圳",
    "isp": "电信"
  },
  "primary": {
    "name": "gz-01",
    "public_ip": "203.0.113.21",
    "province": "广东",
    "city": "深圳",
    "isp": "电信",
    "weight": 100,
    "score": 233,
    "reason": "same-province same-city same-isp"
  },
  "backup": {
    "name": "hk-01",
    "public_ip": "203.0.113.22"
  },
  "candidates": [],
  "note": "共 3 个候选节点"
}
```

DNS 实际只取：

```text
primary.public_ip
backup.public_ip
ttl
```

然后生成 A 记录。

---

## 5. DNS 返回 A 记录

DNS 返回：

```dns
edge.lagran.net. 30 IN A 203.0.113.21
```

最终 TTL：

```text
min(控制面 ttl, DNS_TTL)
且最小 5 秒
```

例如：

- 控制面 `SCHEDULE_TTL=30`
- DNS `DNS_TTL=30`

最终 TTL = 30。

如果控制面返回 60，但 `DNS_TTL=30`，最终仍是 30。

### 5.1 DNS 本地缓存

```text
DNS_CACHE_SECS=30
```

含义：

- 30 秒内相同 ECS/客户端 IP 的查询直接返回缓存
- 不重复调用控制面
- 不影响返回给客户端的 TTL

### 5.2 递归 DNS / 浏览器缓存

递归 DNS 按 A 记录 TTL 缓存，浏览器也会缓存。

一次调度结果可能被多级缓存：

```text
lagran-dns 本地缓存
→ 递归 DNS 缓存
→ 操作系统缓存
→ 浏览器缓存
```

TTL 越长，节点切换越慢，但 DNS 压力和失败率越低。

---

## 6. 用户最终连接边缘

用户拿到：

```text
cdn.example.com → edge.lagran.net → 203.0.113.21
```

浏览器连接：

```text
203.0.113.21:443
```

请求头/SNI：

```http
Host: cdn.example.com
SNI: cdn.example.com
```

边缘节点：

1. 按 Host/SNI 找域名配置
2. 选择证书
3. 检查 WAF/限流/防盗链
4. 查缓存
5. 未命中回源
6. 返回内容

GeoDNS 的职责到此结束；后续缓存、回源、WAF 都在边缘完成。

---

## 7. 失败时的降级逻辑

### 7.1 控制面不可用

DNS 调用 `/api/v1/schedule` 失败时：

```text
先看本地缓存
→ 缓存年龄 ≤ DNS_STALE_SECS，返回 stale IP
→ 否则看 DNS_FALLBACK_IP
→ 否则 SERVFAIL
```

对应配置：

```bash
DNS_CACHE_SECS=30
DNS_STALE_SECS=600
DNS_FALLBACK_IP=203.0.113.21
```

如果没有 `DNS_FALLBACK_IP`，控制面故障且无缓存时，用户会看到解析失败。

### 7.2 没有在线节点

控制面返回：

```json
{
  "primary": null,
  "backup": null,
  "note": "没有可调度的在线节点"
}
```

DNS 没有 IP 可返回：

- 有 `DNS_FALLBACK_IP` → 返回兜底 IP
- 没有 → SERVFAIL

### 7.3 ECS 缺失

DNS 用 LocalDNS 出口 IP 查 GeoIP。

可能的问题：

- 用户在上海，LocalDNS 在北京 → 调度到北京节点
- 用户走了公共 DNS → 出口 IP 在别的城市
- 运营商缓存 DNS → 地理位置偏差

这是 GeoDNS 的天然限制。

### 7.4 GeoIP 没有匹配

GeoIP 表没有该 CIDR：

```text
province/city/isp 为空
```

评分变成：

```text
weight - cpu惩罚 - mem惩罚
```

所有节点按权重和负载竞争。

### 7.5 节点 public_ip 为空

该节点被直接排除，不会返回。

### 7.6 节点 offline

心跳超过约 60 秒未上报，控制面标记 offline，调度不再返回。

### 7.7 一台 NS 不可达

递归 DNS 可能重试另一台 NS。  
如果两台都不可达，或者 LocalDNS 不重试，就会解析失败。

---

## 8. 完整示例

用户：深圳电信，访问 `https://test.akgo.net/s.js`

```text
1. 浏览器查 test.akgo.net
2. Cloudflare 返回 CNAME edge.akgo.net
3. 本地 DNS 查 edge.akgo.net A，带 ECS 1.2.3.0/24
4. 递归 DNS 选择 ns1(146.56.187.190)
5. lagran-dns 缓存未命中
6. 调控制面：
   /api/v1/schedule?domain=edge.akgo.net&subnet=1.2.3.0/24
7. 控制面 GeoIP 匹配：广东/深圳/电信
8. 节点打分：gz-01=233，hk-01=115
9. 返回 primary=203.0.113.21，TTL=30
10. lagran-dns 返回：
    edge.akgo.net. 30 IN A 203.0.113.21
11. 递归 DNS 缓存 30 秒
12. 浏览器连接 203.0.113.21:443
13. 边缘按 Host=test.akgo.net 找配置、证书、缓存
```

---

## 9. 影响调度准确性的关键点

| 因素 | 影响 |
|---|---|
| 是否有 ECS | 没有 ECS 时按 LocalDNS IP 判断，可能不准 |
| GeoIP 表质量 | CIDR 粒度越细，省/市/运营商越准 |
| 节点元数据 | `province/city/isp` 填错会直接选错 |
| 节点 `public_ip` | 必须是用户真实可访问的边缘 IP |
| 节点状态 | offline 不参与调度 |
| 权重 | 权重过高会压过地理位置加分 |
| CPU/内存 | 负载高会被扣分 |
| TTL | 越大越稳定，但切换越慢 |
| 控制面可用性 | 控制面挂了只能靠缓存/兜底 |
| NS 可达性 | 国内 LocalDNS 到海外 NS 可能丢包 |
| 多 NS 冗余 | 一台 NS 故障时另一台能否接管 |

---

## 10. 当前实现限制

当前调度是 **全局节点池**：

```text
domain 参数只用于日志和返回，不参与节点过滤
```

也就是说：

- 所有域名共享同一批 online 节点
- 还没有实现“按域名绑定节点池”
- 没有按节点带宽上限做硬限制
- `max_bandwidth_mbps` 目前不参与评分

如果需要“某客户只能调度到某些节点”，需要在 `resolve()` 中增加域名 → 节点组过滤。

---

## 11. 总结

> 用户查询客户域名 → CNAME 到 `edge.lagran.net` → 递归 DNS 带着 ECS 查询 `lagran-dns` → DNS 把 ECS/客户端 IP 发给控制面 → 控制面用 GeoIP 匹配省市运营商，结合节点权重、CPU、内存打分 → 返回最优边缘 `public_ip` → DNS 返回 A 记录 → 用户直接连接该边缘节点。

GeoDNS 只做 **“选 IP”**，真正的缓存、回源、HTTPS、WAF 都在边缘节点完成。
