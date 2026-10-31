# Lagran Architecture

## 组件

| 组件 | 路径 | 说明 |
|------|------|------|
| Control Plane | `apps/control` | Axum + sqlx/PostgreSQL：认证、项目/租户、域名、缓存规则、证书、刷新、统计、审计 |
| Edge Plane | `apps/edge` | Pingora 公共 HTTP/HTTPS/HTTP2/TLS 层 + 进程内 Axum 数据引擎：多域名反向代理、内存/磁盘缓存、WAF/CC、限流、防盗链、访问日志、WebSocket |
| Admin Console | `apps/frontend` | Nuxt 4 + Pinia 管理后台 |
| Shared cache | `crates/lagran-cache` | `CacheBackend` 抽象 + 带 LRU 淘汰的 `MemoryCache` |

## 通信（当前实现）

边缘与控制面之间是 **HTTP + JSON 轮询**，不是 gRPC：

- 边缘每 15s `GET /api/v1/config`，携带 `X-Lagran-Agent-Token`，拿全量域名/规则/设置与聚合版本号；
- 每 `HEARTBEAT_INTERVAL`（默认 15s）`POST /api/v1/nodes/heartbeat`；
- 心跳每 15s `POST /api/v1/nodes/heartbeat`：上报版本、CPU/内存、Agent 地址；响应携带
  `enabled/status`，被停用的节点会立即停止代理流量；
- 每 15s `POST /api/v1/metrics/report`，每 30s 批量 `POST /api/v1/access-logs/report`；
- 每 `WAF_REPORT_INTERVAL`（默认 5s）批量 `POST /api/v1/waf/events`；
- 每 30s 探测每个启用的源站并 `POST /api/v1/origin-health/report`（逐源站记录）；
- 控制面反向调用 `POST {agent_url}/__lagran/purge`、`/__lagran/certs/load`、`/__lagran/acme/challenge`；
- 边缘每 30s 拉 `GET /api/v1/certs/edge-sync`（含 PEM，需 agent token）。

`crates/lagran-proto` 与 `proto/` 是未来 gRPC 的占位，尚未接入。

## 请求流水线（edge）

1. 解析 Host/SNI → 域名注册表（多域名，未接入域名返回提示页）；域名开启 HTTPS 时，
   HTTP 请求在 WAF/缓存之前返回 301/308 跳转
2. 每域名限流（令牌桶）；源站健康只影响回源，不影响缓存命中
3. WAF 评估（按域名）：IP 白名单放行 → 黑名单拦截 → 托管规则（SQLi/XSS/路径穿越/扫描器/
   RCE/SSRF/XXE/Log4Shell/CRLF）→ 自定义规则（按优先级，支持请求头）→ 安全级别
   （低/中/高/攻击中）；动作为拦截时返回 403 页，动作为质询时返回 JS PoW 页面，
   通过后签发 HMAC 免质询 Cookie；观察模式只记录事件
4. WebSocket upgrade → 与源站完成 RFC 6455 握手后原样隧道
5. 防盗链 Referer 校验
6. 规则解析：**按域名**匹配 路径通配 + 请求方法 + 查询串 + **响应 Content-Type 子串** → `cache | bypass | no_store`、
   TTL、SWR、浏览器 TTL、是否忽略 Query；同优先级取先配置的规则。Content-Type 条件在响应头到达后判定，
   请求阶段先跳过；命中 bypass/no_store 时即使已有旧缓存也不服务。
7. 决定是否走缓存：仅 GET/HEAD，且无 Authorization、客户端未要求 no-store；Cookie 默认绕过，
   规则显式 `ignore_cookie` 时放行（并允许源站 `Vary: Cookie`）。Range GET 在完整对象已缓存时切片返回；
   未命中时透传 Range，避免视频等大文件整包回源。
   所有绕过/未存储响应带 `X-Lagran-Cache-Reason`（cookie / authorization / no-store / no-cache /
   vary:user-agent / rule-bypass / content-type-bypass / set-cookie 等）。
8. 命中：`HIT` / 条件请求 `304`；过期但在 SWR 窗口：先回 `STALE` 再后台单飞刷新
9. 未命中：single-flight 合并并发回源（多源站池：按优先级分组、同组按权重加权轮询；
   健康检查失败的源站跳过，全部异常时回退尝试；连接失败/读超时按顺序换源重试），
   按 规则 TTL → `s-maxage`/`max-age` → `Expires` → 默认 TTL 存缓存
10. 非缓存请求（POST 等）：完整转发 method/body/headers，标记 `DYNAMIC`/`BYPASS`
11. 缓存标签：源站 `Surrogate-Key` / `Cache-Tag` 随缓存对象保存，按标签刷新时只清理匹配对象；
    标签仅匹配这些响应头，不会退化为域名全量清理
12. Range：小段 Range 命中完整对象时切片；开放/大范围 Range 由 Pingora 流式透传，避免视频整包下载；
    多段 Range 透传源站

响应统一带 `X-Cache` / `X-Cache-Status` / `X-Lagran-Cache-Reason`（仅未命中缓存时）/ `Age` / `ETag`
（源站 ETag 优先，否则按内容计算）。

## 数据模型（PostgreSQL）

`users`（含全局 `role`: admin/user）、`projects`、`project_members`（owner/admin/member）、
`domains`（归属项目、多源站池 JSON、限流、CORS/防盗链/超时/自定义头、`shield_url`）、
`cache_rules`（path/ttl/priority/**action**/**swr_seconds**/**enabled**/**match_methods**/**match_query**/
**browser_ttl_seconds**/**ignore_query**/note）、`edge_nodes`、`certificates`、
`acme_challenges`、`edge_metrics`、`audit_logs`、`access_logs`、`prefetch_tasks`、
`prefetch_schedules`（定时预热）、`origin_health`、`config_versions`（域名配置快照与 Diff）、
`config_releases`（审批/灰度发布单）、`config_release_reports`（节点应用回执）、`alert_channels`、`alert_rules`、`alert_events`。

WAF 相关：`waf_settings`（域名级开关/模式/托管规则/RCE/SSRF/XXE/Log4Shell/CRLF/**security_level**）、
`waf_rules`（自定义规则，字段支持 `header:<name>`）、`waf_ip_rules`（allow/deny + CIDR）、
`waf_events`（边缘上报的命中记录，供事件列表与统计聚合）。

节点：`edge_nodes`（name/region/agent_url/status=**pending|online|offline|disabled**、
`auth_token` 单节点令牌、version、cpu_usage/memory_usage/active_connections、last_heartbeat；
调度元数据 `public_ip/isp/country/province/city/weight/max_bandwidth_mbps`）。

## 边缘数据面

`lagran-edge` 的公共网络层由 Pingora 负责：

```text
Internet
  → Pingora HTTP/HTTPS listener（HTTP/1.1 + HTTP/2、SNI 动态证书）
  → 域名请求：WAF/CC/限流/防盗链/HTTPS 预检
      ├─ 可缓存 GET → pingora-cache → upstream_peer → origin
      ├─ BYPASS / 动态 / WebSocket → upstream_peer（流式）
      └─ HEAD → 同进程引擎 + 复用 GET cache key
  → 未知/旧模式域名：进程内调用旧引擎
  → health / ACME / challenge verify / 管理接口：Pingora 直接响应
```

- 所有域名请求先执行 WAF/CC/限流/防盗链/HTTPS 跳转预检；handler 与 Pingora
  共用同一个 `preflight_cacheable` 实现。
- 可缓存 GET 使用 `pingora-cache`；缓存后端由现有 `SharedCache` 适配（key 与旧路径一致，
  admin purge 继续生效），回源由 `upstream_peer` 直连源站；`origin_health` 为
  unhealthy 时优先切换到 backup。
- cache key 包含规范化的 `Accept-Language` 哈希，避免 `Vary: Accept-Language` 响应串语言；
  ETag 由响应 body 计算（源站未提供时），不使用 cache key 生成。
- BYPASS/动态请求保留客户端的 `Cache-Control`/`Pragma`，只在可缓存 GET/HEAD 上做
  `max-age=0` reload 归一化。
- `pingora-cache` 启用 cache lock，并发 miss 会合并；`should_serve_stale` 允许
  `stale-while-revalidate` 窗口返回 STALE。
- Control 的 config/cert 下发支持 ETag + `If-None-Match`/304；Edge 保存上次
  ETag 后不再重复处理未变化的配置/证书。metrics 使用批量接口，access logs 和
  WAF events 使用 gzip 请求体。
- Control → Edge 的 purge/reload/cert/challenge 回调共用 `agent_http` 连接池，
  单次超时和一次重试；DNS → Control 的 schedule 客户端使用持久 HTTP/1.1 连接池。
- BYPASS、POST/PUT 等动态请求和 WebSocket 直接走 `upstream_peer`，请求/响应 body
  流式转发；开放/大范围 Range GET 由 Pingora 直接流式回源，小段命中完整对象时由旧引擎切片返回 206。
- 配置 `shield_url` 时，边缘把 Shield 作为优先级 -1 的回源目标，仍发送公开域名 Host；
  Shield 失败后按普通源站池顺序回退。
- HEAD 由同进程引擎回源 GET 并复用 GET cache key，GET/HEAD 共享同一个缓存对象；
  这样 HEAD 不会把空 body 写入 GET 缓存。HTTP/2 HEAD 返回真实 `Content-Length`；
  HTTP/1.1 因 Pingora H1 编码器限制继续返回 `0`，避免客户端等待不存在的 body。
- 健康检查、ACME HTTP-01、challenge verify、purge/cert/challenge/access-log 管理接口
  由 Pingora 直接响应；`EDGE_ADMIN_LISTEN` 设置时管理接口只在该端口接受，数据口返回 405。
- 未知/旧模式域名仍在进程内调用旧引擎，不再启动 loopback Axum 监听。
- 公共 TLS 只由 Pingora 终止；旧 rustls/hyper HTTPS 终结代码与 `EDGE_TLS_CERT`/
  `EDGE_TLS_KEY` 配置已移除，管理面只保留 HTTP Axum。
- Pingora 终止 TLS，证书回调直接读取 `CertStore` 的 PEM，支持热加载和通配符。
- Pingora 将真实客户端 IP 写入 `X-Forwarded-For`；未开启 `TRUST_PROXY_HEADERS` 时
  会覆盖客户端伪造值，开启时保留上游可信代理的值。
- `EDGE_ADMIN_LISTEN` 管理端口仍由 Axum 直接监听，不经过 Pingora。

## 调度（Phase 1）

控制面 `scheduler` 模块读取 `GEOIP_PATH`（V2Ray/Loyalsoldier `geoip.dat` 国家代码，
或旧版 CIDR JSON 的省/市/运营商），按
`weight + 同国家/同省/同城/同运营商加分 - CPU/内存惩罚` 对在线节点排序，暴露
`/api/v1/schedule` 给 DNS 插件/SDK。`apps/dns` 是自研权威 DNS（UDP/TCP、EDNS0+ECS、
缓存与降级），也可用 `tools/dns/powerdns-pipe.sh` 接入 PowerDNS。DNS TTL 默认 30 秒；
节点故障需等 TTL 过期或 DNS 侧主动刷新。

## 鉴权与多租户

- 管理端：JWT（`Authorization: Bearer`）。`Actor` 提取器在每个请求从库中读取当前角色、启用状态和
  `token_version`，因此降权、禁用、改密即时生效；`/auth/me` 同样校验 token version。
- `admin`：可见全部项目/域名/节点/审计，并可创建/禁用/删除用户、调整全局角色。
- 注册：`ALLOW_REGISTER=true` 时开放，新用户为 `user` 并自动创建个人 `Default` 项目。
- `admin` 不能禁用/降权/删除自己；不能移除最后一个启用中的 admin。
- 项目 `owner`/`admin`：项目内读写；`member`：只读；owner 不可被改角色或移除。
- 未归属任何项目的域名仅 admin 可见可改。
- 非 admin 新建域名时若未指定项目，自动创建/复用它自己的 `Default` 项目，保证隔离。
- 边缘侧接口（配置、证书、心跳、指标、日志上报）只接受节点 `auth_token`；DNS `/schedule` 接受全局 `AGENT_TOKEN` 或节点 token。

## 可观测性与告警

- 控制面 `GET /metrics` 输出 Prometheus 文本：进程/数据库状态、域名与节点分组、逐源站健康与连续失败、
  证书到期时间戳、24h 请求/命中率/WAF 事件、当前 firing 告警和启用通知渠道。
- 边缘 `GET /__lagran/metrics`（管理端口或数据面管理路径）输出逐域名请求、命中、未命中、字节数。
- `OTEL_EXPORTER_OTLP_ENDPOINT` 开启 OTLP/HTTP JSON Trace 导出；HTTP 中间件为每个请求创建
  `http.request` span，字段含 `http.method`、`url.path`、`http.status_code`，采样率由
  `OTEL_TRACES_SAMPLER_ARG` 控制。未配置时完全关闭，不增加导出开销。
- 告警规则保存在 `alert_rules`，通知渠道在 `alert_channels`，事件在 `alert_events`；
  后台每 `ALERT_EVAL_SECS` 秒评估：源站健康、证书到期、节点离线、缓存命中率、WAF 事件突增。
  同一规则+对象只保留一条 `firing` 事件，恢复后更新为 `resolved`；通知支持 SMTP、Webhook（HMAC-SHA256 可选）
  和 Telegram。

## 配置发布

- 每次域名/缓存规则/WAF/高级设置变更后，控制面保存一份 `config_versions` JSON 快照，并与上一版计算字段级 Diff。
- 发布单选择若干域名版本：`pending_approval → approved → publishing → published`；管理员审批后才能发布。
- 指定目标节点时，只有目标节点暂时读取发布快照；其他节点继续使用旧的发布版本。
- 边缘配置请求携带 `x-lagran-node-id`，应用成功后上报 `/api/v1/config/apply-report`；全部目标节点成功后才写入全局
  `domains.published_version_id`。任一节点失败或 120 秒未上报，发布单自动回滚，旧配置继续生效。
- 一旦域名绑定发布版本，后续编辑只产生新版本，不会立即影响边缘；需要新的发布单才会切换。

## 控制台体验

- 列表分页复用 `AppPagination`；域名、用户、节点、统计等支持 CSV 导出，域名支持批量启停/删除。
- 深色模式通过 `<html data-theme>` 与 CSS 变量切换并持久化；PWA 提供 `manifest.webmanifest`、`sw.js` 和客户端注册。
- 中英文切换目前覆盖导航、面包屑、全局控件及新增页面；业务页面可继续接入同一 `useLocale` 字典。
- 域名诊断 API 检查 DNS、TLS 证书链、源站 TCP 可达性，并通过在线边缘执行一次真实缓存探测。
- `/stats/timeseries` 提供小时/天粒度的请求、命中、流量序列；`/monitor` 使用独立全屏布局每 10 秒刷新。

## 存储

- PostgreSQL：控制面元数据与统计；
- 边缘缓存：`memory`（DashMap + LRU）、`disk`（文件 + meta，按 mtime 淘汰，
  写临时文件后 rename），或 `hybrid`（L1 内存 + L2 磁盘，磁盘命中按剩余 TTL 提升）；
- Redis 目前未使用（`lagran-common::config::RedisConfig` 为占位）。
