# RequestPipeline 迁移

目标架构：

```text
Pingora
  TCP/TLS/HTTP2
  连接池
  streaming
  cache storage
  upstream
  HEAD / Range / WebSocket upgrade tunnel

RequestPipeline
  HTTPS redirect
  WAF
  CC
  限流
  认证 / clearance
  缓存规则
  条件请求
  日志
  指标

Legacy
  迁移目标：不承载数据面（阶段 6 删除）
  仅 single-origin 兜底，是否保留见阶段 3 决策
  管理接口是独立监听器（EDGE_ADMIN_LISTEN），不属于 legacy
```

## 当前状态

### 已达到的状态（2026-11-24 代码核对）

共享入口已建立，两个数据面确实都走它：

```rust
RequestPipeline::new(&state)
    .preflight(&domain, &facts)
    .await
```

已经真正落在 `RequestPipeline` 里的部分：

| 能力 | 位置 | 说明 |
|---|---|---|
| 请求分类 | `server/pipeline.rs:103-129` | `RequestClass`：`Cacheable` / `StrictRevalidation` / `Bypass` / `Websocket` / `Dynamic` |
| policy 解析 | `server/pipeline.rs:70-89` | `resolve_rule_policy` + `apply_key_ignore_default` |
| cache key | `server/pipeline.rs:133-202` | Vary 头、ignore_query、HEAD→GET 归一 |
| 条件请求 | `pingora_edge.rs:2088-2456` | `try_normal_revalidation` / `try_large_revalidation` / `revalidate_strict` |
| Range | `pingora_edge.rs:873-1054` | 小范围切片、LargeCache 覆盖、chunk fill 全在 Pingora |

尚未真正完成的部分是 **preflight 只有入口、没有实现**：`RequestPipeline::preflight`
（`server/pipeline.rs:207-225`）仍是转发，实现体 `preflight_cacheable` 留在
`server/handler.rs:2707-3122`（约 415 行）。也就是说，今天的"单一安全管线"靠的是
**同一个函数被两条路径调用**，而不是管线自己拥有实现。

### 本次核对修正的三处认知偏差

1. **WebSocket 已不是 legacy-only**。`tests/integration/ws-echo.sh:2` 写明
   "through Pingora's native upgrade tunnel"，`pingora_edge.rs:763-767` 也说明 upgrade
   走 native proxy。handler 的 WS 分支（`handler.rs:599-640`）只剩
   "未知 host + 空注册表"这一条可达路径。
2. **HEAD 相关实现是死代码**。`native_plan` 在 `pingora_edge.rs:2779` 对 HEAD 直接
   `return None`，于是 `plan.is_head` 恒为 false，`serve_head_cache`（4687）、
   `response_filter` 的 HEAD 分支（1638-1642）、`ctx.head_body`（315-317）、
   `logging` 的 head 落盘（1882 起）全部不可达。这是 64395aa 把 HEAD 回退到
   in-process 引擎的直接结果。
3. `!native_cache || storage.is_none()`（`pingora_edge.rs:2772`）恒不成立：
   `run()` 里 `storage` 恒为 `Some`（5927、5940），`native_cache` 由它派生。

规模：`server/handler.rs` 共 4101 行 ≈ 共享工具（preflight、日志、响应头、host 工具）
700 行 + legacy 专用缓存/回源 2500 行 + WebSocket 隧道 40 行 + 类型与辅助函数。

## 剩余兜底清单

legacy 数据面今天仍会被进入的路径只有下面 6 条。唯一出口是 `handle_in_process`
（调用点 `pingora_edge.rs:798`、`pingora_edge.rs:1079`，实现 `4930`）。

| # | 触发条件 | 代码位置 | 今天的行为 | 迁移目标 |
|---|---|---|---|---|
| 1 | HEAD（全部） | `native_plan` 早退 `pingora_edge.rs:2779` | 命中缓存或 HEAD 回源 | 阶段 2：Pingora 内自应答 |
| 2 | 节点被禁用 `!node_control.is_serving()` | `pingora_edge.rs:2789` | 503 页面（`handler.rs:413-430`） | 阶段 3：filter 内直出 |
| 3 | 严格重校验失败（6 种，见下） | `pingora_edge.rs:2110-2456` | 删缓存 → legacy 全量回源 | 阶段 4：Pingora 内闭环 |
| 4 | 未知 host 且注册表为空 | `pingora_edge.rs:786-799` | single-origin（`handler.rs:537-562`） | 阶段 3：决策保留或废弃 |
| 5 | `parse_origin` 失败 | `pingora_edge.rs:2832` | 回落 legacy | 阶段 3：直出 502 + 配置校验 |
| 6 | 缓存诊断直调 legacy | `server/cache_diag.rs:115` | 诊断测的是 legacy 行为 | 阶段 5：改走 loopback 真实路径 |

### 第 3 类的 6 种情形

`try_normal_revalidation` 返回 `Ok(false)` 的条件，阶段 4 逐个收敛：

- validator 来源是 `computed`（`pingora_edge.rs:2297-2300`）
- 无 etag 也无 last-modified（`2306-2310`）
- 没有 enabled 的 origin target（`2312-2315`）
- 条件请求错误或超时（`2364-2369`）
- origin 返回非 304 且非 2xx（`2410-2411`）
- 304 但 `decide_storage_reason` 失败（`2438-2444`）

### 死代码（迁移前必须先处理）

这些不是"待迁移"，而是"待删除或接回"。阶段 2 不处理它们，HEAD 原生化就会
在死路径上再叠一层：

- `NativePlan::is_head`（`pingora_edge.rs:130`）恒为 `false`，因为 `native_plan` 在 2779 对 HEAD 早退；
- `serve_head_cache`（`4687`）与其调用点（`1059`）不可达；
- `response_filter` 的 `content-length: 0` HEAD 分支（`1638-1642`）不可达；
- `ctx.head_body` / `ctx.head_headers`（`315-317`）与 `logging` 的 head 落盘（`1882` 起）不可达；
- `if !self.native_cache || self.storage.is_none()`（`2772`）恒不成立。

## 迁移阶段

每一步都可以独立合入、独立回滚；任何一步失败时 legacy 仍是可用兜底。
顺序的理由：先建立度量（阶段 0）→ 搬实现（阶段 1）→ 做功能迁移（阶段 2-4）→
解除诊断依赖（阶段 5）→ 删除代码（阶段 6）。

已完成的基线（不在本轮计划内，仅作前提）：请求分类、policy 解析、cache key、
条件请求（no-cache 普通对象与 LargeCache）、Range 全路径都已在 Pingora
（见"已达到的状态"表格）。

### 阶段 0：兜底原因可观测化（1 天）—— ✅ 已完成

现状只有总计数 `lagran_edge_datapath_legacy_total`（`metrics/mod.rs:30-31`，
Prometheus 文本在 `server/listener.rs:242-247`），无法回答"还剩什么在走 legacy"。
没有这一步，后面删代码只能靠猜。

改动：

- `handle_in_process` 增加 `reason: &'static str` 参数，两个调用点分别传
  `unknown_host_single_origin`（`798`）与按 `native_plan` 缺失原因细分的
  `head` / `node_disabled` / `strict_revalidation` / `no_origin` / `parse_origin`（`1079`）。
- `EdgeMetrics` 按 reason 增加固定字段计数，沿用现有"每个维度一个 `AtomicU64` +
  snapshot 结构体 + Prometheus 文本"的写法，暴露
  `lagran_edge_legacy_fallback_total{reason}`。

验收：

- HEAD、no-cache、Range 各打一次请求，断言 reason 计数分别为 `head` / 0 / 0；
- `EDGE_ADMIN_LISTEN` 已设置的实例上打管理接口，确认不计入 legacy
  （管理路径由 `handle_management` 处理，不进 `handle_in_process`）。

落地说明（实际实现）：

- reason 收敛为 7 个固定变体 `LegacyFallback`：`head` / `node_disabled` /
  `strict_revalidation` / `single_origin` / `parse_origin` / `native_cache_disabled` /
  `other`。推导集中在 `plan_blocker`，`native_plan` 与 `legacy_reason` **共用同一份
  判断**，避免"指标里的原因"与"实际路由决策"漂移；
- 指标暴露 `legacy_fallbacks()` → `LegacyFallbackSnapshot`，Prometheus 文本由
  `prometheus_lines()` 统一生成，数据面 `pingora_edge.rs` 的 `/__lagran/metrics`
  与管理面 `server/listener.rs` 复用同一实现，不存在两套口径；
- 两个计数器口径不同，不要互相校验：`lagran_edge_datapath_legacy_total` 含缓存诊断的
  legacy 直调，`lagran_edge_legacy_fallback_total{reason}` 只统计 `handle_in_process`
  交接点（单测已锁定该差异）；
- 验收已落到 `tests/integration/cache-diagnostics.sh`：7 项 reason 计数断言（含
  `head`）、管理接口不计入 legacy、`delta` 辅助函数用于"前后增量"断言。

### 阶段 1：preflight 实现搬进 pipeline（1-2 天，纯机械）

改动：

- 把 `preflight_cacheable`（`handler.rs:2707-3122`）连同 `uuid_like_request_id`（3335）、
  `log_access`（3304）、`hotlink_allowed`（3270）、`policy_browser_ttl`（2511）、
  `apply_browser_ttl` / `apply_security_headers` / `apply_cors_and_custom`（2519/3343/3358）
  迁到 `server/pipeline/preflight.rs` 与 `server/shared/`；
- `RequestPipeline::preflight` 直接调用新实现，`handler.rs` 不再被 pipeline 反向依赖。

零行为变化：review 用 `git diff -M` 确认只有移动，没有逻辑改动。

验收：`cargo test -p edge`；`waf.sh`、`cc.sh`、`cache-rules.sh`、`p2-hardening.sh`、
`cache-diagnostics.sh` 全绿。这 415 行是所有安全策略的入口，**必须跑脚本，不能只看编译**。

### 阶段 2：HEAD 原生化（3-5 天）

设计：**HEAD 不进入 Pingora 代理，而是在 `request_filter` 内自应答**，与
`try_normal_revalidation` 的做法一致，最后用 `write_axum_response(session, resp, true, …)`
写出。理由：

- `write_axum_response`（`pingora_edge.rs:5169` 起）已经实现了正确语义：
  `head_content_length_for_protocol`（`5120`）对 HTTP/1.1 与 HTTP/2 都返回表示长度，
  body 恒为空；单测 `6140-6142` 与集成脚本 `head-h2.sh` 已把该契约钉死；
- 这正是 64395aa 把 HEAD 踢回 legacy 的根因所在：`response_filter` 为绕开
  "Pingora H1 编码器按 Content-Length 等 body"只能写 `content-length: 0`
  （`1638-1642` 的注释），与"H1 也报真实长度"冲突；自应答不走该编码器，问题消失；
- 今天的 HEAD 本来就是 legacy → `write_axum_response(..., is_head)`（`4930-4994`），
  所以上线后的字节序列不变，风险最低。

实现要点：

- 去掉 `native_plan` 的 HEAD 早退（`2779`），HEAD 改走新增 `serve_head()`：
  - 缓存命中（SharedCache / LargeCache 完整对象）→ 复用 `serve_head_cache`（`4687`），
    但把 `is_h2 ? len : 0`（`4714-4721`）改为**始终真实长度**，否则 H1 报 0 会让
    `head-h2.sh` 失败；保留 `If-None-Match` → 304 语义；
  - 带 `no-cache` / `max-age=0` 的 HEAD → 先命中缓存再条件 304，不回落 legacy；
  - 未命中 → 复用 `fetch_head_origin`（`handler.rs:1806`，含多源切换与
    `origin_health` 记录），**不写缓存**；
- 删除"剩余兜底清单"里的 HEAD 死代码：`NativePlan::is_head`、`serve_head_cache` 的
  H1 特例、`response_filter` 的 CL=0 分支、`ctx.head_body` 与 `logging` 的 head 落盘。

明确的取舍：**不要把 HEAD 恢复成 GET 预热**。`handler.rs:1627-1633` 记录了原因——
超过 `MAX_CACHEABLE_BODY` 的对象会 502，并把 origin 记成失败。

验收：

- `head-h2.sh` 全绿，且 warm/cold 四条断言都带 `x-lagran-datapath: pingora`；
- 新增：同一 keepalive 连接连续两次 `curl -I`，验证不因 HEAD 挂住连接；
- 新增：16 MiB 的 `/huge` HEAD 不产生 `origin failed`。

### 阶段 3：确定性兜底改为直出（1-2 天）

- **节点禁用**：在 `request_filter` 中（preflight 之后、`native_plan` 之前）直接
  `default_page::node_disabled_page` + `log_access(503, "NODE_DISABLED")`，与
  `handler.rs:413-430` 完全对齐，不再进 legacy。
- **`parse_origin` 失败**：归为配置错误，直出 502 并记录 `unsupported_origin_url`；
  同时在控制面保存域名时校验 `origin_url`，让运行时不再出现该分支。
- **未知 host + 空注册表（single-origin 模式）**：唯一可能"真需要 legacy"的点，
  需产品决策：
  - (A) 保留能力：在 Pingora 里实现 `NativePlan::default_origin`（origin 取
    `state.origin.base_url()`，policy 用全局 `state.rules.resolve`，无 key-ignore 表）；
    工作量不小，因为要补齐全局规则与"无域名"语义；
  - (B) 明确废弃：只在 `ORIGIN_URL` + 无控制面的开发场景使用，加启动告警并在
    `docs/deployment.md` 标注 deprecated，允许这一条继续走 legacy。
  - 建议先用阶段 0 的 `reason=single_origin` 量化真实用量，再决定做 (A) 还是 (B)。

验收：`dead-origin.sh`、`smoke.sh` 全绿；新增断言"节点禁用响应带
`x-lagran-datapath: pingora`"（该页面经 `write_axum_response` 写出，天然带该头）。

### 阶段 4：重校验兜底在 Pingora 内闭环（2-3 天）

把"剩余兜底清单"第 3 类的 6 种情形从"删缓存 → 回落 legacy"改成"Pingora 内继续"：

| 情形 | 现在 | 目标 |
|---|---|---|
| `computed` validator | 删缓存 → legacy 全量回源 | 删缓存 → `PlanFallback::NativeMiss`，由 native_plan 生成可缓存计划走 native streaming |
| 无 etag / last-modified | 同上 | 同上 |
| 无 enabled origin | 回落 | 直出 502 origin 页面（复用 `fail_to_proxy` 的 `OriginFailure`） |
| origin 错误 / 超时 | 删缓存 → 回落 | 502，不删缓存 |
| origin 非 2xx 非 304 | 删缓存 → 回落 | 直接 native streaming 该响应 |
| 304 但 `decide_storage_reason` 失败 | 删缓存 → 回落 | 保留旧 entry 直接服务 |

关键重构：把"native plan 不可用"与"重校验未命中"拆成两个概念，新增
`enum PlanFallback { InProcess, NativeMiss, OriginError(OriginFailure) }`；
只有 `InProcess` 才进 legacy，其余都在 Pingora 内闭环。

验收：`cache-diagnostics.sh` 的 no-cache 段，加新增 4 条（computed etag、
无 validator、origin 500、origin 超时），全部断言 `x-lagran-datapath: pingora`。

### 阶段 5：缓存诊断改走真实路径（1 天）

`server/cache_diag.rs:115` 现在直接调 `proxy_handler`，也就是说控制台的
"缓存诊断"测的是 legacy 行为，不是生产 Pingora 行为。改为与 prefetch 相同：
向 `state.local_http_addr` 的 loopback 公共监听发 HTTP（`server/prefetch.rs:57`
已有先例），走真实 Pingora 路径。

这一改同时修掉一个既有失真，并解除删除 legacy 的最后一个代码依赖。

验收：`cache-diagnostics.sh` 的 diagnose 段全绿，并断言诊断返回的 headers 里可见
`x-lagran-datapath: pingora`。

### 阶段 6：删除 legacy 数据面（2-3 天）

前置门槛（必须同时满足）：

- `lagran_edge_datapath_legacy_total` 在一个发布周期内零增长
  （single-origin 若按 3(B) 保留，则只允许该 reason 增长）；
- `lagran_edge_legacy_fallback_total{reason}` 各 reason 归零；
- 全部集成脚本绿。

删除顺序（每步单独可回滚）：

1. handler 的 HEAD 回源/缓存分支（`fetch_head_origin` 已在阶段 2 搬走）；
2. `revalidate_cached_entry`（1864）、`spawn_revalidation`（2195）、`serve_cached`（2443）、
   `bypass_to_origin`（1069）、`bypass_to_origin_streaming`（1425）、
   `store_large_response`（2605）、`serve_range_entry`（2381）、`fetch_origin`（1729）、
   `fetch_with_single_flight`（1620）—— 先 grep 确认没有别的调用者；
3. `proxy_handler`（274）/`proxy_handler_inner`（300）与 legacy 专用类型
   （`Effective`、`OriginTarget`、`origin_sequence`），前提是多源/故障切换语义
   已被 Pingora 的 `chunk_origin_targets` 与 origin 序列完整覆盖；
4. 共享工具落位到 `server/state.rs` / `server/shared/`，删除 `server/handler.rs`；
5. handler 的 WebSocket 分支（599-640）与 `server/websocket.rs` 的隧道实现
   （保留 `is_websocket_upgrade`，pipeline 仍在用）；
6. `datapath_legacy` 指标保留一个版本（便于回滚观测），下个版本再删。

## 验收矩阵

| 脚本 | 覆盖 | 要求 |
|---|---|---|
| `head-h2.sh` | HEAD 的 H1/H2 Content-Length、cold HEAD、huge HEAD | 全绿 + 断言 `pingora` |
| `cache-diagnostics.sh` | GET / Range / no-cache / diagnose | 全绿 + diagnose 断言 `pingora` |
| `ws-echo.sh` | WebSocket 隧道 | 全绿（已是 native） |
| `waf.sh` / `cc.sh` / `cache-rules.sh` | preflight 策略 | 阶段 1 后必须全绿 |
| `p2-hardening.sh` | SSRF / 限流 / 日志摄入 | 全绿 |
| `smoke.sh` / `dead-origin.sh` / `multi-origin.sh` | 回源与故障切换 | 阶段 3/4 后全绿 |

指标断言（阶段 0 之后每个阶段都要复查）：

```promql
sum by (reason) (rate(lagran_edge_legacy_fallback_total[5m]))
sum(rate(lagran_edge_datapath_legacy_total[5m]))
```

理想终态：普通 GET / HEAD / Range / no-cache / WebSocket 的 legacy 计数为 0。

## 复核期间顺带修复与发现

迁移复核时为了跑通验收脚本，修掉了三处**与迁移无关的环境/脚本问题**，并发现一处
**真实的产品缺陷**（归入阶段 3/4，不作为阶段 0 的阻塞）。

### 顺带修复（测试脚本）

1. **shell 代理变量让 HTTPS 判定失真**：`http_proxy`/`https_proxy` 存在时 curl 走
   CONNECT 隧道，`--resolve` 被忽略，HTTPS 请求返回 `000` 并报
   `TLS connect error: unexpected eof`。脚本开头统一 `unset http_proxy …`。
   （`head-h2.sh`、`failover-https.sh`）
2. **默认 `EDGE_ADMIN_LISTEN=127.0.0.1:8082` 被占用**：edge 启动即
   `cannot bind … Address already in use (os error 98)` 退出，脚本后续全部超时。测试里
   显式置空（`EDGE_ADMIN_LISTEN=`），管理接口落到数据监听并要求 agent token。
3. **`failover-https.sh` 从未注册节点**：`/api/v1/config` 因缺 per-node token 被拒，
   注册表为空 → 走 single-origin → `ORIGIN_URL` 默认 `https://example.com` → 全站
   404（`reason="status"`）。补 `POST /api/v1/nodes` 取 per-node token、传入
   `AGENT_TOKEN`、并在 cleanup 里删节点行（残留的 online 行会让下次 purge 扇出失败）。

### 发现：kill 主源后不切备份（阶段 3/4 前置）

`failover-https.sh` 仍有 4 项失败，且是**同一根因**：

- legacy 侧：`origin_sequence`（`handler.rs:180-235`）先按健康过滤，再
  `retain(|o| o.priority == min_priority)`，备份是 `priority: 1`；而
  `is_origin_healthy` 在无记录时默认 `true`（`agent/origin_health.rs:63-73`），
  主源刚被 kill 时仍算健康 → **备份在发请求前就被剪掉**；
- native 侧：`record_origin_failure` 已经会在硬失败时立即置不健康
  （`pingora_edge.rs:1299-1312`），但若是 `ConnectRefused` 且首选地址不可达，
  一次请求内不会换地址/换层；
- 环境放大器：测试机 `localhost` 优先解析 `::1`，而 `tools/mock-origin` 只绑
  `127.0.0.1`，即使选中备份也会连不上；
- 连带失败：脚本末尾 `disabling HTTPS redirect takes effect` 依赖 `/page` 返回 200，
  主源被杀后未恢复 → 恒为 502。

结论：`failover-https.sh` 不在阶段 0 的验收矩阵内（矩阵里回源/故障切换由
`smoke.sh`/`dead-origin.sh`/`multi-origin.sh` 承担），因此**不阻塞阶段 0**；但上述
"一次请求内不降级到下一优先级层"是真实语义缺口，须在阶段 3/4 的
`dead-origin.sh`/`multi-origin.sh` 验收前修掉（修法：`origin_order` 返回按优先级
分层的有序列表，最低层全部失败即试下一层；native 路径可复用 `ctx.attempt`）。

## 工作量

| 阶段 | 内容 | 估时 |
|---|---|---|
| 0 | 兜底原因指标 | 1 天 |
| 1 | preflight 实现搬迁 | 1-2 天 |
| 2 | HEAD 原生化 | 3-5 天 |
| 3 | 确定性兜底直出 | 1-2 天 |
| 4 | 重校验兜底闭环 | 2-3 天 |
| 5 | 诊断改真实路径 | 1 天 |
| 6 | 删除 legacy | 2-3 天 |

单人约 2 周。若只推 0/1/2（HEAD 是 legacy 流量主体），约 5-8 天即可把
`datapath_legacy_total` 压到接近 0。

## 原则

- 一个请求只能经过一条缓存/超时/日志管线。
- 不允许 Pingora 和 legacy 各写一份缓存策略。
- 新增功能优先进入 `RequestPipeline`，而不是任一数据面。
- 兜底必须有因由：每条回落 legacy 的路径都要带 `reason` 计入
  `lagran_edge_legacy_fallback_total`，不允许"静默回落"。
- 死代码要么接回、要么删除；"等迁移时再说"的中间态不得超过一个阶段。
- 语义契约以集成脚本为准（HEAD 报真实长度、HEAD 不预热缓存、WS 走 native
  upgrade tunnel），迁移不得顺手改契约。
- 迁移每一步都要能单独回滚：legacy 在阶段 6 之前始终是可用兜底。
