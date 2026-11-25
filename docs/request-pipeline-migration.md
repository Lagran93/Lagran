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
  目标：不承载数据面（阶段 6 删除）；阶段 3 后只剩「严格重校验」与「缓存诊断」两类兜底
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
| 3 | 严格重校验失败（6 种，见下） | `pingora_edge.rs:2110-2456` | 删缓存 → legacy 全量回源 | 阶段 4：Pingora 内闭环（已实现） |
| 4 | 未知 host 且注册表为空 | `pingora_edge.rs:786-799` | single-origin（`handler.rs:537-562`） | 阶段 3：改原生静态默认域名（已实现） |
| 5 | `parse_origin` 失败 | `pingora_edge.rs:2832` | 回落 legacy | 阶段 3：直出 502 + 配置校验 |
| 6 | 缓存诊断直调 legacy | `server/cache_diag.rs:115` | 诊断测的是 legacy 行为 | 阶段 5：改走 loopback 真实路径 |

### 第 3 类的 6 种情形

`try_normal_revalidation` 原返回 `Ok(false)` 的 6 个条件，阶段 4 已逐个收敛为
`RevalOutcome`（`NativeMiss` / `OriginError` / `Served`），不再回落 legacy：

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
  `other`（阶段 3 第 3 项后 `single_origin` 已删除，剩 6 个）。推导集中在 `plan_blocker`，
  `native_plan` 与 `legacy_reason` **共用同一份
  判断**，避免"指标里的原因"与"实际路由决策"漂移；
- 指标暴露 `legacy_fallbacks()` → `LegacyFallbackSnapshot`，Prometheus 文本由
  `prometheus_lines()` 统一生成，数据面 `pingora_edge.rs` 的 `/__lagran/metrics`
  与管理面 `server/listener.rs` 复用同一实现，不存在两套口径；
- 两个计数器口径不同，不要互相校验：`lagran_edge_datapath_legacy_total` 含缓存诊断的
  legacy 直调，`lagran_edge_legacy_fallback_total{reason}` 只统计 `handle_in_process`
  交接点（单测已锁定该差异）；
- 验收已落到 `tests/integration/cache-diagnostics.sh`：7 项 reason 计数断言（含
  `head`）、管理接口不计入 legacy、`delta` 辅助函数用于"前后增量"断言。

### 阶段 1：preflight 实现搬进 pipeline（1-2 天，纯机械）—— ✅ 已完成

改动：

- 把 `preflight_cacheable`（`handler.rs:2707-3122`）连同 `uuid_like_request_id`（3335）、
  `log_access`（3304）、`hotlink_allowed`（3270）、`policy_browser_ttl`（2511）、
  `apply_browser_ttl` / `apply_security_headers` / `apply_cors_and_custom`（2519/3343/3358）
  迁到 `server/pipeline/preflight.rs` 与 `server/shared/`；
- `RequestPipeline::preflight` 直接调用新实现，`handler.rs` 不再被 pipeline 反向依赖。

零行为变化：review 用 `git diff -M` 确认只有移动，没有逻辑改动。

验收：`cargo test -p edge`；`waf.sh`、`cc.sh`、`cache-rules.sh`、`p2-hardening.sh`、
`cache-diagnostics.sh` 全绿。这 415 行是所有安全策略的入口，**必须跑脚本，不能只看编译**。

落地说明（实际实现）：

- 仓库里 `server/pipeline.rs` 是单文件、也没有 `server/shared/` 目录，所以落位调整为：
  `apps/edge/src/server/preflight.rs`（`preflight_cacheable` + `url_query` + `cc_too_many` +
  `host_without_port` + `https_redirect_response`）与 `apps/edge/src/server/shared.rs`
  （`log_access`、`uuid_like_request_id`、`policy_browser_ttl`、`apply_browser_ttl`、
  `apply_security_headers`、`apply_cors_and_custom`、`hotlink_allowed` 及其
  `referer_host`/`host_matches`、`challenge_accepts_html`），并连带动了 8 个 hotlink 单测；
- `pipeline.rs` 现在 `use crate::server::preflight::preflight_cacheable;`，不再从
  `server::handler` 取 preflight；`pingora_edge.rs` 改为 `use crate::server::shared::{…}`；
- 搬迁用脚本按行区间**原样抽取、原样删除**（`git diff` 中 `handler.rs` 只有删除 + 导入行，
  795 行删除 / 7 行新增），并用逐字比对脚本确认三个代码块与 HEAD 完全一致；
- 剩余耦合：`AppState` 仍定义在 `server::handler`，`preflight.rs`/`pipeline.rs` 仍从那里
  `use` 它。彻底解耦（把 `AppState` 移到 `server/state.rs`）放到阶段 6 的共享工具落位，
  否则本阶段会变成跨十几个文件的类型搬迁，失去"可单独回滚"的性质。

### 阶段 2：HEAD 原生化（3-5 天）—— ✅ 已完成

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

落地说明（实际实现）：

- 真正的闸门是阶段 0 加进 `plan_blocker` 的 HEAD 分支（`LegacyFallback::Head`）；
  `native_plan` 本身早就可以产出 `is_head` 计划。删掉该分支后，HEAD 在 `request_filter`
  内自应答（缓存命中 → `serve_head_cache`），未命中则以 HEAD 转发上游，不再进 legacy；
- `serve_head_cache` 的 `is_h2 ? len : 0` 改为**始终** `entry.body.len()`，H1 也报真实
  表示长度；并补上 `x-lagran-datapath: pingora`（它是唯一漏加该头的原生响应路径，其余
  路径在 `upstream_response_filter` / `write_axum_response` 里加）；
- 删掉 HEAD 死代码：`response_filter` 的 `content-length: 0` 覆盖与 `head_headers` /
  `head_status` 暂存、`body_filter` 的 `ctx.head_body` 累积、`logging` 的 HEAD 落盘
  （原先会拿 HEAD 正文回填缓存，违背"不预热"原则），以及 `ReqCtx` 的三个字段。
  `NativePlan::is_head` 由死代码转为**活跃**代码，保留；
- `head_content_length_for_protocol` 未改动：它早已对 H1/H2 都返回真实长度；
- `cache-diagnostics.sh` 的 HEAD 断言从「计 1 次 legacy」翻转为「`head` 增量 0 且响应带
  `pingora`」。

### 阶段 3：确定性兜底改为直出（1-2 天）—— ✅ 全部完成

- **节点禁用**：在 `request_filter` 中（preflight 之后、`native_plan` 之前）直接
  `default_page::node_disabled_page` + `log_access(503, "NODE_DISABLED")`，与
  `handler.rs:413-430` 完全对齐，不再进 legacy。
- **`parse_origin` 失败**：归为配置错误，直出 502 并记录 `unsupported_origin_url`；
  同时在控制面保存域名时校验 `origin_url`，让运行时不再出现该分支。
- **未知 host + 空注册表（single-origin 模式）**：已改为原生（选项 A）。启动时把
  `ORIGIN_URL` 装成注册表的**静态默认条目**，注册表为空时任意 Host 都解析到它、走
  Pingora 计划；一旦控制面同步到真实域名，该条目被整体覆盖遮蔽，已纳管的边缘对未知
  Host 仍返回 404。之所以能直接选 A：生产部署 `CONTROL_URL` 为必需（`docs/deployment.md`），
  注册表必然非空，该路径生产不可达；实测也确认 `reason=single_origin` 只在「无控制面」
  的裸启动下增长（3 次请求 → 3），而所有集成脚本都注册节点、该计数恒为 0。
  legacy 的单源分支（`LegacyFallback::SingleOrigin` 及其指标变体）随之删除。

验收：`dead-origin.sh`、`smoke.sh`、`single-origin.sh` 全绿；新增断言"节点禁用响应带
`x-lagran-datapath: pingora`"（该页面经 `write_axum_response` 写出，天然带该头）。

落地说明（第 1 项，已实现）：

- 直出点在 `request_filter` 里 preflight 之后、`try_large_revalidation`/`native_plan` 之前：
  `!node_control.is_serving()` → `ctx.cache_label = "NODE_DISABLED"`、
  `ctx.status = 503`，用 `write_axum_response(…, node_disabled_page, is_head, …)` 写出，
  因此天然带 `x-lagran-datapath: pingora`，访问日志记为 `NODE_DISABLED`；
- `plan_blocker` 删掉了 `LegacyFallback::NodeDisabled` 分支，禁用节点不再计入 legacy
  （`cache-diagnostics.sh` 的 `node_disabled` 计数保持为 0）；
- 顺带修掉一个**阻塞该验收的产品缺陷**：`repository::node_name_for_token` 原来带
  `AND status <> 'disabled'`，节点被禁用后它的令牌立刻解析失败 → 所有 agent 接口 401，
  edge 既收不到 `enabled:false`（于是继续放行，禁用无效），也看不到后续的重新启用。
  现在禁用节点仍可认证，是否放行完全由数据面的 `NodeControl::is_serving` 决定；
- `nodes.sh` 新增/对齐的断言：`disabled node returns 503`、页面文案、**`disabled page is
  served by Pingora`**、`heartbeat keeps disabled status`、重新启用后恢复 200；同时把
  `commands.binary`/`commands.docker` 的四条断言对齐到加固后的写法（值经 shell 引号包裹、
  `EDGE_ADMIN_LISTEN` 由 `AGENT_URL` 推导、docker 只 publish 80 端口而在容器内
  `EDGE_ADMIN_LISTEN=127.0.0.1:8081`）。

落地说明（第 2 项，已实现）：

- `request_filter` 在节点禁用检查之后、`try_large_revalidation`/`native_plan` 之前判断
  `parse_origin(&domain.origin_url).is_none()`：直出 **502**，页面
  `default_page::config_error_page`，`ctx.cache_label = "CONFIG_ERROR"`，响应带
  `x-lagran-datapath: pingora` 与 `x-lagran-error: UNSUPPORTED_ORIGIN_URL`；
- 新增全局计数 `lagran_edge_config_errors_total`（`EdgeMetrics::record_config_error` /
  `config_errors()`，两个数据面的 metrics 端点都输出同一行），它非 0 即说明控制面放进来了
  一份边缘无法解析的回源配置；
- `legacy_reason` 删掉了 `ParseOrigin` 回落：既然 `request_filter` 已经先拦下，这个标签
  只会让指标与真实路由不一致（`LegacyFallback::ParseOrigin` 变体保留，历史看板不受影响）；
- 设计风险的消解：`config_sync` 的 `origin_url` 来自**已按优先级/权重排序**的源站池
  （优先取 enabled 的第一项，否则取第一项，池为空才回退到单源字段），所以 `origin_url`
  解析失败等价于整个源站池不可用，直接在它上面判断不会误伤合法的多源域名；
- 控制面同步补齐：`domain::create`/`domain::update` 增加 `validate_primary_origin`，对
  仅用旧式 `origin_host`/`origin_port`/`origin_proto` 提交的场景校验（这些字段原本绕过了
  `normalize_origins`，`origin_proto: "ftp"` 之类会被原样落库）；显式源站池仍走
  `normalize_origins`，备份源站仍走 `normalize_backup`。

落地说明（第 3 项 / 剩余项 2，已实现，采用选项 A）：

- 注册表新增 `static_default` 槽位（`config/registry.rs`）与 `set_static_default`；
  `main.rs` 启动时用 `ORIGIN_URL` 构造一条 `version="static"` 的 `DomainEntry`（含同 URL 的
  单条 `OriginTarget`）装入。它与真实条目**分开存放**，所以控制面首次 `replace_all` 会整体
  接管、无需清理；`lookup` 仅在 `inner` 为空时才回退到它——已纳管边缘对未知 Host 仍返回
  404（`cache-diagnostics.sh` 的 `unknown_domain` 语义不变）。
- `request_filter` 删除了 `handle_in_process(…, LegacyFallback::SingleOrigin)` 交接；该
  `else` 分支如今只对应空 Host，改为直出 404（`skip_logging`，与旧行为一致），不再进 legacy。
- `LegacyFallback::SingleOrigin` 变体、计数器与快照字段一并删除，Prometheus 的
  `lagran_edge_legacy_fallback_total` 由 7 个 reason 收敛为 **6** 个；
  `cache-diagnostics.sh` 的断言同步改为 6，并把「未触碰 reason 为 0」的探针换到 `parse_origin`。
- 新增 `tests/integration/single-origin.sh`：不启控制面（`CONTROL_URL` 指关闭端口，避免被
  其它套件残留的控制面污染），断言任意两个不同 Host 都 200、`x-lagran-datapath: pingora`、
  MISS→HIT、以及六个 reason 计数之和为 0。
- 单元测试 `registry::tests::static_default_serves_any_host_until_real_config_arrives`
  锁定「真实配置到达前服务任意 Host、到达后遮蔽」的切换语义。

### 阶段 4：重校验兜底在 Pingora 内闭环（2-3 天）—— ✅ 已完成

把"剩余兜底清单"第 3 类的 6 种情形从"删缓存 → 回落 legacy"改成"Pingora 内继续"：

| 情形 | 以前 | 现在（已实现） |
|---|---|---|
| `computed` validator | 删缓存 → legacy 全量回源 | 删缓存 → `RevalOutcome::NativeMiss` → 原生 MISS 流式回源并回填 |
| 无 etag / last-modified | 同上 | 同上 |
| 无 enabled origin | 回落 | 直出 502 origin 页面（`OriginFailure::Unreachable`） |
| origin 错误 / 超时 | 删缓存 → 回落 | 502 / 504 origin 页面，**不删缓存** |
| origin 非 2xx 非 304 | 删缓存 → 回落 | 删旧 entry → `NativeMiss`，由原生路径流式返回该响应 |
| 304 但 `decide_storage_reason` 失败 | 删缓存 → 回落 | 保留旧 entry，直接 `REVALIDATED` 服务 |

实现时用 `enum RevalOutcome { NotApplicable, Served, NativeMiss, OriginError(OriginFailure) }`
（比草案的 `PlanFallback` 多一个 `NotApplicable`，表示"不是严格重校验，按原路继续"）。
`try_large_revalidation` / `revalidate_strict` / `try_normal_revalidation` 都改成返回它；
`request_filter` 收到 `NativeMiss` 后重建一个"忽略严格重校验"的 plan
（`native_plan(..., ignore_strict_revalidation=true)`，此时 `request_reason` 归零、按普通
可缓存 GET 处理），`OriginError` 则直出 `default_page::origin_error_page`。`plan_blocker`
也带上了该开关，只有 `ignore=false` 且请求带 `no-cache`/`max-age=0` 时才标 `StrictRevalidation`。

验收：新增 `tests/integration/strict-revalidation.sh`（详见下方落地说明），断言
computed validator、origin 500、origin 超时三种情形均由 `x-lagran-datapath: pingora` 服务，
且 `lagran_edge_legacy_fallback_total{reason="strict_revalidation"}` 不增长。
（原计划的 4 条改为独立脚本：`cache-diagnostics.sh` 已在跑大量 revalidation 断言，
再往里塞会互相干扰；`/assets/no-validator.css` 已由 `cache-rules.sh` 覆盖 computed 分支。）

落地说明（阶段 4，已实现）：

- `apps/edge/src/pingora_edge.rs`：
  - 新增 `RevalOutcome`；`try_large_revalidation`/`revalidate_strict`/`try_normal_revalidation`
    返回它，`request_filter` 在 `native_plan` 之前 `match` 处理 `Served`/`NativeMiss`/`OriginError`；
  - `native_plan` 增加 `ignore_strict_revalidation` 参数；为 true 时跳过 `plan_blocker` 的严格
    重校验拦截、把 `request_reason` 置 `None`，于是重建出可缓存 plan；
  - `try_normal_revalidation` 的 6 个 `Ok(false)` 出口逐一映射：computed/无 validator → 删缓存 +
    `NativeMiss`；无 origin → `OriginError(Unreachable)`；origin `Ok(Err)` → `OriginError(Unreachable)`、
    `Err`(超时) → `OriginError(Timeout)`，两者都**不删缓存**；非 2xx → 删缓存 + `NativeMiss`；
    304 但 `decide_storage_reason` 失败 → 服务旧 entry（`origin-304-stale`）；
  - 大对象（LargeCache）分支同样改为 `NativeMiss` / `OriginError` / `Served`，其中 304 但无法
    重存时直接服务既有完整对象（`origin-304-stale`）；
  - `record_pingora_datapath()` 只在真正由 Pingora 写出响应（`Served`/`OriginError`）时计一次，
    避免与 `request_filter` 重复计数。
- `tools/mock-origin/origin.rs`：新增两个有状态 fixture —— `/flaky`（首次 200 带 ETag，
  之后 500）与 `/slow-flaky`（首次 200 带 ETag，之后 sleep 3s），用于稳定复现
  "条件请求返回非 2xx / 超时"两条路径。
- `tests/integration/strict-revalidation.sh`：独立起控制面 + 边缘，`ORIGIN_READ_TIMEOUT_MS=1500`
  让超时用例快速失败；断言三种情形与 `strict_revalidation` 计数不变。

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
  （阶段 3 后 single-origin 已改原生，不再有该 reason 的增长空间）；
- `lagran_edge_legacy_fallback_total{reason}` 各 reason 归零；
- 全部集成脚本绿。

删除顺序（每步单独可回滚）：

1. handler 的 HEAD 回源/缓存分支（`fetch_head_origin` 已在阶段 2 搬走），以及
   `proxy_handler_inner` 里 `domain_entry == None` 的「单源」分支（阶段 3 后注册表总有
   静态默认条目，该分支只剩空 Host 才可能进入，而 Pingora 已先返回 400）；
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
| `head-h2.sh` | HEAD 的 H1/H2 Content-Length、cold HEAD、huge HEAD | ✅ 全绿 + 断言 `pingora` |
| `cache-diagnostics.sh` | GET / Range / no-cache / diagnose | ✅ 全绿 + diagnose 断言 `pingora` |
| `ws-echo.sh` | WebSocket 隧道 | 全绿（已是 native） |
| `waf.sh` / `cc.sh` / `cache-rules.sh` | preflight 策略 | ✅ 全绿（阶段 1） |
| `p2-hardening.sh` | SSRF / 限流 / 日志摄入 | 全绿 |
| `smoke.sh` / `dead-origin.sh` / `multi-origin.sh` | 回源与故障切换 | 阶段 3/4 后全绿 |
| `single-origin.sh` | 无控制面时任意 Host 走原生单源 | ✅ 全绿 + 断言 `pingora` + 6 个 reason |
| `strict-revalidation.sh` | no-cache 重校验的 computed / origin 500 / 超时 | ✅ 全绿 + 断言 `pingora` + `strict_revalidation` 不增长 |

指标断言（阶段 0 之后每个阶段都要复查）：

```promql
sum by (reason) (rate(lagran_edge_legacy_fallback_total[5m]))
sum(rate(lagran_edge_datapath_legacy_total[5m]))
```

理想终态：普通 GET / HEAD / Range / no-cache / WebSocket 的 legacy 计数为 0。

## 复核期间顺带修复与发现

迁移复核时为了跑通验收脚本，修掉了一批**与迁移逻辑无关的环境/脚本问题**，并发现两处
**真实的产品缺陷**（一处已在阶段 1 内修掉，另一处归入阶段 3/4）。

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
4. **同一主机上的第二个 edge 也会撞 8082**：`cc.sh` 的跨节点用例起第二个 edge 时没有置空
   `EDGE_ADMIN_LISTEN`，第一个 edge 已占 `127.0.0.1:8082`，第二个进程启动即
   `Error: cannot bind EDGE_ADMIN_LISTEN … (os error 98)` 退出；随后 `get2` 全得到 502，
   "second edge receives shared ban" 与 header 断言双双失败，`bans/all` 也因 60 秒 TTL
   过期读出 `null`。修法：两个 edge 都显式 `EDGE_ADMIN_LISTEN=`，并把
   `cc_ban_seconds` 从 60 提到 300（否则最长 60 秒的跨节点等待会跑赢 TTL）。
5. **curl `-X HEAD` 会等 body**：`cache-rules.sh` 用 `-X HEAD` 发 HEAD，curl 不会进入
   "HEAD 无 body"模式，于是等待 `Content-Length` 声明的字节（HEAD 报真实长度是本项目的
   既定契约），直接挂死。改用 `-I`（3 处）。
6. **请求一律带 `--max-time`**：`waf.sh` / `cc.sh` / `cache-rules.sh` 此前都有不带超时的
   curl，一个停滞响应就把整个脚本挂死（最长 20 分钟）。现在统一 `--max-time 20`，停滞会
   变成 `000` 快速失败，而不是静默卡住。
7. **HEAD / `Vary: Cookie` 的断言与契约对齐**：`cache-rules.sh` 曾断言"第二次 HEAD 命中
   缓存"与"`ignore_cookie` 规则让 `Vary: Cookie` 命中"。实际契约是 HEAD 只返回元数据、
   **不填充缓存**；且 `cache/policy.rs::vary_cookie_is_rejected` 明确"key 不含 Cookie，
   即使 `ignore_cookie` 也不得存储"。断言改为 `MISS`，并纠正 `tools/mock-origin` 中
   与实现矛盾的注释。
8. **中断的压测会毒化预取队列**：某次 p2 压测被 `kill` 后留下 62 条
   `prefetch_tasks(status='pending')`（`p2-sec05-admin-*` 域名）与 4 条
   `prefetch_schedules(enabled=true)`。worker 每 15 秒只领 20 条且按 `created_at` 排序，
   新任务被陈旧任务饿死在脚本轮询窗口之外 → `cache-diagnostics.sh` 的
   `control worker completes task` / `prefetched path is HIT` 等 5 项失败。清理：
   ```sql
   UPDATE prefetch_tasks SET status='failed', finished_at=now(),
     message='stale backlog cleanup (dead test domain)'
   WHERE status='pending' AND domain LIKE 'p2-%';
   DELETE FROM prefetch_schedules WHERE domain LIKE 'p2-%';
   ```
9. **控制面 worker 日志默认不可见**：`.env` 的
   `RUST_LOG=lagran_control=info,lagran_edge=info,edge::…=debug,…` 不含 `control::*`，
   所以 `prefetch worker started`、`prefetch worker failed` 都不会出现，容易误判"worker
   没启动"。排障需显式 `RUST_LOG=control=debug,…`（实测该配置下可见
   `prefetch worker started interval=15s` 与 `claim … rows_returned=20`）。
10. **`p2-hardening.sh` 会毒化后续预取队列**：它的 SEC-NEW-05 用例排队 120 条预热路径并
    创建一条 60 分钟的周期任务，脚本结束即 kill 控制面，于是留下 121 条 `pending` 与一条
    `enabled` 调度。修法（已落地）：脚本退出前删除自己创建的调度
    （`DELETE /api/v1/prefetch/schedules/:id`）、并把队列排空后再退出；产品侧同时新增
    `repository::expire_unclaimed_prefetch_tasks`，把 5 分钟仍未被领取的 `pending` 标记
    为 `failed`（`reclaim_stale_prefetch_tasks` 只管 `running`，未领取的行此前永不过期）。
11. **`.env` 里重复的 `AGENT_TOKEN` 让节点令牌一律 401**：本地 `.env` 同时存在
    `AGENT_TOKEN=<全局令牌>`（靠前）与一条空的 `AGENT_TOKEN=`（靠后），dotenvy 加载后
    后者生效 → edge 不带 `x-lagran-agent-token` → 心跳与配置同步全部 401 → 节点永远
    学不到禁用状态（表现为"节点禁用不生效"）。已把空赋值注释掉；`edge.env.example` 也
    已明确"AGENT_TOKEN 必须是预注册节点的 auth_token"。
12. **curl `-X HEAD` 会等响应体**：`cache-rules.sh`、`smoke.sh` 里用 `-X HEAD` 发 HEAD，
    curl 不进入"HEAD 无 body"模式，于是等 `Content-Length` 声明的字节（HEAD 报真实长度
    是本项目的既定契约），直接挂死。全部改为 `-I`。
13. **Pingora 输出标题大小写的响应头**：`X-Cache: HIT`、`X-Lagran-Datapath: pingora`
    等与 hyper/legacy 的小写形式不同，`smoke.sh` 原来 19 条大小写敏感的 `contains`
    因此全部失败。新增 `contains_h`（两边都转小写）后统一处理。
14. **`smoke.sh` 的源站故障状态断言过窄**：只接受 502/503，而 Pingora 会按
    `default_page::OriginFailure` 给出 `Unreachable→502`、`Unhealthy→503`、
    `Timeout→504`（该表由 `default_page` 单测锁定）。现改为接受三种 5xx，并由
    `x-lagran-error: ORIGIN_*` 断言锁定具体类别。
15. **残留 `online` 节点会让 purge 扇出失败**：`purge` 的聚合是
    `success: !results.iter().any(|r| !r.success)`，而数据库里会留下历次测试的
    `online` 行（agent_url 指向已关闭的测试端口），任意一个失败就把整体翻成
    `success:false`（`cache-diagnostics.sh` 的 `tag purge succeeds` 因此失败）。
    处理：跑套件前把残留行置为 `offline`（`UPDATE edge_nodes SET status='offline'
    WHERE status='online'`），或清理这些节点。
16. **`no-cache-preflight.sh` 的大小写敏感断言与缺失超时**：它在 warm/HIT 处用大小写敏感的
    `contains … "x-cache: HIT"`，而 Pingora 输出 `X-Cache`（第 13 条），会永远失败；同时
    `request()` 与并发段的两处 curl 没有 `--max-time`，而 WAF 拦截页既无 `Content-Length`
    也无 `Transfer-Encoding`、却保持 keep-alive，curl 会一直等待——整份脚本因此挂死。
    修法：改用 `contains_h`，并给两处 curl 加 `--max-time 20`。（阶段 4 复核时发现，
    与重校验逻辑无关。）

### 发现：`write_axum_response` 的流式分支不定界（阶段 1 内已修）

`write_axum_response` 对"非 HEAD / 非 304-204 / 未压缩 / body 非空 / 非 HTTP-1.0"的响应走
`write_engine_response_streamed`，而该函数用 `ResponseHeader::build(status, None)` 构造响应
头 —— 既没有 `Content-Length` 也没有 `Transfer-Encoding`，只能靠**关闭连接**定界。落在
keep-alive 连接上时，客户端会一直等一个永远不来的 EOF：`waf.sh` 的 403 拦截页与 `cc.sh`
的 429 页都曾因此挂死（表现为脚本"卡住不动"，抓包显示 body 停在 4096 字节）。

修复：把 `body.size_hint().exact()` 作为 `exact_len` 传给
`write_engine_response_streamed`，让 `ResponseHeader::build` 带上真实 `Content-Length`
（内存 body 的 hint 是精确值）；同时在写入字节数与声明长度不一致时 `warn!`，避免把
错误的长度静默写给客户端。未知长度的流式响应行为不变（仍由关闭连接定界）。

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
