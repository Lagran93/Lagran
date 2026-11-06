# RequestPipeline 迁移

目标架构：

```text
Pingora
  TCP/TLS/HTTP2
  连接池
  streaming
  cache storage
  upstream

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
  管理接口
  WebSocket
  极少数动态代理
```

## 当前状态

已建立共享入口：

```rust
RequestPipeline::new(&state)
    .preflight(&domain, &facts)
    .await
```

Pingora native 与 legacy 数据面都通过同一入口执行：

- HTTPS redirect
- Bot challenge
- CC
- 限流
- WAF
- 防盗链

同时新增：

- `RequestClass`：`Cacheable` / `StrictRevalidation` / `Bypass` / `Websocket` / `Dynamic`
- 统一 policy 解析
- 统一 cache key 计算

## 迁移阶段

### 阶段 1：共享 preflight

已完成。两条路径不再各自调用 WAF/CC 实现，而是统一进入 `RequestPipeline::preflight`。

### 阶段 2：共享请求分类与缓存键

已完成。Pingora `native_plan` 和 legacy `proxy_handler` 现在都调用：

```rust
pipeline.classify_request(method, headers, policy)
pipeline.cache_key_for(...)
pipeline.cache_key_with_ignore_query(...)
```

统一覆盖：

- 方法判断
- Cookie / Authorization / no-cache bypass
- 规则 action
- ignore_query
- cache key
- WebSocket 判断

Range 仍由各数据面解析，因为小范围切片和流式 Range 使用不同存储路径。

### 阶段 3：条件请求统一

已完成 no-cache GET 的 Pingora 化：

- `try_normal_revalidation`：普通 SharedCache 对象条件 GET / 304 / origin-200
- `try_large_revalidation`：LargeCache HEAD / 304
- 304 只刷新缓存元数据，不重写 body
- origin-200 重新写入缓存并返回 REVALIDATED
- computed validator 不再用于上游条件请求

legacy `revalidate_cached_entry` 仍保留为 Plan 不可用时的兜底，但 no-cache GET 已优先在 Pingora 完成。

### 阶段 4：删除 legacy GET/HEAD 数据面

进行中。

已迁移：

- 可缓存 GET/HEAD：Pingora native
- no-cache / max-age=0 普通对象：Pingora 条件 GET
- no-cache LargeCache 对象：Pingora HEAD
- Cookie / Authorization / rule bypass GET：Pingora streaming

已完成：

- 小范围 Range 切片：完整 SharedCache 对象直接切 206；未命中时 Pingora 原生流式回源
- WebSocket：显式 legacy-only 路由
- `X-Lagran-Datapath`：响应标识 `pingora` / `legacy`，集成测试断言普通 GET、Range、no-cache 均走 Pingora
- Prometheus：`lagran_edge_datapath_pingora_total` / `lagran_edge_datapath_legacy_total`
- no-cache + LargeCache 关闭场景已由 Pingora 处理

尚未迁移：

- 管理接口（按设计保留）
- native plan 不可用时的兜底
- legacy 代码的最终删除

## 原则

- 一个请求只能经过一条缓存/超时/日志管线。
- 不允许 Pingora 和 legacy 各写一份缓存策略。
- 新增功能优先进入 `RequestPipeline`，而不是任一数据面。
