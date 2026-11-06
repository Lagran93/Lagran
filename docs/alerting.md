# 稳定性告警建议

Edge 暴露 Prometheus 指标：

```text
/__lagran/metrics
```

## 核心规则

```yaml
groups:
  - name: lagran-edge-stability
    rules:
      - alert: LagranOriginTimeouts
        expr: sum(rate(lagran_edge_origin_timeouts_total[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: 回源超时持续出现
          description: 检查源站 RTT、origin_timeout_ms 与 ORIGIN_READ_TIMEOUT_MS。

      - alert: LagranOriginStreamErrors
        expr: sum(rate(lagran_edge_origin_stream_errors_total[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: 流式回源中断或 body 空闲超时
          description: 检查源站 chunk 间隔、ORIGIN_READ_TIMEOUT_MS 与网络质量。

      - alert: LagranLegacyDatapathLeak
        expr: sum(rate(lagran_edge_datapath_legacy_total[5m])) > 0.1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: 普通请求仍在落入 legacy 数据面
          description: 对照 x-lagran-datapath 与 legacy fallback WARN，确认是否 native plan 失败。

      - alert: LagranCacheHitRatioLow
        expr: |
          sum(rate(lagran_edge_cache_hits_total[5m]))
          /
          clamp_min(sum(rate(lagran_edge_requests_total[5m])), 1)
          < 0.5
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: 缓存命中率低于 50%
          description: 检查 TTL、Vary、no-cache 比例、purge 与多节点缓存分布。

      - alert: LagranOriginErrors
        expr: sum(rate(lagran_edge_origin_errors_total[5m])) > 0.5
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: 回源错误率升高
          description: 检查源站健康、DNS、TLS、502/504 与连接池。
```

## 访问日志补充

`lagran_edge_origin_timeouts_total` 只统计 Edge 侧超时；源站 5xx 仍应通过访问日志或 WAF/告警中心规则观察。

## 控制面告警

已有告警中心支持：

```text
origin_unhealthy
cert_expiring
node_offline
cache_hit_ratio
waf_spike
```

配置发布失败、节点离线、证书到期等继续使用控制面告警；上述 Prometheus 规则作为边缘侧补充。
