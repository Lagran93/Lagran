# GeoDNS 接入示例（Phase 1）

`powerdns-pipe.sh` 是一个最小可用的 **PowerDNS pipe backend**：收到 DNS 查询后调用
控制面 `GET /api/v1/schedule`，把调度结果作为 A/AAAA 记录返回。

## PowerDNS 配置

```ini
launch=pipe
pipe-command=/opt/lagran/tools/dns/powerdns-pipe.sh
pipe-abi-version=1
pipe-timeout=2000
```

环境变量：

```bash
CONTROL_URL=https://console.example.com
AGENT_TOKEN=<控制面 AGENT_TOKEN>
```

`pipe-command` 继承 PowerDNS 进程环境，建议通过 systemd `Environment=` 注入。

## 工作方式

1. PowerDNS 把 `Q<TAB>qname<TAB>qclass<TAB>qtype<TAB>id<TAB>remote` 写到脚本 stdin
2. 脚本调用 `/api/v1/schedule?domain=<qname>&ip=<remote>`
3. 控制面用 GeoIP CIDR 表 + 节点省份/城市/运营商/权重/负载打分
4. 脚本输出 `DATA ... <ttl> <primary.public_ip>` 和 `END`

## 限制

- 最小示例，未做本地缓存；生产建议在 PowerDNS 前加缓存/recursor，或改用 CoreDNS 插件并缓存结果
- 依赖 `jq` 与 `curl`
- 只返回 `primary`；`backup` 可用于健康检查失败时的备用 A 记录
- 没有 ECS 时，`remote` 是递归解析器 IP，精度取决于本地 DNS
- 节点必须有 `public_ip` 且状态为 `online` 才会被调度

## GeoIP 数据

控制面默认读取 `GEOIP_JSON_PATH`（默认 `./data/geoip.json`）：

```json
[
  {"cidr":"203.0.113.0/24","country":"CN","province":"广东","city":"深圳","isp":"电信"},
  {"cidr":"198.51.100.0/24","country":"CN","province":"北京","city":"北京","isp":"电信"}
]
```

CIDR 表按最长前缀匹配；缺失时退化为按节点权重/负载调度。可以用 IPIP.net、MaxMind
等数据源离线生成该 JSON，避免在控制面引入 mmdb 依赖。
