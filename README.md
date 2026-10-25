# Lagran CDN

高性能、可自托管的 CDN 系统。

- **控制端（Control Plane）**：Rust + Axum
- **边缘端（Edge Plane）**：Rust 反向代理 + 内存缓存
- **前端**：Nuxt 4 管理后台

## 当前已实现（骨架）

### 控制端 (`apps/control`)
- `GET /health` / `GET /ready` 健康检查
- `POST /api/v1/auth/login` 登录（stub）
- `GET /api/v1/auth/me`
- `GET|POST /api/v1/domains` 域名列表/创建（stub）
- `GET|DELETE /api/v1/domains/{id}`
- `GET /api/v1/nodes` 节点列表
- `POST /api/v1/nodes/{id}/heartbeat`
- `POST /api/v1/purge`
- `GET /api/v1/stats/summary`
- `GET /api/v1/config/{domain}` 下发给边缘的配置

### 边缘端 (`apps/edge`)
- 内存缓存（DashMap + TTL）
- 反向代理到源站（HTTP）
- `GET /__lagran/health`
- 响应头 `X-Cache: HIT|MISS`

### 前端 (`apps/frontend`)
- 侧边栏布局 + 仪表盘 / 项目 / 域名 / 规则 / 节点 / 统计 / 设置 / 登录页

## 快速启动

```bash
# 控制端（默认 0.0.0.0:8080）
cargo run -p control

# 边缘端（默认 0.0.0.0:8081，源站 ORIGIN_URL）
ORIGIN_URL=http://example.com cargo run -p edge

# 前端
cd apps/frontend && npm install && npm run dev
```

### 验证控制端

```bash
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/api/v1/domains
curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"demo@lagran.dev","password":"demo"}'
```

### 验证边缘端

```bash
curl -i http://127.0.0.1:8081/__lagran/health
curl -i http://127.0.0.1:8081/          # 第一次 MISS
curl -i http://127.0.0.1:8081/          # 第二次应 HIT（若源站可访问）
```

## 环境变量

| 变量 | 默认 | 说明 |
|------|------|------|
| CONTROL_HOST | 0.0.0.0 | 控制端监听地址 |
| CONTROL_PORT | 8080 | 控制端端口 |
| EDGE_LISTEN | 0.0.0.0:8081 | 边缘监听 |
| ORIGIN_URL | http://example.com | 回源地址（当前骨架仅支持 HTTP） |
| CACHE_TTL | 60 | 默认缓存秒数 |
| CACHE_CAPACITY | 10000 | 内存缓存条目上限 |

## License

MIT


## 认证与数据库

控制端启动时会自动：

1. 连接 `DATABASE_URL`（默认 `postgres://lagran:lagran@127.0.0.1:5432/lagran`）
2. 执行 migrations
3. 写入演示账号 **demo@lagran.dev / demo123**

前端登录后将 JWT 存入 localStorage，请求自动带 `Authorization: Bearer <token>`。

边缘端默认回源 `https://example.com`，可通过 `ORIGIN_URL` 覆盖（支持 http/https）。
目前最基本的功能已经实现，请继续加强丰富其他功能。