/**
 * Deterministic Edge node sizing for the onboarding wizard.
 *
 * The wizard asks what hardware the node will run on and derives an `edge.env`
 * from the answer. Keeping the formula in one pure module makes the numbers
 * reviewable and testable, and every value written here is clamped to the range
 * `apps/edge/src/config/mod.rs` accepts, so a generated file is never silently
 * re-clamped (or rejected) by the edge process.
 *
 * The generator is also kept honest by the control plane:
 *  - `CONTROL_URL` comes from the node API (`control_url`), which is resolved
 *    server-side from `CONTROL_PUBLIC_URL` / the request Host header. The
 *    browser origin is only a fallback, because the console and the control
 *    API may live on different origins.
 *  - `AGENT_URL` is derived from `EDGE_ADMIN_LISTEN` instead of being typed
 *    independently: the edge parses the admin listener as a `SocketAddr`, and
 *    a callback URL that disagrees with it makes purge/cert/ACME fail while
 *    heartbeats still look healthy.
 *
 * Nothing here talks to the network: the page only renders the result.
 */

export type EdgeDiskType = 'hdd' | 'sata-ssd' | 'nvme'
export type EdgeWorkload = 'web' | 'video' | 'mixed'
/** Ordinary edge, or a dedicated Origin Shield aggregation node. */
export type EdgeNodeRole = 'edge' | 'shield'
/** Where the control plane sits relative to this node. */
export type EdgeDeploymentMode = 'same-host' | 'remote' | 'custom'

export interface EdgeHardware {
  /** vCPU cores available to the edge process. */
  cpuCores: number
  /** Total RAM in GiB. */
  memoryGb: number
  /** Disk capacity reserved for cache in GiB (0 = unknown / no disk). */
  diskGb: number
  diskType: EdgeDiskType
  /** Uplink bandwidth in Mbps (0 = unknown). */
  bandwidthMbps: number
  workload: EdgeWorkload
  /**
   * True when the node talks to a shared Redis, so the wizard also emits the
   * Redis timeout tuning (`CACHE_FLIGHT_TIMEOUT_MS` / `CC_REDIS_TIMEOUT_MS`).
   *
   * This is *not* what enables cross-node sharing: the edge enables CC counters
   * and the distributed rate limiter whenever `REDIS_URL` is set, and the flight
   * lock / L2 cache whenever `CACHE_BACKEND=redis` plus an endpoint is set. Any
   * Redis in the region works — it does not have to be the control plane's.
   */
  sharedRedis: boolean
  /**
   * `shield` makes the node ignore the domain-level `shield_url`. That is the
   * documented requirement for a dedicated Origin Shield; without it the shield
   * can send cache misses back to itself and form an origin loop.
   */
  role: EdgeNodeRole
}

/** Operator overrides for the knobs that are worth hand-tuning. */
export interface EdgeSizingOverrides {
  workerThreads?: number
  memoryCacheMiB?: number
  largeCacheGiB?: number
  /**
   * Raw values the operator edited directly in the capacity table, keyed by
   * env variable name. Only keys with an entry in [`ITEM_EDIT_RULES`] (plus the
   * special `LARGE_CACHE_ENABLED` toggle) are accepted.
   */
  itemValues?: Record<string, string>
  /** Pin `CACHE_BACKEND`; `auto` keeps the hardware-derived value. */
  cacheBackend?: EdgeCacheBackend
  /**
   * False when neither `REDIS_URL` nor `CACHE_REDIS_URL` is configured.
   * `CACHE_BACKEND=redis` is then downgraded instead of emitting a backend the
   * edge can only fall back from with a warning.
   */
  redisConfigured?: boolean
}

export type SizingGroup = 'runtime' | 'memory-cache' | 'large-cache' | 'origin' | 'logging'

/** Display titles shared by the wizard table and the env renderer. */
export const SIZING_GROUP_LABEL: Record<SizingGroup, string> = {
  runtime: '进程与连接',
  'memory-cache': '内存与普通缓存',
  'large-cache': '大对象缓存',
  origin: '回源',
  logging: '日志',
}

/**
 * `CACHE_BACKEND` as accepted by `apps/edge/src/cache/mod.rs`.
 *
 * `auto` never reaches the edge: it tells the wizard to derive `memory` or
 * `hybrid` from the hardware profile. `l2` is an alias of `redis` in the edge,
 * so the console only offers one Redis option.
 */
export type EdgeCacheBackend = 'auto' | 'memory' | 'disk' | 'hybrid' | 'redis'

export const CACHE_BACKEND_LABEL: Record<EdgeCacheBackend, string> = {
  auto: '按硬件自动（推荐）',
  memory: '仅内存 memory',
  disk: '仅磁盘 disk',
  hybrid: '内存 + 磁盘 hybrid',
  redis: '内存 + Redis L2 redis',
}

const CACHE_BACKENDS = ['auto', 'memory', 'disk', 'hybrid', 'redis'] as const

export interface EdgeSizingItem {
  key: string
  value: string
  group: SizingGroup
  /** Why this value was chosen, shown next to the field. */
  reason: string
  /** Set when the operator typed the value instead of the default formula. */
  overridden?: boolean
}

export interface EdgeSizingPlan {
  items: EdgeSizingItem[]
  warnings: string[]
  metrics: {
    workerThreads: number
    memoryCacheBytes: number
    cacheCapacity: number
    /** Effective backend after validation/downgrades (never `auto`). */
    cacheBackend: string
    /** Backend the operator asked for, including `auto`. */
    requestedCacheBackend: EdgeCacheBackend
    /** True when an explicit `redis` / disk backend had to be downgraded. */
    backendDowngraded: boolean
    diskCacheBytes: number
    largeCacheEnabled: boolean
    largeCacheBytes: number
    chunkBytes: number
    maxCacheableBody: number
  }
}

const KiB = 1024
const MiB = 1024 * KiB
const GiB = 1024 * MiB

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min
  return Math.min(Math.max(Math.round(value), min), max)
}

/** Human-readable size (binary units) for the explanation strings. */
export function humanBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value >= 100 || unit === 0 ? Math.round(value) : Number(value.toFixed(1))} ${units[unit]}`
}

/**
 * Accepted ranges, copied from the clamps in `apps/edge/src/config/mod.rs`.
 * Keep these in sync if the edge starts accepting wider values.
 */
export const EDGE_LIMITS = {
  workerThreads: [1, 256] as const,
  cacheMaxBytes: [16 * MiB, 8 * GiB] as const,
  maxCacheableBody: [64 * KiB, 64 * MiB] as const,
  largeCacheMinObject: [1 * MiB, 1 * GiB] as const,
  largeCacheMaxObject: [1 * MiB, 4 * GiB] as const,
  largeCacheChunk: [64 * KiB, 64 * MiB] as const,
  largeCacheFillQueue: [1 * MiB, 1 * GiB] as const,
  largeCacheFillQueueTotal: [1 * MiB, 4 * GiB] as const,
  largeCacheMinFree: [0, 1024 * GiB] as const,
  rangeFillMax: [0, 1 * GiB] as const,
  accessLogBuffer: [100, 50_000] as const,
  compressionLevel: [1, 9] as const,
  originConnectTimeout: [500, 60_000] as const,
  originReadTimeout: [1_000, 600_000] as const,
  originStreamReadTimeout: [5_000, 1_800_000] as const,
  cacheFlightTimeout: [50, 5_000] as const,
  ccRedisTimeout: [5, 2_000] as const,
  configSyncInterval: [5, 300] as const,
}

export const DISK_TYPE_LABEL: Record<EdgeDiskType, string> = {
  hdd: '机械盘 HDD',
  'sata-ssd': 'SATA SSD',
  nvme: 'NVMe SSD',
}

export const WORKLOAD_LABEL: Record<EdgeWorkload, string> = {
  web: '网页 / 小文件',
  video: '视频 / 大文件点播',
  mixed: '混合业务',
}

export const NODE_ROLE_LABEL: Record<EdgeNodeRole, string> = {
  edge: '普通边缘节点',
  shield: 'Origin Shield',
}

export const NODE_ROLE_DESC: Record<EdgeNodeRole, string> = {
  edge: '直接面向访客，按域名配置回源；可以叠加在区域 Shield 后面。',
  shield: '区域汇聚层，缓存命中直接返回，未命中才替普通边缘回源；会自动忽略域名里的 shield_url。',
}

export const DEPLOYMENT_LABEL: Record<EdgeDeploymentMode, string> = {
  remote: '控制面在另一台机器（生产推荐）',
  'same-host': '控制面与本节点同机',
  custom: '自定义管理面地址',
}

export const DEPLOYMENT_DESC: Record<EdgeDeploymentMode, string> = {
  remote: '管理面监听 0.0.0.0:8081，AGENT_URL 指向本节点公网 IP；请用安全组只放行控制面访问 8081。',
  'same-host': '管理面只监听 127.0.0.1:8081，控制面通过回环地址回调，最安全。',
  custom: '手动填写管理面监听与控制面可达地址，适合内网专线、NAT 或独立管理网。',
}

const DEFAULT_ADMIN_PORT = '8081'

export type ItemEditUnit = 'bytes' | 'ms' | 'count'

export interface ItemEditRule {
  min: number
  max: number
  unit: ItemEditUnit
}

/**
 * Parameters that can be edited in the capacity table.
 *
 * Keep these in sync with the clamps in `apps/edge/src/config/mod.rs`; the
 * table writes the raw value, so every rule is an integer range.
 */
export const ITEM_EDIT_RULES: Record<string, ItemEditRule> = {
  EDGE_WORKER_THREADS: { min: EDGE_LIMITS.workerThreads[0], max: EDGE_LIMITS.workerThreads[1], unit: 'count' },
  EDGE_COMPRESSION_LEVEL: { min: EDGE_LIMITS.compressionLevel[0], max: EDGE_LIMITS.compressionLevel[1], unit: 'count' },
  DOWNSTREAM_KEEPALIVE_REQUESTS: { min: 1, max: 100_000, unit: 'count' },
  CACHE_MAX_BYTES: { min: EDGE_LIMITS.cacheMaxBytes[0], max: EDGE_LIMITS.cacheMaxBytes[1], unit: 'bytes' },
  CACHE_CAPACITY: { min: 1, max: 10_000_000, unit: 'count' },
  CACHE_TTL: { min: 0, max: 31_536_000, unit: 'count' },
  MAX_CACHEABLE_BODY: { min: EDGE_LIMITS.maxCacheableBody[0], max: EDGE_LIMITS.maxCacheableBody[1], unit: 'bytes' },
  DISK_CACHE_MAX_BYTES: { min: 0, max: 1_125_899_906_842_624, unit: 'bytes' },
  EDGE_COMPRESSED_CACHE_MAX_BYTES: { min: 0, max: 4 * GiB, unit: 'bytes' },
  LARGE_CACHE_MAX_BYTES: { min: 0, max: 1_125_899_906_842_624, unit: 'bytes' },
  LARGE_CACHE_MIN_OBJECT_BYTES: { min: EDGE_LIMITS.largeCacheMinObject[0], max: EDGE_LIMITS.largeCacheMinObject[1], unit: 'bytes' },
  LARGE_CACHE_MAX_OBJECT_BYTES: { min: EDGE_LIMITS.largeCacheMaxObject[0], max: EDGE_LIMITS.largeCacheMaxObject[1], unit: 'bytes' },
  LARGE_CACHE_CHUNK_BYTES: { min: EDGE_LIMITS.largeCacheChunk[0], max: EDGE_LIMITS.largeCacheChunk[1], unit: 'bytes' },
  LARGE_CACHE_FILL_QUEUE_BYTES: { min: EDGE_LIMITS.largeCacheFillQueue[0], max: EDGE_LIMITS.largeCacheFillQueue[1], unit: 'bytes' },
  LARGE_CACHE_FILL_QUEUE_TOTAL_BYTES: { min: EDGE_LIMITS.largeCacheFillQueueTotal[0], max: EDGE_LIMITS.largeCacheFillQueueTotal[1], unit: 'bytes' },
  LARGE_CACHE_MIN_FREE_BYTES: { min: EDGE_LIMITS.largeCacheMinFree[0], max: EDGE_LIMITS.largeCacheMinFree[1], unit: 'bytes' },
  ORIGIN_CONNECT_TIMEOUT_MS: { min: EDGE_LIMITS.originConnectTimeout[0], max: EDGE_LIMITS.originConnectTimeout[1], unit: 'ms' },
  ORIGIN_READ_TIMEOUT_MS: { min: EDGE_LIMITS.originReadTimeout[0], max: EDGE_LIMITS.originReadTimeout[1], unit: 'ms' },
  ORIGIN_STREAM_READ_TIMEOUT_MS: { min: EDGE_LIMITS.originStreamReadTimeout[0], max: EDGE_LIMITS.originStreamReadTimeout[1], unit: 'ms' },
  RANGE_FILL_MAX_BYTES: { min: EDGE_LIMITS.rangeFillMax[0], max: EDGE_LIMITS.rangeFillMax[1], unit: 'bytes' },
  ACCESS_LOG_BUFFER: { min: EDGE_LIMITS.accessLogBuffer[0], max: EDGE_LIMITS.accessLogBuffer[1], unit: 'count' },
  CACHE_FLIGHT_TIMEOUT_MS: { min: EDGE_LIMITS.cacheFlightTimeout[0], max: EDGE_LIMITS.cacheFlightTimeout[1], unit: 'ms' },
  CC_REDIS_TIMEOUT_MS: { min: EDGE_LIMITS.ccRedisTimeout[0], max: EDGE_LIMITS.ccRedisTimeout[1], unit: 'ms' },
}

/** `LARGE_CACHE_ENABLED` is a boolean toggle handled specially by the wizard. */
export function isItemEditable(key: string): boolean {
  return key === 'LARGE_CACHE_ENABLED' || key in ITEM_EDIT_RULES
}

const BYTE_UNITS: Record<string, number> = {
  '': 1,
  b: 1,
  k: KiB,
  kb: KiB,
  kib: KiB,
  m: MiB,
  mb: MiB,
  mib: MiB,
  g: GiB,
  gb: GiB,
  gib: GiB,
  t: 1024 * GiB,
  tb: 1024 * GiB,
  tib: 1024 * GiB,
}

/** Parse `1048576`, `1M`, `4MiB`, `1.5G` into a byte count. */
function parseByteInput(value: string): number | null {
  const match = /^(\d+(?:\.\d+)?)\s*([a-zA-Z]*)$/.exec(value.trim())
  if (!match) return null
  const multiplier = BYTE_UNITS[match[2].toLowerCase()]
  if (multiplier === undefined) return null
  const bytes = Math.round(Number(match[1]) * multiplier)
  return Number.isSafeInteger(bytes) ? bytes : null
}

/** Compact, exact-enough value for the edit box (1M, 4M, 1G, or raw bytes). */
export function formatItemInput(key: string, value: string): string {
  const rule = ITEM_EDIT_RULES[key]
  if (!rule || rule.unit !== 'bytes') return value
  const bytes = Number(value)
  if (!Number.isSafeInteger(bytes) || bytes <= 0) return value
  if (bytes % GiB === 0) return `${bytes / GiB}G`
  if (bytes % MiB === 0) return `${bytes / MiB}M`
  if (bytes % KiB === 0) return `${bytes / KiB}K`
  return value
}

/** Normalize a raw table edit; returns `null` when the value is not valid. */
export function normalizeItemValue(key: string, raw: string): string | null {
  const value = String(raw).trim()
  if (key === 'LARGE_CACHE_ENABLED') {
    const lowered = value.toLowerCase()
    if (lowered === 'true' || lowered === '1') return 'true'
    if (lowered === 'false' || lowered === '0') return 'false'
    return null
  }
  const rule = ITEM_EDIT_RULES[key]
  if (!rule) return null
  if (rule.unit === 'bytes') {
    const bytes = parseByteInput(value)
    if (bytes === null || bytes < rule.min || bytes > rule.max) return null
    return String(bytes)
  }
  if (!/^\d+$/.test(value)) return null
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < rule.min || parsed > rule.max) return null
  return String(parsed)
}

/** Human-readable validation text for an editable item. */
export function itemRuleHint(key: string): string {
  if (key === 'LARGE_CACHE_ENABLED') return '请输入 true 或 false'
  const rule = ITEM_EDIT_RULES[key]
  if (!rule) return '该参数不可手工修改'
  if (rule.unit === 'bytes') {
    return `请输入 ${humanBytes(rule.min)} – ${humanBytes(rule.max)}；支持 1M / 4M / 1G 等写法`
  }
  if (rule.unit === 'ms') return `请输入 ${rule.min}–${rule.max} 之间的整数（毫秒）`
  return `请输入 ${rule.min}–${rule.max} 之间的整数`
}

/** One-line hardware summary used in the page header and in the env file. */
export function summarizeHardware(hw: EdgeHardware): string {
  const role = hw.role === 'shield' ? `${NODE_ROLE_LABEL.shield} / ` : ''
  return (
    role +
    [
      `${hw.cpuCores || 1} 核`,
      `${hw.memoryGb || 1} GiB 内存`,
      hw.diskGb > 0 ? `${hw.diskGb} GiB ${DISK_TYPE_LABEL[hw.diskType]}` : '未填写磁盘',
      hw.bandwidthMbps > 0 ? `${hw.bandwidthMbps} Mbps` : '未填写带宽',
      WORKLOAD_LABEL[hw.workload],
    ].join(' / ')
  )
}

/**
 * Runtime settings the wizard collects alongside the hardware.
 *
 * Everything that changes the rendered `edge.env` is stored with the profile,
 * because the detail drawer must rebuild the same file: leaving a value out made
 * the two views disagree (Redis endpoints and the two shared secrets were the
 * gaps). These values are only ever rendered into the file — never logged — and
 * the underlying endpoints are admin-only.
 *
 * `AGENT_TOKEN` is still not part of the profile: it belongs to the node record
 * and is returned by the node detail endpoint.
 */
export interface EdgeInfraProfile {
  /** How `adminListen` / `agentUrl` were derived (drives the console form). */
  deployment: EdgeDeploymentMode
  /** Public HTTP listener, e.g. `0.0.0.0:80`. */
  httpListen: string
  httpsEnabled: boolean
  httpsListen: string
  /** Bind address for management endpoints (`EDGE_ADMIN_LISTEN`). */
  adminListen: string
  /**
   * Control-plane callback origin (`AGENT_URL`). Must point at `adminListen`
   * and be reachable from the control plane.
   */
  agentUrl: string
  /** `REDIS_URL`: shared Redis for CC counters, flight locks and L2 fallback. */
  redisUrl: string
  /** `CACHE_REDIS_URL`: dedicated L2 endpoint; empty falls back to `redisUrl`. */
  cacheRedisUrl: string
  /** `CACHE_BACKEND`; `auto` derives memory/hybrid from the hardware profile. */
  cacheBackend: EdgeCacheBackend
  /** `CHALLENGE_SECRET`: must be identical on every node. */
  challengeSecret: string
  /** `WAF_RULEPACK_SECRET`: must match the control plane's signing key. */
  wafRulepackSecret: string
}

/** Everything needed to rebuild an `edge.env` after the wizard has closed. */
export interface EdgeProfile {
  hardware: EdgeHardware
  infra: EdgeInfraProfile
  /** Capacity-table overrides; absent for profiles written before this field. */
  sizing?: EdgeSizingOverrides
  /**
   * Rendered edge.env stored so the node token can fetch it through
   * `GET /api/v1/edge/config`. Empty for nodes not created by the wizard.
   */
  env?: string
}

export const EDGE_PROFILE_DEFAULTS: EdgeProfile = {
  hardware: {
    cpuCores: 4,
    memoryGb: 8,
    diskGb: 200,
    diskType: 'nvme',
    bandwidthMbps: 500,
    workload: 'web',
    sharedRedis: false,
    role: 'edge',
  },
  infra: {
    deployment: 'remote',
    httpListen: '0.0.0.0:80',
    httpsEnabled: true,
    httpsListen: '0.0.0.0:443',
    adminListen: `0.0.0.0:${DEFAULT_ADMIN_PORT}`,
    agentUrl: '',
    redisUrl: '',
    cacheRedisUrl: '',
    cacheBackend: 'auto',
    challengeSecret: '',
    wafRulepackSecret: '',
  },
}

function boundedNumber(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(Math.max(Math.round(parsed), min), max)
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return allowed.includes(value as T) ? (value as T) : fallback
}

/** Serialize a profile for `PUT /api/v1/nodes/:id { edge_profile }`. */
export function serializeEdgeProfile(profile: EdgeProfile): string {
  return JSON.stringify({
    // Bumped when fields were added; `parseEdgeProfile` accepts older shapes.
    version: 3,
    hardware: profile.hardware,
    infra: profile.infra,
    sizing: profile.sizing ?? {},
    // The rendered file is stored verbatim so the edge can fetch it by token.
    env: profile.env || undefined,
  })
}

/**
 * Parse a stored profile defensively.
 *
 * The column is opaque text written by an older build in the worst case, so
 * every field is re-validated and clamped instead of trusted; unrecognised
 * input yields `null` and the caller falls back to the defaults.
 *
 * Version 1 profiles predate `role`, `deployment`, `httpListen` and `agentUrl`.
 * They keep working: the role is `edge`, the deployment is `custom` (so the
 * drawer does not silently rewrite the bind address) and the HTTP listener is
 * the production default.
 */
export function parseEdgeProfile(raw: unknown): EdgeProfile | null {
  if (typeof raw !== 'string' || !raw.trim()) return null
  let parsed: any
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null

  const hardware = parsed.hardware ?? {}
  const infra = parsed.infra ?? {}
  const fallback = EDGE_PROFILE_DEFAULTS

  const sizing = parsed.sizing ?? {}
  const itemValues: Record<string, string> = {}
  if (sizing.itemValues && typeof sizing.itemValues === 'object' && !Array.isArray(sizing.itemValues)) {
    for (const [key, value] of Object.entries(sizing.itemValues)) {
      // `LARGE_CACHE_ENABLED` is represented by `largeCacheGiB`; accepting it
      // here would enable a tier without its dependent rows.
      if (key === 'LARGE_CACHE_ENABLED' || typeof value !== 'string') continue
      const normalized = normalizeItemValue(key, value)
      if (normalized !== null) itemValues[key] = normalized
    }
  }
  const largeCacheGiB =
    typeof sizing.largeCacheGiB === 'number' &&
    Number.isFinite(sizing.largeCacheGiB) &&
    sizing.largeCacheGiB >= 0
      ? Math.round(sizing.largeCacheGiB)
      : undefined

  return {
    hardware: {
      cpuCores: boundedNumber(hardware.cpuCores, 1, 128, fallback.hardware.cpuCores),
      memoryGb: boundedNumber(hardware.memoryGb, 1, 512, fallback.hardware.memoryGb),
      diskGb: boundedNumber(hardware.diskGb, 0, 100_000, fallback.hardware.diskGb),
      diskType: oneOf(hardware.diskType, ['hdd', 'sata-ssd', 'nvme'] as const, fallback.hardware.diskType),
      bandwidthMbps: boundedNumber(hardware.bandwidthMbps, 0, 100_000, fallback.hardware.bandwidthMbps),
      workload: oneOf(hardware.workload, ['web', 'video', 'mixed'] as const, fallback.hardware.workload),
      sharedRedis: hardware.sharedRedis === true,
      role: oneOf(hardware.role, ['edge', 'shield'] as const, fallback.hardware.role),
    },
    infra: {
      // Older profiles have no deployment concept; `custom` means "keep the
      // stored addresses exactly as they are".
      deployment: oneOf(infra.deployment, ['same-host', 'remote', 'custom'] as const, 'custom'),
      httpListen:
        typeof infra.httpListen === 'string' && infra.httpListen.trim()
          ? infra.httpListen.trim()
          : fallback.infra.httpListen,
      // Absent means "the wizard's default"; anything non-boolean falls back to
      // the default instead of being coerced from a truthy string.
      httpsEnabled:
        typeof infra.httpsEnabled === 'boolean'
          ? infra.httpsEnabled
          : fallback.infra.httpsEnabled,
      httpsListen: typeof infra.httpsListen === 'string' && infra.httpsListen.trim()
        ? infra.httpsListen.trim()
        : fallback.infra.httpsListen,
      adminListen: typeof infra.adminListen === 'string' && infra.adminListen.trim()
        ? infra.adminListen.trim()
        : fallback.infra.adminListen,
      agentUrl: typeof infra.agentUrl === 'string' ? infra.agentUrl.trim() : '',
      // Older profiles predate these fields; "" / "auto" keeps them working
      // and lets the drawer show its "fill in the Redis settings" hint.
      redisUrl: typeof infra.redisUrl === 'string' ? infra.redisUrl.trim() : '',
      cacheRedisUrl: typeof infra.cacheRedisUrl === 'string' ? infra.cacheRedisUrl.trim() : '',
      cacheBackend: oneOf(infra.cacheBackend, CACHE_BACKENDS, 'auto'),
      challengeSecret:
        typeof infra.challengeSecret === 'string' ? infra.challengeSecret.trim() : '',
      wafRulepackSecret:
        typeof infra.wafRulepackSecret === 'string' ? infra.wafRulepackSecret.trim() : '',
    },
    sizing: {
      itemValues,
      ...(largeCacheGiB !== undefined ? { largeCacheGiB } : {}),
    },
    env: typeof parsed.env === 'string' ? parsed.env : '',
  }
}

// ---------------------------------------------------------------- addresses

/** Split `host:port` / `[v6]:port` without throwing. */
export function splitListen(value: string): { host: string; port: string } | null {
  const raw = value.trim()
  if (!raw) return null
  if (raw.startsWith('[')) {
    const end = raw.indexOf(']')
    if (end < 0) return null
    const rest = raw.slice(end + 1)
    if (!rest.startsWith(':')) return null
    return { host: raw.slice(1, end), port: rest.slice(1) }
  }
  const idx = raw.lastIndexOf(':')
  if (idx <= 0) return null
  return { host: raw.slice(0, idx), port: raw.slice(idx + 1) }
}

function isValidPort(port: string): boolean {
  return /^\d{1,5}$/.test(port) && Number(port) >= 1 && Number(port) <= 65_535
}

function isIpv4(host: string): boolean {
  const parts = host.split('.')
  return (
    parts.length === 4 &&
    parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
  )
}

/**
 * `EDGE_ADMIN_LISTEN` is parsed as a `SocketAddr` by the edge, so hostnames are
 * rejected there even though `EDGE_LISTEN` accepts them. Mirror that check.
 */
export function isValidSocketAddr(value: string): boolean {
  const parts = splitListen(value)
  if (!parts || !isValidPort(parts.port)) return false
  if (/^[0-9a-fA-F:.]+$/.test(parts.host) && parts.host.includes(':')) return true
  return isIpv4(parts.host)
}

/** `EDGE_LISTEN` / `EDGE_HTTPS_LISTEN` are passed to Pingora, which resolves names. */
export function isValidListen(value: string): boolean {
  const parts = splitListen(value)
  if (!parts || !isValidPort(parts.port)) return false
  if (parts.host.startsWith('[')) return /^\[[0-9a-fA-F:.]+\]$/.test(parts.host)
  return /^[A-Za-z0-9._-]+$/.test(parts.host)
}

/** Accept only a plain http(s) URL; used for `AGENT_URL` and the preview. */
export function isValidHttpUrl(value: string, allowPath = false): boolean {
  const raw = value.trim()
  if (!raw) return false
  // The control plane's `validate_agent_url` strips a lowercase prefix, so an
  // uppercase scheme would be accepted here and rejected there.
  if (!/^https?:\/\//.test(raw)) return false
  try {
    const url = new URL(raw)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return false
    if (!url.hostname) return false
    if (!allowPath && ((url.pathname && url.pathname !== '/') || url.search || url.hash)) {
      return false
    }
    return true
  } catch {
    return false
  }
}

/** Bracket a bare IPv6 literal for use inside a URL authority. */
export function hostForUrl(host: string): string {
  const raw = host.trim()
  if (!raw) return ''
  if (raw.startsWith('[') || !raw.includes(':')) return raw
  return `[${raw}]`
}

/**
 * The pair the wizard derives for the two non-custom deployment modes.
 *
 * Keeping both values in one function is the whole point: `AGENT_URL` must be
 * the address of `EDGE_ADMIN_LISTEN`, otherwise the control plane stores a
 * callback URL nothing is listening on.
 */
export function resolveDeployment(
  mode: EdgeDeploymentMode,
  publicIp: string,
): { adminListen: string; agentUrl: string } {
  if (mode === 'same-host') {
    return {
      adminListen: `127.0.0.1:${DEFAULT_ADMIN_PORT}`,
      agentUrl: `http://127.0.0.1:${DEFAULT_ADMIN_PORT}`,
    }
  }
  if (mode === 'remote') {
    const host = hostForUrl(publicIp)
    return {
      // The documented production shape: bind the management listener, then
      // restrict it to the control-plane source IP with a security group.
      adminListen: `0.0.0.0:${DEFAULT_ADMIN_PORT}`,
      agentUrl: host ? `http://${host}:${DEFAULT_ADMIN_PORT}` : '',
    }
  }
  return { adminListen: '', agentUrl: '' }
}

/** Random hex secret for `CHALLENGE_SECRET` (browser only). */
export function generateSecret(bytes = 32): string {
  const target = new Uint8Array(bytes)
  const cryptoApi = globalThis.crypto
  if (cryptoApi?.getRandomValues) {
    cryptoApi.getRandomValues(target)
  } else {
    // `ssr: false` means this only runs in a browser; keep a fallback so an
    // embedded webview without WebCrypto still produces a value.
    for (let i = 0; i < target.length; i += 1) target[i] = Math.floor(Math.random() * 256)
  }
  return Array.from(target, (b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Derive the edge configuration for a piece of hardware.
 *
 * The rules, in short:
 *  - L1 memory cache gets 25% of RAM (capped at the edge's 8 GiB hard limit).
 *  - The large-object disk cache only turns on when the disk can hold a useful
 *    working set; otherwise it only adds failure modes. A dedicated Origin
 *    Shield always wants it.
 *  - `MAX_CACHEABLE_BODY` stays one byte below the large-cache threshold so no
 *    object size falls into the "cached by neither tier" gap documented in
 *    `edge.env.example`.
 *  - The chunk size follows the disk: HDD seeks force bigger chunks.
 *  - A backend that cannot work (disk on a diskless node, `redis` without an
 *    endpoint) is downgraded here instead of emitting a config the edge would
 *    only warn about.
 */
export function recommendEdgeConfig(
  hw: EdgeHardware,
  overrides: EdgeSizingOverrides = {},
): EdgeSizingPlan {
  const cores = clamp(hw.cpuCores || 1, 1, 128)
  const memoryGb = clamp(hw.memoryGb || 1, 1, 512)
  const diskGb = clamp(hw.diskGb || 0, 0, 100_000)
  const bandwidth = clamp(hw.bandwidthMbps || 0, 0, 100_000)
  const shield = hw.role === 'shield'

  const memoryBytes = memoryGb * GiB
  const diskBytes = diskGb * GiB
  // 15% is left for logs, certs, WAF rulepacks and filesystem overhead.
  const usableDisk = Math.round(diskBytes * 0.85)

  // ------------------------------------------------------------- runtime
  const workerOverridden = overrides.workerThreads !== undefined
  const workerThreads = clamp(
    workerOverridden ? Number(overrides.workerThreads) : cores,
    ...EDGE_LIMITS.workerThreads,
  )
  const compressionLevel = clamp(
    cores >= 8 ? 5 : cores >= 4 ? 4 : 3,
    ...EDGE_LIMITS.compressionLevel,
  )
  // High-bandwidth nodes keep downstream connections a little longer: the
  // reconnect cost per request is relatively larger there.
  const keepaliveRequests = bandwidth >= 2000 ? 2000 : 1000

  // ------------------------------------------------------- L1 memory cache
  const memOverridden = overrides.memoryCacheMiB !== undefined
  const memoryCacheBytes = clamp(
    memOverridden ? Number(overrides.memoryCacheMiB) * MiB : memoryBytes * 0.25,
    ...EDGE_LIMITS.cacheMaxBytes,
  )
  // A shield exists to absorb origin traffic, so it always wants the large
  // cache once the disk is non-trivial. Ordinary nodes need a working set that
  // justifies the extra failure modes.
  const largeSuggested = shield
    ? diskGb >= 10
    : hw.workload === 'video'
      ? diskGb >= 20
      : hw.workload === 'mixed'
        ? diskGb >= 50
        : diskGb >= 200
  const largeOverridden = overrides.largeCacheGiB !== undefined
  const wantLarge = largeOverridden ? Number(overrides.largeCacheGiB) > 0 : largeSuggested
  const largeCacheBytes = wantLarge
    ? clamp(
      largeOverridden
        ? Number(overrides.largeCacheGiB) * GiB
        : // 80% of the usable disk; the remainder feeds the normal disk cache.
        usableDisk * 0.8,
      0,
      usableDisk,
    )
    : 0
  const largeCacheEnabled = largeCacheBytes > 0

  // How many objects fit depends on the workload. Once the large-object tier is
  // on, the memory cache only holds the small remainder, so a video node does
  // not need to reserve for 2 MiB bodies it would send to L3 anyway.
  const avgObject =
    hw.workload === 'video'
      ? largeCacheEnabled
        ? 256 * KiB
        : 2 * MiB
      : hw.workload === 'web'
        ? 64 * KiB
        : 256 * KiB
  const cacheCapacity = clamp(memoryCacheBytes / avgObject, 1_000, 2_000_000)

  const chunkBytes = clamp(hw.diskType === 'hdd' ? 4 * MiB : 1 * MiB, ...EDGE_LIMITS.largeCacheChunk)
  const fillQueueBytes = clamp(
    hw.diskType === 'nvme' ? 128 * MiB : hw.diskType === 'sata-ssd' ? 64 * MiB : 32 * MiB,
    ...EDGE_LIMITS.largeCacheFillQueue,
  )
  const fillQueueTotalBytes = clamp(
    Math.max(fillQueueBytes, memoryBytes * 0.05),
    ...EDGE_LIMITS.largeCacheFillQueueTotal,
  )
  // Keep a real free-space floor, but never reserve more than a quarter of the
  // large cache itself: an override that enables a 1 GiB large cache on a 20 GiB
  // disk must still be able to fill something.
  const minFreeTarget = Math.min(
    Math.max(diskBytes * 0.05, 256 * MiB),
    Math.max(largeCacheBytes * 0.1, 64 * MiB),
  )
  const minFreeBytes = clamp(minFreeTarget, ...EDGE_LIMITS.largeCacheMinFree)

  const minObjectBytes = clamp(
    shield ? 1 * MiB : hw.workload === 'web' ? 4 * MiB : 8 * MiB,
    ...EDGE_LIMITS.largeCacheMinObject,
  )
  const maxObjectTarget = shield
    ? 4 * GiB
    : hw.workload === 'video'
      ? 2 * GiB
      : hw.workload === 'web'
        ? 256 * MiB
        : GiB
  // A maximum object larger than the whole cache can never be admitted.
  const maxObjectBytes = clamp(
    largeCacheEnabled
      ? Math.min(maxObjectTarget, Math.max(largeCacheBytes, 1 * MiB))
      : maxObjectTarget,
    ...EDGE_LIMITS.largeCacheMaxObject,
  )
  // Split the two tiers at one exact byte value, per edge.env.example.
  const maxCacheableBody = clamp(
    largeCacheEnabled ? minObjectBytes - 1 : 8 * MiB,
    ...EDGE_LIMITS.maxCacheableBody,
  )

  // ------------------------------------------------------- cache backend
  // `CACHE_BACKEND` decides which tiers exist at all, so the disk-cache sizing
  // follows the chosen backend rather than the other way round.
  const derivedDiskCacheBytes = largeCacheEnabled
    ? clamp(usableDisk * 0.2, 0, Math.max(0, usableDisk - largeCacheBytes))
    : diskGb >= 40
      ? clamp(usableDisk * 0.5, 2 * GiB, 200 * GiB)
      : 0

  const requestedCacheBackend = overrides.cacheBackend ?? 'auto'
  const redisConfigured = overrides.redisConfigured !== false
  let resolvedBackend: EdgeCacheBackend =
    requestedCacheBackend === 'auto'
      ? derivedDiskCacheBytes > 0
        ? 'hybrid'
        : 'memory'
      : requestedCacheBackend
  let backendDowngraded = false
  if (resolvedBackend === 'redis' && !redisConfigured) {
    // Emitting redis without an endpoint only produces a startup warning and a
    // silent fallback, so derive the best local backend instead.
    resolvedBackend = derivedDiskCacheBytes > 0 ? 'hybrid' : 'memory'
    backendDowngraded = true
  }
  if (diskGb === 0 && (resolvedBackend === 'disk' || resolvedBackend === 'hybrid')) {
    // `disk`/`hybrid` on a memory-only node falls back to `./data/cache` with a
    // 1 GiB default, which is almost never what the operator intended.
    resolvedBackend = 'memory'
    backendDowngraded = true
  }
  const cacheBackend: EdgeCacheBackend = resolvedBackend
  const usesDiskTier = cacheBackend === 'disk' || cacheBackend === 'hybrid'
  const diskCacheBytes = usesDiskTier
    ? derivedDiskCacheBytes > 0
      ? clamp(derivedDiskCacheBytes, 0, usableDisk)
      : clamp(usableDisk * 0.5, 0, 200 * GiB)
    : 0
  const cacheTtlSecs = hw.workload === 'video' ? 3600 : hw.workload === 'mixed' ? 300 : 60
  const compressedCacheBytes = clamp(Math.max(memoryBytes * 0.05, 16 * MiB), 0, 512 * MiB)

  // --------------------------------------------------------------- origin
  const connectTimeoutMs = clamp(
    bandwidth > 0 && bandwidth <= 50 ? 5000 : 3000,
    ...EDGE_LIMITS.originConnectTimeout,
  )
  const readTimeoutMs = clamp(
    hw.workload === 'video' ? 60_000 : hw.workload === 'mixed' ? 30_000 : 20_000,
    ...EDGE_LIMITS.originReadTimeout,
  )
  const streamReadTimeoutMs = clamp(
    hw.workload === 'video' ? 180_000 : 120_000,
    ...EDGE_LIMITS.originStreamReadTimeout,
  )
  const rangeFillBytes = clamp(
    hw.workload === 'web' ? 8 * MiB : 32 * MiB,
    ...EDGE_LIMITS.rangeFillMax,
  )

  // -------------------------------------------------------------- logging
  const accessLogBuffer = clamp(Math.max(cores * 500, 1_000), ...EDGE_LIMITS.accessLogBuffer)

  // ----------------------------------------------------------------- items
  const items: EdgeSizingItem[] = [
    {
      key: 'EDGE_WORKER_THREADS',
      value: String(workerThreads),
      group: 'runtime',
      overridden: workerOverridden,
      reason: workerOverridden
        ? `手工指定为 ${workerThreads}；建议不超过 CPU 核数（${cores}）`
        : `跟随 CPU 核数（${cores}）。Pingora 默认单线程会把下行 TLS、WAF 与回源握手全部串行`,
    },
    {
      key: 'EDGE_COMPRESSION_LEVEL',
      value: String(compressionLevel),
      group: 'runtime',
      reason:
        cores >= 8
          ? '核数充足，用级别 5 换取更小体积'
          : cores >= 4
            ? '平衡 CPU 与体积，取级别 4'
            : '核数较少，取级别 3，避免压缩抢占回源 CPU',
    },
    {
      key: 'DOWNSTREAM_KEEPALIVE_REQUESTS',
      value: String(keepaliveRequests),
      group: 'runtime',
      reason:
        bandwidth >= 2000
          ? '高带宽节点单连接可承载更多请求，减少重复建连'
          : '默认 1000，足够覆盖常规 HTTP/1.1 复用',
    },
    {
      key: 'EDGE_SHIELD_DISABLED',
      value: shield ? 'true' : 'false',
      group: 'runtime',
      reason: shield
        ? 'Origin Shield 必须忽略域名里的 shield_url，否则缓存未命中会回源到自己，形成回源环'
        : '普通边缘节点必须为 false，才会使用管理员配置的 Shield 节点',
    },
    {
      key: 'CACHE_BACKEND',
      value: cacheBackend,
      group: 'memory-cache',
      overridden: requestedCacheBackend !== 'auto' && !backendDowngraded,
      reason: backendDowngraded
        ? `请求的 ${requestedCacheBackend} 在当前硬件/Redis 条件下不可用，已降级为 ${cacheBackend}`
        : requestedCacheBackend !== 'auto'
          ? `手工指定为 ${cacheBackend}${usesDiskTier ? `，磁盘缓存 ${humanBytes(diskCacheBytes)}` : ''}`
          : cacheBackend === 'hybrid'
            ? `磁盘可用 ${humanBytes(diskBytes)}，普通对象落盘做二级缓存`
            : '磁盘未达混合缓存门槛，只使用内存缓存',
    },
    {
      key: 'CACHE_MAX_BYTES',
      value: String(memoryCacheBytes),
      group: 'memory-cache',
      overridden: memOverridden,
      reason: memOverridden
        ? `手工指定为 ${humanBytes(memoryCacheBytes)}`
        : `内存的 25%（${humanBytes(memoryBytes)} × 25%），上限 ${humanBytes(8 * GiB)}`,
    },
    {
      key: 'CACHE_CAPACITY',
      value: String(cacheCapacity),
      group: 'memory-cache',
      reason: `按 ${hw.workload === 'video'
        ? largeCacheEnabled
          ? '视频小对象 256 KiB'
          : '视频 2 MiB'
        : hw.workload === 'web'
          ? '小文件 64 KiB'
          : '混合 256 KiB'
        } 平均对象估算，约 ${cacheCapacity.toLocaleString('zh-CN')} 个对象`,
    },
    {
      key: 'CACHE_TTL',
      value: String(cacheTtlSecs),
      group: 'memory-cache',
      reason:
        hw.workload === 'video'
          ? '点播内容变化慢，默认 TTL 取 1 小时'
          : hw.workload === 'mixed'
            ? '混合业务取 5 分钟，兼顾命中率与更新速度'
            : '网页默认 60 秒，可按路径规则覆盖',
    },
    {
      key: 'MAX_CACHEABLE_BODY',
      value: String(maxCacheableBody),
      group: 'memory-cache',
      reason: largeCacheEnabled
        ? `比大缓存门槛（${humanBytes(minObjectBytes)}）小 1 字节，避免两层校验重叠或出现不缓存空洞`
        : '未启用大对象缓存，8 MiB 以内的响应走内存缓存',
    },
  ]

  if (diskCacheBytes > 0) {
    items.push({
      key: 'DISK_CACHE_MAX_BYTES',
      value: String(diskCacheBytes),
      group: 'memory-cache',
      reason: `取可用磁盘的 ${largeCacheEnabled ? '20%' : '50%'}，其余留给${largeCacheEnabled ? '大对象缓存、' : ''
        }证书、日志与 WAF 规则包`,
    })
  }
  items.push({
    key: 'EDGE_COMPRESSED_CACHE_MAX_BYTES',
    value: String(compressedCacheBytes),
    group: 'memory-cache',
    reason: '内存的 5% 用于预压缩变体，上限 512 MiB',
  })

  if (largeCacheEnabled) {
    items.push(
      {
        key: 'LARGE_CACHE_ENABLED',
        value: 'true',
        group: 'large-cache',
        overridden: largeOverridden,
        reason: shield
          ? 'Origin Shield 必须缓存大对象，否则每个区域都要回源'
          : hw.workload === 'video'
            ? '视频点播以大文件为主，不启用则每次回源'
            : '磁盘容量足够，启用后大对象流式落盘、不占内存',
      },
      {
        key: 'LARGE_CACHE_MAX_BYTES',
        value: String(largeCacheBytes),
        group: 'large-cache',
        overridden: largeOverridden,
        reason: largeOverridden
          ? `手工指定为 ${humanBytes(largeCacheBytes)}`
          : shield
            ? `可用磁盘的 80%（${humanBytes(usableDisk)} × 80%），区域汇聚需要更大的热数据集`
            : `可用磁盘的 80%（${humanBytes(usableDisk)} × 80%）`,
      },
      {
        key: 'LARGE_CACHE_MIN_OBJECT_BYTES',
        value: String(minObjectBytes),
        group: 'large-cache',
        reason: shield
          ? 'Shield 汇聚所有对象，小于 1 MiB 的才继续走普通缓存'
          : `小于 ${humanBytes(minObjectBytes)} 的对象仍走内存 / 普通磁盘缓存`,
      },
      {
        key: 'LARGE_CACHE_MAX_OBJECT_BYTES',
        value: String(maxObjectBytes),
        group: 'large-cache',
        reason: shield
          ? 'Shield 需要覆盖超大视频/安装包，完整对象上限放宽到 4 GiB'
          : `超过 ${humanBytes(maxObjectBytes)} 的完整对象不缓存，但 Range 分片仍可缓存`,
      },
      {
        key: 'LARGE_CACHE_CHUNK_BYTES',
        value: String(chunkBytes),
        group: 'large-cache',
        reason:
          hw.diskType === 'hdd'
            ? '机械盘随机寻道代价高，分片放大到 4 MiB'
            : 'SSD 随机读代价低，1 MiB 分片命中更细',
      },
      {
        key: 'LARGE_CACHE_FILL_QUEUE_BYTES',
        value: String(fillQueueBytes),
        group: 'large-cache',
        reason: `${DISK_TYPE_LABEL[hw.diskType]}的写队列上限，超出后丢弃本次填充而不阻塞请求`,
      },
      {
        key: 'LARGE_CACHE_FILL_QUEUE_TOTAL_BYTES',
        value: String(fillQueueTotalBytes),
        group: 'large-cache',
        reason: '进程级总预算取单队列与内存 5% 的较大值，避免大文件并发写爆内存',
      },
      {
        key: 'LARGE_CACHE_MIN_FREE_BYTES',
        value: String(minFreeBytes),
        group: 'large-cache',
        reason: `至少保留 ${humanBytes(minFreeBytes)} 空闲再拒绝新填充，避免写满系统盘`,
      },
    )
  } else {
    items.push({
      key: 'LARGE_CACHE_ENABLED',
      value: 'false',
      group: 'large-cache',
      overridden: largeOverridden,
      reason:
        diskGb === 0
          ? '未填写磁盘容量，按「仅内存缓存」生成'
          : shield
            ? 'Shield 磁盘小于 10 GiB，无法容纳有意义的热数据集'
            : `磁盘 ${diskGb} GiB 未达 ${hw.workload === 'video' ? 20 : hw.workload === 'mixed' ? 50 : 200
            } GiB 门槛，启用后只会频繁驱逐`,
    })
  }

  items.push(
    {
      key: 'ORIGIN_CONNECT_TIMEOUT_MS',
      value: String(connectTimeoutMs),
      group: 'origin',
      reason:
        bandwidth > 0 && bandwidth <= 50
          ? '出口带宽较小，建连慢时多给一点时间再切换源站'
          : '默认 3 秒，源站不可达时快速切到下一个源站',
    },
    {
      key: 'ORIGIN_READ_TIMEOUT_MS',
      value: String(readTimeoutMs),
      group: 'origin',
      reason: `首字节等待上限，按业务类型取 ${readTimeoutMs / 1000} 秒`,
    },
    {
      key: 'ORIGIN_STREAM_READ_TIMEOUT_MS',
      value: String(streamReadTimeoutMs),
      group: 'origin',
      reason:
        hw.workload === 'video'
          ? '大视频首字节可能很慢，放宽到 3 分钟'
          : '流式读取空闲超时 2 分钟，不影响长连接媒体',
    },
    {
      key: 'RANGE_FILL_MAX_BYTES',
      value: String(rangeFillBytes),
      group: 'origin',
      reason: '预热时单次 Range 前缀上限，避免为冷启动拉取过多数据',
    },
    {
      key: 'ACCESS_LOG_BUFFER',
      value: String(accessLogBuffer),
      group: 'logging',
      reason: `${cores} 核按每核 500 条预留，缓冲越大越能吸收上报抖动`,
    },
  )

  // Timeout tuning only. The edge enables cross-node sharing based on the env
  // itself (REDIS_URL for CC/rate-limit, CACHE_BACKEND=redis for flight + L2),
  // so leaving these keys out just keeps the built-in 250 ms / 50 ms defaults.
  if (hw.sharedRedis) {
    items.push(
      {
        key: 'CACHE_FLIGHT_TIMEOUT_MS',
        value: String(clamp(bandwidth >= 5000 ? 500 : 250, ...EDGE_LIMITS.cacheFlightTimeout)),
        group: 'runtime',
        reason:
          bandwidth >= 5000
            ? '调优项：高带宽节点通常跨机架访问 Redis，放宽合并锁超时以减少降级'
            : '调优项：同机架 Redis 250 ms 足够；超时后自动降级为各自回源',
      },
      {
        key: 'CC_REDIS_TIMEOUT_MS',
        value: String(clamp(50, ...EDGE_LIMITS.ccRedisTimeout)),
        group: 'runtime',
        reason: '调优项：跨节点 CC 计数单次往返预算，超过后退化为进程内限流',
      },
    )
  }

  // ------------------------------------------------- per-item overrides
  // The capacity table lets the operator edit a value in place. Apply those
  // edits before warnings/metrics so the summary matches the rendered file.
  const itemValues = overrides.itemValues ?? {}
  for (const [key, raw] of Object.entries(itemValues)) {
    if (key === 'LARGE_CACHE_ENABLED') continue
    const item = items.find((candidate) => candidate.key === key)
    if (!item) continue
    const normalized = normalizeItemValue(key, raw)
    if (normalized === null) continue
    item.value = normalized
    item.overridden = true
    const shown = /_BYTES$/.test(key)
      ? `${normalized}（${humanBytes(Number(normalized))}）`
      : normalized
    item.reason = `手工指定为 ${shown}；请确认与硬件和其他参数匹配`
  }

  const finalItemValue = (key: string, fallbackValue: string) =>
    items.find((candidate) => candidate.key === key)?.value ?? fallbackValue
  const finalItemNumber = (key: string, fallbackValue: number) => {
    const parsed = Number(items.find((candidate) => candidate.key === key)?.value)
    return Number.isFinite(parsed) ? parsed : fallbackValue
  }
  const finalLargeCacheEnabled =
    finalItemValue('LARGE_CACHE_ENABLED', largeCacheEnabled ? 'true' : 'false') === 'true'

  // ------------------------------------------------------------ warnings
  const warnings: string[] = []
  if (memoryGb < 2) {
    warnings.push(
      `内存小于 2 GiB：内存缓存只能分到 ${humanBytes(memoryCacheBytes)}，建议至少 2 GiB 再承载生产流量。`,
    )
  }
  if (cores < 2) {
    warnings.push('单核节点：下行 TLS、WAF 与回源握手会串行，吞吐上不去，建议至少 2 核。')
  }
  if (hw.workload === 'video' && hw.diskType === 'hdd') {
    warnings.push('视频业务搭配机械盘：随机读抖动明显，建议换 SSD/NVMe，或确认分片已放大到 4 MiB。')
  }
  if (hw.workload === 'video' && diskGb > 0 && diskGb < 20) {
    warnings.push('视频业务磁盘小于 20 GiB：大对象缓存无法启用，命中率会很低。')
  }
  if (shield && !largeCacheEnabled) {
    warnings.push('Origin Shield 未启用大对象缓存：Shield 未命中时会频繁回源，建议至少 50 GiB 磁盘并启用大缓存。')
  }
  if (shield && diskGb > 0 && diskGb < 50) {
    warnings.push(`Shield 磁盘只有 ${diskGb} GiB：区域汇聚的热数据集通常远大于此，建议扩容或降低 LARGE_CACHE_MAX_BYTES。`)
  }
  if (bandwidth > 0 && bandwidth / cores > 2000) {
    warnings.push(
      `单核需承载约 ${Math.round(bandwidth / cores)} Mbps：带宽与核数不匹配，建议增加核数或降低单节点带宽。`,
    )
  }
  if (backendDowngraded) {
    if (requestedCacheBackend === 'redis' && !redisConfigured) {
      warnings.push(
        'CACHE_BACKEND=redis 但 REDIS_URL / CACHE_REDIS_URL 都为空：已降级为本地缓存；如需 L2 共享缓存请先填写 Redis 地址。',
      )
    } else if (diskGb === 0) {
      warnings.push(
        `CACHE_BACKEND=${requestedCacheBackend} 需要磁盘，但未填写磁盘容量：已降级为仅内存缓存。`,
      )
    }
  }
  if (diskGb === 0 && !usesDiskTier && cacheBackend !== 'redis') {
    warnings.push('未填写磁盘容量：已按「仅内存缓存」生成，重启后缓存全部丢失。')
  }
  if (cacheBackend === 'redis' && !hw.sharedRedis) {
    warnings.push(
      '未勾选「使用共享 Redis」只会让 CACHE_FLIGHT_TIMEOUT_MS / CC_REDIS_TIMEOUT_MS 保持默认值（250 / 50 ms）；' +
      'CACHE_BACKEND=redis 仍会使用 CACHE_REDIS_URL（留空则 REDIS_URL）跨节点共享 L2 缓存与合并锁。',
    )
  }
  if (finalLargeCacheEnabled) {
    const finalMinObject = finalItemNumber('LARGE_CACHE_MIN_OBJECT_BYTES', minObjectBytes)
    const finalMaxObject = finalItemNumber('LARGE_CACHE_MAX_OBJECT_BYTES', maxObjectBytes)
    const finalMaxBody = finalItemNumber('MAX_CACHEABLE_BODY', maxCacheableBody)
    const finalMaxBytes = finalItemNumber('LARGE_CACHE_MAX_BYTES', largeCacheBytes)
    if (finalMaxBody >= finalMinObject) {
      warnings.push(
        'MAX_CACHEABLE_BODY 应比 LARGE_CACHE_MIN_OBJECT_BYTES 小 1 字节，否则两层缓存会重叠或出现不缓存空洞；请调整这两个手工值。',
      )
    }
    if (finalMaxObject < finalMinObject) {
      warnings.push('大缓存对象上限小于最小对象阈值：大缓存不会生效，请调大磁盘或降低门槛。')
    }
    if (finalMaxBytes <= 0) {
      warnings.push('LARGE_CACHE_MAX_BYTES 为 0：大对象缓存不会写入任何对象。')
    }
  }

  return {
    items,
    warnings,
    metrics: {
      workerThreads: finalItemNumber('EDGE_WORKER_THREADS', workerThreads),
      memoryCacheBytes: finalItemNumber('CACHE_MAX_BYTES', memoryCacheBytes),
      cacheCapacity: finalItemNumber('CACHE_CAPACITY', cacheCapacity),
      cacheBackend: finalItemValue('CACHE_BACKEND', cacheBackend),
      requestedCacheBackend,
      backendDowngraded,
      diskCacheBytes: finalItemNumber('DISK_CACHE_MAX_BYTES', diskCacheBytes),
      largeCacheEnabled: finalLargeCacheEnabled,
      largeCacheBytes: finalLargeCacheEnabled
        ? finalItemNumber('LARGE_CACHE_MAX_BYTES', largeCacheBytes)
        : 0,
      chunkBytes: finalLargeCacheEnabled
        ? finalItemNumber('LARGE_CACHE_CHUNK_BYTES', chunkBytes)
        : 0,
      maxCacheableBody: finalItemNumber('MAX_CACHEABLE_BODY', maxCacheableBody),
    },
  }
}

// ------------------------------------------------------------- env renderer

/** Everything the generated `edge.env` needs beyond the sizing plan. */
export interface EdgeEnvInput {
  nodeId: string
  region: string
  publicIp: string
  /**
   * Management-plane callback URL (`AGENT_URL`). Derive it from `adminListen`
   * (`resolveDeployment`) instead of asking the operator independently.
   */
  agentUrl: string
  token: string
  /** Control-plane base URL reported by the node API, not the browser origin. */
  controlUrl: string
  /** Public HTTP listener (`EDGE_LISTEN`). */
  httpListen: string
  adminListen: string
  httpsEnabled: boolean
  httpsListen: string
  /** `REDIS_URL`. */
  redisUrl: string
  /** `CACHE_REDIS_URL`; empty means "reuse redisUrl" (edge behaviour). */
  cacheRedisUrl: string
  challengeSecret: string
  wafRulepackSecret: string
  hardware: EdgeHardware
  plan: EdgeSizingPlan
  generatedAt?: Date
}

const GROUP_TITLE = SIZING_GROUP_LABEL

const GROUP_ORDER: SizingGroup[] = ['runtime', 'memory-cache', 'large-cache', 'origin', 'logging']

const RULE = '# ' + '='.repeat(50)

function envLine(key: string, value: string): string {
  // Values are written unquoted: systemd EnvironmentFile and dotenvy treat the
  // whole line after `=` literally, and quoting would change the value.
  return `${key}=${value}`
}

function stamp(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}

function portOf(listen: string): string {
  return splitListen(listen)?.port ?? ''
}

/**
 * Render the complete `edge.env` for one node.
 *
 * Sections mirror `edge.env.example` so an operator who already knows that file
 * can diff the two; every sizing value carries a one-line reason so the numbers
 * stay auditable without reading the wizard's source.
 */
export function renderEdgeEnvFile(input: EdgeEnvInput): string {
  const { hardware: hw, plan } = input
  const shield = hw.role === 'shield'
  const lines: string[] = []

  const httpListen = input.httpListen.trim() || '0.0.0.0:80'
  const adminListen = input.adminListen.trim() || '127.0.0.1:8081'
  const agentUrl = input.agentUrl.trim().replace(/\/+$/, '')
  const controlUrl = input.controlUrl.trim().replace(/\/+$/, '')
  const redisUrl = input.redisUrl.trim()
  const cacheRedisUrl = input.cacheRedisUrl.trim()
  const redisBackend = plan.metrics.cacheBackend === 'redis'

  lines.push(RULE)
  lines.push(`# Lagran 边缘节点环境配置 · ${input.nodeId}`)
  lines.push(`# 由控制台「新增 Edge 向导」按硬件与角色生成 · ${stamp(input.generatedAt ?? new Date())}`)
  lines.push(`# 硬件画像：${summarizeHardware(hw)}`)
  lines.push(
    `# 业务类型：${WORKLOAD_LABEL[hw.workload]}${hw.sharedRedis ? ' · 共享 Redis' : ' · 无共享 Redis'}`,
  )
  lines.push(`# 角色：${shield ? 'Origin Shield（忽略域名 shield_url）' : '普通边缘节点'}`)
  lines.push('#')
  lines.push('# 应用方式：')
  lines.push('#   1. 把本文件保存为节点上的 /etc/lagran/edge.env')
  lines.push('#   2. sudo chmod 600 /etc/lagran/edge.env')
  lines.push('#   3. sudo systemctl restart lagran-edge')
  lines.push('#')
  lines.push('# 注意：AGENT_TOKEN 是该节点的身份凭证，等同密码，文件权限必须是 600。')
  lines.push(RULE)
  lines.push('')

  lines.push('# ----------------------------------- 节点身份与控制面')
  lines.push('# 这几项决定节点能否连上控制面，必须与控制台预注册的信息一致。')
  lines.push(envLine('CONTROL_URL', controlUrl || 'http://<控制面地址>:8080'))
  lines.push(envLine('NODE_ID', input.nodeId))
  lines.push(envLine('NODE_REGION', input.region || 'default'))
  lines.push(envLine('PUBLIC_IP', input.publicIp))
  if (agentUrl) {
    lines.push('# 控制面回调本节点的地址，必须与下面的 EDGE_ADMIN_LISTEN 对应且控制面可达。')
    lines.push(envLine('AGENT_URL', agentUrl))
  } else {
    lines.push('# 未设置 AGENT_URL：Edge 会推导为 http://127.0.0.1:<管理端口>，跨机部署时控制面无法回调。')
    lines.push('# AGENT_URL=http://<控制面可达地址>:8081')
  }
  lines.push(envLine('AGENT_TOKEN', input.token))
  lines.push('# 管理面监听：purge / 证书 / ACME 回调都走这里；只允许控制面来源访问，不要暴露给访客。')
  lines.push(envLine('EDGE_ADMIN_LISTEN', adminListen))
  lines.push('')

  lines.push('# ---------------------------------------------- 监听')
  lines.push(envLine('EDGE_LISTEN', httpListen))
  if (input.httpsEnabled) {
    const httpsListen = input.httpsListen.trim() || '0.0.0.0:443'
    lines.push('# 已启用 HTTPS：证书由控制面同步到 CERT_DIR，无需手工放置。')
    lines.push(envLine('EDGE_HTTPS_LISTEN', httpsListen))
    const httpsPort = portOf(httpsListen)
    if (httpsPort && httpsPort !== '443') {
      lines.push('# HTTPS 不在 443 时，HTTP→HTTPS 跳转需要显式指定端口。')
      lines.push(envLine('EDGE_HTTPS_REDIRECT_PORT', httpsPort))
    }
  } else {
    lines.push('# 暂不启用 HTTPS；域名开启 HTTPS 后补上 EDGE_HTTPS_LISTEN 并重启。')
    lines.push('# EDGE_HTTPS_LISTEN=0.0.0.0:443')
  }
  lines.push('')

  for (const group of GROUP_ORDER) {
    const groupItems = plan.items.filter((item) => item.group === group)
    if (!groupItems.length) continue
    lines.push(`# ${'-'.repeat(18)} ${GROUP_TITLE[group]}（按硬件推导）`)
    for (const item of groupItems) {
      lines.push(`# ${item.reason}`)
      lines.push(envLine(item.key, item.value))
    }
    lines.push('')
  }

  lines.push('# ------------------------------------------- 数据目录')
  lines.push('# 以下路径对应 install.sh 默认数据目录 /var/lib/lagran；自定义安装请同步修改。')
  lines.push('CERT_DIR=/var/lib/lagran/certs')
  lines.push('DISK_CACHE_DIR=/var/lib/lagran/cache')
  if (plan.metrics.largeCacheEnabled) {
    lines.push('LARGE_CACHE_DIR=/var/lib/lagran/large-cache')
  }
  lines.push('WAF_RULEPACK_CACHE_DIR=/var/lib/lagran/waf-rulepacks')
  lines.push('# 如需 WAF Geo/ASN 名单，把 MaxMind 数据库放到下列路径（启动时加载）：')
  lines.push('# GEOIP_COUNTRY_DB=/var/lib/lagran/maxmind/GeoLite2-Country.mmdb')
  lines.push('# GEOIP_ASN_DB=/var/lib/lagran/maxmind/GeoLite2-ASN.mmdb')
  lines.push('')

  lines.push('# ---------------------------------- 共享 Redis 与密钥')
  if (redisUrl) {
    lines.push('# 共享 Redis：CC 计数与分布式限流用它跨节点共享；区域实例即可，无需与控制面同一台。')
    lines.push(envLine('REDIS_URL', redisUrl))
    if (redisBackend && !cacheRedisUrl) {
      lines.push('# CACHE_BACKEND=redis 且未单独指定，L2 缓存与合并锁复用上面的 REDIS_URL。')
    }
  } else {
    lines.push('# 未配置 REDIS_URL：CC 计数与分布式限流为单节点状态；多节点部署请填写区域 Redis。')
    lines.push('# REDIS_URL=redis://127.0.0.1:6379/0')
  }
  if (cacheRedisUrl) {
    if (redisBackend) {
      lines.push('# 专用于 L2 共享缓存。')
      lines.push(envLine('CACHE_REDIS_URL', cacheRedisUrl))
    } else {
      lines.push('# 当前 CACHE_BACKEND 未使用 Redis L2；改为 redis 后启用下面的地址。')
      lines.push(`# CACHE_REDIS_URL=${cacheRedisUrl}`)
    }
  } else if (redisBackend) {
    lines.push('# 留空则复用 REDIS_URL；想给缓存单独一个库时在这里填写。')
    lines.push('# CACHE_REDIS_URL=')
  } else {
    lines.push('# 仅当 CACHE_BACKEND=redis 时启用；留空复用 REDIS_URL。')
    lines.push('# CACHE_REDIS_URL=')
  }
  if (input.challengeSecret.trim()) {
    lines.push('# 多节点必须配置同一个 CHALLENGE_SECRET，否则质询无法跨节点通过。')
    lines.push(envLine('CHALLENGE_SECRET', input.challengeSecret.trim()))
  } else {
    lines.push('# [多节点必填] 留空时由各节点自己的 AGENT_TOKEN 派生，跨节点质询会失败。')
    lines.push('# CHALLENGE_SECRET=')
  }
  if (input.wafRulepackSecret.trim()) {
    lines.push('# 必须与控制面 /etc/lagran/control.env 的 WAF_RULEPACK_SECRET 完全一致。')
    lines.push(envLine('WAF_RULEPACK_SECRET', input.wafRulepackSecret.trim()))
  } else {
    lines.push('# [生产必填] 需与控制面 WAF_RULEPACK_SECRET 完全一致，否则签名规则包验签失败。')
    lines.push('# WAF_RULEPACK_SECRET=')
  }
  lines.push('')

  lines.push('# ----------------------------------------- 日志')
  lines.push('RUST_LOG=lagran_edge=info,edge=info,tower_http=info')
  lines.push('ACCESS_LOG_PATH=/var/lib/lagran/access.log')
  lines.push('')
  lines.push('# 前置代理（可选）：只有 Edge 前面还有 SLB / Cloudflare 时才填写可信网段。')
  lines.push('# TRUSTED_PROXIES=10.0.0.0/8,2400:cb00::/32')
  lines.push('# 未列出的参数保持 Edge 默认值；完整清单见仓库根目录 edge.env.example。')
  lines.push('# 应用后可在节点上执行 `lagran-edge check-config` 校验 CONTROL_URL 与管理面监听。')

  return `${lines.join('\n')}\n`
}

/** Shell snippet that installs the generated file and restarts the service. */
export const EDGE_ENV_INSTALL_STEPS = `# 1) 把 edge.env 上传到节点，落到固定路径并收紧权限
sudo install -d -m 0750 /etc/lagran
sudo install -m 600 ./edge.env /etc/lagran/edge.env

# 2) 重启并确认启动摘要（首次心跳约 15 秒内出现）
sudo systemctl restart lagran-edge
sudo systemctl status lagran-edge --no-pager -l
sudo journalctl -u lagran-edge -n 30 --no-pager`

/** Check the file without binding any port. */
export const EDGE_ENV_CHECK_STEPS = `# 只解析配置、不监听端口（在节点上执行；二进制路径按实际安装位置调整）
sudo sh -c 'set -a; . /etc/lagran/edge.env; set +a; exec /opt/lagran/bin/lagran-edge check-config'`
