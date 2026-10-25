export function formatNumber(value?: number | null): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—'
  return value.toLocaleString('zh-CN')
}

export function formatBytes(value?: number | null): string {
  if (!value || value <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let n = value
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i += 1
  }
  return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n)
}

export function formatDateTime(input?: string | null): string {
  if (!input) return '—'
  const d = new Date(input)
  if (Number.isNaN(d.getTime())) return String(input).slice(0, 19).replace('T', ' ')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
    d.getHours(),
  )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export function formatDay(input?: string | null): string {
  if (!input) return '—'
  const d = new Date(input)
  if (Number.isNaN(d.getTime())) return String(input).slice(0, 10)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

export function fromNow(input?: string | null): string {
  if (!input) return '—'
  const d = new Date(input)
  if (Number.isNaN(d.getTime())) return '—'
  const diff = Date.now() - d.getTime()
  if (diff < 0) return '刚刚'
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return '刚刚'
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min} 分钟前`
  const hour = Math.floor(min / 60)
  if (hour < 24) return `${hour} 小时前`
  const day = Math.floor(hour / 24)
  if (day < 30) return `${day} 天前`
  return formatDay(input)
}

export function percent(value?: number | null): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—'
  return `${(value * 100).toFixed(1)}%`
}

export function daysLeft(iso?: string | null): number | null {
  if (!iso) return null
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return null
  return Math.ceil((d.getTime() - Date.now()) / 86400000)
}
