/**
 * Convert backend/user-facing error codes into concise Chinese hints.
 *
 * The control plane still keeps English messages for API clients and logs, but
 * console users should not see raw strings such as "domain already exists".
 */
const EXACT: Record<string, string> = {
  'domain already exists': '该域名已经接入，请勿重复添加',
  'node name already exists': '节点名称已存在，请更换名称',
  'password must contain letters and digits': '密码必须同时包含字母和数字',
  'password must be at least 8 characters': '密码至少需要 8 个字符',
  'invalid email': '邮箱格式不正确',
  'email already registered': '该邮箱已经注册，请直接登录或更换邮箱',
  'invalid email or password': '邮箱或密码错误',
  'account is disabled': '账号已被禁用，请联系管理员',
  'user is disabled': '账号已被禁用，请联系管理员',
  forbidden: '没有权限执行该操作',
  'admin only': '仅管理员可以执行该操作',
  'domain not found': '域名不存在或已被删除',
  'domain is required': '请选择域名',
  'node not found': '节点不存在或已被删除',
  'user not found': '用户不存在或已被删除',
  'member not found': '项目成员不存在',
  'not found': '目标不存在或已被删除',
  'not found or not owner': '目标不存在，或你不是该项目的所有者',
  'invalid token': '登录状态已失效，请重新登录',
  'token error': '登录状态异常，请重新登录',
  'session expired': '登录状态已过期，请重新登录',
  'database error': '服务暂时不可用，请稍后重试',
  'config serialization error': '配置序列化失败，请检查配置内容',
  'hash error': '密码处理失败，请稍后重试',
  'too many login attempts, try again later': '登录尝试过于频繁，请稍后再试',
  'too many registration attempts, try again later': '注册尝试过于频繁，请稍后再试',
  'current password is incorrect': '当前密码不正确',
  'registration is disabled': '当前未开放自助注册',
  'name and at least one origin are required': '请填写名称和至少一个源站',
  'name required': '请填写名称',
  'name is too long': '名称过长',
  'name must be 1-64 characters': '名称长度需为 1-64 个字符',
  'invalid project_id': '项目不存在或已失效',
  'invalid domain_id': '域名不存在或已失效',
  'invalid id': 'ID 格式不正确',
  'invalid node id': '节点不存在或已失效',
  'invalid ip': 'IP 地址格式不正确',
  'invalid ip or cidr': 'IP 或 CIDR 格式不正确',
  'domain and paths required': '请选择域名并填写路径',
  'domain_name required': '请填写域名',
  'no active cert': '没有可用证书',
  'role must be member or admin': '角色必须为 member 或 admin',
  'status must be active or disabled': '状态必须为 active 或 disabled',
  'cc_mode must be block or monitor': 'CC 模式必须为 block 或 monitor',
  'shield_url must start with http:// or https://':
    'Origin Shield 地址必须以 http:// 或 https:// 开头',
  'shield_url must be selected from the administrator-configured shield nodes':
    '请从管理员配置的 Shield 节点中选择',
  'shield url already exists': '该 Shield 地址已经存在',
  'shield node not found': 'Shield 节点不存在或已被删除',
  'shield url is required': '请填写 Shield 地址',
  'shield url is too long': 'Shield 地址过长',
  'invalid shield url': 'Shield 地址格式不正确',
  'shield url must include http:// or https://':
    'Shield 地址必须包含 http:// 或 https://',
  'shield url must use http:// or https://':
    'Shield 地址必须使用 http:// 或 https://',
  'shield url must include a host': 'Shield 地址缺少主机名',
  'shield url must not contain credentials': 'Shield 地址不能包含账号密码',
  'shield url must not contain query or fragment':
    'Shield 地址不能包含查询串或 fragment',
  'shield url must be an origin without a path': 'Shield 地址不能包含路径',
  'name is required': '请填写名称',
  'name must be at most 64 characters': '名称不能超过 64 个字符',
  'schedule not found': '调度记录不存在',
  'user is the project owner': '不能移除项目所有者',
  'cannot remove the project owner': '不能移除项目所有者',
  'cannot change the project owner': '不能修改项目所有者',
  'only an admin can unassign a domain': '仅管理员可以取消域名归属',
  'acme directory is not configured': 'ACME 目录未配置',
}

const PATTERNS: Array<[RegExp, (match: RegExpMatchArray) => string]> = [
  [/^unsupported method:\s*(.+)$/i, (m) => `不支持的请求方法：${m[1]}`],
  [/^invalid regex:\s*(.+)$/i, (m) => `规则正则无效：${m[1]}`],
  [/^path_pattern required$/i, () => '请填写路径匹配规则'],
  [/^path_pattern must start with \/$/i, () => '路径规则必须以 / 开头'],
  [/^invalid release version$/i, () => '版本号格式不正确'],
  [/^invalid latest release tag$/i, () => '最新 Release 的版本号格式不正确'],
  [/^HTTP\s+(\d+)$/i, (m) => `服务返回异常状态（HTTP ${m[1]}），请稍后重试`],
  [/^shield node is used by (\d+) domain\(s\); update those domains first$/i,
    (m) => `该 Shield 节点仍被 ${m[1]} 个域名使用，请先修改这些域名`],
]

export function friendlyErrorMessage(input: unknown, fallback = '操作失败，请稍后重试'): string {
  const raw = typeof input === 'string' ? input.trim() : ''
  if (!raw) return fallback

  const exact = EXACT[raw.toLowerCase()]
  if (exact) return exact

  for (const [pattern, render] of PATTERNS) {
    const match = raw.match(pattern)
    if (match) return render(match)
  }

  // Preserve Chinese messages from backend/validation.
  if (/[\u4e00-\u9fff]/.test(raw)) return raw

  // Unknown English diagnostics should not leak into the console UI.
  return fallback
}
