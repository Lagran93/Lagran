//! Module-level permissions used by user groups.
//!
//! Permissions are strings such as `domain:read` or `waf:write`. The union of
//! a user's groups is checked by the API permission middleware. Project
//! membership still scopes every project/domain, so a permission never grants
//! cross-tenant access.

pub const ALL: &[(&str, &str)] = &[
    ("domain:read", "查看域名"),
    ("domain:write", "新增/编辑/停用/删除域名"),
    ("cache:read", "查看缓存规则与诊断"),
    ("cache:write", "编辑缓存规则、刷新与预热"),
    ("waf:read", "查看 WAF/CC 配置与事件"),
    ("waf:write", "编辑 WAF/CC、封禁与解封"),
    ("cert:read", "查看证书"),
    ("cert:write", "申请/上传/删除证书"),
    ("prefetch:read", "查看预热任务"),
    ("prefetch:write", "创建/修改预热任务"),
    ("project:read", "查看项目与成员"),
    ("project:write", "编辑项目与成员"),
    ("node:read", "查看边缘节点"),
    ("node:write", "新增/编辑/下线节点"),
    ("analytics:read", "查看统计与访问日志"),
    ("config:read", "查看配置版本与发布单"),
    ("config:write", "创建/审批/发布/回滚配置"),
    ("alert:read", "查看告警配置与事件"),
    ("alert:write", "编辑告警渠道与规则"),
    ("audit:read", "查看操作审计"),
    ("settings:read", "查看系统设置"),
    ("settings:write", "修改系统设置与系统更新"),
    ("user:read", "查看用户"),
    ("user:write", "新增/编辑/删除用户与用户组"),
];

pub fn is_valid(permission: &str) -> bool {
    ALL.iter().any(|(name, _)| *name == permission)
}

/// Resolve the module permission for a request path. `None` means the route is
/// not covered (health, auth, public or agent endpoints).
pub fn required_for_path(method: &str, path: &str) -> Option<&'static str> {
    let rest = path.strip_prefix("/api/v1/")?;
    let module = rest.split('/').next().unwrap_or("");
    let read = method == "GET" || method == "HEAD" || method == "OPTIONS";
    let suffix = if read { "read" } else { "write" };
    let module = if rest.starts_with("domains/") && rest.contains("/waf") {
        "waf"
    } else {
        match module {
            "domains" | "origin-health" | "edge-endpoints" => "domain",
            "rules" | "cache" | "purge" => "cache",
            "prefetch" => "prefetch",
            "waf" | "cc" => "waf",
            "certs" => "cert",
            "projects" => "project",
            "nodes" => "node",
            "stats" | "metrics" | "access-logs" | "analytics" => "analytics",
            "config" => "config",
            "alert-channels" | "alert-rules" | "alert-events" | "alerts" => "alert",
            "audit" => "audit",
            "users" | "groups" => "user",
            "system" | "settings" => "settings",
            _ => return None,
        }
    };
    let permission = match (module, suffix) {
        ("analytics", "read") => "analytics:read",
        ("audit", "read") => "audit:read",
        ("node", "read") => "node:read",
        ("node", "write") => "node:write",
        ("domain", "read") => "domain:read",
        ("domain", "write") => "domain:write",
        ("cache", "read") => "cache:read",
        ("cache", "write") => "cache:write",
        ("prefetch", "read") => "prefetch:read",
        ("prefetch", "write") => "prefetch:write",
        ("waf", "read") => "waf:read",
        ("waf", "write") => "waf:write",
        ("cert", "read") => "cert:read",
        ("cert", "write") => "cert:write",
        ("project", "read") => "project:read",
        ("project", "write") => "project:write",
        ("config", "read") => "config:read",
        ("config", "write") => "config:write",
        ("alert", "read") => "alert:read",
        ("alert", "write") => "alert:write",
        ("settings", "read") => "settings:read",
        ("settings", "write") => "settings:write",
        ("user", "read") => "user:read",
        ("user", "write") => "user:write",
        _ => unreachable!("all modules mapped above"),
    };
    Some(permission)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_modules_and_methods() {
        assert_eq!(
            required_for_path("GET", "/api/v1/domains"),
            Some("domain:read")
        );
        assert_eq!(
            required_for_path("POST", "/api/v1/domains"),
            Some("domain:write")
        );
        assert_eq!(
            required_for_path("PUT", "/api/v1/domains/1"),
            Some("domain:write")
        );
        assert_eq!(
            required_for_path("GET", "/api/v1/waf/events"),
            Some("waf:read")
        );
        assert_eq!(
            required_for_path("PUT", "/api/v1/domains/1/waf"),
            Some("waf:write")
        );
        assert_eq!(
            required_for_path("GET", "/api/v1/config"),
            Some("config:read")
        );
        assert_eq!(required_for_path("GET", "/api/v1/auth/me"), None);
        assert!(is_valid("domain:write"));
        assert!(!is_valid("root:everything"));
    }
}
