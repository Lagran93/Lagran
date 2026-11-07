//! Curated managed WAF rulesets.
//!
//! A ruleset is a versioned set of the existing signature categories. Selecting
//! a ruleset never weakens explicit per-category switches: the effective config
//! is the union of both. That keeps a domain protected when a ruleset is
//! updated centrally, while still allowing operators to enable extra checks.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RulesetCategory {
    pub key: &'static str,
    pub label: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ManagedRuleset {
    pub id: &'static str,
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    /// low | medium | high
    pub severity: &'static str,
    pub recommended: bool,
    pub categories: &'static [&'static str],
    pub category_labels: &'static [&'static str],
}

const OWASP_CORE: &[&str] = &[
    "sqli",
    "xss",
    "traversal",
    "scanners",
    "rce",
    "ssrf",
    "xxe",
    "log4shell",
    "crlf",
    "protocol",
];
const OWASP_LABELS: &[&str] = &[
    "SQL 注入",
    "XSS",
    "路径穿越",
    "扫描器",
    "命令执行",
    "SSRF",
    "XXE",
    "Log4Shell",
    "CRLF",
    "协议异常",
];

const INJECTION_EXTENDED: &[&str] = &["ssti", "nosql", "ldap", "java", "webshell"];
const INJECTION_LABELS: &[&str] = &[
    "模板注入",
    "NoSQL 注入",
    "LDAP 注入",
    "Java 反序列化",
    "WebShell",
];

const SSRF_XXE: &[&str] = &["ssrf", "xxe"];
const SSRF_XXE_LABELS: &[&str] = &["SSRF / 云元数据", "XXE 外部实体"];

const SCANNER_GUARD: &[&str] = &["scanners", "protocol"];
const SCANNER_GUARD_LABELS: &[&str] = &["扫描器与敏感路径", "协议异常"];

pub const CATALOG: &[ManagedRuleset] = &[
    ManagedRuleset {
        id: "owasp-core",
        name: "OWASP 核心防护",
        version: "2026.11",
        description: "覆盖 SQL 注入、XSS、路径穿越、命令执行、SSRF、XXE、Log4Shell 与协议异常。",
        severity: "high",
        recommended: true,
        categories: OWASP_CORE,
        category_labels: OWASP_LABELS,
    },
    ManagedRuleset {
        id: "injection-extended",
        name: "注入扩展防护",
        version: "2026.11",
        description: "补充模板注入、NoSQL、LDAP、Java 反序列化与 WebShell 特征。",
        severity: "high",
        recommended: true,
        categories: INJECTION_EXTENDED,
        category_labels: INJECTION_LABELS,
    },
    ManagedRuleset {
        id: "ssrf-xxe",
        name: "SSRF / XXE 防护",
        version: "2026.11",
        description: "针对云元数据访问、内网探测与外部实体注入的专项规则。",
        severity: "medium",
        recommended: false,
        categories: SSRF_XXE,
        category_labels: SSRF_XXE_LABELS,
    },
    ManagedRuleset {
        id: "scanner-guard",
        name: "扫描器与协议基线",
        version: "2026.11",
        description: "拦截常见漏洞扫描器 UA、敏感探测路径、空字节和超长请求。",
        severity: "low",
        recommended: false,
        categories: SCANNER_GUARD,
        category_labels: SCANNER_GUARD_LABELS,
    },
];

pub fn catalog() -> &'static [ManagedRuleset] {
    CATALOG
}

pub fn find(id: &str) -> Option<&'static ManagedRuleset> {
    let id = id.trim();
    CATALOG.iter().find(|r| r.id == id)
}

/// Validate a user-provided list and return canonical ids in catalog order.
pub fn validate_ids(ids: &[String]) -> Result<Vec<String>, String> {
    let mut selected = Vec::new();
    for raw in ids {
        let id = raw.trim();
        if id.is_empty() {
            continue;
        }
        if find(id).is_none() {
            return Err(format!("unknown managed ruleset: {id}"));
        }
        if !selected.iter().any(|existing| existing == id) {
            selected.push(id.to_string());
        }
    }
    selected.sort_by_key(|id| {
        CATALOG
            .iter()
            .position(|r| r.id == id.as_str())
            .unwrap_or(usize::MAX)
    });
    Ok(selected)
}

/// Parse the persisted comma-separated form, ignoring stale/unknown ids.
pub fn parse_csv(value: &str) -> Vec<String> {
    let mut result = Vec::new();
    for part in value.split(',') {
        let id = part.trim();
        if id.is_empty() || find(id).is_none() || result.iter().any(|x| x == id) {
            continue;
        }
        result.push(id.to_string());
    }
    result
}

#[derive(Debug, Clone, Default)]
pub struct Categories {
    pub sqli: bool,
    pub xss: bool,
    pub traversal: bool,
    pub scanners: bool,
    pub rce: bool,
    pub ssrf: bool,
    pub xxe: bool,
    pub log4shell: bool,
    pub crlf: bool,
    pub ssti: bool,
    pub nosql: bool,
    pub ldap: bool,
    pub java: bool,
    pub webshell: bool,
    pub protocol: bool,
}

impl Categories {
    pub fn with(mut self, id: &str) -> Self {
        let Some(ruleset) = find(id) else {
            return self;
        };
        for category in ruleset.categories {
            self = self.enable(category);
        }
        self
    }

    /// Enable one signature category by its canonical name.
    pub fn enable(mut self, category: &str) -> Self {
        match category {
            "sqli" => self.sqli = true,
            "xss" => self.xss = true,
            "traversal" => self.traversal = true,
            "scanners" => self.scanners = true,
            "rce" => self.rce = true,
            "ssrf" => self.ssrf = true,
            "xxe" => self.xxe = true,
            "log4shell" => self.log4shell = true,
            "crlf" => self.crlf = true,
            "ssti" => self.ssti = true,
            "nosql" => self.nosql = true,
            "ldap" => self.ldap = true,
            "java" => self.java = true,
            "webshell" => self.webshell = true,
            "protocol" => self.protocol = true,
            _ => {}
        }
        self
    }

    pub fn from_csv(value: &str) -> Self {
        let mut categories = Self::default();
        for id in value.split(',') {
            categories = categories.with(id.trim());
        }
        categories
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique_and_valid() {
        let mut seen = std::collections::HashSet::new();
        for ruleset in CATALOG {
            assert!(seen.insert(ruleset.id));
            assert!(!ruleset.categories.is_empty());
            assert_eq!(ruleset.categories.len(), ruleset.category_labels.len());
        }
    }

    #[test]
    fn validates_and_orders_ids() {
        let ids = vec![
            "scanner-guard".to_string(),
            "unknown".to_string(),
        ];
        assert!(validate_ids(&ids).is_err());
        let ids = vec!["scanner-guard".to_string(), "owasp-core".to_string()];
        let out = validate_ids(&ids).unwrap();
        assert_eq!(out, vec!["owasp-core", "scanner-guard"]);
    }

    #[test]
    fn categories_union() {
        let c = Categories::from_csv("owasp-core,injection-extended");
        assert!(c.sqli && c.ssti && c.webshell && c.ssrf);
        let c = c.with("ssrf-xxe");
        assert!(c.ssrf && c.xxe);
    }
}
