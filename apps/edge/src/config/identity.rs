//! Node identity for the control plane and for the `CDN-Loop` chain.
//!
//! Two concepts are deliberately kept apart:
//!
//! * [`NodeIdentity::node_id`] — the control-plane identity (`NODE_ID`). The
//!   heartbeat, access log and metrics all report it, and the control plane
//!   only accepts a token whose node name matches. It is therefore *not*
//!   something this module may silently rewrite when the operator did set it.
//! * [`NodeIdentity::loop_id`] — the value stamped into `CDN-Loop` /
//!   `X-Lagran-Shield-Hops`. Loop detection compares this value against the
//!   chain forwarded by the previous hop, so it has to be unique **per machine**.
//!
//! The old code used `NODE_ID` for both, with a fallback of the literal
//! `"edge-001"`. Every edge that did not set `NODE_ID` — and every operator who
//! copied one env file to several hosts — stamped the same id, so the second
//! edge in an Origin Shield chain found its "own" id in the incoming chain and
//! answered `508 Loop Detected` to valid traffic. That is a topology deadlock
//! that needs no attacker at all.
//!
//! The fix: a per-machine instance token, generated on first start and
//! persisted to `NODE_ID_FILE` (default `./data/edge-node-id`), is appended to
//! the loop id. `loop_id` is therefore unique even when `NODE_ID` is absent or
//! duplicated, while `node_id` keeps whatever the control plane expects.
//!
//! If the file cannot be written the process falls back to a per-boot random
//! token and logs a warning. Loop ids are only compared within one request
//! chain, so a token that changes across restarts is still correct; it just
//! stops matching chains stamped by the previous process (which cannot be in
//! flight anyway).

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;

use ring::rand::SecureRandom;

/// Entropy of the per-machine instance token. 8 bytes (16 hex chars) makes a
/// collision inside one cluster practically impossible while keeping the value
/// short enough to stay readable in a header and in logs.
const INSTANCE_BYTES: usize = 8;
/// Default location of the persisted instance token.
pub const DEFAULT_NODE_ID_FILE: &str = "./data/edge-node-id";
/// Shortest / longest persisted token accepted from disk.
const MIN_TOKEN_LEN: usize = 8;
const MAX_TOKEN_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// Control-plane node name.
    pub node_id: String,
    /// `CDN-Loop` id: `node_id` plus the per-machine instance token.
    pub loop_id: String,
    /// False when `NODE_ID` was unset and [`NodeIdentity::node_id`] is a
    /// generated machine id, which the control plane will not recognise.
    pub node_id_configured: bool,
}

/// Resolve the identity from an explicit `NODE_ID` (if any) and the instance
/// file path.
pub fn resolve(explicit: Option<&str>, file: &str) -> NodeIdentity {
    let instance = load_or_create_instance(file);
    match explicit.map(str::trim).filter(|value| !value.is_empty()) {
        Some(node_id) => NodeIdentity {
            loop_id: format!("{node_id}-{instance}"),
            node_id: node_id.to_string(),
            node_id_configured: true,
        },
        // No control-plane name: use the machine id for both. It cannot
        // collide with another node, which is the property the loop guard
        // needs; registration will still fail until NODE_ID is set.
        None => NodeIdentity {
            node_id: format!("edge-{instance}"),
            loop_id: format!("edge-{instance}"),
            node_id_configured: false,
        },
    }
}

fn load_or_create_instance(file: &str) -> String {
    let path = Path::new(file);
    if let Some(token) = read_token(path) {
        return token;
    }
    let proposed = random_token();
    match persist(path, &proposed) {
        Ok(token) => token,
        Err(error) => {
            tracing::warn!(
                path = %path.display(),
                %error,
                "could not persist the edge instance id; using a per-boot id \
                 (CDN-Loop ids will change on restart)"
            );
            proposed
        }
    }
}

fn read_token(path: &Path) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let token = raw.trim();
    valid_token(token).then(|| token.to_string())
}

fn valid_token(token: &str) -> bool {
    (MIN_TOKEN_LEN..=MAX_TOKEN_LEN).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Persist `proposed` and return the token that is actually in the file.
///
/// `create_new` makes two processes starting at the same moment race safely:
/// the loser reads the winner's token instead of overwriting it, so the two
/// workers of one host cannot disagree about the machine identity.
fn persist(path: &Path, proposed: &str) -> std::io::Result<String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            file.write_all(format!("{proposed}\n").as_bytes())?;
            file.sync_all()?;
            Ok(proposed.to_string())
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => match read_token(path) {
            // Another process won the race; adopt its identity.
            Some(existing) => Ok(existing),
            // The file exists but is unusable (truncated, hand-edited): replace
            // it rather than re-generating on every boot.
            None => {
                fs::write(path, format!("{proposed}\n"))?;
                Ok(proposed.to_string())
            }
        },
        Err(error) => Err(error),
    }
}

fn random_token() -> String {
    use std::fmt::Write as _;

    let mut bytes = [0u8; INSTANCE_BYTES];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .expect("system random is available");
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(token, "{byte:02x}");
    }
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lagran-node-id-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("edge-node-id")
    }

    #[test]
    fn generated_identity_is_persistent_and_not_the_old_default() {
        let path = temp_path("generated");
        let file = path.to_string_lossy().to_string();

        let first = resolve(None, &file);
        assert!(!first.node_id_configured);
        assert_ne!(first.node_id, "edge-001");
        assert!(first.node_id.starts_with("edge-"));
        assert_eq!(first.loop_id, first.node_id);

        // A restart must keep the chain identity.
        let second = resolve(None, &file);
        assert_eq!(second, first);
        assert!(path.is_file());
        fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn explicit_node_id_keeps_the_control_plane_name() {
        let path = temp_path("explicit");
        let file = path.to_string_lossy().to_string();

        let identity = resolve(Some("edge-hk-01"), &file);
        assert!(identity.node_id_configured);
        assert_eq!(identity.node_id, "edge-hk-01");
        assert!(
            identity.loop_id.starts_with("edge-hk-01-"),
            "loop id must keep the readable node name: {}",
            identity.loop_id
        );
        assert_ne!(identity.loop_id, identity.node_id);
        fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// The reported defect: two hosts that share one `NODE_ID` (a copied env
    /// file, or the old `edge-001` default) must not share a loop id, or each
    /// one sees "its own" id in the forwarded chain and answers 508.
    #[test]
    fn duplicated_node_ids_get_distinct_loop_ids() {
        let a_path = temp_path("dup-a");
        let b_path = temp_path("dup-b");

        let a = resolve(Some("edge-001"), &a_path.to_string_lossy());
        let b = resolve(Some("edge-001"), &b_path.to_string_lossy());

        assert_eq!(a.node_id, b.node_id);
        assert_ne!(a.loop_id, b.loop_id);
        assert_ne!(a.loop_id, b.node_id);
        assert_ne!(b.loop_id, a.node_id);

        fs::remove_dir_all(a_path.parent().unwrap()).ok();
        fs::remove_dir_all(b_path.parent().unwrap()).ok();
    }

    #[test]
    fn blank_node_id_is_treated_as_unset() {
        let path = temp_path("blank");
        let identity = resolve(Some("   "), &path.to_string_lossy());
        assert!(!identity.node_id_configured);
        assert!(identity.node_id.starts_with("edge-"));
        fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn corrupted_instance_file_is_replaced() {
        let path = temp_path("corrupt");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "\u{0}\nnot a token\n").unwrap();

        let identity = resolve(Some("edge-1"), &path.to_string_lossy());
        // A fresh token was written, so the id is stable from now on.
        let again = resolve(Some("edge-1"), &path.to_string_lossy());
        assert_eq!(identity.loop_id, again.loop_id);
        fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn unwritable_location_still_yields_a_usable_id() {
        // A directory cannot be opened as a file; the fallback must not panic
        // or return an empty id.
        let dir =
            std::env::temp_dir().join(format!("lagran-node-id-unwritable-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        let identity = resolve(Some("edge-1"), &dir.to_string_lossy());
        assert!(identity.loop_id.starts_with("edge-1-"));
        assert!(identity.loop_id.len() > "edge-1-".len());
        fs::remove_dir_all(&dir).ok();
    }
}
