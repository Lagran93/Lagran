//! Hot-reloadable multi-cert store with SNI resolution + disk persistence

use pingora::tls::{
    pkey::{PKey, Private},
    x509::X509,
};
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub struct CertStore {
    inner: Arc<RwLock<StoreInner>>,
    dir: Option<PathBuf>,
}

type OpenSslKeyPair = (Arc<X509>, Arc<PKey<Private>>);

#[derive(Default)]
struct StoreInner {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
    /// Parsed certificates for the Pingora/OpenSSL listener. Parsing PEM on
    /// every handshake is expensive and needlessly blocks the TLS accept path.
    openssl: HashMap<String, OpenSslKeyPair>,
    openssl_default: Option<OpenSslKeyPair>,
}

impl CertStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StoreInner::default())),
            dir: None,
        }
    }

    /// Create store and load any PEMs already on disk under `dir`.
    pub fn with_persist_dir(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref().to_path_buf();
        let store = Self {
            inner: Arc::new(RwLock::new(StoreInner::default())),
            dir: Some(dir.clone()),
        };
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::warn!(error = %e, path = %dir.display(), "cert dir create failed");
        } else {
            let n = store.load_from_disk();
            if n > 0 {
                tracing::info!(count = n, path = %dir.display(), "loaded certs from disk");
            } else {
                tracing::info!(path = %dir.display(), "cert persist dir ready (empty)");
            }
        }
        store
    }

    fn load_from_disk(&self) -> usize {
        let Some(ref dir) = self.dir else {
            return 0;
        };
        let Ok(rd) = std::fs::read_dir(dir) else {
            return 0;
        };
        let mut count = 0;
        for ent in rd.flatten() {
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("crt") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if stem.is_empty() {
                continue;
            }
            let key_path = dir.join(format!("{stem}.key"));
            if !key_path.exists() {
                tracing::warn!(cert = %path.display(), "missing matching .key, skip");
                continue;
            }
            let cert_pem = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, "read cert failed");
                    continue;
                }
            };
            let key_pem = match std::fs::read(&key_path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, "read key failed");
                    continue;
                }
            };
            // name from filename: example.com.crt → example.com
            // also support wildcard files written as _star_.example.com
            let name = stem.replace("_star_", "*");
            match self.upsert_memory(std::slice::from_ref(&name), &cert_pem, &key_pem) {
                Ok(()) => {
                    tracing::info!(server_name = %name, "cert loaded from disk");
                    count += 1;
                }
                Err(e) => tracing::warn!(server_name = %name, error = %e, "disk cert parse failed"),
            }
        }
        count
    }

    fn persist_files(&self, names: &[String], cert_pem: &[u8], key_pem: &[u8]) {
        let Some(ref dir) = self.dir else {
            return;
        };
        for n in names {
            let stem = n.replace('*', "_star_").to_lowercase();
            let crt = dir.join(format!("{stem}.crt"));
            let key = dir.join(format!("{stem}.key"));
            if let Err(e) = std::fs::write(&crt, cert_pem) {
                tracing::warn!(error = %e, path = %crt.display(), "write cert failed");
            }
            // The private key must never be world-readable. `fs::write` creates
            // with 0666 minus the process umask, and the packaged systemd unit
            // did not set one, so these files landed as 0644: any local user
            // could read the TLS key for every domain this node serves.
            match write_private(&key, key_pem) {
                Ok(()) => tracing::debug!(server_name = %n, "cert persisted to disk"),
                Err(e) => tracing::warn!(error = %e, path = %key.display(), "write key failed"),
            }
        }
    }

    fn upsert_memory(
        &self,
        names: &[String],
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<(), String> {
        let ck = Arc::new(parse_certified_key(cert_pem, key_pem)?);
        // Parse the OpenSSL representation once while the certificate is
        // installed, never on the connection handshake path.
        let tls_pair: OpenSslKeyPair = (
            Arc::new(X509::from_pem(cert_pem).map_err(|e| format!("parse openssl cert: {e}"))?),
            Arc::new(
                PKey::private_key_from_pem(key_pem)
                    .map_err(|e| format!("parse openssl key: {e}"))?,
            ),
        );
        let mut w = self.inner.write().map_err(|e| e.to_string())?;
        for n in names {
            // Same normalisation as `remove`/`retain_only`: a trailing-dot name
            // written here under a different key could never be removed.
            let key = normalize_cert_name(n);
            w.by_name.insert(key.clone(), ck.clone());
            w.openssl.insert(key, tls_pair.clone());
        }
        if w.default.is_none() {
            w.default = Some(ck);
            w.openssl_default = Some(tls_pair);
        }
        Ok(())
    }

    pub fn upsert(&self, names: &[String], cert_pem: &[u8], key_pem: &[u8]) -> Result<(), String> {
        self.upsert_memory(names, cert_pem, key_pem)?;
        self.persist_files(names, cert_pem, key_pem);
        for n in names {
            tracing::info!(server_name = %n.to_lowercase(), "cert upsert (SNI + disk)");
        }
        Ok(())
    }

    /// Remove one hostname from the in-memory store and from disk.
    ///
    /// Certificates had no removal path: once one reached an edge it stayed in
    /// memory and on disk forever, so deleting or disabling it in the console
    /// never took effect, and a restart simply reloaded the stale file.
    pub fn remove(&self, name: &str) -> bool {
        let key = normalize_cert_name(name);
        let removed = match self.inner.write() {
            Ok(mut w) => {
                let existed = w.by_name.remove(&key).is_some();
                w.openssl.remove(&key);
                // Drop the default when it pointed at this entry, so a removed
                // certificate is not still served to unmatched SNI.
                if existed && w.by_name.is_empty() {
                    w.default = None;
                    w.openssl_default = None;
                }
                existed
            }
            Err(_) => false,
        };
        if removed {
            self.delete_files(&key);
            tracing::info!(server_name = %key, "cert removed (SNI + disk)");
        }
        removed
    }

    /// Keep only `keep`, removing everything else from memory and disk.
    ///
    /// Returns how many entries were removed. Used after a successful bulk sync:
    /// the control plane's active set is authoritative, so anything absent from
    /// it has been deleted or disabled.
    pub fn retain_only(&self, keep: &[String]) -> usize {
        let wanted: std::collections::HashSet<String> =
            keep.iter().map(|n| normalize_cert_name(n)).collect();
        let stale: Vec<String> = match self.inner.read() {
            Ok(g) => g
                .by_name
                .keys()
                .filter(|k| !wanted.contains(*k))
                .cloned()
                .collect(),
            Err(_) => return 0,
        };
        let mut removed = 0;
        for name in stale {
            if self.remove(&name) {
                removed += 1;
            }
        }
        removed
    }

    /// Hostnames currently installed, lowercased.
    pub fn names(&self) -> Vec<String> {
        self.inner
            .read()
            .map(|g| g.by_name.keys().cloned().collect())
            .unwrap_or_default()
    }

    fn delete_files(&self, name: &str) {
        let Some(ref dir) = self.dir else {
            return;
        };
        let stem = name.replace('*', "_star_");
        for ext in ["crt", "key"] {
            let path = dir.join(format!("{stem}.{ext}"));
            match std::fs::remove_file(&path) {
                Ok(()) => tracing::debug!(path = %path.display(), "cert file removed"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    tracing::warn!(error = %e, path = %path.display(), "remove cert file failed")
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.by_name.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Parsed certificate/key for the OpenSSL-based Pingora TLS listener.
    /// Exact SNI first, then `*.example.com`, then the first/default cert.
    pub fn certificate_for(&self, name: &str) -> Option<OpenSslKeyPair> {
        let guard = self.inner.read().ok()?;
        let key = name.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(v) = guard.openssl.get(&key) {
            return Some(v.clone());
        }
        if let Some((_, rest)) = key.split_once('.') {
            if let Some(v) = guard.openssl.get(&format!("*.{rest}")) {
                return Some(v.clone());
            }
        }
        guard.openssl_default.clone()
    }

    pub fn resolver(self: &Arc<Self>) -> Arc<DynResolver> {
        Arc::new(DynResolver {
            store: Arc::clone(self),
        })
    }
}

pub struct DynResolver {
    store: Arc<CertStore>,
}

impl std::fmt::Debug for DynResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynResolver")
            .field("certs", &self.store.len())
            .finish()
    }
}

impl ResolvesServerCert for DynResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let guard = self.store.inner.read().ok()?;
        if let Some(name) = client_hello.server_name() {
            let key = name.to_lowercase();
            if let Some(ck) = guard.by_name.get(&key) {
                return Some(ck.clone());
            }
        }
        guard.default.clone()
    }
}

fn parse_certified_key(cert_pem: &[u8], key_pem: &[u8]) -> Result<CertifiedKey, String> {
    let certs = rustls_pemfile::certs(&mut &*cert_pem)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| format!("parse certs: {e}"))?;
    if certs.is_empty() {
        return Err("no certificates in PEM".into());
    }

    let key = rustls_pemfile::private_key(&mut &*key_pem)
        .map_err(|e| format!("parse key: {e}"))?
        .ok_or_else(|| "no private key in PEM".to_string())?;

    let provider = rustls::crypto::ring::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("load private key: {e}"))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Canonical hostname key used by lookups and removals.
///
/// `upsert` stores lowercased names; removal and retention must use the same
/// form or they would silently miss the entry.
fn normalize_cert_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Write a file readable only by its owner (0600), replacing any existing mode.
///
/// Uses `OpenOptions::mode` on Unix so the permissions apply at creation time:
/// writing first and chmod-ing afterwards leaves a window where the private key
/// is world-readable.
#[cfg(unix)]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    // `mode` is ignored when the file already exists, so normalise it.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::rsa::Rsa;
    use openssl::x509::X509NameBuilder;

    fn test_certificate() -> (Vec<u8>, Vec<u8>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "example.com").unwrap();
        let name = name.build();

        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = builder.build();
        (
            cert.to_pem().unwrap(),
            key.private_key_to_pem_pkcs8().unwrap(),
        )
    }

    #[test]
    fn parsed_certificates_are_shared_across_handshakes() {
        let store = CertStore::new();
        let (cert_pem, key_pem) = test_certificate();
        store
            .upsert(&["*.example.com".to_string()], &cert_pem, &key_pem)
            .unwrap();

        let first = store.certificate_for("a.example.com").unwrap();
        let second = store.certificate_for("b.example.com").unwrap();
        assert!(Arc::ptr_eq(&first.0, &second.0));
        assert!(Arc::ptr_eq(&first.1, &second.1));
    }
    /// Removing a certificate must drop it from memory and from disk.
    ///
    /// Before this existed the store only ever grew, so a certificate deleted or
    /// disabled in the console stayed installed until the process restarted (and
    /// a restart reloaded the stale file).
    #[test]
    fn remove_drops_the_certificate_from_memory_and_disk() {
        let dir = std::env::temp_dir().join(format!("lagran-cert-remove-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = CertStore::with_persist_dir(&dir);
        let (cert, key) = test_certificate();
        store
            .upsert(&["gone.example".to_string()], &cert, &key)
            .unwrap();
        assert_eq!(store.len(), 1);
        assert!(dir.join("gone.example.crt").exists());

        assert!(store.remove("gone.example"));
        assert!(store.is_empty(), "memory entry must be dropped");
        assert!(
            !dir.join("gone.example.crt").exists(),
            "cert file must be deleted"
        );
        assert!(
            !dir.join("gone.example.key").exists(),
            "key file must be deleted"
        );

        // Removing something absent is a no-op, not an error.
        assert!(!store.remove("gone.example"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Name matching must be case- and trailing-dot-insensitive, matching how
    /// upsert stores entries.
    #[test]
    fn remove_normalises_the_name() {
        let store = CertStore::new();
        let (cert, key) = test_certificate();
        store
            .upsert(&["MiXeD.Example.".to_string()], &cert, &key)
            .unwrap();
        assert!(store.remove("mixed.example"));
        assert!(store.is_empty());
    }

    /// A bulk sync must prune everything outside the advertised active set.
    #[test]
    fn retain_only_keeps_the_active_set() {
        let dir = std::env::temp_dir().join(format!("lagran-cert-retain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = CertStore::with_persist_dir(&dir);
        let (cert, key) = test_certificate();
        for name in ["a.example", "b.example", "c.example"] {
            store.upsert(&[name.to_string()], &cert, &key).unwrap();
        }
        assert_eq!(store.len(), 3);

        let removed = store.retain_only(&["a.example".to_string(), "c.example".to_string()]);
        assert_eq!(removed, 1, "only b.example should go");
        let mut names = store.names();
        names.sort();
        assert_eq!(
            names,
            vec!["a.example".to_string(), "c.example".to_string()]
        );
        assert!(!dir.join("b.example.crt").exists());
        assert!(dir.join("a.example.crt").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Emptying the store must clear the default, or a removed certificate keeps
    /// being served to clients whose SNI matches nothing.
    #[test]
    fn removing_the_last_certificate_clears_the_default() {
        let store = CertStore::new();
        let (cert, key) = test_certificate();
        store
            .upsert(&["only.example".to_string()], &cert, &key)
            .unwrap();
        assert!(store.certificate_for("unmatched.example").is_some());
        store.remove("only.example");
        assert!(
            store.certificate_for("unmatched.example").is_none(),
            "default must not outlive the certificate it pointed at"
        );
    }
}
