//! Hot-reloadable multi-cert store with SNI resolution + disk persistence

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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

#[derive(Default)]
struct StoreInner {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
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
            match self.upsert_memory(&[name.clone()], &cert_pem, &key_pem) {
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
            if let Err(e) = std::fs::write(&key, key_pem) {
                tracing::warn!(error = %e, path = %key.display(), "write key failed");
            } else {
                tracing::debug!(server_name = %n, "cert persisted to disk");
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
        let mut w = self.inner.write().map_err(|e| e.to_string())?;
        for n in names {
            let key = n.to_lowercase();
            w.by_name.insert(key, ck.clone());
        }
        if w.default.is_none() {
            w.default = Some(ck);
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

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.by_name.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

    let key = PrivateKeyDer::from(key);
    let provider = rustls::crypto::ring::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("load private key: {e}"))?;

    Ok(CertifiedKey::new(certs, signing_key))
}
