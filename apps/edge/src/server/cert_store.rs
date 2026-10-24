//! Hot-reloadable multi-cert store with SNI resolution

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Clone, Default)]
pub struct CertStore {
    inner: Arc<RwLock<StoreInner>>,
}

#[derive(Default)]
struct StoreInner {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

impl CertStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&self, names: &[String], cert_pem: &[u8], key_pem: &[u8]) -> Result<(), String> {
        let ck = Arc::new(parse_certified_key(cert_pem, key_pem)?);
        let mut w = self.inner.write().map_err(|e| e.to_string())?;
        for n in names {
            let key = n.to_lowercase();
            tracing::info!(server_name = %key, "cert upsert (SNI)");
            w.by_name.insert(key, ck.clone());
        }
        if w.default.is_none() {
            w.default = Some(ck);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|g| g.by_name.len()).unwrap_or(0)
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

    let key: PrivateKeyDer<'static> = key;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| format!("signing key: {e:?}"))?;
    Ok(CertifiedKey::new(certs, signing))
}
