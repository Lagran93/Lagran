//! In-memory ACME HTTP-01 challenge tokens (pushed from control)

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Clone, Default)]
pub struct ChallengeStore {
    // token -> key_authorization
    map: Arc<RwLock<HashMap<String, String>>>,
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, token: &str, key_auth: &str) {
        if let Ok(mut w) = self.map.write() {
            w.insert(token.to_string(), key_auth.to_string());
        }
    }

    pub fn get(&self, token: &str) -> Option<String> {
        self.map.read().ok()?.get(token).cloned()
    }

    pub fn remove(&self, token: &str) {
        if let Ok(mut w) = self.map.write() {
            w.remove(token);
        }
    }
}
