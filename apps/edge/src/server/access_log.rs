//! Simple access log line to stdout (and optional file)

use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct AccessLog {
    file: Arc<Mutex<Option<tokio::fs::File>>>,
}

impl AccessLog {
    pub async fn open(path: Option<&str>) -> Self {
        let file = if let Some(p) = path {
            if !p.is_empty() {
                let path = PathBuf::from(p);
                if let Some(parent) = path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                match tokio::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .await
                {
                    Ok(f) => {
                        tracing::info!(path = %path.display(), "access log file opened");
                        Some(f)
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "access log file open failed");
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };
        Self {
            file: Arc::new(Mutex::new(file)),
        }
    }

    pub async fn write(&self, line: &str) {
        tracing::info!(target: "access", "{line}");
        let mut guard = self.file.lock().await;
        if let Some(f) = guard.as_mut() {
            let _ = f.write_all(line.as_bytes()).await;
            let _ = f.write_all(b"\n").await;
        }
    }
}
