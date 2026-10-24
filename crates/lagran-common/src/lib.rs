//! Shared utilities and error types for Lagran

pub mod config;
pub mod utils;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LagranError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, LagranError>;
