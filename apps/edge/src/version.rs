//! Build version stamped by `build.rs` at compile time.

pub const GIT_HASH: &str = env!("LAGRAN_GIT_HASH");
pub const VERSION: &str = env!("LAGRAN_BUILD_VERSION");
