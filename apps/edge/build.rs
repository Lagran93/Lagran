use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Accept a release tag such as `v0.1.5` and return `0.1.5`. Plain branch
/// names (e.g. `main`) are ignored so local/PR builds keep Cargo's version.
fn normalize_version(raw: &str) -> Option<String> {
    let value = raw.trim().trim_start_matches('v');
    if value.is_empty() {
        return None;
    }
    let core = value.split(['+', '-']).next()?;
    let mut parts = core.split('.');
    parts.next()?.parse::<u64>().ok()?;
    parts.next()?.parse::<u64>().ok()?;
    parts.next()?.parse::<u64>().ok()?;
    Some(value.to_string())
}

fn main() {
    // A commit changes .git/index and the branch ref; watch both so local
    // builds do not keep a stale hash after committing.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    println!("cargo:rerun-if-env-changed=LAGRAN_GIT_HASH");
    println!("cargo:rerun-if-env-changed=LAGRAN_BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=LAGRAN_VERSION");
    println!("cargo:rerun-if-env-changed=GITHUB_REF_NAME");

    // Release builds must carry the release tag, not the static workspace
    // package version. CI supplies LAGRAN_BUILD_VERSION; tag builds also expose
    // GITHUB_REF_NAME, which is enough for a local `git checkout v0.1.5` build.
    let version = std::env::var("LAGRAN_BUILD_VERSION")
        .ok()
        .and_then(|v| normalize_version(&v))
        .or_else(|| {
            std::env::var("LAGRAN_VERSION")
                .ok()
                .and_then(|v| normalize_version(&v))
        })
        .or_else(|| {
            std::env::var("GITHUB_REF_NAME")
                .ok()
                .and_then(|v| normalize_version(&v))
        })
        .unwrap_or_else(|| std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into()));
    let supplied = std::env::var("LAGRAN_GIT_HASH")
        .ok()
        .map(|s| s.chars().take(7).collect::<String>());
    let mut hash = supplied
        .or_else(|| {
            std::env::var("GITHUB_SHA")
                .ok()
                .map(|s| s.chars().take(7).collect())
        })
        .or_else(|| git(&["rev-parse", "--short=7", "HEAD"]))
        .unwrap_or_else(|| "unknown".into());

    if std::env::var("LAGRAN_GIT_HASH").is_err() {
        if let Some(dirty) = git(&["status", "--porcelain", "--untracked-files=no"]) {
            if !dirty.is_empty() {
                hash.push_str("-dirty");
            }
        }
    }

    println!("cargo:rustc-env=LAGRAN_GIT_HASH={hash}");
    println!("cargo:rustc-env=LAGRAN_BUILD_VERSION={version}+{hash}");
}
