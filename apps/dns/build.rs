use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn main() {
    // A commit changes .git/index and the branch ref; watch both so local
    // builds do not keep a stale hash after committing.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");
    println!("cargo:rerun-if-env-changed=LAGRAN_GIT_HASH");

    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let supplied = std::env::var("LAGRAN_GIT_HASH")
        .ok()
        .map(|s| s.chars().take(7).collect::<String>());
    let mut hash = supplied
        .or_else(|| std::env::var("GITHUB_SHA").ok().map(|s| s.chars().take(7).collect()))
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
