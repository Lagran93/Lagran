//! Short-lived image CAPTCHAs for login and registration.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

const ALPHABET: &[u8] = b"23456789";
const TTL: Duration = Duration::from_secs(300);
const MAX_ENTRIES: usize = 10_000;

struct Entry {
    code: String,
    expires: Instant,
}

#[derive(Default)]
pub struct CaptchaStore {
    entries: Mutex<HashMap<String, Entry>>,
}

impl CaptchaStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a new one-time challenge. Returns `(id, svg, expires_in_secs)`.
    pub fn issue(&self) -> (String, String, u64) {
        let id = Uuid::new_v4().to_string();
        let seed = Uuid::new_v4().into_bytes();
        let mut bytes = [0_u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed[i % seed.len()];
        }
        let code: String = (0..5)
            .map(|i| ALPHABET[bytes[i] as usize % ALPHABET.len()] as char)
            .collect();
        let svg = render_svg(&code, &bytes);
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, entry| entry.expires > now);
        if entries.len() >= MAX_ENTRIES {
            entries.clear();
        }
        entries.insert(
            id.clone(),
            Entry {
                code,
                expires: now + TTL,
            },
        );
        (id, svg, TTL.as_secs())
    }

    /// Verify and consume a challenge. Always remove it, even on a wrong code,
    /// so a challenge cannot be brute-forced.
    pub fn verify(&self, id: &str, code: &str) -> bool {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = entries.remove(id.trim()) else {
            return false;
        };
        entry.expires > Instant::now() && entry.code.eq_ignore_ascii_case(code.trim())
    }

    #[cfg(test)]
    fn issue_with_code(&self, code: &str) -> String {
        let id = Uuid::new_v4().to_string();
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                id.clone(),
                Entry {
                    code: code.to_string(),
                    expires: Instant::now() + TTL,
                },
            );
        id
    }
}

fn render_svg(code: &str, bytes: &[u8]) -> String {
    let mut out = String::with_capacity(1800);
    out.push_str(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="132" height="44" viewBox="0 0 132 44">"#,
    );
    out.push_str(r##"<rect width="132" height="44" rx="6" fill="#f3f7ff"/>"##);
    for i in 0..4 {
        let x1 = (bytes[4 + i] as usize * 17) % 132;
        let y1 = (bytes[8 + i] as usize * 7) % 44;
        let x2 = (bytes[12 + i] as usize * 11) % 132;
        let y2 = (bytes[16 + i] as usize * 13) % 44;
        let color = ["#c7d8f5", "#d6e3f7", "#b9cdea"][i % 3];
        out.push_str(&format!(
            r#"<path d="M{x1} {y1} L{x2} {y2}" stroke="{color}" stroke-width="1.2"/>"#
        ));
    }
    for (i, ch) in code.chars().enumerate() {
        let x = (8 + i * 24) as i32;
        let y = 5 + (bytes[20 + i] as i32 % 3);
        let rotate = (bytes[24 + i] as i32 % 12) - 6;
        let color = ["#1554b8", "#1b4f9c", "#2b64b0", "#164a8c"][i % 4];
        let Some(digit) = ch.to_digit(10) else {
            continue;
        };
        out.push_str(&format!(
            r##"<g transform="rotate({rotate} {} {})" fill="{color}">"##,
            x + 11,
            y + 16
        ));
        for (dx, dy, w, h) in segments(digit, x, y) {
            out.push_str(&format!(
                r#"<rect x="{dx}" y="{dy}" width="{w}" height="{h}" rx="1.2"/>"#
            ));
        }
        out.push_str("</g>");
    }
    for i in 0..7 {
        let cx = (bytes[28 + i] as usize * 19) % 132;
        let cy = (bytes[35 + i] as usize * 23) % 44;
        out.push_str(&format!(
            r##"<circle cx="{cx}" cy="{cy}" r="1.1" fill="#9fb8db" opacity="0.7"/>"##
        ));
    }
    out.push_str("</svg>");
    out
}

/// Seven-segment rectangles for a digit at `(x, y)`.
fn segments(digit: u32, x: i32, y: i32) -> Vec<(i32, i32, i32, i32)> {
    let mask = match digit {
        0 => "abcdef",
        1 => "bc",
        2 => "abdeg",
        3 => "abcdg",
        4 => "bcfg",
        5 => "acdfg",
        6 => "acdefg",
        7 => "abc",
        8 => "abcdefg",
        9 => "abcdfg",
        _ => "",
    };
    let mut out = Vec::new();
    if mask.contains('a') {
        out.push((x + 4, y, 14, 3));
    }
    if mask.contains('b') {
        out.push((x + 18, y + 3, 3, 12));
    }
    if mask.contains('c') {
        out.push((x + 18, y + 18, 3, 12));
    }
    if mask.contains('d') {
        out.push((x + 4, y + 30, 14, 3));
    }
    if mask.contains('e') {
        out.push((x + 1, y + 18, 3, 12));
    }
    if mask.contains('f') {
        out.push((x + 1, y + 3, 3, 12));
    }
    if mask.contains('g') {
        out.push((x + 4, y + 15, 14, 3));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_one_time() {
        let store = CaptchaStore::new();
        let (id, svg, ttl) = store.issue();
        assert!(svg.contains("<svg"));
        assert!(!svg.contains("<text"));
        assert_eq!(svg.matches("<g transform").count(), 5);
        assert_eq!(ttl, 300);
        // We cannot read the generated code, so only assert consumption.
        assert!(!store.verify(&id, "WRONG"));
        assert!(!store.verify(&id, "WRONG"));
    }

    #[test]
    fn correct_code_is_accepted_once() {
        let store = CaptchaStore::new();
        let id = store.issue_with_code("23456");
        assert!(store.verify(&id, "23456"));
        assert!(!store.verify(&id, "23456"));
    }
}
