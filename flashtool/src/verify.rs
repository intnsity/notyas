// SPDX-License-Identifier: GPL-3.0-or-later
// GPG signature verification and SHA256 hash checking.

use crate::key;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

/// Find gpg.exe on PATH or in the default Gpg4win location.
pub fn find_gpg() -> Option<String> {
    if let Ok(out) = Command::new("gpg").arg("--version").output() {
        if out.status.success() {
            return Some("gpg".to_string());
        }
    }
    let candidates = [
        r"C:\Program Files\GnuPG\bin\gpg.exe",
        r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
        r"C:\Program Files\Gpg4win\bin\gpg.exe",
    ];
    for c in &candidates {
        if Path::new(c).exists() {
            return Some(c.to_string());
        }
    }
    None
}

/// Import the embedded release key into the user's GPG keyring.
pub fn import_key(gpg: &str) -> Result<(), String> {
    let result = Command::new(gpg)
        .args(["--import"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();

    let mut child = match result {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to start gpg: {}", e)),
    };

    use std::io::Write;
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(key::PUBLIC_KEY.as_bytes());
    }
    drop(child.stdin.take());

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return Err(format!("Failed to wait for gpg: {}", e)),
    };

    // Exit 0 = imported. Exit 2 = already in keyring, also fine.
    if output.status.success() || output.status.code() == Some(2) {
        Ok(())
    } else {
        Err(format!(
            "gpg --import failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

/// Verify the detached signature and check the fingerprint matches.
/// Returns Ok(()) if the signature is valid AND from the notyas release key.
pub fn verify_signature(
    gpg: &str,
    asc_path: &Path,
    sums_path: &Path,
) -> Result<(), String> {
    let output = Command::new(gpg)
        .args([
            "--status-fd", "1",
            "--verify",
            &asc_path.to_string_lossy(),
            &sums_path.to_string_lossy(),
        ])
        .output()
        .map_err(|e| format!("Failed to run gpg: {}", e))?;

    let status_output = String::from_utf8_lossy(&output.stdout).to_string();

    // Check for VALIDSIG with our exact fingerprint
    let fp = key::FINGERPRINT;
    if status_output
        .lines()
        .any(|line| line.contains("VALIDSIG") && line.contains(fp))
    {
        Ok(())
    } else {
        // Check for BADSIG or other failure
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "Signature verification failed.\n\nGPG status:\n{}\n\nGPG stderr:\n{}",
            status_output, stderr
        ))
    }
}

/// Parse a SHA256SUMS.txt file: each line is "<hash>  <filename>"
pub fn parse_sums(path: &Path) -> Result<Vec<(String, String)>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;

    let entries: Vec<(String, String)> = content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            // Format: <64 hex chars>  <filename>  (two spaces or one)
            let parts: Vec<&str> = line.splitn(2, |c: char| c.is_whitespace()).collect();
            if parts.len() != 2 {
                return None;
            }
            let hash = parts[0].trim().to_string();
            let name = parts[1].trim().to_string();
            if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) {
                Some((name, hash))
            } else {
                None
            }
        })
        .collect();

    if entries.is_empty() {
        Err("No valid hash entries found in SHA256SUMS.txt".to_string())
    } else {
        Ok(entries)
    }
}

/// Compute SHA256 of a file.
pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut hasher = Sha256::new();
    let mut file = fs::File::open(path)
        .map_err(|e| format!("Cannot open {}: {}", path.display(), e))?;
    let mut buf = [0u8; 65536];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => return Err(format!("Read error: {}", e)),
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Verify all file hashes listed in SHA256SUMS.txt against files in the same directory.
/// Returns (ok_count, fail_count, details) where details is per-file results.
pub fn verify_hashes(
    sums_path: &Path,
) -> Result<Vec<(String, bool, String)>, String> {
    let entries = parse_sums(sums_path)?;
    let dir = sums_path.parent().ok_or("Cannot determine directory")?;
    let mut results = Vec::new();

    for (filename, expected_hash) in &entries {
        let file_path = dir.join(filename);
        match sha256_file(&file_path) {
            Ok(actual_hash) => {
                let ok = actual_hash == *expected_hash;
                results.push((
                    filename.clone(),
                    ok,
                    if ok {
                        "OK".to_string()
                    } else {
                        format!("MISMATCH (expected {}, got {})", expected_hash, &actual_hash[..16])
                    },
                ));
            }
            Err(e) => {
                results.push((filename.clone(), false, e));
            }
        }
    }

    Ok(results)
}
