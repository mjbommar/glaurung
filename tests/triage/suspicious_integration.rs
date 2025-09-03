//! Integration test for suspicious import detection in symbol summaries.
use std::fs;
use std::path::{Path, PathBuf};

use glaurung::triage::api::analyze_path;
use glaurung::triage::io::IOLimits;

fn collect_matching_files(root: &Path, needle: &str, limit: usize) -> Vec<PathBuf> {
    fn walk(dir: &Path, needle: &str, limit: usize, out: &mut Vec<PathBuf>) {
        if out.len() >= limit {
            return;
        }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for e in entries.flatten() {
            if out.len() >= limit {
                break;
            }
            let path = e.path();
            if path.is_dir() {
                walk(&path, needle, limit, out);
            } else if path.is_file() {
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    if name.contains(needle) {
                        out.push(path);
                    }
                }
            }
        }
    }
    let mut files = Vec::new();
    walk(root, needle, limit, &mut files);
    files
}

#[test]
fn suspicious_imports_detected_in_suspicious_samples() {
    // Keep this separate from IOC tests; only symbol summaries are exercised here.
    let root = Path::new("samples/binaries");
    if !root.exists() {
        eprintln!(
            "Sample binaries root not present; skipping suspicious imports test ({}).",
            root.display()
        );
        return;
    }

    // Search for suspicious sample binaries built by the sample builders.
    let mut candidates = Vec::new();
    candidates.extend(collect_matching_files(root, "suspicious_linux", 16));
    candidates.extend(collect_matching_files(root, "suspicious_win", 16));
    if candidates.is_empty() {
        eprintln!(
            "No suspicious sample binaries found under {}; skipping test.",
            root.display()
        );
        return;
    }

    let limits = IOLimits { max_read_bytes: 512 * 1024, max_file_size: u64::MAX };
    let mut any_detected = false;
    for p in candidates {
        let art = match analyze_path(&p, &limits) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Skipping {}: {}", p.display(), e);
                continue;
            }
        };
        if let Some(sym) = art.symbols {
            if let Some(list) = sym.suspicious_imports {
                // Check for at least one known suspicious API (normalized)
                let known = [
                    // Windows
                    "createremotethread",
                    "writeprocessmemory",
                    "virtualallocex",
                    // Linux/Unix
                    "ptrace",
                    "mprotect",
                    "execve",
                ];
                if list.iter().any(|s| known.contains(&s.as_str())) {
                    any_detected = true;
                    break;
                }
            }
        }
    }
    assert!(any_detected, "expected at least one suspicious import to be detected");
}

