use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use glaurung::strings::{extract_summary, StringsConfig};

fn collect_sample_files(root: &Path, limit: usize) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>, limit: usize) {
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
                walk(&path, out, limit);
            } else if path.is_file() {
                out.push(path);
            }
        }
    }

    let mut files = Vec::new();
    walk(root, &mut files, limit);
    files
}

fn read_prefix<P: AsRef<Path>>(path: P, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let p = path.as_ref();
    // Use a streaming take() reader to avoid loading very large files
    let mut f = fs::File::open(p)?;
    let mut buf = Vec::new();
    let mut limited = std::io::Read::take(&mut f, max_bytes as u64);
    limited.read_to_end(&mut buf)?;
    Ok(buf)
}

#[test]
fn strings_extract_summary_on_sample_binaries() {
    let root = Path::new("samples/binaries");
    if !root.exists() {
        eprintln!(
            "Skipping strings integration test; samples not found at {}",
            root.display()
        );
        return;
    }

    // Limit to a small number of files to keep CI fast
    let files = collect_sample_files(root, 8);
    if files.is_empty() {
        eprintln!("No sample files found under {}", root.display());
        return;
    }

    // Config tuned for integration (slightly larger time guard to avoid flakes)
    let cfg = StringsConfig {
        min_length: 4,
        max_samples: 32,
        max_scan_bytes: 1_048_576, // 1 MiB
        time_guard_ms: 100,        // generous for CI
        enable_language: true,
        max_lang_detect: 16,
        min_len_for_detect: 10,
        max_len_for_lingua: 32,
        min_lang_confidence: 0.65,
        min_lang_confidence_agree: 0.55,
        texty_strict: false,
        use_fast_detection: true,
        enable_classification: true,
        max_classify: 64,
        max_ioc_per_string: 8,
        max_ioc_samples: 32,
    };

    for path in files {
        // Read at most 2 MiB prefix to bound IO
        let data = match read_prefix(&path, 2 * 1024 * 1024) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Skipping file {}: {}", path.display(), e);
                continue;
            }
        };
        if data.is_empty() {
            continue;
        }

        let summary = extract_summary(&data, &cfg);

        // Invariants: samples, if present, are bounded and well-formed
        if let Some(strings) = &summary.strings {
            assert!(strings.len() <= cfg.max_samples);
            for s in strings {
                // encodings we currently emit
                assert!(matches!(
                    s.encoding.as_str(),
                    "ascii" | "utf16le" | "utf16be"
                ));
                if let Some(off) = s.offset {
                    assert!(off as usize <= data.len());
                }
            }
        }

        // Language budget should never be exceeded
        if let Some(counts) = &summary.language_counts {
            let total: u32 = counts.values().copied().sum();
            assert!(total as usize <= cfg.max_lang_detect);
        }
    }
}
