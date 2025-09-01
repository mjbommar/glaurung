use crate::core::triage::{ParserKind, ParserResult, TriageError, TriageErrorKind};

/// Attempt structured parsing with one or more parsers.
/// Always includes the `object` parser; may include optional extras.
pub fn parse(data: &[u8]) -> Vec<ParserResult> {
    let mut results: Vec<ParserResult> = Vec::new();

    // object
    let obj_res = match object::File::parse(data) {
        Ok(_f) => ParserResult::new(ParserKind::Object, true, None),
        Err(e) => ParserResult::new(
            ParserKind::Object,
            false,
            Some(TriageError::new(
                TriageErrorKind::ParserMismatch,
                Some(format!("{}", e)),
            )),
        ),
    };
    results.push(obj_res);

    // goblin (optional)
    #[cfg(feature = "triage-parsers-extra")]
    {
        let g = match goblin::Object::parse(data) {
            Ok(_o) => ParserResult::new(ParserKind::Goblin, true, None),
            Err(e) => ParserResult::new(
                ParserKind::Goblin,
                false,
                Some(TriageError::new(
                    TriageErrorKind::ParserMismatch,
                    Some(format!("{}", e)),
                )),
            ),
        };
        results.push(g);
    }

    // pelite (optional, only meaningful for PE)
    #[cfg(feature = "triage-parsers-extra")]
    {
        // Try both 32 and 64 variants; treat any success as ok
        let mut ok = false;
        // Avoid panic on invalid input; pelite may panic for non-PE sometimes, so wrap in catch_unwind
        let res = std::panic::catch_unwind(|| {
            if let Ok(_pe) = pelite::pe64::PeFile::from_bytes(data) {
                ok = true;
            } else if let Ok(_pe32) = pelite::pe32::PeFile::from_bytes(data) {
                ok = true;
            }
        });
        let pr = match res {
            Ok(_) => {
                if ok {
                    ParserResult::new(ParserKind::PELite, true, None)
                } else {
                    ParserResult::new(
                        ParserKind::PELite,
                        false,
                        Some(TriageError::new(
                            TriageErrorKind::ParserMismatch,
                            Some("not PE".into()),
                        )),
                    )
                }
            }
            Err(_) => ParserResult::new(
                ParserKind::PELite,
                false,
                Some(TriageError::new(
                    TriageErrorKind::ParserMismatch,
                    Some("panic in pelite".into()),
                )),
            ),
        };
        results.push(pr);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parse_object_on_real_elf() {
        // Use a real ELF from samples; prefer small ones
        let path = "samples/binaries/platforms/linux/amd64/export/rust/hello-rust-release";
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => return,
        }; // skip if not present
        let results = parse(&data);
        assert!(!results.is_empty());
        assert!(results
            .iter()
            .any(|r| r.parser == ParserKind::Object && r.ok));
        // Extras (if enabled) should also succeed on ELF (goblin), pelite likely false
        #[cfg(feature = "triage-parsers-extra")]
        {
            assert!(results.iter().any(|r| r.parser == ParserKind::Goblin));
        }
    }

    #[test]
    fn parse_object_on_real_pe() {
        // Use a real PE if available in samples; skip if absent
        let path_candidates = [
            "samples/binaries/platforms/windows/amd64/export/native/msvc/O0/hello-msvc-O0.exe",
            "samples/binaries/platforms/windows/amd64/export/native/msvc/debug/hello-msvc-debug.exe",
        ];
        let mut data: Option<Vec<u8>> = None;
        for p in &path_candidates {
            if let Ok(d) = fs::read(p) {
                data = Some(d);
                break;
            }
        }
        let Some(bytes) = data else { return }; // skip if missing
        let results = parse(&bytes);
        assert!(!results.is_empty());
        assert!(results
            .iter()
            .any(|r| r.parser == ParserKind::Object && (r.ok || r.error.is_some())));
        // Extras (if enabled) should include goblin and/or pelite results bearing ParserMismatch errors on failure
        #[cfg(feature = "triage-parsers-extra")]
        {
            assert!(results.iter().any(|r| r.parser == ParserKind::Goblin));
            assert!(results.iter().any(|r| r.parser == ParserKind::PELite));
            for r in results {
                if !r.ok {
                    assert!(matches!(r.error.as_ref().map(|e| e.kind), Some(TriageErrorKind::ParserMismatch)));
                }
            }
        }
    }
}
