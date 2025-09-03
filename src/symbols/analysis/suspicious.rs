//! Suspicious API detection with normalization.
use once_cell::sync::Lazy;
use std::collections::{HashSet, VecDeque};
use std::sync::RwLock;

/// Normalize a Windows/C API function name to a canonical base for matching.
/// - Strips leading underscores
/// - Strips stdcall suffix like `@N`
/// - Strips ANSI/Wide suffix `A`/`W` when present (CreateFileA/W)
/// - Case-insensitive compares are used by callers
pub fn normalize_api_name(name: &str) -> String {
    let mut s = name.trim();
    if s.starts_with('_') {
        s = &s[1..];
    }
    // Strip stdcall suffix @N
    if let Some(at) = s.rfind('@') {
        if s[at + 1..].chars().all(|c| c.is_ascii_digit()) {
            s = &s[..at];
        }
    }
    // Strip trailing 'A'/'W' when preceded by a letter (common WinAPI variants)
    if let Some(last) = s.chars().last() {
        if (last == 'A' || last == 'W') && s.len() > 1 {
            let pen = s[..s.len() - 1].chars().last().unwrap_or('a');
            if pen.is_ascii_alphabetic() {
                s = &s[..s.len() - 1];
            }
        }
    }
    s.to_ascii_lowercase()
}

/// Suspicious API base names (lowercase, normalized)
const SUSPICIOUS_APIS: &[&str] = &[
    // Process manipulation
    "createremotethread",
    "writeprocessmemory",
    "readprocessmemory",
    "openprocess",
    "ntwritevirtualmemory",
    "ntreadvirtualmemory",
    // Memory allocation / mapping
    "virtualallocex",
    "virtualprotect",
    "virtualprotectex",
    "ntallocatevirtualmemory",
    "ntmapviewofsection",
    // Anti-debugging
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "outputdebugstring",
    // Privileges / tokens
    "adjusttokenprivileges",
    "lookupprivilegevalue",
    // Network / comms
    "winhttpopen",
    "internetopen",
    "wsastartup",
    "connect",
    "send",
    "recv",
    // Persistence / registry
    "setwindowshookex",
    "regsetvalueex",
    "createservice",
    // Evasion / thread info
    "ntsetinformationthread",
    "zwsetinformationthread",
    // Unix/Linux
    "ptrace",
    "dlopen",
    "mprotect",
    "fork",
    "execve",
    // Additional Windows process/thread and token manipulation
    "createremotethreadex",
    "queueuserapc",
    "ntqueueapcthread",
    "setthreadcontext",
    "getthreadcontext",
    "suspendthread",
    "resumethread",
    "openthread",
    "openprocesstoken",
    "duplicatetoken",
    "duplicatetokenex",
    "createtoolhelp32snapshot",
    "process32first",
    "process32next",
    "thread32first",
    "thread32next",
    "createremotethread64",
    // Memory mapping / code injection helpers
    "mapviewoffile",
    "mapviewoffileex",
    "createthread",
    "createprocessinternalw",
    // Hiding / evasion
    "ntsetinformationprocess",
    "zwsetinformationprocess",
    "rtladjustprivileges",
];

static EXTRA_APIS: Lazy<RwLock<HashSet<String>>> = Lazy::new(|| RwLock::new(HashSet::new()));

/// Detect suspicious import names from a list of raw symbol names.
/// Returns a deduplicated, normalized list limited to `max_out`.
pub fn detect_suspicious_imports(names: &[String], max_out: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for n in names {
        let base = normalize_api_name(n);
        let hit_builtin = SUSPICIOUS_APIS.contains(&base.as_str());
        let hit_extra = {
            if let Ok(g) = EXTRA_APIS.read() {
                g.contains(&base)
            } else {
                false
            }
        };
        if (hit_builtin || hit_extra) && seen.insert(base.clone()) {
            out.push(base);
            if out.len() >= max_out {
                break;
            }
        }
    }
    out
}

/// Replace or extend the extra suspicious API set.
pub fn set_extra_apis<I: IntoIterator<Item = String>>(iter: I, clear: bool) -> usize {
    let mut guard = EXTRA_APIS.write().expect("lock EXTRA_APIS");
    if clear {
        guard.clear();
    }
    for s in iter {
        guard.insert(normalize_api_name(&s));
    }
    guard.len()
}

/// Load suspicious API names from a capa rules directory or file.
/// This performs a lightweight line scan for `api:` or `import:` features.
pub fn load_capa_apis_from_path(path: &std::path::Path, limit: usize, clear: bool) -> std::io::Result<usize> {
    let mut acc: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<std::path::PathBuf> = VecDeque::new();
    if path.is_dir() {
        queue.push_back(path.to_path_buf());
        while let Some(dir) = queue.pop_front() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_dir() {
                    queue.push_back(p);
                } else if let Some(ext) = p.extension() {
                    if ext == "yml" || ext == "yaml" { acc.insert(p.to_string_lossy().into_owned()); }
                }
            }
        }
    } else if path.is_file() {
        acc.insert(path.to_string_lossy().into_owned());
    }
    let mut names: HashSet<String> = HashSet::new();
    for file in acc.into_iter() {
        if names.len() >= limit { break; }
        if let Ok(text) = std::fs::read_to_string(&file) {
            for line in text.lines() {
                let l = line.trim();
                if l.starts_with("api:") || l.starts_with("- api:") {
                    if let Some(idx) = l.find(':') {
                        let val = l[idx+1..].trim().trim_matches('"').trim_matches('\'');
                        if !val.is_empty() { names.insert(normalize_api_name(val)); }
                    }
                } else if l.starts_with("import:") || l.starts_with("- import:") {
                    if let Some(idx) = l.find(':') {
                        let val = l[idx+1..].trim().trim_matches('"').trim_matches('\'');
                        if !val.is_empty() { names.insert(normalize_api_name(val)); }
                    }
                }
                if names.len() >= limit { break; }
            }
        }
    }
    let count = set_extra_apis(names.into_iter(), clear);
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_winapi_variants() {
        assert_eq!(
            normalize_api_name("CreateRemoteThread"),
            "createremotethread"
        );
        assert_eq!(
            normalize_api_name("_CreateRemoteThread@24"),
            "createremotethread"
        );
        assert_eq!(normalize_api_name("VirtualAllocExA"), "virtualallocex");
        assert_eq!(normalize_api_name("VirtualAllocExW"), "virtualallocex");
    }

    #[test]
    fn detect_suspicious() {
        let names = vec![
            "CreateRemoteThread".to_string(),
            "VirtualAllocEx@12".to_string(),
            "printf".to_string(),
        ];
        let v = detect_suspicious_imports(&names, 10);
        assert!(v.contains(&"createremotethread".to_string()));
        assert!(v.contains(&"virtualallocex".to_string()));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn extra_apis_are_detected() {
        set_extra_apis(vec!["very_suspicious".to_string()], true);
        let names = vec!["Very_Suspicious@4".to_string()];
        let v = detect_suspicious_imports(&names, 10);
        assert_eq!(v, vec!["very_suspicious".to_string()]);
    }
}
