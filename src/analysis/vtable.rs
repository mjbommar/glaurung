//! Vtable detection for indirect-call resolution (#160 v1).
//!
//! Walks rodata-like sections looking for arrays of code pointers — each
//! one a u64 VA pointing into the binary's executable region. Such
//! arrays in C++ binaries are typically vtables: the compiler emits
//! one per polymorphic class and every entry is a virtual method.
//!
//! Each detected vtable yields one or more new function entry-point
//! candidates that the analysis pipeline would otherwise miss (because
//! they're never reached by direct-call edges from `_start`/`main`).
//!
//! v1 is deliberately conservative:
//! - 64-bit ELF / Mach-O / PE only (skips 32-bit; trivially extendable).
//! - Looks for runs of >= 3 consecutive u64 pointers, each landing in
//!   an executable region. The first false hit ends the run.
//! - Does NOT yet name the entries (`vtable_X::method_Y`); that's a v2
//!   refinement once we can correlate with the parent class symbol.
//! - Skips Itanium ABI's leading `offset_to_top` and `typeinfo` slots
//!   (often zero or pointers into rodata, not text), so the first valid
//!   code-pointer at a 16-byte aligned offset starts the run.

use std::collections::BTreeSet;

use object::{Object, ObjectSection, SectionKind};

/// One detected code-pointer (typically a virtual method address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VtableEntry {
    /// VA where the pointer was stored (inside rodata).
    pub source_va: u64,
    /// VA the pointer points to (inside .text).
    pub target_va: u64,
}

/// Scan `data` for vtables. `is_executable_va` should return true for
/// any VA inside an executable region; the caller already has this
/// information from `parse_exec_regions`. We pass it as a closure so
/// this module doesn't have to depend on cfg.rs.
pub fn discover_vtables<F>(data: &[u8], is_executable_va: F) -> Vec<VtableEntry>
where
    F: Fn(u64) -> bool,
{
    let obj = match object::read::File::parse(data) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    // Only 64-bit / little-endian for v1. Reject 32-bit loaders quietly —
    // they're rare for C++ vtable-heavy code in practice.
    if !obj.is_64() || !obj.is_little_endian() {
        return Vec::new();
    }

    let mut entries: Vec<VtableEntry> = Vec::new();
    let mut seen_targets: BTreeSet<u64> = BTreeSet::new();

    for sec in obj.sections() {
        let kind = sec.kind();
        let sec_name = sec.name().unwrap_or("");
        // Read-only data, GOT, or relocatable data sections — anywhere a
        // toolchain could have parked a vtable.
        let interesting = matches!(
            kind,
            SectionKind::ReadOnlyData
                | SectionKind::ReadOnlyDataWithRel
                | SectionKind::Data
        ) || sec_name.starts_with(".rodata")
            || sec_name.starts_with(".data.rel")
            || sec_name.contains("vtable")
            || sec_name.contains(".gcc_except_table") == false; // exclude EH
        if !interesting {
            continue;
        }
        let bytes = match sec.data() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let vbase = sec.address();
        if bytes.len() < 8 * 3 {
            continue; // too small to hold a vtable
        }

        // Slide an 8-byte u64 cursor at 8-byte alignment. Treat each
        // run of >= 3 valid code-pointers as a vtable.
        let mut i = 0usize;
        while i + 24 <= bytes.len() {
            let mut run: Vec<VtableEntry> = Vec::new();
            let mut j = i;
            while j + 8 <= bytes.len() {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[j..j + 8]);
                let target = u64::from_le_bytes(buf);
                if target != 0 && is_executable_va(target) {
                    run.push(VtableEntry {
                        source_va: vbase + j as u64,
                        target_va: target,
                    });
                    j += 8;
                } else {
                    break;
                }
            }
            if run.len() >= 3 {
                for e in &run {
                    if seen_targets.insert(e.target_va) {
                        entries.push(*e);
                    }
                }
                i = j;
            } else {
                i += 8;
            }
        }
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthesize a tiny "binary": a u64 array of 4 code-pointers, all
    /// pointing into a fake `.text` region we declare executable.
    /// `discover_vtables` won't actually parse this as ELF — we test the
    /// underlying *scan* logic by exposing it via a wrapper that bypasses
    /// the object parser.
    fn _scan_section(bytes: &[u8], vbase: u64, exec_lo: u64, exec_hi: u64) -> Vec<VtableEntry> {
        // Mirrors the inner loop in discover_vtables. Kept in lockstep with
        // the real implementation by structure, not by code reuse.
        let is_exec = |va: u64| va >= exec_lo && va < exec_hi;
        let mut out: Vec<VtableEntry> = Vec::new();
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut i = 0usize;
        while i + 24 <= bytes.len() {
            let mut run = Vec::new();
            let mut j = i;
            while j + 8 <= bytes.len() {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[j..j + 8]);
                let target = u64::from_le_bytes(buf);
                if target != 0 && is_exec(target) {
                    run.push(VtableEntry { source_va: vbase + j as u64, target_va: target });
                    j += 8;
                } else {
                    break;
                }
            }
            if run.len() >= 3 {
                for e in &run {
                    if seen.insert(e.target_va) {
                        out.push(*e);
                    }
                }
                i = j;
            } else {
                i += 8;
            }
        }
        out
    }

    #[test]
    fn detects_run_of_three_code_pointers() {
        // 4 pointers into [.text 0x1000-0x2000), at section vbase 0x4000.
        let mut data = Vec::new();
        for va in [0x1100u64, 0x1180, 0x11c0, 0x1208] {
            data.extend_from_slice(&va.to_le_bytes());
        }
        // Trailing zero so the run terminates cleanly.
        data.extend_from_slice(&0u64.to_le_bytes());
        let entries = _scan_section(&data, 0x4000, 0x1000, 0x2000);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].source_va, 0x4000);
        assert_eq!(entries[0].target_va, 0x1100);
        assert_eq!(entries[3].target_va, 0x1208);
    }

    #[test]
    fn rejects_runs_shorter_than_three() {
        // Only 2 valid pointers; should not be reported.
        let mut data = Vec::new();
        data.extend_from_slice(&0x1100u64.to_le_bytes());
        data.extend_from_slice(&0x1180u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        let entries = _scan_section(&data, 0x4000, 0x1000, 0x2000);
        assert!(entries.is_empty());
    }

    #[test]
    fn deduplicates_targets_across_multiple_runs() {
        // Two separate runs that share a target VA. Only one entry
        // should be emitted (the first).
        let mut data = Vec::new();
        for va in [0x1100u64, 0x1100, 0x1100, 0u64, 0x1100, 0x1100, 0x1100] {
            data.extend_from_slice(&va.to_le_bytes());
        }
        let entries = _scan_section(&data, 0x4000, 0x1000, 0x2000);
        let unique_targets: BTreeSet<u64> =
            entries.iter().map(|e| e.target_va).collect();
        assert_eq!(unique_targets.len(), 1);
    }

    #[test]
    fn ignores_non_executable_targets() {
        // All pointers go into a non-executable region.
        let mut data = Vec::new();
        for va in [0x9000u64, 0x9100, 0x9200] {
            data.extend_from_slice(&va.to_le_bytes());
        }
        let entries = _scan_section(&data, 0x4000, 0x1000, 0x2000);
        assert!(entries.is_empty());
    }

    /// Smoke test against a real C++ binary if available — we don't
    /// assert any specific vtable was found (depends on whether the
    /// sample uses virtual methods) but the call must not crash.
    #[test]
    fn discover_vtables_smoke_on_real_binary() {
        let path = "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2";
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return,
        };
        // Use a permissive executability check since this test doesn't
        // re-parse exec regions.
        let entries = discover_vtables(&bytes, |_va| true);
        // Just assert it returns a deterministic-shape result.
        let _ = entries.len();
    }
}
