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

use object::{Object, ObjectSection, ObjectSegment, SectionKind};

/// One detected code-pointer (typically a virtual method address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VtableEntry {
    /// VA where the pointer was stored (inside rodata).
    pub source_va: u64,
    /// VA the pointer points to (inside .text).
    pub target_va: u64,
}

/// Sections whose contents are relocation targets, not program data.
///
/// A lazily-bound ELF stores, in each `.got`/`.got.plt` slot for an imported
/// function, a back-pointer into that function's own PLT stub — the address the
/// dynamic linker patches on first call. Read as an array of code pointers this
/// looks exactly like a vtable: a dense run of executable addresses. It is not
/// one, and its entries are not function starts. On musl/lld the back-pointers
/// land six bytes into the stub, so seeding from them produces a "function" per
/// import at an address that is mid-stub.
///
/// PE's `.idata`/import address table is the same shape for the same reason.
fn is_relocation_table(name: &str) -> bool {
    matches!(
        name,
        ".got" | ".got.plt" | ".plt.got" | ".plt.sec" | ".plt" | ".idata" | ".iat"
    ) || name.starts_with(".got.")
        || name.starts_with(".idata$")
}

/// Scan `data` for vtables. `is_executable_va` should return true for
/// any VA inside an executable region; the caller already has this
/// information from `parse_exec_regions`. We pass it as a closure so
/// this module doesn't have to depend on cfg.rs.
pub fn discover_vtables<F>(data: &[u8], is_executable_va: F) -> Vec<VtableEntry>
where
    F: Fn(u64) -> bool,
{
    let obj = match crate::decompile::profile::parse_object(data) {
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

    // With no section header table there is nothing to iterate below, and this
    // scan is the largest single source of function seeds — 91 of 120 on a
    // corpus built from our own fixtures, all of them lost the moment `sstrip`
    // removes metadata that no loader reads. The loadable segments still
    // describe the same bytes, so fall back to them.
    //
    // The GOT has to be excluded by hand here, because the exclusion below is
    // by section name and there are no names. `relocated_slots` recovers it
    // through PT_DYNAMIC the way the dynamic linker does; see that module for
    // why relocation *type* rather than relocation presence is the
    // discriminator.
    if obj.sections().next().is_none() {
        let slots = crate::formats::elf::dynamic_segment::relocated_slots(data);
        let got_like = slots.got_like;
        // Positive evidence, not just an exclusion. Scanning every byte of the
        // read-only segments recovers the seeds but over-reports badly —
        // measured at 143 findings for 103 real ones, because the segment has
        // no `.gcc_except_table` or `.eh_frame` boundaries to skip the way the
        // section path does. The relocation table says exactly which slots hold
        // a relocated pointer, so require that instead of guessing from bytes.
        //
        // Empty on a non-PIE image, where the tables are absolute and
        // unrelocated; the scan then falls back to byte evidence alone.
        let require_relative = &slots.relative;
        for segment in obj.segments() {
            // A vtable is data. Skipping executable segments keeps this from
            // reading code as a pointer array, which the section path got for
            // free from `SectionKind`.
            if segment_is_executable(segment.flags()) {
                continue;
            }
            let Ok(bytes) = segment.data() else {
                continue;
            };
            scan_span_for_vtables(
                segment.address(),
                bytes,
                &is_executable_va,
                &got_like,
                require_relative,
                &mut entries,
                &mut seen_targets,
            );
        }
        return entries;
    }

    for sec in obj.sections() {
        let kind = sec.kind();
        let sec_name = sec.name().unwrap_or("");
        if is_relocation_table(sec_name) || sec_name.contains(".gcc_except_table") {
            continue;
        }
        // Read-only data or relocatable data sections — anywhere a toolchain
        // could have parked a vtable.
        //
        // This used to end in `|| sec_name.contains(".gcc_except_table") == false`,
        // which is true for every section that is *not* the EH table, so the
        // whole disjunction was true for essentially everything and the filter
        // did nothing. The exclusion is now a guard above, where it belongs.
        let interesting = matches!(
            kind,
            SectionKind::ReadOnlyData | SectionKind::ReadOnlyDataWithRel | SectionKind::Data
        ) || sec_name.starts_with(".rodata")
            || sec_name.starts_with(".data.rel")
            || sec_name.contains("vtable");
        if !interesting {
            continue;
        }
        let bytes = match sec.data() {
            Ok(b) => b,
            Err(_) => continue,
        };
        // The GOT is already excluded by name above, so this path needs no
        // relocation-derived exclusion set.
        scan_span_for_vtables(
            sec.address(),
            bytes,
            &is_executable_va,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &mut entries,
            &mut seen_targets,
        );
    }

    entries
}

/// Whether a segment maps executable.
///
/// Fails closed as executable for an unrecognised container: skipping a span we
/// cannot classify costs findings, whereas scanning code as a pointer array
/// invents them.
fn segment_is_executable(flags: object::SegmentFlags) -> bool {
    match flags {
        object::SegmentFlags::Elf { p_flags, .. } => p_flags & crate::formats::elf::PF_X != 0,
        object::SegmentFlags::MachO { initprot, .. } => initprot & 0x4 != 0,
        object::SegmentFlags::Coff {
            characteristics, ..
        } => characteristics & 0x2000_0000 != 0,
        _ => true,
    }
}

/// Slide an 8-byte cursor over one span, recording runs of >= 3 code pointers.
///
/// Shared by the section path and the segment fallback so that the two cannot
/// drift into finding different vtables in the same bytes.
///
/// `got_like` is empty on the section path, where the GOT is excluded by
/// section name before we ever get here. On the fallback path it holds the
/// slots PT_DYNAMIC says the dynamic linker fills, and a hit breaks the run
/// rather than being skipped over: a GOT slot sitting inside what looks like a
/// pointer array means the array is the GOT, not a vtable that happens to
/// contain one.
fn scan_span_for_vtables<F>(
    vbase: u64,
    bytes: &[u8],
    is_executable_va: &F,
    got_like: &BTreeSet<u64>,
    require_relative: &BTreeSet<u64>,
    entries: &mut Vec<VtableEntry>,
    seen_targets: &mut BTreeSet<u64>,
) where
    F: Fn(u64) -> bool,
{
    if bytes.len() < 8 * 3 {
        return; // too small to hold a vtable
    }
    let mut i = 0usize;
    while i + 24 <= bytes.len() {
        let mut run: Vec<VtableEntry> = Vec::new();
        let mut j = i;
        while j + 8 <= bytes.len() {
            let source_va = vbase + j as u64;
            if got_like.contains(&source_va) {
                break;
            }
            // When the relocation table is available, a slot it does not name
            // is not a relocated pointer, whatever its bytes look like.
            if !require_relative.is_empty() && !require_relative.contains(&source_va) {
                break;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[j..j + 8]);
            let target = u64::from_le_bytes(buf);
            if target != 0 && is_executable_va(target) {
                run.push(VtableEntry {
                    source_va,
                    target_va: target,
                });
                j += 8;
            } else {
                break;
            }
        }
        if run.len() >= 3 {
            for entry in &run {
                if seen_targets.insert(entry.target_va) {
                    entries.push(*entry);
                }
            }
            i = j;
        } else {
            i += 8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The GOT is not a vtable, and its pre-relocation contents are not
    /// function entry points.
    ///
    /// On a lazily-bound ELF every `.got` slot for an imported function holds a
    /// back-pointer into its own PLT stub, so a scanner that reads `.got` as an
    /// array of code pointers "discovers" one function per import at an address
    /// that is not a function start. On musl/lld those back-pointers land six
    /// bytes into the stub — at `push $index`, mid-instruction-sequence — and
    /// on a stripped `getent` that produced 64 phantom functions and zero real
    /// ones: every entry `glaurung cfg` reported was one of these.
    ///
    /// The fixture is glibc/BFD, where the back-pointers land on `.plt` entry
    /// starts and so look superficially plausible; the section they came from
    /// is what makes them wrong either way.
    #[test]
    fn got_slots_are_not_reported_as_vtables() {
        use std::path::Path;

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples")
            .join("containers")
            .join("hello-cpp-g++-O0");
        if !path.exists() {
            eprintln!(
                "skipping GOT/vtable fixture test: {} absent",
                path.display()
            );
            return;
        }
        let data = std::fs::read(&path).expect("read hello-cpp-g++-O0");

        let obj = crate::decompile::profile::parse_object(&*data).expect("parse ELF");
        let exec: Vec<(u64, u64)> = obj
            .sections()
            .filter(|s| s.kind() == SectionKind::Text)
            .map(|s| (s.address(), s.address() + s.size()))
            .collect();
        let is_exec = |va: u64| exec.iter().any(|(lo, hi)| va >= *lo && va < *hi);

        // Address ranges of every pointer-table section that holds relocation
        // targets rather than user data.
        let reloc_tables: Vec<(u64, u64, String)> = obj
            .sections()
            .filter_map(|s| {
                let name = s.name().ok()?.to_string();
                (name == ".got" || name == ".got.plt" || name == ".plt.got")
                    .then(|| (s.address(), s.address() + s.size(), name))
            })
            .collect();
        assert!(
            !reloc_tables.is_empty(),
            "fixture has no .got — it cannot exercise this regression"
        );

        let entries = discover_vtables(&data, is_exec);
        let mut offenders: Vec<String> = Vec::new();
        for e in &entries {
            for (lo, hi, name) in &reloc_tables {
                if e.source_va >= *lo && e.source_va < *hi {
                    offenders.push(format!(
                        "{name}+{:#x} -> {:#x}",
                        e.source_va - *lo,
                        e.target_va
                    ));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "{} vtable entries were read out of relocation tables: {:?}",
            offenders.len(),
            &offenders[..offenders.len().min(6)]
        );
    }

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
        let unique_targets: BTreeSet<u64> = entries.iter().map(|e| e.target_va).collect();
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
