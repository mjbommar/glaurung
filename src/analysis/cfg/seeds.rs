//! Where the discovery worklist comes from.
//!
//! Function discovery is an entry-rooted walk, and a walk is only as good as
//! the set of places it is told to start. [`collect_seeds`] is that set: eleven
//! independent seed sources, run in a fixed order, appending into one vector.
//!
//! The order is not cosmetic. The parent drains the vector into a FIFO
//! `VecDeque` worklist and stops the moment `budgets.max_functions` is reached,
//! so a seed's position decides whether it is analysed at all under a tight
//! budget. It also decides *ownership*: the body-overlap gate rejects a
//! candidate that lands inside an already discovered function, so whichever
//! source seeds a VA first is the one that claims the surrounding bytes. The
//! phases below therefore run cheapest-to-trust first:
//!
//! 1. caller-requested VAs -- authoritative, never displaced by heuristics;
//! 2. the entrypoint, then symbol-table starts;
//! 3. FLIRT prologue matches (also builds the `sub_* -> real_name` map);
//! 4. vtable slot targets;
//! 5. jump-table case targets (ELF only -- see the phase comment);
//! 6. PE export directory;
//! 7. PE `.pdata` (`IMAGE_DIRECTORY_ENTRY_EXCEPTION`);
//! 8. ELF `.eh_frame` FDE starts (also builds the proven-end bound map);
//! 9. PE/ELF/AArch64 prologue byte scans;
//! 10. PE thunk and tiny-stub scans;
//! 11. PE raw direct-call targets, then PE data-referenced code pointers.
//!
//! Every phase is a forward append: it reads `known` to skip a VA another
//! source already claimed, pushes to `seeds`, and records provenance into the
//! caller's [`FunctionDiscoveryStats`]. No phase reads a later phase's output,
//! which is what makes the whole block liftable as one function. Three
//! intermediate values *are* shared between phases and stay local here because
//! nothing downstream reads them: `pdata_start_set` (phases 10-11 use it to
//! suppress candidates the exception directory already covers),
//! `code_pointer_target_set` and `pe_code_pointers`.
//!
//! What stays in [`super::worklist`], because the call graph says so: `bits` is
//! derived before this call and used again by the worklist loop and the
//! callgraph build; `noreturn_targets` and `plt_stub_ranges` are
//! `DiscoveryFacts` inputs, not seeds; and the `Vec<Function>` passed in as
//! `discovered` is the caller's result vector, which the FLIRT scan reads to
//! skip matches inside a known body. It is empty at this point in the pass --
//! the parameter exists so that stays a fact about the caller rather than an
//! assumption made here.

use super::*;

use object::{Object, ObjectSymbol};

/// Everything the discovery pass needs that was computed while collecting seeds.
///
/// Six of the eight fields outlive the seed phases: the worklist itself, the
/// two dedup maps the worklist loop keeps extending as it finds xref targets,
/// the FLIRT library and name map used to rename `sub_*` after discovery, the
/// jump-table index handed to `DiscoveryFacts`, and the `.eh_frame` extent map
/// consulted per seed for a proven function end.
pub(super) struct Seeds {
    /// The worklist, in insertion order. The parent drains it front-to-back.
    pub(super) seeds: Vec<(Address, DiscoverySeedKind)>,
    /// Every VA already claimed by some seed source. The worklist loop keeps
    /// inserting into this as xref backtracking finds new targets.
    pub(super) known: std::collections::HashSet<u64>,
    /// First-claim seed kind per VA, used to label a discovered function with
    /// the provenance that found it. Also extended by the worklist loop.
    pub(super) seed_kind_by_va: std::collections::HashMap<u64, DiscoverySeedKind>,
    /// The signature library, loaded once and reused for post-discovery
    /// overrides.
    pub(super) flirt_library: Option<std::sync::Arc<FlirtLibrary>>,
    /// `va -> name` for every FLIRT prologue match, applied after DWARF and
    /// symbol renaming so it only touches functions still named `sub_*`.
    pub(super) flirt_name_by_va: std::collections::HashMap<u64, String>,
    /// `table_va -> case targets`, so a dispatch site can ask what the table it
    /// computed points at. Empty on PE.
    pub(super) jump_table_index: std::collections::BTreeMap<u64, Vec<u64>>,
    /// `fde_start -> exclusive end`, the proven boundary a walk can stop at.
    pub(super) eh_frame_extent: std::collections::HashMap<u64, u64>,
    /// Whether the input is a PE image. Several later gates key off it.
    pub(super) is_pe_image: bool,
}

/// Run every seed source over `data` and return the discovery worklist.
///
/// `discovered` is the caller's function vector, read only by the FLIRT scan to
/// skip matches inside a body that is already known. `stats` accumulates seed
/// provenance, scan rejections and per-source counters as the phases run.
#[allow(clippy::too_many_arguments)]
pub(super) fn collect_seeds(
    data: &[u8],
    image: Option<&crate::program::image::ProgramImage>,
    regions: &[ExecRegion],
    arch: BArch,
    bits: u8,
    entry: Option<Address>,
    requested_vas: &[u64],
    discovered: &[Function],
    deadline: Deadline<'_>,
    stats: &mut FunctionDiscoveryStats,
) -> Seeds {
    // Explicit caller-provided addresses are authoritative and go first so a
    // tight function budget cannot be consumed by whole-binary heuristics
    // before the requested entries are reached. Callers provide executable
    // code VAs (with ARM's Thumb metadata bit already cleared).
    let mut seeds: Vec<(Address, DiscoverySeedKind)> = Vec::new();
    let mut requested_known = std::collections::HashSet::new();
    for requested_va in requested_vas {
        let va = *requested_va;
        if in_exec_regions(regions, va).is_none() || !requested_known.insert(va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Requested));
        }
    }

    // Remaining seeds: entrypoint + symbol-defined function addresses.
    let mut automatic_seeds: Vec<(Address, DiscoverySeedKind)> =
        parse_function_seeds(data, regions, arch)
            .into_iter()
            .map(|addr| (addr, DiscoverySeedKind::Symbol))
            .collect();
    if let Some(ep) = entry.clone() {
        automatic_seeds.retain(|(a, _kind)| a.value != ep.value);
        automatic_seeds.insert(0, (ep, DiscoverySeedKind::EntryPoint));
    }
    automatic_seeds.retain(|(addr, _kind)| !requested_known.contains(&addr.value));
    seeds.extend(automatic_seeds);

    // FLIRT seed augmentation. On stripped binaries (no symbol table),
    // the seed list is otherwise just the entrypoint, so the analyser
    // never finds any of the dozens of functions that exist. Scan exec
    // regions for FLIRT prologue matches and seed those VAs too. A name
    // mapping is also kept so we can rename `sub_*` → real_name once
    // discovery completes (see post-processing below).
    // Loaded through `flirt::library_for`, which parses a given library file
    // at most once per process: this call used to re-read and re-parse the
    // whole JSON on every `analyze()`.
    let flirt_library: Option<std::sync::Arc<FlirtLibrary>> = load_default_library();
    let flirt_seeds: Vec<(u64, String)> = if let Some(ref lib) = flirt_library {
        scan_within(deadline, stats, || {
            discover_flirt_seeds(data, discovered, lib)
        })
    } else {
        Vec::new()
    };
    let is_pe_image = data.len() >= 2 && &data[..2] == b"MZ";
    let flirt_name_by_va: std::collections::HashMap<u64, String> =
        flirt_seeds.iter().cloned().collect();
    let mut known: std::collections::HashSet<u64> = seeds.iter().map(|(a, _)| a.value).collect();
    let mut seed_kind_by_va: std::collections::HashMap<u64, DiscoverySeedKind> =
        std::collections::HashMap::new();
    for (addr, kind) in &seeds {
        seed_kind_by_va.entry(addr.value).or_insert(*kind);
        record_seed_provenance(stats, addr.value, None, *kind, "initial_seed");
    }
    for (va, _name) in &flirt_seeds {
        if known.contains(va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, *va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Flirt));
            known.insert(*va);
            seed_kind_by_va.insert(*va, DiscoverySeedKind::Flirt);
            record_seed_provenance(stats, *va, None, DiscoverySeedKind::Flirt, "flirt");
        }
    }

    // Vtable discovery (#160 v1). For each rodata-resident array of
    // code-pointers (>= 3 consecutive pointers, all landing in exec
    // regions), seed every target VA as a discovery candidate. C++
    // virtual methods are otherwise unreachable from `_start`/`main`
    // because they're called indirectly through `this->vtable[N]`.
    let regions_for_check = regions.to_vec();
    let is_executable = |va: u64| -> bool {
        regions_for_check
            .iter()
            .any(|r| va >= r.start && va < r.end)
    };
    let vtable_entries = scan_within(deadline, stats, || discover_vtables(data, is_executable));
    let mut vtable_method_count = 0usize;
    for entry in &vtable_entries {
        if known.contains(&entry.target_va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, entry.target_va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Vtable));
            known.insert(entry.target_va);
            seed_kind_by_va.insert(entry.target_va, DiscoverySeedKind::Vtable);
            record_seed_provenance(
                stats,
                entry.target_va,
                Some(entry.source_va),
                DiscoverySeedKind::Vtable,
                "vtable",
            );
            vtable_method_count += 1;
        }
    }
    let _ = vtable_method_count; // available for telemetry; unused for now.

    // Jump-table discovery (#177). Case targets feed the owning CFG through
    // `jump_table_index` below. They remain fallback entry seeds for stripped
    // ELF code only when no previously discovered function owns the target;
    // an ordinary switch arm is a basic block, not another top-level function.
    // PE never promotes case labels because its trusted entry metadata is much
    // stronger and Ghidra likewise keeps switch arms intraprocedural.
    // Indexed by table VA so a dispatch site can ask "what does the table I
    // computed point at". Previously these targets were consumed ONLY as
    // function-entry seeds, which is why the dispatching function's own CFG
    // never gained the arms — see `analysis::dispatch`.
    let mut jump_table_index: std::collections::BTreeMap<u64, Vec<u64>> =
        std::collections::BTreeMap::new();
    if !is_pe_image {
        let regions_for_check2 = regions.to_vec();
        let is_executable2 = move |va: u64| -> bool {
            regions_for_check2
                .iter()
                .any(|r| va >= r.start && va < r.end)
        };
        let jump_tables = scan_within(deadline, stats, || {
            discover_jump_tables(data, is_executable2)
        });
        for jt in &jump_tables {
            jump_table_index.insert(jt.table_va, jt.targets.clone());
        }
        for jt in &jump_tables {
            for tgt in &jt.targets {
                if known.contains(tgt) {
                    continue;
                }
                if let Ok(addr) = Address::new(AddressKind::VA, *tgt, bits, None, None) {
                    seeds.push((addr, DiscoverySeedKind::JumpTable));
                    known.insert(*tgt);
                    seed_kind_by_va.insert(*tgt, DiscoverySeedKind::JumpTable);
                    record_seed_provenance(
                        stats,
                        *tgt,
                        Some(jt.table_va),
                        DiscoverySeedKind::JumpTable,
                        "jump_table",
                    );
                }
            }
        }
    }

    // PE export-table seeds. The `object` crate's `dynamic_symbols()`
    // returns 0 entries for PE files (verified on kernel32.dll: 1671
    // exports, 0 returned). We parse IMAGE_DIRECTORY_ENTRY_EXPORT
    // directly so every export address becomes a discovery seed.
    // Closes the 58 % recall observed on kernel32 in the iter 14
    // sweep (most kernel32 exports are tiny `jmp [iat]` thunks not
    // covered by .pdata). Exports are trusted entry points, so insert
    // them before the body-overlap-gated .pdata seeds below.
    let export_starts = scan_within(deadline, stats, || {
        parse_pe_export_function_starts(data, regions, arch)
    });
    stats.export_function_starts = export_starts.len();
    for va in export_starts {
        if known.contains(&va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Export));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::Export);
            record_seed_provenance(stats, va, None, DiscoverySeedKind::Export, "pe_export");
            stats.export_seeds_inserted = stats.export_seeds_inserted.saturating_add(1);
        }
    }

    // Win64 exception-directory seeds. On x86-64 Windows the calling
    // convention emits a RUNTIME_FUNCTION unwind record for nearly
    // every function; IMAGE_DIRECTORY_ENTRY_EXCEPTION is therefore a
    // near-complete function index for free. This is the single
    // highest-leverage seed source on stripped Windows PE -- it
    // closed most of the ~98% recall gap vs Ghidra on ntdll.dll
    // observed in asb's iter 13 comparison.
    let (pdata_starts, pdata_stats) = scan_within(deadline, stats, || {
        parse_pdata_function_starts(data, regions, arch)
    });
    let pdata_start_set: std::collections::HashSet<u64> = pdata_starts.iter().copied().collect();
    stats.pdata_entries = pdata_stats.entries;
    stats.pdata_function_starts = pdata_stats.accepted_starts;
    stats.pdata_zero_begin_rejected = pdata_stats.zero_begin_rejected;
    stats.pdata_zero_size_rejected = pdata_stats.zero_size_rejected;
    stats.pdata_overlapping_entries = pdata_stats.overlapping_entries;
    stats.pdata_chained_unwind_rejected = pdata_stats.chained_unwind_rejected;
    stats.pdata_chained_unwind_parsed = pdata_stats.chained_unwind_parsed;
    stats.pdata_chained_unwind_parse_failed = pdata_stats.chained_unwind_parse_failed;
    stats.pdata_chained_parent_starts = pdata_stats.chained_parent_starts;
    stats.pdata_nonexec_rejected = pdata_stats.nonexec_rejected;
    for va in &pdata_stats.zero_begin_rejected_starts {
        record_scan_rejection(
            stats,
            *va,
            None,
            "pdata:zero_begin",
            "PE exception directory entry has BeginAddress == 0",
        );
    }
    for va in &pdata_stats.zero_size_rejected_starts {
        record_scan_rejection(
            stats,
            *va,
            None,
            "pdata:zero_size",
            "PE exception directory entry has EndAddress <= BeginAddress",
        );
    }
    for va in &pdata_stats.chained_unwind_rejected_starts {
        record_scan_rejection(
            stats,
            *va,
            None,
            "pdata:chained_unwind",
            "PE exception directory entry is a chained unwind record",
        );
    }
    for va in &pdata_stats.nonexec_rejected_starts {
        record_scan_rejection(
            stats,
            *va,
            None,
            "pdata:nonexec",
            "PE exception directory entry does not start in executable code",
        );
    }
    for va in pdata_starts {
        if known.contains(&va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Pdata));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::Pdata);
            record_seed_provenance(stats, va, None, DiscoverySeedKind::Pdata, "pe_pdata");
            stats.pdata_seeds_inserted = stats.pdata_seeds_inserted.saturating_add(1);
        }
    }

    // `.eh_frame` FDE starts — the ELF counterpart of `.pdata`, and the only
    // authoritative function boundary a stripped ELF still carries. Trusted, so
    // not body-overlap gated: an earlier wrong function must not be allowed to
    // suppress a proven start. Before this, a stripped ELF was discovered from
    // its entry point and direct calls alone, which recovered 48-57% of these
    // starts on glibc binaries and none at all on small musl ones.
    // Only the byte-only arm is deadline-guarded, and the asymmetry is the
    // point. `ProgramImage::eh_frame_functions` returns a stored field — an
    // index lookup that cannot overrun, and guarding it would drop proven
    // starts for no gain. The `image == None` arm is a full-image sweep, and it
    // is the arm every `analyze_functions_bytes*` entry point takes. It was the
    // only whole-image scan in this module outside `scan_within`, so it ran to
    // completion after the total-timeout ceiling had already passed while its
    // twelve siblings returned empty.
    let eh_frame_functions = image.map_or_else(
        || {
            scan_within(deadline, stats, || {
                crate::analysis::exception::eh_frame_functions(data)
            })
        },
        |image| image.eh_frame_functions().to_vec(),
    );
    stats.eh_frame_candidates = eh_frame_functions.len();
    // start -> exclusive end, so a walk can be stopped at the proven boundary.
    let eh_frame_extent: std::collections::HashMap<u64, u64> = eh_frame_functions
        .iter()
        .map(|f| (f.start, f.end))
        .collect();
    for func in &eh_frame_functions {
        let va = func.start;
        if !regions.iter().any(|r| va >= r.start && va < r.end) {
            record_scan_rejection(
                stats,
                va,
                None,
                "eh_frame:nonexec",
                "FDE start is outside every executable region",
            );
            continue;
        }
        if known.contains(&va) {
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::EhFrame));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::EhFrame);
            record_seed_provenance(stats, va, None, DiscoverySeedKind::EhFrame, "eh_frame");
            stats.eh_frame_seeds_inserted = stats.eh_frame_seeds_inserted.saturating_add(1);
        }
    }

    let mut prologue_starts = scan_within(deadline, stats, || {
        scan_pe_prologue_function_starts(data, regions, arch)
    });
    // The ELF counterpart. `.eh_frame` (above) covers every function built with
    // unwind tables, which is most of them; this scan exists for the rest —
    // hand-written assembly and `-fno-asynchronous-unwind-tables` builds like
    // Alpine's `busybox`, whose `.eh_frame` is four bytes long. Discovery recall
    // against the full DWARF function set was 0.514 with `.eh_frame` alone.
    prologue_starts.extend(scan_within(deadline, stats, || {
        scan_elf_prologue_function_starts(image, data, regions, arch)
    }));
    // AArch64 ELF PAC prologues recover functions on stripped hardened binaries
    // (Pixel device .so files) where the PE-specific scan does not apply.
    prologue_starts.extend(scan_within(deadline, stats, || {
        scan_aarch64_prologue_function_starts(image, data, regions, arch)
    }));
    stats.prologue_scan_candidates = prologue_starts.len();
    for va in prologue_starts {
        if known.contains(&va) {
            record_scan_rejection(
                stats,
                va,
                None,
                "prologue_scan:known_seed",
                "candidate already present in trusted seed set",
            );
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Prologue));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::Prologue);
            record_seed_provenance(
                stats,
                va,
                None,
                DiscoverySeedKind::Prologue,
                "prologue_scan",
            );
            stats.prologue_scan_seeds_inserted =
                stats.prologue_scan_seeds_inserted.saturating_add(1);
        }
    }

    let thunk_starts = scan_within(deadline, stats, || {
        scan_pe_thunk_function_starts(data, regions, arch)
    });
    stats.thunk_scan_candidates = thunk_starts.len();
    for va in thunk_starts {
        if known.contains(&va) {
            record_scan_rejection(
                stats,
                va,
                None,
                "thunk_scan:known_seed",
                "candidate already present in trusted seed set",
            );
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::Thunk));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::Thunk);
            record_seed_provenance(stats, va, None, DiscoverySeedKind::Thunk, "thunk_scan");
            stats.thunk_scan_seeds_inserted = stats.thunk_scan_seeds_inserted.saturating_add(1);
        }
    }

    let pe_code_pointers = scan_within(deadline, stats, || scan_pe_code_pointers(data));
    stats.data_ref_code_pointer_candidates = pe_code_pointers.len();
    let code_pointer_tables: std::collections::BTreeSet<(String, usize)> = pe_code_pointers
        .iter()
        .map(|ptr| (ptr.section_name.clone(), ptr.table_index))
        .collect();
    stats.data_ref_code_pointer_table_count = code_pointer_tables.len();
    let code_pointer_target_set: std::collections::HashSet<u64> =
        pe_code_pointers.iter().map(|ptr| ptr.target_va).collect();

    let tiny_stub_scan = scan_within(deadline, stats, || {
        scan_pe_tiny_stub_function_starts(
            data,
            regions,
            arch,
            &pdata_start_set,
            &code_pointer_target_set,
        )
    });
    stats.tiny_stub_scan_candidates = tiny_stub_scan.starts.len();
    for va in &tiny_stub_scan.pdata_rejected {
        record_scan_rejection(
            stats,
            *va,
            None,
            "tiny_stub_scan:pdata_start",
            "candidate already covered by PE exception directory",
        );
    }
    for va in &tiny_stub_scan.unpromoted_candidates {
        record_scan_rejection(
            stats,
            *va,
            None,
            "tiny_stub_scan:unpromoted_candidate",
            "tiny-stub shape lacks promotion provenance",
        );
    }
    for va in tiny_stub_scan.starts {
        if known.contains(&va) {
            record_scan_rejection(
                stats,
                va,
                None,
                "tiny_stub_scan:known_seed",
                "candidate already present in trusted seed set",
            );
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::TinyStub));
            known.insert(va);
            seed_kind_by_va.insert(va, DiscoverySeedKind::TinyStub);
            record_seed_provenance(
                stats,
                va,
                None,
                DiscoverySeedKind::TinyStub,
                "tiny_stub_scan",
            );
            stats.tiny_stub_scan_seeds_inserted =
                stats.tiny_stub_scan_seeds_inserted.saturating_add(1);
        }
    }

    let raw_call_starts = scan_within(deadline, stats, || {
        scan_pe_raw_call_function_starts(data, regions, arch, &pdata_start_set)
    });
    stats.raw_call_target_candidates = raw_call_starts.len();
    for start in raw_call_starts {
        if known.contains(&start.va) {
            record_scan_rejection(
                stats,
                start.va,
                None,
                "raw_call_scan:known_seed",
                "raw direct-call candidate already present in seed set",
            );
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, start.va, bits, None, None) {
            let seed_kind = if start.allow_body_split {
                DiscoverySeedKind::DirectCallBodySplit
            } else {
                DiscoverySeedKind::DirectCall
            };
            seeds.push((addr, seed_kind));
            known.insert(start.va);
            seed_kind_by_va.insert(start.va, seed_kind);
            record_seed_provenance(stats, start.va, None, seed_kind, "raw_direct_call_scan");
            stats.raw_call_target_seeds_inserted =
                stats.raw_call_target_seeds_inserted.saturating_add(1);
            if start.allow_body_split {
                stats.raw_call_target_body_split_seeds_inserted = stats
                    .raw_call_target_body_split_seeds_inserted
                    .saturating_add(1);
            }
        }
    }

    for ptr in &pe_code_pointers {
        if !should_seed_pe_code_pointer(ptr) {
            record_scan_rejection(
                stats,
                ptr.target_va,
                Some(ptr.pointer_va),
                "data_ref:weak_pointer",
                format!(
                    "{}:slot{}:table{}:len{}:{}",
                    ptr.section_name,
                    ptr.slot_size,
                    ptr.table_index,
                    ptr.table_length,
                    ptr.confidence
                ),
            );
            continue;
        }
        if known.contains(&ptr.target_va) || pdata_start_set.contains(&ptr.target_va) {
            record_scan_rejection(
                stats,
                ptr.target_va,
                Some(ptr.pointer_va),
                "data_ref:known_or_pdata",
                format!(
                    "{}:slot{}:table{}:len{}:{}",
                    ptr.section_name,
                    ptr.slot_size,
                    ptr.table_index,
                    ptr.table_length,
                    ptr.confidence
                ),
            );
            continue;
        }
        if let Ok(addr) = Address::new(AddressKind::VA, ptr.target_va, bits, None, None) {
            seeds.push((addr, DiscoverySeedKind::DataRef));
            known.insert(ptr.target_va);
            seed_kind_by_va.insert(ptr.target_va, DiscoverySeedKind::DataRef);
            record_seed_provenance(
                stats,
                ptr.target_va,
                Some(ptr.pointer_va),
                DiscoverySeedKind::DataRef,
                format!(
                    "pe_code_pointer:{}:slot{}:table{}:len{}:{}",
                    ptr.section_name,
                    ptr.slot_size,
                    ptr.table_index,
                    ptr.table_length,
                    ptr.confidence
                ),
            );
            stats.data_ref_code_pointer_seeds_inserted =
                stats.data_ref_code_pointer_seeds_inserted.saturating_add(1);
        }
    }

    Seeds {
        seeds,
        known,
        seed_kind_by_va,
        flirt_library,
        flirt_name_by_va,
        jump_table_index,
        eh_frame_extent,
        is_pe_image,
    }
}

/// Every defined symbol in an executable region, as a function-entry seed.
///
/// The first and cheapest seed source, and the only one that needs no
/// heuristic: a symbol table that says a function starts here is taken at its
/// word. Address 0 is NOT special-cased -- `in_exec_regions` already excludes it
/// in a linked binary, while keeping a genuine function at offset 0 of a
/// relocatable object, which is where the first Thumb function lands once
/// `code_addr` has masked its T-bit off.

pub(super) fn parse_function_seeds(
    data: &[u8],
    regions: &[ExecRegion],
    arch: BArch,
) -> Vec<Address> {
    let bits = if arch.is_64_bit() { 64 } else { 32 };
    let mut seeds: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    if let Ok(obj) = crate::decompile::profile::parse_object(data) {
        // Symbols defined in executable regions. We do NOT special-case
        // addr==0: `in_exec_regions` already excludes address 0 in linked
        // binaries (where it is never executable), while keeping a genuine
        // function at offset 0 in a relocatable object — e.g. the first Thumb
        // function, whose symbol value is the T-bit `1` masked to `0`.
        for sym in obj.symbols() {
            if sym.is_definition() {
                let addr = code_addr(sym.address(), arch);
                if in_exec_regions(regions, addr).is_some() {
                    seeds.insert(addr);
                }
            }
        }
        // Also consider dynamic symbols (ELF .plt entries often appear here)
        for sym in obj.dynamic_symbols() {
            if sym.is_definition() {
                let addr = code_addr(sym.address(), arch);
                if in_exec_regions(regions, addr).is_some() {
                    seeds.insert(addr);
                }
            }
        }
    }
    seeds
        .into_iter()
        .filter_map(|va| Address::new(AddressKind::VA, va, bits, None, None).ok())
        .collect()
}
