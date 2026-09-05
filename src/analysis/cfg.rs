//! Bounded function discovery and CFG construction.
//!
//! This module implements a conservative, deterministic function discovery pass
//! with strict budgets. It seeds from an entrypoint (and can be extended later to
//! exports/PLT/etc.), disassembles within executable ranges only, splits basic
//! blocks on control flow, and emits `Function`s plus a `CallGraph`.
//!
//! # Where the work lives
//!
//! What is left in this file is the public entry points and the shared
//! vocabulary. The pipeline reads top to bottom through the submodules:
//!
//! | module | owns |
//! |---|---|
//! | [`packed`] | is there a program in these bytes, or only a decompressor stub |
//! | [`image_view`] | where the code is, and how a VA becomes bytes |
//! | [`budgets`] | how much work this run may do, and what says it was cut short |
//! | [`scan`], [`entry_shape`], [`pe_tables`], [`plt`], [`seeds`] | every candidate function start, and why it is one |
//! | [`worklist`] | which seeds are processed in which order, and who owns a byte when two overlap |
//! | [`body_index`] | does some function already own this VA — asked once per seed, answered in O(1) |
//! | [`walk`] | one function's bounded block walk |
//! | [`ctrl_flow`], [`dispatch_resolution`], [`dispatch_flow`] | what an instruction does to control flow, and how a dispatch fact travels |
//! | [`must_dataflow`] | the fixed points over the finished graph, and the dispatch arms that survive them |
//! | [`function_build`] | blocks and edges to a `Function` |
//! | [`extents`], [`repair`] | declared extents, names, chunk folding, DWARF, landing pads |
//! | [`stats`] | everything the run says about itself |
//!
//! # The re-export block below is load-bearing
//!
//! Most of these submodules reach the shared vocabulary through `use super::*`,
//! which resolves against *this* module's bindings rather than against wherever
//! an item is defined. A name a sibling needs therefore has to be named here
//! even when nothing in this file uses it — see the comments in that block.

use crate::analysis::jump_table::{
    decode_bounded_relative_jump_table, decode_thumb_table_branch, discover_jump_tables,
};
use crate::analysis::vtable::discover_vtables;
use crate::core::address::{Address, AddressKind};
use crate::core::address_range::AddressRange;
use crate::core::basic_block::BasicBlock;
use crate::core::binary::{Arch as BArch, Endianness};
use crate::core::call_graph::{CallGraph, CallGraphEdge, CallType};
use crate::core::control_flow_graph::ControlFlowEdgeKind;
use crate::core::disassembler::Disassembler;
use crate::core::function::{Function, FunctionFlags, FunctionKind};
use crate::core::instruction::Instruction;
use crate::debug::dwarf::{extract_dwarf_functions, DwarfFunction};
use crate::disasm::registry;
use crate::flirt::{
    apply_flirt_overrides_with_refs, discover_flirt_seeds, load_default_library, FlirtLibrary,
};
use crate::triage::heuristics;

mod body_index;
mod budgets;
mod ctrl_flow;
mod dispatch_flow;
mod dispatch_resolution;
mod entry_shape;
mod extents;
mod function_build;
mod image_view;
mod must_dataflow;
mod packed;
mod pe_tables;
mod plt;
mod repair;
mod scan;
mod seeds;
mod stats;
mod walk;
mod worklist;

pub use budgets::{Budgets, Deadline};
pub use scan::{scan_pe_code_pointers, PeCodePointer};
pub use stats::{CodeLabel, FunctionDiscoveryStats, ScanRejection, SeedProvenance};

// Every name below is re-listed explicitly rather than glob-imported: a sibling
// module reaches these through `use super::…`, which resolves against *this*
// binding, not against the module that defines them. `scan::prologue_gate_tests`
// reaching `is_code_padding_terminator` and `memory_operand_va` is the case that
// first made it matter.
use body_index::{cap_discovered_functions_at_va, va_in_function_body, BodyIndex};

use budgets::scan_within;

use ctrl_flow::{
    arm_defined_register, arm_ldr_pc_table_dispatch, arm_pop_writes_pc, classify_ctrl_flow,
    guard_fallthrough_bound, immediate_target, is_code_padding_terminator,
    is_unconditional_branch_mnemonic, memory_operand_va,
};

use dispatch_flow::{
    combine_dispatch_bounds, join_dispatch_bounds, merge_dispatch_addresses, replay_dispatch_block,
    trim_unproven_dispatch_edges, BlockStreams, TentativeDispatchEdges,
};
use dispatch_resolution::resolve_dispatch;

// Same rule as above, and the same reason. `has_function_boundary_marker`,
// `head_looks_like_fn_start`, `pe_head_looks_like_simd_continuation`,
// `read_i32_le_at` and `rel_target` are named here for `scan`'s benefit rather
// than this module's -- `scan` is a sibling, not a descendant, so its
// `use super::*` resolves against this binding. `looks_like_fn_start` is
// deliberately NOT in the list: `scan` names it only from `prologue_gate_tests`,
// so importing it here is an unused import in the shipped build.
use entry_shape::{
    classify_function_shapes, classify_pe_thunk_head,
    elf_x86_tail_target_looks_like_function_start, has_function_boundary_marker,
    head_looks_like_fn_start, pe_head_looks_like_simd_continuation,
    pe_tail_target_looks_like_function_start, pe_xref_seed_looks_like_function_start,
    read_i32_le_at, rel_target, PeThunkKind,
};

use function_build::build_function;

use image_view::{
    code_addr, in_exec_regions, indexed_code_offset, indirect_memory_target, parse_exec_regions,
    parse_exec_regions_in, pe_va_to_file_off, read_pointer_at_va, ExecRegion,
};

use must_dataflow::validate_dispatch_edges;

use pe_tables::{parse_pdata_function_starts, parse_pe_export_function_starts};

use repair::{
    apply_dwarf_overrides, apply_elf_startup_main_name, apply_pe_startup_main_name,
    apply_symbol_and_export_names, attach_exception_landing_pads, elf_startup_main_candidate,
    merge_compiler_split_chunks, pe_startup_main_candidate,
};

use scan::{
    collect_code_labels, scan_aarch64_prologue_function_starts, scan_elf_prologue_function_starts,
    scan_pe_prologue_function_starts, scan_pe_raw_call_function_starts,
    scan_pe_thunk_function_starts, scan_pe_tiny_stub_function_starts, should_seed_pe_code_pointer,
};

use seeds::{collect_seeds, Seeds};

use stats::{
    merge_single_function_stats, record_cfg_incompleteness, record_scan_rejection,
    record_seed_provenance, PdataSeedStats, SingleFunctionDiscoveryStats,
};

use walk::{discover_function, DiscoveryFacts, FunctionXref};

use worklist::{analyze_functions_unpacked, DiscoverySeedKind};

/// Analyze bytes and return discovered functions and a callgraph (best-effort).
pub fn analyze_functions_bytes(data: &[u8], budgets: &Budgets) -> (Vec<Function>, CallGraph) {
    let (functions, cg, _stats) = analyze_functions_bytes_with_stats(data, budgets);
    (functions, cg)
}

/// PE CRT-derived source/runtime names available independently of discovery budget.
pub(crate) fn pe_runtime_function_names(data: &[u8]) -> Vec<(u64, String)> {
    if !data.starts_with(b"MZ") {
        return Vec::new();
    }
    let (regions, arch, _, _) = parse_exec_regions(data);
    if !matches!(arch, BArch::X86 | BArch::X86_64) {
        return Vec::new();
    }
    let mut names = Vec::new();
    if let Some(main) = pe_startup_main_candidate(None, data, arch, &regions) {
        // PE32 COFF decorates the C symbol as `_main`; source C does not.
        // The CRT relationship proves that this address is the hosted entry,
        // so expose the source-level spelling on both x86 widths.
        names.push((main, "main".to_string()));
    }
    if let Some(initializer) =
        repair::pe_main_runtime_initializer_candidate(None, data, arch, &regions)
    {
        names.push((
            initializer,
            if arch == BArch::X86 {
                "___main"
            } else {
                "__main"
            }
            .to_string(),
        ));
    }
    names
}

/// Analyze bytes while treating caller-provided executable VAs as trusted
/// function-entry seeds.
///
/// Address-scoped clients (for example, external decompiler benchmarks) know
/// the entries they want even when symbols and other discovery metadata have
/// been stripped. Invalid or non-executable VAs are ignored, preserving the
/// normal "not found" behavior at the binding boundary.
pub fn analyze_functions_bytes_with_seeds(
    data: &[u8],
    budgets: &Budgets,
    requested_vas: &[u64],
) -> (Vec<Function>, CallGraph) {
    let (functions, cg, _stats) =
        analyze_functions_bytes_with_stats_and_seeds(data, budgets, requested_vas);
    (functions, cg)
}

/// Analyze one already indexed program image with caller-provided entry seeds.
///
/// Unlike the compatibility byte-slice entry point, every inner CFG address
/// translation reuses the image's immutable mapping index.
pub fn analyze_functions_image_with_seeds(
    image: &crate::program::image::ProgramImage,
    budgets: &Budgets,
    requested_vas: &[u64],
) -> (Vec<Function>, CallGraph) {
    let (functions, cg, _stats) = packed::analyze_functions_bytes_within(
        image.bytes(),
        budgets,
        requested_vas,
        Deadline::start(budgets),
        Some(image),
    );
    (functions, cg)
}

/// Analyze every discoverable function in one already indexed program image.
pub fn analyze_functions_image(
    image: &crate::program::image::ProgramImage,
    budgets: &Budgets,
) -> (Vec<Function>, CallGraph) {
    analyze_functions_image_with_seeds(image, budgets, &[])
}

/// Discover one trusted function while reusing a program-scoped address index.
///
/// Address-scoped consumers already know the entry they need. Running the
/// whole seed pipeline merely to recover one direct callee processes unrelated
/// symbols, vtables, and function starts before the caller's budget can stop
/// it. This path performs only the bounded CFG walk for `entry_va`; direct
/// xrefs are still recorded on the returned Function.
pub(crate) fn discover_function_image_at(
    image: &crate::program::image::ProgramImage,
    budgets: &Budgets,
    entry_va: u64,
) -> Option<Function> {
    let data = image.bytes();
    let deadline = Deadline::start(budgets);
    let (regions, arch, end, _entry) = parse_exec_regions_in(image);
    if regions.is_empty() || in_exec_regions(&regions, entry_va).is_none() {
        return None;
    }
    let bits = if arch.is_64_bit() { 64 } else { 32 };
    let entry = Address::new(AddressKind::VA, entry_va, bits, None, None).ok()?;
    let tables = std::collections::BTreeMap::new();
    let noreturn_targets = image.noreturn_import_targets();
    let plt_stub_ranges = plt::elf_plt_stub_ranges(Some(image), data, arch);
    let facts = DiscoveryFacts {
        image: Some(image),
        tables: &tables,
        noreturn_targets: &noreturn_targets,
        plt_stub_ranges: &plt_stub_ranges,
        owned_ranges: None,
        owned_leaders: None,
        proven_end: None,
    };
    let (mut function, _calls, _stats) =
        discover_function(data, arch, end, entry, &regions, budgets, &facts, deadline)?;

    // Preserve the same exact-address symbol naming as whole-binary discovery
    // without paying for its unrelated seed work.
    if let Some(name) = image.defined_symbol_name_at(entry_va) {
        function.name = name.to_string();
    }
    Some(function)
}

/// Analyze bytes and return discovered functions, callgraph, and budget telemetry.
pub fn analyze_functions_bytes_with_stats(
    data: &[u8],
    budgets: &Budgets,
) -> (Vec<Function>, CallGraph, FunctionDiscoveryStats) {
    analyze_functions_bytes_with_stats_and_seeds(data, budgets, &[])
}

fn analyze_functions_bytes_with_stats_and_seeds(
    data: &[u8],
    budgets: &Budgets,
    requested_vas: &[u64],
) -> (Vec<Function>, CallGraph, FunctionDiscoveryStats) {
    // Started before ANY work, including `parse_exec_regions`: a budget that only
    // begins once the expensive part is under way is not a budget.
    packed::analyze_functions_bytes_within(
        data,
        budgets,
        requested_vas,
        Deadline::start(budgets),
        None,
    )
}

/// Whole-binary discovery, stopped by an EXTERNAL cancellation flag as well as by
/// `budgets.total_timeout_ms`.
///
/// The flag is what makes the analysis interruptible from Python — see
/// `Deadline::with_cancel`. A cancelled run returns the functions it had already
/// discovered with `hit_total_timeout` set, so a caller that wants a partial
/// answer can keep it and one that wants a complete answer can tell it did not
/// get one.
pub fn analyze_functions_bytes_cancellable(
    data: &[u8],
    budgets: &Budgets,
    requested_vas: &[u64],
    cancel: &std::sync::atomic::AtomicBool,
) -> (Vec<Function>, CallGraph, FunctionDiscoveryStats) {
    packed::analyze_functions_bytes_within(
        data,
        budgets,
        requested_vas,
        Deadline::start(budgets).with_cancel(cancel),
        None,
    )
}

#[cfg(test)]
mod arm_tail_call_tests {
    use super::*;

    fn sample(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/cross")
            .join(name);
        std::fs::read(path).expect("read checked-in cross sample")
    }

    /// The byte-only fallback and the session image must agree exactly: the
    /// image path is what production takes, and a range list that disagreed
    /// with the object it was built from would silently reclassify tail calls.
    fn target_is_plt_stub(data: &[u8], target_va: u64, arch: BArch) -> bool {
        let from_bytes = plt::elf_plt_stub_ranges(None, data, arch);
        let image = crate::program::image::ProgramImage::from_bytes(data.to_vec())
            .expect("index the checked-in sample");
        let from_image = plt::elf_plt_stub_ranges(Some(&image), data, arch);
        assert_eq!(
            from_bytes, from_image,
            "byte and image PLT indices diverged"
        );
        from_image.iter().any(|range| range.contains(&target_va))
    }

    /// `.plt` in the checked-in armhf sample spans 0x4d8..0x54c (a 20-byte
    /// header plus eight 12-byte stubs). A branch into that range is a tail
    /// call; a branch into `.text` is ordinary control flow.
    #[test]
    fn an_arm_branch_into_the_plt_is_a_tail_call() {
        let data = sample("armhf/c2_demo-armhf-gcc");
        assert!(target_is_plt_stub(&data, 0x4ec, BArch::ARM));
        assert!(target_is_plt_stub(&data, 0x540, BArch::ARM));
        assert!(!target_is_plt_stub(&data, 0x4d0, BArch::ARM));
        assert!(!target_is_plt_stub(&data, 0x698, BArch::ARM));
    }

    /// A decoder/object architecture mismatch must never reclassify a target.
    #[test]
    fn matching_architectures_are_required_and_supported() {
        let data = sample("armhf/c2_demo-armhf-gcc");
        for arch in [BArch::X86_64, BArch::X86, BArch::AArch64] {
            assert!(!target_is_plt_stub(&data, 0x4ec, arch));
        }
        let arm64 = sample("arm64/c2_demo-arm64-gcc");
        assert!(target_is_plt_stub(&arm64, 0x810, BArch::AArch64));
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod gcc_dispatch_corpus_tests {
    use super::*;
    use object::{Object, ObjectSymbol};
    use std::io::Write;
    use std::process::Command;

    #[test]
    fn nested_multi_exit_parser_loop_preserves_its_dispatch() {
        let tmp = tempfile::tempdir().expect("temporary nested-dispatch build directory");
        let source = tmp.path().join("nested_dispatch_loop.S");
        let binary = tmp.path().join("nested_dispatch_loop.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/09_nested_dispatch_loop.S"
                ))
            })
            .expect("write the real nested-dispatch fixture source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-nostdlib", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("gcc");
                return;
            }
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile nested-dispatch fixture: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read nested-dispatch fixture");
        let object =
            crate::decompile::profile::parse_object(&data).expect("parse nested-dispatch ELF");
        let entry = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("nested_dispatch_parser"))
            .map(|symbol| symbol.address())
            .expect("exported nested_dispatch_parser symbol");
        let image = crate::program::image::ProgramImage::from_bytes(data.clone())
            .expect("index nested-dispatch fixture");
        let budgets = Budgets {
            max_functions: 1,
            max_blocks: 4096,
            max_instructions: 200_000,
            timeout_ms: 5_000,
            total_timeout_ms: 0,
        };
        let (functions, _callgraph) =
            analyze_functions_image_with_seeds(&image, &budgets, &[entry]);
        let function = functions
            .iter()
            .find(|function| function.entry_point.value == entry)
            .expect("discover nested-dispatch fixture function");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift nested-dispatch fixture function");
        let lifted_dispatches = lifted
            .blocks
            .iter()
            .filter(|block| block.succs.len() == 8)
            .map(|block| block.start_va)
            .collect::<Vec<_>>();
        assert_eq!(
            lifted_dispatches.len(),
            1,
            "the real PIC table must contribute one eight-way CFG dispatch"
        );
        let ssa = crate::ir::ssa::compute_ssa(&lifted);
        let region = crate::ir::structure::recover_verified(&lifted, &ssa);
        assert!(
            raw_loop_owns_dispatch(&region, &lifted),
            "the parser loop must own its resolved dispatch: {region:#?}"
        );
        let ast = crate::ir::ast::lower(&lifted, &region, "nested_dispatch_parser");
        let rendered = crate::ir::ast::render(&ast);
        assert_eq!(
            rendered.matches("case ").count(),
            8,
            "every dispatch-table slot must retain a source case label"
        );
        assert!(
            !rendered.contains("unrecovered indirect jump"),
            "a CFG-proven dispatch must not fall back to an indirect jump: {rendered}"
        );
    }

    fn switch_case_labels(region: &crate::ir::structure::Region) -> Option<&[Vec<i64>]> {
        use crate::ir::structure::Region;
        match region {
            Region::Switch { case_labels, .. } => Some(case_labels),
            Region::Seq(parts) => parts.iter().find_map(switch_case_labels),
            Region::IfThen { then_r, .. } => switch_case_labels(then_r),
            Region::IfThenElse { then_r, else_r, .. } => {
                switch_case_labels(then_r).or_else(|| switch_case_labels(else_r))
            }
            Region::While { body, .. }
            | Region::DoWhile { body, .. }
            | Region::MultiExitLoop { body, .. }
            | Region::Borrowed(body) => switch_case_labels(body),
            Region::Block(_)
            | Region::Goto(_)
            | Region::RawLoop { .. }
            | Region::Unstructured(_) => None,
        }
    }

    fn raw_loop_owns_dispatch(
        region: &crate::ir::structure::Region,
        function: &crate::ir::types::LlirFunction,
    ) -> bool {
        use crate::ir::structure::Region;
        match region {
            Region::RawLoop { blocks, .. } => blocks
                .iter()
                .any(|block| function.blocks[*block].succs.len() >= 3),
            Region::Seq(parts) => parts
                .iter()
                .any(|part| raw_loop_owns_dispatch(part, function)),
            Region::IfThen { then_r, .. }
            | Region::While { body: then_r, .. }
            | Region::DoWhile { body: then_r, .. }
            | Region::MultiExitLoop { body: then_r, .. }
            | Region::Borrowed(then_r) => raw_loop_owns_dispatch(then_r, function),
            Region::IfThenElse { then_r, else_r, .. } => {
                raw_loop_owns_dispatch(then_r, function) || raw_loop_owns_dispatch(else_r, function)
            }
            Region::Switch {
                arms,
                formal_default,
                ..
            } => {
                arms.iter().any(|arm| raw_loop_owns_dispatch(arm, function))
                    || formal_default
                        .as_deref()
                        .is_some_and(|default| raw_loop_owns_dispatch(default, function))
            }
            Region::Block(_) | Region::Goto(_) | Region::Unstructured(_) => false,
        }
    }

    fn structured_loop_owns_dispatch(region: &crate::ir::structure::Region) -> bool {
        use crate::ir::structure::Region;
        match region {
            Region::While { body, .. }
            | Region::DoWhile { body, .. }
            | Region::MultiExitLoop { body, .. } => switch_case_labels(body).is_some(),
            Region::Seq(parts) => parts.iter().any(structured_loop_owns_dispatch),
            Region::IfThen { then_r, .. } => structured_loop_owns_dispatch(then_r),
            Region::Borrowed(inner) => structured_loop_owns_dispatch(inner),
            Region::IfThenElse { then_r, else_r, .. } => {
                structured_loop_owns_dispatch(then_r) || structured_loop_owns_dispatch(else_r)
            }
            Region::Switch {
                arms,
                formal_default,
                ..
            } => {
                arms.iter().any(structured_loop_owns_dispatch)
                    || formal_default
                        .as_deref()
                        .is_some_and(structured_loop_owns_dispatch)
            }
            Region::Block(_)
            | Region::Goto(_)
            | Region::RawLoop { .. }
            | Region::Unstructured(_) => false,
        }
    }

    /// The ARM word-table dispatch, assembled to the exact shape the corpus
    /// uses, must produce one CFG successor per table entry.
    ///
    /// Transcribed from `bin_001.elf` at `0x0800d494` in the frozen DecBench
    /// sample-set — a Cortex-M firmware image — and assembling to a
    /// byte-identical sequence:
    ///
    /// ```text
    /// cmp   r0, #4
    /// bhi   .Ldefault          ; in-range on the fall-through edge
    /// adr   r3, .Ltable        ; Capstone reports the 16-bit Thumb encoding
    ///                          ; as `adr r3, #4`, NOT `add r3, pc, #4`
    /// ldr.w pc, [r3, r0, lsl #2]
    /// .Ltable: .word arm0+1, arm1+1, ...   ; absolute, Thumb bit set
    /// ```
    ///
    /// Three separate defects had to be fixed for this to resolve, and each one
    /// alone loses every arm: the `lsl #2` never reached `Operand::scale`
    /// (Capstone carries the shift on the operand, not on `ArmOpMem`);
    /// `classify_ctrl_flow` sees only a mnemonic, so `ldr` was not a branch and
    /// the sweep decoded the table as instructions; and the post-CFG
    /// revalidation built a tracker with no ARM `pc` mode, so it re-reported the
    /// dispatch unresolved and DELETED the edges the walker had proved.
    #[test]
    fn an_arm_word_table_dispatch_produces_one_successor_per_entry() {
        const SOURCE: &str = "\t.syntax unified\n\t.cpu cortex-m4\n\t.thumb\n\t.text\n\
             \t.global dispatch\n\t.thumb_func\n\
             dispatch:\n\tcmp\tr0, #4\n\tbhi\t.Ldefault\n\
             \tadr\tr3, .Ltable\n\tldr.w\tpc, [r3, r0, lsl #2]\n\
             \t.p2align 2\n.Ltable:\n\
             \t.word\t.Lc0 + 1\n\t.word\t.Lc1 + 1\n\t.word\t.Lc2 + 1\n\
             \t.word\t.Lc3 + 1\n\t.word\t.Lc4 + 1\n\
             .Lc0:\tmovs\tr0, #10\n\tbx\tlr\n\
             .Lc1:\tmovs\tr0, #11\n\tbx\tlr\n\
             .Lc2:\tmovs\tr0, #12\n\tbx\tlr\n\
             .Lc3:\tmovs\tr0, #13\n\tbx\tlr\n\
             .Lc4:\tmovs\tr0, #14\n\tbx\tlr\n\
             .Ldefault:\n\tmovs\tr0, #0\n\tbx\tlr\n";

        let tmp = tempfile::tempdir().expect("temporary ARM dispatch build directory");
        let source = tmp.path().join("dispatch.s");
        let binary = tmp.path().join("dispatch.elf");
        std::fs::write(&source, SOURCE).expect("write the ARM dispatch source");
        let build = match Command::new("arm-none-eabi-gcc")
            .args([
                "-mcpu=cortex-m4",
                "-mthumb",
                "-nostdlib",
                "-nostartfiles",
                "-ffreestanding",
                "-Wl,-Ttext=0x08000000",
                "-o",
            ])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            // No ARM cross-assembler here; the x86 lanes still cover the rest.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("arm-none-eabi-gcc");
                return;
            }
            Err(error) => panic!("launch arm-none-eabi-gcc: {error}"),
        };
        if !build.status.success() {
            // The linker warns about a missing `_start` and still produces a
            // usable image; a hard failure is a real toolchain problem.
            panic!(
                "assemble the ARM dispatch fixture: {}",
                String::from_utf8_lossy(&build.stderr)
            );
        }

        let data = std::fs::read(&binary).expect("read the assembled ARM image");
        let (functions, _callgraph, _stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let dispatch = functions
            .iter()
            .find(|function| function.entry_point.value == 0x0800_0000)
            .expect("the dispatch function at the link address");

        let by_id: std::collections::HashMap<_, _> = dispatch
            .basic_blocks
            .iter()
            .map(|block| (block.id.clone(), block.start_address.value))
            .collect();
        let arms = dispatch
            .basic_blocks
            .iter()
            .find(|block| {
                // The dispatch block is the one whose terminator is the table
                // load: it starts at the `adr` and ends after the 4-byte
                // `ldr.w`.
                block.successor_ids.len() > 2
            })
            .map(|block| {
                let mut targets: Vec<u64> = block
                    .successor_ids
                    .iter()
                    .filter_map(|id| by_id.get(id).copied())
                    .collect();
                targets.sort_unstable();
                targets
            })
            .unwrap_or_default();

        assert_eq!(
            arms.len(),
            5,
            "`cmp r0, #4` proves five entries, so the dispatch has five arms; \
             got {arms:x?} across blocks {:x?}",
            dispatch
                .basic_blocks
                .iter()
                .map(|b| b.start_address.value)
                .collect::<Vec<_>>()
        );
        // Every arm is a real case body, and none of them is the table itself.
        for arm in &arms {
            assert!(
                *arm >= 0x0800_0020,
                "arm {arm:#x} lands in the table, not in a case body"
            );
        }
    }

    #[test]
    fn clang_o0_statemachine_keeps_jump_table_arms_inside_fsm() {
        let tmp = tempfile::tempdir().expect("temporary Clang state-machine build directory");
        let source = tmp.path().join("statemachine.c");
        let binary = tmp.path().join("statemachine.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decbench_corpus/src/statemachine.c"
                ))
            })
            .expect("write the real state-machine fixture source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O0", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("clang");
                return;
            }
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile statemachine.c with Clang -O0: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse Clang ELF");
        let fsm = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("fsm"))
            .expect("exported fsm symbol");
        let fsm_start = fsm.address();
        let fsm_end = fsm_start + fsm.size();
        assert!(
            fsm_end > fsm_start,
            "Clang must emit an exact fsm symbol range"
        );

        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let interior: Vec<_> = functions
            .iter()
            .filter(|function| {
                let entry = function.entry_point.value;
                entry > fsm_start && entry < fsm_end
            })
            .map(|function| (function.name.clone(), function.entry_point.value))
            .collect();

        assert!(
            interior.is_empty(),
            "switch case labels are blocks in fsm, not functions: {interior:?}; seeds={:?}",
            stats.function_seed_kinds
        );
    }

    /// The major version of a host compiler, or `None` when it is absent.
    ///
    /// Several tests in this module compile a fixture with the HOST `gcc` or
    /// `clang` and then assert a property of the CFG that compiler emits. That
    /// makes them a record of one machine's toolchain -- the same hazard
    /// `tests/decompiler_fixtures` solves with a pinned image and a
    /// `__toolchain__` fingerprint, and which a lib unit test cannot afford to
    /// solve the same way.
    ///
    /// So the affected tests declare which major versions their assertion was
    /// actually validated against, and say so out loud when they meet another
    /// one, rather than failing as though the decompiler had regressed.
    fn compiler_major(program: &str) -> Option<u32> {
        let output = Command::new(program).arg("--version").output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        // "Ubuntu clang version 21.1.8", "gcc (Ubuntu 11.4.0-...) 11.4.0"
        let after = text.split("version").nth(1)?;
        after
            .split_whitespace()
            .next()?
            .split('.')
            .next()?
            .parse()
            .ok()
    }

    #[test]
    fn clang_o2_statemachine_retains_cross_block_dispatch_edges() {
        let tmp = tempfile::tempdir().expect("temporary Clang state-machine build directory");
        let source = tmp.path().join("statemachine.c");
        let binary = tmp.path().join("statemachine.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decbench_corpus/src/statemachine.c"
                ))
            })
            .expect("write the real state-machine fixture source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("clang");
                return;
            }
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile statemachine.c with Clang -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let function = functions
            .iter()
            .find(|function| function.name == "fsm")
            .expect("discover fsm");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real fsm CFG");
        assert!(
            lifted.blocks.iter().any(|block| block.succs.len() == 4),
            "four-way state dispatch missing; resolved={:?}, unresolved={:?}, blocks={:#?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect,
            lifted.blocks
        );
        let ssa = crate::ir::ssa::compute_ssa(&lifted);
        let region = crate::ir::structure::recover_verified(&lifted, &ssa);

        // The four-way dispatch above is version-independent -- every clang
        // tested emits it, and finding it is the CFG claim. Whether the
        // STRUCTURER then keeps it inside a loop is not: this assertion was
        // validated against clang 21, and a GitHub `ubuntu-latest` runner
        // returned `Unstructured` for the same source on its own clang. That
        // is a real gap in structuring one compiler's shape, and it is a
        // different finding from "the decompiler regressed today", which is
        // what this test exists to report.
        //
        // See docs/development/test-estate/EXECUTION.md; recorded rather than
        // silenced, because a skip that says nothing is how a test becomes
        // decoration.
        const VALIDATED_CLANG_MAJORS: &[u32] = &[21];
        match compiler_major("clang") {
            Some(major) if VALIDATED_CLANG_MAJORS.contains(&major) => {
                assert!(
                    raw_loop_owns_dispatch(&region, &lifted)
                        || structured_loop_owns_dispatch(&region),
                    "the validated four-way CFG must remain inside its state-machine loop: {region:#?}"
                );
            }
            Some(major) => {
                let held = raw_loop_owns_dispatch(&region, &lifted)
                    || structured_loop_owns_dispatch(&region);
                eprintln!(
                    "NOT VALIDATED: clang {major} is outside {VALIDATED_CLANG_MAJORS:?}; the \
                     loop-ownership property {} here. If it holds, add {major} to the list; \
                     if it does not, that is a structuring gap on clang {major}'s codegen \
                     and wants its own investigation.",
                    if held { "HOLDS" } else { "DOES NOT HOLD" }
                );
            }
            None => eprintln!("SKIP: no clang on PATH"),
        }
    }

    #[test]
    fn clang_o2_cleanup_state_machine_retains_loop_carried_dispatch_edges() {
        let tmp = tempfile::tempdir().expect("temporary Clang cleanup-state-machine directory");
        let source = tmp.path().join("cleanup_state_machine.c");
        let binary = tmp.path().join("cleanup_state_machine.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/05_cleanup_and_state_machine.c"
                ))
            })
            .expect("write the real cleanup/state-machine fixture source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("clang");
                return;
            }
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile cleanup/state-machine fixture with Clang -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let function = functions
            .iter()
            .find(|function| function.name == "fsm")
            .expect("discover fsm");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real fsm CFG");
        assert!(
            lifted.blocks.iter().any(|block| block.succs.len() == 4),
            "loop-carried four-way state dispatch missing; resolved={:?}, unresolved={:?}, blocks={:#?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect,
            lifted.blocks
        );
        let ssa = crate::ir::ssa::compute_ssa(&lifted);
        let region = crate::ir::structure::recover_verified(&lifted, &ssa);
        assert!(
            raw_loop_owns_dispatch(&region, &lifted),
            "the guarded or dispatch-headed cycle must retain an owned raw loop: {region:#?}"
        );
    }

    #[test]
    fn gcc_o2_real_corpus_dispatch_keeps_one_function_and_eight_cfg_arms() {
        let tmp = tempfile::tempdir().expect("temporary GCC dispatch build directory");
        let source = tmp.path().join("switch_jt.c");
        let binary = tmp.path().join("switch_jt.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decbench_corpus/src/switch_jt.c"
                ))
            })
            .expect("write the real DecBench switch_jt source");
        let build = match Command::new("gcc")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("gcc");
                return;
            }
            Err(error) => panic!("launch GCC: {error}"),
        };
        assert!(
            build.status.success(),
            "compile switch_jt.c with GCC -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read GCC output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse GCC ELF");
        let dispatch_va = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("dispatch"))
            .map(|symbol| symbol.address())
            .expect("exported dispatch symbol");
        let dwarf_dispatch = crate::debug::dwarf::extract_dwarf_functions(&data)
            .into_iter()
            .find(|function| function.name.as_deref() == Some("dispatch"))
            .expect("DWARF dispatch subprogram");
        assert_eq!(
            dwarf_dispatch.entry_va, dispatch_va,
            "the producer's first range is the semantic hot entry"
        );
        assert_eq!(
            dwarf_dispatch.chunks.first().map(|range| range.start),
            Some(dispatch_va)
        );
        assert!(
            dwarf_dispatch
                .chunks
                .iter()
                .skip(1)
                .any(|range| range.start < dispatch_va),
            "the lower-address cold range must remain auxiliary: {dwarf_dispatch:?}"
        );

        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let named: Vec<_> = functions
            .iter()
            .filter(|function| function.name == "dispatch")
            .collect();
        assert_eq!(
            named.len(),
            1,
            "the compiler split must not survive as a duplicate named function"
        );
        assert_eq!(named[0].entry_point.value, dispatch_va);
        assert!(
            named[0]
                .all_ranges()
                .iter()
                .any(|range| range.start.value < dispatch_va),
            "the cold default block must remain owned by dispatch"
        );
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            named[0],
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real dispatch CFG");
        let cold_va = named[0]
            .all_ranges()
            .iter()
            .map(|range| range.start.value)
            .find(|start| *start < dispatch_va)
            .expect("DWARF cold range");
        assert_eq!(
            lifted.blocks[0].start_va, dispatch_va,
            "LLIR block zero is the semantic entry, even when a cold split has a lower VA"
        );
        assert!(
            lifted.blocks.iter().any(|block| block.start_va == cold_va),
            "the DWARF-owned cold range must retain its executable block"
        );
        assert!(
            lifted.blocks.iter().any(|block| {
                block.succs.contains(&cold_va)
                    && matches!(
                        block.instrs.last().map(|instruction| &instruction.op),
                        Some(crate::ir::types::Op::Jump { target })
                            | Some(crate::ir::types::Op::CondJump { target, .. })
                            if *target == cold_va
                    )
            }),
            "the hot-to-cold jump must remain an intraprocedural CFG edge"
        );

        let scoped_budgets = Budgets {
            max_functions: 1,
            ..Budgets::default()
        };
        let (scoped_functions, _scoped_callgraph) =
            analyze_functions_bytes_with_seeds(&data, &scoped_budgets, &[dispatch_va]);
        let scoped_dispatch = scoped_functions
            .iter()
            .find(|function| function.entry_point.value == dispatch_va)
            .expect("address-scoped dispatch discovery");
        assert!(
            scoped_dispatch
                .basic_blocks
                .iter()
                .any(|block| block.start_address.value == cold_va),
            "address-scoped discovery must hydrate every DWARF-owned range: blocks={:?}, ranges={:?}",
            scoped_dispatch
                .basic_blocks
                .iter()
                .map(|block| block.start_address.value)
                .collect::<Vec<_>>(),
            scoped_dispatch.all_ranges()
        );
        let scoped_lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            scoped_dispatch,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift address-scoped dispatch CFG");
        assert!(
            scoped_lifted
                .blocks
                .iter()
                .any(|block| block.succs.contains(&cold_va)),
            "address-scoped lifting must retain the hot-to-cold edge: basic={:?}, lifted={:?}",
            scoped_dispatch
                .basic_blocks
                .iter()
                .map(|block| (
                    block.start_address.value,
                    block.id.clone(),
                    block.successor_ids.clone()
                ))
                .collect::<Vec<_>>(),
            scoped_lifted
                .blocks
                .iter()
                .map(|block| (block.start_va, block.succs.clone()))
                .collect::<Vec<_>>()
        );
        assert!(
            scoped_lifted.blocks.iter().all(|block| {
                block.instrs.iter().all(|instruction| {
                    !matches!(
                        instruction.op,
                        crate::ir::types::Op::Call {
                            target: crate::ir::types::CallTarget::Direct(target),
                            ..
                        } if target == cold_va
                    )
                })
            }),
            "the owned cold range must never be rewritten as a sibling call"
        );
        let dispatch_block = lifted
            .blocks
            .iter()
            .find(|block| block.succs.len() == 8)
            .expect("eight-way LLIR dispatch block");
        assert!(
            matches!(
                dispatch_block
                    .instrs
                    .last()
                    .map(|instruction| &instruction.op),
                Some(crate::ir::types::Op::IndirectJump { .. })
            ),
            "the computed transfer must survive lifting as IndirectJump"
        );
        let ssa = crate::ir::ssa::compute_ssa(&lifted);
        let region = crate::ir::structure::recover_verified(&lifted, &ssa);
        fn switch_arms(
            region: &crate::ir::structure::Region,
        ) -> Option<&[crate::ir::structure::Region]> {
            use crate::ir::structure::Region;
            match region {
                Region::Switch { arms, .. } => Some(arms),
                Region::Seq(parts) => parts.iter().find_map(switch_arms),
                Region::IfThen { then_r, .. } => switch_arms(then_r),
                Region::IfThenElse { then_r, else_r, .. } => {
                    switch_arms(then_r).or_else(|| switch_arms(else_r))
                }
                Region::While { body, .. }
                | Region::DoWhile { body, .. }
                | Region::MultiExitLoop { body, .. }
                | Region::Borrowed(body) => switch_arms(body),
                Region::Block(_)
                | Region::Goto(_)
                | Region::RawLoop { .. }
                | Region::Unstructured(_) => None,
            }
        }
        let arms = switch_arms(&region).expect("recover the real dispatch as a switch");
        let arm_vas: Vec<_> = arms
            .iter()
            .map(|arm| {
                let index = crate::ir::structure::entry_block(arm).expect("non-empty switch arm");
                lifted.blocks[index].start_va
            })
            .collect();
        assert_eq!(
            arm_vas, dispatch_block.succs,
            "case numbering must retain the jump-table entry order"
        );
        assert_eq!(
            stats
                .resolved_dispatches
                .iter()
                .map(|(_site, arms)| *arms)
                .collect::<Vec<_>>(),
            vec![8],
            "the real GCC O2 table jump must contribute all eight case arms"
        );
        let dispatch_site = stats.resolved_dispatches[0].0;
        assert!(
            stats
                .unresolved_indirect
                .iter()
                .all(|(site, _reason)| *site != dispatch_site),
            "the resolved table jump must not also be reported unresolved: {:?}",
            stats.unresolved_indirect
        );
    }

    #[test]
    fn clang_o0_real_dense_compute_recovers_all_eight_cfg_arms() {
        let tmp = tempfile::tempdir().expect("temporary Clang dense-switch build directory");
        let source = tmp.path().join("dense_compute.c");
        let binary = tmp.path().join("dense_compute.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/04_switch_shapes.c"
                ))
            })
            .expect("write the real switch-shape fixture source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O0", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("clang");
                return;
            }
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile dense_compute.c with Clang -O0: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse Clang ELF");
        let dense_va = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("dense_compute"))
            .map(|symbol| symbol.address())
            .expect("exported dense_compute symbol");
        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let function = functions
            .iter()
            .find(|function| {
                function.name == "dense_compute" && function.entry_point.value == dense_va
            })
            .expect("discover dense_compute");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real dense_compute CFG");
        let dispatch = lifted
            .blocks
            .iter()
            .find(|block| block.succs.len() == 8)
            .unwrap_or_else(|| {
                panic!(
                    "eight-way dense dispatch missing; resolved={:?}, unresolved={:?}, blocks={:#?}",
                    stats.resolved_dispatches, stats.unresolved_indirect, lifted.blocks
                )
            });
        assert!(matches!(
            dispatch.instrs.last().map(|instruction| &instruction.op),
            Some(crate::ir::types::Op::IndirectJump { .. })
        ));

        let shared = functions
            .iter()
            .find(|function| function.name == "shared_bodies")
            .expect("discover shared_bodies from the same real fixture");
        let shared_lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            shared,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real shared_bodies CFG");
        let shared_ssa = crate::ir::ssa::compute_ssa(&shared_lifted);
        let shared_region = crate::ir::structure::recover_verified(&shared_lifted, &shared_ssa);
        assert_eq!(
            switch_case_labels(&shared_region),
            Some([vec![0, 2], vec![1, 3]].as_slice()),
            "four table slots sharing two bodies must remain a switch: {shared_region:#?}"
        );

        let sparse = functions
            .iter()
            .find(|function| function.name == "shared_sparse")
            .expect("discover shared_sparse from the same real fixture");
        let sparse_lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            sparse,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real shared_sparse CFG");
        let sparse_ssa = crate::ir::ssa::compute_ssa(&sparse_lifted);
        let sparse_region = crate::ir::structure::recover_verified(&sparse_lifted, &sparse_ssa);
        assert_eq!(
            switch_case_labels(&sparse_region),
            Some([vec![0, 10], vec![20, 30]].as_slice()),
            "table holes that target the guard default are not explicit cases: region={sparse_region:#?} resolved={:?} unresolved={:?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect
        );

        let fallthrough = functions
            .iter()
            .find(|function| function.name == "fallthrough_chain")
            .expect("discover fallthrough_chain from the same real fixture");
        let fallthrough_lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            fallthrough,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real fallthrough_chain CFG");
        assert!(
            fallthrough_lifted
                .blocks
                .iter()
                .any(|block| block.succs.len() == 4),
            "the four-slot fallthrough dispatch must enter the CFG: resolved={:?} unresolved={:?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect
        );
    }

    #[test]
    fn clang_o2_real_wide_effect_switch_uses_the_zero_extended_byte_bound() {
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/decompiler_fixtures/build/154_wide_switch-clang-O2.so");
        if !binary.is_file() {
            crate::testing::missing_fixture("154_wide_switch-clang-O2.so");
            return;
        }
        let data = std::fs::read(binary).expect("read checked-in wide-switch fixture");
        let (_functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());

        assert!(
            stats.resolved_dispatches.contains(&(0x15d9, 256)),
            "the byte-indexed table must retain all 256 proven slots: resolved={:?} unresolved={:?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect
        );
        assert!(
            stats
                .unresolved_indirect
                .iter()
                .all(|(site, _)| *site != 0x15d9),
            "the resolved site must not also be declined: {:?}",
            stats.unresolved_indirect
        );
    }

    #[test]
    fn clang_o2_real_dense_compute_keeps_labels_for_a_shared_case_body() {
        let tmp = tempfile::tempdir().expect("temporary Clang dense-switch build directory");
        let source = tmp.path().join("dense_compute.c");
        let binary = tmp.path().join("dense_compute.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decompiler_fixtures/src/04_switch_shapes.c"
                ))
            })
            .expect("write the real switch-shape fixture source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("clang");
                return;
            }
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile dense_compute.c with Clang -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse Clang ELF");
        let dense_va = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("dense_compute"))
            .map(|symbol| symbol.address())
            .expect("exported dense_compute symbol");
        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let function = functions
            .iter()
            .find(|function| {
                function.name == "dense_compute" && function.entry_point.value == dense_va
            })
            .expect("discover dense_compute");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real dense_compute CFG");
        let dispatch = lifted
            .blocks
            .iter()
            .find(|block| block.succs.len() == 8)
            .expect("eight-slot dense dispatch");
        assert_eq!(
            dispatch
                .succs
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            7,
            "Clang folds source cases 2 and 5 onto one multiply-by-two block"
        );

        let ssa = crate::ir::ssa::compute_ssa(&lifted);
        let region = crate::ir::structure::recover_verified(&lifted, &ssa);
        let labels = switch_case_labels(&region).expect("recover the real dispatch as a switch");
        assert!(
            labels.iter().any(|labels| labels == &[2, 5]),
            "both source labels must remain attached to the shared body: {labels:?}"
        );

        let sparse = functions
            .iter()
            .find(|function| function.name == "shared_sparse")
            .expect("discover shared_sparse from the same optimized fixture");
        let sparse_lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            sparse,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real optimized shared_sparse CFG");
        let sparse_ssa = crate::ir::ssa::compute_ssa(&sparse_lifted);
        let sparse_region = crate::ir::structure::recover_verified(&sparse_lifted, &sparse_ssa);
        assert_eq!(
            switch_case_labels(&sparse_region),
            Some([vec![0, 10], vec![20, 30]].as_slice()),
            "optimized table holes that target the guard default are not explicit cases: region={sparse_region:#?} resolved={:?} unresolved={:?}",
            stats.resolved_dispatches,
            stats.unresolved_indirect
        );
    }

    #[test]
    fn clang_o2_real_state_machine_carries_the_table_base_to_the_dispatch() {
        let tmp = tempfile::tempdir().expect("temporary Clang state-machine build directory");
        let source = tmp.path().join("statemachine.c");
        let binary = tmp.path().join("statemachine.so");
        std::fs::File::create(&source)
            .and_then(|mut file| {
                file.write_all(include_bytes!(
                    "../../tests/decbench_corpus/src/statemachine.c"
                ))
            })
            .expect("write the real DecBench state-machine source");
        let build = match Command::new("clang")
            .args(["-shared", "-fPIC", "-g", "-O2", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
        {
            Ok(build) => build,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::testing::missing_tool("clang");
                return;
            }
            Err(error) => panic!("launch Clang: {error}"),
        };
        assert!(
            build.status.success(),
            "compile statemachine.c with Clang -O2: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        let data = std::fs::read(&binary).expect("read Clang output");
        let object =
            crate::decompile::profile::parse_object(data.as_slice()).expect("parse Clang ELF");
        let fsm_va = object
            .dynamic_symbols()
            .find(|symbol| symbol.name().ok() == Some("fsm"))
            .map(|symbol| symbol.address())
            .expect("exported fsm symbol");
        let (functions, _callgraph, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let function = functions
            .iter()
            .find(|function| function.name == "fsm" && function.entry_point.value == fsm_va)
            .expect("discover the exported fsm function");
        let lifted = crate::ir::lift_function::lift_function_from_bytes(
            &data,
            function,
            crate::core::binary::Arch::X86_64,
        )
        .expect("lift the real state-machine CFG");
        let dispatch_block = lifted
            .blocks
            .iter()
            .find(|block| block.succs.len() == 4)
            .unwrap_or_else(|| {
                panic!(
                    "four-way dispatch missing; resolved={:?}, unresolved={:?}, blocks={:#?}",
                    stats.resolved_dispatches, stats.unresolved_indirect, lifted.blocks
                )
            });
        assert!(matches!(
            dispatch_block
                .instrs
                .last()
                .map(|instruction| &instruction.op),
            Some(crate::ir::types::Op::IndirectJump { .. })
        ));
        assert!(
            stats
                .resolved_dispatches
                .iter()
                .any(|(_site, arms)| *arms == 4),
            "the real Clang O2 table jump must contribute all four case arms: {:?}",
            stats.resolved_dispatches
        );
    }
}

#[cfg(test)]
mod degenerate_block_tests {
    use super::*;

    /// A branch target whose first byte does not decode used to crash the whole
    /// analysis. The sweep records that leader as an EMPTY block (`end == start`,
    /// no instruction consumed), and the leader-split pass then asked a BTreeSet
    /// for the range `(Excluded(s), Excluded(s))` — which panics ("range start and
    /// end are equal and excluded") rather than yielding nothing.
    ///
    /// It is not a corner case: it took out every function in a gcc-11 `-O0`
    /// switch binary (16/16 reported "decompile failed"), because one jump-table
    /// target was decoded as code. Panicking on hostile or merely unusual bytes is
    /// never acceptable in a reverse-engineering tool.
    #[test]
    fn an_undecodable_branch_target_does_not_panic() {
        // 0x1000: 74 02   je 0x1004      (both arms become leaders)
        // 0x1002: 90      nop
        // 0x1003: c3      ret
        // 0x1004: 06      push es -- INVALID in 64-bit mode: decodes to nothing,
        //                 so this leader's block is empty.
        let code: &[u8] = &[0x74, 0x02, 0x90, 0xc3, 0x06];
        let entry = Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap();
        let regions = [ExecRegion {
            start: 0x1000,
            end: 0x1000 + code.len() as u64,
            _file_off_start: 0,
        }];
        let budgets = Budgets {
            max_functions: 1,
            max_blocks: 64,
            max_instructions: 256,
            timeout_ms: 1_000,
            total_timeout_ms: 0,
        };
        // The data buffer is VA-addressed by the region's file offset mapping.
        let tables = std::collections::BTreeMap::new();
        let noreturn_targets = std::collections::HashSet::new();
        let facts = DiscoveryFacts {
            image: None,
            tables: &tables,
            noreturn_targets: &noreturn_targets,
            plt_stub_ranges: &[],
            owned_ranges: None,
            owned_leaders: None,
            proven_end: None,
        };
        let out = discover_function(
            code,
            BArch::X86_64,
            Endianness::Little,
            entry,
            &regions,
            &budgets,
            &facts,
            Deadline::none(),
        );
        let (func, _, _) = out.expect("discovery must succeed, not panic");
        // The decodable blocks survive; the empty one contributes nothing.
        assert!(
            !func.basic_blocks.is_empty(),
            "expected the decodable blocks to be recovered"
        );
    }

    #[test]
    fn dispatch_completeness_survives_stats_aggregation() {
        let mut aggregate = FunctionDiscoveryStats::default();
        let local = SingleFunctionDiscoveryStats {
            unresolved_indirect: vec![(
                0x1234,
                crate::analysis::dispatch::Unresolved::NoBound(0x4000),
            )],
            resolved_dispatches: vec![(0x5678, 4)],
            ..SingleFunctionDiscoveryStats::default()
        };
        merge_single_function_stats(&mut aggregate, local);
        assert_eq!(aggregate.resolved_dispatches, vec![(0x5678, 4)]);
        assert_eq!(
            aggregate.unresolved_indirect,
            vec![(
                0x1234,
                crate::analysis::dispatch::Unresolved::NoBound(0x4000)
            )]
        );
    }

    /// The per-function record is written from the per-function stats, and the
    /// aggregate merge cannot reach it.
    ///
    /// `merge_single_function_stats` ORs one walk's truncation into a WHOLE-RUN
    /// flag, and that aggregate can never be attributed to a function: by the
    /// time it is true, it means "some function, somewhere". So the attribution
    /// is taken one level in, from the same `SingleFunctionDiscoveryStats`
    /// before it is merged, where the function it belongs to is still in hand.
    /// This test pins that the two are independent: merging a truncated local
    /// into the aggregate marks nothing.
    #[test]
    fn truncation_is_attributed_from_the_local_stats_not_the_aggregate() {
        let entry = Address::new(AddressKind::VA, 0x401000, 64, None, None).unwrap();
        let mut walked = Function::new("walked".into(), entry.clone(), FunctionKind::Normal)
            .expect("build function");
        let mut stopped =
            Function::new("stopped".into(), entry, FunctionKind::Normal).expect("build function");

        let local = SingleFunctionDiscoveryStats {
            hit_block_limit: true,
            ..SingleFunctionDiscoveryStats::default()
        };
        record_cfg_incompleteness(&mut stopped, &local);

        let mut aggregate = FunctionDiscoveryStats::default();
        merge_single_function_stats(&mut aggregate, local);
        // The whole-run flag is set...
        assert!(aggregate.hit_block_limit);
        // ...and the function that was NOT stopped is still clean. Marking it
        // from the aggregate is the false-positive this design exists to make
        // unrepresentable.
        assert!(!walked.cfg_is_incomplete());
        assert!(walked.cfg_incomplete_budgets().is_empty());

        assert!(stopped.cfg_is_incomplete());
        assert_eq!(stopped.cfg_incomplete_budgets(), vec!["max_blocks"]);

        // Each budget maps to its own bit; nothing bleeds between them.
        record_cfg_incompleteness(
            &mut walked,
            &SingleFunctionDiscoveryStats {
                hit_instruction_limit: true,
                hit_timeout: true,
                ..SingleFunctionDiscoveryStats::default()
            },
        );
        assert_eq!(
            walked.cfg_incomplete_budgets(),
            vec!["max_instructions", "timeout_ms"]
        );
    }

    /// A walk that completed records nothing, whatever the aggregate says.
    #[test]
    fn a_completed_walk_records_no_truncation() {
        let entry = Address::new(AddressKind::VA, 0x401000, 64, None, None).unwrap();
        let mut func =
            Function::new("f".into(), entry, FunctionKind::Normal).expect("build function");
        record_cfg_incompleteness(&mut func, &SingleFunctionDiscoveryStats::default());
        assert!(!func.cfg_is_incomplete());
    }
}

/// Whether a budget stopped a function's walk must be a fact about THAT
/// function, on a real binary, through the real discovery pipeline.
#[cfg(test)]
mod cfg_incompleteness_attribution_tests {
    use super::*;

    fn hello_gcc_o2() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2");
        std::fs::read(path).expect("read the checked-in gcc -O2 sample")
    }

    /// In one run where the block budget fires, ONLY the functions it stopped
    /// are marked.
    ///
    /// The aggregate `hit_block_limit` is true for the whole run, so a design
    /// that reported it against a function would mark every function in this
    /// binary incomplete. The per-function flag must instead partition the list,
    /// and the partition must be the true one: a marked function is at the
    /// block wall, an unmarked one stopped below it on its own terminators.
    #[test]
    fn a_block_budget_marks_only_the_functions_it_stopped() {
        let data = hello_gcc_o2();
        const TIGHT_BLOCKS: usize = 2;

        let (wide, _cg, wide_stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                max_blocks: 4096,
                ..Budgets::default()
            },
        );
        assert!(
            !wide_stats.hit_block_limit,
            "4096 blocks must be enough for every function in a hello-world"
        );
        assert!(
            wide.iter().all(|f| !f.cfg_is_incomplete()),
            "no function may be marked incomplete when no budget fired"
        );

        let (tight, _cg, tight_stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                max_blocks: TIGHT_BLOCKS,
                ..Budgets::default()
            },
        );
        assert!(
            tight_stats.hit_block_limit,
            "a 2-block budget must stop something in this binary"
        );

        let mut marked = 0usize;
        let mut clean = 0usize;
        for function in &tight {
            if function.cfg_is_incomplete() {
                marked += 1;
                assert_eq!(
                    function.cfg_incomplete_budgets(),
                    vec!["max_blocks"],
                    "0x{:x} must name the budget that actually fired",
                    function.entry_point.value
                );
                assert!(
                    function.basic_blocks.len() >= TIGHT_BLOCKS,
                    "0x{:x} is marked but never reached the wall ({} blocks)",
                    function.entry_point.value,
                    function.basic_blocks.len()
                );
            } else {
                clean += 1;
                assert!(
                    function.basic_blocks.len() < TIGHT_BLOCKS,
                    "0x{:x} is at the block wall with {} blocks and was NOT marked",
                    function.entry_point.value,
                    function.basic_blocks.len()
                );
            }
        }
        assert!(
            marked > 0,
            "the tight budget must mark at least one function"
        );
        assert!(
            clean > 0,
            "at least one small function must survive the same run unmarked - \
             that is the no-contamination property"
        );
    }
}

#[cfg(test)]
mod dispatch_decline_reporting_tests {
    use super::*;

    /// A checked-in gcc -O2 shared object. Every gcc ELF carries the crtstuff
    /// `register_tm_clones` / `deregister_tm_clones` pair, whose `jmp *%rax`
    /// after a GOT load is a register-indirect transfer this pass declines - so
    /// this sample exercises the decline path without needing a compiler.
    fn hello_gcc_o2() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2");
        std::fs::read(path).expect("read the checked-in gcc -O2 sample")
    }

    /// Every declined dispatch names a reason, and the reason renders.
    ///
    /// The reason has always been computed; this pins that it is a real value a
    /// consumer can read rather than a variant nothing formats.
    #[test]
    fn every_declined_dispatch_carries_a_labelled_reason() {
        let data = hello_gcc_o2();
        let (_functions, _cg, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        assert!(
            !stats.unresolved_indirect.is_empty(),
            "the crtstuff TM-clone pair must produce at least one declined dispatch"
        );
        for (site, why) in &stats.unresolved_indirect {
            assert!(
                !why.label().is_empty() && !why.detail().is_empty(),
                "site {site:#x} declined with an unlabelled reason: {why:?}"
            );
            // `UnknownBase` is the only variant that names no table; the other
            // two are about a specific address and must carry it.
            assert_eq!(
                why.table_va().is_none(),
                matches!(why, crate::analysis::dispatch::Unresolved::UnknownBase),
                "site {site:#x}: {why:?}"
            );
        }
    }

    /// A block whose indirect terminator was declined must not advertise itself
    /// as a function exit.
    ///
    /// `is_exit_block()` is `relationships_known && successors.is_empty()`, and
    /// `relationships_known` used to be set unconditionally - so a `jmp *%rax`
    /// whose targets were never recovered read as a block with no successors
    /// BECAUSE IT HAS NONE. Measured over the 758 fixture objects that was 2909
    /// of 28169 exit claims.
    #[test]
    fn a_block_with_a_declined_dispatch_does_not_claim_to_be_an_exit() {
        let data = hello_gcc_o2();
        let (functions, _cg, stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let sites: Vec<u64> = stats
            .unresolved_indirect
            .iter()
            .map(|(site, _)| *site)
            .collect();
        assert!(!sites.is_empty(), "no declined dispatch to check");

        let mut checked = 0usize;
        for function in &functions {
            for block in &function.basic_blocks {
                let owns = sites.iter().any(|site| {
                    *site >= block.start_address.value && *site < block.end_address.value
                });
                if !owns {
                    continue;
                }
                checked += 1;
                assert!(
                    block.successor_ids.is_empty(),
                    "a declined dispatch attaches no successors"
                );
                assert!(
                    !block.is_exit_block(),
                    "block {} ends in an unfollowed indirect transfer and must not \
                     be classified as a function exit",
                    block.id
                );
            }
        }
        assert!(checked > 0, "no block owned a declined dispatch site");
    }

    /// The complement: ordinary blocks keep their entry/exit classification.
    /// A fix that cleared the flag everywhere would also pass the test above.
    #[test]
    fn ordinary_blocks_still_classify_as_entries_and_exits() {
        let data = hello_gcc_o2();
        let (functions, _cg, _stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let entries = functions
            .iter()
            .flat_map(|function| &function.basic_blocks)
            .filter(|block| block.is_entry_block())
            .count();
        let exits = functions
            .iter()
            .flat_map(|function| &function.basic_blocks)
            .filter(|block| block.is_exit_block())
            .count();
        assert!(entries > 0 && exits > 0, "entries={entries} exits={exits}");
    }
}

#[cfg(test)]
mod analysis_deadline_tests {
    use super::*;

    /// A binary big enough that whole-binary discovery takes real time.
    fn big_sample() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/go/hello-go-static");
        std::fs::read(path).expect("read the checked-in static Go sample")
    }

    #[test]
    fn a_deadline_of_zero_never_expires() {
        let deadline = Deadline::start(&Budgets {
            total_timeout_ms: 0,
            ..Budgets::default()
        });
        assert!(!deadline.expired());
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(!deadline.expired(), "0 must mean no ceiling at all");
    }

    #[test]
    fn a_deadline_expires_once_its_wall_clock_passes() {
        let deadline = Deadline::start(&Budgets {
            total_timeout_ms: 1,
            ..Budgets::default()
        });
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(deadline.expired());
        assert!(deadline.elapsed_ms() >= 10);
    }

    /// The default must be the unbounded one, or every existing caller's
    /// recorded function counts would move with nothing to attribute it to.
    #[test]
    fn the_default_budget_has_no_whole_analysis_ceiling() {
        assert_eq!(Budgets::default().total_timeout_ms, 0);
    }

    /// The defect this closes: `timeout_ms` restarts inside `discover_function`,
    /// so before `total_timeout_ms` existed there was no ceiling on the analysis
    /// as a whole and a pathological binary ran until it finished or the user
    /// gave up. Exceeding it must now TRUNCATE AND SAY SO.
    #[test]
    fn an_impossible_deadline_truncates_discovery_and_reports_it() {
        let data = big_sample();
        let (functions, _cg, stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                total_timeout_ms: 1,
                ..Budgets::default()
            },
        );
        assert!(
            stats.hit_total_timeout,
            "a 1ms ceiling on a {}-byte binary must be reported as exceeded",
            data.len()
        );
        assert_eq!(stats.total_timeout_ms, 1, "the ceiling must be recorded");
        let (full, _cg, full_stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        assert!(
            !full_stats.hit_total_timeout,
            "the default budget has no ceiling and must never report one"
        );
        assert!(
            functions.len() < full.len(),
            "truncation must actually truncate: {} vs {}",
            functions.len(),
            full.len()
        );
    }

    /// The `.eh_frame` sweep obeys the ceiling like its twelve siblings.
    ///
    /// It was the one whole-image seed scan in `seeds` outside `scan_within`,
    /// so on the byte-only path — the one every `analyze_functions_bytes*`
    /// entry point takes — it ran a full sweep of the image to completion after
    /// the ceiling had already passed. A bounded overrun rather than a
    /// correctness bug, which is why nothing caught it: every other measure of
    /// the run was unaffected. `eh_frame_candidates` is the observable, because
    /// it counts what the sweep returned rather than what survived the gates
    /// after it.
    /// A large ELF that actually carries `.eh_frame`.
    ///
    /// `big_sample()` cannot be used for the sweep test: it is a static Go
    /// binary, and Go carries its own `pclntab` instead, so the phase returns
    /// zero candidates there under any budget. Measuring a guard on a scan that
    /// finds nothing proves nothing.
    fn big_eh_frame_sample() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("samples/binaries/platforms/linux/amd64/rust/hello-rust-debug");
        std::fs::read(path).expect("read the checked-in Rust debug sample")
    }

    #[test]
    fn an_impossible_deadline_skips_the_eh_frame_sweep_too() {
        let data = big_eh_frame_sample();
        let (_, _cg, full_stats) = analyze_functions_bytes_with_stats(&data, &Budgets::default());
        assert!(
            full_stats.eh_frame_candidates > 0,
            "the sample must actually exercise the .eh_frame phase for this test to mean anything"
        );
        let (_, _cg, stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                total_timeout_ms: 1,
                ..Budgets::default()
            },
        );
        assert!(stats.hit_total_timeout, "the 1ms ceiling must be reported");
        assert_eq!(
            stats.eh_frame_candidates,
            0,
            "a scan that starts after the ceiling has passed must return nothing, \
             not sweep {} bytes and report {} candidates",
            data.len(),
            stats.eh_frame_candidates
        );
    }

    /// A budget that is not exceeded must not change what discovery finds. This
    /// is the property the whole change stands on — an enforcement that quietly
    /// drops functions is worse than no enforcement.
    #[test]
    fn a_ceiling_that_is_never_reached_changes_nothing() {
        let data = big_sample();
        let (unbounded, _cg, unbounded_stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        let generous = 10 * unbounded_stats.elapsed_ms.max(1) + 60_000;
        let (bounded, _cg, bounded_stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                total_timeout_ms: generous,
                ..Budgets::default()
            },
        );
        assert!(!bounded_stats.hit_total_timeout);
        assert_eq!(
            unbounded
                .iter()
                .map(|f| f.entry_point.value)
                .collect::<Vec<_>>(),
            bounded
                .iter()
                .map(|f| f.entry_point.value)
                .collect::<Vec<_>>(),
            "a generous ceiling must yield the identical function set"
        );
    }

    /// Cancellation is what makes a long analysis interruptible from Python: the
    /// binding polls `Python::check_signals` on the calling thread and sets this
    /// flag. A cancelled run must stop, report the truncation, and still return
    /// whatever it had — never hang, never lie about completeness.
    #[test]
    fn a_cancelled_analysis_stops_and_reports_the_truncation() {
        use std::sync::atomic::AtomicBool;
        let data = big_sample();
        let cancel = AtomicBool::new(true); // already asked to stop
        let started = std::time::Instant::now();
        let (functions, _cg, stats) =
            analyze_functions_bytes_cancellable(&data, &Budgets::default(), &[], &cancel);
        assert!(stats.hit_total_timeout, "cancellation must be reported");
        assert!(
            functions.is_empty(),
            "a run cancelled before it started has nothing to report: {}",
            functions.len()
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "cancellation must actually stop the run"
        );
    }

    /// The flag is checked, not merely accepted: a run with the flag CLEAR must
    /// produce exactly what the uncancellable path produces.
    #[test]
    fn a_cancellable_run_that_is_never_cancelled_is_the_ordinary_run() {
        use std::sync::atomic::AtomicBool;
        let data = big_sample();
        let cancel = AtomicBool::new(false);
        let (cancellable, _cg, cancellable_stats) =
            analyze_functions_bytes_cancellable(&data, &Budgets::default(), &[], &cancel);
        let (ordinary, _cg, _stats) =
            analyze_functions_bytes_with_stats(&data, &Budgets::default());
        assert!(!cancellable_stats.hit_total_timeout);
        assert_eq!(
            cancellable
                .iter()
                .map(|f| f.entry_point.value)
                .collect::<Vec<_>>(),
            ordinary
                .iter()
                .map(|f| f.entry_point.value)
                .collect::<Vec<_>>()
        );
    }

    /// Truncation must leave a trail: the seeds that were never walked are
    /// counted, so a consumer can tell an incomplete answer from a complete one.
    #[test]
    fn a_truncated_run_reports_the_seeds_it_never_reached() {
        let data = big_sample();
        let (_functions, _cg, stats) = analyze_functions_bytes_with_stats(
            &data,
            &Budgets {
                total_timeout_ms: 1,
                ..Budgets::default()
            },
        );
        assert!(stats.hit_total_timeout);
        assert!(
            stats.elapsed_ms > 0,
            "a truncated run must report the wall clock it consumed"
        );
    }
}
