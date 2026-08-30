//! End-to-end decompile pipeline benchmarks: binary bytes -> recovered C.
//!
//! This is the composed-whole lane. The sibling benches (`ir_lift`,
//! `ir_dataflow`, `ir_structure`, `analysis_cfg`) time individual stages in
//! isolation; this one times the pipeline that runs them in sequence, plus a
//! phase split so the total is attributable.
//!
//! # What "end to end" means here, and what it does not
//!
//! The SHIPPED whole-pipeline entry points (`decompile_at`, `decompile_all`,
//! `decompile_many`, `decompile_range_at`) live in `src/python_bindings/ir.rs`
//! and are gated behind the `python-ext` feature. That feature turns on
//! `pyo3/extension-module`, which deliberately does not link libpython, so a
//! `cargo bench` target cannot be built against it. Their orchestration helpers
//! -- `prepare_llir_for_lowering`, `run_ast_passes`, `annotate_calls_in`,
//! `recover_direct_callee_layouts`, `decbench_text`, `target_calling_convention`
//! -- are all `pub(super)` inside `src/python_bindings/ir/`, so the composition
//! itself is not reachable from the library either.
//!
//! What IS reachable is every constituent stage, as ordinary `glaurung::ir::*`
//! and `glaurung::program::*` public functions. This bench therefore re-composes
//! the library-reachable pipeline in `decompile_one`, following the shipped
//! order exactly, and is explicit about the stages it cannot reach:
//!
//! | stage                              | here | shipped `decompile_at` |
//! |------------------------------------|------|------------------------|
//! | object parse / `ProgramImage`      | yes  | yes                    |
//! | function discovery + CFG           | yes  | yes                    |
//! | LLIR lift                          | yes  | yes                    |
//! | definedness normalize + SSA        | yes  | yes                    |
//! | value numbering                    | yes  | yes                    |
//! | indirect-target + region recovery  | yes  | yes                    |
//! | AST lower                          | yes  | yes                    |
//! | AST pass pipeline                  | *subset* | full `run_ast_passes` |
//! | render                             | `render` | `decbench_text` / `render_with_types` |
//! | soft-helper inlining, ABI call annotation | NO | yes             |
//! | direct-callee layout recovery (nested, demand-driven) | NO | yes |
//! | address map / PDB / string pool / GOT / DWARF contracts | NO | yes |
//! | semantic prototype + type recovery | NO   | yes                    |
//!
//! The omitted stages are not cheap -- `recover_direct_callee_layouts` runs a
//! nested analysis per direct callee -- so the `end_to_end` numbers here are a
//! LOWER BOUND on the shipped per-function cost, not an estimate of it. The
//! phase split, by contrast, is exact for the phases it reports.
//!
//! # Fixture subset
//!
//! `tests/decompiler_fixtures/build/` holds ~1,676 prebuilt binaries. Iterating
//! them in criterion would cost hours, so this bench pins a documented subset of
//! four `gcc` fixtures chosen for *function size tiers* (the axis that makes
//! superlinear behaviour visible), each measured at both `-O0` and `-O2`:
//!
//! * `07_packet_parser::parse_packet`          O0 0x16f / O2 0x103  -- small
//! * `155_long_dependency_chain::chain155_scalar` O0 0xa22 / O2 0x776 -- medium
//! * `153_many_live_locals::spill153_live_set` O0 0x2901 / O2 0x1d44 -- large
//! * `151_wide_branch_ladder::big151_branch_ladder` O0 0x3c35 / O2 0x1f7d -- xlarge
//!
//! They are also different *shapes*, per their `tests/decompiler_fixtures/src/`
//! headers: a bounded struct/bitfield packet parser, a 320-step straight-line
//! dependency chain (quadratic for expression builders), a 128-live-local spill
//! web (dense stack/register pressure), and a wide branch ladder (region
//! recovery pressure). The whole-binary lane adds `03_loop_shapes` and
//! `154_wide_switch` for loop and switch shapes at whole-image scale.
//!
//! The fixtures are gitignored build output. Every lane is skipped silently when
//! its binary is absent, with one warning on stderr -- see `warn_missing`.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use glaurung::analysis::cfg::Budgets;
use glaurung::analysis::exception::{with_exceptional_successors, ExceptionCallSite};
use glaurung::core::function::Function;
use glaurung::ir::ast;
use glaurung::ir::definedness::{erase_unobserved_masked_inputs, BitDemandOracle};
use glaurung::ir::indirect_targets::resolve_indirect_jumps;
use glaurung::ir::lift_function::lift_function_from_image;
use glaurung::ir::ssa::{compute_ssa, SsaInfo};
use glaurung::ir::structure::{recover_verified_with_health_and_destinations, Region};
use glaurung::ir::types::{LlirFunction, VReg};
use glaurung::ir::value_number::value_number_with_parameter_slots;
use glaurung::program::image::ProgramImage;
use glaurung::program::session::ProgramSession;
use glaurung::target::abi::CallConv;

const FIXTURE_DIR: &str = "tests/decompiler_fixtures/build";

/// The per-function budgets `decompile_at` ships with.
const FUNC_BUDGETS: Budgets = Budgets {
    max_functions: 1,
    max_blocks: 4096,
    max_instructions: 200_000,
    timeout_ms: 5_000,
    total_timeout_ms: 0,
};

/// The whole-binary budgets `decompile_many` ships with (`max_functions = 0`,
/// i.e. no ceiling on the discovery walk).
const ALL_BUDGETS: Budgets = Budgets {
    max_functions: 0,
    max_blocks: 4096,
    max_instructions: 200_000,
    timeout_ms: 10_000,
    total_timeout_ms: 0,
};

/// One benchmarked function: fixture, optimization lane, symbol, size tier.
struct Target {
    tier: &'static str,
    fixture: &'static str,
    function: &'static str,
    opt: &'static str,
}

/// Size-tiered per-function targets, both optimization lanes. See module docs.
const TARGETS: &[Target] = &[
    Target {
        tier: "1small",
        fixture: "07_packet_parser",
        function: "parse_packet",
        opt: "O0",
    },
    Target {
        tier: "1small",
        fixture: "07_packet_parser",
        function: "parse_packet",
        opt: "O2",
    },
    Target {
        tier: "2medium",
        fixture: "155_long_dependency_chain",
        function: "chain155_scalar",
        opt: "O0",
    },
    Target {
        tier: "2medium",
        fixture: "155_long_dependency_chain",
        function: "chain155_scalar",
        opt: "O2",
    },
    Target {
        tier: "3large",
        fixture: "153_many_live_locals",
        function: "spill153_live_set",
        opt: "O0",
    },
    Target {
        tier: "3large",
        fixture: "153_many_live_locals",
        function: "spill153_live_set",
        opt: "O2",
    },
    Target {
        tier: "4xlarge",
        fixture: "151_wide_branch_ladder",
        function: "big151_branch_ladder",
        opt: "O0",
    },
    Target {
        tier: "4xlarge",
        fixture: "151_wide_branch_ladder",
        function: "big151_branch_ladder",
        opt: "O2",
    },
];

/// Whole-binary targets. Deliberately the smaller fixtures plus two shape
/// fixtures: a whole-image decompile of `151_wide_branch_ladder` is minutes.
const WHOLE_BINARY: &[(&str, &str)] = &[
    ("07_packet_parser", "O0"),
    ("07_packet_parser", "O2"),
    ("03_loop_shapes", "O0"),
    ("03_loop_shapes", "O2"),
    ("154_wide_switch", "O0"),
    ("154_wide_switch", "O2"),
];

fn fixture_path(fixture: &str, opt: &str) -> PathBuf {
    PathBuf::from(FIXTURE_DIR).join(format!("{fixture}-gcc-{opt}.so"))
}

fn warn_missing(path: &std::path::Path) {
    eprintln!(
        "decompile_pipeline: SKIPPING {} (fixture not built; run tests/decompiler_fixtures build)",
        path.display()
    );
}

/// Everything one benchmarked function needs, computed once outside the timed
/// region so each phase lane can start from the exact input the shipped
/// pipeline hands it.
struct Prepared {
    bytes: Vec<u8>,
    session: ProgramSession,
    func: Function,
    cc: CallConv,
    exception_sites: Arc<[ExceptionCallSite]>,
    /// Straight out of the lifter, before definedness normalization.
    raw_lf: LlirFunction,
    /// After `normalize_definedness`, which is what region recovery consumes.
    normalized_lf: LlirFunction,
    ssa: SsaInfo,
    numbered: LlirFunction,
    region: Region,
    /// After `ast::lower`, before the AST pass pipeline.
    lowered: ast::Function,
    /// After the context-free AST pass subset; the input to `render`.
    passed: ast::Function,
}

/// `pipeline::normalize_definedness_and_compute_ssa`, reproduced from its public
/// parts. The helper itself is private to `src/python_bindings/ir/pipeline.rs`.
fn normalize_definedness_and_compute_ssa(
    function: &mut LlirFunction,
    exception_sites: &[ExceptionCallSite],
    cc: CallConv,
) -> SsaInfo {
    let graph = with_exceptional_successors(function, exception_sites);
    let initial = compute_ssa(&graph);
    let oracle = BitDemandOracle::analyze(&graph, &initial, cc);
    if erase_unobserved_masked_inputs(function, &initial, &oracle) == 0 {
        return initial;
    }
    let normalized = with_exceptional_successors(function, exception_sites);
    compute_ssa(&normalized)
}

/// The subset of `run_ast_passes` whose passes need no analysis context the
/// library exposes (no address map, string pool, callee facts, GOT map, DWARF
/// contract or recovered prototype). Pass ORDER matches the shipped pipeline;
/// the context-dependent passes are simply absent, and their absence is why the
/// composed figures are a lower bound.
///
/// `should_split_unspilled_dual_role` is `pub(crate)`, but it returns `false`
/// unconditionally when no prototype was recovered -- which is this
/// composition's case -- so passing `false` is exact rather than a guess.
fn run_context_free_ast_passes(f: &mut ast::Function, cc: CallConv) -> HashSet<usize> {
    let mut param_slots: HashSet<usize> = HashSet::new();
    let no_layouts: HashMap<u64, Vec<VReg>> = HashMap::new();

    glaurung::ir::vector_copy::recover_wide_copies(f);
    glaurung::ir::expr_reconstruct::reconstruct(f);
    glaurung::ir::const_fold::fold_constants(f);
    glaurung::ir::select_fold::fold_boolean_masks(f);
    glaurung::ir::dce::prune_overwritten_flags(f);
    glaurung::ir::dce::prune_dead_flags(f);
    glaurung::ir::call_args::reconstruct_args_with_layouts(
        f,
        cc,
        &mut param_slots,
        &no_layouts,
        &no_layouts,
    );
    glaurung::ir::call_contracts::apply_known_call_contracts(f);
    glaurung::ir::call_result_split::split_call_result_lifetimes(f, cc);
    glaurung::ir::canary::recognise_canary(f);
    glaurung::ir::stack_locals::promote_stack_locals_with_facts(f, Some(cc), None, &[]);
    glaurung::ir::aapcs64_indirect_result::bind_indirect_result_buffers(f, cc);
    if matches!(cc, CallConv::SysVAmd64 | CallConv::Win64) {
        glaurung::ir::x86_prologue::recognise_x86_prologue(f);
    }
    glaurung::ir::dead_stores::prune_callee_saved_spills(f, cc);
    glaurung::ir::value_split::split_argument_storage_reuse(f, cc, false);
    glaurung::ir::naming::apply_role_names_with_parameter_roles(
        f,
        cc,
        &param_slots,
        &HashMap::new(),
    );
    glaurung::ir::canary::collapse_canary_save(f);
    glaurung::ir::dead_stores::eliminate_dead_stores(f, cc);
    glaurung::ir::stack_idiom::rematerialise_stack_ops(f);
    glaurung::ir::label_prune::prune_unreferenced_labels(f);
    param_slots
}

/// The composed, library-reachable decompile of ONE function, from an already
/// parsed session. This is the body of the `warm` per-function lane and of each
/// function in the whole-binary lane.
fn decompile_one(session: &ProgramSession, func: &Function, cc: CallConv) -> Option<String> {
    let image = session.image();
    let exception_sites = image.exception_call_sites();
    let mut lf = lift_function_from_image(image, func).ok()?;
    let ssa = normalize_definedness_and_compute_ssa(&mut lf, &exception_sites, cc);
    let (numbered, _widths, _slots) = value_number_with_parameter_slots(&lf, &ssa, cc);
    let destinations = resolve_indirect_jumps(&lf, &ssa, &image.relocated_symbol_slots());
    let (region, _health) = recover_verified_with_health_and_destinations(&lf, &ssa, &destinations);
    let mut f = ast::lower(&numbered, &region, func.name.clone());
    run_context_free_ast_passes(&mut f, cc);
    Some(ast::render(&f))
}

/// Fully cold: bytes in, C out, including the object parse and whole-binary
/// function discovery. This is the shape `glaurung decompile <bin> <va>` pays.
fn decompile_cold(bytes: Vec<u8>, func_va: u64) -> Option<String> {
    let image = ProgramImage::from_bytes(bytes).ok()?;
    let cc = image.target().calling_convention()?;
    let func_va = image.normalize_function_entry(func_va);
    let session = ProgramSession::from_image(image);
    let funcs = session.discover_functions(&FUNC_BUDGETS, &[func_va]);
    let func = funcs
        .iter()
        .find(|f| f.entry_point.value == func_va)?
        .clone();
    decompile_one(&session, &func, cc)
}

/// Whole-binary decompile: one parse, one discovery, every discovered function
/// lifted through to rendered C. Returns the total rendered length so nothing
/// can be optimized away, and the function count for the report.
fn decompile_whole(bytes: Vec<u8>) -> Option<(usize, usize)> {
    let image = ProgramImage::from_bytes(bytes).ok()?;
    let cc = image.target().calling_convention()?;
    let session = ProgramSession::from_image(image);
    let funcs = session.discover_functions(&ALL_BUDGETS, &[]);
    let mut rendered = 0usize;
    let mut count = 0usize;
    for func in funcs.iter() {
        if let Some(text) = decompile_one(&session, func, cc) {
            rendered += text.len();
            count += 1;
        }
    }
    Some((rendered, count))
}

fn prepare(target: &Target) -> Option<Prepared> {
    let path = fixture_path(target.fixture, target.opt);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => {
            warn_missing(&path);
            return None;
        }
    };
    let image = ProgramImage::from_bytes(bytes.clone()).ok()?;
    let func_va = image
        .defined_text_symbol_address(target.function)
        .map(|va| image.normalize_function_entry(va))?;
    let cc = image.target().calling_convention()?;
    let exception_sites = image.exception_call_sites();
    let session = ProgramSession::from_image(image);
    let funcs = session.discover_functions(&FUNC_BUDGETS, &[func_va]);
    let func = funcs
        .iter()
        .find(|f| f.entry_point.value == func_va)?
        .clone();

    let raw_lf = lift_function_from_image(session.image(), &func).ok()?;
    let mut normalized_lf = raw_lf.clone();
    let ssa = normalize_definedness_and_compute_ssa(&mut normalized_lf, &exception_sites, cc);
    let (numbered, _widths, _slots) = value_number_with_parameter_slots(&normalized_lf, &ssa, cc);
    let destinations = resolve_indirect_jumps(
        &normalized_lf,
        &ssa,
        &session.image().relocated_symbol_slots(),
    );
    let (region, _health) =
        recover_verified_with_health_and_destinations(&normalized_lf, &ssa, &destinations);
    let lowered = ast::lower(&numbered, &region, func.name.clone());
    let mut passed = lowered.clone();
    run_context_free_ast_passes(&mut passed, cc);

    Some(Prepared {
        bytes,
        session,
        func,
        cc,
        exception_sites,
        raw_lf,
        normalized_lf,
        ssa,
        numbered,
        region,
        lowered,
        passed,
    })
}

fn id(target: &Target) -> String {
    format!(
        "{}/{}::{}/gcc-{}",
        target.tier, target.fixture, target.function, target.opt
    )
}

/// Lane 1: per-function end to end. `cold` includes the object parse and the
/// whole-binary discovery walk; `warm` is the per-function work only, i.e. what
/// a function costs once discovery has been amortized across a binary. `warm`
/// is the figure comparable to a published s/fn number measured over a corpus.
fn bench_per_function(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompile/per_function");
    group.sample_size(20);

    for target in TARGETS {
        let Some(p) = prepare(target) else { continue };
        let name = id(target);

        group.bench_function(format!("cold/{name}"), |b| {
            b.iter_batched(
                || p.bytes.clone(),
                |bytes| {
                    let func_va = p.func.entry_point.value;
                    std::hint::black_box(decompile_cold(bytes, func_va))
                },
                BatchSize::LargeInput,
            )
        });

        group.bench_function(format!("warm/{name}"), |b| {
            b.iter(|| std::hint::black_box(decompile_one(&p.session, &p.func, p.cc)))
        });
    }

    group.finish();
}

/// Lane 2: the phase split. Each phase starts from the exact artifact the
/// previous one produced, so `parse + discover + lift + dataflow + structure +
/// lower + ast_passes + render` sums to the `cold` figure above (modulo the
/// per-phase setup criterion excludes).
fn bench_phases(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompile/phase");
    group.sample_size(20);

    for target in TARGETS {
        let Some(p) = prepare(target) else { continue };
        let name = id(target);

        // parse: bytes -> ProgramImage (object parse, section/segment indices,
        // eh_frame, symbol tables).
        group.bench_function(format!("parse/{name}"), |b| {
            b.iter_batched(
                || p.bytes.clone(),
                |bytes| std::hint::black_box(ProgramImage::from_bytes(bytes).is_ok()),
                BatchSize::LargeInput,
            )
        });

        // discover: whole-binary function discovery + CFG construction. A fresh
        // session per iteration, because ProgramSession caches discovery.
        group.bench_function(format!("discover/{name}"), |b| {
            b.iter_batched(
                || {
                    let image = ProgramImage::from_bytes(p.bytes.clone())
                        .expect("fixture parsed during setup");
                    ProgramSession::from_image(image)
                },
                |session| {
                    let va = p.func.entry_point.value;
                    std::hint::black_box(session.discover_functions(&FUNC_BUDGETS, &[va]).len())
                },
                BatchSize::LargeInput,
            )
        });

        // lift: machine code -> LLIR for this one function.
        group.bench_function(format!("lift/{name}"), |b| {
            b.iter(|| {
                std::hint::black_box(lift_function_from_image(p.session.image(), &p.func).is_ok())
            })
        });

        // dataflow: definedness normalization + SSA + value numbering.
        group.bench_function(format!("dataflow/{name}"), |b| {
            b.iter_batched(
                || p.raw_lf.clone(),
                |mut lf| {
                    let ssa =
                        normalize_definedness_and_compute_ssa(&mut lf, &p.exception_sites, p.cc);
                    std::hint::black_box(value_number_with_parameter_slots(&lf, &ssa, p.cc))
                },
                // PerIteration, not SmallInput: at the large tiers the cloned
                // LLIR/AST is megabytes, and criterion's batched setup then
                // pre-allocates a whole batch of them. That cache pressure
                // showed up as a phase measuring MORE than the composed total
                // it is part of (2medium/O0 ast_passes 191 ms against a 140 ms
                // end-to-end). One clone per iteration removes it.
                BatchSize::PerIteration,
            )
        });

        // structure: indirect-target resolution + region recovery (the control
        // flow structuring that turns a CFG into if/while/switch).
        group.bench_function(format!("structure/{name}"), |b| {
            let slots = p.session.image().relocated_symbol_slots();
            b.iter(|| {
                let destinations = resolve_indirect_jumps(&p.normalized_lf, &p.ssa, &slots);
                std::hint::black_box(recover_verified_with_health_and_destinations(
                    &p.normalized_lf,
                    &p.ssa,
                    &destinations,
                ))
            })
        });

        // lower: structured LLIR -> AST.
        group.bench_function(format!("lower/{name}"), |b| {
            b.iter(|| std::hint::black_box(ast::lower(&p.numbered, &p.region, p.func.name.clone())))
        });

        // ast_passes: the optimize/cleanup pass pipeline over the AST. Subset --
        // see `run_context_free_ast_passes`.
        group.bench_function(format!("ast_passes/{name}"), |b| {
            b.iter_batched(
                || p.lowered.clone(),
                |mut f| std::hint::black_box(run_context_free_ast_passes(&mut f, p.cc)),
                BatchSize::PerIteration,
            )
        });

        // render: AST -> C text.
        group.bench_function(format!("render/{name}"), |b| {
            b.iter(|| std::hint::black_box(ast::render(&p.passed).len()))
        });
    }

    group.finish();
}

/// Lane 3: whole-binary end to end, with byte throughput. One parse, one
/// discovery, every discovered function rendered.
fn bench_whole_binary(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompile/whole_binary");
    group.sample_size(10);

    for (fixture, opt) in WHOLE_BINARY {
        let path = fixture_path(fixture, opt);
        let Ok(bytes) = std::fs::read(&path) else {
            warn_missing(&path);
            continue;
        };
        // Prove the lane produces real output before spending measurement time
        // on it, and report the function count so the s/fn figure is derivable
        // from the criterion result.
        let Some((rendered, functions)) = decompile_whole(bytes.clone()) else {
            eprintln!(
                "decompile_pipeline: SKIPPING {} (no supported calling convention)",
                path.display()
            );
            continue;
        };
        eprintln!(
            "decompile_pipeline: {}-gcc-{} -> {functions} functions, {rendered} chars of C",
            fixture, opt
        );

        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_function(format!("{fixture}/gcc-{opt}"), |b| {
            b.iter_batched(
                || bytes.clone(),
                |bytes| std::hint::black_box(decompile_whole(bytes)),
                BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_per_function,
    bench_phases,
    bench_whole_binary
);
criterion_main!(benches);
