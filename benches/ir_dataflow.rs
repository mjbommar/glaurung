//! Criterion benches for the LLIR **dataflow** and **type-recovery** passes.
//!
//! Two tiers, both fed from real prebuilt fixtures in
//! `tests/decompiler_fixtures/build/` — nothing here fabricates IR.
//!
//! 1. **Micro** (`ir_dataflow/pass/...`): one pass at a time over a single
//!    lifted function, so a regression attributes to ONE pass. Every pass is
//!    given the state the real pipeline hands it (each AST pass runs on the
//!    prefix state produced by all the passes before it), and all of that
//!    preparation happens in `iter_batched` setup so it is not counted.
//!
//! 2. **Pass-pipeline**: the passes composed in the order
//!    `src/python_bindings/ir/pipeline.rs` and `src/ir/ast/prepare.rs` run
//!    them, over functions of increasing size. Four groups:
//!
//!    * `ir_dataflow/llir_pipeline/...` — the LLIR stage from the raw lifted
//!      function: `annotate_calls` -> SSA -> definedness -> value numbering ->
//!      type/prototype recovery.
//!    * `ir_dataflow/llir_dataflow/...` — the same, minus `annotate_calls`.
//!      It exists because `annotate_calls` currently costs ~100x everything
//!      after it on a large function and would otherwise hide every other
//!      movement in the LLIR stage.
//!    * `ir_dataflow/ast_pipeline/...` — the AST dataflow chain.
//!    * `ir_dataflow/copyprop_constfold_fixpoint/...` — the bounded four-round
//!      copy-propagation / constant-folding fixpoint from `prepare_for_decbench`,
//!      which clones and structurally compares the whole body once per round.
//!
//!    Several of these passes are worst-case quadratic in block or instruction
//!    count, so throughput is declared in LLIR instructions: a pass that is
//!    linear holds its elements/sec across the sweep, and one that is not
//!    visibly falls off. The subject set separates the two axes on purpose —
//!    `155_chain155_scalar` is 5,200 instructions in ONE block and
//!    `151_big151_branch_ladder` is 25,173 instructions in 984, so a pass that
//!    is quadratic in block count and one that is quadratic in instructions
//!    per block do not look alike here.
//!
//! Structuring (`ir::structure`) and lowering (`ir::ast::lower`) are deliberately
//! kept in setup — they belong to the `ir_structure` bench, not this one.
//!
//! The subjects are chosen for what stresses these passes specifically:
//!
//! | subject                       | blocks / LLIR instrs | shape                       |
//! |-------------------------------|---------------------:|-----------------------------|
//! | `112_nontail_depth`           |          6 /      89 | small recursive frame — the attribution baseline |
//! | `112_recursion_entry`         |         10 /     101 | driver over four recursion shapes — call chains |
//! | `192_sum_until_key`           |          7 /     128 | dependent pointer-load walk over caller memory |
//! | `100_struct_assignment_copies`|          1 /     134 | struct copy incl. padding — aggregate typing |
//! | `152_deep152_nested_loops`    |         50 /   1,031 | 12 nested loops, innermost statement 16 levels down |
//! | `155_chain155_scalar`         |          1 /   5,200 | 320-step serial dependency chain, ONE block |
//! | `153_spill153_live_set`       |         15 /  18,202 | 128 live locals across a loop — dense spill web |
//! | `153_spill153_static_web`     |         12 /  23,505 | 104 simultaneously-live locals, straight line |
//! | `151_big151_branch_ladder`    |        984 /  25,173 | ~1000 basic blocks at -O0 |
//!
//! All are the `gcc-O0` builds: -O0 keeps every local in a stack slot and every
//! copy on the page, which is the input these passes actually have to chew.
//! Sizes above were measured 2026-08-30; the bench re-reports them to stderr on
//! every run, because criterion ids have to stay stable and so cannot carry them.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};

use glaurung::analysis::cfg::{analyze_functions_image_with_seeds, Budgets};
use glaurung::ir::ast;
use glaurung::ir::call_args::CallConv;
use glaurung::ir::lift_function::lift_function_from_image;
use glaurung::ir::ssa::SsaInfo;
use glaurung::ir::types::LlirFunction;
use glaurung::ir::{
    abi, call_args, const_fold, copy_prop, dce, dead_stores, definedness, expr_reconstruct, ssa,
    stack_locals, structure, types_recover, value_number,
};
use glaurung::program::image::ProgramImage;

const FIXTURE_DIR: &str = "tests/decompiler_fixtures/build";

/// One real function to run the passes over.
struct Subject {
    /// Bench-id component. Stable across runs; sizes are reported separately.
    label: &'static str,
    binary: &'static str,
    symbol: &'static str,
}

/// The size sweep, smallest first by measured LLIR instruction count.
///
/// The order is presentational only — every bench id is the subject's own
/// label, so reordering or dropping a subject never renames another one.
/// [`report_sizes`] prints the measured sizes on every run; nothing here
/// assumes them.
const SUBJECTS: &[Subject] = &[
    Subject {
        label: "112_nontail_depth",
        binary: "112_recursion_shapes-gcc-O0.so",
        symbol: "nontail_depth",
    },
    Subject {
        label: "112_recursion_entry",
        binary: "112_recursion_shapes-gcc-O0.so",
        symbol: "recursion_entry",
    },
    Subject {
        label: "192_sum_until_key",
        binary: "192_pointer_chased_list-gcc-O0.so",
        symbol: "l192_sum_until_key",
    },
    Subject {
        label: "100_struct_assignment_copies",
        binary: "100_struct_layout-gcc-O0.so",
        symbol: "struct_assignment_copies",
    },
    Subject {
        label: "152_deep152_nested_loops",
        binary: "152_deep_nesting-gcc-O0.so",
        symbol: "deep152_nested_loops",
    },
    Subject {
        label: "155_chain155_scalar",
        binary: "155_long_dependency_chain-gcc-O0.so",
        symbol: "chain155_scalar",
    },
    Subject {
        label: "153_spill153_live_set",
        binary: "153_many_live_locals-gcc-O0.so",
        symbol: "spill153_live_set",
    },
    Subject {
        label: "153_spill153_static_web",
        binary: "153_many_live_locals-gcc-O0.so",
        symbol: "spill153_static_web",
    },
    Subject {
        label: "151_big151_branch_ladder",
        binary: "151_wide_branch_ladder-gcc-O0.so",
        symbol: "big151_branch_ladder",
    },
];

/// The subject the micro tier isolates passes over: big enough that every pass
/// is measurable, small enough that a full micro sweep is seconds rather than
/// minutes. 128 simultaneously-live locals is the shape `stack_locals`,
/// `value_number`, `copy_prop` and `dead_stores` all have to work hardest on.
const MICRO_SUBJECT: &str = "153_spill153_live_set";

/// Every intermediate the passes need, prepared once per subject.
struct Lifted {
    label: &'static str,
    cc: CallConv,
    /// Straight out of the lifter — the input `abi::annotate_calls` sees.
    raw: LlirFunction,
    /// After `annotate_calls`, before definedness normalization. This is the
    /// state `BitDemandOracle::analyze` and `erase_unobserved_masked_inputs`
    /// are actually handed by `normalize_definedness_and_compute_ssa`.
    annotated: LlirFunction,
    annotated_ssa: SsaInfo,
    oracle: definedness::BitDemandOracle,
    /// After definedness normalization — the state value numbering, type
    /// recovery and prototype recovery see.
    normalized: LlirFunction,
    normalized_ssa: SsaInfo,
    param_slots: HashSet<usize>,
    /// The lowered AST, before any AST pass has run.
    ast: ast::Function,
    /// Input state for each AST pass, parallel to [`ast_passes`].
    ast_prefixes: Vec<ast::Function>,
    blocks: usize,
    instrs: usize,
}

fn fixture_path(binary: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURE_DIR)
        .join(binary)
}

/// Discover, lift and prepare one subject. `None` when the fixture has not been
/// built (`tests/decompiler_fixtures/build/` is gitignored) — the bench then
/// skips that subject and says so, rather than substituting something else.
fn load(subject: &Subject) -> Option<Lifted> {
    let image = ProgramImage::from_path(&fixture_path(subject.binary)).ok()?;
    let cc = image.target().calling_convention()?;
    let entry = image
        .defined_text_symbol_address(subject.symbol)
        .map(|address| image.normalize_function_entry(address))?;
    // Generous per-function budgets: `big151_branch_ladder` alone is ~1000
    // blocks at -O0, and a truncated CFG would silently shrink the largest
    // point of the size sweep.
    let budgets = Budgets {
        max_functions: 1,
        max_blocks: 8192,
        max_instructions: 200_000,
        timeout_ms: 60_000,
        total_timeout_ms: 0,
    };
    let (functions, _) = analyze_functions_image_with_seeds(&image, &budgets, &[entry]);
    let source = functions
        .iter()
        .find(|function| image.normalize_function_entry(function.entry_point.value) == entry)?;
    let raw = lift_function_from_image(&image, source).ok()?;

    let mut annotated = raw.clone();
    abi::annotate_calls(&mut annotated, cc);
    let annotated_ssa = ssa::compute_ssa(&annotated);
    let oracle = definedness::BitDemandOracle::analyze(&annotated, &annotated_ssa, cc);

    let mut normalized = annotated.clone();
    let normalized_ssa =
        if definedness::erase_unobserved_masked_inputs(&mut normalized, &annotated_ssa, &oracle)
            == 0
        {
            annotated_ssa.clone()
        } else {
            ssa::compute_ssa(&normalized)
        };

    let (numbered, _definition_widths, param_slots) =
        value_number::value_number_with_parameter_slots(&normalized, &normalized_ssa, cc);
    let region = structure::recover_verified(&normalized, &normalized_ssa);
    let ast = ast::lower(&numbered, &region, subject.symbol);
    let ast_prefixes = ast_prefix_states(&ast, cc, &param_slots);

    let blocks = normalized.blocks.len();
    let instrs = normalized
        .blocks
        .iter()
        .map(|block| block.instrs.len())
        .sum();

    Some(Lifted {
        label: subject.label,
        cc,
        raw,
        annotated,
        annotated_ssa,
        oracle,
        normalized,
        normalized_ssa,
        param_slots,
        ast,
        ast_prefixes,
        blocks,
        instrs,
    })
}

// ------------------------------------------------------------------ AST tier

/// One AST-level pass, in the order `run_ast_passes` / `prepare_for_decbench`
/// run them. Restricted to the dataflow and type-recovery passes this bench
/// owns; the naming, structuring and rendering passes belong elsewhere.
type AstPass = (
    &'static str,
    fn(&mut ast::Function, CallConv, &HashSet<usize>),
);

fn ast_passes() -> Vec<AstPass> {
    vec![
        ("expr_reconstruct::reconstruct", |f, _, _| {
            expr_reconstruct::reconstruct(f)
        }),
        ("const_fold::fold_constants", |f, _, _| {
            const_fold::fold_constants(f)
        }),
        ("dce::prune_overwritten_flags", |f, _, _| {
            dce::prune_overwritten_flags(f)
        }),
        ("dce::prune_dead_flags", |f, _, _| dce::prune_dead_flags(f)),
        ("call_args::reconstruct_args", |f, cc, slots| {
            call_args::reconstruct_args_with_params(f, cc, slots)
        }),
        ("copy_prop::propagate_copies", |f, _, _| {
            copy_prop::propagate_copies(f)
        }),
        ("stack_locals::promote_stack_locals_typed", |f, cc, _| {
            let _ = stack_locals::promote_stack_locals_typed(f, Some(cc));
        }),
        ("dead_stores::eliminate_dead_stores", |f, cc, _| {
            dead_stores::eliminate_dead_stores(f, cc)
        }),
        ("dead_stores::prune_callee_saved_spills", |f, cc, _| {
            dead_stores::prune_callee_saved_spills(f, cc)
        }),
    ]
}

/// The AST state each pass is handed when the whole chain runs in order.
///
/// Measuring `dead_stores` on an un-promoted, un-propagated body would time a
/// pass over input the real pipeline never gives it.
fn ast_prefix_states(
    base: &ast::Function,
    cc: CallConv,
    slots: &HashSet<usize>,
) -> Vec<ast::Function> {
    let mut current = base.clone();
    let mut states = Vec::with_capacity(ast_passes().len());
    for (_, pass) in ast_passes() {
        states.push(current.clone());
        pass(&mut current, cc, slots);
    }
    states
}

/// The AST dataflow chain, composed. Mirrors `run_ast_passes`' ordering for the
/// passes in scope here.
fn run_ast_pipeline(f: &mut ast::Function, cc: CallConv, slots: &HashSet<usize>) {
    for (_, pass) in ast_passes() {
        pass(f, cc, slots);
    }
}

/// The bounded copy-propagation / constant-folding fixpoint from
/// `ir::ast::prepare::prepare_for_decbench_with_output_and_protected_locals`.
///
/// Worth its own bench: the loop clones the entire function body once per round
/// and compares it structurally, so its cost is at least quadratic in rounds x
/// body size before either pass does any work.
fn run_copyprop_constfold_fixpoint(f: &mut ast::Function) {
    for _ in 0..4 {
        let before = f.clone();
        copy_prop::propagate_copies(f);
        const_fold::fold_constants(f);
        if *f == before {
            break;
        }
    }
}

// ----------------------------------------------------------------- LLIR tier

/// The LLIR dataflow + type-recovery chain, composed, exactly as
/// `normalize_definedness_and_compute_ssa` and `prepare_llir_for_lowering`
/// sequence it — minus region recovery, which is the `ir_structure` bench's.
///
/// Input is the RAW lifted function, so `abi::annotate_calls` is included. That
/// pass currently costs two orders of magnitude more than everything after it
/// (see the module docs), which is why [`run_llir_dataflow`] exists: without a
/// post-annotation variant, a regression anywhere in SSA, definedness, value
/// numbering or type recovery is invisible under it in this composition.
fn run_llir_pipeline(f: &mut LlirFunction, cc: CallConv) {
    abi::annotate_calls(f, cc);
    run_llir_dataflow(f, cc);
}

/// [`run_llir_pipeline`] from the already-ABI-annotated function.
fn run_llir_dataflow(f: &mut LlirFunction, cc: CallConv) {
    let mut ssa_info = ssa::compute_ssa(f);
    let oracle = definedness::BitDemandOracle::analyze(f, &ssa_info, cc);
    if definedness::erase_unobserved_masked_inputs(f, &ssa_info, &oracle) != 0 {
        ssa_info = ssa::compute_ssa(f);
    }
    let (_, _, provisional_slots) =
        value_number::value_number_with_parameter_slots(f, &ssa_info, cc);
    let _ = types_recover::recover_types(f);
    let _ = types_recover::recover_prototype(f, &ssa_info, cc, &provisional_slots);
    let _ = value_number::value_number_with_parameter_slots(f, &ssa_info, cc);
}

// -------------------------------------------------------------------- benches

/// Sample count for the pipeline groups.
///
/// Criterion's default of 100 is unusable here: one `153_spill153_static_web`
/// LLIR-pipeline iteration is measured in seconds, so the default would put a
/// single bench past ten minutes. Ten is criterion's floor and keeps a full run
/// in single-digit minutes; the numbers these benches produce move by factors,
/// not by percent, so the lost resolution costs nothing.
const PIPELINE_SAMPLES: usize = 10;

/// Sample count for the micro tier. Individual passes are cheap enough for more
/// samples, and per-pass attribution is where small movements actually matter.
const MICRO_SAMPLES: usize = 20;

/// Print the recovered size of every subject to stderr.
///
/// Criterion ids have to be stable, so the sizes cannot live in them; without
/// this, a reader of the size sweep has no way to tell whether "large" is 10x
/// or 100x "small", which is the whole question the sweep answers.
fn report_sizes(subjects: &[Lifted]) {
    eprintln!("ir_dataflow subjects (LLIR blocks / instructions):");
    for subject in subjects {
        eprintln!(
            "  {:<32} {:>6} blocks {:>7} instrs",
            subject.label, subject.blocks, subject.instrs
        );
    }
    let missing = SUBJECTS.len() - subjects.len();
    if missing > 0 {
        eprintln!(
            "  NOTE: {missing} subject(s) skipped — fixture not present under {FIXTURE_DIR}."
        );
    }
}

fn bench_micro_passes(c: &mut Criterion) {
    let subjects = subjects();
    let Some(subject) = subjects.iter().find(|s| s.label == MICRO_SUBJECT) else {
        eprintln!("ir_dataflow: micro subject {MICRO_SUBJECT} unavailable; skipping micro tier.");
        return;
    };

    let mut group = c.benchmark_group("ir_dataflow/pass");
    group.sample_size(MICRO_SAMPLES);
    let cc = subject.cc;

    group.bench_function("abi::annotate_calls", |b| {
        b.iter_batched(
            || subject.raw.clone(),
            |mut f| abi::annotate_calls(&mut f, cc),
            BatchSize::SmallInput,
        )
    });
    group.bench_function("ssa::compute_ssa", |b| {
        b.iter(|| ssa::compute_ssa(&subject.annotated))
    });
    group.bench_function("definedness::BitDemandOracle::analyze", |b| {
        b.iter(|| {
            definedness::BitDemandOracle::analyze(&subject.annotated, &subject.annotated_ssa, cc)
        })
    });
    group.bench_function("definedness::erase_unobserved_masked_inputs", |b| {
        b.iter_batched(
            || subject.annotated.clone(),
            |mut f| {
                definedness::erase_unobserved_masked_inputs(
                    &mut f,
                    &subject.annotated_ssa,
                    &subject.oracle,
                )
            },
            BatchSize::SmallInput,
        )
    });
    group.bench_function("value_number::live_in_arg_slots_llir", |b| {
        b.iter(|| value_number::live_in_arg_slots_llir(&subject.normalized, cc))
    });
    group.bench_function("value_number::value_number", |b| {
        b.iter(|| value_number::value_number(&subject.normalized, &subject.normalized_ssa, cc))
    });
    group.bench_function("value_number::value_number_with_parameter_slots", |b| {
        b.iter(|| {
            value_number::value_number_with_parameter_slots(
                &subject.normalized,
                &subject.normalized_ssa,
                cc,
            )
        })
    });
    group.bench_function("types_recover::recover_types", |b| {
        b.iter(|| types_recover::recover_types(&subject.normalized))
    });
    group.bench_function("types_recover::recover_prototype", |b| {
        b.iter(|| {
            types_recover::recover_prototype(
                &subject.normalized,
                &subject.normalized_ssa,
                cc,
                &subject.param_slots,
            )
        })
    });

    for (index, (name, pass)) in ast_passes().into_iter().enumerate() {
        let input = &subject.ast_prefixes[index];
        group.bench_function(name, |b| {
            b.iter_batched(
                || input.clone(),
                |mut f| pass(&mut f, cc, &subject.param_slots),
                BatchSize::SmallInput,
            )
        });
    }

    group.finish();
}

fn bench_llir_pipeline(c: &mut Criterion) {
    let subjects = subjects();
    let mut group = c.benchmark_group("ir_dataflow/llir_pipeline");
    group.sample_size(PIPELINE_SAMPLES);
    for subject in subjects {
        group.throughput(Throughput::Elements(subject.instrs as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(subject.label),
            subject,
            |b, subject| {
                b.iter_batched(
                    || subject.raw.clone(),
                    |mut f| run_llir_pipeline(&mut f, subject.cc),
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

fn bench_llir_dataflow(c: &mut Criterion) {
    let subjects = subjects();
    let mut group = c.benchmark_group("ir_dataflow/llir_dataflow");
    group.sample_size(PIPELINE_SAMPLES);
    for subject in subjects {
        group.throughput(Throughput::Elements(subject.instrs as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(subject.label),
            subject,
            |b, subject| {
                b.iter_batched(
                    || subject.annotated.clone(),
                    |mut f| run_llir_dataflow(&mut f, subject.cc),
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

fn bench_ast_pipeline(c: &mut Criterion) {
    let subjects = subjects();
    let mut group = c.benchmark_group("ir_dataflow/ast_pipeline");
    group.sample_size(PIPELINE_SAMPLES);
    for subject in subjects {
        group.throughput(Throughput::Elements(subject.instrs as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(subject.label),
            subject,
            |b, subject| {
                b.iter_batched(
                    || subject.ast.clone(),
                    |mut f| run_ast_pipeline(&mut f, subject.cc, &subject.param_slots),
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

fn bench_copyprop_constfold_fixpoint(c: &mut Criterion) {
    let subjects = subjects();
    let mut group = c.benchmark_group("ir_dataflow/copyprop_constfold_fixpoint");
    group.sample_size(PIPELINE_SAMPLES);
    for subject in subjects {
        // The fixpoint runs on the expression-reconstructed body, which is the
        // second prefix state (index 1: after `expr_reconstruct::reconstruct`).
        let input = &subject.ast_prefixes[1];
        group.throughput(Throughput::Elements(subject.instrs as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(subject.label),
            input,
            |b, input| {
                b.iter_batched(
                    || input.clone(),
                    |mut f| run_copyprop_constfold_fixpoint(&mut f),
                    BatchSize::SmallInput,
                )
            },
        );
    }
    group.finish();
}

/// Lift every subject exactly once for the whole bench binary.
///
/// Four bench groups need the same prepared functions; discovering, lifting and
/// value-numbering ~1000 blocks four times over would dominate the wall clock
/// of a run without any of it being measured.
fn subjects() -> &'static [Lifted] {
    static SUBJECTS_ONCE: OnceLock<Vec<Lifted>> = OnceLock::new();
    SUBJECTS_ONCE.get_or_init(|| {
        let loaded: Vec<Lifted> = SUBJECTS.iter().filter_map(load).collect();
        report_sizes(&loaded);
        loaded
    })
}

criterion_group!(
    benches,
    bench_micro_passes,
    bench_llir_pipeline,
    bench_llir_dataflow,
    bench_ast_pipeline,
    bench_copyprop_constfold_fixpoint
);
criterion_main!(benches);
