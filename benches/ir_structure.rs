//! Control-flow structuring and C rendering — the decompiler back end.
//!
//! Everything here measures what happens *after* a function has been discovered,
//! lifted and value-numbered: turning an LLIR control-flow graph into a
//! [`Region`] tree (`src/ir/structure.rs`), lowering that tree into the C AST
//! (`src/ir/ast/lower_region.rs`), recovering source-level loops over the AST
//! (`src/ir/loop_form.rs`, driven from `src/ir/ast/prepare.rs`), and printing C
//! (`src/ir/ast/c_render.rs`).
//!
//! **Why the stages are separate benches.** A structuring regression and a
//! rendering regression look identical end to end. Each stage is timed on the
//! *same* precomputed input so a movement can be attributed to exactly one of
//! `structure.rs`, `lower_region.rs`, `loop_form.rs` or `c_render.rs`.
//!
//! **Why the input is hoisted, not batched.** The brief for this bench is that
//! discovery/lifting/SSA/value-numbering must not be inside the measurement.
//! `recover`, `lower`, `prepare_for_decbench` and `render_c` all take their
//! input by shared reference and do not mutate it, so the whole prefix is built
//! once per lane in [`Stages::build`] and the timing loop touches nothing else —
//! strictly cheaper and less noisy than re-cloning it per batch. The one stage
//! that *does* mutate its input, the `loop_form` quartet (`&mut Function`), uses
//! `iter_batched` with a clone as its setup step.
//!
//! **Why a shape sweep and not a size sweep.** Structuring cost is driven by the
//! SHAPE of the control-flow graph, not its instruction count: a 256-arm switch,
//! a 16-deep if/else tower and a two-entry irreducible loop take completely
//! different paths through `build_full`. Each lane below is a fixture whose
//! header comment states exactly which shape it exercises, and the bench id
//! leads with that shape tag.
//!
//! All inputs are real prebuilt fixture binaries from
//! `tests/decompiler_fixtures/build/` (gitignored; produced by the fixture
//! toolchain). A lane whose binary or symbol is missing is reported on stderr
//! and skipped — nothing here fabricates IR, an AST or binary content.

use std::collections::HashMap;
use std::hint::black_box;
use std::path::{Path, PathBuf};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use glaurung::analysis::cfg::{analyze_functions_image_with_seeds, Budgets};
use glaurung::ir::abi::annotate_calls;
use glaurung::ir::ast::{self, Function as AstFunction};
use glaurung::ir::call_args::CallConv;
use glaurung::ir::lift_function::lift_function_from_image;
use glaurung::ir::loop_form;
use glaurung::ir::ssa::{self, SsaInfo};
use glaurung::ir::structure::{self, Region};
use glaurung::ir::types::LlirFunction;
use glaurung::ir::value_number;
use glaurung::program::image::ProgramImage;

const FIXTURE_BUILD_DIR: &str = "tests/decompiler_fixtures/build";

/// One measured function: which fixture it comes from, which control-flow shape
/// its header comment says it exercises, and which build lane to read.
struct Lane {
    /// Short tag for the control-flow shape; leads the bench id so the report
    /// sorts by shape rather than by fixture number.
    shape: &'static str,
    fixture: &'static str,
    function: &'static str,
    toolchain: &'static str,
    opt: &'static str,
}

impl Lane {
    fn id(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.shape, self.function, self.toolchain, self.opt
        )
    }

    fn path(&self) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(FIXTURE_BUILD_DIR)
            .join(format!(
                "{}-{}-{}.so",
                self.fixture, self.toolchain, self.opt
            ))
    }
}

/// The single small, known-shape function for the micro tier: a four-arm
/// `if / else if / else` ladder at `-O0` (`01_conditional_polarity.c:elseif`).
const MICRO_LANE: Lane = Lane {
    shape: "if_elseif_ladder",
    fixture: "01_conditional_polarity",
    function: "elseif",
    toolchain: "gcc",
    opt: "O0",
};

/// The shape sweep. Every entry names a fixture whose header comment documents
/// the control-flow construct it exists to exercise; the comment beside each
/// lane quotes what that construct is.
const SWEEP_LANES: &[Lane] = &[
    // Sixteen levels of nested if/else and no loops at all: pure conditional
    // nesting depth, the recursion axis of `build_full`.
    Lane {
        shape: "if_tower_depth16",
        fixture: "152_deep_nesting",
        function: "deep152_conditional_tower",
        toolchain: "gcc",
        opt: "O0",
    },
    Lane {
        shape: "if_tower_depth16",
        fixture: "152_deep_nesting",
        function: "deep152_conditional_tower",
        toolchain: "gcc",
        opt: "O2",
    },
    // Twelve counted loops inside one another with four conditionals
    // interleaved: loop nesting depth rather than conditional depth.
    Lane {
        shape: "nested_loops_depth12",
        fixture: "152_deep_nesting",
        function: "deep152_nested_loops",
        toolchain: "gcc",
        opt: "O0",
    },
    Lane {
        shape: "nested_loops_depth12",
        fixture: "152_deep_nesting",
        function: "deep152_nested_loops",
        toolchain: "gcc",
        opt: "O2",
    },
    // 256 contiguous cases returning distinct constants — the compiler turns
    // this into a constant lookup table, so the switch has to be found in data.
    Lane {
        shape: "switch_dense_256",
        fixture: "154_wide_switch",
        function: "wide154_dense_switch",
        toolchain: "gcc",
        opt: "O0",
    },
    Lane {
        shape: "switch_dense_256",
        fixture: "154_wide_switch",
        function: "wide154_dense_switch",
        toolchain: "gcc",
        opt: "O2",
    },
    // 200 cases on a stride of 4099: lowered to a binary comparison tree, which
    // is `switch_ladder::recover_switches` work rather than jump-table work.
    Lane {
        shape: "switch_sparse_tree_200",
        fixture: "154_wide_switch",
        function: "wide154_sparse_switch",
        toolchain: "gcc",
        opt: "O0",
    },
    // A switch nested inside a loop: switch-break and loop-break have to stay
    // distinguishable.
    Lane {
        shape: "switch_in_loop",
        fixture: "04_switch_shapes",
        function: "switch_in_loop",
        toolchain: "gcc",
        opt: "O0",
    },
    // Duff's device: switch cases falling into the middle of a do/while, so the
    // loop and the switch share a body and cannot be structured independently.
    Lane {
        shape: "switch_interleaved_loop",
        fixture: "102_duffs_device",
        function: "duff_copy",
        toolchain: "gcc",
        opt: "O0",
    },
    // Kernel-style cleanup ladder: forward gotos into a reversed unwind chain
    // where later labels fall through earlier ones.
    Lane {
        shape: "goto_cleanup_ladder",
        fixture: "105_goto_ladder",
        function: "acquire_and_release",
        toolchain: "gcc",
        opt: "O0",
    },
    // `goto cleanup` ladder plus a backward retry loop plus cold error blocks.
    Lane {
        shape: "cleanup_ladder_retry_loop",
        fixture: "05_cleanup_and_state_machine",
        function: "process",
        toolchain: "gcc",
        opt: "O0",
    },
    // A return from inside a loop, which makes the shared epilogue
    // post-dominate the loop body — the classic mis-join.
    Lane {
        shape: "loop_early_exit",
        fixture: "13_loop_early_exit",
        function: "bisect",
        toolchain: "gcc",
        opt: "O0",
    },
    Lane {
        shape: "loop_early_exit",
        fixture: "13_loop_early_exit",
        function: "bisect",
        toolchain: "gcc",
        opt: "O2",
    },
    // A multi-way dispatch inside a loop, ONE arm of which returns: the shape
    // `04`, `13` and `05` each cover half of.
    Lane {
        shape: "loop_with_returning_arm",
        fixture: "212_loop_with_returning_arm",
        function: "fsm_returns_from_arm",
        toolchain: "gcc",
        opt: "O0",
    },
    Lane {
        shape: "loop_with_returning_arm",
        fixture: "212_loop_with_returning_arm",
        function: "fsm_returns_from_arm",
        toolchain: "gcc",
        opt: "O2",
    },
    // Two loop headers and no dominating entry: `detect_natural_loop` cannot
    // fire and `build_full` reaches its whole-function `Region::Unstructured`
    // goto bailout. This is the goto-heavy lane.
    Lane {
        shape: "irreducible_two_entry",
        fixture: "211_irreducible_loops",
        function: "two_entry_loop",
        toolchain: "gcc",
        opt: "O0",
    },
    // OLLVM-style control-flow flattening: one `while` around a `switch` on a
    // state variable, every original edge living in data rather than the CFG.
    Lane {
        shape: "flattened_dispatch",
        fixture: "145_control_flow_flattening",
        function: "flattened_accumulate",
        toolchain: "gcc",
        opt: "O0",
    },
    Lane {
        shape: "flattened_dispatch",
        fixture: "145_control_flow_flattening",
        function: "flattened_accumulate",
        toolchain: "gcc",
        opt: "O2",
    },
    // Scale stress: a 211-arm descending threshold ladder, each arm with its own
    // inner branching — about a thousand basic blocks at -O0.
    Lane {
        shape: "branch_ladder_211arm",
        fixture: "151_wide_branch_ladder",
        function: "big151_branch_ladder",
        toolchain: "gcc",
        opt: "O0",
    },
    Lane {
        shape: "branch_ladder_211arm",
        fixture: "151_wide_branch_ladder",
        function: "big151_branch_ladder",
        toolchain: "gcc",
        opt: "O2",
    },
    // Rust iterator adapter chain. At -O0 a stack of real `next()` calls over
    // small aggregates; at -O2 the whole pipeline is fused into one loop whose
    // induction variable, bound and body came from different source constructs.
    Lane {
        shape: "rust_iter_chain",
        fixture: "219_rust_iterator_chains",
        function: "iter_filter_map_sum",
        toolchain: "rustc",
        opt: "O0",
    },
    Lane {
        shape: "rust_iter_chain",
        fixture: "219_rust_iterator_chains",
        function: "iter_filter_map_sum",
        toolchain: "rustc",
        opt: "O2",
    },
];

/// Discovery budgets wide enough that the scale fixtures are not truncated.
///
/// The defaults (`max_blocks: 2048`, `timeout_ms: 100`) would clip
/// `big151_branch_ladder`, which is ~1000 blocks at `-O0`; a clipped CFG is a
/// different shape, so the bench would then be measuring the truncation rather
/// than the structurer.
fn bench_budgets() -> Budgets {
    Budgets {
        max_functions: 1,
        max_blocks: 16_384,
        max_instructions: 400_000,
        timeout_ms: 60_000,
        total_timeout_ms: 0,
    }
}

/// Load one fixture binary. `None` when it has not been built
/// (`tests/decompiler_fixtures/build/` is gitignored) — the lane is then
/// reported and skipped rather than substituted.
fn load_image(path: &Path) -> Option<ProgramImage> {
    if !path.exists() {
        eprintln!("ir_structure: skipping — no such fixture binary: {path:?}");
        return None;
    }
    match ProgramImage::from_path(path) {
        Ok(image) => Some(image),
        Err(error) => {
            eprintln!("ir_structure: skipping {path:?} — image load failed: {error:?}");
            None
        }
    }
}

/// Every intermediate the back end consumes, built once outside the timing loop.
struct Stages {
    /// Lifted, call-annotated LLIR — the input to region recovery.
    llir: LlirFunction,
    ssa: SsaInfo,
    /// Value-numbered LLIR — what `ast::lower` reads alongside the region.
    numbered: LlirFunction,
    /// The recovered region tree — the input to `ast::lower`.
    region: Region,
    /// The freshly lowered AST — the input to loop recovery and to `prepare`.
    ast: AstFunction,
    /// The AST after the full structuring schedule — what `render_c` prints.
    prepared: AstFunction,
    /// Basic-block count, used as the throughput element for the CFG stages.
    blocks: u64,
    /// Length of the emitted C, used as the throughput byte count for rendering.
    c_bytes: u64,
}

impl Stages {
    fn build(lane: &Lane, image: &ProgramImage) -> Option<Stages> {
        let cc: CallConv = match image.target().calling_convention() {
            Some(cc) => cc,
            None => {
                eprintln!(
                    "ir_structure: skipping {} — target has no calling convention",
                    lane.id()
                );
                return None;
            }
        };
        let entry = image
            .defined_text_symbol_address(lane.function)
            .map(|address| image.normalize_function_entry(address))?;
        let (functions, _call_graph) =
            analyze_functions_image_with_seeds(image, &bench_budgets(), &[entry]);
        let function = functions
            .iter()
            .find(|candidate| candidate.entry_point.value == entry)?;

        let mut llir = match lift_function_from_image(image, function) {
            Ok(llir) => llir,
            Err(error) => {
                eprintln!(
                    "ir_structure: skipping {} — lift failed: {error:?}",
                    lane.id()
                );
                return None;
            }
        };
        annotate_calls(&mut llir, cc);

        let ssa = ssa::compute_ssa_for_target(&llir, *image.target());
        let region = structure::recover(&llir, &ssa);
        let (numbered, _definition_widths, _parameter_slots) =
            value_number::value_number_with_parameter_slots(&llir, &ssa, cc);
        let ast = ast::lower(&numbered, &region, function.name.clone());
        let prepared = ast::prepare_for_decbench(&ast);
        let c_bytes = ast::render_c(&prepared).len() as u64;
        let blocks = llir.blocks.len() as u64;

        Some(Stages {
            llir,
            ssa,
            numbered,
            region,
            ast,
            prepared,
            blocks,
            c_bytes,
        })
    }
}

/// Run the loop-recovery passes `prepare_for_decbench` drives, in its order.
///
/// These are the only back-end passes that take `&mut Function`, which is why
/// this stage is the one that needs a per-iteration clone.
fn recover_loops(function: &mut AstFunction) {
    loop_form::recover_linear_latched_do_whiles(function);
    loop_form::recover_head_tested_whiles(function);
    loop_form::recover_guarded_do_whiles(function);
    loop_form::recover_sentinel_search_loops(function);
    loop_form::promote_for_loops(function);
}

/// Build every lane's stages up front, sharing one loaded image per fixture
/// binary (several lanes read different functions out of the same `.so`).
fn build_lanes(lanes: &[Lane]) -> Vec<(String, Stages)> {
    let mut images: HashMap<PathBuf, Option<ProgramImage>> = HashMap::new();
    let mut built = Vec::new();
    for lane in lanes {
        let path = lane.path();
        let image = images
            .entry(path.clone())
            .or_insert_with(|| load_image(&path));
        let Some(image) = image.as_ref() else {
            continue;
        };
        match Stages::build(lane, image) {
            Some(stages) => built.push((lane.id(), stages)),
            None => eprintln!(
                "ir_structure: skipping {} — function {:?} not recovered from {path:?}",
                lane.id(),
                lane.function
            ),
        }
    }
    built
}

/// Micro tier: one small four-arm if/else-if ladder, every back-end stage timed
/// separately so a regression lands on exactly one module.
fn bench_micro(c: &mut Criterion) {
    let built = build_lanes(std::slice::from_ref(&MICRO_LANE));
    let Some((id, stages)) = built.first() else {
        eprintln!("ir_structure: micro tier unavailable — fixture binary missing");
        return;
    };

    let mut group = c.benchmark_group("ir-structure/micro");
    group.throughput(Throughput::Elements(stages.blocks));

    // LLIR CFG -> Region tree: if/else detection, switch detection, goto reduction.
    group.bench_function(format!("recover-cfg-to-region/{id}"), |b| {
        b.iter(|| black_box(structure::recover(&stages.llir, &stages.ssa)))
    });

    // The same recovery plus `verify_region`, so verification cost is separable.
    group.bench_function(format!("recover-verified-cfg-to-region/{id}"), |b| {
        b.iter(|| black_box(structure::recover_verified(&stages.llir, &stages.ssa)))
    });

    // `verify_structure` alone: the region well-formedness check.
    group.bench_function(format!("verify-structure/{id}"), |b| {
        b.iter(|| black_box(structure::verify_structure(&stages.llir, &stages.ssa)))
    });

    // Region tree + value-numbered LLIR -> C AST.
    group.bench_function(format!("lower-region-to-ast/{id}"), |b| {
        b.iter(|| {
            black_box(ast::lower(
                &stages.numbered,
                &stages.region,
                stages.ast.name.clone(),
            ))
        })
    });

    // Source-level loop recovery over the AST (`src/ir/loop_form.rs`). This is
    // the mutating stage, so the clone is the `iter_batched` setup step and is
    // not inside the measurement.
    group.bench_function(format!("loop-form-ast-loop-recovery/{id}"), |b| {
        b.iter_batched(
            || stages.ast.clone(),
            |mut function| {
                recover_loops(&mut function);
                black_box(function)
            },
            BatchSize::SmallInput,
        )
    });

    // The whole AST structuring schedule: loop recovery + switch ladders +
    // label/goto pruning + return folding.
    group.bench_function(format!("prepare-ast-structuring/{id}"), |b| {
        b.iter(|| black_box(ast::prepare_for_decbench(&stages.ast)))
    });

    // AST -> C text. Rendering only; the AST it prints is already structured.
    group.throughput(Throughput::Bytes(stages.c_bytes));
    group.bench_function(format!("render-c-ast-to-text/{id}"), |b| {
        b.iter(|| black_box(ast::render_c(&stages.prepared)))
    });

    group.finish();
}

/// Shape sweep: the same four stages across deliberately different control-flow
/// shapes, so a cost that is specific to one shape is visible as such.
fn bench_shape_sweep(c: &mut Criterion) {
    let built = build_lanes(SWEEP_LANES);
    if built.is_empty() {
        eprintln!("ir_structure: shape sweep unavailable — no fixture binaries found");
        return;
    }

    // Stage 1 — LLIR CFG -> Region tree (`src/ir/structure.rs`).
    let mut group = c.benchmark_group("ir-structure/recover-cfg-to-region");
    for (id, stages) in &built {
        group.throughput(Throughput::Elements(stages.blocks));
        group.bench_function(id, |b| {
            b.iter(|| black_box(structure::recover(&stages.llir, &stages.ssa)))
        });
    }
    group.finish();

    // Stage 2 — Region tree -> C AST (`src/ir/ast/lower_region.rs`).
    let mut group = c.benchmark_group("ir-structure/lower-region-to-ast");
    for (id, stages) in &built {
        group.throughput(Throughput::Elements(stages.blocks));
        group.bench_function(id, |b| {
            b.iter(|| {
                black_box(ast::lower(
                    &stages.numbered,
                    &stages.region,
                    stages.ast.name.clone(),
                ))
            })
        });
    }
    group.finish();

    // Stage 3a — loop recovery alone (`src/ir/loop_form.rs`), the mutating pass.
    let mut group = c.benchmark_group("ir-structure/loop-form-ast-loop-recovery");
    for (id, stages) in &built {
        group.bench_function(id, |b| {
            b.iter_batched(
                || stages.ast.clone(),
                |mut function| {
                    recover_loops(&mut function);
                    black_box(function)
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();

    // Stage 3b — the full AST structuring schedule (`src/ir/ast/prepare.rs`),
    // which drives loop_form, switch_ladder, label_prune and the return folds.
    let mut group = c.benchmark_group("ir-structure/prepare-ast-structuring");
    for (id, stages) in &built {
        group.bench_function(id, |b| {
            b.iter(|| black_box(ast::prepare_for_decbench(&stages.ast)))
        });
    }
    group.finish();

    // Stage 4 — AST -> C text (`src/ir/ast/c_render.rs`).
    let mut group = c.benchmark_group("ir-structure/render-c-ast-to-text");
    for (id, stages) in &built {
        group.throughput(Throughput::Bytes(stages.c_bytes));
        group.bench_function(id, |b| {
            b.iter(|| black_box(ast::render_c(&stages.prepared)))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_micro, bench_shape_sweep);
criterion_main!(benches);
