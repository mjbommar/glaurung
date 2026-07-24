# Review findings: control-flow closure and range CFG (recommendation #3)

READ-ONLY verification of the P0 review item "Require control-flow-closed
output and build a real range CFG." Each claim is checked against the current
code on branch `master` and reproduced with the already-built `glaurung` CLI /
`glaurung.ir` bindings. File:line citations are to the tree at
`/nas4/data/workspace-infosec/glaurung-decbench`.

## Summary verdicts

| Claim | Verdict | Where | Severity |
|-------|---------|-------|----------|
| (a) `decompile_range_at` builds one synthetic block, ignores branches, emits gotos without labels | CONFIRMED | `src/python_bindings/ir.rs:596-608` | Medium (opt-in binding only) |
| (b) Regular (`plain`/`c`) output emits gotos without matching labels | CONFIRMED | `src/ir/ast.rs` render_c/render_with_types vs 2345-2350 | High (pervasive on the main path) |
| (c) Out-of-function jump targets are not classified as tail calls vs external jumps | CONFIRMED | `src/ir/ast.rs:282`; `src/ir/lift_function.rs:66-85` | High (root cause of (b)) |

All three are real. (b) and (c) are the same underlying defect surfaced two ways;
(a) is a separate, narrower defect on a rarely-used binding.

---

## (a) CONFIRMED - `decompile_range_at` builds a single block, no CFG

`decompile_range_at_py` (`src/python_bindings/ir.rs:538-677`) fabricates a
`Function` with exactly **one** basic block spanning the whole range and with
empty predecessor/successor lists:

```rust
// src/python_bindings/ir.rs:601-608
func.basic_blocks.push(BasicBlock::new(
    format!("bb_{:x}", range_start),
    block_start,
    block_end,
    1,
    Some(Vec::new()),   // predecessors: empty
    Some(Vec::new()),   // successors:   empty
));
```

It never runs `analyze_functions_bytes` (contrast the main path,
`decompile_at_py`, `ir.rs:415`). `lift_function_from_bytes`
(`src/ir/lift_function.rs:47-86`) then lifts one `LlirBlock` for the whole range
with `succs` derived from `successor_ids` (empty here), so the structurer
(`recover`) sees a single block with no edges. Every in-range branch lowers to a
bare `Stmt::Goto` (`src/ir/ast.rs:282`) whose target block was never split out
and therefore has no `Stmt::Label`. Because the binding defaults to
`style=""`/`types=true`, it renders through `render_with_types`, which does **not**
reconcile gotos and labels (see (b)).

**Reproduction** (`hello-arm64-gcc`, `main` at 0x700):

```
$ python -c "import glaurung as g; print(g.ir.decompile_range_at(
    'samples/binaries/platforms/linux/amd64/cross/arm64/hello-arm64-gcc',
    0x700, 0x700, 0x760, style=''))"
function sub_700 @ 0x700 {
    ...
    if ((%var3 <= 0)) { goto L_79c; }     // no L_79c: anywhere
    ...
    if ((%var0 != %var2)) { goto L_740; } // no L_740: anywhere
}
# DANGLING GOTOS: ['740', '79c']
```

0x740 is an in-range back-edge (the loop) and 0x79c a forward target; both are
lost. The proper `decompile_at(...,0x700)` structures the same bytes into
`while (1) { ... }`. So the claim "constructs one synthetic block with no
successors, ignores branches structurally, and can emit gotos without labels"
is exactly right.

**Scope: this is the rarely-used binding, not the main path.** `decompile_range_at`
is only reached from the CLI when the user passes `--range-start/--range-end`
(`python/glaurung/cli/commands/decompile.py:322-338`); the default `decompile`
path uses `decompile_at`, which builds a real CFG via `analyze_functions_bytes`.

## (b) CONFIRMED - plain/c output emits gotos without matching labels

Only the DecBench renderer closes the goto/label set. `render_decbench_typed`
(and `render_decbench`) pins every unmatched target with a trailing null-statement
label:

```rust
// src/ir/ast.rs:2345-2350
for target in ids.gotos.difference(&ids.labels) {
    let _ = writeln!(out, "    L_{:x}: ;", target);
}
```

`render` (`ast.rs:1473`, Display), `render_c` (`ast.rs:1560-1571`) and
`render_with_types` (`ast.rs:3033-3046`) simply walk the body and print
`goto L_<va>;` (`ast.rs:1373`, `1780`, `2945`) and `L_<va>:` only for statements
that actually exist in the tree. There is **no** difference/closure pass, so any
goto whose target is not an in-function block start (or whose label was pruned)
renders dangling. `label_prune::prune_unreferenced_labels`
(`src/ir/label_prune.rs:18-22`) only removes *labels* not referenced by a goto;
it never adds a missing label, so it cannot fix this and in some cases the block
merge upstream already dropped the label.

**Reproduction (main path, `decompile_all`, both `plain` and `c`):** dangling
gotos are widespread. On `hello-gcc-O2` every PLT stub plus `main`,
`_GLOBAL__sub_I_main`, `frame_dummy`, and several others carry them; on
`hello-arm64-gcc`, `_start`, `main`, `call_weak_fn`, `frame_dummy`, `print_sum`
all do.

Concrete external-jump case - a PLT thunk (`_ZNSo3putEc@plt`, 0x1030,
style plain):

```
function _ZNSo3putEc@plt @ 0x1030 {
    ...
    push 0;
    goto L_1020;     // 0x1020 = PLT-0 resolver, outside this "function"; no L_1020:
    ...
}
```

Concrete in-function case where the label was structured away
(`hello-arm64-gcc` `main`, 0x700, style plain):

```
    if ((%var3 <= 0)) {
        %var4 = 0;
        goto L_754;   // 0x754 is this function's epilogue; no L_754: survives
    } else { ... }
```

So (b) is confirmed for *both* triggers the review names: external tail calls
(PLT `goto L_1020`) and in-function targets whose block was folded/omitted
during structuring (`goto L_754`). Counts above are reproducible via
`decompile_all` + regex `goto L_(\w+);` minus `^\s*L_(\w+):`.

## (c) CONFIRMED - no tail-call / external-jump classification

Lowering converts *every* unconditional jump to a goto with the raw target VA,
with no test for whether the target lies inside the function:

```rust
// src/ir/ast.rs:282
Op::Jump { target } => vec![Stmt::Goto { target: *target }],
```

Successors in the LLIR are populated only from in-function `successor_ids`
(`src/ir/lift_function.rs:66-78`), so a jump leaving the function contributes no
edge and the structurer (`src/ir/structure.rs`) degrades that block to
`Region::Unstructured`, whose lowering labels only the blocks it owns
(`ast.rs:793-798`). Nothing ever asks "is `target` a block start of this
function?" and reclassifies a miss as a tail call (`Return`/`Call` + `Return`)
or an external branch (call-like annotation). The CFG layer *does* have a
`tail_call` notion (`src/analysis/cfg.rs:210,243,582`), but that classification
is not threaded into the lifter/lowerer, so it never reaches the AST. This is
the root cause of the external-jump half of (b).

---

## Recommended fix order (low-risk first)

1. **Pre-render CFG-closure validation for all renderers (low risk).**
   Lift the goto/label reconciliation already proven in `render_decbench_typed`
   (`ast.rs:2345-2350`) into a shared pre-render pass over the AST body, and call
   it from `render`, `render_c`, and `render_with_types`. For each
   `goto`-target with no surviving `Stmt::Label`, either (a) emit a trailing
   labeled no-op (`L_<va>: ;`) as decbench does, or (b) replace the goto with a
   `Stmt::Comment` (e.g. `// tail call / external -> 0x<va>`). This closes every
   dangling goto in (b) with no change to structuring and is well covered by an
   existing test pattern (`ast.rs:4043-4049`). Do this first.

2. **Classify out-of-function jump targets at lowering (medium risk).**
   Thread the function's block-start set (available as the `LlirFunction` block
   VAs) into `lower`/`lower_block` so `Op::Jump { target }` can branch: in-set ->
   `Stmt::Goto`; out-of-set + target is a known function/PLT entry -> `Stmt::Call`
   followed by `Stmt::Return` (tail call); otherwise -> annotated external branch.
   This removes most dangling gotos at the source and makes PLT thunks read as
   `return func();`. Reuse the existing `cfg.rs` tail-call detection rather than
   re-deriving it. Medium risk because it changes emitted statements and needs
   fixture updates.

3. **Real range CFG for `decompile_range_at` (higher risk).**
   Replace the single-synthetic-block construction (`ir.rs:596-608`) with a
   bounded intra-range CFG build (split the range on branch targets / fallthroughs,
   or run `analyze_functions_bytes` scoped to the range) so branches structure
   instead of becoming gotos. Higher risk (new block-splitting logic on a partial
   byte window) and, because the binding is opt-in and off the main path, lower
   priority than 1-2. If deferred, at minimum apply fix 1 so its output is at
   least control-flow-closed.

Fixes 1 and 2 are independent of 3; landing 1 alone already makes all
main-path output control-flow-closed.
