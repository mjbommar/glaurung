# Decompiler middle architecture: root causes and migration plan

**Status:** proposed  
**Scope:** function discovery through C rendering  
**Reviewed snapshot:** local `master` at `d6144a7` on 2026-07-26

## 1. Verdict

The top-level Glaurung architecture does not need a rewrite. The decompiler's
middle needs a deliberate architectural migration:

> Introduce one authoritative, typed SSA/MIR representation between executable
> LLIR and structured HIR.

The recent fixes are substantive and directionally correct, but the pipeline is
still transitional. Machine semantics are repeatedly converted into register
names and AST shapes, then inferred back later. That is the common cause behind
the flag, polarity, width, parameter, frame-pointer, phi, loop, and structuring
failures.

This is a localized replacement of accidental contracts, not a framework-wide
rewrite.

## 2. Root design problems

### 2.1 No authoritative semantic value representation

Normal arithmetic values and operations still lack explicit width in
`src/ir/types.rs`. SSA is a sidecar over the original LLIR; it excludes flags and
memory and does not make SSA values first-class. `value_number` then encodes SSA
identity in strings such as `rax#2`.

Type recovery compounds the problem. It is keyed by `VReg`, infers widths from
register spelling, and does not consume SSA identity. The DecBench pipeline must
therefore keep two versions of the function alive:

- canonicalized LLIR for value correctness and AST lowering;
- raw LLIR for sub-register widths and type recovery.

The two representations are reconciled later through name remapping. This has
caused or enabled:

- width loss and incorrect widening;
- stale sub-register values;
- register-reuse type contamination;
- dangling phi results and eliminated definitions;
- wrong parameter arity and narrowing;
- returned values being confused with scratch uses.

The root correction is a real value identity with an exact machine sort. Names
must become presentation metadata, never semantic identity.

### 2.2 Branch predicates are recognized by syntax, not semantics

`Flag` currently mixes architectural status flags with derived predicates such
as `Ule`, `Slt`, and `Sle`. `CondJump` consumes a `VReg` plus an `inverted` bit.
AST lowering searches backward for assignments with particular expression
shapes to reconstruct the comparison and its polarity.

The failed flag experiment demonstrated the coupling precisely. Its condition
algebra was correct, but a composite predicate arrived in a `Temp` rather than a
`Flag`. The AST's structural matcher stopped recognizing it, producing ten
pass-to-fail polarity regressions.

Teaching the AST to "treat a materialized temp like a flag" would only broaden
the accidental syntax contract. A temporary is not semantically a flag. The
branch must consume an explicitly typed boolean value with provenance.

The proper protocol is:

```text
producer -> FlagDef/FlagEffect -> condition materialization -> BoolId -> branch
```

Every flag effect must be explicit:

```text
Defined(expr) | Preserved | Undefined
```

Leaving stale state in place cannot represent `Undefined`.

### 2.3 Machine state is allowed to leak into generated C

On the machine, `rbp` is valid incoming state. In emitted C, a surviving `rbp`
becomes a declared but uninitialized local. An expression such as `rbp - 32`
therefore passes a garbage address even though the corresponding machine address
was valid.

The new definition verifier correctly diagnoses the symptom, but a
frame-pointer-specific verifier rule is not the final model. HIR needs semantic
objects:

- `FrameBase` for machine frame state;
- `StackObject` or `StackSlot` for recovered storage;
- explicit address-of operations for address-taken objects;
- ABI inputs and outputs rather than raw live-in register variables.

Raw frame and stack registers must not be renderable as ordinary C locals.

### 2.4 The structurer assigns graph ownership using a consuming tree walk

`structure.rs` still builds a tree with a global `visited` set and a sequence of
shape-specific recognizers. Shared joins, rotated loops, switches, early exits,
and loop-contained dispatches therefore compete for block ownership. A block can
be consumed by the wrong region, duplicated, or reached through an empty arm.

Typed CFG edges and total structural accounting are major improvements, but
they are not yet the structurer's authoritative input. Accounting also remains
diagnostic/shadow-only.

Region ownership must derive from graph boundaries:

- dominator and postdominator trees;
- SCC and natural-loop forests;
- single-entry/single-exit regions;
- explicit edge accounting.

When no high-level construct is valid, every remaining edge must become a
label/goto. Goto-heavy output is inferior but correct; plausible structure with
a missing or invented edge is not.

### 2.5 Stage contracts remain porous

The four public decompile entry points repeat the pass sequence. Tests currently
keep the copies aligned, but there is no type-level guarantee that all entry
points run the same pipeline.

Other porous boundaries remain:

- pass behavior depends on presentation names such as `ret`, `argN`, and
  `local_N`;
- type maps are remapped after naming;
- renderer configuration uses thread-local name maps;
- verifiers run late and usually report symptoms instead of preventing an
  invalid representation from proceeding;
- some verification is enabled only through environment variables.

Each stage should accept one verified input type and produce one verified output
type. A public API should select a function and rendering style, not assemble a
pipeline.

### 2.6 CFG completeness is not represented

LLIR has a direct `Jump` and an indirect `Call`, but no proper indirect-jump
terminator. Jump-table structure is inferred from successor count. If discovery
does not resolve an indirect dispatch, the case blocks may never enter the CFG,
and the transfer can be rendered as an indirect call.

Structural accounting can only prove that a region represents the CFG it was
given. It cannot prove that the CFG represents the function's machine code.

Discovery must produce an explicit completeness result:

```text
Complete | Incomplete(reason, unresolved_targets, uncovered_ranges)
```

An indirect jump must remain an indirect jump even when its target set is
unknown.

## 3. Foundations that should be retained

Recent work has created several correct architectural foundations:

- `src/ir/regview.rs` is the single owner of register family/view semantics for
  lifting, SSA, and execution.
- Calls carry explicit argument/result effects before SSA.
- Rendering was made formatting-only, allowing verification of the AST that is
  actually printed.
- Typed CFG edges distinguish taken, fallthrough, switch, explicit jump, and
  linear flow.
- Structural accounting detects missing, duplicated, goto-only, and invented
  control-flow relationships.
- The fixture gate and per-cell ratchet provide a credible migration net.
- The experimental flag branch was kept isolated after measured regressions.

These should become mandatory properties of the new middle representation,
rather than optional analyses surrounding the old one.

## 4. Target architecture

```text
Function discovery
  -> CFG { typed terminators, resolved targets, completeness status }
  -> verified machine LLIR
       exact widths
       register views
       flag effects
       call/memory effects
  -> typed SSA/MIR
       ValueId
       Bool / BitVec(width)
       explicit Phi
       ABI inputs and outputs
       StackObject / FrameBase
       optional memory-effect token
  -> normalized CFG
       Branch { predicate: BoolId, taken, fallthrough }
       IndirectJump / Switch explicitly represented
  -> total SESE/loop region recovery
       every edge structured or emitted as goto
  -> typed HIR
       source variables, declarations, address-of, recovered C types
  -> pure renderers
```

### 4.1 Keep machine truth separate from recovered source types

The type model must have three layers:

1. **Machine sort:** exact bit width and boolean/bit-vector identity. This is
   mandatory semantic truth.
2. **Operation interpretation:** signed or unsigned behavior at a particular
   use. This often belongs to the operation rather than the value.
3. **Recovered source type:** pointer, integer, structure, and declaration
   hypotheses, including confidence and provenance.

A narrow use such as `%dil` must not shrink an ABI parameter declaration by
itself. A pointer hypothesis must not alter the exact width or modular arithmetic
of the underlying machine value.

### 4.2 Make uncertainty explicit

Every stage should return an artifact plus diagnostics/trust status. Unknown
instruction effects, undefined flags, unresolved indirect jumps, incomplete
CFGs, or failed invariants must not silently become plausible C.

A failure should degrade only the affected function. Depending on the stage, it
may fall back to a more explicit representation, retain an opaque intrinsic, or
mark the function unsupported. It must not abort unrelated functions, and it
must not silently continue with invented semantics.

## 5. Migration plan

### Phase 1: consolidate the pipeline and enforce contracts

Create one `DecompilerPipeline::run_function()` used by `decompile_at`,
`decompile_range_at`, `decompile_all`, and `decompile_many`. It should return a
structured result containing the HIR, diagnostics, trust status, and requested
renderings.

Make existing verification unconditional in the fixture gate. A failed
invariant should stop semantic optimization of that function and select an
honest fallback or untrusted result.

#### Acceptance criteria

- All four entry points produce byte-identical output for the same function and
  configuration.
- There is one pass list and one pass-dump implementation.
- Structural accounting and prepared-AST verification run for every fixture.
- This phase changes no fixture verdict or rendered output.

### Phase 2: finish machine-IR widths and implement predicates correctly

Complete the existing executable-LLIR contract. Every constant, value,
assignment, arithmetic operation, comparison, and load result must carry an
exact width.

Introduce lazy flag definitions:

```text
FlagDef {
    operation,
    lhs,
    rhs,
    result,
    width,
    prior_flags,
}
```

All `Jcc`, `SETcc`, and `CMOVcc` consumers must use the same condition mapping and
produce or consume one typed `BoolId`. AST lowering receives the final boolean
expression directly; it does not search for flag-shaped assignments.

Unimplemented producers may initially mark effects `Undefined`, but consumers
must fail closed rather than read stale state.

#### Acceptance criteria

- Individual instruction lifters no longer write `Ule`, `Slt`, or `Sle`.
- A read of an undefined flag is rejected by a dominance-aware verifier.
- Tests cover all sixteen `Jcc` condition families, `SETcc`, `CMOVcc`, `ADC/SBB`,
  8/16/32/64-bit producers, and shift counts 0, 1, and greater than 1.
- Every existing conditional-polarity fixture remains passing.
- `14_flag_effects` becomes green without a pass-to-fail regression.
- The rendered condition does not expose raw `sf`, `of`, or `zf` plumbing when a
  source-like comparison can be reconstructed from provenance.

### Phase 3: replace string-numbered SSA with typed SSA/MIR

Introduce explicit values:

```rust
struct ValueInfo {
    sort: MachineSort, // Bool or BitVec(Width)
    storage: Storage,
    definition: Definition,
}

enum Storage {
    RegisterView(RegView),
    StackObject(StackObjectId),
    Temporary,
    AbiInput(AbiSlot),
}
```

Phi definitions must exist in the IR. Naming, type recovery, expression
reconstruction, and rendering must key on `ValueId`, not register spelling.
Register reads/writes must use the existing architecture-aware view descriptor
and canonical parent semantics.

Introduce explicit ABI inputs, outputs, clobbers, and call memory effects.
Introduce `FrameBase`, `StackObject`, and address-of before lowering to C HIR.

#### Acceptance criteria

- No `reg#version` string encoding remains.
- No raw/canonical dual LLIR path remains in DecBench lowering.
- `remap_type_map` and renderer name-based type side channels are removed.
- A raw frame/stack pointer cannot be declared as an ordinary C local.
- `countdown` recovers the correct one-argument `int` signature, with no phantom
  arguments.
- Def-use, phi, flag, width, and ABI validation operate on stable value IDs and
  dominance.
- C++ O0 address-taken stack-object quarantines are removed only after both the
  verifier and execution differential pass.

### Phase 4: replace the structurer behind shadow mode

Normalize the complete CFG first. Add explicit terminators for:

- conditional branch with a `BoolId` predicate;
- direct jump;
- indirect jump with known/unknown targets;
- switch with case values and default;
- return, tail call, and non-returning transfer.

Build regions from dominator/postdominator trees, SCC/loop forests, and SESE
boundaries. Region ownership must derive from boundaries rather than visitation
order.

Run the new structurer beside the old one and compare both structurally and
semantically. Use explicit labels/gotos for every edge that is not legally
structured.

#### Acceptance criteria

- Zero `BlockDropped`, `BlockDuplicated`, `EdgeUnaccounted`,
  `ImpliedEdgeAbsent`, and `GotoTargetMissing` findings.
- `EdgeViaGoto` is allowed and separately counted as output-quality debt.
- Unknown indirect dispatches report an incomplete CFG rather than clean
  structure.
- Targeted short-circuit, switch, early-exit, loop-rotation, nested-loop, and
  state-machine fixtures are structurally faithful.
- The new structurer replaces the old one only with zero semantic regressions
  and materially fewer goto-only edges.

### Phase 5: remove compatibility mechanisms

After the new middle is authoritative, remove:

- `value_number` string mangling;
- AST flag hoisting by register/expression shape;
- raw/canonical type-map reconciliation;
- frame-pointer-specific verifier exceptions that the HIR makes impossible;
- duplicated public pipeline bodies;
- renderer thread-local semantic context;
- obsolete or conflicting flag/LLIR design claims.

The removal is part of the migration. Leaving both architectures alive would
allow new callers to bypass the verified path and recreate the same class of
bugs.

## 6. Immediate implementation directive

Do not merge the experimental flag branch and do not add another AST temp
special case.

Work in this order:

1. Consolidate the four public entry points into one pipeline without changing
   output.
2. Add a typed-predicate vertical slice in which an arithmetic producer records
   its width and flag effects, a branch consumes a `BoolId`, and undefined flags
   fail closed.
3. Lower that `BoolId` directly into an HIR boolean expression; no AST backward
   search or `Flag`-versus-`Temp` test is permitted.
4. Prove the slice against `01_conditional_polarity` and `14_flag_effects`.
5. Refresh baselines only after manually reviewing every changed differential.

Required validation for every bounded slice:

```bash
cargo test --lib --tests
scripts/decbench-local-gate.sh
git diff --check
```

Do not call the slice complete if any required local gate regresses, if an
improvement is recorded without reviewing its output, or if required remote CI
is red, queued, skipped, or missing.

## 7. Stop conditions

Stop and redesign the slice rather than patching around it if any of these occur:

- a semantic value must be identified by parsing a display name;
- equivalent boolean expressions take different polarity paths because one is a
  `Flag` and one is a `Temp`;
- exact width must be recovered from pre-canonicalization register spelling;
- a raw frame/stack register must be emitted as a C variable to preserve an
  address;
- one CFG block is owned according to which arm visited it first;
- an unknown indirect jump is rendered as a call;
- a verifier detects corruption but the same function continues through the
  semantic optimization pipeline unchanged;
- a fix for one CFG silhouette produces a regression in another silhouette.

Any of these means the implementation has crossed the new architectural
boundary in the wrong direction.
