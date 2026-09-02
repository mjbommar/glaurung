# Register views and the verifier boundary

> **Kind:** architecture · **Status:** maintained

Two ownership rules in the decompiler, both of the same shape: knowledge that
must have exactly one owner, and a stage that must be pure.

1. **`src/ir/regview.rs` is the only place that knows what a register name
   means.** Every consumer — the lifters, SSA, the ABI, the emulator's register
   file — asks it rather than carrying its own table.
2. **Preparation and rendering are separate stages, with a verifier between
   them.** A renderer may format an AST; it may not change one.

---

## 1. One register-view descriptor

### The model

A physical register name is a **view** onto a canonical full-width **parent**:
`al`, `ah`, `ax` and `eax` are windows onto `rax`; `w0` is a window onto `x0`;
`xmm0_d0` is a 32-bit lane of the 128-bit `xmm0`. Every consumer that reasons
about registers needs the same four facts — canonical parent, bit offset, view
width, and what a write through the view does to the bits *outside* it — so
`src/ir/regview.rs` holds them once, per architecture.

`RegView` carries the offsets, widths and the exact `keep` / `value` masks.
`ParentDefinition` answers the question a naive table cannot: does a set of
writes cover **every** bit of a parent, **some** of them, or **none**? "Some" is
a first-class answer. It is not "unrelated", and per the pipeline's design rule
that unknown never means no effect, it is not "no effect" either.

The semantics encoded (Intel SDM Vol. 1 3.4.1.1, AMD64 APM Vol. 1 3.1, ARM DDI
0487 B1.2.1):

| write through | effect on the parent |
|---|---|
| a full-width view | replaces it |
| a 32-bit view (`eax`, `w0`) | **zero-extends** — bits 32..63 become 0 |
| a 16- or 8-bit view (`ax`, `al`, `ah`..`dh` at bit offset 8) | **preserves** every bit outside the view, including the high 32 |
| a packed dword lane (`xmm0_d0`..`xmm0_d3`, `v0_d0`..`v0_d3`) | preserves every parent bit outside its own 32-bit window — the parent is simply 128 bits wide |

### Why it is one table and not three

Because three disagreeing copies produced wrong code. The lifter used to model
`mov $0xAA,%al` as a read-modify-write of the **32-bit** view `eax` with a
32-bit keep mask. A 32-bit write zero-extends, so that silently cleared bits
32..63 of `rax` — bits the instruction must preserve — while the emulator's own
table preserved them. Any time `rax` held a 64-bit value (any pointer, any
`long`), the decompilation was wrong, and the two subsystems could not both be
right by construction because neither was reading the other's table.

### Who asks it

`rg -l 'regview::' src/` finds fourteen modules. The four that matter
structurally:

| consumer | what it asks for |
|---|---|
| `src/exec/state.rs` | builds the emulator's register file from `regview::gp_views(arch)`, and re-exports `regview::Arch` as `RegArch` — **one** architecture enum, not two. The emulator's partial-register semantics are therefore this table's semantics by construction |
| `src/ir/lift_x86.rs` (and `lift_x86/flags.rs`, `wide_arith.rs`, `mul_flags.rs`) | lifts a partial write as a read-modify-write of the **canonical 64-bit parent** using `keep_mask` / `value_mask`, and normalises names through `canonical_name` |
| `src/ir/ssa.rs` | `parent64` delegates to `regview::ssa_parent` for both x86-64 and AArch64 |
| `src/ir/abi.rs`, `src/ir/types_recover/float_bank.rs`, `src/ir/callee_return_pair.rs`, `src/ir/call_result_split.rs` | family membership, lane relationships, and which bank a result lives in |

### `parent64`, and what it still does

`ssa::parent64` (`src/ir/ssa.rs:280`) is the SSA-facing question: *may this view
share one SSA value with its parent?* It is not a lookup table any more — it
delegates to `regview::ssa_parent` — but it remains the name four modules
outside `ssa.rs` call:

```
src/program/environment.rs
src/ir/value_number/keep_bare.rs
src/ir/value_number/tagging.rs
src/ir/use_def.rs
```

(`rg -n 'parent64' src/`, at `13faa6f7`; the remaining hits are `ssa.rs` itself,
doc comments, and unit tests.)

The rule it encodes is the interesting part. **Only a total write may share an
identity.** A full-width view and a zero-extending 32-bit view are total: after
either, the parent's value is fully determined by the write, so `rax` and `eax`
version as one value and an `%rax` write correctly shadows a later `%eax` read.
A bit-preserving view (`al`, `ah`, `ax`) is *not* total — its result depends on
the parent's previous value — so merging it would claim a definition that does
not exist. Those are lifted as explicit read-modify-writes of the parent
instead, which gives SSA a real definition to version.

The vector bank is declined outright, whole registers included. Answering
`Some("xmm0")` for `xmm0` would be a harmless identity merge, but every caller
reads `is_some()` as "this table settles the name's SSA identity", and for a
vector register it does not: the lifters scalarise packed operations into dword
lanes versioned independently, with no read-modify-write lowering that would
join them back. What *does* hold for vectors is recorded by `parent_definition`
and `is_lane_of` instead. Getting that distinction wrong has a cost with a
shape: `lift_x86::synchronise_xmm_views` must append a `concat` bridge per
instruction precisely because a lane write does not define the parent, and
`ir::abi`'s call-result recovery once matched only a whole-`xmm0` read, so
`call; movd eax,%xmm0` looked like nobody consumed the float result at all.

### How it is verified

`tests/register_view_semantics.rs` is the loop that was missing: it **lifts real
machine code, runs it on the concrete machine, and asserts the resulting 64-bit
parent.** The emulator's own unit tests proved the register file correct; nothing
proved the *lifter* emitted ops that mean what the architecture says. The cases
cover a parent write read back through every narrower view; `al` / `ax` / `ah` /
`r8b` writes preserving the rest of the parent including bits 32..63; `eax`
zeroing the upper half; a register-sourced partial write; ALU destinations at 8,
16 and 32 bits; the sign-extending accumulator instructions (`cdqe`, `cwde`,
`cqo`, `cdq`); family independence; and AArch64 `w0` zero-extending into `x0`.
`regview`'s own invariants are asserted alongside: keep ∪ value covers the
parent, keep ∩ value is empty, every parent is itself a full-width view.

---

## 2. The verifier boundary: prepare, then render

### The rule

**A renderer formats; it does not decide.** Giving a bare return its ABI return
register, coalescing parameter spill slots, folding copy chains and recovering
source-level loop form all change definitions, uses and value identities. They
are pipeline operations. For a while they happened *inside*
`render_decbench_typed`, and the cost was concrete: a def-before-use checker was
written, produced false positives on correct functions, and was reverted —
because the AST it checked was not the AST that got printed. The renderer
emitted a string, so there was no post-fold AST to check at all.

### The shape

`src/python_bindings/ir/decbench_render.rs` states the order in its own module
doc, and it is four steps, deliberately separate:

1. **prepare** — `ast::prepare_for_decbench*` (`src/ir/ast/prepare.rs`) performs
   the semantic transformation: bare-return ABI register, parameter-spill
   coalescing, copy-chain folding, source-level loop-form recovery;
2. **sharpen** — the typed refine chain, every step of which is a *named* pass
   (see [`../reference/decompiler-passes.md`](../reference/decompiler-passes.md)),
   ending at the `ready_to_render` health boundary;
3. **verify** — `verify_defs::verify_before_render` (`src/ir/verify_defs.rs:774`)
   on exactly the AST that is about to be printed;
4. **render** — formatting, and nothing else.

Step 2's naming is not cosmetic. `run_ast_passes` had always announced each of
its passes; this tail did not, so seventeen AST-mutating transforms ran between
preparation and rendering with no boundary between them — and
`tools/pass_health_report.py` attributes a counter movement to the *first* pass
at which it appears. A newly introduced undefined read anywhere in that tail was
reported against `ready_to_render`, the boundary that observes the damage rather
than the pass that caused it. With the passes named, the same report blames the
transform.

### What the verifier checks, and why so little

Two rules, both chosen to have **no false positives**:

- **`NeverDefined`** — read somewhere, assigned nowhere. No control flow can
  rescue this, so it is always checked.
- **`UsedBeforeDefinition`** — flow-sensitive and deliberately *may*-defined: a
  definition in one arm of an `if` satisfies a use at the join, a loop body is
  checked with its own definitions pre-seeded (a later iteration may have
  produced the value), and a call defines its recorded destination. Skipped
  entirely for functions containing `goto`/labels, whose flow this walk does not
  model — better to check less than to guess.

Only names the decompiler **invents**, and therefore owes a definition for, are
checked: `ret`, `varN`, `local_*`, `stack_*`, and surviving lifter temporaries.
Parameters are defined by the ABI; raw machine registers are live-in state.

### How a violation leaves the boundary

Three channels, ranked by what they cost the consumer, and the ranking is the
design:

| channel | when | effect |
|---|---|---|
| `health::record_render_verification` | always | `take_render_verification` reports an honest count for the run; the CLI prints one stderr line. The emitted C is unchanged, which is why this can be unconditional |
| `GLAURUNG_PASS_HEALTH` | opt-in | the same count as `undefined_uses` on the `ready_to_render` event, beside the CFG fidelity counters |
| `GLAURUNG_VERIFY_DEFS` | opt-in | each violation spliced in as a `// glaurung-verify:` comment |

The third is opt-in because the decbench render is an artifact other tools parse
and score, and an unconditional comment is a note announcing our own bug inside
C we are asking someone else to measure. The fixture gate's structural lane opts
in, so its ratchet still sees every violation, and
`python/tests/test_decompiler_defuse_census.py` censuses every lane each fixture
supports.

**Reporting rather than erroring is deliberate.** A violation means *that
function's* decompilation is untrustworthy, not that an analyst's whole run
should abort, and suppressing the body would destroy the only evidence of what
went wrong.

---

## See also

- [`decompiler-pipeline.md`](decompiler-pipeline.md) — where both of these sit
  in the pipeline, and the design rules they instantiate.
- [`x86-flags.md`](x86-flags.md) — the same ownership argument applied to
  EFLAGS.
- [`../development/decompiler-testing.md`](../development/decompiler-testing.md) —
  the definition-before-use lane and its ratchet.
