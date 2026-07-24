# Typed SSA / HLIR layer (design)

> Review recommendation #6. Concrete, phased plan to move the decompiler from
> *physical-register-keyed, non-SSA* typing + a string-mangling value-numbering
> hack to a **value-scoped** representation where types attach to SSA values
> `(base, version)` and the AST/HLIR carries that identity end to end. This lets
> naming, typing, and rendering read from **one** typed representation and lets us
> delete `remap_type_map` and the `DEC_PTR_ARGS`/`DEC_PTRS` render-time
> reconciliation.
>
> Scope guard: build on what already landed — `src/ir/value_number.rs`
> (LLIR value-tagging) and `live_in_arg_slots_llir` — and keep the ~866-test
> `cargo test` suite and the DecBench render path green at every phase.

---

## 1. Current state (verified against the code)

### 1.1 What SSA computes

`compute_ssa` (`src/ir/ssa.rs:470-479`) produces a **side-car** `SsaInfo`
(`src/ir/ssa.rs:42-56`): `idom`, dominance `frontier`, placed `phis`, and two
version maps — `def_versions: HashMap<InstrAddr, u32>` and
`use_versions: HashMap<(InstrAddr, usize), u32>`. It deliberately does **not**
rewrite the LLIR; consumers cross-reference by `InstrAddr` (`src/ir/ssa.rs:11-14`).

Version 0 is the implicit entry-def / live-in (a parameter for an ABI arg
register); explicit defs number from 1 (`src/ir/ssa.rs:329-346`,
`top_version` returns 0 when the stack is empty at `src/ir/ssa.rs:348-350`).

**Who actually consumes `SsaInfo`:** only the structurer, and only for
dominance. `Cfg::from` reads `ssa.idom` to materialise the dominance relation
(`src/ir/structure.rs:153`, `:183-190`) and never touches `def_versions`,
`use_versions`, or `phis`. `value_number.rs` is the *only* consumer of the
version maps.

### 1.2 Critique (a) — SSA versions neither flags nor memory. **CONFIRMED.**

`is_ssa_reg` (`src/ir/ssa.rs:61-63`) is
`matches!(v, VReg::Phys(_) | VReg::Temp(_))` — `VReg::Flag(_)` is excluded, so no
flag is ever versioned (documented at `src/ir/ssa.rs:16-22`, `:58-60`). Memory is
not modelled at all: `def_uses` gives `Op::Store` no def and treats a load/store
`MemOp` purely as *register* uses of its `base`/`index`
(`src/ir/use_def.rs:52-59`, `:91-99`). There is no memory SSA token, no phi over
memory, and no notion of a load reading a particular store's value.

### 1.3 What type recovery does, and critique (b). **CONFIRMED.**

`recover_types` / `recover_types_for` (`src/ir/types_recover.rs:461`, `:321`) take
a bare `&LlirFunction` — **no `SsaInfo`** — and build a `TypeMap` that is a flat
`HashMap<VReg, TypeHint>` (`src/ir/types_recover.rs:43-46`). Every rule keys on
the physical `VReg`, unioned flow-insensitively across the whole function via the
`upsert` lattice (pointer ⟩ int, wider pointee ⟩ narrower, unsigned sticky, etc.,
`src/ir/types_recover.rs:72-113`). The module header itself states it "does not
require SSA form" and that "passes that need SSA precision can … re-run on a
per-version basis" (`src/ir/types_recover.rs:20-22`).

The demotion the review names is real and function-global:

- First pass gathers `gets_const` — **every** register that receives *any*
  `Op::Assign { src: Const }` **anywhere** in the function
  (`src/ir/types_recover.rs:469-480`).
- After all propagation, any reg in `gets_const` currently classified
  `Pointer`/`CodePointer` is overwritten to `int_for_reg` — unconditionally,
  ignoring program point (`src/ir/types_recover.rs:580-591`).

So a single `%rax = 0` at *one* site demotes `rax`'s pointer classification for
*all* uses of `rax` in the function. The test
`const_assignment_demotes_pointer_classification` (`src/ir/types_recover.rs:969`)
locks in exactly this whole-function behavior. `refine_return_type`
(`src/ir/types_recover.rs:284-316`) is a second flow-insensitive patch: it finds
the *textually last* def of the return register and rewrites every return-reg
alias — a heuristic for the value-identity it lacks.

**Nuance (important for the plan).** In the `decbench` path, type recovery is fed
the **value-numbered** `lf` (`decompile_at_py` shadows `lf` at
`src/python_bindings/ir.rs:432-436`, then calls `recover_types_for(&lf, cc)` at
`:466`). Because `value_number` renamed non-zero-version physical regs to
`rax#1`, `rax#2`, … (`src/ir/value_number.rs:143-153`), the demotion and the
union are *partially* value-scoped there — but only by **string encoding**:
version-0 live-ins stay bare `rax` (`src/ir/value_number.rs:145-148`), structural
regs `rbp/rsp/x29` stay bare (`src/ir/value_number.rs:133-138`,`:149`), and the
returned value is force-kept bare (`src/ir/value_number.rs:288-311`) — all of
which collapse multiple SSA values back onto one `TypeMap` key. The pass is still
a non-SSA `HashMap<VReg, _>` union; it merely runs over an LLIR whose register
*strings* were pre-mangled. That is the fragile workaround this design replaces.

### 1.4 Critique (c) — `remap_type_map` cannot map `varN`. **CONFIRMED.**

`remap_type_map` (`src/python_bindings/ir.rs:706-780`) rebuilds a `TypeMap` whose
keys match the post-naming AST by reconstructing only the `argN`/`ret` alias table
from the calling convention (`:715-768`). Its own comment concedes the gap:
"`varN` aliases are assigned by first-appearance order and we can't trivially
recover them here, so those keys survive untouched" (`:713-715`). Any register the
naming pass renamed to `varN` (or a value-tagged `rbx#2`, which matches no alias
at `:773`) keeps its raw key and its recovered type never reaches the renderer.
`merge_slot_sizes` (`:684-700`) is a parallel by-name patch for promoted stack
slots, papering over the same missing identity.

### 1.5 Critique (d) — AST lowering discards SSA value identity. **CONFIRMED.**

`lower(lf, region, name)` (`src/ir/ast.rs:782-790`) takes **no `SsaInfo`**.
`lower_value` maps `Value::Reg(r) => Expr::Reg(r.clone())`
(`src/ir/ast.rs:180-186`); `Expr::Reg(VReg)` (`src/ir/ast.rs:39-40`) carries only
the physical string / temp id — no version. The `region` passed in was computed
from SSA but, as shown in §1.1, encodes only dominance. Thus the only way any
value identity reaches the AST today is the `value_number` **string tag** baked
into the `VReg::Phys` name *before* `lower` runs. Everything downstream —
`copy_prop`, `naming`, `stack_locals`, the renderers — parses or matches those
strings. Value identity is structurally absent from the HLIR.

### 1.6 The resulting seam

```
LLIR ──ssa──▶ SsaInfo(versions)      (only idom consumed by structurer)
  │
  ├─ value_number(lf,ssa,cc) ──▶ LLIR' with reg#version STRINGS  (decbench only)
  │        └ live_in_arg_slots_llir(lf',cc) ──▶ param slot set
  │
  ├─ recover_types_for(lf', cc) ──▶ TypeMap keyed by Phys STRING  (non-SSA union)
  │
  └─ lower(lf', region) ──▶ AST(Expr::Reg = string) ──naming──▶ argN/ret/varN
                                                   │
                        remap_type_map(TypeMap, f) ┘  ← re-derives arg/ret aliases,
                                                         DROPS varN + reg#version keys
                                                   │
                        render_decbench_typed + DEC_PTR_ARGS/DEC_PTRS thread-locals
```

Three lossy string round-trips (value_number encode → naming rename → remap
re-derive) exist because there is no shared value identity. The fixes for (b),
(c), (d) are all the same fix: **give every value a stable id and key types, names,
and AST nodes on it.**

---

## 2. Target design

### 2.1 The value id

```rust
// src/ir/ssa.rs (new public type)
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct SsaValue { pub base: VReg, pub version: u32 }
```

`base` is the existing `VReg` (`Phys`/`Temp`/`Flag`), `version` the SSA version
already computed. `version == 0` keeps its current meaning (live-in / entry-def).
This is exactly the `(base, version)` pair the review asks for — the same pair
`value_number` already reconstructs implicitly via `def_versions`/`use_versions`.

Add query methods so consumers stop re-deriving it:

```rust
impl SsaInfo {
    pub fn def_value(&self, lf: &LlirFunction, at: InstrAddr) -> Option<SsaValue>;
    pub fn use_value(&self, lf: &LlirFunction, at: InstrAddr, ui: usize) -> Option<SsaValue>;
    // phi result / incoming already carry (base, version) in `Phi` (ssa.rs:31-39)
}
```

These are pure lookups over the existing maps + `def_uses`; the alignment
guarantee (use order mirrors `def_uses`) is already relied on by `value_number`
(`src/ir/value_number.rs:189-191`, `:323-327`) and by `ssa::rename`
(`src/ir/ssa.rs:375-380`).

### 2.2 Value-scoped types

Replace the register-keyed map with a value-keyed one:

```rust
pub struct TypeMapV { inner: HashMap<SsaValue, TypeHint> }
```

Every rule in `recover_types` (`src/ir/types_recover.rs:461-594`) re-expressed to
key on the def/use `SsaValue` instead of the raw `VReg`:

- Pointer-from-memory-base, index-unsigned, shift-unsigned, cmp-eq-zero-bool,
  indirect-call-code-pointer: key on the `use_value` of the operand register.
- The `upsert` lattice (`:72-113`) is unchanged — it now merges **per value**, so
  two versions of one register no longer contaminate each other.
- **Fix (b):** the const-demotion becomes per-value. `gets_const` becomes a set of
  `SsaValue` (the def value produced by each `Assign{src:Const}`); demotion only
  clears the pointer bit on *that* value, never on sibling versions. A pointer
  loaded into `rax#3` survives a `rax#5 = 0` elsewhere.
- **Fix the return heuristic:** `refine_return_type`'s "textually last def"
  (`:284-316`) becomes "the `SsaValue`(s) that reach a `Return`" — read directly
  from the value flowing into the return-register at each `Op::Return`, deleting
  the fragile last-def-in-block scan. Same for `value_number`'s kept-bare logic
  (`src/ir/value_number.rs:288-311`).
- Backward pointer propagation and spill-slot propagation
  (`:402-458`, `:209-249`) key on values; a spilled parameter's value and its
  reload value link through the slot, which is strictly more precise than the
  current physical-name match.

### 2.3 Flags and memory (critique (a))

- **Flags — do version them, cheaply.** Extend `is_ssa_reg`
  (`src/ir/ssa.rs:61-63`) to include `VReg::Flag` behind the existing scope so a
  flag def and its consuming branch/`CondAssign`/`Ite` share a value. This gives
  precise bool-vs-int typing per condition and lets `hoist_inline_flag_conds`
  (`src/ir/ast.rs:408`) match on value identity instead of "same flag, no
  intervening read." Low risk: flags are short-lived and rarely merge.
- **Memory — version tokens are NOT required for this layer, and we defer them.**
  Register SSA + a conservative store/call barrier already make the single-use
  address fold sound (`src/ir/copy_prop.rs:78-99`, `:163-183`, and the aliasing
  note at `:375`). We add memory SSA only if/when a pass needs load-store value
  forwarding (e.g. promoting a spill slot to a scalar without the current
  pattern-match). The design keeps room for it: introduce `SsaValue` for a
  synthetic `Mem` base later without disturbing register values. Documenting this
  as an explicit non-goal keeps the phase list small.

### 2.4 One typed HLIR

Give the AST value identity so naming, typing, and rendering share it:

```rust
// src/ir/ast.rs
pub enum Expr { Val(SsaValue), /* … existing variants … */ }
// or additively: Reg { base: VReg, version: u32 }
```

`lower` gains an `ssa: &SsaInfo` parameter and stamps each `Value::Reg` use / op
def with its `SsaValue` (via §2.1 queries). Naming then assigns **one** display
name per `SsaValue` — `arg0`, `ret`, `varN`, `local_k` — into a single
`HashMap<SsaValue, String>`, and `render_decbench_typed` looks up a value's type
by `SsaValue` directly.

Consequences:

- **`remap_type_map` is deleted** (`src/python_bindings/ir.rs:706-780`): the
  renderer no longer needs to reverse-engineer aliases, because the type map and
  the AST are keyed by the same `SsaValue`. The "can't map varN" gap (c)
  disappears by construction — a `varN` *is* some `SsaValue` and its type is found
  under that key.
- **`DEC_PTR_ARGS` / `DEC_PTRS` thread-locals** (`src/ir/ast.rs:2517-2525`,
  populated at `:2257-2289`) become direct per-value lookups: "is this value a
  pointer, and what pointee width?" is answered from the value-keyed `TypeMapV`,
  not a name-string side table rebuilt each render.
- **`merge_slot_sizes`** (`src/python_bindings/ir.rs:684-700`) folds into the
  value map (the promoted slot is a value), removing the by-name second channel.
- `value_number`'s **string mangling is removed**: identity lives in the AST, not
  in `rax#2` names. `live_in_arg_slots_llir` (`src/ir/value_number.rs:76-112`) and
  the reused-temp splitting (`:333-389`) are *kept* but re-expressed on
  `SsaValue`; the temp split becomes "distinct versions are distinct values,"
  which is now free.

End state — one representation:

```
LLIR ──ssa──▶ SsaInfo ──▶ recover_types_valued : HashMap<SsaValue,TypeHint>
  │                                    │
  └─ lower(lf, region, ssa) ──▶ AST(Expr::Val(SsaValue))
                                       │
              naming: HashMap<SsaValue,String>  (arg0/ret/varN/local_k)
                                       │
      render_decbench_typed(f, types_by_value, names_by_value)   ← no remap, no thread-locals
```

---

## 3. Phased migration plan

Each phase is independently shippable, ends with a testable outcome, and keeps
both `cargo test` and the DecBench render path (`decompile_at`/`_range`/`_all`/
`_many`, `style ∈ {"", "c", "decbench"}`) working. Run `cargo test` plus the local
DecBench eval (`type_match` / `GED` / `byte_match`, `NO_COLOR=1`) as the gate on
every phase — types/GED/byte must not regress.

### Phase 1 — `SsaValue` vocabulary (additive, zero wiring)
Add `SsaValue` and the `def_value`/`use_value` query methods (§2.1) to
`src/ir/ssa.rs`. No existing caller changes.
**Outcome:** unit tests that def/use queries return the same `(base, version)`
pairs the current `def_versions`/`use_versions` encode on the `ssa.rs` fixtures
(`single_block…`, `diamond…`, `loop_with_counter…`). `cargo test` count grows;
nothing else moves.

### Phase 2 — value-scoped type recovery (parallel pass + shim)
Add `recover_types_valued(lf, ssa, cc) -> TypeMapV` (§2.2), porting every rule and
**fixing (b)** per value. Keep `recover_types_for` intact for the non-decbench
paths. Add a compatibility projection `TypeMapV -> TypeMap` that emits the current
`reg#version`/bare strings, and switch only the `decbench` callers
(`src/python_bindings/ir.rs:466`, `:513`, `:637`, `:663`, `:867`, `:965`, `:996`)
to `recover_types_valued(&raw_lf, &ssa, cc)` projected through the shim — so
`remap_type_map` and the renderer are untouched.
**Outcome:** new fixture — `rax#3` is a pointer, `rax#5 = 0` elsewhere → the
pointer survives (today's function-global demotion would kill it). DecBench
`type_match` ≥ current (0.891 O0); no output diff on the register/`c` styles
(they still use the old pass). This is the first phase that *changes* behavior,
and only for decbench typing.

### Phase 3 — carry `SsaValue` in the AST (observationally a no-op)
Add `Expr::Val(SsaValue)` (or `version` on `Expr::Reg`), give `lower` the
`ssa: &SsaInfo` arg, and populate identity during lowering (§2.4). Renderers keep
printing today's spelling (bare for v0/structural/kept-bare, `base#v` otherwise)
so output is **byte-identical**. Re-express `copy_prop`'s read-counting and the
temp-split on `SsaValue`. Then **delete `value_number`'s Phys-string rewriting**
(`tag_phys`/`tag_op`/`value_number`, `src/ir/value_number.rs:143-331`); the
decbench path calls `lower(lf, region, ssa)` on the raw LLIR instead of the
mangled one. Keep `live_in_arg_slots_llir` (re-expressed on the raw LLIR/values).
**Outcome:** golden AST/render tests unchanged; DecBench output diff empty; the
`value_number` string tests (`distinct_defs…#1/#2`, `address_chain_reuse…`)
are rewritten as identity assertions. Gate: byte/GED unchanged (this is the
riskiest no-op — see §4).

### Phase 4 — single typed representation; delete the remap
Naming assigns one name per `SsaValue`; type lookups in `render_decbench_typed`
read `TypeMapV` by value. **Delete `remap_type_map`** and `merge_slot_sizes`
(`src/python_bindings/ir.rs:684-780`), and replace `DEC_PTR_ARGS`/`DEC_PTRS`
(`src/ir/ast.rs:2517-2525`) with per-value lookups.
**Outcome:** `varN` and value-tagged locals now render with their recovered types
(critique (c) closed) → `type_match` should rise, especially where pointer `varN`s
were previously untyped; `byte_match` non-regressing. Remove the remap tests.

### Phase 5 — flag versioning (and memory only if needed)
Extend `is_ssa_reg` to `VReg::Flag` (§2.3); point per-condition bool typing and
`hoist_inline_flag_conds` at value identity. Memory SSA remains a documented
non-goal unless a concrete pass (spill→scalar without pattern-match) needs it.
**Outcome:** targeted tests for bool-vs-int on a reused flag; no metric regression.
Ship or stop here.

---

## 4. Risks & interactions

- **`copy_prop` single-use fold (biggest lever, biggest risk).**
  `propagate_copies` (`src/ir/copy_prop.rs:25`) counts reads to find single-use
  values and folds `t=i*4; p=base+t; *p` into `*(base+i*4)`
  (`:25-40`); this drove `byte_match` 0.192→0.349. It currently depends on
  `value_number`'s single-def strings. In **Phase 3** the read-count must key on
  `SsaValue`, and the store/push aliasing barrier (`:78-99`, `:163-183`, `:375`)
  must be preserved exactly — regressing it re-inflates the CFG (GED) and breaks
  recompiled byte parity. This phase is the one to land behind a strict byte/GED
  diff gate.

- **Stack-slot promotion pattern-matches bare `rbp`/`rsp`.**
  `promote_stack_locals_typed` (`src/ir/stack_locals.rs:69`) and the frame-base
  checks in `types_recover` (`is_frame_base`, `:197-203`) match on the bare
  register name — which is precisely why `value_number` keeps structural regs bare
  (`src/ir/value_number.rs:133-138`). When identity moves into the AST (Phase 3),
  structural registers must still render/anchor as bare **or** the promoter must
  match on `SsaValue.base ∈ {rsp,rbp,x29,…}`. Get this wrong and every `local_k`
  disappears. Prefer teaching the promoter to match on `base` so we can drop the
  "keep bare" special-case entirely.

- **`decbench` vs `c` vs register render styles.**
  Only `decbench` runs `value_number` today (`src/python_bindings/ir.rs:432-436`,
  `:615-619`, `:833-837`, `:949-953`); `style=="c"` (`render_c`) and the default
  register/`render_with_types` styles do not. Phase 3's identity must be **inert**
  for the non-decbench styles (they print bare spellings). Note the default
  `types=true` non-decbench path also uses `remap_type_map` via
  `render_with_types` (`:527-529`, `:670-675`, `:1006-1012`) — Phase 4's removal
  must update that path too, not only decbench.

- **Return-value identity.** Both `value_number` kept-bare
  (`src/ir/value_number.rs:288-311`) and `refine_return_type`
  (`src/ir/types_recover.rs:284-316`) reimplement "which value is returned" with
  block-local heuristics. Replacing both with "the `SsaValue` reaching `Return`"
  (§2.2) is a simplification, but the SysV/Win64/AArch64 return-reg alias sets
  (`return_reg_names`, `:251-259`) and the sub-64-bit-narrowing rule must be
  carried over verbatim or `type_match` on return types regresses.

- **`upsert` lattice precedence must hold per value.** The pointer⟩int, wider-
  pointee, unsigned-sticky, bool ordering (`src/ir/types_recover.rs:72-113`) is
  load-bearing for `type_match`. Re-keying to `SsaValue` must not reorder it; port
  it byte-for-byte and keep the existing rule tests (`pointer_beats_int…`,
  `wider_pointee…`, `return_type_narrowed…`).

- **Phi handling in typing.** `recover_types_valued` should unify the types of a
  phi's incoming values into the phi result value (join over the `upsert`
  lattice), using the `Phi.incoming` list already built (`src/ir/ssa.rs:31-39`).
  Skipping this leaves merged values (loop-carried pointers) untyped — a latent
  O2 gap the current non-SSA union accidentally hides by keying on the bare name.

- **O2 reality check.** Per `docs/design/decompiler-refactors.md`, at O2 there are
  no spill slots to type from and the type story is weak for everyone (angr's GED
  explodes too). This layer *enables* an O2 type story (values survive
  optimisation better than physical-name unions) but does not by itself deliver
  it; do not gate the refactor on O2 `type_match`.
