# Register views and the verifier boundary

Two structural problems in the decompiler pipeline, both of the same shape:
knowledge that must have exactly one owner had several, and a stage that must be
pure was not. This documents what the owners are now, why, and what each change
fixed.

## 1. One register-view descriptor

### The problem

A physical register name is a *view* onto a canonical full-width parent: `al`,
`ah`, `ax`, `eax` are windows onto `rax`; `w0` is a window onto `x0`. Three
independent copies of that knowledge existed:

| location | what it knew | how it was wrong |
|----------|--------------|------------------|
| `src/exec/state.rs` | full x86-64 + AArch64 view table (parent, offset, width) with correct partial-write semantics | nothing — this was the good one, but it was private to the emulator |
| `src/ir/ssa.rs::parent64` | 32↔64-bit GP aliasing only | a second hand-written table to keep in sync |
| `src/ir/lift_x86.rs::partial_gp_parent` | 8-/16-bit low views mapped to their **32-bit** parent | wrong parent and wrong mask (below); high-byte registers unsupported |

The disagreement was not theoretical. `partial_write_ops` lifted a sub-register
write as a read-modify-write of the *32-bit* view with a *32-bit* keep mask:

```
mov $0xAA, %al   ==>   eax = (eax & 0xFFFFFF00) | 0xAA
```

Because a 32-bit write zero-extends (and because `ssa.rs` merges `eax` with `rax`
as one value), that clears bits 32..63 of `rax` — bits the instruction must
preserve. Any time `rax` held a 64-bit value (any pointer, any `long`), the
decompilation was wrong. Architecturally:

```
movabs $0x1122334455667788, %rax
mov    $0xAA, %al
; correct:      rax = 0x11223344556677AA
; what we got:  rax = 0x00000000556677AA
```

A second, quieter bug: iced-x86 spells the byte views of the extended registers
`R8L`..`R15L`, while the manuals, GNU as, LLVM, and the emulator's table all say
`r8b`..`r15b`. The lifter emitted `r8l`, which matched no register at all — so
`mov $0xAA,%r8b` wrote nowhere and a read of `r8b` returned zero.

### The design

`src/ir/regview.rs` is the single descriptor. It answers, per architecture:
canonical parent, bit offset, view width, whether a write zero-extends, whether it
preserves the parent's other bits, and the exact `keep`/`value` masks. Consumers:

* `exec/state.rs` builds its register-file slot map from `regview::views(arch)` and
  keeps only what is genuinely execution-local (the dense cell index). `RegArch` is
  now a re-export of `regview::Arch` — one architecture enum, not two.
* `lift_x86.rs` lifts a partial write as a read-modify-write of the **canonical
  64-bit parent** using the descriptor's masks, and supports the legacy high bytes
  (`ah`..`dh`, bit offset 8) via the descriptor's offset. `reg_name` normalises
  through `regview::canonical_name`.
* `ssa.rs::parent64` delegates to `regview::ssa_parent`, which encodes the merge
  *rule* (only total writes — full-width and zero-extending views — may share one
  SSA value; a bit-preserving view depends on the parent's previous value, so
  merging it would claim a definition that does not exist).

### How it is verified

`tests/register_view_semantics.rs` lifts real machine code, runs it on the concrete
machine, and asserts the resulting 64-bit parent. That is the loop that was
missing: the emulator's own unit tests proved the register file correct, but
nothing proved the *lifter* produced ops that mean what the architecture says.
Cases: parent write then narrow reads; `al`/`ax`/`ah`/`r8b` writes preserving the
rest of the parent (including bits 32..63); `eax` zeroing the upper half; a
register-sourced partial write; family independence; AArch64 `w0` zero-extending
into `x0`. Plus `regview`'s own mask/table invariants (keep ∪ value covers the
parent, keep ∩ value is empty, every parent is itself a full-width view).

## 2. The verifier boundary: prepare, then render

### The problem

`render_decbench_typed` mutated the function while printing it: it gave bare
returns their ABI return register, coalesced parameter spill slots, and
copy-propagated. Those change definitions, uses, and value identities — they are
pipeline operations, not formatting.

The cost was concrete. A def-before-use checker was written, produced false
positives on correct functions (`rt_u8`), and was reverted — because the AST it
checked was not the AST that got printed. The renderer emitted a string, so there
was no post-fold AST to check at all.

### The design

* `ast::prepare_for_decbench(&Function) -> Function` — the named transformation
  (bare-return ABI register → parameter-spill coalescing → copy-chain folding),
  tested directly: each step is asserted to change the AST, and the renderer is
  asserted *not* to make that change on its own. It is idempotent, and rendering
  the same prepared AST twice is byte-identical and leaves it unchanged.
* `render_decbench_typed` / `render_decbench` — formatting only.
* `ir::verify_defs::check(&Function)` — definition-before-use verification of the
  prepared AST, i.e. of exactly what will be printed.

Two rules, both chosen to have no false positives:

* `NeverDefined` — read somewhere, assigned nowhere. No control flow can rescue
  this. Always checked.
* `UsedBeforeDefinition` — flow-sensitive and deliberately *may*-defined: a
  definition in one arm of an `if` satisfies a use at the join, a loop body is
  checked with its own definitions pre-seeded (a later iteration may have produced
  the value), and a `call` defines the return register. Skipped entirely for
  functions containing `goto`/labels, whose flow this walk does not model — better
  to check less than to guess.

Only names the decompiler invents and therefore owes a definition for are checked:
`ret`, `varN`, `local_*`, `stack_*`, and surviving lifter temporaries. Parameters
are defined by the ABI; raw machine registers are live-in state.

### How violations are gated

The pipeline emits each violation as a `// glaurung-verify:` comment ahead of the
code. Comments, so the compiled C is byte-identical for recompilation — and the
structural lane records them per function in `structural_baseline.json`, where the
existing ratchet applies: a known violation stays visible, a **new** one fails the
gate, and a resolved one forces a baseline refresh. Reporting rather than erroring
is deliberate: a violation means that function's decompilation is untrustworthy,
not that an analyst's whole run should abort.

This routes verification through rendered comments because the lift→structure→
passes→prepare sequence is currently duplicated across four `python_bindings/ir.rs`
entry points, so no Rust test can build a real prepared AST from a fixture binary.
Factoring that pipeline into one reusable core is the follow-up that would let the
corpus gate live in Rust directly.

## 3. What is left, classified by demonstrated root cause

The directive asked for three representative failures to be classified from pass
dumps, and warned against forcing them into one architectural story. They do not
share one. (`mul_widen`, named in the directive, already passes — the earlier
sub-register canonicalisation fixed it.) Measured on the fingerprinted toolchain,
gcc `-O0`:

**`deposit_byte1` — a high-byte partial write that never reaches the parent.**
Source: `v = (v & 0xFFFF00FFu) | ((b & 0xFFu) << 8)`. gcc emits `xor %ah,%ah`
(clear bits 8..15). The lifted body shows the loss directly:

```
%ret = %local_4;      // eax = v
%var0 = 0;            // <- `xor %ah,%ah` became a write to an unrelated name
%var1 = %ret;         // edx = eax   ... reading the UNCLEARED value
```

Parent `rax`, view `ah`, offset 8, width 8, bit-preserving. The corruption is in
the LIFT, not in a later pass — the `plain` render already shows it. Two gaps:
partial-view writes are modelled only in the `mov` path (`partial_write_ops`), not
in the generic ALU path; and partial-view *reads* are not modelled at all, so `ah`
is an independent SSA name rather than `Extract(rax, 8, 8)`.

**`rotr32` — not a register-view problem at all.** `n &= 31u` on a spilled
parameter compiles to a memory read-modify-write, `andl $0x1f,-0x18(%rbp)`. Promote
rewrites the store address to the slot's register name; parameter coalescing then
renames that slot to `arg1`; and the decbench renderer only turns
`Store{addr: Reg(name)}` into `name = src` when the name still looks like a
promoted local. So it emits a store *through* a non-pointer parameter:

```
*(int *)(arg1) = (arg1 & 31);     // writes through a value, not a pointer
```

Root cause: the "this store defines a slot" fact is lost when coalescing renames
the slot. It needs to be carried explicitly, not re-derived from the name — and it
is shared with any `-O0` in-place arithmetic on a spilled scalar.

**`sum_arg7` — a stack-passed argument that is never defined.** The 7th SysV
integer argument arrives at `[rbp+16]`. It is promoted to `stack_0`, which the
signature does not mention and nothing assigns:

```
long sum_arg7(long arg0, ..., long arg5) {   // arity 6, should be 7
    int stack_0;                             // never assigned
    ret = ((((stack_0 << 3) - stack_0) + ...
```

The def-before-use verifier from §2 flags exactly this (`stack_0 is read but never
defined`) — independent confirmation that it is a value-model hole, not a naming
cosmetic. Root cause: stack-passed arguments are not part of the recovered
parameter set.

Three causes, three fixes, in ascending order of blast radius: the ALU partial-write
path (local to `lift_x86`), the slot-store marking (promote/coalesce/render
contract), and stack arguments (ABI descriptor + signature arity).

### Fixed: the ALU partial-write path

`partial_alu_ops` lifts `op view, src` as a read-modify-write of the canonical
parent, with the view read as `(parent >> offset) & mask` — including for a
partial-view *source*, so `add %ah,%al` contributes `ah`'s byte rather than the
whole parent. When the source names the destination view (`xor %ah,%ah`) the
accumulator is reused for both operands, so constant folding still collapses the
idiom to zero. `deposit_byte1` now renders the clear it always meant:

```
ret = ((local_4 & -0xff01) | ((0 & 255) << 8));   // rax &= ~0xFF00
```

### Fixed: the slot-store marking

`slot_stores_to_assigns` converts a slot's own stores to assignments *before*
coalescing renames the slot, while the name still identifies it as a slot. Doing it
before the rename is what makes it unambiguous — afterwards, `Store{addr: Reg(arg0)}`
could equally be a genuine `*arg0 = v`, and converting that would turn a memory
write into a local assignment. `rotr32` now renders `arg1 = (arg1 & 31);` instead of
writing through a non-pointer parameter, and the `02_integer_widths` gcc-`-O0` lane
goes 22/24 to 24/24.

### Fixed: stack arguments

`stack_locals::stack_arg_layout` states where each ABI puts the arguments that do
not fit in registers (SysV AMD64: six registers, then `[rbp+16]` upward; AArch64:
eight, then `[x29+16]`), so a positive frame-pointer offset at or above that slot is
named `argN` instead of inventing a `stack_N` local the function never assigns. The
naming pass had to stop rewriting those to `varN`. `06_calling_conventions:gcc:O0`
went 8/17 to 13/17 (sum_arg7..10, sum_mixed_widths), and the verifier's
`stack_N is read but never defined` entries disappeared — 9 violations in 6 functions
down to 4 in 3.

Win64 and ARM32 deliberately keep `stack_N`: their layouts differ (a 32-byte shadow
space; a different frame record), no fixture exercises them, and guessing at an ABI
is how a decompiler invents a parameter that does not exist.

## 4. The next slice: a call defines a value

The remaining `06` failures — `fib`, `fact_mod`, `forward_sum6`,
`tailcall_to_sum4` — are one root cause, and it is not naming. `use_def::def_uses`
reports that `Op::Call` defines NOTHING and uses nothing, so the value model believes
the return register still holds whatever it held before the call. `fib` renders:

```
var2 = (arg0 - 1);
fib_localalias();      // the argument is not passed
var4 = var2;           // ... and the RESULT is not taken: this is the argument
```

Both halves have to land together, or the output gets worse rather than better:

1. **the value model** must treat a call as defining the return register (a
   CC-aware extension of `def_uses`, since the register depends on the ABI and
   `def_uses` is deliberately CC-free), so a post-call read is a NEW value rather
   than the stale pre-call one;
2. **the AST** must be able to say which value that is. `Stmt::Call` currently has
   no destination, so there is nowhere to put it. Adding `dst: Option<VReg>` is the
   direct answer but touches ~85 match sites across 15 files, and this codebase has
   already had one fixup commit for exactly that class of change (`b3bbac7`, a
   missed `Stmt::Store` size arm). It wants its own pass with the gate green
   before and after — not a corner of a larger change.

Landing (1) alone would make the value model honest and the output visibly wrong
(the verifier would start reporting a read-before-definition where the call result
should be), which is worse for a user than the current quiet wrongness.

**Half 2 has landed.** `Stmt::Call { dst: Option<VReg> }`,
`call_args::attribute_call_results` filling it from the ABI, the naming pass renaming
it and reporting it as a write, both renderers printing the assignment, and
`verify_defs` using the recorded destination. Measured verdict-neutral (189/224/74
unchanged; every structural dimension unchanged). It cost 28 compiler-flagged sites,
not the 85 feared — most matches already used `..`.

**What doing it taught us about half 1.** Attaching the destination at the AST level
is not sufficient, and the reason is instructive: `value_number` renames registers
while rewriting the **LLIR**, and the AST is lowered from its output. `Op::Call` has
no destination, so the rename cannot reach it; `attribute_call_results` therefore
writes the *raw* ABI register name, which is not the name the renamed post-call read
carries. The two never meet. The same mechanism explains why the call above still
passes no arguments: `value_number` has already renamed the argument-register setup
(`rdi = x` became `var2 = x`) by the time `reconstruct_args` looks for it, because
`def_uses(Op::Call)` reports no uses, so nothing marks those registers as live into
the call.

So half 1 is really: **`Op::Call` needs the destination too**, at the LLIR level, where
the value model can rename it — plus the ABI argument registers as uses. That is ~60
references across 19 files, and unlike `Stmt::Call` it reaches `src/symbolic/` and
`src/analysis/` — subsystems this fixture gate does not cover. It needs its own
session with its own verification story (the symbolic ioctl tests, the Unicorn
differential oracle under `--features dev-oracle`), not a corner of another change.

`fib_localalias` is a separate, smaller defect: the self-call resolves to a local
alias symbol rather than to `fib`, so the emitted C calls an undeclared function.

## 4. Why the gate had to be repaired first

Neither change above can be trusted without a gate that actually runs. Two things
were wrong with it:

* the CI matrix job never executed — `uv run maturin develop` failed with
  `Failed to spawn: maturin`, because `[build-system].requires` provisions the PEP
  517 backend, not a runnable command. It is now installed explicitly and its
  presence asserted before use;
* the baseline was not reproducible anywhere but the machine that wrote it. Both
  the fixture compiler and the compiler that rebuilds our decompiled C decide
  verdicts, so the gate now performs every compile inside a digest-pinned image and
  records the toolchain fingerprint in the baseline, asserting it before comparing
  anything. That also provisions clang++'s C++ runtime, which closes the hole where
  the C++ fixture's clang lanes were recorded `env-missing` locally, silently ran on
  CI, and had their results excluded from every comparison.

See `tests/decompiler_fixtures/README.md` for the operational details.
