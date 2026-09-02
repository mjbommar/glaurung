# x86 flags: a producer/consumer protocol

> **Kind:** architecture · **Status:** maintained

EFLAGS is the one part of the x86 machine model where the obvious design is
wrong, and wrong in a way that produces plausible C. This is the protocol the
lifter implements, the mistake it exists to prevent, and where each piece lives.

Where it lives:

| piece | file |
|---|---|
| the ALU emitters that define EFLAGS, and the width helpers | `src/ir/lift_x86/flags.rs` |
| CF/OF for the multiplies, which need a wider intermediate than the result | `src/ir/lift_x86/mul_flags.rs` |
| the sixteen `cc` families and their flag expressions | `src/ir/lift_x86/conditions.rs` |
| `BT`/`BTS`/`BTR`/`BTC`, `TZCNT`, `POPCNT` | `src/ir/lift_x86/bit_ops.rs` |
| `DIV`/`IDIV`, `XADD`, `CMPXCHG`, the wide forms | `src/ir/lift_x86/wide_arith.rs` |
| `Flag`, `VReg::FlagValue`, `Op::Undef` | `src/ir/types.rs` |
| whole-function dead-predicate removal | `src/ir/dce.rs` |
| the executable stop condition | `src/ir/lift_x86.rs`, test `no_lifter_writes_a_derived_predicate_as_a_flag` |

---

## 1. The model

**Producers write architectural flags only: `{CF, PF, AF, ZF, SF, OF}`.**

**Consumers derive conditions through one shared mapping.** Every `Jcc`, `SETcc`
and `CMOVcc` goes through `conditions::materialize_condition`, so there is
exactly one place where a condition's meaning is written down. x86 spells most
conditions two or three interchangeable ways (`jz`/`je`, `jnae`/`jb`/`jc`), and
the negative forms are recorded as an `inverted` flag on the positive family
rather than as sixteen separate cases — which is what keeps the lowering to
eight arms.

| suffix | condition | derived from |
|---|---|---|
| `o` / `no` | overflow | `OF` |
| `b` `c` `nae` / `ae` `nb` `nc` | unsigned below | `CF` |
| `e` `z` / `ne` `nz` | equal | `ZF` |
| `be` `na` / `a` `nbe` | unsigned below-or-equal | `CF \| ZF` |
| `s` / `ns` | sign | `SF` |
| `p` `pe` / `np` `po` | parity | `PF` |
| `l` `nge` / `ge` `nl` | signed less | `SF != OF` |
| `le` `ng` / `g` `nle` | signed less-or-equal | `ZF \| (SF != OF)` |

Eight families, each with a negated sibling — the sixteen `Jcc` conditions.
Three of them are **composite**, and that composition is the whole point of the
protocol.

**Every flag effect is one of three states, stated explicitly:**

```
Defined(expr)   the instruction determines this flag; here is the expression
Preserved       the instruction leaves the previous value intact, on purpose
Undefined       the architecture does not define it; reading it is a bug
```

`Undefined` **must not** be represented by leaving the old definition in place.
An undefined flag has to poison, so that a consumer reading it is detectable
rather than plausible.

---

## 2. The mistake to avoid

At one point the lifter had seventeen flag definitions in total, and `add`,
`sub`, `and`, `or`, `xor`, `inc`, `dec`, the shifts and `imul` defined **none**.
At `-O0` that mostly hid, because gcc emits an explicit `cmp` or `test` before
every branch. At `-O2`, arithmetic-then-branch is the dominant idiom, and a
branch then read either a flag nothing defined or — worse — one left over from a
comparison outside the loop, which never updated. A plain
`for (int i = n; i > 0; i--)` recovered as an infinite loop: `sub` set ZF and we
defined nothing, so the latch read a stale `zf` from outside the loop, and `~` of
a 0/1 flag is always true. The execution differential could only report "did not
terminate within 5.0 s"; no metric distinguishes an infinite loop from a slow
one.

**The obvious reading of that enumeration is "`cmp` is complete, make the others
like `cmp`". That is wrong twice over**, and following it would have pushed the
defect into six more places:

- `cmp` did **not** define `OF` at all;
- `cmp` wrote *derived predicates* — `Ule`, `Slt`, `Sle` — in place of
  architectural flags. Those are **conditions, not flags**.

A producer that writes a condition has frozen one consumer's interpretation into
its own output, so every other consumer wanting a different composition of the
same underlying flags is stuck reading a predicate somebody else chose. That is
why `test` broke: it defined ZF and SF honestly, and a following `jle` wanted
`ZF | (SF != OF)` and found only a pre-baked `Sle` left by whatever ran before
it. Making `test` also write `Sle` would have papered over that instruction and
left the shape intact.

**The enumeration was evidence of a representation gap, not a coverage gap.**

---

## 3. Per-family semantics

Audited against Intel SDM Volume 2. These are the cases that bite.

| family | CF | OF | ZF/SF/PF | AF | note |
|---|---|---|---|---|---|
| `add` `sub` `cmp` | defined | defined | defined | defined | the general case |
| `and` `or` `xor` `test` | **cleared** | **cleared** | defined | undefined | logic ops zero CF/OF |
| `inc` `dec` | **preserved** | defined | defined | defined | the reason they exist as separate opcodes |
| `neg` | `src != 0` | defined | defined | defined | not merely ZF/SF |
| `imul` | defined | defined | **undefined** | undefined | only CF/OF are meaningful |
| `bt` | defined | **undefined** | **undefined** | undefined | other flags undefined, *not* preserved |
| shifts | defined | count-sensitive | defined | undefined | see below |
| rotates | defined | count-sensitive | **preserved** | **preserved** | only CF/OF change |
| `adc` `sbb` | defined | defined | defined | defined | **also CONSUME CF as an input** |

Shifts are count-sensitive and are the easiest to get wrong:

- count `0` — **all** flags preserved, including ZF/SF. The instruction is a no-op.
- count `1` — `OF` is defined.
- count `> 1` — `OF` is **undefined**.

`adc`/`sbb` matter because they make the protocol bidirectional: a producer of
flags is also a consumer of one. A model that only pushes flags forward cannot
express them.

The multiplies are their own module for a reason worth stating. A multiply's
overflow predicate is not a property of the result — it is a property of a
product **wider** than the result, which the architectural write throws away.
Reconstructing it afterwards is impossible for the two-operand form, whose
destination is one of the multiplicands, so the wide product is snapshotted
before the result is written and turned into flags after. That two-step shape is
why `mul_flags.rs` exists. And the reader of OF after a multiply is an overflow
check: `seto` / `jo` after `imul` is how Rust spells `overflowing_mul` /
`checked_mul` / `saturating_mul`, and how Clang range-checks an allocation byte
count. While those flags were poisoned, the decompiler showed the analyst a
program in which the check was not there.

---

## 4. The protocol as implemented

The implementation differs from a lazy, demand-driven flag model in one
deliberate first-step choice: it **eagerly emits the demanded architectural
effects** and relies on whole-AST dead-predicate elimination to remove what
nobody reads. That keeps the representation explicit while making the
undefined-state boundary testable now. Concretely:

- **`VReg::FlagValue { flag, version }`** (`src/ir/types.rs:120`) gives every
  architectural flag definition its own SSA identity, phis included. This is the
  piece that makes "a definition of `ZF`" a value rather than a name.
- **`Op::Undef { dst, reason }`** (`src/ir/types.rs:297`) replaces stale state,
  for architectural undefinedness *and* for a defined effect whose expression is
  not yet modelled. It carries a human reason, so a poisoned flag says why.
- **The verifier reports a live undefined value** (`src/ir/verify.rs`,
  `VerifyError::ExplicitUndef`), and the interpreter halts with
  `Halt::UndefinedValue` (`src/exec/helpers.rs`) rather than fabricating a
  plausible result.
- **All sixteen `Jcc`, `SETcc` and `CMOVcc` families share
  `materialize_condition`.**
- **ADD/SUB/CMP/logic/TEST/NEG/INC/DEC** have exact ZF/SF and exact CF/OF.
- **IMUL/MUL/BT/DIV/IDIV, ADC/SBB, shifts, XADD, CMPXCHG and rotates** all
  replace or intentionally preserve every affected flag. ADC/SBB consume the
  prior CF before replacing their outputs. Variable-count shifts and rotates fail
  closed where a guarded flag write is still required.
- **Dead-predicate removal is whole-function and fixed-point**
  (`dce::prune_overwritten_flags` per definition, then `dce::prune_dead_flags`
  per name), so a loop-body definition used by its `do…while` latch is retained.

### What is still poison, and how to see it

`Op::Undef` is used for two different things, and the reason string separates
them: `"… architecturally undefined"` is the architecture's own answer, while
`"… but their exact low-bit expressions are not modelled"` is our debt. PF and AF
on the arithmetic families are the second kind; so is IMUL's CF/OF at a width
with no representable wide product. The current list is:

```bash
rg -n 'append_undef_flags\(|undef_flag\(' src/ir/lift_x86.rs src/ir/lift_x86/*.rs
```

This is **visible** technical debt rather than silent stale state, which is the
property the protocol was built to guarantee. Each poison definition can be
replaced by an exact expression incrementally without changing the
producer/consumer contract.

---

## 5. The stop condition, made executable

Do not merge a change to this area if either holds:

- any individual instruction lifter still writes `Ule`, `Slt` or `Sle`; or
- an undefined flag is represented by leaving stale state untouched.

The first clause is a test, not a convention.
`src/ir/lift_x86.rs::no_lifter_writes_a_derived_predicate_as_a_flag` lifts a
table of flag-producing encodings (`add`, `sub`, `cmp`, `test`, `neg`, `inc`,
the logic ops, the shifts, `imul`, the `bt` family, `tzcnt`, `popcnt`, `rcr`,
`xadd`, `cmpxchg`, the rotates), asks `use_def::def_uses` what each defines, and
fails with the offending assembly named if any of them defines a derived
predicate.

The scope of that guarantee is exactly x86. The shared `Flag` enum
(`src/ir/types.rs:71`) **still contains `Ule`, `Slt` and `Sle`**, and the ARM
lifters (`src/ir/lift_arm32/flags.rs`, `src/ir/lift_arm64/flags.rs`) still write
them. Extending the protocol to ARM is open work, and this document's rules are
what it should be held to.

`src/ir/structure_accounting.rs` is the precedent that this class of check — "the
IR does not say what the code claims" — pays for itself.

---

## 6. Test obligations for a change here

RED first, before any implementation:

- all sixteen `Jcc` condition families;
- `SETcc` and `CMOVcc`, which share the consumer mapping;
- representative `ADC`/`SBB` consumption;
- producers at 8/16/32/64-bit widths;
- shift counts `0`, `1`, and `> 1`.

Use **handwritten assembly** wherever a compiler would select a different idiom
and silently delete the case under test. A fixture that no longer contains the
shape it was written for is worse than no fixture, because it reads as coverage.

Keep every C execution input demonstrably **UB-free**. Two false failures have
been shipped from unbounded undefined behaviour — a left shift of a negative
value, and `INT_MIN + INT_MIN`. A differential that can fail for reasons
unrelated to the decompilation is not a gate.

Two failure modes are worth naming because they were found the expensive way,
and both are *downstream* of lifting:

- **Condition polarity.** The AST layer matches conditions structurally on
  `Stmt::If { cond: Expr::Reg(flag) }` and `Expr::Un { op: Not, src: Reg(flag) }`
  to hoist a `flag = <Cmp>` assignment into the `if` and decide polarity. A
  composite condition arrives as a `VReg::Temp` rather than a `VReg::Flag`, so
  that matching does not fire and polarity falls through to a path that assumed a
  bare flag. Every function that regressed on the first attempt at this protocol
  was a polarity function; algebraically correct derivations are not sufficient.
- **Rendering.** With `of = slt ^ sf`, the consumer's `sf != of` is
  `sf XOR (slt XOR sf)` = `slt`, so `a != (b ^ a) -> b` collapses it with no
  knowledge of `cmp` at all. But `const_fold.rs` works on the AST, where the
  flags are separate *statements* and both operands are `Expr::Reg`, so the
  identity cannot see `of`'s definition. Fold at LLIR/SSA level — where
  `of#1 = Xor(slt#1, sf#1)` and its consumer are both in view — or inline the
  single-use flag definition into the condition first.

Verify with the fixture matrix **and** a GED measurement. A correctness win
traded for an unmeasured output-quality loss is how this work stalled once
already; see
[`decompiler-pipeline.md` §7.3](decompiler-pipeline.md#73-the-cautionary-datum).

---

## Prior art

- Ghidra centralizes these as SLEIGH macros —
  `Ghidra/Processors/x86/data/languages/ia.sinc`
- Remill splits producers and consumers exactly this way —
  `lib/Arch/X86/Semantics/BINARY.cpp` for arithmetic flag helpers,
  `lib/Arch/X86/Semantics/COND_BR.cpp` for the branch predicates
- Binary Ninja documents the producer/consumer framing explicitly —
  <https://docs.binary.ninja/dev/flags.html>
- Intel SDM Volume 2 is the authority for the per-instruction tables above

## See also

- [`decompiler-pipeline.md`](decompiler-pipeline.md) — where the lifter sits and
  what the pipeline guarantees around it.
- [`register-model.md`](register-model.md) — the same ownership argument applied
  to register views, and the width helpers these emitters call.
