# x86 flags: a producer/consumer protocol

## Why this document exists

The lifter currently has seventeen flag definitions in total. `add`, `sub`, `and`,
`or`, `xor`, `inc`, `dec`, the shifts and `imul` define **none**. At `-O0` that
mostly hides, because gcc emits an explicit `cmp` or `test` before every branch. At
`-O2`, arithmetic-then-branch is the dominant idiom, and a branch then reads either a
flag nothing defined or — worse — one left over from a comparison outside the loop,
which never updates.

Measured consequence, `14_flag_effects:dec_loop` at `-O2`, a plain
`for (int i = n; i > 0; i--)`:

```c
zf = (arg0 == 0);            // `test` defines Z...
if (sle) { return ret; }     // ...but `jle` reads Sle, which NOTHING defines
L_1180: ;
var1 = (var1 - 2);           // `sub` sets ZF; we define nothing
if ((~zf)) { goto L_1180; }  // stale zf from OUTSIDE the loop, and `~` of a
                             // 0/1 flag is always true
```

That is an infinite loop. The differential caught it as "did not terminate within
5.0s on an input the original returned on" — no metric distinguishes an infinite loop
from a slow one.

## The mistake to avoid

The obvious reading of that enumeration is "`cmp` is complete, make the others like
`cmp`". That is wrong twice over, and following it would push the defect into six
more places:

* `cmp` does **not** define `OF` at all.
* `cmp` writes *derived predicates* — `Ule`, `Slt`, `Sle` — in place of architectural
  flags. Those are conditions, not flags.

The enumeration is evidence of a **representation** gap, not a coverage gap.

## The model

**Producers write architectural flags only: `{CF, PF, AF, ZF, SF, OF}`.**
`Ule`, `Slt`, `Sle` stop existing as producer-written state.

**Consumers derive conditions through one shared mapping.** Every `Jcc`, `SETcc` and
`CMOVcc` goes through it, so there is exactly one place where a condition's meaning
is written down.

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

Eight families, each with a negated sibling — the sixteen `Jcc` conditions. Note that
three of them are *composite*, and that composition is exactly what the current code
freezes into a producer-written pseudo-flag.

**Every flag effect is one of three states, stated explicitly:**

```
Defined(expr)   the instruction determines this flag; here is the expression
Preserved       the instruction leaves the previous value intact, on purpose
Undefined       the architecture does not define it; reading it is a bug
```

`Undefined` **must not** be represented by leaving the old definition in place. That
silent retention is the measured failure above: `if (sle)` reading a flag a `cmp`
outside the loop had set. An undefined flag has to poison, so that a consumer reading
it is detectable rather than plausible.

## Per-family semantics

Audit against Intel SDM Volume 2; these are the cases that bite.

| family | CF | OF | ZF/SF/PF | AF | note |
|---|---|---|---|---|---|
| `add` `sub` `cmp` | defined | defined | defined | defined | the general case |
| `and` `or` `xor` `test` | **cleared** | **cleared** | defined | undefined | logic ops zero CF/OF |
| `inc` `dec` | **preserved** | defined | defined | defined | the reason they exist as separate opcodes |
| `neg` | `src != 0` | defined | defined | defined | not merely ZF/SF |
| `imul` | defined | defined | **undefined** | undefined | only CF/OF are meaningful |
| `bt` | defined | **undefined** | **undefined** | undefined | other flags undefined, *not* preserved |
| shifts / rotates | defined | count-sensitive | defined | undefined | see below |
| `adc` `sbb` | defined | defined | defined | defined | **also CONSUME CF as an input** |

Shifts are count-sensitive and are the easiest to get wrong:

* count `0` — **all** flags preserved, including ZF/SF. The instruction is a no-op.
* count `1` — `OF` is defined.
* count `> 1` — `OF` is **undefined**.

`adc`/`sbb` matter because they make the protocol bidirectional: a producer of flags
is also a consumer of one. A model that only pushes flags forward cannot express them.

## Implementation shape

Prefer a lazy, VEX-style flag definition over eagerly expanding six flags at every
arithmetic instruction:

```
FlagDef { op, lhs, rhs, result, width, prior_flags }
```

Materialize only the flags a consumer actually demands. Most flags are never read, and
eager expansion would put six dead assignments after every `add` — which the emitted C
would then have to carry, and which the graph-edit-distance metric charges for.

`width` is explicit because flag semantics are width-dependent (`SF` is the top bit of
the *operand size*, not of a 64-bit register), and `prior_flags` is explicit because
`adc`/`sbb`/`inc`/`dec` and shift-count-0 all need what came before.

## Verifier

The failure mode in every case here was a **silent** stale or absent read. That is
findable cheaply:

> a consumer reads flag `X`, and no definition of `X` dominates it — or the nearest
> definition marks it `Undefined`.

`src/ir/structure_accounting.rs` is precedent that this class of "the IR does not say
what the code claims" check pays for itself: it found the `bsearch_i` join defect that
GED scored perfectly.

## Prior art

* Ghidra centralizes these as SLEIGH macros —
  `Ghidra/Processors/x86/data/languages/ia.sinc`
* Remill splits producers and consumers exactly this way —
  `lib/Arch/X86/Semantics/BINARY.cpp` for arithmetic flag helpers,
  `lib/Arch/X86/Semantics/COND_BR.cpp` for the branch predicates
* Binary Ninja documents the producer/consumer framing explicitly —
  <https://docs.binary.ninja/dev/flags.html>
* Intel SDM Volume 2 is the authority for the per-instruction tables above

## Test obligations

RED first, before any implementation:

* `dec_loop` — currently an infinite loop
* all sixteen `Jcc` condition families
* `SETcc` and `CMOVcc`, which share the consumer mapping
* representative `ADC`/`SBB` consumption
* producers at 8/16/32/64-bit widths
* shift counts `0`, `1`, and `> 1`

Use **handwritten assembly** wherever a compiler would select a different idiom and
silently delete the case under test — a fixture that no longer contains the shape it
was written for is worse than no fixture, because it reads as coverage.

Keep every C execution input demonstrably **UB-free**. Two false failures have already
been shipped from unbounded undefined behaviour — `fp_div`'s left shift of a negative
value, and `add_then_negative`'s `INT_MIN + INT_MIN`. A differential that can fail for
reasons unrelated to the decompilation is not a gate.

## Stop condition

Do not merge if either holds:

* any individual instruction lifter still writes `Ule`, `Slt` or `Sle`; or
* an undefined flag is represented by leaving stale state untouched.
