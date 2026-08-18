# Decompiler roadmap — execution diary, 2026-08-18

Continues [the 2026-08-16 diary](decompiler-roadmap-diary-2026-08-16.md).
Entry numbering is continuous across files; the roadmap cites entries by number.

## Entry 70 — 8.6% of the tree is never compiled by the command we call the gate

`CLAUDE.md` has warned for days that plain `cargo test` skips
`src/python_bindings/` and that a green result over code it never built is the
worst kind. The same trap is an order of magnitude larger one directory over,
and nobody had looked.

`src/lib.rs:65` is `#[cfg(feature = "symbolic")]`, and `symbolic` is in neither
`default = ["triage-core"]` nor
`python-ext = ["pyo3", "pyo3/extension-module", "exec"]`.

I proved it rather than reading the manifest, because reading the manifest is
what everyone had already done. Appending `this is not valid rust @@@` to
`src/symbolic/expr.rs`:

```
cargo build --features python-ext   ->  0 errors
cargo build --features symbolic     ->  2 errors
```

**21 files, 14,649 product LOC — 8.6% of a 170,474-line tree — that
`cargo test --features python-ext` does not compile.**

### What was hiding in there

- **All three SMT solver backends had not compiled for seventeen days.**
  `b03d5057` (2026-07-31) added `BinOp::LogicalAnd` and `BinOp::LogicalOr`,
  updated `symbolic/expr.rs`, and updated no backend. `axeyum_backend`,
  `z3_backend` and `bitwuzla_backend` all carried the same ten-arm match.
- **`triage-parsers-extra` had been broken for 350 days.**
- **A fourth copy of the same E0004** in `examples/axeyum_bench_primitives.rs`,
  which none of us knew about and which only `--all-targets` finds.
- **`symbolic/explore.rs` set `product_max_loc` for this entire refactor
  program** — the measure the program is judged by — while being invisible to
  every command in CLAUDE.md's build/test block.

### I was wrong about why nobody noticed, and the truth is worse

I reported that no script runs the solver features. In fact
`scripts/lint-rust.sh:14` runs `cargo clippy --all-targets --all-features --
-D warnings`, which would have caught **every one** of these. Two things
defeated it:

1. `--all-features` turns on `solver-bitwuzla`, whose `build.rs` **panicked**
   when Bitwuzla was absent — so the script died inside the build script before
   clippy saw a line, on every machine without Bitwuzla, which is every machine.
2. **Nothing calls it.** Nor `scripts/harden.sh`. And no GitHub workflow runs
   cargo at all — CI builds wheels through maturin. The only Rust gate in the
   repository was `decbench-local-gate.sh` lane 1: one configuration,
   `--lib --tests`, which is also why the broken examples were invisible.

So the repository had a lint that would have caught this, and three independent
reasons it never ran. That is a more uncomfortable finding than "there was no
lint", and it generalises: **a gate that is not called is worse than a missing
gate, because its existence is mistaken for coverage.**

### The fix, and mutation-testing the gate itself

`scripts/feature-build-gate.sh` — 11 `cargo check --all-targets` lanes, 4m31s
warm, exit 1 on any failure, wired into `decbench-local-gate.sh` as lane 1a and
into a new GitHub workflow.

A gate is a claim, so it gets tested like one. Reverting the `translate.rs` fix
makes lanes 5, 6, 10 and 11 fail and the script exit **1**; restoring it exits
**0**. `build.rs` gains `GLAURUNG_BITWUZLA_TYPECHECK_ONLY=1` so `cargo check`
can type-check the bitwuzla backend without the library present — which also
revives the two lint scripts.

The feature coverage table, previously unenumerated anywhere:

| feature | `#[cfg]` sites | gated before | now |
|---|---:|---|---|
| `python-ext` | 277 | decbench lane 1, CI wheels | lane 2 |
| `solver-axeyum` | 62 | **none** | lane 5 — broken 17d |
| `solver-z3` | 56 | **none** | lane 9 — broken 17d |
| `solver-bitwuzla` | 31 | **none**, unbuildable | lane 7, type-check only |
| `triage-parsers-extra` | 4 | **none** | lane 8 — broken 350d |
| `symbolic` | 2 | **none** | lane 4 |
| `dev-oracle` | 1 | **none** | lane 11 |
| `triage-core`/`-heuristics`/`-containers` | **0** | n/a | vestigial — gate no code at all |

### The semantics question, which was the real work

`unreachable!()` was the tempting arm and would have been a panic. Two `Expr`
types share one `BinOp`: the decompiler AST (where `ir/guard_chain.rs`
synthesises `&&`/`||`, never reaching a solver) and the symbolic pool. The
variants reach the second through **deserialization** —
`symbolic/native_trace.rs:469` parses `"logical_and"` from a JSON pack, and
`ordered_replay.rs:314` imports that pack into the pool a backend then
translates. A `LogicalAnd` in a file on disk was a panic in a solver call.

And `ordered_replay.rs:316-320` settles what the arms must *do*: it re-renders
every imported pack through the text bridge and rejects it unless the rendering
hashes to the recorded constraint. The native backends do not merely aspire to
agree with `expr.rs` — replay breaks if they don't. All three now implement its
truthiness renderer exactly: coerce to the node width, **then** test `!= 0`,
then `ite`. Coercion order is load-bearing, because truncation can zero a
non-zero operand.

## Entry 71 — the bug under the bug: sixteen-bit division was being discarded

Fixture `194_narrow_return_widths` found that byte `mul`/`div` were never
lifted — `accumulator_halves` matched 64/32/16 and returned `None` below, so the
instruction fell to `Op::Unknown` and gcc's reciprocal constant `0xAB` appeared
nowhere in the output.

Fixing that surfaced something bigger. **Even at sixteen bits the lowering
*wrote* `VReg::phys("ax")` and `phys("dx")`** — bare partial-view names.
`regview::ssa_parent` declines to merge a bit-preserving view with its parent,
and every *read* of such a view is lowered by `read_view_ops` as an extract from
`rax`/`rdx`. Definition and use were two unrelated SSA names, so the result was
silently discarded. `185:gcc:O0:divide_unsigned_shorts` shows it plainly —
`divw -0x2(%rbp)` recovered as

```c
return (unsigned int)((unsigned short)(((unsigned int)(dividend) & 0xffff)));
```

with the divide simply gone.

`snapshot_accumulator_half`'s existing doc comment had fixed only the **read**
side of this hazard. The write side had never been done, and nothing pointed at
it because the corpus had no fixture that divided at a sub-word width — which is
exactly what 194 added. **Nine cells were predicted; forty-four moved.**

### The scope argument for `_Bool`, which is the part worth keeping

The second defect was that a narrow return is never truncated to its declared
width. I asked the agent to measure the blast radius and choose between
"truncate whenever wider than declared" and "truncate only `_Bool`", expecting a
size answer.

The right answer is a language answer. **C's return conversion is the assignment
conversion.** For every integer type except `_Bool`, 6.3.1.3 defines it as
reduction modulo 2^N — precisely the machine truncation we would spell, so the
cast is *provably* a no-op, not merely usually one. `_Bool` alone (6.3.1.2)
makes the conversion a **test**, which cannot recover a low byte from a
register-width value. The rule is "narrow where the language's own conversion is
not a truncation", and that set is `{_Bool}`.

It is also the smaller rule — 3 affected definitions against 704 — but that is a
coincidence, not the reason.

I also had the file wrong, and the correction matters:
`fold_typed_return_abi_extensions` **cannot see this case**, because
`inferred_return_width` comes from the recovered `TypeMap` and
`types_recover.rs:100` maps `TypeHint::BoolLike` to `"int"` — width 4, never 1.
`_Bool` exists only in the DWARF `CallPrototype` the renderer prints.

## Entry 72 — a correctness bug I traced correctly and that cannot happen

I traced the jump-table trim by hand and was confident: `attached` is built one
edge per table entry with no dedup; `extras` is the unproven suffix; the retain
removes **by value**, so a target present in both the proven prefix and the
trimmed suffix loses every edge. And `repair.rs:408` dedups `successor_ids`, so
the duplicate edges were harmless before — but dedup cannot restore a successor
that was never added.

Every step of that is true. The overlap still cannot occur, and the measurement
is the entry.

Instrumented over **12,249 binaries** — `samples/`, a seeded sample of system
ELFs, the whole fixture corpus, and 10,272 synthetic variants:

```
4,712 needs_bound_proof dispatches · 38 reached the trim · 0 overlaps
```

Both ingredients are individually common — `/bin/grep` has a table with
`n=153 distinct=53 dup=100` — but never together, and there is a structural
reason, verified byte-for-byte in `.rodata`. `discover_jump_tables` builds the
**longest run** of section words decoding to executable VAs, so the over-read
runs into the *next* table, and entries of table 2 read relative to `base1`
resolve to `T_j − 4·N1`. In one trimming binary: table 1 at `0x2000` with six
arms, table 2 at `0x2018` with real targets `0x12fc…0x13ff`, over-read as
`0x12e4…0x13e7` — exactly `real − 0x18`. **`extras` is always shifted garbage in
a different address range, never a repeat of a proven arm.**

Fixed anyway, in the multiplicity-keyed form, because the fix is free. Provably
a no-op at overlap zero, so no cell moved and no baseline needed regenerating.

Three things this produced that are worth more than the fix:

- **The dedup alternative was refuted concretely.** `resolved_targets` is a
  prefix of the raw scan, so deduping `attached` alone breaks
  `attached.starts_with(targets)` and sends every duplicate-bearing dispatch to
  `invalid_dispatches`, losing *all* its arms. Deduping both sides makes `arms`
  count distinct successors rather than table entries. **Edge multiplicity is
  load-bearing:** `clang_o2_shared_case_bodies` asserts `succs.len() == 8` over
  seven distinct blocks — that is how `case 2: case 5:` survives.
- **`arms` and the edge set can no longer disagree.** The helper returns the
  surviving count and the caller writes `*arms = kept`, so the arm count is read
  *off* the edge set instead of asserted beside it. That they could disagree at
  all was arguably the deeper defect.
- **The route that *would* fire it is now named.** `combine_dispatch_bounds`
  applies a fallthrough-only index bound to a dispatch block unconditionally,
  even when that block has a predecessor that does not satisfy the guard. There
  `extras` would contain *real* table entries, where duplicates are guaranteed.
  No binary was found where it bites, so it is filed rather than changed —
  altering a soundness-critical bound on an unmeasured hypothesis is how the
  next entry in this diary gets written.

And a corpus fact worth acting on separately: the 716 fixture binaries produce
**three** bound-proof dispatches and **zero** trims. The entire trim path has no
fixture coverage, because every observed trim was `gcc -O1` and
`REQUIRED_MATRIX` is `gcc/clang × O0/O2`.

## Entry 73 — three corrections to Entry 72's neighbourhood, one of them mine in a commit message

### `ReturnClass::Memory` does not shift arguments

`f252aa4b`'s message says AAPCS64 cannot reuse `ReturnClass::Memory` because
that variant "encodes System V's contract: hidden pointer in the FIRST ARGUMENT
REGISTER, every declared argument shifted one slot right." **The second half is
not implemented.** I checked after an agent said so:

```
grep -rn "ReturnClass::Memory" src/ --include=*.rs
```

Three real consumers — `python_bindings/ir.rs:2086`, `types_recover.rs:2309`
and `:2315`, `return_class.rs:149` — and `apply_locked_parameters` receives the
unshifted DWARF parameter list regardless of class. Nothing shifts.

The conclusion survives on its other leg: `Memory` maps to `HiddenReturn`, which
suppresses `materialize_return_values`, and `x8` needs a *size* the variant has
no field for. But the mechanism as stated is aspirational, and anyone reasoning
from that commit message would be reasoning from something the code does not do.
Recorded here rather than by rewriting history.

### The HFA proxy over-refuses, with two concrete falsifications

The committed `aapcs64_return_class` refuses all-SSE eightbytes as a proxy for
HFA — the reasoning being that every HFA member is floating point, so refusing
all-float refuses every HFA, and over-refusal is the safe direction. Measured
against `aarch64-linux-gnu-gcc`, it over-refuses twice in ways that matter:

- `struct {double d; float a; float b;}` at `-O1` returns through
  `fmov x0, d30` plus `x1`. It is `x0:x1`, and the proxy calls it float.
- `struct {float a, b;}` is **8 bytes and still an HFA** — `s0` *and* `s1`. A
  "≤ 8 bytes is one register" shortcut gets this wrong, which is why a real
  homogeneity walk has to run **before** any size test.

### HFA cannot reuse `SsePair`, and `trio3f` is the proof

`hfa197_trio3f` (three floats) on aarch64, both `-O0` and `-O2`:

```
fmov s29, s0 ; fmov s30, s1 ; fmov s31, s2        (-O0)
fcvtzs w3, s0 ; fcvtzs w1, s1 ; fcvtzs w2, s2     (-O2)
```

Three registers, **one member each**, `s3` untouched. SysV packs the same struct
into `xmm0:xmm1` at two floats apiece, which is why `SsePair` carries a
`high_bytes` occupancy for a half-used *eightbyte*. **AAPCS64 has no partial
occupancy anywhere; it needs a member count, up to four.** Different shape,
different class.

### And the finding that outranks all of it: 197's aarch64 lanes are not an ABI problem

`abi::result_register_candidates` answers `None` for `CallConv::Aarch64`, so
**every** AArch64 call is annotated `result = x0` unconditionally. SysV, Win64,
Cdecl32 and ArmHardFloat all have first-read-wins float/integer candidate lists;
AArch64 has none. `ast::float_gate::scalar_float_semantics_proof` then shuts the
whole function's scalar-float lowering, because a non-VFP call result means the
float registers cannot be assumed caller-saved:

```
[float-gate] va=0xbec call result=%x0  no vfp result,
             float regs NOT all caller-saved -> gate SHUTS
```

Every `fcvtzs` after that renders `/* asm: vcvt.s32.f32(...) */` with its
destination undefined. So `hfa197_scalar_control` — a plain `double` return with
no aggregate anywhere — was red for a reason that has nothing to do with return
classes, and my brief describing it as a passing cell that "must stay refused"
was wrong about a cell that was never green.

The one-line candidate list was measured and then reverted rather than shipped:
**11 improvements instead of 7 across 44 aarch64 lanes, zero regressions**, with
`197:aarch64:O2:hfa197_trio3f_roundtrip` passing only when the HFA class is
present too — the two compose. It was reverted because 44 lanes is not proof for
a change that touches every AArch64 call annotation, which is the correct call
and the reason it is being re-measured against the full aarch64 lane set before
it lands.

## Entry 74 — an unmodelled instruction does not fail to be modelled; it lies

`movlpd`, `movhpd`, `movlps` and `movhps` had no arm anywhere in `src/ir/`. The
interesting part is what that cost, and why it is not "one missing family".

The two fallbacks in this IR are `Op::Unknown { mnemonic: String }` — one field,
no operands — and `Op::opaque`, which builds `Op::Intrinsic` with
`reads_mem: true, writes_mem: true` and **empty `ins`/`outs`**. Conservative
about memory; silent about registers. So an unmodelled instruction is not
conservatively modelled, it is **invisible to register dataflow**: the def-use
census believes the destination was never written, and the previous value flows
on.

On `197:clang:O0:hfa197_quad4f_roundtrip` a correct `SsePair` return split was
computed and then **discarded**, because every consumer of `xmm0`/`xmm1` was a
declined `/* asm: movlpd */`. The split's reads had no users. And the `pd`
suffix made `movlpd` an unmodelled *float* producer to `float_gate.rs`'s
`OPAQUE_SUFFIXES`, which shut the whole-function gate — so eight `cvttss2si`
were declined as well. Ten undefined reads in one function, from one absent
match arm.

### Bit-identical is not inference-identical

The agent's first lowering emitted two 4-byte lane accesses, matching MOVQ's
`packed_qword_move_ops`. It removed all ten opaque markers and **the lane stayed
`fail`**: two 4-byte stores made the spill slot two `int` frame objects, and the
function's own 8-byte reload then narrowed to the first four bytes, silently
dropping two members. One 8-byte access with the lanes unpacked through a
temporary is what turned it green.

The stack-object recovery reads **access widths as layout evidence**. Two
lowerings that move the same bits are not interchangeable, because a later pass
is inferring structure from how the bits moved. That is worth remembering
whenever a lowering is chosen by analogy to a neighbouring one.

### The guard, and its stated limit

A new test sweeps the 238 committed amd64 samples and flags any instruction
whose lift leaves an `Op::Unknown` while `iced_x86` reports a written register.
1.8 seconds. Decoding only inside sized `STT_FUNC` bounds matters: a whole-`.text`
linear sweep invents `aesenc`/`xlatb`/`iretd` out of padding, and that alone cut
79 mnemonics to 52.

**52 mnemonics**, and the list is the argument:

```
pcmpeqb 204  punpcklbw 260  pmovmskb 222  pshuflw 232   <- glibc strlen/memcmp
syscall 310  bsr bts btc btr tzcnt popcnt shrd rcr
vmovdqu vpand vpbroadcastb vpcmpeqb vpmovmskb vpxor vzeroupper
movsb movsq  cpuid rdtsc rdtscp xgetbv popfq pushfq
fadd faddp fchs fisub fmul fstp fsub fsubp fxch
```

These are the SSE string primitives every statically linked binary's string
routines are built from. Not exotica.

The guard is **demonstrated rather than asserted** — deleting this commit's two
dispatch arms puts `"movhps": 26` back on the list, every `movhps` in the
corpus. And its limit is written into its own doc: **it would not have caught
`movlpd`**, because the committed samples contain none and its store form writes
no register. That one needed the fixture corpus, which is compiled rather than
committed and cannot be swept from a unit test. A guard that names what it
cannot see is worth more than one that implies it sees everything.

## Entry 75 — three suspects, all innocent, and the dumps said so

`194:{armv7,armv7_a32}:O0:nrw194_i8_divide` rendered
`(unsigned long long)(narrowed) >> 31` where `narrowed` is a `signed char` —
`0x1FFFFFFFF` instead of `1`.

I named three candidates: `lift_arm32/shifts.rs`, `ast/abi_widths.rs`,
`ast/width_semantics.rs`. **All three were innocent**, and the evidence was a
dump rather than a reading:

- the LLIR is exact — the `Shr` is over `r3`, a 32-bit register, immediately
  after an explicit `SExt 8 -> 32`;
- the AST is exact through `insert_widening_casts_for_machine_width` and all
  twelve passes after it, carrying an explicit `Cast{signed, width: 4}`.

The wrong width appears only in the C text emitted *after* the final pass dump.
The owner is `expr_machine_width`, which had no `Expr::Cast` arm and answered
`None`, so `shift_operand_ctype` fell through to its 8-byte default. A separate
pass then elided the now-unprinted `(int)((signed char)…)`, which is why the bad
cast ends up sitting on `narrowed` and reads like a type error rather than a
width default. **Two independent behaviours composing into a symptom that
resembles neither** is the reason the three-suspect list was wrong.

Blast radius was measured, not argued: every fixture source × {Thumb, A32} ×
{O0, O2} rendered both ways — **4 of 6,586 renders changed text at all**, two of
them the target, two an inert 64-bit cast over an already-wrapping 32-bit
product. So the *failure* is one function; the *mechanism* is not, because the
8-byte fallback is still the default for any operand whose width cannot be
established.

And one layer up, filed rather than fixed: **`phys_reg_width` does not model
ARM32 at all and answers with other architectures' registers.** `r0`-`r7` give
`None`; `r8`/`r12` hit x86-64's 64-bit table; `lr`/`pc` hit AArch64's; `sp` hits
x86's 16-bit `sp`. Its live consumer is the `Sar` arm of `lower_ops.rs`, so on
ARM32 that protection is inert for `r0`-`r7` and wrong by 2× for `r8`/`r12`.
No fixture reproduces it — gcc `-O0` keeps these functions in `r0`-`r3`.

## Entry 76 — every aggregate-return fix was validated one step removed from the thing it fixed

`tools/diff_decompile.py`'s `exec_class` declined **every** struct return with
"aggregate return — not execution-differential". The reason was mechanical:
`_ctypes_fn` built its restype from `_scalar_ctype`, which knows integers and
floats. `_value_ctype` handled structs — but only for arguments.

So fixtures 195, 197 and 198 — the three built specifically to pin SysV and
AAPCS64 return classes — exercised their aggregate returns **only through
`int32_t`-returning wrapper functions**. Every aggregate-return defect this
project has closed was verified by a wrapper that hashed the members, never by
comparing the returned aggregate.

The fix is small because the machinery already existed: `_struct_ctype` builds
an exact packed layout from DWARF offsets, and libffi then applies the
platform's own return-class rules to it — which is precisely the thing under
test. Use it as a restype, compare the returned bytes, stop declining.

### What was behind the curtain

**Twenty host cells and sixty across six architectures became executable. 20
pass, 40 fail. Zero regressed from a passing state** — every change is
`structural ->` a real verdict.

`bv195_make_quad` is the clearest, and the shape is worth seeing:

```c
unsigned long bv195_make_quad(int arg0) {          // declared as ONE word
    unsigned char local_10[16];
    *(int *)(&local_10[0])        = arg0 + 1;
    *(int *)((&local_10[0] + 4))  = arg0 + 2;
    *(int *)((&local_10[0] + 8))  = arg0 * 3;
    *(int *)((&local_10[0] + 12)) = arg0 * 5;
    return *(long *)(&local_10[0]);                // only the first eightbyte
}
```

All four members are computed correctly and two are thrown away. This is the
**callee** side of `IntegerPair`, a class whose **caller** side was fixed weeks
ago — and a roundtrip wrapper only ever exercises the caller side. The defect
was structurally invisible to the only test that could have seen it.

### The limit, measured rather than assumed

MEMORY-class returns stay `structural`. `bv195_make_big` (32 bytes) and
`agr198_make_five` (20) both SIGSEGV the worker, because libffi marshals a
`_pack_ = 1` layout differently from the ABI's hidden-pointer contract. The
predicate declines above 16 bytes with that written down. And one crash that
looked like mine was not: `bv195_big_roundtrip` SIGSEGVs at HEAD with the
harness unmodified — it takes a struct *parameter*, not a struct return. Checked
by stashing the change rather than by reasoning about it.

## Entry 77 — a review that could never expire

`analysis/java_class.rs` (2,644 LOC) carried:

```
"accepted: the Java class-file format in one owner."
```

I expected another fabricated-destination entry — four were found this week
naming modules that never existed. This is not that. **It names nothing, so
there is nothing to fabricate, and nothing to check.**

That is a worse failure mode, and probably a more common one: a review that is
*formally valid and unfalsifiable*. "One input format, one owner" cannot be
contradicted by any measurement, so it never expires. It survived a file growing
to 2,644 lines with seven strictly-layered concerns and 26 of 96 items reachable
from outside their layer.

"One format" is not "one reason to change". The opcode table changes when the
JVM adds an opcode; the annotation decoder when JSR-308 grows; the module
attribute at Java 9. Three other entries use the identical formula —
`debug/dwarf.rs`, `symbols/pdb.rs`, `ir/dwarf_fields.rs` — and deserve the same
call-graph test that refuted this one.

**The rule worth adopting: a review entry should state something a later
measurement can contradict.** "One format" cannot be. "One cluster, measured
2026-08-18, 96 items / 3 cross-layer references" can.

### The attribute trap has two directions and they are not symmetric

32% of this file's items have a leading line a keyword scan cannot see — but the
composition is the opposite of the PyO3 file's. **28 of 31 are attribute-
prefixed with no doc comment at all:** every one of the 26 public types sits
under a bare `#[derive(Debug, Clone, PartialEq, Eq)]`. Cutting at
`^pub struct JavaMethod` orphans that derive and every `PartialEq`/`Eq` in the
file with it. Meanwhile the swallow-the-next-doc trap barely fires here, because
**65 of the ~66 private functions carry no documentation whatsoever**.

A file's documentation density decides which half of the trap you face. The
`ast.rs` family was doc-heavy and lost doc blocks; this one is attribute-heavy
and would have lost derives.

### Two analysis errors the compiler caught, both worth naming

An identifier-level dependency graph put `JavaAnnotation` in `attributes.rs`'s
imports — a false positive from a **field type** (`Vec<JavaAnnotation>`) rather
than a call. Trap 8 has a third form: not a comment, not a struct field *name*,
but a field's *type*.

And the dead-code counts needed `touch src/lib.rs` to force re-emission, because
cargo replays a cached build with **zero** warnings. Read naively that is a
100 → 0 improvement. The measurement instrument lies when it is not made to
speak.
