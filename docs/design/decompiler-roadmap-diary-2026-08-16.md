# Decompiler roadmap execution diary — from 2026-08-16

**Plan:** [decompiler-roadmap.md](decompiler-roadmap.md)
**Previous volume:** [decompiler-roadmap-diary-2026-08-13.md](decompiler-roadmap-diary-2026-08-13.md) — Entries 1-48, 2026-08-13..16
**Continues from:** `0acfe20`

Running evidence log for working the roadmap. One entry per increment,
RED -> GREEN -> VERIFY, with the exact command output that justifies each claim.

**Entry numbering continues across volumes**, so a reference to "Entry 34" stays
unambiguous. The next free number is **54**.

Two conventions worth restating, both of which this project has paid to learn:

- **Write the command next to the number.** Two tables in `docs/design/` turned
  out never to have been produced by any run, and both shaped later decisions.
- **Measure the tool's own noise floor before trusting a diff.** A byte-identity
  check over the corpus showed 16 functions changed by a refactor; running the
  unmodified build against itself showed 13 changed there too. Without that
  control the refactor would have been blamed for a pre-existing 0.083%
  non-determinism. (Entry 52 found and fixed it: `HashMap` iteration order in
  `merge_exact_definition_widths`, not the time-based budget first suspected.)

---

## Entry 50 — A cursor writes the range; a displacement reads inside it

> **CORRECTION, added 2026-08-16 after Entry 53 measured it.** The SYMPTOM below
> is real and the disassembly is accurate, but the MECHANISM this entry proposes
> — "promotion meeting a frame address it did not form itself" — is wrong, and it
> was my theory rather than a measurement. The actual cause is that
> `dwarf_contracts.rs` mapped SysV `DW_OP_call_frame_cfa` onto `("rbp", +16)`, a
> frame-pointer coordinate that a frame-pointer-omitted `-O2` body never forms.
> The proven extents therefore sat on dead keys while every access resolved
> against `entry_rsp`, so promotion was not "meeting a borrowed address" — it was
> never shown the right address at all. The two fixes this entry proposes are
> consequently both aimed at the wrong layer. Entry 53 has the measurement.


`196_disjoint_frame_slots:gcc:O2:dfs196_alias_control` fails, and it failed
identically before the copy_prop disjointness work that added the fixture — the
control was confirmed against the unpatched build precisely because a failing
control is the one result that would have meant that patch was unsound. So this
is pre-existing, and it is a wrong-code defect rather than an ugly-output one.

### The shape, from the machine

    tools/dectest.py 196_disjoint_frame_slots --full
    objdump -d --no-show-raw-insn tests/decompiler_fixtures/build/196_disjoint_frame_slots-gcc-O2.so

```
1f9d: mov  %rsp,%rax          # cursor := frame base
1fa0: lea  0x20(%rsp),%rdx    # end := rsp+32
1fa8: mov  %esi,(%rax)        # store through the cursor
1faa: add  $0x4,%rax
1fb1: cmp  %rdx,%rax
1fb4: jne  1fa8               # strided fill of [rsp+0, rsp+32)

1fb6: mov  0xc(%rsp),%edx     # direct displacement read at rsp+12
```

`rsp+12` is INSIDE the range the loop just filled. The recovered C keeps those
two facts apart:

```c
var3 = rsp;
do { *(int *)((var3)) = var5; var3 = (var3 + 4); } while ((var3 != var4));
var8 = ((unsigned long)((unsigned int)(local_2c)) + 4096);   /* never assigned */
```

Promotion names `rsp+12` as `local_2c` because it is a direct displacement
access, and never attributes the cursor's stores to it. `local_2c` is therefore
read before definition — and separately `rsp` itself is declared and read
undefined, the familiar unpromoted-frame-base symptom.

### Why this is not a corner

A pointer-strided fill is the ordinary shape gcc chooses for array
initialisation at `-O2`. The fixture reaches it with an 8-element array; earlier
attempts with fewer live locals did not, which is why the lane needed ~48 live
locals to force the web at all.

### The two candidate fixes, and which is honest first

**Connect them.** When a frame address is used as a strided cursor over a proven
range, attribute the stores to the frame slots that range covers. Correct but
needs the range proven — stride, bounds, and that the cursor cannot escape.

**Fail closed.** If a strided cursor writes a range that overlaps a promoted
local, refuse to promote that local and fall back to raw frame access. This turns
wrong code into ugly code, which is the right direction under design rule 8 and
is almost certainly the smaller change. It should land first regardless, because
it removes an undefined read whether or not the connecting analysis is ever built.

### Related, and probably one fix

The undefined-read census's cluster E is the same promotion path failing on a
computed frame address: `111_self_referential_struct` leaves
`%rdx#6 = %rdx#5 + %rbp` unpromoted, so `recognise_machine_frame` fails closed
and `rbp` is declared and read. Both are promotion meeting an address it did not
form itself.

---

## Entry 51 — `rax:rdx` is two values, so it needed a class and not a longer list

> Entry 50 is a concurrent session's (`0e90587`); this one took 51. The header's
> "next free" still said 50 after that entry landed, which is how a collision
> nearly happened. It now says 52 — bump it when you take a number.

### RED

    tools/dectest.py 195_by_value_aggregates --full

    195_by_value_aggregates:{gcc,clang}:{O0,O2}:bv195_pair_roundtrip     pass
    195_by_value_aggregates:{gcc,clang}:{O0,O2}:bv195_consume_pair       pass
    195_by_value_aggregates:{gcc,clang}:{O0,O2}:bv195_scalar_control     pass
    195_by_value_aggregates:{gcc,clang}:{O0,O2}:bv195_quad_roundtrip     fail
    195_by_value_aggregates:{gcc,clang}:{O0,O2}:bv195_mixed_roundtrip    fail
    195_by_value_aggregates:{gcc,clang}:{O0,O2}:bv195_big_roundtrip      fail

12 failing cells, 8 passing, graduated exactly at the eight-byte boundary — so
nothing could be fixed by routing every aggregate through one path, and the
scalar control proves the lane is not vacuous.

The diagnosis in the roadmap was right about the cause.
`abi::return_registers(SysVAmd64)` is `["rax","eax","ax","al","xmm0"]`, which is a
list of SPELLINGS of one logical result. `rax:rdx` is not another spelling: it is
two registers holding different bytes. So a 16-byte INTEGER aggregate came back as
`extern long bv195_make_quad(int)` and the `rdx` half was read while never
defined.

    tools/dectest.py 195_by_value_aggregates:gcc:O2:bv195_quad_roundtrip --show

```c
extern long bv195_make_quad(int);
var3 = bv195_make_quad(...);          // rax only
var6 = ((long)(var3) >> 32);
*(int *)((var1 + 0x8)) = var7;        // var7 is the rdx half: UNDEFINED
```

### GREEN — the model

`abi::ReturnClass` names the four System V result contracts, and `Eightbyte`
names the two classes a chunk can have:

| source result | storage | class |
|---|---|---|
| `<= 8` bytes, all integer | `rax` | `Single` |
| `<= 16` bytes, all integer | `rax:rdx` | `IntegerPair` |
| `<= 16` bytes, integer + double | `rax` + `xmm0` | `SplitBanks { integer_first }` |
| `> 16` bytes | caller's buffer, hidden pointer | `Memory` |

`abi::sysv_amd64_return_class(size, eightbytes)` is the pure table;
`ir::return_class::declared_return_class` is the DWARF-driven front end that
computes the eightbyte join over a recorded layout. Both fail closed — two SSE
eightbytes (`xmm0:xmm1`), unions, arrays, bitfields, `long double`, non-System-V
conventions, and a missing type environment all return `None`, which means
"keep today's behaviour".

**Why the class comes from a DECLARED type and not from liveness.** Machine
evidence looks sufficient and is not: at `-O2` an unused `idiv` remainder leaves a
dedicated definition of `rdx` reaching the `RET` of an ordinary `int` function,
and by liveness that is indistinguishable from the high eightbyte of a pair. A
wrong class there retypes the callee for EVERY caller and produces C that compiles
and returns the wrong bytes, which is strictly worse than no class.

### GREEN — the wiring, which turned out to be one machine word up

The pipeline already had a two-register integer result: `wide_integer_return_pair`
and the high-half compatibility copy in `call_result_split`, built for ILP32's
`long long` in `rax:rdx` / `r0:r1`. System V's 16-byte INTEGER aggregate is that
same shape one machine word up, so the change was to derive the pair width from
the machine word (`wide_integer_return_width = 2 * machine_word_bytes`) rather
than hard-code eight.

The C spelling matters and was the only real design choice. `unsigned __int128`
is classified INTEGER,INTEGER by the ABI itself, so declaring it gives the call
site EXACTLY the `rax:rdx` contract with no aggregate reconstruction and no
synthesised tag. Three small facts had to agree for that to render:

- `integer_c_type_width("unsigned __int128", 8) = 16` so `call_result_split`
  finds the pair;
- `call_return_hint` gives the destination width 16, without which `widen`
  states a one-word reinterpretation and the shift truncates before it extracts;
- `shift_operand_ctype` spells a two-machine-word operand with
  `double_width_ctype`, because `(unsigned long)(v) >> 64` is a shift by the
  operand's own width and yields nothing.

That last one was found the expensive way. The first build produced
`var4 = (unsigned long)(((unsigned long)(var3) >> 64))` — a correct-looking
extraction of zero.

`RecoveredOutputKind::HiddenReturn` now has its first producer: a proven
`Memory` class. It is deliberately behaviour-neutral, because under System V the
callee returns the caller's buffer address in the ordinary result register, so
recording the contract changes no spelling.

### VERIFY

    cargo test --features python-ext          2571 passed, 0 failed
                                              (2562 at 51c2b88; +9 new tests)
    tools/dectest.py 195_by_value_aggregates --full
      IMPROVEMENTS (4): bv195_quad_roundtrip fail -> pass on gcc:O0, gcc:O2,
                        clang:O0, clang:O2
      no regressions in scope
    tools/dectest.py @o0                      368 lanes, 2 improvements, 0 regressions
    tools/dectest.py @o2                      368 lanes, 2 improvements, 0 regressions
    tools/dectest.py @structs @aggregates      48 lanes, 4 improvements, 0 regressions
                                               (48 not 44: `195_by_value_aggregates`
                                                was added to the `[aggregates]` set,
                                                which had covered aggregate LAYOUT and
                                                no aggregate ABI CONTRACT at all)

    touch src/lib.rs && cargo build --features python-ext
      never-used FUNCTION count: 0

**The 32-bit targets are unchanged by construction, and were checked anyway.**
`wide_integer_return_width` is `2 * machine_word_bytes`, which is the 8 that was
hard-coded before for every ILP32 convention; `integer_c_type_width` only knows
`__int128` where the pointer is eight bytes; and the new `shift_operand_ctype`
branch spells a two-machine-word operand with `double_width_ctype(false, 4)` on
i386, which is the `unsigned long long` `target_int_ctype(false, 8)` already
produced there.

    tools/dectest.py @aggregates --arch i386   20 lanes, no regressions
    tools/dectest.py @aggregates --arch armv7  20 lanes, no regressions

(`@widths` is not available on either: `02_integer_widths:i386:*` is a declared,
probed gap because `__int128` is not a type there — which is the same fact this
entry relies on in the other direction.)

Baselines were NOT refreshed; the four moved cells are listed for whoever does.

### The judgement the brief asked for: returns and parameters are SEPARABLE

The roadmap said the return classification "is the same eightbyte classification
the SysV PARAMETER side needs, so the two should land together", and that the
memory class "shifts every real argument one register right, which is why the
32-byte case fails". The first half is true about the MACHINERY and false about
the SCHEDULE; the second half is not what the evidence shows.

The classifier IS shared — the parameter side can call the same `Eightbyte` join
unchanged. But the consumers are independent, and the return side landed alone
with zero regressions across 736 lanes.

The argument shift never materialises, because we never claim a source arity for
the callee. `bv195_make_big`'s storage layout is recovered from liveness, which
sees `rdi` and `rsi`, so the emitted call is positionally correct against the
machine. What actually breaks the MEMORY lane is somewhere else entirely:

    objdump -d --no-show-raw-insn tests/decompiler_fixtures/build/195_by_value_aggregates-gcc-O2.so

```
1331: mov  %rsp,%rdi          # hand the frame base out as the hidden pointer
1334: call 10f0 <bv195_make_big@plt>
1339: mov  0x8(%rsp),%rcx     # ...then read the object back
```

```c
var4 = bv195_make_big(rsp);                  /* `long rsp;` — read undefined */
var6 = *(long *)((&local_38[0] + 8));        /* promoted stack object */
```

The reads are promoted to `local_38`; the address handed to the callee stays raw
`rsp`. The callee writes to garbage and the caller reads a buffer nothing wrote.
That is promotion failing to connect an address it did not form itself — the same
shape as Entry 50's strided cursor and `111_self_referential_struct` — and it
belongs to the stack work, not to ABI classification.

### The defect this uncovered and did not fix

`call_result_split::result_storage` maps `xmm0` onto the SAME storage key as
`rax` under both x86-64 conventions, because `is_return_register` accepts the
whole alias list. A post-call read of `xmm0` is therefore rewritten to the
INTEGER call result. It is visible in `bv195_mixed_roundtrip`:

```c
var3 = bv195_make_mixed(...);                       /* rax */
var4 = (int)(((union { unsigned long long bits; double value; })
              { .bits = (unsigned long long)(var3) }).value);   /* xmm0, WRONG */
```

The AArch64 and ARM branches of that function already keep their banks apart;
x86-64 does not. Splitting them is a soundness fix independent of aggregates, but
on its own it converts wrong bytes into an undefined read and moves no cell, so it
is left to land with the `SplitBanks` consumer rather than as unmeasured churn.

## Entry 52 — The 0.10% was hash order, and the reason we thought it wasn't

Entry 48 measured the tool's noise floor before trusting a diff, and found it:
three same-process passes of ONE unmodified build over the corpus disagreed with
themselves on 13 functions. The declaration-plan split had to quarantine 16
functions to get a clean before/after comparison. That is the thing this entry
removes, because a noise floor that only one person knows about is a trap for
everybody else.

### Reproduce first

```
$ uv run python repro.py '*rustc*' 3        # 30 objects, ONE process, 3 passes
objects: 30  runs: 3
run 0: 5595 functions  95.7s
run 1: 5595 functions  191.8s
run 2: 5595 functions  287.6s
TOTAL functions (union): 5595
DIFFERING functions:     13  (0.2324%)
```

All 13 are in the `-rustc-` subset, so the whole defect lives in 30 of the 766
objects. The full corpus at `51c2b88` agrees exactly:

```
$ uv run python repro.py '*' 3
run 2: 15698 functions  796.7s
TOTAL functions (union): 15698
DIFFERING functions:     13  (0.0828%)
```

13 of 15,698 is 0.083%, not 0.10% — the count reproduces, the percentage was
rounded up. Same list of symbols: the two `memchr` routines across six `rustc`
fixtures, plus `rust_slice_get_range`.

A single function reproduces it in seconds, which is what made the rest of this
tractable:

```
$ uv run python one.py 169_rust_slices_bounds-rustc-O2.so 28832 20
2 distinct outputs over 20 same-process calls
  variant runs=[0, 1, 3, 6, 7, 9, 11, 13, 17, 18] count=10
  variant runs=[2, 4, 5, 8, 10, 12, 14, 15, 16, 19] count=10
-long rust_slice_get_range(char * arg0, unsigned int arg1, ...) {
+unsigned long rust_slice_get_range(char * arg0, unsigned int arg1, ...) {
```

Ten and ten. A coin flip, inside one interpreter, on identical bytes.

### RED

```
$ uv run pytest python/tests/test_decompile_determinism.py -k decbench_render -q
E  AssertionError: 169_rust_slices_bounds-rustc-O2.so:rust_slice_get_range
   rendered 2 distinct texts over 16 same-process decompile_at(style='decbench')
   calls -- identical inputs produced different output (roadmap design rule 12).
E    'long rust_slice_get_range(char * arg0, ...)'
E    'unsigned long rust_slice_get_range(char * arg0, ...)'
```

Both parameters fail at `51c2b88`, and again at `c2fb19d` after Entry 51 gave
SysV a return CLASS. That is worth stating: Entry 51 is the nearest work in the
tree to this defect - it is about `rax`, `xmm0` and what the return storage
contract is - and it does not touch this. The flip is not in the ABI model. The
existing file had 9 cases and missed this
entirely: its same-process test calls `decompile_all` with no `style`, so it
renders the **plain** profile, and the only decbench coverage anywhere compares
across separate subprocesses. Neither shape can see a second call in one process
at the profile every published number is rendered at.

### The lead that was wrong, and why it was believable

The roadmap recorded that within-process variation "rules out per-process hash
seeding and points at a time-based budget." That inference is backwards, and it
is the reason this sat unexplained.

`std::collections::hash_map::RandomState::new` seeds from a thread-local pair of
keys **and bumps a counter on every construction**. Two `HashMap`s built at
different moments in one process therefore iterate differently. Within-process
variation is evidence *for* hash ordering, not against it.

The time-budget hypothesis was also refuted directly rather than abandoned.
`grep -rl 'Instant::now\|\.elapsed()' src/` names 19 files; the only one
reachable from a decompile is `src/analysis/cfg.rs`, and its whole-run ceiling
`total_timeout_ms` is hardcoded to `0` at every decompile entry point, so
`Deadline::expired()` can never fire. There is no deadline on this path to be
load-dependent.

### Root cause

Bisected by instrumenting the stages of `decbench_type_maps` and printing the
`ret` hint after each:

```
DBGSTAGE decl:stack_source:    Some(Int { signed: false, width: 4 })
DBGSTAGE decl:exact_defwidths: Some(Int { signed: false, width: 8 })   -> unsigned long
...
DBGSTAGE decl:stack_source:    Some(Int { signed: false, width: 4 })
DBGSTAGE decl:exact_defwidths: Some(Int { signed: false, width: 16 })  -> long
```

One stage, both directions. Printing what that stage consumed named it outright:

```
DBGDEF storage=rax#3 role=ret width=8
DBGDEF storage=xmm0  role=ret width=16   -> 16 wins
DBGDEF storage=xmm0  role=ret width=16
DBGDEF storage=rax#3 role=ret width=8    -> 8 wins
```

`merge_exact_definition_widths` (`src/python_bindings/ir.rs`) iterates
`definition_widths: HashMap<VReg, u8>` and writes each storage's width through
`TypeMap::refine_from_value`, which is last-write-wins on integer width. But
`role_names` is **many-to-one**: the naming pass maps every return carrier onto
the single role `ret`, so an integer `rax#3` and an SSE `xmm0` both land there
and the hash picks which one the signature gets. `Int { width: 16 }` is not a C
integer width at all, so `hint_to_ctype` degrades it to `long` and the `unsigned`
is lost on the way — which is why the flip changes signedness as well as width.

This is the third instance of one class. `ir::stack_locals` documents a bare
`collect()` that "made HashMap iteration order choose the declaration width, so
identical inputs could alternate between `char` and `long`"; `types_recover.rs`
carries a `BTreeMap` with a comment naming the same failure. Neither fix covered
this loop.

### The fix, and why withholding rather than a winner

A census of the blast radius before choosing a rule, over the 30 `-rustc-`
objects:

```
merge calls: 11190   calls with >=1 conflicting role: 506 (4.52%)
conflicting role families: [('ret', 506)]
conflicting width sets: [((8,16), 384), ((4,8), 84), ((4,16), 22), ((2,8), 16)]
```

`ret` is the **only** role that ever disagrees. No `varN` ever does. That bounds
the change to the return type and made the choice of rule a small decision rather
than a large one.

The loop now collects into a `BTreeMap<&str, Option<u8>>` keyed by role and
applies afterwards; disagreeing storages set the entry to `None` and the role is
left alone. Withholding, not min or max, for two reasons. It is what
`stack_locals` already does with its `ambiguous_coordinates` when two machine slot
keys reach one name — the same situation, so the same answer. And `ret` is the
one role with better evidence on both sides of this call:
`RecoveredPrototype::result_type_map` before it and the explicit
`recovered_width.max(proven_width)` union in
`ast::refine_decbench_abi_widths_with_value_widths` after it. A projection that
cannot say which definition a role follows should say nothing, not guess.

Reading `tm` moved out of the write loop as a consequence, which is its own small
correctness gain: the pointer-class check and the signedness carry no longer
observe writes the same loop made.

### GREEN / VERIFY

All numbers below are on `c2fb19d`.

```
$ uv run pytest python/tests/test_decompile_determinism.py -q -rs
11 passed

$ uv run python repro.py '*' 3
run 0: 15698 functions  237.3s
run 1: 15698 functions  487.8s
run 2: 15698 functions  787.2s
TOTAL functions (union): 15698
DIFFERING functions:     0  (0.0000%)

$ cargo test --features python-ext
2573 passed; 0 failed          (2571 on c2fb19d, plus the two added here)

$ uv run tools/dectest.py @o0
SCOPED: 368 lanes of 748 (49%) - no regressions in scope
$ uv run tools/dectest.py @o2
SCOPED: 368 lanes of 748 (49%) - no regressions in scope

$ touch src/lib.rs && cargo build --features python-ext | grep -c 'function .* is never used'
0
```

No improvements either, on either set — expected: `ret` is the only affected
role and the flipping functions are Rust standard-library code that no C fixture
lane covers.

The before/after comparison that matters most is not the lane count. Rendering
the whole corpus on `c2fb19d` and again with the fix, and diffing the texts
function by function:

```
keys: 15698 15698
functions whose text differs (HEAD single pass vs fixed): 12
```

Every one of the 12 is in the already-flipping set - the two `memchr` symbols
across six `rustc` objects, plus `rust_slice_get_range`. Nothing else in 15,698
functions moved. **No deterministic output changed.** The same comparison run
against `51c2b88`, using the set of texts from three HEAD passes rather than one,
put it the other way round: 15,694 of 15,698 were byte-identical to a HEAD
variant, and all 4 that were not were in the flipping set.

And the one place there is ground truth, the fix is not merely deterministic but
right. `tests/decompiler_fixtures/src/169_rust_slices_bounds.rs` declares

```rust
pub extern "C" fn rust_slice_get_range(p: *const i32, n: u32, a: u32, b: u32) -> i32
```

The coin flip returned `long` or `unsigned long`; both are the wrong width. It
now renders `unsigned int` — 4 bytes, matching `i32`. The signedness is still
wrong, and that is a separate pre-existing defect in this role's evidence chain,
not something this change touches.

### What is still open

`decompile_all`/`decompile_many` are still not parametrized over
`style in {"", "c", "decbench"}` in the determinism test, and `render_c` still
has no determinism test at all. This entry closes the measured hole, not the
class. The general defence — a determinism check that renders the same function
twice in one process for every profile — is still the roadmap item.

### The time-based budget that does exist, and is not this

Worth recording precisely, because "the deadline hypothesis was wrong" is easy to
over-read as "there is no load-dependent budget on the output path." There is
one, it is just not what fired here.

`Budgets::timeout_ms` carries a doc comment saying it "has never bounded an
analysis." That is true of the *whole* analysis and false of a single function:
`discover_function` checks `t0.elapsed() > budgets.timeout_ms` at two sites
(`src/analysis/cfg.rs:1374`, `:1409`) and sets `stats.hit_timeout` before
breaking out of the block walk, which truncates the recovered CFG. Wall clock in,
different output out. `total_timeout_ms` really is `0` at all five decompile
entry points, so the whole-run `Deadline` never expires, but the per-function
clock is live.

It is not a practical hazard at the decbench entry points — `decompile_all`
passes `timeout_ms=10_000` and `decompile_at` `5_000`, against fixture objects
where hundreds of functions are discovered in about a second, so the headroom is
roughly four orders of magnitude. `decompile_range` (`ir.rs:1291`) is the thin
one at `timeout_ms=500`.

The principle from the task stands and should be written down: **a load-dependent
budget is acceptable, a load-dependent RESULT is not.** The right shape is for a
truncation to be reported rather than silently rendered - `hit_timeout` already
exists and is already aggregated, and nothing on the decompile path reads it. That
is a separate item from this entry and has not been done.
---

## Entry 53 — Three symptoms, two defects, and the proven extent was in a coordinate the body never forms

> Entry 52 is a concurrent session's (`3273120`); this one took 53, and the
> header now says 54. That session also refreshed `defuse_baseline.json`
> (`2c928d6`) and removed the corpus noise floor this entry had measured at 8
> bodies, so every number below was re-measured on `3273120` rather than
> carried over from `c2fb19d`.

> **STATUS: measured clean and the fix is ready.** This entry was first
> committed with the finding only, because the `@o2` sweep its author had not
> finished found `24_merge_sort:gcc:O2:merge_sort_i32` going `pass -> fail`. That
> was real, it was a FIFTH thing the coordinate repair exposed rather than an
> over-extended extent, and rules 2 and 3 below are what close it. Re-measured on
> `3273120`: `24_merge_sort` passes on all four lanes, `@o0` and `@o2` have no
> regressions, and the four improvements stand.

Entry 50 read `196_disjoint_frame_slots:gcc:O2:dfs196_alias_control`,
`111_self_referential_struct` and (through Entry 51) `195_by_value_aggregates`'s
MEMORY lane as one defect — "promotion meeting a frame address it did not form
itself" — and proposed failing closed when a strided cursor's range overlaps a
promoted local. **The convergence does not survive the slot map.** Two of the
three are one defect and it is not that one; the third is separate and blocked
somewhere else entirely.

### RED — what the three lanes actually contain

    GLAURUNG_DUMP_PASSES=1 glaurung decompile <fixture>.so --func <fn> --style decbench
    (plus a temporary dump of the final `(base, disp) -> SlotVal` map, removed before landing)

| lane | slot map at `c2fb19d` |
|---|---|
| `196:gcc:O2:dfs196_alias_control` | `entry_rsp-44 local_2c` scalar; `entry_rsp-16 local_10`; **`rbp-48 local_30 obj=32 "int32_t[]"`** |
| `111:gcc:O2:link_and_sum` | `entry_rsp-152 local_98` scalar; `entry_rsp-144 stack_0 obj=144` heuristic; **`rbp-144 local_90 obj=128 "struct Node[]"`** |
| `111:gcc:O0:link_and_sum` | `rbp-144 local_90 obj=128` — live and used |
| `195:gcc:O2:bv195_big_roundtrip` | `entry_rsp-56 local_38 obj=40 bounded` — heuristic, and formed LATE |

The bold rows are DWARF-proven extents **no access in the body ever reaches**.
`dwarf_contracts.rs:55` mapped SysV `DW_OP_call_frame_cfa` onto `("rbp", +16)`,
which is a real coordinate only when the body establishes a frame pointer. At
`-O2` gcc omits it as a matter of course, so the proven extent sits on a key
nothing addresses while every access resolves against `entry_rsp`. `rsp+12` is
inside `a`'s proven 32 bytes and became the bare scalar `local_2c` that the
array's own filling loop never appeared to define.

So this is not promotion failing on a borrowed address. **It is promotion never
being told the object exists**, in every frame-pointer-omitted x86-64 function
that has an aggregate. The strided cursor is a red herring: once the object is
named, `mov %rsp,%rax` and `mov 0xc(%rsp),%edx` resolve to the same C object,
with no store attribution, no stride proof and no non-escape proof. `111:gcc:O0`
is the control — a real `rbp` frame, a live hint, and it does not move.

### GREEN — four changes, each with the control that shaped it

Every one after the first exists because the first exposed something. Landing (1)
alone regresses cells; the set is what is sound.

1. **Rebase a CFA-derived hint onto the entry coordinate when the body omits the
   frame pointer.** `StackObjectHint::cfa_relative` records which arm of
   `dwarf_stack_object_hints` produced the base, because a hint DWARF genuinely
   rooted at `rbp` (`DW_OP_breg6`) is already in the body's coordinate and moving
   it would break a correct object. The omitted frame pointer would have sat one
   machine word below the entry SP, so the rebase is `disp - stack_word_size`.
   (Independent of whether `rbp` is pushed at all: CFA is `entry_rsp + 8`, the
   hint carries `offset + 16`, so the entry coordinate is `offset + 8`.)
2. **An indexed partition that OVERLAPS a debug-proven object is not a second
   allocation.** Two shapes, both measured, both producing two C arrays over one
   piece of storage — which the recompiled C then allocates apart:
   * the partition starts INSIDE the object. `nodes[i].next` is an indexed access
     eight bytes into `struct Node nodes[8]`, and seeding it separately put
     `111_self_referential_struct:gcc:O2`'s list terminator in the wrong object.
   * the partition starts BELOW it and runs through it. gcc addresses
     `int32_t temp[16]` at `rsp+0x30` as `0x2c(%rsp) + (out+1)*4`, so the
     recovered start is one element low; the conservative extent then covered the
     proven array AND the `width` scalar in front of it, and
     `24_merge_sort:gcc:O2:merge_sort_i32` went pass -> fail on the first
     attempt at this entry.
   The pre-existing rule ("never replace an exact extent with the heuristic's
   conservative partition") covered only an exact START match.
3. **An indexed access biased one element below a proven object still reaches
   it.** The other half of merge_sort: with the partition suppressed, nothing
   CONTAINED `entry_rsp-60`, and the store fell back to raw frame arithmetic.
   `seed_indexed_stack_objects` already treats a start within one of its own
   elements as an aliasing bias when comparing two heuristic partitions;
   `biased_indexed_object` is that same rule against an authoritative extent, and
   the relative offset comes out negative — `&temp[0] + (out+1)*4 - 4` — which is
   exactly the bias the machine applied. The result is better than what passed
   before: `width` is now an `int`, the canary a `long`, and `temp` a 64-byte
   array, where the old output had one 140-byte blob covering all three.
4. **A debug-proven object admits an address one past its end, in an
   assignment.** `lea 0x20(%rsp),%rdx` is `&a[8]`, the bound of the loop that
   fills `a`. While the heuristic ran to the frame base this was swallowed by
   accident; the exact extent refused it and left the bound as arithmetic on an
   undefined `rsp`, taking `dfs196_indexed_control` from pass to fail. Three
   conditions keep it from eating the neighbour that begins at that same
   coordinate, and each was paid for:
   * a DEREFERENCE there is still refused;
   * the extent must be **debug-proven**. Allowing it for any bounded object cost
     `rustc:O0` +275 and `rustc:O2` +165 undefined reads — iterator code is built
     out of end pointers — and moved no cell;
   * only a **value-producing assignment** asks for it. As a call argument it
     took `10_cpp_runtime_shapes:gcc:O0:cpp_move` from pass to fail, because
     `Movable b` sits directly above `Movable a` and its constructor is handed
     `&a + sizeof a`. `mov %rsp,%rbp` is excluded for the same reason: it defines
     a coordinate system rather than computing a bound, and without that
     exclusion `-O0` prologues rendered as a dead `stack_0 = &local_c[0] + 12`.
5. **An object that contains only the FIRST address of an indexed sequence is
   not the array that sequence walks.** Found on `i386`, by a baseline
   regeneration, after `@o0` and `@o2` had both been clean twice — see the
   section below, which is the part of this entry worth reading twice.
   `queue[head++]` in `23_topological_sort` is `0x58(%esp,%edi,4)` with `%edi`
   starting at one: the same one-element bias as merge_sort, except that here the
   element below `queue` is the LAST element of the adjacent `indegree[16]`.
   Containment matched, and matched the wrong array — every dynamic address the
   sequence produces is in `queue`, and only the base byte is in `indegree`, so
   the recovered C read `indegree[16]`, one past its end, where the machine reads
   `queue[0]`. Rule 3's bias lookup was never consulted because containment had
   already succeeded. Two conditions, both RED-verified separately:
   * the sequence must leave the containing object by its SECOND element;
   * the base must not be that object's own start. A bias displaces the base from
     the array it walks, so a base sitting exactly on an object is that object
     being addressed. Without this, a one-element proven object indexed at its
     own start hands itself to whatever follows it.

### The i386 lane, and why two clean host sweeps could not see it

This is the methodological result, and it cost a baseline regeneration to learn.
Rules 1-4 were verified by `@o0` and `@o2` — 736 lanes, twice, no regressions —
and by a 748-lane corpus render. **All of that is host x86-64.** `@o0` and `@o2`
expand over `gcc`/`clang` and nothing else by design, so they cover 742 of the
2950 selectable lanes; the 2208 cross-architecture lanes were untouched, and the
regression lived there.

It is not an ILP32 arithmetic bug — the rebase is exact on both: SysV has
`CFA = entry_rsp + 8` with the hint carrying `offset + 16`, cdecl32 has
`CFA = entry_esp + 4` with the hint carrying `offset + 8`, and `disp -
stack_word_size` is right in both. What i386 supplied was a LAYOUT the host
corpus does not contain: two proven arrays exactly adjacent, with a biased base
landing in the last element of the lower one. On x86-64 the same source puts
padding between them and the biased base falls in a gap, where nothing contains
it and rule 3 alone was enough.

The lesson for the next frame change is the cheap one: `dectest` takes arch
selectors now, so
`tools/dectest.py 23_topological_sort:i386:O2:topological_sort` is a 1.9-second
question. A scoped `--arch` run over a frame-heavy set costs a couple of minutes
and would have caught this before the baseline did.

### The third symptom is NOT fixed, and the blocker is not stack promotion

`195:gcc:O2:bv195_big_roundtrip` has no DWARF stack object to rebase:

    readelf --debug-dump=loc 195_by_value_aggregates-gcc-O2.so
    b: (DW_OP_reg4; DW_OP_piece: 8; DW_OP_fbreg: -56; DW_OP_piece: 8; DW_OP_reg0; ...)

`b` lives in registers with pieces. Its buffer object is formed heuristically by
`stack_assignment_object_address` from the EPILOGUE's dead `%t147 = %rsp` — after
the call argument was visited, which is exactly why the escaping `%rsp` and the
promoted reads disagree.

The connect was prototyped and reverted. Admitting a bare architectural stack
pointer as an escaping address in ARGUMENT position, bounded by the next known
slot, does produce `bv195_make_big(&local_38[0])` — and then the recovered callee
prototype truncates it, because `extern long *bv195_make_big(int)` renders
`(int)(&local_38[0])`, a 64-bit pointer through an `int`. **What is missing is the
parameter side: `RecoveredOutputKind::HiddenReturn` has a producer (Entry 51) and
no consumer**, so the callee never declares the MEMORY-class hidden pointer. The
cell still failed, and the change cost `rustc:O0` +15 / `rustc:O2` +9 undefined
reads against a ratcheted ceiling. That is a wrong attribution being worse than
the read it replaces, exactly as the brief anticipated.

### What Entry 50's fail-closed proposal is still for

It was not implemented, and the reason is measurable rather than a preference:

    strip --strip-debug 196_disjoint_frame_slots-gcc-O2.so
    glaurung decompile ... --func dfs196_alias_control
      // glaurung-verify: local_2c is read but never defined   (unchanged)

Stripped, the defect is exactly as it was. Every lane the corpus judges carries
`-g`, so a fail-closed rule for the no-debug case has **no measurable surface
here at all** — it could only be justified by assertion. Naming that gap is
worth more than shipping an unmeasured guard over every frame in the corpus.

### VERIFY

All of it on `3273120`, not on the `c2fb19d` this entry started from.

    cargo test --features python-ext          2583 passed, 0 failed
                                              (2573 at 3273120; +10 new tests —
                                               6 RED without the fix, 4 controls
                                               green by construction, which is
                                               what a control is for)

    tools/dectest.py 196_disjoint_frame_slots 111_self_referential_struct 195_by_value_aggregates
      IMPROVEMENTS (2): 111_self_referential_struct:gcc:O2:link_and_sum  fail -> pass
                        196_disjoint_frame_slots:gcc:O2:dfs196_alias_control fail -> pass
      no regressions in scope
      (195's twelve cells are unchanged — see above)

    tools/dectest.py @o0                      368 lanes, no regressions, 0 improvements
    tools/dectest.py @o2                      368 lanes, no regressions, 4 improvements:
      111_self_referential_struct:gcc:O2:link_and_sum       fail -> pass
      164_nested_tlv_walker:gcc:O2:tlv164_leaf_sum          fail -> pass
      196_disjoint_frame_slots:gcc:O2:dfs196_alias_control  fail -> pass
      85_designated_initializers:gcc:O2:designated_sum      fail -> pass

    tools/dectest.py 24_merge_sort --full     all 4 lanes pass
      (the cell rules 2 and 3 exist for; it regressed under rule 1 alone)

    tools/dectest.py 23_topological_sort:i386:O2:topological_sort   pass
      (the cell rule 5 exists for; 1.9s, and it regressed under rules 1-4)

SCOPED ARCHITECTURE RUNS, which rules 1-4 did not have and needed. A frame-heavy
selection — `@aggregates @structs @curriculum-graphs @curriculum-dynamic-programming
@curriculum-sequences @curriculum-sorting @curriculum-structures` — retargeted:

    ... --arch i386        74 lanes, no regressions, 3 improvements
      111_self_referential_struct:i386:O2:link_and_sum   fail -> pass
      161_packed_struct_layout:i386:O2:pk161_roundtrip   fail -> pass
      162_unaligned_memcpy_access:i386:O2:ua162_roundtrip fail -> pass
    ... --arch armv7_a32   74 lanes, no regressions, 3 improvements
      25_kmp_search:armv7_a32:O2:kmp_search              fail -> pass
      32_longest_common_subsequence:armv7_a32:O2:lcs_recover fail -> pass
      39_counting_radix_sort:armv7_a32:O2:radix_sort_u32 fail -> pass

and the bias-sensitive fixtures on every configured architecture:

    tools/dectest.py 23_topological_sort 24_merge_sort 141_atomics
      161_packed_struct_layout 162_unaligned_memcpy_access 39_counting_radix_sort
      25_kmp_search 196_disjoint_frame_slots --arch <A>      16 lanes each
        i386           no regressions, 4 improvements (141_atomics x2, 161, 162)
        armv7          no regressions, 2 improvements
        armv7_a32      no regressions, 2 improvements
        aarch64        no regressions, 0 improvements
        x86_64_gcc15   no regressions, 2 improvements

    touch src/lib.rs && cargo build --features python-ext
      never-used FUNCTION count: 0

Two of those four were not on anybody's list. `164_nested_tlv_walker` and
`85_designated_initializers` were failing for the same reason and nothing had
named it, which is the ordinary consequence of a defect that lives in a
COORDINATE rather than in a shape: it has no signature to grep for.

**No baseline was refreshed.** `baseline.json` has four cells to move, all
`gcc:O2`, all `fail -> pass`: the four listed above. `arch_baseline.json` moves
too and by much more — a regeneration run elsewhere counted 23 improvements
across five architectures against the one regression rule 5 now closes.
`structural_baseline.json` was not measured: it builds one `gcc -O0 -g` lane per
fixture, which `@o0` already covers here, but that is an argument, not a
measurement, so it is left unclaimed.

**Blast radius, which is the number this change has to be judged on.** A
`--all --style decbench` render of every function in all 748 lanes, before and
after (14,639 bodies):

      53 bodies differ (0.36%):  gcc:O2 51,  clang:O0 2,  rustc 0

Of those 53, 47 changed which byte-array objects they declare.

The tool's own noise floor was re-measured on this HEAD the way Entry 48
prescribes — the SAME build twice over all 748 lanes — and Entry 52 having fixed
the `HashMap` iteration order, it is now **0 of 14,639**. So the figure above
needs no subtraction, which is the first time a corpus-wide diff in this
directory has been able to say that. Every changed body is in a lane that carries
DWARF aggregates and omits its frame pointer, which is exactly the population the
fix is about. Sampling them, the change is quality-positive rather than merely
neutral:

* `06_calling_conventions:gcc:O2:guarded_spin` — `local_4` becomes `x`. The
  rebase reaches SCALAR hints too, so DWARF source names land where they did not.
* `10_cpp_runtime_shapes:gcc:O2:cpp_virtual_dispatch` — a frame-spanning
  `stack_1[16]` guess becomes two proven 8-byte objects, and the canary goes back
  to being `local_10`.
* `24_merge_sort:gcc:O2:merge_sort_i32` — one 140-byte `local_8c[140]` blob that
  covered `width`, `temp[16]` and the stack canary becomes `int local_8c`,
  `unsigned char local_88[64]` and `long local_40`. It passed before and passes
  after; the old output was right only because every offset was consistent
  INSIDE one fictitious array.
* `134_cpp_virtual_inheritance:clang:O0:*` — `local_30[48]` and `local_38[48]`
  overlapped by 40 bytes over one allocation. Now one object. **Both lanes passed
  before and after**: this is a fixture passing with output that was wrong in a
  way its vectors never exercised.

**Def-before-use census.** `tools/gen_defuse_baseline.py --dry-run` (which
prints and writes nothing) reports `299 violation(s) in 173 of 2598
function-lanes` on the same 748 lanes, agreeing exactly with the snapshot above.
Against the same measurement at `c2fb19d`:

    required violations   317 -> 299   (-18)   in 181 -> 173 function-lanes
    INTRODUCED: 0
    RESOLVED: 9 function-lanes — 111_self_referential_struct:gcc:O2:link_and_sum,
      196_disjoint_frame_slots:gcc:O2:dfs196_alias_control, 16_red_black_tree:gcc:O2:rb_validate
      (3 -> 1), 22_dijkstra, 23_topological_sort, 33_knapsack x2, 35_matrix_chain,
      39_counting_radix_sort
    lane ceilings: gcc:O2 126 -> 108; clang:O0/clang:O2/gcc:O0/rustc:O0/rustc:O2 unchanged

**`defuse_baseline.json` was NOT refreshed.** `2c928d6` had just refreshed it for
the two new fixtures, so it now pins exactly what `3273120` produces — 317
violations across 181 function-lanes — and this change moves it to 299/173.
Whoever ratchets should expect those, with `gcc:O2`'s aggregate ceiling going
126 -> 108 and no other lane moving.

(Measured before `2c928d6` landed, the same delta ran 304/175 -> 299/173, because
the +13 the refresh absorbed is entirely `195_by_value_aggregates` and
`196_disjoint_frame_slots`. Same nine resolved function-lanes either way.)
