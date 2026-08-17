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

## Entry 54 — OPEN: the SSE half of a split-bank return is read out of the integer result

**Status: CLOSED.** Opened before the work, updated as evidence arrived.
Prediction 1 held, prediction 2 was FALSIFIED, prediction 3 held on an
architecture the plan never mentioned. Six cells, zero regressions.
Entries in this file have until now been written after the fact, which makes them
a record rather than a working log — and a record cannot be wrong in public,
which is most of their value.

### The claim to be tested

`src/ir/call_result_split.rs:71` — `result_storage` maps `xmm0` onto the SAME
storage key as `rax` under both x86-64 conventions. The AArch64 and ARM branches
already keep their banks apart, so this reads as an x86-64 gap rather than a
design position. If that is right, a post-call `xmm0` read is rewritten to the
INTEGER call result.

Reported symptom, from the aggregate-return work (`c2fb19d`):
`195_by_value_aggregates:bv195_mixed_roundtrip` renders

```c
(union { unsigned long long bits; double value; }){ .bits = var3 }.value
```

— the SSE half of a 16-byte `{int32_t; double}` return being punned out of the
integer result rather than read from `xmm0`.

### Why now

`abi::ReturnClass::SplitBanks { integer_first }` landed in `c2fb19d` and is
classified but has NO consumer. This defect and that unused variant are one
change: the classifier says which half is where, and `result_storage` is what
currently prevents anyone acting on it. Landing them separately would mean
shipping either an unmeasured storage change or a second dead variant.

### Predictions, recorded before measuring

1. `bv195_mixed_roundtrip` fails on all four host lanes today.
2. Separating the banks alone, without a `SplitBanks` consumer, moves NO cell —
   it converts wrong bytes into an undefined read.
3. The corpus contains other functions reading `xmm0` after a call where the
   callee returns in `rax`; those are where a regression would show up.

Prediction 2 is the one worth being wrong about: if separating the banks alone
DOES move a cell, my model of the defect is incomplete.

### Method

    tools/dectest.py 195_by_value_aggregates --full          # confirm 1
    tools/dectest.py @o0 @o2                                 # 736 host lanes
    tools/dectest.py @aggregates --arch i386 --arch armv7    # 32-bit, where the
                                                             # ABI differs
    tools/gen_defuse_baseline.py --dry-run                   # 299 today

Results and any corrections go below as they arrive.

#### Prediction 1: CONFIRMED

    tools/dectest.py 195_by_value_aggregates --full

    195_by_value_aggregates:clang:O0:bv195_mixed_roundtrip  fail
    195_by_value_aggregates:clang:O2:bv195_mixed_roundtrip  fail
    195_by_value_aggregates:gcc:O0:bv195_mixed_roundtrip    fail
    195_by_value_aggregates:gcc:O2:bv195_mixed_roundtrip    fail

All four host lanes. `bv195_make_mixed` is `structural` on all four — the callee's
own signature is not execution-scored, so this defect is only observable through
the caller, which is why the fixture was built to exercise the helpers through
`int32_t`-returning callers.

#### The code argues the case better than the report did

`call_result_split.rs:69-77`:

```rust
Some(match self.cc {
    CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32 => "rax".to_string(),
    CallConv::Aarch64 => "x0".to_string(),
    // AAPCS hard-float has disjoint integer and FP result banks.  Keep
    // their identities distinct; every call still invalidates all of
    // them before installing its attributed destination below.
    CallConv::Arm | CallConv::ArmHardFloat => base.to_string(),
})
```

The ARM arm keeps `base`, and its comment states the principle: *disjoint integer
and FP result banks keep distinct identities*. SysV amd64 has exactly that
property — `rax` and `xmm0` are disjoint result banks — and collapses them to one
key anyway. So this is not a design position that x86-64 declined; it is a
principle already written down in this function and not applied to the
architecture that also needs it. Win64 has the same shape (`rax`/`xmm0`).

That also sharpens the fix: the ARM branch is the model, and the change is to
stop special-casing the x86 conventions rather than to invent a rule.

#### Prediction 2: FALSIFIED. Separating the banks alone moves a cell

    tools/dectest.py @o0      # separation only, no SplitBanks consumer
    SCOPED: 368 lanes of 748 (49%) — no regressions in scope

    tools/dectest.py @o2      # separation only, no SplitBanks consumer
    IMPROVEMENTS (1):
      181_compensated_summation:gcc:O2:summation_disagrees: fail -> pass
    SCOPED: 368 lanes of 748 (49%) — no regressions in scope, 1 improvement(s)

    tools/dectest.py 181_compensated_summation --full   # same build, one fixture
    IMPROVEMENTS (1):
      181_compensated_summation:gcc:O2:summation_disagrees: fail -> pass

The model was incomplete, and the reason is the second thing one shared key does.
The prediction only accounted for the REWRITE: an `xmm0` read bound to the
integer result, wrong bytes instead of an undefined read, no score either way.
One key also shares the KILL. `result_storage` is what `kill_definition` uses, so
under the collapse any definition of `rax`/`eax`/`ax`/`al` evicts the FLOAT call
result too.

`summation_disagrees` is exactly that, and the machine code says so plainly
(`objdump -d 181_compensated_summation-gcc-O2.so`):

    1202:  call   kahan_sum_f64      # double result -> xmm0
    120d:  xor    %eax,%eax          # an INTEGER definition, unrelated
    1214:  ucomisd %xmm0,%xmm1       # reads the call result

The `xor` sat between the call and the read of its result. Under one key it
evicted the reaching identity, the `ucomisd` operand fell back to the
architectural `xmm0`, and it reached the comparison as a literal zero — the
second call's result was never read at all:

```c
// before: var4 = kahan_sum_f64(...) assigned, then never used
return ((((local_20 == 0) | (local_20 != local_20)) == 0) ? 1 : (local_20 != local_20));
// after
return ((((local_20 == var4) | ((local_20 != local_20) | (var4 != var4))) == 0) ? 1
        : (((local_20 != local_20) | (var4 != var4)) & 255));
```

So the collapse was not merely under-informative about aggregates: an ordinary
`xor %eax,%eax` was deleting a float call result. Separating the banks is a
correctness fix on its own, with no aggregate anywhere near it, and
`181_compensated_summation` is the lane that says so. It is the fixture `abi.rs`
already cites for the i386 x87 version of the same confusion — and the i386 lane
moves too, once the split reaches `Cdecl32` (below).

#### The consumer, and the C it needed

`ReturnClass::SplitBanks` now has one. The shape follows `IntegerPair` exactly:
the class decides the CALL-BOUNDARY SPELLING, and the spelling is what makes the
call site's storage correct.

`rax:rdx` could borrow a builtin — `unsigned __int128` IS INTEGER,INTEGER.
`rax + xmm0` has no builtin, so the tag is synthesised
(`abi::split_bank_return_tag` / `split_bank_return_definition`) and defined at
block scope above the declaration that names it, next to where
`SymbolRecord::required_structs` is emitted. Its members are chosen for their
EIGHTBYTE CLASSES, not for the source fields — `unsigned long` classifies
INTEGER, `double` classifies SSE — so two tags (one per bank order) serve every
aggregate of that shape and no field recovery is required.

The second half is the decomposition, and this is where the renderer's real
limit shows. There is no member-access node for a value base (`Expr` has
`PdbFieldAddr`, which is `p->field` through a POINTER), so `tmp.__sse` is not
sayable. The call's destination therefore becomes a 16-byte frame object and each
bank is read back out of it at the offset the ABI put it — all of which the
existing `StackAddr`/`Bin`/`Deref` nodes already spell, and which the
`stack_objects` collector already declares. `bv195_mixed_roundtrip` at `gcc:O0`:

```c
struct __glaurung_split_is { unsigned long __integer; double __sse; };
extern struct __glaurung_split_is bv195_make_mixed(int);
unsigned char var1[16];
...
*(struct __glaurung_split_is *)(&var1[0]) = bv195_make_mixed(...);
var5 = *(long *)((&var1[0] + 8));          // the SSE eightbyte, as raw bytes
*(int *)(&local_10[0]) = *(long *)(&var1[0]);   // the INTEGER eightbyte
*(long *)((&local_10[0] + 8)) = var5;
```

Reading the SSE eightbyte as eight raw bytes is exact rather than a shortcut: a
float consumer reinterprets those bits back, which is precisely what the machine
`movsd` store did. The bit-pun the old output performed was not wrong because it
was a pun; it was wrong because it punned the WRONG EIGHT BYTES.

#### Prediction 3: confirmed, on the architecture I was not looking at

    tools/dectest.py 172_float_double_widths 173_float_int_conversions \
      174_float_compare_classify 175_float_matrix_kernel 181_compensated_summation \
      --arch i386 --arch armv7 --arch aarch64 --arch armv7_a32

    REGRESSIONS (1):
      175_float_matrix_kernel:aarch64:O0:dot_product_f32: pass -> fail
    IMPROVEMENTS (1):
      181_compensated_summation:i386:O2:summation_disagrees: fail -> pass

"The corpus contains other functions reading the other bank after a call" was
right, and the first attempt keyed the storage on the machine model's bank class
for EVERY convention — which separated AArch64's `x0` from `v0`/`d0`/`s0` too.
`dot_product_f32` is the function `abi.rs` already names for consuming a call
result through a bank the call was not attributed to, and on AAPCS64 there is
nothing to re-attribute it FROM: `wide_integer_return_pair` and
`declared_return_class` are both System V only. Separation without a class to
repair it with is a regression, not a fix.

So the AArch64 arm keeps its collapse, with the measurement recorded in the code
next to it. Fail closed: separate the banks where a class can put the other half
back, and nowhere else. Three lanes stayed clean under this scope — no
regressions on `@aggregates @structs` across i386, armv7 and aarch64 (72 lanes).

#### Where the six cells came from

Two changes, one increment, and the split of credit is worth keeping:

| cells | cause |
|---|---|
| `181_compensated_summation:gcc:O2:summation_disagrees` | bank separation alone (x86-64) |
| `181_compensated_summation:i386:O2:summation_disagrees` | bank separation alone (`Cdecl32`, `rax` vs `st0`) |
| `bv195_mixed_roundtrip` x4 | the `SplitBanks` consumer, which the separation made reachable |

The two halves really were one change: the consumer cannot bind an `xmm0`
identity while `xmm0` resolves to `rax`, and the separation on its own leaves the
aggregate lane failing (measured above — it moved 195 by exactly zero cells).

#### Verification

    cargo test --features python-ext          2587 passed; 0 failed
                                              (2583 at 5230a35, plus the 4 added here)
    tools/dectest.py 195_by_value_aggregates --full
        4 improvements, 0 regressions (40 cells: 10 functions x 4 host lanes)
        bv195_mixed_roundtrip pass on all four; bv195_big_roundtrip still fails
        on all four, for the reason Entry 53 established and not this one
    tools/dectest.py @o0                      368 lanes, 2 improvements, 0 regressions
    tools/dectest.py @o2                      368 lanes, 3 improvements, 0 regressions
    tools/dectest.py @aggregates @structs --arch i386 --arch armv7 --arch aarch64
                                              72 lanes, 0 regressions
    tools/dectest.py 172_… 173_… 174_… 175_… 181_… --arch i386 --arch armv7
      --arch aarch64 --arch armv7_a32         40 lanes, 1 improvement, 0 regressions
    tools/gen_defuse_baseline.py --dry-run    299 -> 299 (no delta)
    touch src/lib.rs && cargo build --features python-ext
                                              0 never-used functions (unchanged)

Baselines are NOT refreshed here; the six moved cells are listed above so the
regeneration is a separate, reviewable step.

#### What this did not close

- **The MEMORY lane.** `bv195_big_roundtrip` still fails on all four host lanes.
  Entry 53 established it is not an ABI defect at all, and nothing here touches it.
- **Win64.** It has the same `rax`/`xmm0` shape and now gets the same separation,
  but `declared_return_class` refuses every non-System-V convention, so it can
  never reach the consumer. There are no Windows fixtures to measure a change
  against; the refusal stays.
- **AArch64.** Its banks are disjoint and it keeps the collapse anyway, because
  the class that would repair the separation does not exist for AAPCS64. That is
  now a recorded cost with a named lane rather than an unexamined default.
- **Member access.** The frame-object decomposition exists because `Expr` has no
  value-base member node. It is exact, but it is a workaround, and it is the same
  gap EPIC 6's "project solved access paths" item names.

---

## Entry 55 — OPEN: the CFG says "I truncated this" and the only caller that matters writes it to `_`

**Status: OPEN.** Written before the work, with predictions recorded in advance
so they can be wrong in public. Entry 54 is why: a prediction I recorded there
was falsified, and the falsification was worth more than the fix.

### The premise I was given, and the measurement that corrected it

My own todo carried this as *"a wall clock silently truncates the CFG —
`Budgets::timeout_ms` sets `hit_timeout` before truncating; nothing reads it;
`decompile_range` runs at 500 ms."* The second and third clauses survive
measurement. **The first does not.**

```
uv run python $CLAUDE_JOB_DIR/tmp/measure_timeout.py
binary                  budget  wall_s   funcs  truncated / which
NETwtw10.sys              5000    9.68   12185  False  []
NETwtw10.sys               500    9.55   12185  False  []
NETwtw10.sys               100    9.57   12185  False  []
xrt_coreutil.dll          5000    7.37    8634  False  []
xrt_coreutil.dll           500    7.37    8634  False  []
xrt_coreutil.dll           100    7.37    8634  False  []
```

A 4.9 MB driver, 12,185 functions, 9.6 s of wall clock — and moving the
per-function budget by 50x changes neither the function count nor the runtime by
a measurable amount. `hit_timeout` never fires, because the clock is **per
function** and restarts on every seed (`src/analysis/cfg.rs:1374`, and the
roadmap's own performance box already says so: `timeout_ms` "has never bounded an
analysis"). The wall clock is not the truncation that bites. Chasing it would
have been a day spent on a limit that has never fired.

### The limit that does bite

```
uv run python $CLAUDE_JOB_DIR/tmp/measure_limits.py
NETwtw10.sys           funcs= 12185  max_blocks_seen=  643  >256:9  >4096:0
xrt_coreutil.dll       funcs=  8634  max_blocks_seen=  766  >256:7  >4096:0
hello-go               funcs=  1522  max_blocks_seen=  203  >256:0  >4096:0
```

`max_blocks`. Sixteen functions across two shipped Microsoft/AMD binaries exceed
the 256-block default that `decompile_range_at` hardcodes
(`src/python_bindings/ir.rs:1291`); none exceeds `decompile_at`'s 4096.

### The defect, reproduced on the shipping API

```
uv run python $CLAUDE_JOB_DIR/tmp/measure_truncation_visible.py
target 0x1401fd8a0  blocks_at_2048=643
  max_blocks= 4096  cfg_blocks=643  truncated_flag=False ([])                decompiled_chars=153068  says_truncated=False
  max_blocks=  256  cfg_blocks=256  truncated_flag=True  (['hit_block_limit'])  decompiled_chars= 61942  says_truncated=False
  max_blocks=   64  cfg_blocks=64   truncated_flag=True  (['hit_block_limit'])  decompiled_chars= 17833  says_truncated=False
```

387 of 643 blocks disappear. The rendered body loses 60% of its characters. The
CFG layer **knows** — `hit_block_limit` is set, and the `analyze_functions_*`
Python bindings report a `truncated` field built from exactly this
(`src/python_bindings/analysis.rs:581`). The decompiled text contains no marker
of any kind. An analyst reading that output cannot tell they are holding 40% of a
function.

This is stop condition 1 verbatim: *incomplete input becoming apparently complete
downstream.*

### Where it is severed, to the line

`src/analysis/cfg.rs:4351`:

```rust
let (functions, cg, _stats) = analyze_functions_bytes_within(...);
```

`analyze_functions_image_with_seeds` is the **only** discovery entry point the
decompiler uses — `ProgramSession::discover_functions` (`src/program/session.rs:272`)
calls it, and `decompile_at_session`, `decompile_many` and `list_functions` call
that. Every truncation flag dies on that underscore.

The struct being discarded documents the rule the discard breaks
(`src/analysis/cfg.rs:203`):

> A consumer that treats this result as a complete function list is wrong, which
> is why it is reported rather than absorbed.

It is reported. Then it is absorbed, by the one caller that feeds the product.

### Which box this is

Not a new one. `[~]` **"Carry typed diagnostics/completeness through discovery,
lifting, recovery, HIR, and rendering."** Its 2026-08-15 audit found four
stage-local typed signals and no carrier, and named lifting's `LiftError` as the
first step. This is the *discovery* half of the same box, and unlike the lifting
half it now has a reproduction.

### Predictions, recorded before the work

1. **Per-function attribution already exists internally and is destroyed in the
   merge.** `SingleFunctionDiscoveryStats` is per function
   (`src/analysis/cfg.rs:224`) and `merge_single_function_stats` ORs it into a
   whole-run aggregate. So today the flag cannot even say *which* function was
   truncated — reporting the aggregate against a specific function would mark
   clean functions as incomplete. Adding the entry VA at the merge site is
   mechanical.
2. **No fixture cell moves.** This is an architecture-track change: the boundary
   holds and zero cells are expected. Every fixture function is far under 256
   blocks. To be checked, not assumed.
3. **`hit_total_timeout` must not be attributed per function.** It stops *seed
   discovery*, so the function list itself is short — a whole-run fact with no
   owning function. If the design tries to hang it on a VA it will be wrong.
4. **The one I am least sure of, and want measured rather than taken.** I expect
   threading stats through `ProgramSession::discover_functions` to cost a widened
   `DiscoveryCache` value type (it stores `Arc<[Function]>`), and I expect
   recording the truncation *on the `Function`* to be smaller — but `Function` is
   a core data model with PyO3 bindings and serialization, so its blast radius may
   be larger than the cache's. **Measure both and report which is smaller. Do not
   take my guess.**

### Done means

A truncated function's rendered output says so, the untruncated function beside
it in the same run does not, and a test on a real sample proves both.

### Appended during the work — prediction 2 is already falsified

Prediction 2 said "every fixture function is far under 256 blocks." It is wrong,
and the correction made the test design better than the brief that preceded it.

```
uv run python $CLAUDE_JOB_DIR/tmp/fixture_blocks.py
fixture objects scanned: 766
  1457 blocks  151_wide_branch_ladder-clang-O0.so  big151_branch_ladder
   984 blocks  151_wide_branch_ladder-gcc-O0.so    big151_branch_ladder
   715 blocks  154_wide_switch-clang-O0.so         wide154_dense_effects
   602 blocks  154_wide_switch-clang-O0.so         wide154_sparse_switch
functions over 256 blocks: 15
functions over  64 blocks: 21
```

Fixtures 151 and 154 were built wide on purpose. `big151_branch_ladder` at 1457
blocks sits only 2.8x under `decompile_at`'s 4096 default — much less headroom
than "far under."

The consequence is a better test than the one I specified. `151_wide_branch_ladder-clang-O0.so`
holds a 1457-block function *and* small ones, so a budget that truncates only the
big one gives the **no-contamination** case directly: assert the small function's
output carries no marker while the big one's does. That test is in-tree,
deterministic, and runs in seconds. I asked for it against a 4.9 MB Windows
driver because I had not measured the corpus I already own.

### Appended during the work — the consumer that makes this a correctness bug

`python/glaurung/llm/finding_verifier.py:139`:

```python
text = g.ir.decompile_at(
    self.binary_path, va,
    timeout_ms=5_000, max_blocks=256, max_instructions=2_000,
    types=True, style="",
)
```

The vulnerability-finding verifier runs at **256 blocks and 2,000 instructions** —
below both thresholds the reproduction truncates at. A verifier reasoning about
40% of a function while believing it holds all of it will clear a finding whose
evidence sat in the discarded part. Budgets across shipping callers
(`grep -rn "max_blocks" python/glaurung/ --include=*.py`): 256/2,000 in
`finding_verifier.py`, 512 in `windows_api_contract_primitives.py`, 1,024 in
`windows_project_zero_length_write_paths.py` and `windows_function_pretty_lift.py`,
2,048 in `llm/context.py` and `llm/evidence.py`.

### Appended during the work — the honest rate, so this is not oversold

```
uv run python $CLAUDE_JOB_DIR/tmp/measure_instr.py
NETwtw10.sys           funcs= 12185  max_instr= 3989  >2000instr:5  >256blk:9  either: 10 (0.08%)
xrt_coreutil.dll       funcs=  8634  max_instr= 2776  >2000instr:5  >256blk:7  either:  9 (0.10%)
win11-webservices.dll  funcs=  4909  max_instr=15169  >2000instr:1  >256blk:2  either:  2 (0.04%)
hello-go               funcs=  1522  max_instr= 1054  >2000instr:0  >256blk:0  either:  0 (0.00%)
```

**0.04%–0.10% of functions.** Roughly ten per large binary. The case for fixing
it is not the rate. It is that the affected set is systematically biased toward
the largest and most complex functions — the ones an analyst or a vuln-hunting
agent is most likely to be looking at — and that the failure is silent wrongness
rather than an error. Stated as a rate this looks negligible; stated as "the ten
functions you most wanted to read are the ten we quietly halve" it does not.

---

## Entry 56 — OPEN: a fixture for the return class `195` left out, and it found two defects on its first run

**Status: OPEN.** The lane exists and fails; nothing is fixed yet. Written as the
evidence arrived.

### The gap, found by census rather than by theory

`195_by_value_aggregates` covers SysV's INTEGER (`rax`), INTEGER-pair
(`rax:rdx`), split-bank (`rax`+`xmm0`) and MEMORY classes. It has **no all-SSE
case**, so nothing in the corpus returned a value in `xmm0:xmm1` — two SSE
registers holding one value, which is a different contract from the split case
and from a scalar `double`.

The same structs are a different mechanism entirely on AArch64, and the corpus
had no lane for that at all. AAPCS64 returns a *homogeneous float aggregate* in
consecutive SIMD registers.

**Verified by disassembling both targets rather than from memory** — the whole
point of the fixture is the ABI contract, so asserting it from recollection would
have been the same mistake this diary keeps recording:

```
gcc -O1 -c 197_homogeneous_float_aggregates.c && objdump -d
  make_pair2d   movq %xmm0,%rax / movq %xmm1,%rdx ... -> xmm0:xmm1
  make_quad4f   shl $0x20,%rsi / or %rsi,%rcx / movq %rcx,%xmm1  -> TWO floats packed per xmm
  make_tagged   movd %xmm0,%eax / or %rdi,%rax  -> rax ALONE, float bit-packed in

aarch64-linux-gnu-gcc -O1 -c ... && aarch64-linux-gnu-objdump -d
  make_pair2d   scvtf d0,w1 / scvtf d1,w0        -> d0,d1
  make_quad4f   fmov s0,w3 / s1,w2 / s2,w0 / s3,w1 -> FOUR registers, one value
  make_tagged   bfxil x0,x2 / bfi x0,x1          -> x0 ALONE
```

Same struct, same source: SysV packs `{float x4}` into two registers, AAPCS64
spreads it across four. A recovery that models "the float result" as a single
register is wrong on both, differently, and nothing in the corpus could say so.

### First run, x86-64

```
GLAURUNG_FIXTURE_TMPDIR=... tools/dectest.py 197_homogeneous_float_aggregates --full
  clang:O0  pair2d fail  quad4f fail  trio3f fail  tagged fail  scalar PASS
  clang:O2  pair2d fail  quad4f fail  trio3f fail  tagged PASS  scalar PASS
  gcc:O0    pair2d fail  quad4f fail  trio3f fail  tagged PASS  scalar PASS
  gcc:O2    pair2d fail  quad4f fail  trio3f fail  tagged fail  scalar PASS
```

12 of 20 cells fail, and **the discrimination is exactly what the fixture was
built for**: `hfa197_scalar_control` — a plain `double` return — passes on all
four lanes, so this is not "floats are broken." The three all-SSE positives fail
on all four lanes. The corpus could not previously distinguish those two claims.

### Defect 1 — the second SSE result register is read from nowhere

`197:gcc:O2:hfa197_trio3f_roundtrip`, our C:

```c
extern long hfa197_make_trio3f(int);     /* declared SCALAR */
var1 = hfa197_make_trio3f(...);
local_14 = var1;
local_10 = var2;                          /* var2  is NEVER DEFINED */
...
var5 = ... var6 ...;                      /* var6  is NEVER DEFINED */
```

The callee returns in `xmm0:xmm1`; the recovery models one result register, so
the second and third members come from undefined variables. This is the same
shape as the split-bank defect closed in `7105e26`, one class over: that one was
`rax`+`xmm0`, this one is `xmm0`+`xmm1`. `declared_return_class` has no all-SSE
case to produce.

### Defect 2 — an unlifted instruction becomes a comment, and the old value flows on

This one is unrelated to aggregates and is the more interesting find.
`197:gcc:O2:hfa197_tagged_control` — the NON-homogeneous control, which returns in
`rax` alone and should have been the easy case:

```c
var1 = hfa197_make_tagged(...);
local_c = var1;
/* asm: cvttss2si(...) */                 /* <- the conversion, as a COMMENT */
var4 = ((long)(var1) >> 32);              /* tag: correct */
*(int *)((var0 + 0x4)) = var4;            /* correct */
*(int *)((var0)) = var1;                  /* WRONG: raw float BITS, not (int)value */
return (unsigned int)(((var1 + (var1 * 2)) + var4));   /* bits*3 + tag */
```

The machine code (`gcc -O2 -c … && objdump -d`):

```
movd      %eax,%xmm0        ; float bits out of rax's low half
cvttss2si %xmm0,%eax        ; float -> int
sar       $0x20,%rcx        ; tag
movd      %ecx,%xmm1
movd      %eax,%xmm0
punpckldq %xmm1,%xmm0       ; interleave both 32-bit lanes
movq      %xmm0,(%rdx)      ; ONE 8-byte store covering both scratch slots
```

`cvttss2si` lowered to `Stmt::Unknown`, which `src/ir/ast.rs:11298` renders as
`/* asm: … */`. The mnemonic **is** lifted (`src/ir/lift_x86.rs:4208`,
`src/ir/ast.rs:1047`), so this is a lowering decline on this operand shape, not a
missing capability — a capability census would have said "covered."

The comment is honest about the instruction. It is silent about the
**consequence**: the value the instruction was supposed to produce is quietly the
value from before it, so the emitted C compiles, runs, and is wrong. That is the
same shape as Entry 55's truncation — a step that knows it is incomplete, feeding
a downstream that cannot tell — and it is what Design Rule 8 exists to forbid.

It is also the argument for execution-differential fixtures in one screen: this
output is plausible, well-formed, type-correct C. Only running it catches it.

### What is deliberately not claimed yet

- **The AArch64 lane does not exist yet.** `tools/dectest.py --arch aarch64`
  sources its function list from `arch_baseline.json` alone, so the HFA half of
  this fixture — the whole reason for the four-`s`-register case — is unmeasured
  until the baselines are refreshed. The disassembly above proves the ABI; it
  does not prove what we recover from it.
- **No fix is attempted here.** The lane is being recorded failing, exactly as
  `bv195_big_roundtrip` was, so any later fix shows up as cells moving rather
  than as a baseline edit.

### Appended — the mechanism, and a correction to what I wrote above

Entry 56 called these "two distinct defects" and said defect 2 was "unrelated to
aggregates." **The second half of that is probably wrong**, and the part I can
prove is more interesting than the part I guessed.

What is established, by reading the path the output proves it took:

1. The decline is at **`src/ir/ast.rs:1897`**, not at the lifter. A scalar-float
   `Convert` only lowers when `lower_scalar_float` is true:

   ```rust
   if lower_scalar_float || matches!(operation, Move | Negate) { … }
   ```

   `cvttss2si` is lifted (`src/ir/lift_x86.rs:4208`) and tabled
   (`src/ir/ast.rs:1047`), and `scalar_convert_ops` gives it exactly one input,
   so the `(Convert, [src])` arm would have matched. The instruction is fully
   modelled; the *gate* is shut.

2. **The gate is whole-function and all-or-nothing.**
   `lower_scalar_float = scalar_float_semantics_are_closed(lf)` is computed once
   per function in `lower_on_this_stack` (`src/ir/ast.rs:3306`) and threaded
   unchanged through every `lower_region`/`lower_block`/`lower_op` call. One
   unmodelled float producer anywhere in a function therefore costs that whole
   function its float arithmetic. This is not a hypothesis about the design — the
   proof's own comment says so, and names the case:

   > treating one as opaque costs the whole function its float arithmetic —
   > `dot_product_f64` reduced to `/* asm: mulsd */ /* asm: addsd */` purely
   > because it also called a bounds check that returns an `int`.

3. The emitted spelling confirms which branch ran. `Stmt::Unknown` is formatted
   `"{name}(...)"` only when `ins` is non-empty (`src/ir/ast.rs:1936`), and the
   output is `/* asm: cvttss2si(...) */`. So it fell through the gate rather than
   failing the arm match.

What is **not** established, and what I stopped short of asserting: *which* op in
`hfa197_tagged_control` trips the proof. I checked the obvious candidates against
`unmodelled_x86_float_mnemonic` by hand and none of them should trip it —
`punpckldq` starts with `pu`, so `starts_with("unpck")` is false, and it ends in
`dq`, which is not in `["ss","sd","ps","pd"]`; `movd`/`movq` likewise. The
`Op::Call` arm should not fire either, because `float_registers_are_all_caller_saved`
is satisfied the moment any `xmm` appears, and this body is full of them.

So by inspection it should NOT decline, and it does. That gap is the actual
finding, and it needs instrumentation rather than more reading. Recording it
unresolved is the point: the lane distribution is a clue I would otherwise have
smoothed over —

```
clang:O0 tagged FAIL   clang:O2 tagged PASS
gcc:O0   tagged PASS   gcc:O2   tagged FAIL
```

— two compilers disagreeing in opposite directions at opposite optimisation
levels, which is not the signature of a missing mnemonic.

### Why this is one defect and not two, most likely

If the trip is the unmodelled all-SSE aggregate return (defect 1), then defect 2
is defect 1 at one remove: the packed return leaves a float producer unmodelled,
the whole-function proof shuts, and every float conversion in that function
becomes a comment. That would explain why the *control* — the one function here
whose return is a plain `rax` — still failed: it calls a helper whose return the
recovery cannot spell.

I am not claiming that yet. It is the first hypothesis to test, and it is
testable: model the all-SSE return class and see whether the `/* asm: cvttss2si */`
comments disappear without anyone touching the lifter.

### The part that stands regardless of the mechanism

Whatever shuts the gate, the consequence is the same and is the thing to fix:
`Stmt::Unknown` **drops the assignment**, so the destination silently keeps its
previous value, and the emitted C compiles, runs, and is wrong. The comment is
honest about the instruction and silent about the value. A declined lowering
should leave an explicit unknown in the value, per Design Rule 8 — the same
demand Entry 55 makes of a truncated CFG.

### Appended — the hypothesis I stated one section ago is already weakened

I wrote, above, that the first hypothesis to test is "the trip is the unmodelled
all-SSE aggregate return." A cheap measurement makes that unlikely, and it costs
less to say so now than to let an agent spend an afternoon on it.

```
gcc -O0 -c 197_homogeneous_float_aggregates.c && objdump -d   # the lane that PASSES
hfa197_tagged_control mnemonics: 14 mov, 3 add, 2 movss, 2 cvttss2si, sub, ret,
                                 push, leave, lea, jne, jmp, endbr64
```

At `-O0` the function contains **the same `cvttss2si`** and **the same aggregate
return from the same callee** — and it passes. The gate is open there. So the
aggregate return cannot be what shuts it.

The difference is entirely in the `-O2` instruction set: `punpckldq`, `movd`,
`movq %xmm0,(%rdx)` replace the `movss`/`mov` traffic. The trip is among those,
not in the return class.

Which returns the mystery to where it was, but smaller and better bounded: none
of those three passes `unmodelled_x86_float_mnemonic` either — `punpckldq` starts
`pu` so `starts_with("unpck")` is false and it ends `dq`, not in
`["ss","sd","ps","pd"]`; `movd`/`movq` likewise — and `cvttss2si` still sets
`saw_scalar_float`, so the proof should return true. It does not.

**Consequence for the plan: #46 is not blocked on #45, and should not be
sequenced behind it.** I had recorded exactly that dependency an hour ago on the
strength of a hypothesis I had not tested. The two defects are independent until
something shows otherwise, and the O0/O2 split is the handle to pull on.

### Appended — four probes that do NOT reproduce it, which is the useful part

Having said the gate question needs instrumentation, I tried to shortcut it with
minimal probes instead. All four failed to reproduce, and my reading of the
mechanism is now falsified twice over. Recording them so the next person does not
spend the same hour.

```
gcc -O2 -fPIC -shared probe*.c   +   g.ir.decompile_at on each
probe_packed      cvttss2si, plain stores                    -> fully lowered
probe_unpacked    cvttss2si, distant stores                  -> fully lowered
probe_punned      movd + cvttss2si, 64-bit float/int pun     -> fully lowered
probe_nofloat     no float at all                            -> fully lowered
probe_two_conv    cvttps2dq + unpcklps + pshufd + movd/movq  -> fully lowered
probe_mixed       cvttss2si AND cvttps2dq AND unpcklps       -> fully lowered
probe_scalar_only cvttss2si alone                            -> fully lowered
```

`probe_mixed` is the one that matters. It puts a modelled scalar `cvttss2si` in
the same function as `cvttps2dq` and `unpcklps` — and **both of those satisfy
`unmodelled_x86_float_mnemonic`** (`cvt` is in `OPAQUE_PREFIXES`; `unpcklps` both
starts with `unpck` and ends with `ps`). By my reading of
`scalar_float_semantics_are_closed` that function should have gone entirely
opaque. It lowers cleanly.

So the trip is **not** "an opaque-named float mnemonic appears in the function."
Either the lifter never emits those names as `Op::Intrinsic`/`Op::Unknown` — it
may decompose them into typed ops, in which case the proof never sees the string
— or the proof does something other than what its source reads like to me.

**Two things I got wrong here, both worth keeping:**

1. I predicted the aggregate return shut the gate. The `-O0` lane disproved it.
2. I predicted an opaque-named packed op shuts the gate. `probe_mixed` disproved
   it.

The honest position is that I do not know what shuts it, and
`197:gcc:O2:hfa197_tagged_control` is currently the only known reproduction. That
is a good place to stop guessing: the fixture is the instrument, which is the
argument for having built it. What is needed next is a dump of the actual
`Op` stream for that one function — not more reading of the proof, and not more
probes.

---

## Entry 57 — Three gates that did not gate

A day of agent work turned up three separate cases of a check that everyone
believed was running and was not. None was found by looking for them; each fell
out of trying to satisfy the check honestly.

**Bookkeeping note, since this file is the record:** the ruff configuration and
the gate-script change described below were swept into commit `3b437b1`
("cfg: a bounded walk now says so"), whose message does not mention them. That is
a mixed commit and a process slip. Recording it here rather than rewriting three
commits to tidy it.

### 1. `cargo test` without `--features python-ext`, in the pre-push gate itself

`scripts/decbench-local-gate.sh:121` ran `cargo test --lib --tests`. Its own
header calls lane 1 "the only lane that gates the Rust logic." Without the
feature, `src/python_bindings/` is not merely untested — it is **not compiled**.
CLAUDE.md has warned about this since 2026-08-14, when a signature change there
left five call sites on the old arity and a bare `cargo test` reported
`2321 passed; 0 failed`. The warning lived in the guidance; the script that
enforces the gate did not have it. Both live docs (`decompiler-roadmap.md`'s
broad gate and `docs/development/setup.md`) said the same wrong thing, fixed in
`c3e92a9`.

Measured live during today's split, which is the cleanest demonstration I have
seen of why it matters:

```
cargo build --features python-ext  | grep -c "never used"   ->  0
cargo build                        | grep -c "never used"   -> 97
```

### 2. The gate could not fail on an ordinary test, and `master` was red

Lane 2 runs `pytest -m slow`. Nothing in the gate ran the *default-selected*
Python tests at all. So when `b423297` broke two tests in
`test_decompiler_session.py` at 00:03 this morning — tests added six days earlier
in `ae88988` specifically to pin the discovery cache's hit accounting — every
gate stayed green while `master` was red for nineteen hours.

A `1b` lane now runs the not-slow, not-corpus Python tests. **It costs 13m08s**
(measured; `real 13m8.429s`), which is not nothing on a gate that is already
~50 minutes, and a large share of it is benchmark tests that have no business in
a correctness gate. That is a follow-up, not a reason to leave the hole open.

### 3. `ruff` was never configured, so the gate was both impossible and unstable

CLAUDE.md requires ruff and ty before claiming a change is done. No ruff
configuration existed anywhere in the repo — no `[tool.ruff]`, no `ruff.toml`:

```
uvx ruff --version              -> 0.16.3        (uvx resolves LATEST, every run)
uvx ruff check python/          -> 3507 errors, 413 rules enabled
uvx ruff format --check python/ -> 305 files would be reformatted
```

Two problems, and the second is worse than the first. Unachievable is obvious:
nobody was going to bury a change under a 305-file reformat, so everyone quietly
skipped the step — two agents today independently reported doing exactly that,
which is how it surfaced. **Non-deterministic** is the real defect: with no
`select`, the verdict is whatever the latest ruff defaults to, so the gate could
change with no commit in this repo. That is the same shape as defect 1 — a
command that does not do what the document says it does.

`[tool.ruff]` now pins `select = ["E4","E7","E9","F"]` with an `ignore` list that
is explicitly **debt, not policy**: each entry carries its measured count so the
backlog is visible in the file that enforces it. `uvx ruff check python/` now
passes.

The one finding worth acting on immediately was fixed: a redundant
re-import of `get_config` shadowing the module-level import in
`suggest_function_name.py`. The seven `F821`s are all string annotations naming a
type the module never imports — `binary_diff.py` annotates
`Optional[Dict[str, "FunctionStructure"]]` while that class lives in
`structural_fingerprint.py` and is imported nowhere, not even under
`TYPE_CHECKING`. No runtime error, because the annotation is never evaluated, and
no type checker can resolve it either. An annotation that asserts something
nothing verifies.

Still open, and deliberately not done mid-flight: `ruff format` remains 315 files
out of line, and `ty check python/` reports 2002 diagnostics on the untouched
tree. Both need their own decision.

### The pattern

Each of these is the same failure at a different scale: a **stated** gate and an
**executed** gate that had drifted apart, with nobody able to see the gap because
the stated one is what everyone reads. The roadmap's own habit line covers it —
"a number in a document is not a measurement, write the command next to the
number" — but a *command* in a document is not a gate either. The gate is what
the script runs.

---

## Entry 58 — The fast loop hid two defects, in exactly the window where it is used most

Fixture 197's first baseline refresh (`f1851d5`) added four lanes and 44 cells —
20 `structural`, 18 `fail`, 6 `pass` — and changed nothing else: every
pre-existing shared lane kept its identical verdict, and no lane was removed.
Verified rather than assumed, because a regeneration is exactly where an
unrelated regression gets quietly baked in.

The interesting part is that **18 fail is more than the 12 I reported yesterday**,
and the extra six are in functions I could not see.

### The blind spot, confirmed in both directions

`tools/dectest.py --full` resolves its function list from
`lane_function_universe()` (`tools/dectest.py:158`), which is the union of
`M.REQUIRED_FUNCTIONS` **and whatever the baseline already observed**. For a
fixture with no baseline entry yet, that union is just the required list.

Fixture 197 declares five required functions and contains eleven. So:

```
before the refresh:  tools/dectest.py 197… --full   ->  5 functions per lane
after  the refresh:  tools/dectest.py 197… --full   -> 11 functions per lane
```

Both measured. This is not a permanent gap — it closes on the first refresh —
but it is open during precisely the window in which someone is iterating on a
new fixture and most wants the feedback. I wrote 197's helpers deliberately, ran
the fast loop, saw five verdicts, and reported "12 of 20 cells fail" as though
that were the fixture's full result. It was 18 of 44.

### Defect 1 — a signed integer becomes unsigned on its way to a double

`hfa197_make_scalar`, failing on all four lanes:

```c
source:  return (double)(seed * 6 + 1);
ours:    return (double)((unsigned long)((unsigned int)(…)));
```

Every intermediate is spelled unsigned before the conversion, so a negative
result converts to a huge positive double. At `seed = -1` the source returns
`-5.0` and the recovery returns `4294967291.0`. The fixture's vectors include
`-1` and `-4`, which is why it is caught.

Note which function this is. `hfa197_scalar_control` — the *required* one —
passes on all four lanes, because it returns `int32_t` and never performs an
int-to-double conversion. The helper it calls is the one that does. I added that
helper purely as a negative control for the return-bank work, and it found an
unrelated defect on a path nothing else in the corpus exercises.

### Defect 2 — a function returns its own argument instead of the call result

`172_float_double_widths:gcc:O0:double_precision_horner`, pre-existing and
previously unexplained:

```c
source:  return fp172_horner_f64(x, a, b);

ours:    extern long fp172_horner_f64(double);   /* ONE parameter, not three */
         ret   = arg0;
         var25 = fp172_horner_f64(arg0);         /* result DISCARDED */
         return <ret bits as double>;            /* returns x, the INPUT */
```

Three faults compounding: a float-argument callee loses two of its three
parameters, the call result is dropped, and the function returns its own first
argument. The emitted C compiles, runs, and returns the input — the same shape as
Entry 56's `Stmt::Unknown` defect, and the same reason execution-differential
testing exists.

### Two defects, not one, and I checked the harness before blaming the product

The corpus-wide pattern is "functions returning a floating-point value fail," and
filing that as a single cause would have been easy and wrong: defect 1 has no
call in it at all, and defect 2 has no int-to-float conversion.

The harness is not the explanation either. `tools/diff_decompile.py` compares
floating-point results **by bit pattern** via `float_bits`, deliberately, with
recorded reasoning about `-0.0` and NaN — so a float return is fully comparable
and these cells fail because the output is wrong. Worth checking before
attributing 435 failing cells to a comparator.

---

## Entry 59 — The casts that make the arithmetic right make the conversion wrong

Located `hfa197_make_scalar`'s failure (Entry 58, defect 1) without writing any
code. The interesting part is that my first diagnosis was wrong in a way that
would have sent the fix to the wrong place.

### What the symptom suggested, and why that was wrong

```c
source:  return (double)(seed * 6 + 1);
ours:    return (double)((unsigned long)((unsigned int)(…)));
```

Read alone, this says "signed-to-double conversion is broken." It is not. The
machine is unambiguous —

```
gcc -O0 -c 197_homogeneous_float_aggregates.c && objdump -d
  cvtsi2sd %eax,%xmm0
```

— `si` means *signed integer*, and the HIR keeps it: `lower_scalar_conversion`
(`src/ir/ast.rs:782`) builds `NumericConvert { from: SignedInt(4), to: Float(8) }`.
The signedness survives all the way to the renderer.

The measurement that corrected me is a sibling fixture that has been passing all
along:

```
173_float_int_conversions:*:*:widen_int_to_float     PASS on all four lanes
    float widen_int_to_float(int32_t value) { return (float)value; }
173_float_int_conversions:*:*:widen_long_to_double   PASS on all four lanes
197_homogeneous_float_aggregates:*:*:hfa197_make_scalar   FAIL on all four
    return (double)(seed * 6 + 1);
```

A **bare** operand converts correctly. Only an **arithmetic** one fails. If
signed-to-float were broken, `widen_int_to_float` would be the first casualty and
it has never failed.

### The actual cause, `src/ir/ast/dec_render.rs:774`

```rust
Expr::NumericConvert { from, to, expr } => {
    let _ = write!(out, "({})(", to.c_name());
    if from.is_float() {
        write_float_expr_dec(expr, from.width(), out);
    } else {
        write_expr_dec(expr, out);        // <-- the signed-int path
    }
    out.push(')');
}
```

`from` is consulted only to choose float-or-not. On the integer path the operand
goes through `write_expr_dec`, which wraps integer arithmetic in
`(unsigned int)`/`(unsigned long)` machine-width casts — **correct, and necessary
for wraparound** — and then `(double)` converts an expression whose C type is now
unsigned. A bare register operand gets no wraparound cast, which is exactly why
the simple case survives.

So the defect is not in the conversion and not in the wraparound casts. It is
that the two are individually right and compose wrong, and nothing in between
notices that the operand's C type changed under the conversion's feet.

Both other renderers have the same shape and ignore `from` entirely
(`src/ir/ast.rs:4062` ctx, `:4729` c); whether they can reach the bug depends on
whether they emit the wraparound casts, which is a measurement not yet taken.

### Why this is written down before it is fixed

The fix is three lines and I am not making it yet: an agent is mid-flight
splitting the ctx renderer out of `ast.rs` and owns one of the three sites. What
would be lost by waiting is the diagnosis, not the code — so the diagnosis is
here, with the measurement that produced it and the wrong turn it corrected.

---

## Entry 60 — The gate we trust recorded a failure that was not there

Fixture 197 is now baselined on all four baselines. Getting the fourth one right
took two attempts, and the discarded attempt is the more useful half.

### The near-miss

The first `arch_roundtrip.py --write-baseline` recorded
`112_recursion_shapes:armv7_a32:O2:tail_countdown` as `pass -> fail`. Three
things said not to believe it:

```
git log over arch_baseline.json, last 14 regenerations   ->  pass, every one
                                                             (back to 2026-08-13)
tools/dectest.py 112_recursion_shapes:armv7_a32:O2:tail_countdown, x3
                                                         ->  pass, pass, pass
/proc/loadavg during that regeneration                   ->  24.42 on 24 cores
```

So it was discarded and re-run on the same tree with the machine quiet. The two
runs differ by **exactly one cell**:

```
loaded  6162 pass, 1580 fail    armv7_a32  918 pass  73.0%
quiet   6163 pass, 1579 fail    armv7_a32  919 pass  73.1%
```

That cell is `tail_countdown`. Nothing else in 7,742 judged cells moved.

### Why this is worth an entry rather than a shrug

Our own cross-architecture gate is load-sensitive and will record a failure that
is not a property of the code. That is precisely what `CLAUDE.md` warns about for
DecBench — "reports its own resource problems as cell failures" — occurring in
the gate we *do* trust and *do* commit from. And a baseline regeneration is the
worst possible place for it: once written, the next run compares against it and
agrees.

This same cell has now cost time twice by two different mechanisms. The earlier
false alarm came from diffing `arch_baseline.json` while `--write-baseline` was
still flushing. Same cell, different cause, both times a measurement artifact
rather than a defect. Twice is enough to suspect the cell is genuinely marginal —
`arch_roundtrip.py` already carries a note about ASLR ("a recovery that reads an
uninitialised local gives a different answer under each"), and an uninitialised
read would explain a scheduling-sensitive verdict exactly.

Recorded as its own item rather than pinned to `pass`, because pinning it would
hide the thing worth knowing.

### What the cross lane showed that the host lanes could not

```
lane                    pass  fail  struct
aarch64:O0 / O2            0     6       5
armv7:O0 / O2              0     6       5
armv7_a32:O0 / O2          0     6       5
i386:O0 / O2               0     6       5
x86_64:O0                  2     4       5
x86_64:O2                  1     5       5
x86_64_gcc15:O0 / O2       2     4       5
```

Every non-x86-64 architecture fails all six judged functions, **including
`hfa197_scalar_control`**. On x86-64 that control passes on all four host lanes
and is the fixture's discriminator: it is what proves the failures are about the
all-SSE return class rather than about floats in general. On aarch64, armv7 and
i386 it fails too — so there the problem is not the aggregate at all, and it is
wider than anything the host lanes could have told us.

Design Rule 11 in one table. AAPCS64 returns `{float x4}` in `s0`-`s3`, four
registers for one value, and until this fixture nothing in the corpus had ever
asked us to recover that.

---

## Entry 61 — Two mysteries collapse into one, and a three-line fix worth 12 cells

### The fix: restoring the type the operand had before the conversion

Entry 59 located `hfa197_make_scalar`'s failure at `src/ir/ast/dec_render.rs:774`
without writing code. The fix is to do what the comment two lines above it
already says — spell the operand at the type it HAS before the conversion:

```rust
let _ = write!(out, "({})(", from.c_name());
write_expr_dec(expr, out);
out.push(')');
```

**12 cells, 0 regressions**, `cargo test --features python-ext` 2476 passed:

```
GLAURUNG_FIXTURE_TMPDIR=… tools/dectest.py @o0                     2 improvements
GLAURUNG_FIXTURE_TMPDIR=… tools/dectest.py @o2                     2 improvements
… 197_homogeneous_float_aggregates --arch aarch64 --arch i386      4 improvements
… 197_homogeneous_float_aggregates --arch x86_64 --arch x86_64_gcc15  4 improvements
```

`armv7` and `armv7_a32` still fail; ARM32 takes a different path and this does not
touch it.

**The fix is complete rather than partial, and I measured that rather than
assuming it.** Entry 59 said all three renderers "have the same shape" because all
three ignore `from`. They do not have the same *defect*: the wraparound-cast
idiom is a dec-renderer property. `grep -c unsigned` gives **45** in
`dec_render.rs` against **2** in `ctx_render.rs`, and both of those are
`unsigned_abs()` for negative-constant formatting. The c renderer is the same.
Only the dec renderer can reach the bug, so only it needed changing — which is a
smaller and better answer than "fix all three sites."

### The narrowing: one cause, two symptoms

Entry 56 left two things unexplained and I said both needed an `Op` stream dump
rather than more reading. `g.ir.lift_window_at` is that dump, and it exists
already:

```
uv run python $CLAUDE_JOB_DIR/tmp/opdump2.py
hfa197_tagged_control @ 0x13f0 size=64, 75 ops
ops carrying a name/mnemonic: 1
   {'va': 5135, 'kind': 'intrinsic', 'name': 'cvttss2si'}
```

**Exactly one named op in the whole function.** No `punpckldq`, no `movd`, no
`movq` — those lower to typed ops, so their *names* never reach
`unmodelled_x86_float_mnemonic` at all. That kills the entire "which packed
mnemonic trips the proof" line, including both of my falsified hypotheses.
Nothing trips it because nothing named ever arrives.

`Stmt::Unknown` is constructed in exactly three places, all in `lower_op`
(`src/ir/ast.rs:1934`, `:1935`, `:1940`). The observed spelling carries the
`(...)` suffix, so it is `:1935`.

And that is where the two mysteries join. **If `scalar_float_intrinsic(name, ins,
outs)` returns `None` for this op instance, both symptoms follow from that single
fact:**

- in `scalar_float_semantics_are_closed`, arm 1 does not match, so
  `saw_scalar_float` is never set; arm 2 does not match either, because
  `unmodelled_x86_float_mnemonic("cvttss2si")` is *false* (the name IS known); the
  op falls to `_ => {}` and the proof returns `false` — **the gate shuts**;
- in `lower_op`, the same `None` fails the `if let` — **`Stmt::Unknown`**.

One cause, both symptoms. It also explains why none of the seven probes
reproduced it: every one of them had a `scalar_float_intrinsic` that *resolved*,
so their gates stayed open. I was testing the wrong variable in all seven.

What remains is narrow: why does `scalar_float_intrinsic` return `None` here? Its
x86 branch reads `outs.first()`, converts the declared width to `u8`, and asks
`x86_scalar_float_intrinsic`. So it is an empty `outs` or a declining width. The
raw lift cannot answer it — the proof runs on the post-SSA `lf`, and value
numbering canonicalises `eax` to `rax`, so the declared width at proof time is not
necessarily what the lifter wrote. That needs instrumentation at the proof site,
which is a different and much smaller job than where this started.

---

## Entry 62 — The class knows where the value is; the spelling does not

`ReturnClass::SsePair` landed (`fdbcf58`). Fixture 197's all-SSE return class —
2-4 floats or doubles coming back in `xmm0:xmm1`, two registers holding one
value — is modelled, including the case where the high register is half occupied.

```
gate baseline    5 cells fail -> pass          arch baseline   6 more
def-use census   clang:O0 136->134   clang:O2 250->246
                 gcc:O0    98-> 94   gcc:O2   116->111     = -15, 0 lane worse
structural       3 violation lists emptied
cargo test --features python-ext   2481 passed, 0 failed
```

### The instruction I gave that was wrong

I told the agent to follow `7105e26`'s ordering. `SplitBanks` is checked *after*
`result_storage`; I assumed the neighbouring class would sit in the same place.

It cannot. At `gcc:O2` the attributed destination of a pair-returning call is
`Phys("xmm0_d0#1")` — a dword **lane**, not a spelling of "the result", which
`is_return_register` therefore declines. So the scalar storage gate rejects the
call before any class is consulted, and following my instruction verbatim left
the cell exactly as broken as before.

The principle underneath is worth more than the fix: **the proven return class
says where the value is, regardless of which spelling the attribution happened to
pick.** A destination-first check asks the wrong question, because the
destination is an artifact of register allocation and the class is a property of
the ABI.

### The lanes, which nobody predicted

`regview::ssa_parent` declines the vector bank. A definition spelled `xmm0`
therefore never reaches a use spelled `xmm0_d0` — and callers unpacking a
returned float aggregate read almost exclusively through lanes.

```
modelling xmm0 and xmm1 only                       1 cell
+ xmm0_d0, xmm0_d1, xmm1_d0, xmm1_d1               7 cells
```

Two guards keep that from becoming a leak: each lane gets its own storage key, so
a reader of the second float never receives the first one's bits; and a new
`destination_storage`, deliberately narrower than `result_storage`, refuses a
lane as an *ordinary scalar* call destination — only a DWARF-proven `SsePair`
claims one.

### Occupancy comes from the object, not the class list

`{float,float,float}` is 12 bytes: four bytes of `xmm1` are defined and four are
not. `high_bytes` is derived from the object SIZE, and sizes 9/10/11/13/14/15
classify `None` rather than rounding up. The lane table is filtered by it, so
`xmm1_d1` is *not defined at all* for a 12-byte return — the fourth member cannot
be manufactured, because there is no identity to read it from. That is stronger
than emitting a read and hoping nobody uses it.

### The two things this exposed about the corpus

**A cell can be sound and still fail.** `pair2d_roundtrip`'s structural violation
list is now empty — its return is fully correct — and its execution cell still
fails, on the **argument** side: a 16-byte all-SSE aggregate passed by value has
no parameter-storage model. The mirror class, now filed. The fixture's
`hfa197_consume_pair2d` was written for exactly that case and has been waiting.

**And #46 is now load-bearing rather than curious.** On `clang:O0:quad4f` the
split *engages* — a probe shows `ret=Some("struct __glaurung_sse_pair")` — and is
then discarded, because every consumer of `xmm0`/`xmm1` in that function is a
declined `/* asm: movlpd */`, so the six reads the split emits have no users. The
whole-function float gate is what blocks the hardest remaining cells of this
class. It stopped being a side mystery today.

---

## Entry 63 — Three cuts, three wrong boundaries, three corrections from the call graph

The untyped `c` renderer is out (`63a2a42`). `src/ir/ast.rs` is 19,269 -> 15,934
lines and 11,582 -> 8,247 product LOC across the three renderer cuts — **down
29%** — and `product_max_loc` has tracked every step of it while four of the
other seven measures went the wrong way at least once.

```
a792b9a  dec renderer -> ast/dec_render.rs  2,170 lines   1 pub(super)
3c1bb91  ctx renderer -> ast/ctx_render.rs    746 lines   0 widened
63a2a42  c   renderer -> ast/c_render.rs      562 lines   0 widened
```

All three pure: `@o0`/`@o2` at 370 lanes with zero regressions **and zero
improvements** each time.

### The pattern is now unambiguous

I specified a boundary three times. It was wrong at an edge three times, and the
call graph corrected it three times — in both directions.

| cut | what I got wrong |
|---|---|
| dec | `render_with_types` was inside the dec block while calling `write_stmt_ctx`. It is the **ctx** front door, production-used from `python_bindings/ir.rs` at three sites. |
| ctx | Two listed items stayed as shared vocabulary; eight unlisted ones moved. |
| c | I listed `binop_sym`/`cmpop_sym` as staying and **omitted their `_c`-suffixed siblings** — which sit at the END of the named range and are called from `dec_render.rs` at four sites (`:381`, `:741`, `:823`, `:1188`). |

The c cut turned up two more list errors that cost nothing but are the same
shape: `target_int_ctype` and `store_pointee_ctype` are real shared vocabulary
that the moving range never calls, so they needed no decision at all; and
`write_unit_step`, defined 4,800 lines away, IS called from both
`write_for_clause_c` and `dec_render.rs:2188` and was missing from my list
entirely.

**A line range cannot see any of this. That is the whole finding.** Three
independent agents, three different regions of one file, three corrections — none
of which came from reading more carefully, all of which came from enumerating
callers.

### Why the corrections keep being free

Leaving a shared helper in `ast.rs` costs nothing, because a descendant module
already sees its ancestor's private items. Moving one costs a `pub(super)` plus a
re-export and buys nothing. That asymmetry is why the visibility cost fell to
zero and stayed there: when in doubt, leave it.

### Lowering is now measured three times and is still not a move

~2,570 lines across four tangled concerns; then 3,208 physical lines by section
boundary; then 3,208 again, independently. Three agents, one conclusion. The
newest one found a concrete reason it is harder than it looks: the
loop-hoisting-safety helpers inside that span have a unit test in `ast.rs`'s own
`mod tests`, so cutting there forces a decision about whether tests move with
them — which "move, don't rewrite" cannot answer by itself.

The recommended fourth cut is the **ABI-width refinement block** instead
(~1,100-1,180 lines, one `pub(crate)` front door called from exactly two
production sites, and `declaration_plan.rs` already a sibling for that concern).
It is not caller-verified yet, and unlike the three renderer cuts it would land
over 1,000 LOC and need a review entry. Recorded as a recommendation with its
prerequisite named, not as a plan.

---

## Entry 64 — A spilled float made an x86 function look like ARM

Three landings close the 2026-08-16/17 arc: the SysV argument prefix
(`ba90363`), the float gate (`7d834ed7`), and the c-renderer cut (`63a2a42`,
Entry 63). Two of the three turned on a premise of mine being wrong, and in one
case on my *method* being wrong.

### The float gate: right shape, wrong location

Entry 61 narrowed this to "if `scalar_float_intrinsic` returns `None` for that op
instance, both symptoms follow." A guarded diagnostic at the proof site settled
it:

```
[glaurung-float-gate] function entry_va=0x13f0 closed=false float_registers_are_all_caller_saved=false
[glaurung-float-gate]   va=0x1403 call result=%rax#1 no vfp result and float regs are NOT all caller-saved -> gate SHUTS
[glaurung-float-gate]   va=0x140f intrinsic cvttss2si ins=[Reg(Temp(13))] outs=[%rax#2:4] scalar_float=yes width=4
```

`scalar_float=yes`. It resolves. The gate shuts one op *earlier*, on the
`Op::Call` arm, because `float_registers_are_all_caller_saved` asked *"does an
`xmm` or `st0..7` name appear anywhere?"* as a proxy for *"is this x86?"* — and
gcc had spilled the float and converted out of the spill slot:

```
objdump -d --start-address=0x13f0 --stop-address=0x1430 \
    tests/decompiler_fixtures/build/197_homogeneous_float_aggregates-gcc-O2.so
140b:  mov       %eax,0xc(%rsp)
140f:  cvttss2si 0xc(%rsp),%eax
                              grep -c xmm  ->  0
```

Zero SSE registers in the function. It looked like AAPCS. The join of the two
symptoms into one cause was right in shape and wrong in location.

### The method error, which is the part worth keeping

Seven probes failed to reproduce this, and I concluded the mechanism was elusive.
It was not. **Every probe kept the float in a register, because I built them with
the host gcc while the fixture was built by the pinned harness compiler, which
spilled.** My own `-O2` build of the identical source emits
`movd %eax,%xmm0 / cvttss2si %xmm0,%eax`; the fixture's does not. I disassembled
my object and reasoned from it about a failure in a different binary.

The rule: **when investigating a failing fixture cell, disassemble
`tests/decompiler_fixtures/build/<the object>`, never a local rebuild of the same
source.** The whole point of a pinned toolchain is that its codegen differs from
yours.

### Per-value gating: rejected on a census, not on taste

The obvious follow-up is "the gate is per-function and all-or-nothing, make it
per-value." Measured over all 740 built objects and 2,777 functions:

- **5 functions (0.18%)** have the gate shut while carrying a modelled
  scalar-float op — the entire population per-value could rescue.
- All 5 are shut by an **opaque mnemonic**; zero by the `Op::Call` arm, which
  this fix makes inert on x86 corpus-wide.
- 2,502 of 2,777 functions are x86 with no float-bank register at all. The old
  predicate misjudged every one of them; only 3 carried a float op, which is
  exactly why this hid for so long.

And the decisive fact: every one of those opaque ops carries `ins=[] outs=[]`.
A per-value gate needs the poisoning op's def set to know which values are
poisoned. That set is empty and **wrong** — `unpcklps` really writes `xmm0`. So
per-value must either believe it, reintroducing the invented-live-in failure the
gate exists to prevent, or assume it defines everything, which is the
whole-function gate again. **Not a smaller change; one that cannot be made
correctly on this IR.**

### A correction to Entry 62

I recorded that `clang:O0:hfa197_quad4f_roundtrip` discards its `SsePair` split
because its consumers are declined `/* asm: movlpd */`, and implied a
consumer-typing problem. Wrong mechanism. `movlpd` lifts to `Op::opaque` with
**no operands at all**, so `xmm0` and `xmm1` never enter that function's IR. The
split's reads have no users because the consumers are operandless markers.

That makes lifting `movlpd`/`movhpd` the highest-value next step, and it pays
twice: real users for the `SsePair` reads, and the removal of that function's only
opaque producer, opening 8 further declined `cvttss2si`. `movlpd` alone covers 3
of the 5 survivors above.

### The ratchet fired on the change it exists to encourage — for the third time

`3c1bb91` and `63a2a42` each tripped `ir_median_loc` 492 -> 493; this change
tripped `product_median_loc` 276 -> 277.5. In all three the largest owner shrank.

The `.5` is the tell. A median is an order statistic over a population whose size
changes when a file is added: the parity flips, and the median moves from one
file's LOC to the mean of two adjacent ones. That is arithmetic, not code. So the
statistic was fixed rather than the baseline — medians carry a 2-LOC tolerance
now, with three tests pinning that `product_max_loc` and both "files above N"
counts keep zero.

## Entry 65 — A rule I taught every agent was false, and it had been blocking real cuts

Four cuts landed together. Three are pure moves; the fourth is the first
**non-pure** cut this program has taken, and it is the one that needed the most
evidence.

```
cfg.rs        seed collection -> analysis/cfg/seeds.rs        516 lines  NOT pure
lift_x86.rs   xmm views       -> ir/lift_x86/xmm_views.rs     101 lines  pure
lift_x86.rs   conditions      -> ir/lift_x86/conditions.rs    112 lines  pure
call_args.rs  return attrib.  -> ir/call_args/return_attribution.rs  246 lines  pure
```

After them, `product_max_loc` is `symbolic/solver/axeyum_backend.rs` at 3,357 —
**a file this program has never touched and which is not a decompiler file at
all.** That was the terminal condition for the owners, and it is reached.

### The rule that was false

Nine boundary traps had accumulated across the program, taught verbatim to every
agent. Trap 7 said: *a sibling child's `use super::X` pins `X` to the parent*, so
a cluster a sibling imports cannot move.

An agent disproved it, and did it the right way — not with an argument but with a
compiled probe. It added `use super::materialize_condition as _probe;` to
`packed.rs`, naming an item that had just moved into a *different* child, and
built clean.

The mechanism is obvious in hindsight: the parent's own `use child::X;` re-binds
`X` in the parent's namespace, so `super::X` from a sibling still resolves.
Nothing is pinned. The same mechanism keeps rustdoc `[`super::X`]` links working,
which is why the doc-warning count held at 35 across two cuts that the rule said
would break links.

This was not a harmless over-caution. It had already been recorded as the reason
the x86 register-view family (~215 contiguous lines) could not move. It could;
`packed.rs` needs no edit at all. **A false rule that makes files stay large is
worse than no rule**, because it reads as diligence.

One caveat survives and is real: if the *only* consumer of the parent's
re-export is a `#[cfg(test)]` module, the re-export is unused in the shipped lib
build and adds a warning. That is the inversion, not the rule.

### The purity standard is now a token diff

"Pure move" had been an assertion in a report. It is now a check I run myself:
extract the moved region from `git show HEAD:<parent>`, tokenise both sides with
comments and `use` statements stripped, and `difflib` them.

```
src/ir/call_args.rs -> return_attribution.rs   1390 tok vs 1390 tok  ratio 1.000000  0 hunks
src/ir/lift_x86.rs  -> conditions+xmm_views    1245 tok vs 1245 tok  ratio 1.000000  0 hunks
```

For the non-pure cfg.rs cut the same tool, run after applying the five declared
substitutions, gave ratio 0.997312 over 2,796 tokens with five hunks — and
checking each one is what the standard buys. Two were rustfmt artifacts the agent
had named. **Three were not in its report**: a collapsed closure block, a
re-added renamed call site, and a `);` that `git diff -U0` had hidden by aligning
it with an identical line in the *new* call. All three are benign, and I only
know that because I looked at each rather than accepting "two rustfmt artifacts".

Zero regressions **and zero improvements** on `@o0` and `@o2` (370 lanes each)
plus `@aggregates` cross-arch. For the non-pure cut that is the primary evidence
rather than a formality: seed *order* decides both budget priority and body
ownership, so a reordering would surface as a moved cell, not a compile error.

### Three defects found by moving code, none fixed

- **`seeds.rs:340` — the `.eh_frame` sweep is the only whole-image seed scan with
  no deadline guard.** Twelve sibling phases route through `scan_within`; this one
  does not. On the byte-only path (the path every `analyze_functions_bytes*` entry
  uses) it runs a full sweep to completion *after* the total-timeout ceiling has
  passed. Bounded overrun, not unsoundness. It was invisible until moving the
  phases put all twelve guards on one screen.
- **`xmm_views.rs` — a comment and its code describe different predicates.**
  "Every lane the instruction wrote must be accounted for by the copy" sits over
  `(lanes_seen == 4).then_some(source?)`, which demands *exactly four*. A
  register-to-register move writing only lanes 0-1 — precisely the case
  `synchronise_xmm_views`' own doc says the pass exists for — fails and falls
  through to the concat bridge.
- **`classify_pe_thunk_head` — 32-bit PE import thunks get a wild pointer.** It
  computes a RIP-relative target for `ff 25 disp32`. Correct on x86-64; on 32-bit
  x86 that encoding is an *absolute* indirect and is the canonical MSVC import
  thunk, so the computed target points at nothing. The PE corpus that exercises
  the thunk scan is x86-64, which is why nothing caught it.

### Boundary corrections, round twenty-five

The tail-doc swallow (trap 4) was avoided for the **sixth** time, by one line, in
`call_args.rs`: the run ends at `attribute_call_results`' closing brace and the
very next line opens an 18-line doc block on `struct EnclosingSlots`.

Two corrections were made *against my own brief*, both by measurement:

- I asked for `.pdata` bounds in the `Seeds` struct. All three readers of
  `pdata_start_set` are inside the moved block; carrying it out would have been a
  widening with no consumer. I had conflated it with `eh_frame_extent`, which is
  the map that actually supplies a proven function end.
- I said the return-attribution cluster was "roughly 455 lines". It is 246, and
  contiguous. The agent cut what was there.

And one trap fired that no rule covered: `let bits` is declared *between* the
doc comment that opens the moved region and the loop that comment describes, and
is read twice after the block. A line-number cut of the commented range would
have taken it and broken both readers.

## Entry 66 — Three agents, eight cuts, and every one of my line numbers was wrong at a boundary

Three parallel splits landed together: `types_recover.rs` 3,058 -> 2,358,
`lift_arm32.rs` 2,998 -> 1,941, `structure.rs` 2,607 -> 2,044. Eight moves,
`files_above_2000` 12 -> 11, `product_loc_above_1000` 54,271 -> 51,951.

Of the six largest files in the tree, four are now outside the decompiler
entirely — `symbolic/solver/axeyum_backend.rs`, `symbolic/explore.rs`,
`python_bindings/ir.rs`, `analysis/java_class.rs`. The largest decompiler file
is `analysis/cfg.rs` at 2,634.

### Every seam I specified was wrong at a boundary. All eight.

I gave three agents nine candidate line ranges, measured from the same HEAD they
branched from. **Not one of the nine was right at both ends.** The corrections:

```
types_recover  B  1133-1515 -> 1133-1508   end -7:  next item's doc
               C  1516-1847 -> 1510-1840   both:    stranded doc / next item's doc
               A  2389-2895 -> 2389-2893   end -2:  next item's doc
lift_arm32     A   530-982  ->  528-975    both:    stranded doc / next item's doc
               B  2589-2898 -> 2588-2890   both:    stranded doc / next item's doc
               C   221-529  ->  206-526    start -15: THREE stacked traps
structure      C  2040-2235 -> 2035-2227   both:    stranded doc / next item's doc
               A  2236-2608 -> 2229-2607   start -7:  stranded doc
```

Trap 4 — swallowing the *next* item's doc comment — is now at eleven instances.
It fired in **six of my nine ranges**. One deserves naming: `structure` Cut C's
stated range ended on the last line of `commit_borrowed_switch_arm`'s seven-line
doc block. Taking that cut alone would have stranded the doc of the function the
*next* cut moves. It was harmless only because the same agent took both.

The worst single boundary was `lift_arm32` Cut C, where three traps stacked
within 15 lines: a `#[derive]` attribute the cut would have stranded on an
unrelated function (trap 3), the struct's own doc block above that (trap 1), and
a `// --- Shifted register operands ---` section banner above *that*, which has
no referent left in the parent once the section leaves.

**The lesson is not "read more carefully."** It is that a line range is the wrong
unit. Every one of these errors is invisible in a range and obvious in an item
list; the ranges were derived by an `awk` over `^fn|^struct|^impl`, which by
construction cannot see a doc block or an attribute, because those do not start
at column zero with a keyword. I have been handing agents a tool's blind spot and
calling it a specification.

### An agent reversed my ranking with a table I should have built

I ordered `types_recover`'s three seams A, B, C "by how self-contained they
look." The agent measured the actual dependency edges:

| cut | outbound (region -> parent) | inbound (parent needs) |
|---|---:|---:|
| B | **0** | 5 |
| C | 5 | 6 |
| A | 5 — *including `recover_types`, the parent's own public front door* | **11** |

B reads nothing from its parent and was ranked last; A calls back into the
parent's entry point and was ranked first. It took B and C and left A, which is
the correct order. "How self-contained it looks" is not a measurement.

### The purity standard held, and cost exactly three commas

My own token diff over all eight moves: `types_recover` ratio 0.999866,
`lift_arm32` 0.999919, `structure` 0.999850. Each differs from byte-identity by
**one inserted `,`** — in all three cases a `pub(super) ` prefix pushed a
signature past rustfmt's 100 columns, rustfmt broke the parameter list
vertically, and its style appends a trailing comma.

One agent noted it could have held 1.000000 by writing `pub` instead of
`pub(super)` (shorter, fits in 100 columns) and refused: **widening visibility to
buy a cosmetic ratio is the wrong trade.** That is the right instinct, and it is
worth recording that the metric was tempting enough to be worth resisting.

### Trap 7's caveat is now the common case

The revised rule (a sibling's `use super::X` does not pin `X`) held under
compilation in all three splits. Its *inversion* fired three times in one round —
a re-export whose only consumer is a `#[cfg(test)]` module is unused in the
shipped lib build. Each agent found it independently and gated the re-export:

```rust
#[cfg(test)]
use shifts::SHIFT_TEMP;
```

with a comment saying why. Three independent discoveries of the same caveat in
one round means it belongs in the rule, not beside it.

### Two more stranded docs, both pre-existing, both filed not fixed

The `lift_x86.rs:603` defect fixed this week was not unique; it is a *class*
produced by earlier cuts in this same program.

- **`lift_arm32.rs:608`** — `flags_for_arith` carries two stacked summary lines,
  the first of which describes `cmp_flag_ops` (which has its own correct summary
  40 lines below) and is *also* stale: it says "four flag writes" where the
  function emits seven.
- **`structure.rs:1685`** — two doc paragraphs fused into one `///` run with no
  blank line between them. The first three sentences plainly document
  `detect_if_shape`, the 353-line centrepiece of the file, which consequently
  carries **no doc at all**. A previous cut moved something out from between them
  and merged what was left.

Both are one-line repairs and both stayed out of the patches, because a content
edit inside a moved region destroys the purity claim that is the only evidence a
move is safe. They are queued as their own change.
