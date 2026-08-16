# Decompiler roadmap execution diary — from 2026-08-16

**Plan:** [decompiler-roadmap.md](decompiler-roadmap.md)
**Previous volume:** [decompiler-roadmap-diary-2026-08-13.md](decompiler-roadmap-diary-2026-08-13.md) — Entries 1-48, 2026-08-13..16
**Continues from:** `0acfe20`

Running evidence log for working the roadmap. One entry per increment,
RED -> GREEN -> VERIFY, with the exact command output that justifies each claim.

**Entry numbering continues across volumes**, so a reference to "Entry 34" stays
unambiguous. The next free number is **53**.

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
