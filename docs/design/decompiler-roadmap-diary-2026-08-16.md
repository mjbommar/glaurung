# Decompiler roadmap execution diary — from 2026-08-16

**Plan:** [decompiler-roadmap.md](decompiler-roadmap.md)
**Previous volume:** [decompiler-roadmap-diary-2026-08-13.md](decompiler-roadmap-diary-2026-08-13.md) — Entries 1-48, 2026-08-13..16
**Continues from:** `0acfe20`

Running evidence log for working the roadmap. One entry per increment,
RED -> GREEN -> VERIFY, with the exact command output that justifies each claim.

**Entry numbering continues across volumes**, so a reference to "Entry 34" stays
unambiguous. The next free number is **52**.

Two conventions worth restating, both of which this project has paid to learn:

- **Write the command next to the number.** Two tables in `docs/design/` turned
  out never to have been produced by any run, and both shaped later decisions.
- **Measure the tool's own noise floor before trusting a diff.** A byte-identity
  check over the corpus showed 16 functions changed by a refactor; running the
  unmodified build against itself showed 13 changed there too. Without that
  control the refactor would have been blamed for a pre-existing 0.10%
  non-determinism.

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
