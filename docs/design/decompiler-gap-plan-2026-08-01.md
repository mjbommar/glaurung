# Closing the measured gap to Ghidra, angr and RetDec

**Date:** 2026-08-01
**Basis:** head-to-head run of Glaurung 0.1.0, Ghidra 12.1.2, angr 9.3.1 and
RetDec v5.0 over 27 real Linux binary images from `/nas4/data/binary-analysis`
(18 distinct files; nine also run as an unstripped/stripped pair). Ground truth
from DWARF on nine Alpine 3.18 binaries, `.eh_frame` FDE starts elsewhere.

This is a remediation plan, not a benchmark report. It states what was measured
only far enough to justify what to change, then names the change, the file, the
test, and the number that has to move.

---

## 1. What the measurement actually said

Glaurung is not uniformly behind. It leads on two axes and trails badly on one,
and the one it trails on is upstream of almost everything else.

**Where it already leads**

| | Glaurung | Ghidra | angr | RetDec |
|---|---|---|---|---|
| decompile success, stripped (93 GT functions) | **93/93** | 75/93 | 87/93 | 87/93 |
| output parses as C (`gcc -fsyntax-only`) | **90%** | 20% | 51% | 74% |
| `undefined`-width types per function | **0.00** | 2.61 | 0.00 | 0.00 |
| wall clock per binary, Tier B (large, x86-64) | **17.5 s** | 26.5 s | 39.9 s | 42.1 s |

The lifter is robust and fast, and `--style decbench` genuinely delivers a
self-contained artifact. **Nothing in this plan should be allowed to regress
those four rows.**

**Where it trails**

| | Glaurung | best of the rest |
|---|---|---|
| function-discovery recall, stripped (DWARF set) | **13%** | 91% (angr) |
| imported-callee recall | **52%** | 100% (Ghidra) |
| functions containing an *invented* call | **35%** | 0% (all three) |
| prototype arg count exactly right, stripped | **53%** | 80% (Ghidra) |
| local declarations per function (small / large) | **31.9 / 72.2** | 11.6 / 13.5 (Ghidra) |
| raw registers surviving into C (small / large) | **2.2 / 9.4** | 0.00 (all three) |
| string literals per function — AArch64 / ARMv7 | **0.00 / 0.00** | 5.68 / 2.55 |
| `glaurung cfg` on AArch64 GNU grep | **>300 s, no output** | 22 s (Ghidra, full decompile) |

---

## 2. Nine symptoms, four root causes

The measured defects are not nine independent bugs. They collapse to four.

| # | Root cause | Symptoms it explains |
|---|---|---|
| **A** | **ELF function discovery is entry-point recursive descent.** Everything richer is PE-gated. | 13% discovery recall; PLT stubs anchored +6; 1-edge callgraph on musl; part of the arg-count gap |
| **B** | **Functions have no authoritative end.** Lifting runs past the last instruction into the next function. | 35% invented calls; 52% callee recall; part of the arg-count gap |
| **C** | **Value fusion is adjacent-only and memory is not in SSA.** | 31.9→72.2 locals/fn; 2.2→9.4 registers leaking; unfolded triple casts; verbosity growing with function size |
| **D** | **ARM/AArch64 is lifted but not *analysed*.** | 0.00 string literals on both ARM targets; AArch64 discovery not terminating; callee names 4.96→2.89→1.41 across x86-64/AArch64/ARMv7 |

Cause **A** is upstream of **B** and of much of **D**, and it is also the
cheapest to fix. It should go first.

---

## 3. Workstream A — ELF function discovery

### A.0 The evidence

`src/analysis/cfg.rs:4` says it plainly:

> It seeds from an entrypoint (and can be extended later to exports/PLT/etc.)

The seed taxonomy at `src/analysis/cfg.rs:228` has sixteen kinds. Counting which
ones fire on a stripped ELF x86-64 binary:

| seed kind | fires on stripped ELF x86-64? |
|---|---|
| `EntryPoint`, `DirectCall`, `DirectCallBodySplit`, `TailCall`, `IndirectCall`, `JumpTable`, `Vtable`, `Flirt` | yes |
| `Requested` | only when the caller names an address |
| `Symbol`, `Export` | only if not stripped |
| `Pdata` | no — PE `.pdata` only |
| `Prologue` | **no** — `scan_pe_prologue_function_starts` returns empty unless `data[..2] == b"MZ"` (`cfg.rs:1931`); the AArch64 companion only matches PAC prologues (`cfg.rs:1883`) |
| `Thunk`, `TinyStub`, `DataRef` | no — all three PE-only |

So a stripped ELF gets the entry point plus whatever recursive descent reaches
from it. That is the whole story:

| discovery recall, stripped | Glaurung | Ghidra | angr | RetDec |
|---|---|---|---|---|
| `cat` (glibc, vs `.eh_frame`) | 57% | 100% | 100% | 83% |
| `grep` (glibc, vs `.eh_frame`) | 48% | 100% | 92% | 88% |
| `getent` (musl, vs `.eh_frame`) | **0%** | 100% | 96% | 96% |
| `busybox` (musl, vs ≥3-tool consensus) | 82% | 92% | 100% | 100% |

The `getent` zero is not a musl result — `busybox` is also musl and reaches 82%.
It is a *small binary* result: when most of the image is PLT, one PLT bug
consumes the entire score.

### A.1 Seed from `.eh_frame` — the single highest-value change

`.eh_frame` is already parsed in-tree with `gimli`
(`src/analysis/exception.rs:56`, `extract_exception_call_sites`), and
`ExceptionCallSite.function_start` is literally an FDE start address. But that
function only walks FDEs carrying an LSDA, and **the CFG pass never calls it at
all** — its only consumers are in `src/python_bindings/ir.rs`.

Every x86-64 and AArch64 Linux binary built in the last fifteen years has
`.eh_frame`, because `-fasynchronous-unwind-tables` is the default. It is the
exact reference this benchmark scored against, and Glaurung already links the
library that reads it.

**Change**

- New `pub fn eh_frame_function_starts(data: &[u8]) -> Vec<(u64, u64)>` in
  `src/analysis/exception.rs`, returning `(initial_location, address_range)` for
  every FDE. Reuse the existing `BaseAddresses` / `EhFrame` setup at
  `exception.rs:61-89`; the only change is not requiring an LSDA.
- New `DiscoverySeedKind::EhFrame` in `cfg.rs:228`, ranked as a **trusted**
  seed (alongside `Symbol`/`Export`, *not* body-overlap-gated — an FDE start is
  authoritative, and gating it behind overlap would let a wrong earlier function
  suppress a correct one).
- Wire it into the seed collection near the `Pdata` block (`cfg.rs:~3985`),
  which is its exact PE analogue.
- Add `eh_frame_seeds_inserted` to `FunctionDiscoveryStats`.

**Also carry the FDE's `address_range`** — that is workstream B's input, and it
comes free from the same parse.

**Acceptance:** discovery recall vs `.eh_frame` ≥ 0.95 on `cat`, `grep`, `find`,
`tar`, both `bash` builds, and stripped `getent`/`getconf`/`iconv`. This is
close to definitionally true once the seeds are wired, so the real acceptance is
that **nothing else regresses** — specifically the four leading rows in §1.

**Effort:** small (~1 day). **Risk:** low. **Leverage:** highest in this document.

### A.2 An ELF prologue scan

`.eh_frame` will not cover hand-written assembly, `-fno-asynchronous-unwind-tables`
builds (Alpine's `busybox`, measured here with a 4-byte `.eh_frame`), or
`.init`/`.fini` fragments. PE has had a prologue scan for a while; ELF needs the
same.

**Change**

- Generalise `scan_pe_prologue_function_starts` (`cfg.rs:1931`) into
  `scan_prologue_function_starts(data, regions, arch, format)`, dropping the
  `MZ` gate and dispatching the candidate predicate on format+arch.
- x86-64 ELF predicate: `endbr64`; `push rbp; mov rbp,rsp`; `sub rsp,imm`
  preceded by padding (`0xCC`/`0x90`/`0x00` run) or by a `ret`/`jmp` at a
  16-byte-aligned address. Keep the existing
  `has_function_boundary_marker` (`cfg.rs:1634`) as the padding oracle.
- Broaden `scan_aarch64_prologue_function_starts` (`cfg.rs:1883`) beyond
  PAC-only: `stp x29, x30, [sp, #-N]!` and `sub sp, sp, #N` are the common
  unhardened forms and are what Ubuntu/Alpine AArch64 actually ship. This is
  also a prerequisite for D.2.

Prologue seeds stay `is_body_overlap_gated` (`cfg.rs:248`) — unlike `.eh_frame`,
a prologue match is a heuristic and must not split a function already proven.

**Acceptance:** on `busybox` (no `.eh_frame`), coverage of the ≥3-tool consensus
set rises from 82% to ≥92% (Ghidra's number). No new false starts inside proven
`.eh_frame` bodies — assert this directly in the test.

**Effort:** medium (~2–3 days). **Risk:** medium — a bad predicate manufactures
functions. Mitigated by overlap gating and by the false-start assertion.

### A.3 The GOT is not a vtable — RESOLVED, and the hypothesis above was wrong

**What the instrumentation actually printed.** The plan required proving the
mechanism before fixing it. `analyze_functions_path_with_stats` already exposes
`seed_provenance`, so no instrumentation was needed:

```
0x2026  seed_kind=vtable  prov_kind=vtable  src=0x5dc0
0x2036  seed_kind=vtable  prov_kind=vtable  src=0x5dc8
seed_kind_counts: {entrypoint: 1, symbol: 2, vtable: 64}
```

Not a fall-through seed after an unresolved indirect jump, as hypothesised. The
seeds are **`vtable` seeds sourced from `.got`**, and `0x5dc0` is the GOT slot
for `putchar`. A lazily-bound ELF stores, in each GOT slot, a back-pointer into
that import's own PLT stub — the address the dynamic linker patches on first
call. Dumping the section confirms it exactly:

```
.got 0x5dc0 -> 0x2026    .got 0x5dc8 -> 0x2036    .got 0x5dd0 -> 0x2046
```

`discover_vtables` was reading `.got` as an array of code pointers, which is
precisely what it looks like. All 64 "functions" on stripped `getent` were GOT
slots; there were no others.

Underneath sat a plain logic bug in the section filter
(`src/analysis/vtable.rs`):

```rust
|| sec_name.contains(".gcc_except_table") == false; // exclude EH
```

That disjunct is true for every section that is not the EH table, so the whole
predicate was true for essentially everything and the filter did nothing.

**Fixed** by turning the exclusion into a guard and adding
`is_relocation_table()` — `.got`, `.got.plt`, `.plt.got`, `.plt.sec`, `.plt`,
`.idata`, `.iat` — with a regression test that asserts no vtable entry is ever
sourced from a relocation table (`got_slots_are_not_reported_as_vtables`).

**Measured:** discovery recall on stripped `getent` 0% → **100%**.

**Still open from the original A.3:** seeding real PLT entries by name from
`elf_plt_map`. Lower priority than it looked — with `.eh_frame` seeding in
place, imported-callee recall already reached 99%, so calls resolve to correct
names without it.

### A.4 AArch64 PLT names were off by one — RESOLVED

Found while investigating D.1. `elf_plt_map` skipped `reserved * entry_size`
bytes for the PLT header. x86-64's PLT0 is one 16-byte entry, so that was right
there; **AArch64's is 32 bytes**, two entries' worth. Every AArch64 name was
therefore shifted onto its neighbour's stub, and a stripped `getconf` rendered

```c
__deregister_frame_info(*(long *)((var5)), 0x1c56);   // really fprintf(...)
__libc_start_main(1);                                 // really exit(1)
```

Confidently wrong output, which is worse than an unresolved call — and invisible
to every metric in the original study, because `callcheck.py` scores whether an
emitted callee is *called somewhere in the function*, and these were.

**Fixed** by deriving the header from the table the linker emitted —
`size - count * entry_size`, accepted only when it is a whole number of entries
— instead of assuming one entry. Test pins the first five entries of a committed
AArch64 fixture against objdump's own `<name@plt>` labels.

---

## 4. Workstream B — function termination

### B.0 The evidence

This is the most serious *correctness* finding, and the only one in the study
measured against the machine rather than against another tool's opinion. For
each DWARF-known function, `llvm-objdump` was run over exactly its byte range
and every call/branch target resolving to a named import was collected, then
compared with what each tool's C claims to call:

| | Glaurung | Ghidra | angr | RetDec |
|---|---|---|---|---|
| imported callees recovered | **52%** | 100% | 93% | 99% |
| functions containing an invented call | **35%** (22/62) | 0% | 0% | 0% |
| invented calls per function | **1.08** | 0.00 | 0.00 | 0.00 |

The figures are identical with and without DWARF, so this is a lifting result,
not a symbol result.

**The mechanism, concretely.** `main` in stripped `getent` (x86-64) is 97 bytes,
`0x2440`–`0x24a1`. `_start` begins at `0x24a1` and `_start_c` at `0x24b7`.
Glaurung's output for `main` ends:

```c
    var24 = warn("Unknown database `%s'");
    L_2499: ;
    var25 = sub_316a(*(long *)((var3)));
    rsp = (rsp & -16);
    var27 = sub_24b7((long *)(rsp), 0x5be8);        // _start_c — not main
    ret = __libc_start_main(0x2440, ..., 0x2000, 0x321f, 0);   // never called by main
    return ret;
```

Everything before `L_2499` is structurally correct. Glaurung simply did not stop
at `0x24a1`: `main`'s final instruction is a call to a `noreturn` helper, there
is no `ret`, and lifting fell through into the adjacent function and kept going.

### B.1 Give every function an authoritative end

**Change**

- Thread the FDE `address_range` from A.1 through to the lifter as a hard
  upper bound. When an FDE covers the entry, **lifting stops at
  `start + range`, unconditionally.** This alone should fix the majority of the
  22 affected functions, since almost all of them have an FDE.
- Where no FDE exists, bound by the next known function start (from any trusted
  seed) and stop there.
- Treat `noreturn` as terminal. `__stack_chk_fail`, `abort`, `exit`,
  `__libc_start_main`, `_exit`, `pthread_exit`, `longjmp` already have
  contract data available via `src/ir/call_contracts.rs`; a call to a
  `noreturn` callee must end the block with no fall-through successor.
- Add a verifier assertion in `src/ir/verify.rs`: **no lifted instruction may
  lie outside the function's declared range.** Fail closed. A silent overrun is
  precisely what shipped here.

**Acceptance — this is the headline number of the whole plan:**

- invented calls per function: 1.08 → **0.00**
- functions containing an invented call: 35% → **0%**
- imported-callee recall: 52% → **≥95%**

Measured by `bench/callcheck.py` (see §8), which needs no source.

**Effort:** medium (~3–4 days). **Risk:** medium — a too-tight bound truncates
real functions, which would show up as a drop in the §1 success rate. Watch both
numbers together; they are in tension by design.

### B.2 Re-check prototypes once boundaries are right

Arg-count accuracy is 53% stripped against Ghidra's 80%, and 100% for everyone
when DWARF is present. Some of that gap is genuine ABI inference in
`src/ir/call_args.rs` and `src/ir/abi.rs`, but an unknown share is simply
downstream of B.1: a function that swallows its neighbour has the wrong live-in
set, so it has the wrong parameters.

**Do not tune argument recovery until B.1 lands.** Re-measure first; only the
residual is a real `call_args` problem. On AArch64 the residual is likely to be
the larger part (arg accuracy is 0.77 there vs 0.50 on x86-64 — note the
*inversion* relative to every other metric, which is worth understanding before
touching anything).

---

## 5. Workstream C — value fusion and output density

### C.0 The evidence

| | Glaurung | Ghidra | angr | RetDec |
|---|---|---|---|---|
| local declarations/fn — Tier A (small) | 31.9 | 11.6 | 1.2 | 4.4 |
| local declarations/fn — Tier B (large) | **72.2** | 13.5 | 3.8 | 4.1 |
| lines/fn — small → large | 87.8 → 222.6 | 62.9 → 115.9 | 74.8 → 121.8 | 120.5 → 119.0 |
| raw registers in C/fn — small → large | 2.2 → **9.4** | 0.00 | 0.00 | 0.00 |

Note the shape: everyone else is roughly flat from small to large functions;
Glaurung's declaration count grows 2.3× and its register leakage 4.3×. That is
the signature of a *local* optimisation applied to a *global* problem.

Reading the pipeline confirms it. `src/ir/ast.rs:5805-5850` documents an
impressively careful sequence, but the propagators are named
`propagate_adjacent_promoted_values`, `propagate_adjacent_guard_values`,
`propagate_adjacent_overwritten_values` — all adjacency-scoped and one-use-gated.
Each is provably safe. None of them fuse a value across a basic block, so the
longer the function, the more temporaries survive.

The structural reason is at `src/ir/ssa.rs:17-18`:

> Scope (v1): operates on register and predicate VRegs … **memory is not
> versioned**.

Stack slots are memory. `local_2b4`, `stack_0`…`stack_5`, `var0`…`var145` cannot
be fused by a pass that has no SSA over them, so the only safe rewrites are the
adjacency ones that already exist.

### C.1 Stack-slot SSA

**Change**

- Extend `src/ir/ssa.rs` to version *provably non-escaping, fixed-offset,
  fixed-width* stack slots. The qualifier is the whole design: a slot whose
  address is taken, or accessed at a computed offset, or aliased by an
  overlapping width, stays unversioned and behaves exactly as today.
- `src/ir/stack_locals.rs` (4,316 lines) already classifies slots and is the
  natural place to compute the escape/alias predicate.
- With slots versioned, general copy propagation and dead-store elimination
  (`copy_prop.rs`, `dead_stores.rs`) can run over them instead of only over
  registers.

**Acceptance:** local declarations/fn ≤ 15 on Tier A and ≤ 20 on Tier B; lines/fn
on Tier B ≤ 150. **Success rate stays 93/93 and C well-formedness stays ≥ 90%** —
this pass must not buy density with correctness.

**Effort:** large (~2 weeks). **Risk:** high. This is the deepest change here and
the one most able to introduce silent wrongness. It should land behind the
existing fixture matrix and the execution differential, not behind metrics alone —
`tools/dectest.py` and the recompile-and-run gate are the relevant checks, and
`docs/development/decompiler-testing.md` already describes exactly how a perfect
GED score coexisted with a body reading undefined locals.

### C.2 Register views must not reach the printer

9.4 raw register identifiers per function in Tier B output (`rsp`, `rbp`, `lr`,
`fp`, `stack_top`) is a rendering-layer symptom: values that were never promoted
to source identities are printed under their machine names. Ghidra, angr and
RetDec all emit exactly zero.

**Change**

- After `high_variables::refine` (`src/ir/high_variables.rs`), assert that no
  `VReg::Phys` survives into a rendered declaration except a genuinely
  unrecovered value, and render those as an explicitly named
  `unrecovered_<reg>` rather than the bare register.
- `rsp` arithmetic (`rsp = (rsp - 8)` appears throughout the prologue in the
  measured output) should be consumed by the frame-setup recogniser in
  `src/ir/x86_prologue.rs` / `arm64_prologue.rs` / `arm32_prologue.rs` and
  deleted, not printed.

**Acceptance:** raw registers/fn = 0.00 on both tiers.

**Effort:** medium (~3 days). **Risk:** low–medium. Partly independent of C.1 and
worth doing first as a visible win.

### C.3 Fold redundant cast chains

`(unsigned long)((unsigned long)((unsigned int)(...)))` appears routinely in the
measured output; Ghidra and angr both fold these. A width-lattice pass over the
prepared AST that collapses a chain of same-signedness widening casts to the
widest, and drops any cast that is a no-op at the value's known width, is
mechanical and independent of C.1.

**Effort:** small (~1–2 days). **Risk:** low. Good first-week task.

---

## 6. Workstream D — ARM and AArch64

### D.0 The evidence

| stripped | x86-64 | AArch64 | ARMv7 |
|---|---|---|---|
| string literals/fn | 1.52 | **0.00** | **0.00** |
| resolved callee names/fn | 4.96 | 2.89 | 1.41 |
| arg count right | 0.50 | 0.77 | 0.32 |
| decompile success | 1.00 | 1.00 | 1.00 |

The lifters work — success is 1.00 everywhere, the best in the study. What does
not work is everything *around* the lifter: data-reference resolution, callee
naming, and discovery.

### D.1 PC-relative data references on ARM — RESOLVED for AArch64

Zero string literals on both ARM targets, against 5.68 (Ghidra) and 2.55
(RetDec). Two separate causes, neither of which was missing code.

**Cause 1 — a pass-ordering gap, not a missing pass.** x86-64 materialises the
address of a string in one instruction (`lea rax, [rip+disp]`), which lifts
directly to `Value::Addr(abs)`, so `strings_fold` sees a complete VA. AArch64
needs two — `adrp` supplies the 4 KiB page, a following `add` the low 12 bits —
and `strings_fold` runs *before* the algebraic folder, so at that point the
value is still `Addr(page) + Const(offset)` and never matches.

Fixed inside `strings_fold` itself, which already owns the walker: an `Add` of
an `Addr` and a `Const` is combined and looked up in the pool before recursing.
No pass reordering, no new pass, no effect on any other target. A matching
`Addr ± Const -> Addr` rule was also added to `const_fold` (with a test that a
*masked* address is deliberately left alone, since it no longer refers to that
object).

**Cause 2 — the AArch64 PLT off-by-one**, see A.4.

Together, on stripped AArch64 `getconf`:

```c
// before
var7 = __deregister_frame_info(*(long *)((var5)), 0x1c56);
var8 = __libc_start_main(1);

// after
var7 = fprintf((void *)(*(long *)((var5))),
               (const char *)("Usage: %s system_var\n\t%s -a\n\t..."));
exit((int)(1));
```

**Still open:** ARM32. It has no analogue of `aarch64_literals.rs` — literal
pools (`ldr rN, [pc, #off]`) and `movw`/`movt` pairs are not reconstructed, so
the same fix has nothing to fold. That is genuinely missing code rather than a
wiring gap, and it is the remaining half of this item.

### D.2 AArch64 discovery did not terminate — RESOLVED

The hardest failure in the study, and the cause was one API call.

`CapstoneDisassembler::disassemble_instruction` called `disasm_all(bytes, ...)`
and then used only the first instruction. Callers pass the rest of the image
(`let slice = &data[fo..]` in `cfg.rs`), so **every instruction decoded the
entire remaining binary** — cost quadratic in file size, paid on every
architecture routed through Capstone: ARM, AArch64, MIPS, PowerPC and RISC-V.

x86-64 goes through `iced`, which decodes exactly one instruction, and was never
affected. That is the whole explanation for a gap that looked architectural:

| | functions | before | after |
|---|---|---|---|
| `cat` x86-64 (iced) | 164 | 0.1 s | 0.1 s |
| `cat` AArch64 | 78 | 12.2 s | **1.8 s** |
| `gzip` AArch64 (134 KB) | 119 | >108 s | **1.9 s** |
| `ls` AArch64 (199 KB) | 289 | — | **2.0 s** |
| `grep` AArch64 (199 KB) | 282 | **never finished** (>20 min) | **1.9 s** |

**Fixed** by `disasm_count(window, addr, 1)` over a 16-byte window. The window is
x86's architectural maximum rather than this backend's own
`max_instruction_length()` of 8, because `for_arch_with` lets a caller select
Capstone for x86 where an instruction may be 15 bytes; every other architecture
here is fixed-width and far below 16.

None of the plan's three suspects (the prologue sweep, jump-table discovery,
repeated `va_to_code_file_offset` lookups) was involved. The profile-first
instruction was right; the guesses attached to it were not.

**Still open from D.2:** the budget is still not enforced on the hot path
(`Budgets::timeout_ms` defaults to 100 ms and a whole-binary run far exceeds
it), and long Rust analysis called from Python still does not release the GIL,
so `Ctrl-C` cannot interrupt it. Both were masked by the quadratic decode and
remain real.

## 6b. Phase 1 outcome — measured 2026-08-01

Five defects fixed, each with a regression test. Every gate green: **1566 Rust
tests**, **`dectest @smoke`** clean, **fixture matrix 656 pass / 0 fail**.

### Targets

| metric | before | after | target |
|---|---|---|---|
| invented calls per function | 1.08 | **0.00** | 0.00 |
| functions containing an invented call | 35% | **0%** | 0% |
| imported-callee recall | 52% | **94%** | ≥95% |
| discovery recall vs `.eh_frame` (stripped) | 18% | **100%** | ≥90% |
| `glaurung cfg`, AArch64 `grep` | never finished | **1.9 s** | <30 s |
| AArch64 `grep`, functions decompiled | did not finish | **40/40** | — |

### Must-not-regress

| metric | before | after |
|---|---|---|
| decompile success, stripped | 93/93 | **93/93** |
| C well-formedness | 90% | **90%** |
| `undefined`-width types per function | 0.00 | **0.00** |
| wall clock per binary, Tier B | 17.5 s (fastest) | **5.1 s** (fastest; Ghidra 19.1, angr 36.7, RetDec 38.4) |

Tier B wall clock improved 3.4x, and Glaurung is now **3.7x faster than Ghidra**
on large binaries rather than 1.5x.

### What did not improve, honestly

* **Prototype arg-count fell 0.530 to 0.478** (AArch64 0.77 to 0.61). This is
  partly an artefact of the fixes: functions that previously truncated after a
  hallucinated call now lift completely, so more of them are scored on their
  real live-in set instead of a short wrong body. Some of it is a genuine
  `call_args` gap. B.2 was written to be measured *after* boundaries were fixed;
  that condition now holds, and this is the number to work.
* **Verbosity got worse, for the same reason.** Lines per function 87.8 to
  111.0 (Tier A) and 222.6 to 220.3 (Tier B); locals 31.9 to 40.3. The output is
  longer because it is no longer truncated. C.1 and C.2 are untouched and remain
  the largest remaining gap: 40 locals per function against Ghidra's 11.6.
* **Register leakage improved but is not gone** — 9.4 to 4.7 per function on
  Tier B, against 0.00 for all three comparators. C.2 still applies.
* **ARM32 string literals are still 0.00.** The AArch64 half of D.1 is fixed;
  ARM32 needs literal-pool and `movw`/`movt` reconstruction that does not exist
  yet.
* **A.2 (ELF prologue scan) was not done.** Discovery recall against the *DWARF*
  set is 0.514 — `.eh_frame` covers only functions with unwind tables, and the
  remaining half needs the prologue scan. This is now the top remaining
  discovery item.

### A metric bug found while reading the results

`condition flags per function` reports 0.00 for Glaurung on both tiers, but its
AArch64 output plainly contains `zf_3`, `zf_4`, `zf_6`. The harness regex
(`\b[zcosap]f\b`) does not match `zf_3`. Flag leakage is therefore
**undercounted for everyone**, and the real figure is unknown. Fix the pattern
before using that row to justify anything.

## 6c. Phase 2 — output quality

Six more changes, all test-backed. Two of them exist only because the *harness*
was wrong, which is worth stating first.

### The metric was hiding the largest defect

`analyze.py` reported `condition flags per function` as **0.00 for every tool**
while Glaurung's AArch64 output plainly contained `zf_1`…`zf_6`. Two separate
bugs:

* `\b[zcosap]f\b` cannot match `zf_3` — `_` is a word character, so there is no
  boundary after `f`. Decompilers number their flag temporaries, so the row
  matched nothing anywhere.
* `ARM_REGS` was defined and never referenced. `register` matched the x86 list
  only, so `fp`, `lr`, `sp` and `x0`..`x30` in AArch64 output were invisible.

Corrected, the true readings were **7.15 flag temporaries** and **5.73 raw
registers** per function, against 0.00 for Ghidra and RetDec. The two largest
quality defects in the study had been reported as perfect scores.

*A metric that reads 0.00 deserves the same suspicion as one that reads 1.00.*

### C.2a — flag-setting arithmetic on AArch64 (`subs`, `adds`, `ands`)

Unlifted `subs` was not merely a missing instruction. A dropped flag *write*
leaves the flag's later reader bound to a **stale earlier definition**, so in a
stripped `parsenum` the stack-canary branch tested a comparison from the top of
the function. `subs`/`adds` were 50 of the 302 apparent AArch64 gaps.

Fixed by lifting the `S`-suffixed forms as the operation plus the flags `cmp`
would have set. `adds`/`ands` claim only zero and sign — carry and overflow
depend on width and signedness this lifter does not model, and a *wrong* flag is
worse than an absent one because a branch will render it.

Measured on that function: flag temporaries **6 → 1**, lines **62 → 51**, and
the canary check became a real comparison.

> **A miscount corrected.** `paciasp`/`autiasp` were counted as 85 of those 302
> gaps. They are not gaps — they are already zero-output intrinsics, and the
> `/* asm: */` text is just how an intrinsic *renders*. The premise was wrong and
> the change was reverted; a test now pins the real contract.

### C.2b — callee-saved spill/restore pairs

`stack_2 = rbp` at entry with `rbp = stack_2` at exit is what `push rbp`/`pop
rbp` becomes. Neither statement exists in the source. These were the *entire*
source of raw register names in Glaurung's output.

Removed as a pair, and only when the restored value is never observed. A
one-sided "never read" rule is not enough: the epilogue reads the slot, so the
spill is not dead on its own. `eliminate_dead_stores` cannot make this call —
it walks forward and stops at the first nested `If`, and these sit above all of
a function's control flow.

On `getent`: frame registers **gone**, `main` **37 → 25 lines**, `shells`
**74 → 62**.

### D.1b — suffix-merged strings

`printf((const char *)(0x3005), ...)` — because `"%s = %lu\n"` lives at 0x3000
and the linker stores `"%lu\n"` as *the same bytes* at 0x3005. `collect_string_pool`
indexed only the start of each null-terminated run, so every reference to a
merged suffix resolved to nothing. This was most of why string recovery read
1.52 per function against Ghidra's 5.63 **on x86-64**, where addresses already
arrive complete — the ARM explanation never applied here.

Suffixes are now indexed down to the 3-character floor, so this cannot
manufacture short "strings" out of arbitrary integers.

### A.2 — ELF prologue scan

`.eh_frame` only covers functions built with unwind tables; recall against the
full DWARF set was 0.514. The PE scan was gated on an `MZ` magic check and the
AArch64 companion matched PAC prologues only — which the Ubuntu and Alpine
AArch64 builds in the sample tree do not use.

Added ELF x86-64 (`endbr64`, `push rbp; mov rbp,rsp`, `sub rsp,imm`) and
unhardened AArch64 (`stp x29,x30,[sp,#-N]!`, `sub sp,sp,#N`) predicates. Bit
masks are unit-tested against real encodings *and* against near-misses —
`stp x19,x20` is a very common instruction and matching it would over-generate
badly. Prologue seeds stay body-overlap gated: unlike an FDE start this is a
heuristic and must never split a proven function.

### C.2c — orphaned stack-pointer arithmetic

Removing the spill left its other half behind. `push X` lifts to
`rsp = rsp - 8; store [rsp] = X`; with the store gone, a function that saved
four registers rendered four bare `rsp = (rsp - 8);` lines corresponding to
nothing in the source. `rsp` alone was 80 of the remaining register tokens.

Dropped, but only when the stack pointer is never read for anything else. If any
local is addressed relative to it, every adjustment stays — the frame is then
real storage and deleting the arithmetic would move every local.

### D.1c — ARM32 flag-setting arithmetic

The same defect as C.2a and strictly worse, because it was invisible.
`bin_for_mnem` maps `sub` and `subs` to the same `BinOp`, so the `S` suffix was
recognised and then discarded — the flag write vanished without the mnemonic
ever appearing as unlifted. ARMv7 output carried **6.19** leaked flag
temporaries per function against AArch64's 1.45 after C.2a.

Fixed symmetrically: `subs` reuses the `cmp` operand comparison; every other
`S` form claims only zero and sign. A test pins that the *non*-`S` form
fabricates no flags.

### C.3 — cast-chain folding

`castN(castM(x))` collapses to `castN(x)` whenever `M >= N`: the outer cast
observes only the low N bits and a widening inner cast cannot have touched them.
A *narrowing* inner cast is a real truncation and is preserved — pinned by test.

## 6d. The correction — ARM was never behaviourally verified

Everything in §6c about ARM was measured on **rendered output**, not on
behaviour. That was a mistake, and the mistake had a structural cause worth
recording.

### The gate could not see ARM at all

`tools/fixture_harness.py` is the behavioural gate and its matrix is
`{gcc, clang} x {O0, O2}` **on the host**. Every lane is x86-64. The AArch64 and
ARM32 lifters therefore had *zero* execution coverage: a change inverting a
branch in every ARM binary would leave all 656 cases green. That is exactly the
kind of change §6c made.

`tools/arch_roundtrip.py` closes it, for **every** lifted architecture rather
than only ARM. The recovered artifact is portable C, so it does not need to run
on the target — cross-build the fixture, decompile it, build the recovery for the
host, and execute it against the *source* built for the host. No emulator is in
the loop, so a qemu bug cannot be mistaken for a decompiler bug. Judging is
`tools/diff_decompile.py`, invoked as a subprocess exactly the way
`fixture_harness._run_lane` invokes it; it gained `--reference-so` (the
host-loadable object the recovery is executed and linked against) and `--lane`.

Matrix: `{x86_64, i386, aarch64, armv7} x {O0, O2}` over the whole 30-fixture
corpus, keyed `fixture:arch:opt` and ratcheted against
`tests/decompiler_fixtures/arch_baseline.json` via `--check` /
`--write-baseline`. It is lane 3 of `scripts/decbench-local-gate.sh`. i386 is in
because `src/ir/lift_x86.rs` has a 32-bit half the x86-64 gate never exercises.

**A control lane is mandatory and is built in.** `x86_64` builds the fixture with
the same pinned compiler and byte-identical flags as
`fixture_harness.compile_fixture`, so its verdicts must equal that gate's
`gcc:{opt}` verdicts function for function — `control_gate_disagreements`
asserts exactly that, and both `--check` and `--write-baseline` refuse a run
where it does not hold. Measured: **328 executed, 328 pass, 0 fail, 0
disagreements with the committed `baseline.json`.** Without that control the
first ARM numbers were worthless.

### Three harness artifacts the control lane exposed

The prototype's ARM percentages were inflated by its own bugs, all three found
by insisting the control lane be clean:

1. **File-local `static` roots were executed.** They have no dynamic symbol, so
   the reference cannot be called at all; and being local, the round-trip closure
   in `include_referenced_local_callees` matched their own definition line and
   prepended the body under test, so the rebuild died with `redefinition of ...`.
   11 cases, identically in the control and the AArch64 lane — the matching count
   is what gave it away. `diff_decompile.run` now executes exported functions
   only, at every architecture.
2. **The rebuilt C was linked against the foreign-architecture object.** That
   link silently fails and the rebuild falls back to unlinked, so every recovered
   body calling an exported sibling died at load with `undefined symbol`. 44
   cases across the two ARM lanes. It now links against the host reference.
3. **Verdicts were a property of where the gate was run from.** A recovery that
   reads an uninitialised local dereferences whatever the stack held, and three
   channels fed that residue — each found only after fixing the previous one:
   address randomization (`read_counter`, recovered as
   `*(int *)(*(int *)(var1 + 4) + var1)`, segfaulted on 4 of 8 identical runs);
   the caller's environment block, which sits at the top of the initial stack so
   its size shifts every frame beneath it (passed in an interactive shell, failed
   under the pre-push gate's `env -i`); and the length of the scratch directory's
   path, because the dynamic loader's own stack use scales with what it is handed
   (`dense_compute` said `fail` from `/tmp/aa` and `pass` from a 65-character
   sibling). Fixed by `setarch --addr-no-randomize`, a canonical fixed-width
   worker environment, and running the worker with `cwd=workdir` so every path in
   its spec is a short relative name. The randomization setting is part of the
   baseline fingerprint. The x86-64 gate is unaffected: 656 pass / 0 fail under
   both a short and a long scratch root.

### What it found

Committed as `arch_baseline.json`. `structural` = no diffable value (pointer
return, aggregate return, void-with-no-buffer); those carry structural
assertions in the other lane. `skip` = a declared, probed gap: `__int128` is not
a type on a 32-bit target, and Debian ships no `aarch64-linux-gnu-g++`.

| lane | executed | pass | fail | structural | skip | correctness |
|---|---|---|---|---|---|---|
| x86-64 (control) | 328 | 328 | 0 | 38 | 0 | **100%** |
| i386 | 272 | 160 | 112 | 38 | 2 | **59%** |
| AArch64 | 317 | 107 | 210 | 9 | 2 | **34%** |
| ARMv7 | 262 | 102 | 160 | 8 | 4 | **39%** |

Fail = differing return value, differing mutated buffer, a crash, or C that does
not rebuild. On the two 32-bit lanes the recovery is rebuilt at the host pointer
width, so a `fail` there can also mean the recovered C is non-portable rather
than semantically wrong; confirm which before acting on it. The 64-bit lanes
carry no such caveat.

**The ARM lifters are broadly incorrect**, and it was invisible because nothing
executed them. 32-bit x86 is better but far from the 100% the x86-64 lane holds.

### What §6c's ARM work was actually worth

Measured with the prototype by stashing `lift_arm32.rs` and `lift_arm64.rs` and
re-running (numbers on its narrower single-`-O0` matrix):

| | pass before | pass after |
|---|---|---|
| AArch64 | 58 | **59** |
| ARMv7 | 78 | **78** |

**One function.** The `subs`/`adds` flag work moved behavioural correctness by a
single function on AArch64 and none on ARMv7. The reported gains — flag
temporaries 6 → 1, lines 62 → 51 — were real but *cosmetic*: rendering
improvements layered on semantics that are wrong roughly two thirds of the time.

The one thing checked properly was the `cmp_unsigned` failure on ARMv7, which
reproduces identically with the changes stashed, so it is pre-existing rather
than a regression. That is the only defensible claim in the ARM half of §6c.

### Consequences for the plan

* **ARM correctness outranks every remaining item.** Density and structuring
  work on a 34%-correct lifter is polish on something that does not work.
* `tools/arch_roundtrip.py --check` is lane 3 of the pre-push gate, and a missing
  cross compiler FAILS there rather than skipping. A lane with no execution
  coverage will drift again otherwise — that is precisely how this happened.
* Any future claim about an architecture must cite an execution differential for
  *that architecture*. Rendering metrics — leaked registers, flag temporaries,
  line counts — describe the artifact and say nothing about whether it is right.

## 7. Sequencing

Ordered by leverage per unit effort, with dependencies respected.

**Phase 1 — one week, unblocks everything else**

1. **A.1** `.eh_frame` seeding *and* carry FDE ranges through. (~1 day)
2. **A.3** PLT seeding + stop seeding stub tails; instrument seed provenance
   first. (~2 days)
3. **B.1** authoritative function end from the FDE range, `noreturn` as terminal,
   verifier assertion. (~3 days)

Phase 1 alone should move discovery recall 13% → ~90%, invented calls 35% → ~0%,
and imported-callee recall 52% → ~95%. It is mostly wiring of parts that already
exist, and it addresses the only measured *correctness* defect.

**Phase 2 — two weeks, visible quality**

4. **C.3** cast-chain folding (~1–2 days, independent).
5. **C.2** no register views in rendered output (~3 days).
6. **A.2** ELF/AArch64 prologue scan (~2–3 days).
7. **D.1** ARM data-reference and PLT resolution (~4 days).
8. **B.2** re-measure prototypes, then fix the residual.

**Phase 3 — the deep one**

9. **D.2** AArch64 discovery profiling and budget enforcement — *pull forward
   into Phase 1 if AArch64 is on the near-term path.*
10. **C.1** stack-slot SSA and general copy propagation (~2 weeks, highest risk).

---

## 8. How progress gets measured

The harness built for the original comparison is reusable and lives in the
session scratchpad (`bench/`). It should be moved into the repo — suggested home
`tools/extbench/` — because these numbers need to be re-runnable per commit, not
per investigation.

| script | what it answers |
|---|---|
| `gt.py` | ground truth: DWARF subprograms (name, VA, size, param types), `.eh_frame` FDEs, imports |
| `drive.py` / `runall.sh` | run all four tools over one binary against the *same* stride-sampled function set |
| `analyze.py` / `report.py` | success, recall, prototypes, goto density, machine leakage, callee/string recovery |
| `callcheck.py` | **the correctness probe** — emitted calls vs `llvm-objdump` over the exact DWARF byte range |
| `compilable.py` | `gcc -fsyntax-only` rate |
| `sidebyside.py` | all four tools' C for one ground-truth function |
| `discover_only.py` | cross-tool discovery consensus where no ground truth exists |

**Ratchet these seven numbers per phase.** Four are the strengths from §1 that
must not regress; three are the targets.

| metric | today | after Phase 1 | after Phase 2 | after Phase 3 |
|---|---|---|---|---|
| invented calls / fn | 1.08 | **0.00** | 0.00 | 0.00 |
| imported-callee recall | 52% | **≥95%** | ≥95% | ≥95% |
| discovery recall (stripped, `.eh_frame`) | 18% | **≥90%** | ≥95% | ≥95% |
| local declarations / fn (Tier B) | 72.2 | 72 | ~40 | **≤20** |
| raw registers / fn (Tier B) | 9.4 | 9.4 | **0.00** | 0.00 |
| string literals / fn (ARM) | 0.00 | 0.00 | **≥2.0** | ≥2.0 |
| decompile success (stripped) | 93/93 | 93/93 | 93/93 | 93/93 |
| C well-formedness | 90% | ≥90% | ≥90% | ≥90% |

### Three harness lessons worth keeping

Each of these produced a wrong headline before it was caught, and each will bite
again if the harness is re-implemented from scratch:

1. **angr reports 32-bit ARM functions at `addr | 1`** (Thumb convention) while
   DWARF `DW_AT_low_pc` is even. Exact-VA matching scored 19 found functions as
   misses.
2. **"First N functions by address" is a biased sample.** `bash`'s lowest 40
   FDEs are a contiguous run of 29–46-byte stubs. Use an even stride.
3. **`pyghidra.open_program()` defaults `project_location` to the binary's own
   directory and reopens it if present**, so a second run over the same binary
   skips auto-analysis and looks 3–8× faster. Always pass an explicit temporary
   project location — and note it otherwise writes `<name>_ghidra/` into the
   sample tree.

---

## 9. Explicitly not in scope

- **Chasing Ghidra on `undefined`-width types.** Glaurung emits none, by design.
  That is a real difference in philosophy, not a gap.
- **Matching RetDec on wall clock for small binaries** (0.13 s vs 5.9 s). RetDec
  is whole-image with no per-function entry point; the comparison is not
  like-for-like, and Glaurung is already *fastest of the four* on large binaries,
  which is the case that matters.
- **Reducing goto density as a goal in itself.** 3.12/100 lines against Ghidra's
  2.47 and angr's 1.31 is the smallest gap in the study, and structuring work
  should follow C.1 rather than precede it — fusing values first will remove
  some gotos for free.
- **A general fix for stripped ARMv7 Thumb.** Stripping removes `$a`/`$t`
  mapping symbols and no disassembler here recovers mode reliably; the reference
  itself was unscoreable there. Do not optimise against a metric that cannot be
  measured.

---

## 10. Two data-quality issues in the sample tree

Unrelated to the decompiler, but they will mislead the next person who benchmarks
against `/nas4/data/binary-analysis`:

- `binaries-small/alpine3.19/linux-arm64/` is a **byte-identical copy of the
  armv7 tree** (same MD5, `ELF 32-bit ARM`) — it contains no AArch64 binaries at
  all. `alpine3.18` is correct.
- `alpine3.19/.../bin/busybox` has a 4-byte `.eh_frame`
  (`-fno-asynchronous-unwind-tables`), so it supports no FDE-based ground truth
  and must be scored by cross-tool consensus or not at all.

---

## 11. AArch64 correctness: what was fixed, and what is left

Measured with `tools/arch_roundtrip.py --arch aarch64`. The x86-64 control lane
was 328 pass / 0 fail before and after every change below, and
`tools/fixture_harness.py` stayed at 656 pass / 0 fail.

    aarch64   107 pass / 210 fail   33.8%   ->   261 pass / 57 fail   82.1%

Seven root causes, each with its measured delta:

| # | root cause | pass |
|---|---|---|
| — | baseline | 107 |
| 1 | `wN`/`xN` were two SSA values, and a 32-bit write did not zero-extend its parent (`ssa::parent64` was hard-coded to x86-64) | 116 |
| 2 | `xzr`/`wzr` read as a register instead of zero (133 `str wzr` sites), and `ldrsb`/`ldrsh`/`ldrsw` did not sign-extend | 166 |
| 3 | ~30 scalar mnemonics lifted to `Op::Unknown`, `ccmp` alone in 58 failing functions | 197 |
| 4 | shift/extend modifiers (`lsl #3`, `sxtw`, `[x1, x2, lsl #3]`) were dropped entirely — 320 sites | 240 |
| 5 | `cmn`/`tst` defined no flags at all on the decompile path | 252 |
| 6 | the AArch64 stack canary (a GOT-indirect load) was unrecognised; the recovered C dereferenced a null synthetic global. And `subs Rd,Rn,Rm` with Rd==Rn read its flags off the already-overwritten destination | 259 |
| 7 | an `adrp`+`add` global whose page collided with a symbol stayed `name + off` and rendered as a raw original-image address | 261 |

`18_binary_heap:aarch64:O0:heap_pop`'s `skip_exec_lanes` declaration was removed:
the hang was root cause 2 (`str wzr` left the sift-down index uninitialised, so
the loop indexed the heap with garbage and did not terminate). Both functions in
that lane now execute and pass.

### The 57 that remain — NOT root-caused, do not assume they are one bug

Only 11 still contain an instruction this lifter does not model, and all 11 are
NEON (`movi`, `fmov`, `addv`, `tbl`, `dup`, `ushl`, `umaxp`, `cmtst`, `mvni`,
`bit`, `clz`, `rev16`) from -O2 auto-vectorisation. Scalar instruction coverage
is effectively complete. The rest are downstream of the lifter:

- **`06_calling_conventions` (7).** `sum_arg9`/`sum_arg10` read the 9th/10th
  argument from `[sp]`, which is never bound to a parameter — the recovered body
  reads an unassigned `stack_top`. AArch64 stack-passed arguments are unmodelled.
  `fib`/`fact_mod` are a separate, unexamined problem.
- **`08_indirect_dispatch` (5), `11_call_shapes` (5).** Not examined.
- **`07_packet_parser` (4), `17_hash_table` (2), `19_disjoint_set` (2),
  `20`–`25` (10), `15`/`16` (4).** All have local arrays; `graph_bfs`'s recovered
  stack objects are over-sized and overlapping (`local_28[40]` for a 16-byte
  array). This looks like stack-object layout recovery, i.e. task #20's
  territory, not lifter semantics — but that was inferred from one function and
  is NOT proven.
- **`02_integer_widths` (4).** `rotl16_3`, `trunc_u16_after_mul`, `mul_widen:O2`,
  `rt_u32:O2` — a 16-bit-width residue the parent-zero-extension rule does not
  cover, since it only models the 32-bit view.

One thing the canary work left half-done: the guard now renders as its own
address constant (`stack_7[16] = 0x1ffd8; if (stack_7[16] != 0x1ffd8) …`) rather
than collapsing to the `// stack-canary check` comment the x86-64 path produces.
That is self-consistent and executes correctly, but it is not what
`collapse_canary_save` is supposed to leave behind, and nobody has checked why
that pass does not fire on the AArch64 shape.

## 12. The three measurement gaps, closed — 2026-08-02

`tools/arch_roundtrip.py` reported `100.0 / 89.7 / 82.1 / 69.8` across
`x86_64 / i386 / aarch64 / armv7`. Three places in it could not go red no matter
what the decompiler did. Each is now either fixed or quantified.

### 12.1 The 32-bit rebuild-width confound

The recovered C is rebuilt and executed at the HOST's pointer width, so on the
32-bit lanes the two sides of the differential are not built for the same
machine. Options were evaluated in the order given:

- **`gcc -m32`.** Multilib IS present on this host (`dpkg --print-foreign-
  architectures` reports `i386`; `gcc -m32` links a working binary). Multilib was
  never the blocker. The blocker is the EXECUTOR: `tools/diff_decompile.py`'s
  worker is 64-bit CPython calling `ctypes.CDLL`, which refuses a 32-bit object
  outright (`wrong ELF class: ELFCLASS32`). Executing at 32 bits means replacing
  the worker with a generated C driver — a new comparator, and therefore a new
  source of failures attributable to the harness rather than the lifter, which is
  precisely the mistake the pre-control-lane prototype made (50 invented "AArch64
  failures"). Not taken.
- **`qemu-i386`/`qemu-arm`.** Same blocker: there is no 32-bit Python interpreter
  to run under them, so it still needs the C driver first. The emulator is not
  what stands in the way. Not taken.
- **Make the confound detectable.** Taken, in three parts:

**(a) ABI comparability — `incomparable`.** The host reference's own DWARF
prototype is now compared against the target's, and a function whose ABI types
disagree gets NO execution verdict (`diff_decompile.abi_incomparable`). `long` is
4 bytes on i386/ARM32 and 8 on the host, so `long count_up(int)` was being called
with a 32-bit argument through a 64-bit prototype and its 64-bit return truncated
to 32 before comparison. **32 measurements** were being scored that way — 16 per
32-bit lane, in `12_loop_rotation` (all 7 `long`-returning functions, both opts)
and `06_calling_conventions:sum_mixed_widths`. 31 of them read `pass`. They are
not passes; they are the harness comparing a truncation against itself. The same
32 were identified independently by diffing the two builds' DWARF outside the
tool, which is how the delta was verified function by function.
`aarch64` has zero — the control for the whole idea.

**(b) Target-buildability — `nonportable`.** Every recovered body on every
foreign lane is now compiled with the target's own driver, object only
(`diff_decompile.native_rebuild_diagnostic`). Result on the current corpus: **0**.
Two things had to be held fixed for that number to mean anything, and both were
found by a first run that reported 10 false positives:
  - the harness PRELUDE spelled `int64_t` as `long` and `undefined16` as an
    unguarded `__uint128_t`, neither of which exists at 32 bits (fixed: a
    portable `NATIVE_PRELUDE`, and `#ifdef __SIZEOF_INT128__` in `PRELUDE`
    itself, which is a no-op for the pinned 64-bit rebuild);
  - the target drivers are host gcc 15 while the rebuild is the pinned gcc 11,
    and gcc 14 promoted five warnings to errors. `07_packet_parser`'s
    `read_be32(local_28)` passes a machine word where a pointer is expected —
    a real TYPE-RECOVERY defect, equally present at 64 bits, and not evidence
    that the target cannot compile the code. `_NATIVE_PARITY_FLAGS` pins the
    dialect and those five diagnostics so the probe measures the architecture and
    nothing else.

**(c) Residue, quantified — `--width-audit`.** A failing recovery whose C names no
type that changes size between ILP32 and LP64 computes the same values at either
width, so the host rebuild IS the 32-bit semantics and the failure is real. One
that does cannot be separated without a genuine 32-bit run. Measured:

| lane  | failures | real semantic defect | unseparable from the confound |
|-------|---------:|---------------------:|------------------------------:|
| i386  |       28 |                   18 |                     10 (36 %) |
| armv7 |       78 |                   35 |                     43 (55 %) |
| both  |      106 |                   53 |                     53 (50 %) |

Half the 32-bit failure population still cannot be attributed. That is the
residue, and it is now a number rather than a sentence.

### 12.2 `__int128` on 32-bit lanes: two claims that were one

`detect_unsupported` skips `02_integer_widths` on i386/armv7 because the SOURCE
uses `__int128`, which no 32-bit target has. That is true and stays. It was
conflated with a second claim — that Glaurung may not EMIT `__int128` for a
32-bit target — and the conflation is why the renderer could emit it for every
32-bit multiply-high with all four lanes green. The two are now separate: the
exemption covers only the unbuildable fixture, while 12.1(b) compiles every
recovered body for its own architecture on every foreign lane.

`python/tests/test_decompiler_wide_arithmetic_width.py` was checked for
vacuity and is sound: it builds a real i386/armv7 object, asserts the recovered C
contains no `__int128`, asserts positively that it DOES contain the double-width
`long long` intermediate (so "no `__int128`" cannot be satisfied by recovering
nothing), and rebuilds the fragment with `gcc -m32`. Inspected output confirms
the assertion bites on the real thing: `div_by_ten` recovers
`((unsigned long long)(unsigned int)(-0x33333333LL) * …) >> 32`. Its x86-64
control asserts a genuine 64x64 multiply-high still keeps `__int128`.

### 12.3 PE32 `type_match` 0.1012 -> 0.0417 — root-caused, NOT pre-existing

The premise that this predates the branch work is **wrong**. The two sides of that
A/B (`docs/design/decbench-submission-readiness.md:191`, values in
`glaurung-evidence-wt9c0ba99/type_match_all_columns.json`) are commit `5f8b933`
and `a374669` **plus the uncommitted tree**. `git show HEAD:src/python_bindings/ir.rs
| grep -c word_width_implies_int` returns `0`: the cause is uncommitted.

The whole 0.0595 delta is two functions. The other six PE32 entries are identical
on both sides:

| key | 5f8b933 | now |
|---|---|---|
| `mydoom::O0::xmemcmpi` | 0.3333 | 0.0 |
| `x0r-usb::O0::IRC_Connect` | 0.1429 | 0.0 |

Cause: `word_width_implies_int(cc)` in `src/python_bindings/ir.rs` (uncommitted)
returns `false` for `CallConv::Cdecl32`, which stops every 4-byte frame slot and
every 4-byte register definition from contributing an `Int{width:4}` hint on
i386. With no hint, `ctype_for` falls back to its `long` default. cdecl32 passes
every argument on the stack, so parameters lose their types too. DecBench's
`type_match` hard-codes LP64 (`TYPE_MAP: "long" -> "long long"`), so a recovered
`long` can never match a ground-truth `int`. Confirmed live on the stripped kit
binaries: `bin_156.exe@0x401af2` recovers `int sub_401af2(long, long, long)`
where `5f8b933` gave `int sub_401af2(int, int, int)`. Local `int` declarations
across the 8 PE32 payloads went 53 -> 1.

**Not fixed, deliberately.** The one-line revert (`word_width_implies_int` -> always
`true`) is provably scoped to `Cdecl32` — there is a test asserting the predicate
is `true` for every other convention, and on the 64-bit conventions `word == 8`
so the branch cannot fire — so x86-64 and ARM32 output would not move at all.
But:

- the upside is 2 true positives out of 8 functions: PE32 type_match 0.0417 ->
  0.1012, headline 235-function type_match +0.002;
- the cost is the i386 pointer-truncation class the gate was added to kill
  ("50 of i386's 110 execution failures", per the code comment), and PE32
  byte_match, which improved 0.1180 -> 0.2027 in the same change.

And there is a sharper reason to leave it: **the gate is optimising a metric the
confound created.** Those 50 i386 execution failures were failures of a
host-width rebuild. Emitting `long` for a machine word is right at 64 bits and
wrong at 32 — on a real i386 `long` is 4 bytes, so the "fix" makes the recovered
C worse for its actual target while making the harness greener. §12.1(c) is what
would settle it, and it cannot yet: 10 of i386's 28 remaining failures are in the
unseparable bucket. The correct fix is the one the code comment already names —
propagate pointer types through copies instead of inferring a type from storage
width — with the width-4 `int` hint suppressed only where there is pointer-ish
evidence (dereferenced, used as an address base, passed to a pointer parameter).
That is a dataflow pass in `types_recover`, not a one-liner. Scheduled, not done.

### 12.4 What moved

| lane | before | after | why |
|---|---|---|---|
| `x86_64` | 328/328 100.0 % | 328/328 100.0 % | control unchanged — the instrument check held throughout |
| `i386` | 244/272 89.7 % | 228/256 89.1 % | 16 verdicts withdrawn as ABI-incomparable (all had read `pass`) |
| `aarch64` | 261/318 82.1 % | 261/318 82.1 % | unchanged; 0 incomparable, 0 non-portable |
| `armv7` | 183/262 69.8 % | 168/246 68.3 % | 16 withdrawn (15 `pass`, 1 `fail`) |

Newly-exposed real defects: **0**. Newly-fixed artifacts: **0**. Withdrawn as
unmeasurable: **32** (31 previously green). The baseline was refreshed only after
the 32 were enumerated one by one and cross-checked against an independent DWARF
comparison of the two builds. `comparison_problems` was also tightened: a change
between two non-`pass` statuses (`fail -> nonportable`) used to pass the ratchet
silently and is now reported as `RECLASSIFIED`.

## 13. Analysis budgets and interruptibility — 2026-08-02

### 13.1 `Budgets.timeout_ms` never bounded an analysis

It is a PER-FUNCTION clock: `discover_function` restarts it on every seed. A
binary with 20 000 functions could spend 20 000 x `timeout_ms` and still be
inside budget, and the whole-binary seed scans (vtables, jump tables, `.pdata`,
`.eh_frame`, prologue/thunk/tiny-stub/raw-call/code-pointer scans, FLIRT) checked
nothing at all.

`Budgets.total_timeout_ms` is the whole-run ceiling, enforced by `cfg::Deadline`
at every phase boundary (`scan_within`), in the seed worklist, and inside both of
`discover_function`'s loops. Exceeding it sets `FunctionDiscoveryStats::
hit_total_timeout` and feeds the existing `truncated` flag, and `glaurung cfg`
prints how much was lost:

```
WARNING: analysis budget exceeded (1 ms, used 9 ms) - discovery was TRUNCATED
with 1 seed(s) never analysed; 0 function(s) below are a partial result.
Raise --total-timeout-ms (0 = no ceiling).
```

The default is `0` — no ceiling — on purpose. A ceiling that truncates changes
what discovery finds, and every recorded corpus number was measured without one;
applying a wall clock to existing callers silently would move those numbers with
nothing to attribute the movement to. `glaurung cfg --total-timeout-ms` is the
opt-in.

### 13.2 Releasing the GIL is necessary and NOT sufficient

`Python::allow_threads` (`detach` in pyo3 0.26) lets other Python threads run,
but CPython executes a signal handler only on a thread that holds the GIL and is
running Python bytecode — and the calling thread is inside Rust for the whole
analysis. Measured A/B on a 123 MB `libLLVM-18.so.1`, `SIGINT` at t=5.0 s:

```
analyze_functions_bytes  (holds the GIL - the old behaviour)
    INTERRUPTED at t=  55.1s
analyze_functions_path   (interruptible)
    INTERRUPTED at t=   5.3s
```

50 seconds of unkillable analysis after the user asked it to stop. The fix is
`analysis::analyze_interruptible`: the analysis runs on a scoped worker thread,
the calling thread stays in `Python::check_signals` sleeping with the GIL
released, and a signal sets the `Deadline` cancellation flag the discovery loops
already poll. Real CLI, real `SIGINT`:

```
t=8.0s  sending SIGINT to pid 1039958
t=8.9s  exited rc=130
tail: Interrupted by user
```

The `_bytes` entry points deliberately keep the GIL: their input is a BORROWED
Python buffer, and releasing it would let another thread resize a `bytearray`
underneath the analysis. Callers who need either property want the `_path` form,
which owns its data.

## 14. P8 — re-measuring extbench, and what the re-measure found — 2026-08-03

The plan deferred the string/callee gap with an explicit instruction to measure
before investing, because the recorded extbench numbers predated the whole
lifter campaign. That was the right call: two of the three "gaps" had closed,
one "regression" was an artifact of the harness, and the two genuine defects the
re-measure surfaced were not the ones the plan named.

Only Glaurung was re-run. Ghidra, angr and RetDec are unchanged versions, so
their result JSON was reused rather than regenerated — the reference columns in
every table below are byte-identical to the original run.

### 14.1 What actually moved (Tier A, 9 stripped binaries, 3 architectures)

| | before | after | best reference |
|---|---:|---:|---|
| discovery recall vs `.eh_frame` | 0.183 | **1.000** | 1.000 (Ghidra) |
| imported-callee recall | 52% | **94%** | 100% (Ghidra) |
| invented calls per function | 1.06 | **0.00** | 0.00 (all) |
| functions with an invented call | 35% | **0%** | 0% (all) |
| condition flags per function | 6.58 | **0.50** | 0.00 (Ghidra) |
| string literals per function | 0.505 | **1.100** | 4.121 (RetDec) |
| resolved callees per function | 3.086 | **4.597** | 7.125 (Ghidra) |
| wall clock per binary | 5.88 s | **3.39 s** | 0.13 s (RetDec) |

ARMv7 strings went `0.000 -> 0.665`, which retires the plan's claim that ARM32
"has no analogue of `aarch64_literals.rs` ... genuinely missing code rather than
a wiring gap". It is now ahead of Ghidra on that metric (0.067) on stripped
ARMv7 specifically. AArch64 strings went `0.000 -> 1.071` and callees
`2.892 -> 4.877`.

On Tier B (real distro binaries) discovery recall went `0.564 -> 1.000` and wall
clock `17.5 s -> 5.07 s`, against Ghidra 26.5 s, angr 39.9 s and RetDec 42.1 s —
Glaurung is now the fastest of the four by roughly 5x, having been the second
slowest. It also now completes `ub_grep_arm64`, which it previously could not
finish at all; the reference tools had always covered it, so this is the first
run where all four tools are scored on the same 7 binaries.

### 14.2 The AArch64 `argc` "regression" was a macro-average artifact

The report showed AArch64 prototype arg-count accuracy falling `0.766 -> 0.565`
and nothing else regressing. It is not a regression.

`report.py` averages each metric per binary and then averages the binaries.
`strip_iconv_arm64` contributes only **2** scored functions, so one function
flipping moves that binary's rate by 0.500 and the reported mean by 0.167.
Micro-averaged over all 31 AArch64 functions the same data reads
`0.710 -> 0.742` — an improvement. Per binary:

```
strip_getconf_arm64   before 4/7=0.571   after 2/7=0.286
strip_getent_arm64    before 16/22=0.727 after 20/22=0.909
strip_iconv_arm64     before 2/2=1.000   after 1/2=0.500
```

Filed as a harness defect: a per-binary mean must not be presentable as a
per-function one without its `n`.

### 14.3 Two real defects the re-measure did surface

**Phantom trailing parameters.** `main` in `strip_getconf_arm64` recovered as
four parameters against DWARF's two, and `strip_iconv_arm64:main` as six. The
cause was not architectural: `live_in_arg_slots_llir` already skips `Op::Call`
so the `annotate_calls` may-use list cannot be read as a parameter, but that
skip was laundered through a synthetic phi copy. `insert_phi_copies` keeps a phi
whose destination appears in `def_uses` — which reports the call's argument list
— and materialises it as an `Op::Assign`, which the `Op::Call` guard never sees.
First touch of `x3` then reads as a parameter.

This was **not** AArch64-specific: the same mechanism produced phantom
parameters on x86-64 (`strip_getconf_amd64:print_pathconf`,
`strip_iconv_amd64:main`) and on 5 ARMv7 functions. Corpus-wide arity against
DWARF over 93 functions: `exact 53 -> 62, over 35 -> 25, under 5 -> 6`.

One residual x86-64 over-report has a genuinely different cause — GCC's
stack-realignment `push %rcx` is a real architectural read — and is filed
separately rather than folded into a heuristic.

**The AArch64 prologue annotation was silently lost.** `collapse_prologue` keyed
on the fp/lr spill stores, and `prune_callee_saved_spills` correctly deletes
them as dead, so `%sp = (%sp - 48); %fp = %sp;` reached the reader unannotated.
Recognising the pruned shape is safe; *collapsing* it is not. At -O0 AArch64
keeps `fp` live and addresses every local through it, so draining `%fp = %sp`
broke 10 execution-differential cases. The pruned shape therefore annotates and
deletes nothing — the deletion stays gated on the spills, which are what prove
the frame pointer dead.

### 14.4 A gate that had never run

`callcheck.py` — the only probe in the harness that checks emitted calls against
the calls the CPU actually makes — read ground truth from `gt["dwarf"]` only.
Tier B is `.eh_frame`-sourced, so `dwarf` is empty there and the probe scored
**zero functions on every stripped distro binary** while still printing a
well-formed table of dashes and `0.00`. Fixed to fall back to `gt["fde"]`, and
to say `NOTHING WAS SCORED` rather than render an empty result that reads like a
clean one.

Separately, `llvm-objdump --start-address` does not make disassembly cheap — it
decodes the whole image and filters what it prints — so the per-function call
was O(filesize). Now one disassembly per binary, sliced by address: byte-identical
Tier A output, minutes to 0.25 s.

**That did not make Tier B run, and this is not a solved problem.** With the FDE
fallback and the single-disassembly rewrite both in place, the probe still wedges
on the Tier B corpus — 17 minutes elapsed against 4 seconds of CPU, sleeping in
`poll_schedule_timeout` on a subprocess pipe with no live child, past a
`timeout=600` that should have fired. The cause is not diagnosed. So the
imported-callee numbers in §14.1 are **Tier A only**; call quality on the large
distro binaries is unmeasured, not measured-and-fine. Filed.

### 14.5 What is still short

The string gap is the one the plan named and it is still the largest: 1.100 per
function against RetDec's 4.121 and Ghidra's 3.792 on Tier A. Resolved callees
4.597 against Ghidra's 7.125. Verbosity remains the other: 53.5 local
declarations per function on Tier B against Ghidra's 13.5. None of these are
correctness defects — they are completeness and readability — but they are what
separates the output from a production decompiler's.

## 15. P9 execution closure — 2026-08-03

The ten-item follow-up was executed as one evidence-bounded campaign. The string
and callee-name work deliberately stopped at diagnosis; the request explicitly
required root cause before code, and the corrected architecture split disproved
the proposed single ARM/data-xref explanation. The other eight items landed with
focused regressions and current native-extension output.

| item | current result | retained acceptance evidence |
|---|---|---|
| string recovery | diagnosed, no speculative recovery heuristic added | `string-recovery-root-cause-2026-08-03.md`; x86-64 remains the widest real string deficit and the misses split across address provenance, join loss, and short-string policy |
| phi-copy coalescing | implemented past missing-width evidence while refusing contradictory arithmetic widths | Tier B local declarations/function **52.445 -> 48.217** (Ghidra 13.468); real stripped AArch64 loop still recovers 2 parameters after parameter evidence was moved before provenance-erasing coalescing |
| interprocedural pointer parameters | direct-callee layouts and recovered fixed-arity contracts now apply to SysV AMD64, AArch64, ARM hard-float, and 32-bit cdecl | callee layout tests cover register and stack conventions; pointer parameter spills remain exact rather than width-guessed |
| large-function GED | unwind/symbol extents now bound the real body; the 15 retained historical outliers all decompile | aggregate GED **4,434 -> 1,856** (-58.1%); wrapper collapses include `em_inc_search_prev` 267 -> 0, `fill_inbuf` 454 -> 4, and `modinfo_name_do` 216 -> 7. Remaining high cells are genuinely large bodies, including Betaflight's 350-node dispatcher, rather than adjacent-function capture |
| resolved callee names | scoped with the string diagnosis, then separated where the data disagreed | corrected x86-64 density is 3.774 vs Ghidra 3.893; the large residual is ARMv7 PLT/call-target resolution, not the x86 string root cause |
| fused bitwise guards | pure, explicitly boolean SETcc trees recover `&&`/`||`; eager evaluation is retained for memory reads or other unsafe leaves | positive logical-disjunction regression plus memory-read and unobserved-value refusal controls |
| x86 ADC/SBB flags | CF/ZF/SF/OF are exact over the wrapped result; PF/AF stay explicitly undefined | ADC/SBB unit regressions pass and x86-64 `14_flag_effects` is 14/14 across O0/O2 |
| ARM adds/adc/subs/sbc | exact carry/borrow, zero, sign, and overflow in the existing borrow polarity | randomized O0/O2 flag fixture preserves `dec_preserves_carry`; a new real ITTE sequence proves narrow Thumb ADD/SUB do not overwrite the incoming `cmp` carry. Existing `lo/hs/ls/hi` polarity assertions remain unchanged |
| instruments | micro-averaged rates with denominators; Tier B uses one bounded local disassembly per binary and refuses an empty score | aggregation tests pass; Tier B call check completes in **1.52 s**, scores **263** Glaurung functions, reports 63% imported-callee recall and **0/263** functions with an invented import call |
| `cpp_exception` | Itanium throws/catches recovered on AArch64, ARM EHABI, and i386 | all six non-control cells pass at O0 and O2. Fixes include AArch64 bit-branch targets, Itanium runtime arity, relocation-backed `_ZTIi`, throw-value preservation, ARM EHABI LSDA discovery, and catch-return folding |

The GED replay used an isolated materialized tree. The retained shared benchmark's
`function_results.json` and `scoreboard.toml` were restored byte-for-byte from
their immutable `24b3826` evidence snapshot after an exploratory evaluator run;
no `glaurung_current` artifact remains in that tree.

The final architecture ratchet matches its refreshed baseline exactly with no
regressions and 25 verified improvements: x86-64 328/328, i386 232 behavioral
passes, AArch64 274, and ARMv7 202. The Rust library gate passes 1,802 tests;
the focused Python decompiler/instrument tests and all 24 register-view semantic
tests pass.
