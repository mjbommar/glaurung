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

## 16. The byte_match regression — attributed, NOT root-caused — 2026-08-04

`byte_match` on the 250-function holdout fell **0.2392 -> 0.2005** between the
`fix1` package and `89b220e`, and no gate saw it for four commits. Attribution,
by extracting and scoring three trees:

| package | byte_match | vs previous |
|---|---:|---|
| `fix1` | 0.2392 | — |
| `89b220e` | 0.2005 | 43 improved / **77 worse** |
| `+ strings` | 0.2015 | 11 improved / **0 worse** |

The string work is strictly positive. The loss belongs to the campaign commits.
**The cause within those commits is still unknown.**

### A wrong root cause, and how it was caught

This section first claimed the cause was *overlapping frame slots* — emitted
units declaring `local_50[80]` spanning into `local_70` and `local_78`. That was
an artifact of reading the slot names backwards.

`alloc_name` formats `local_{:x}` from `disp.unsigned_abs()` under `disp < 0`.
`local_50` is therefore `[rbp-0x50]` — eighty bytes **below** the frame pointer.
The stack grows down, so a LARGER label is a LOWER address and ascending memory
order is DESCENDING label order. Sorting by label inverts every comparison and
makes a correctly-tiled frame look like a pile of overlaps:

```text
local_80   [fp-128, fp-120)
local_78   [fp-120, fp-112)
local_70   [fp-112, fp-80)
local_50   [fp-80,  fp+0)     <- tiles exactly; no overlap anywhere
```

The independent check that settles it: the emitted canary write is
`*(long *)(&local_50[0] + 72)`, and `fp-80+72 = fp-8`, which is exactly where
x86-64 puts the stack canary. The frame model was right; the analysis was wrong.

Re-measured with the correct ordering, overlaps are a real but MINOR
phenomenon — and far too small to account for 77 regressed functions:

| | units with an overlap | overlapping pairs |
|---|---:|---:|
| `fix1` | 11 / 224 | 45 |
| `89b220e` | 17 / 224 | 50 |

(The inverted model reported 26 -> 77 units and 72 -> 158 pairs, which is what
made it look causal.)

### What is actually established

* the regression is real, is 16 %, and belongs to the four campaign commits;
* it is NOT the string work;
* it is NOT primarily frame-slot overlap;
* every existing gate is blind to it, because all of them ask what the recovered
  code *does* and this changes what it *claims about itself*.

Next step is a bisect across `e91c7d0`, `f5b4e0f`, `20f9acd`, `89b220e`, scoring
`byte_match` at each. `f5b4e0f` (phi/width coalescing) remains the prime suspect
because it is also the commit that broke the three `linkedlist`/`matrix` GED
cells, but that is a hypothesis and the last one did not survive contact.

### New gate: `python/tests/test_decompiler_emission_invariants.py`

Seven properties, each checked on all four architectures at `-O0` and `-O2`
(48 cases). They are self-consistency properties of the emitted translation
unit, not copies of any benchmark metric:

1. frame locals occupy disjoint byte ranges;
2. an unassigned value never reaches an observable use (entry spills of
   callee-saved registers are excluded by construction: `slot = varN` where
   `varN` is the caller's value is meaningful and universal);
3. an emitted prototype agrees with its own call sites;
4. recovered arity matches the source for a function with more arguments than
   any of the four ABIs passes in registers;
5. decompiling the same bytes twice is deterministic;
6. every local used is declared;
7. a pointer selected in two predecessors is defined on both paths.

Fixture: `tests/decompiler_fixtures/invariants/frame_and_arity_shapes.c`,
written for the properties rather than derived from any corpus, and deliberately
NOT under `decompiler_fixtures/src` — that directory is auto-discovered by the
shared execution gate, and dropping a file into it silently took that gate from
656 pass / 0 fail to 664 pass / 12 fail.

All 48 currently pass. Property 1 keeps a `FRAME_OVERLAP_KNOWN_BAD` ratchet that
is now empty and fails if any listed lane starts passing, so it can only shrink.

## 17. A recovered frame array invites a stack protector — 2026-08-04

One mechanism behind the `byte_match` loss, found and fixed.

### The defect

A recovered frame slot renders as `unsigned char name[N]`.
`-fstack-protector-strong` is the default in every mainstream distro toolchain
and protects **any function containing an array**. So a function that had no
canary in the original acquires a guard load, a guard compare and a failure
branch purely because we spelled a register spill as an array.

`sum_arg1` — source is `return a + 1` — is the clean case. ARMv7 `-O0`:

```text
original                        11 instructions, 12-byte frame, no canary
rebuilt (protector on)          39 instructions, 40-byte frame, + __stack_chk_guard
rebuilt (-fno-stack-protector)  19 instructions
```

Isolating the one variable: similarity to the original is **0.400** with the
protector and **0.733** without it. More than half that function's loss is the
canary, and none of it is anything the decompiler got semantically wrong.

### The fix

Emit `__attribute__((no_stack_protector))` on a recovered function when — and
only when — it declares a frame array **and** the recovered body contains no
`__stack_chk_fail` call. That absence is the evidence the original had no
protector. Where the original DID have one we stay silent and let the rebuild
add its own, which matches the code being compared against.

The attribute is guarded by `__has_attribute` (GCC 5+, Clang) with an empty
fallback, so a toolchain that lacks it still compiles. There was precedent for a
function attribute in this renderer: the `optimize("O1")` guard for
2,000-statement bodies.

### Measured

`tools/recompile_fidelity.py`, ARM fixture corpus, 278 functions:

| | mean |
|---|---:|
| before | 0.6260 |
| after | **0.6606** |

**+0.0346, 51 functions better, 0 worse** — and identical to what
`-fno-stack-protector` on the rebuild achieves, confirming the attribute
captures the whole effect. x86-64 is unchanged (0.6932), because those fixtures'
originals already carry canaries so no attribute is emitted.

Gates: `cargo test --lib` 1,735; `fixture_harness` 656 pass / 0 fail — the
attribute changes what a compiler does with the code, not what the code does;
`decbench_matrix --check` shows no new regressions (the three pre-existing GED
cells are unchanged).

### New tooling

`tools/recompile_fidelity.py` — asks the question `byte_match` asks, but locally
on our own fixtures in seconds rather than ~30 min per holdout column. It
compares the ORIGINAL and REBUILT instruction streams as mnemonic sequences. It
is a proxy, deliberately uncalibrated against DecBench; its value is
differential, which is what makes it usable for finding a regression rather than
only reporting one. `--rebuild-flag` isolates a single compiler variable, which
is how the protector was separated from frame growth.

### Caveat

This was measured with the host's default flags. If DecBench rebuilds with
`-fno-stack-protector`, the canary half of this does not apply to their metric
and only the frame-size half does. The holdout score settles it.

## 18. The three GED cells, fixed — 2026-08-04

`linkedlist:gcc:O2`, `linkedlist:clang:O2` (both 0.0 -> 2.5) and
`matrix:clang:O2` (21 -> 24) had been red since the campaign. All three are
back at baseline; `decbench_matrix --check` reports **no per-cell regressions
across 56 of 56 cells** for the first time since `f5b4e0f`.

### The defect

`linkedlist.c` is one line:

```c
int list_sum(const struct node *h){ int s=0; while(h){ s+=h->val; h=h->next; } return s; }
```

At `-O2` GCC rotates the loop and emits a zero-trip guard. We recovered it
faithfully — and then kept the guard:

```c
ret = 0;
if (((long)arg0 != 0)) {          /* not in the source */
    var1 = 0; var2 = arg0;
    while (((long)var2 != 0)) { ... }
}
```

One extra branch node and two extra edges against the source CFG. `list_find`
in the same file has no rotation and was always clean, which is why the cost
looked like a whole-file mystery rather than one construct.

### Why the fix is sound

`recover_owned_pretested_do_while` **already proved** the guard redundant: it
refuses to rewrite unless `resolve_entry_aliases(latch_guard) == entry_guard`,
i.e. unless the loop's head test, with the prelude's copies substituted, IS the
entry guard. It simply chose to keep the `if` ("so no seed moves across the
entry guard").

Given that proof the guard cannot change behaviour: when it is false the head
test is false too, so the loop runs zero times either way. And the prelude is
`stable_value_expr` throughout — no load, call, or unknown — so hoisting it out
of the guard can neither fault nor be observed. The `if` was sound but
redundant, and redundancy is not free when the metric is graph edit distance.

The earlier decision was deliberate, so the test that asserted the guard was
retained (`an_entry_owned_coalesced_cursor_recovers_a_head_tested_loop`) was
rewritten to assert the new contract *and carry the reason*, rather than
deleted.

### Gates

```
cargo test --lib                  1,735 passed / 0 failed
tools/fixture_harness.py          656 pass / 0 fail
tools/arch_roundtrip.py --check   328/328 control — matches baseline exactly
tools/decbench_matrix.py --check  FULL MATRIX: 56 of 56 cells clean
emission invariants               52 cases, 8 properties
```

The behavioural lanes are untouched, which is the point: removing a provably
redundant branch changes structure, not semantics.

## 19. Two proxies that lied, and one that held — 2026-08-04

### goto density is NOT a proxy for GED

`goto_sink` moved a labelled block whose only predecessor is a single nested
`goto` down to that jump, removing both. Sound in principle — the block executes
exactly when the goto fires — and it measured well on every local number:

| | before | after |
|---|---:|---:|
| gotos | 409 | 364 (-11%) |
| gotos / 100 lines | 8.63 | 7.82 |
| declarations / fn | 17.720 | 17.054 |

Behaviour was untouched: 656/0 on the fixture harness and `arch_roundtrip`
matching the baseline exactly on all four architectures, which is the check that
matters when code moves across nesting levels.

The DecBench matrix then failed it:

```text
statemachine:gcc:O0.ged:        10.0 -> 35.0
statemachine:gcc:O0.byte_match:  0.37 -> 0.21
linkedlist:gcc:O0.byte_match:    0.44 -> 0.34
sort:{gcc,clang}:O0.byte_match:  0.30 -> 0.27, 0.12 -> 0.10
```

A 3.5x structural regression bought with an 11 % readability gain. **Reverted.**
The pass is retained at `src/ir/goto_sink.rs` with its four tests but is NOT
wired into the pipeline; anyone re-enabling it must explain `statemachine`.

The lesson is specific: fewer `goto` tokens is not a flatter graph. Sinking a
block *into* an `if` deepens nesting and can defeat the region recovery that
would otherwise have found a loop or switch — which costs far more GED than the
jump saved.

### the local fidelity proxy DID hold

`tools/recompile_fidelity.py` predicted the stack-protector fix (+0.0346 on ARM,
51 better / 0 worse) and that fix survived the matrix unchanged. Same tool, same
corpus, opposite outcome from goto density — because it asks the question
`byte_match` asks (recompile and compare) rather than a readability question
that merely correlates with it.

### two filings of mine were wrong

* **`SBB`/`ADC` SF/OF** was already fixed at `b83a066`, an ancestor of the base
  I filed against. Worse, the symptom I quoted — `__unknown(0)` in a `sf ^ of`
  compare — is how `Expr::Unknown` renders an unrecognised *intrinsic*, not how
  an undefined flag renders, so it could never have been evidence for that
  claim. `28_euler_ode` passes on i386 at both optimisation levels.
* **`push %rcx`** is necessary but not sufficient for the phantom parameter.
  Suppressing it alone changes nothing; the other half is that
  `live_in_arg_slots_llir` `continue`s past `Op::Call`, so a call that clobbers
  `rcx` under SysV never registers as a definition and `setne %cl`'s
  preservation read counts as a parameter. Both together give `[0, 1]`, matching
  DWARF. The naive call-kill was prototyped, measured working, and deliberately
  reverted: it is order-sensitive rather than dataflow-sound.

### what landed

`bsr`/`bsf`, modelled as `(BITS-1) - clz(...)` with the zero case gated on
`src != 0` and the destination's prior value preserved (x86 leaves the
destination unmodified for a zero source — it does not produce 32). i386
**232 -> 233 of 256 (90.6 % -> 91.0 %)**, total behavioural correctness
1036 -> 1037, control lane unchanged at 328/328.

## 20. Preserving a value the architecture refuses to define — 2026-08-04

The `bsr`/`bsf` lowering in §19 was exact and still wrong, in a way that took a
second look to see. Its zero case gated the count on `src != 0` with the
destination's **prior value** as the else arm:

```
ops.push(Op::Ite { dst: dst.clone(), cond: found,
                   t: Value::Reg(index), e: Value::Reg(dst), width });
```

That reads `dst` before defining it. The consequence is not cosmetic. A live-in
physical register sitting in an argument slot is what parameter recovery
promotes to a parameter, so `shift_until_zero` — whose source is

```c
int shift_until_zero(unsigned x) { int n = 0; while (x) { x >>= 1; n++; } return n; }
```

came out as

```c
unsigned int shift_until_zero(int arg0, long arg1, long arg2, unsigned int arg3)
```

with three parameters that do not exist, and `arg3` read in an arm the outer
guard never selects. Before parameter recovery reached it, the same read
surfaced as `long var1;` — declared, never assigned, and read. Two symptoms, one
cause.

The premise was also false. **Intel documents the destination as UNDEFINED when
the source is zero**; only AMD promises it is preserved. So the lowering was
paying three phantom parameters to model a value no correct program can observe
and no architecture guarantees. It now writes the count unconditionally; ZF —
the one flag x86 defines here, and the one callers actually branch on — still
separates the two cases exactly. `shift_until_zero` recovers one parameter.

The test that guarded the old behaviour asserted the else arm *was* the
destination's own prior value. It now asserts the property that actually
matters: **no read of the destination precedes its definition**, checked over
every op in the lowering.

### The general rule, and why it is not in the tree

An arm that is undefined permits any value, so collapsing a select onto its
other arm is a refinement rather than a change. That rule is sound. The oracle I
built for it was not: `copy_prop::count_assignments` was written for parameter
aliases and does not see every form of definition. It missed a frame slot's, and
the pass rewrote the signed divide-by-4 rounding idiom

```c
*(int *)(arg0 + local_c * 4) = (long)((local_8 < 0) ? (local_8 + 3) : local_8) >> 2;
```

into `(local_8 + 3) >> 2`, changing the result for every non-negative value.
Cost: four `arch_roundtrip` regressions including **the control lane**
(`30_finite_difference:{x86_64,aarch64}:O0:heat_step_1d`,
`14_flag_effects:i386:O0:{dec_preserves_carry,sub_then_sign}`).

Reverted. A correct version needs a real reaching-definitions oracle over the
AST covering stack slots and every defining statement — the same machinery task
#56 is blocked on. Filed as #66. The case that motivated it needs nothing: it
was fixed at the lifter.

The lesson generalises past this pass. Both defects in this section are the same
mistake at different levels — modelling a value that is not there. A lowering
that preserves an architecturally-undefined destination manufactures a live-in;
an oracle that counts *some* definitions manufactures an undefined value. Being
exact about the machine is only worth what it costs everything downstream.

## 21. What the ARM32 argument work found — 2026-08-04

Two of the three defects sent to the ARM32 agent came back changed.

**Filed as "adds/subs claim only Z and N".** Already fixed at `b83a066`, an
ancestor of the base. `arm_carry_arithmetic` writes Z/S/C/O/Slt/Sle/Ule with
32-bit width stated at the point of use, and handles the borrow-polarity trap.
What still routes to `flags_for_arith` is `ands`/`orrs`/`eors`/the shifts/`muls`
— where Z and N genuinely are the only flags the result determines. A stale
filing, not a defect.

**Filed as "one undefined local is the argument to ten distinct callees".**
Real, and the cause sat one level below where it was filed. An ARM32 PLT stub is
`add ip,pc,#0,#12 / add ip,ip,#4096 / ldr pc,[ip,#n]!`, and function discovery
does not stop at that indirect branch — so lifting a "callee" at a stub runs
through the seven stubs after it and into misdecoded bytes. Every one of the 16
imported callees of `strip_iconv_arm-v7` was therefore recovered with the same
argument layout, `[r2, r3]`, read out of that garbage. `fold_one_call` trusts a
recovered layout ahead of the call site and returns before the local backward
scan runs, so ten different calls all received the same two undefined live-in
registers, and no call-site value survived for string folding to see.

The fix does not guess at the callee. `layout_matches_abi_allocation_order`
admits a recovered layout only when its argument-slot registers form the
contiguous prefix slot 0, 1, 2, … in order — every convention modelled here
allocates that way, and the separate AAPCS-VFP bank is skipped rather than
judged. `[r2, r3]` cannot be any callee's first two parameters, so the layout is
withdrawn and the call falls back to the evidence the caller actually executed.
Withdrawing unusable outside evidence is safe by construction.

`sub_6fc`: pathological locals 2 → 0, string literals 0 → 2, all ten call sites
carrying real values — `getopt(argc, argv, "f:t:csl")`, `nl_langinfo(CODESET)`,
`iconv` at four arguments instead of two — each checked against the unstripped
disassembly and raw `.rodata`.

The discovery bug itself is still there (#64), as is a third defect the agent
found, implemented, measured as a 202 → 199 loss on armv7, and reverted (#65):
`value_number` reads a call's ABI may-use list as an alias read, and
`return_registers(ArmHardFloat)` overlaps `argument_registers(ArmHardFloat)` at
`s0`, so every pre-call `r0` definition is kept spelled as the function's
live-in. The clean fix is a no-op on SysV/Win64/Cdecl32, whose return and
argument tables are disjoint — but three armv7 consumers depend on the bare
spelling and have to move in the same change.

## 22. Widening one property gate, and the two lifter gaps it found — 2026-08-04

Emission invariant #2 — *a value read is a value assigned* — forbids exactly the
unassigned read that §20's `bsr` defect produced. It did not fire. The reason is
structural rather than subtle: the module compiles **one** fixture, and the
defect was in another. A property gate that runs on a single input is a unit
test wearing a property's name.

Two measurements shaped the fix.

**How much would the property flag corpus-wide?** Scanning every fixture (30
sources × 4 architectures × {O0, O2}, ~264 units) for a declared-but-never-
assigned local reaching an observable use:

```text
40  total
35  i386 CRT/PLT glue (sub_1020/sub_1030/sub_1040)
 5  real, ALL armv7:O2, ZERO on x86_64 / i386 / aarch64
```

The 35 are not defects. A PIC PLT stub legitimately reads the GOT-base register
its *caller* set up; it is live-in by construction. That is precisely the class
`FIXTURE_FUNCTIONS` scoping exists to exclude, and it is why widening the gate
to "every function in the corpus" would have been the wrong move — it would have
bought 35 permanent false positives for 5 true ones.

**So widen the fixture, not the corpus.** Six shapes were added to
`frame_and_arity_shapes.c`, chosen for what the *compiler* emits rather than
what the source says: shift-until-zero and trailing-zero (bit scans, which
define their destination only for a non-zero source), signed division and
remainder by powers of two (the bias-and-shift idiom that §20's bad pass
rewrote), a fused `||`/`&&` guard, and a conditional move. Cost: one extra
translation unit per lane. The existing eight properties apply to them for free.

The arity property was also generalised from a single function to a ceiling over
all of them. The asymmetry is the point: recovering **fewer** parameters can be
legitimate — at `-O2` an argument that is never read leaves no trace — but
recovering **more** cannot be, under any optimisation. That is the phantom-
parameter class exactly.

### What it caught on the first run

Both on **AArch64**, both at `-O0` and `-O2`, both pre-existing:

* **`clz` was not lifted at all.** It emitted `/* asm: clz */`, so its
  destination was never defined and `32 - clz(x)` read a local nothing assigns.
  `lift_arm32` has had this fix for some time, with a comment describing this
  same defect class; AArch64 was simply never given it. A second layer sat
  underneath: the first attempt named the intrinsic `arm64.clz.32`, and
  `wide_integer_intrinsic` strips only `x86.` / `aarch64.` / `arm.` — so it
  lifted correctly and *still* rendered as raw asm. The namespace is part of the
  contract, not decoration.
* **`negs` was not lifted.** `negs Rd, Rn` is `subs Rd, ZR, Rn`: it negates AND
  sets comparison flags against zero. Unmodelled, `signed_remainder` came out as
  `slt_0 ? (v & 15) : -(var3 & 15)` with both names never assigned. The flags are
  a function of the pre-operation operands, so they are emitted before the write.

Measured: aarch64 **274 → 275**, total behavioural correctness **1037 → 1038**,
control lane unchanged at 328/328. `14_flag_effects:aarch64:O2:shift_until_zero`
went fail → pass and the baseline cell was refreshed; a semantic diff of
`arch_baseline.json` against HEAD confirms exactly two changed cells, both
`shift_until_zero` improvements (i386:O2 from §20, aarch64:O2 from here).

### The five armv7 findings, re-diagnosed

The original filing called them "-O2 fused guards read undefined locals". They
are not that. Every one is:

```c
var2 = ((arg2 <= 16) ? ((arg2 <= 16) ? 0 : var1) : 1);
```

a select nested inside its **own true arm on the identical condition**. ARM32
predicated execution (`it ls` / `movls`) preserves its destination when the
condition fails, which — unlike x86 `bsr`, where the architecture leaves it
undefined — is exactly right. Nothing about definedness is wrong here. The inner
alternative is simply *unreachable*: inside the true arm, `C` holds.

So the collapse needs no oracle at all, only structural equality of the
condition — which is why it is sound where §20's attempt was not. That one had
to prove an arm undefined; this one only has to observe that the enclosing arm
already decided the branch. Implemented as
`copy_prop::collapse_dominated_select_arms` with four tests, deliberately
outside `select_fold.rs` / `guard_chain.rs` / `ast.rs` while agents hold those
files; not yet wired, so not yet measured.

`newton_isqrt` shows a second instance the expression-local rule does not reach:

```c
var3 = ((arg0 <= 1) ? arg0 : var0);
if ((arg0 <= 1)) { return var3; }
```

Here the dominating condition is a *statement*, not an enclosing arm. Extending
dominance across the following `if` would cover it and is a strictly larger
change — do the expression-local form first and re-measure.

### A measurement hazard worth writing down

Two gate runs in this session produced numbers that meant nothing:

* A `decbench_matrix --check` against the main worktree while that worktree was
  rebuilt three times underneath it. A gate measures whatever is installed when
  each case runs, not the tree as it stood at launch.
* A worktree agent's `export PATH="$PWD/.venv/bin:$PATH"`. `git worktree add`
  does **not** copy `.venv` — it is untracked — so the export is a no-op and
  `glaurung` resolves to the first one on the inherited PATH, which is the main
  checkout's build. An agent measuring in a worktree must create a venv *in that
  worktree* and confirm `which glaurung` points inside it, or it is measuring
  someone else's tree while believing it measures its own.

## 23. Two agents, three of my filings wrong — 2026-08-04

Both parallel agents came back with a working change AND a correction to the
task that produced it. Recording the corrections first, because they are the
more durable result.

### #44 — the fused guards were never fused

I filed: "at -O2 compilers fuse short-circuit conditions into branchless bitwise
expressions; we emit them literally; every such guard is a permanent GED penalty
because it collapses two source basic blocks into one." Both halves are false.

They are **our own x86 flag model**. `jle` is `ZF | (SF^OF)`, and the lifter
computes `zf` over the UNSIGNED view of the operands while `sf`/`of` use the
SIGNED view:

```text
%t35 = (unsigned long)((unsigned int)(%t10));   %zf = (%t35 == 99)
%t30 = (long)((int)(%t10));                     %sf^%of  ==  (%t30 < 99)
```

`const_fold::merge_equality_and_less` already merges this pair — but only when
the two comparisons are syntactically identical, which the signed/unsigned view
split guarantees they never are. A signedness-tolerant version existed and was
deliberately reverted in `320e960`, because merging that early destroys GCC
switch ladders before `switch_ladder` sees them.

A scan of every function in both corpora: **in all 56 DecBench cells, every `|`
between two comparisons is this flag pair.** The only other `|` uses are genuine
bit rotates and 64-bit merges. Not one compiler-fused short-circuit. The fixture
corpus has exactly one. So the fix I proposed — rewrite to `||` — would have
been actively wrong: it invents a basic block the source never had. The correct
recovery is `<=`.

And the motivation was measurably false: **all 56 `ged` cells are byte-identical
before and after, corpus total 403.17 → 403.17.** Neither spelling adds or
removes a branch, so Joern builds the same CFG either way. The `&&`/`||`
recovery I asked for had also already shipped on 2026-08-03 (§15) and emits 25
short-circuit operators today.

What shipped instead is `bool_guard::recover_inclusive_comparisons`: fold
`(a == b) | (a < b)` → `a <= b` when the equality's operands match under the
same cast-*width* chain and differ only in cast *signedness*. Exact, because
`zext(a)==zext(b) ⟺ trunc(a)==trunc(b) ⟺ sext(a)==sext(b)`; the strict half is
kept verbatim so its signedness — the one that decides the relation — is never
reinterpreted. Sequenced LAST in `prepare_for_decbench`, after every switch
recogniser has seen the un-merged ladder, which honours `320e960`'s reason
rather than overriding it. Fused-guard lines 377 → 237; one `byte_match` cell up.

A more aggressive variant was measured and rejected: merging under an `== 0`
polarity gave `if (arg1 < arg0)` instead of four-comparison soup, GED still
identical, but cost `branches:gcc:O2.byte_match` 1.00 → 0.80. `CmpOp` has no
`>`, so negating `a <= b` swaps operands to `b < a`, and gcc then emits
`cmpl %edi,%esi; jl` where the original had `cmpl %esi,%edi; jg`. Preserving the
source's operand order is fidelity; chasing the extra sites was not.

### #42 — right defect, wrong consequence

The indexed-seeding bug was real and is fixed: `resolved_memory_address` now
resolves the index expression's own definition chain, so an affine
`(reg << k) + C` contributes `C` to the displacement instead of vanishing into
the index. armv7 **202 → 206**, control lane 328/328, all 56 matrix cells
byte-identical. In `graph_bfs` the frame goes `local_80[100] + local_1c[28]` →
`local_80[36] + local_5c[64] + local_1c[28]`, the queue store becomes
`*(int *)(&local_5c[0] + (i * 4))`, and **the out-of-bounds write is gone** —
every `seen[]` access had been `&local_80[0] + 100 + i`, past the end of a
100-byte object.

But I also claimed the five scalars render as `*(int *)(&local_80[0] + N)`
*because of* that bug. They do not, and they still do not recover names after
the fix. Instrumentation found the real cause: `stack_assignment_object_address`'s
contiguous-run join, triggered by a **dead** `Temp(49) = r7#1` left over from
flag-width modelling (`JOIN-RUN disp=-128 size=36`). `graph_dfs` has no such dead
copy. Filed as #68.

Two self-caused regressions are worth remembering because both came from
dropping an assumption the surrounding code already documented:

* A **bare** `rax` with an affine def `rax = rax#5 + 1` textually AFTER the
  store that read it moved `seen[]` one byte up the frame — on the CONTROL lane.
  Fixed by recording facts only when the register and its root carry an SSA
  version, which `collect_stack_address_defs` already required.
* Folding a one-element bias (`k` indexed as `(k-1)+1`) re-rooted the subscript
  on an earlier value. Fixed by refusing when `|bias| <= scale` — the same rule
  the partitioner immediately below already used.

### The pattern

Three filings wrong in one session: #44 (wrong mechanism *and* wrong
motivation), #53 (already fixed at base), and half of #42 (wrong consequence).
Each was written by reasoning from a symptom to the nearest plausible mechanism.
Each was corrected by someone instrumenting the actual pass — a `GLAURUNG_DUMP_PASSES`
dump, a `JOIN-RUN` trace, a corpus-wide scan of what `|` operands actually are.

The cost is not just wasted work: a confidently-worded filing sends an agent
toward a fix that would have been wrong, and #44's would have shipped invented
basic blocks. Instrument before filing, and state the evidence in the task so
the next reader can check it rather than inherit the guess.

### Gates, fully merged

```text
cargo test --lib          1765 pass / 0 fail
fixture_harness            656 pass / 0 fail
arch_roundtrip --check    1042 pass  ·  x86_64 328/328 (CONTROL)
                          i386 233 · aarch64 275 · armv7 206 (80.5%)
```

Six `arch_baseline.json` cells refreshed, all `fail -> pass`, verified by a
semantic diff against HEAD rather than by reading the textual one:
`14_flag_effects:{aarch64,i386}:O2:shift_until_zero`,
`16_red_black_tree:armv7:O0:rb_validate`, `20_graph_bfs:armv7:O0:graph_bfs`,
`21_graph_dfs:armv7:O0:graph_dfs`, `25_kmp_search:armv7:O2:kmp_search`.
