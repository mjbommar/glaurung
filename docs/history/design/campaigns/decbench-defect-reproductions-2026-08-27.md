# Three named defects, reproduced from source — and a plan that is not a patch

> **Kind:** record · **Date:** 2026-08-27

**Date:** 2026-08-27
**Glaurung:** `5e16879802d4f1594bf9e8c8286ae420cf3ae869`
**Toolchains:** gcc 15.2.0, clang 21.1.8, arm-none-eabi-gcc 14.2.1,
arm-linux-gnueabihf-gcc 15.2.0, aarch64-linux-gnu-gcc 15.2.0, binutils 2.46
**Companion:** [`decbench-native-provenance-2026-08-27.md`](decbench-native-provenance-2026-08-27.md) §10c
named these three as the roadmap's calibration targets. This document is the
evidence.

**Status:** evidence, design, and the work that followed. §§0–9 are the
investigation; §10 is what was measured, built, and reverted. If the remaining
plan in §7 is adopted, it belongs in
[`decompiler-roadmap.md`](../../../design/decompiler-roadmap.md).

**Delivered** (all gates green, all four baselines refreshed under the pinned
toolchain and purely additive):

* ARM/AArch64 scaled-index operands lost their `lsl #n` shift — every effective
  address in the analysis layer was off by the scale factor (§10b.1).
* ARM `ldr pc, [rBase, rIdx, lsl #2]` jump tables now resolve, end to end on real
  corpus firmware (§10b, §10g). Measured **on the complete corpus, not the
  sample** — 32,441 function instances across the six ARM firmware projects at
  O0/O2/O2-noinline, A/B under an identical build: **+2,085 basic blocks and
  +4,610 CFG edges of real program recovered that were previously absent from
  the graph entirely** (§10h). GED is an edit distance against the source CFG and
  is where 69 of our 82 published Union points come from, so this is a direct
  improvement to the complete board's dominant metric.
* A new fixture, `205_x87_long_double.c`, covering the form that is **99.997% of
  the measured unmodelled-instruction exposure** and had no coverage whatsoever
  (§10e).
* A structurer gap isolated to one line, fixed, measured — and **reverted**,
  because it bought nothing on the corpus and cost 26 wrong-code undefined reads
  (§10f). That is the third local fix to `detect_if_shape` reverted on
  measurement, and the evidence for doing §7 P3 properly instead.
* Two corrected priorities and six corrected claims in our own docs (§5, §10a).

---

## 0. Executive summary

Every defect was reproduced by writing source, compiling it with a real
toolchain, and decompiling the stripped result. All three are real. **Two of the
three are described incorrectly in our own docs**, and in both cases the
description points at code that now works while the actual hole is somewhere
else.

| # | defect | doc claim | measured reality |
|---|---|---|---|
| D1 | jump-table discovery | "clang's 4-byte **relative** table is unrecognised" | That form **works**. The unrecovered forms are x86 **memory-operand** dispatch and — the one that matters — **ARM A32 `ldr pc, [base, idx, lsl #2]`, 321 occurrences in 34 of 58 ARM binaries** |
| D2 | `detect_if_shape` strands a loop body | "gcc -O0 `statemachine`: loop body ends at the first case" | gcc -O0 now recovers a **complete, correct switch**. The LLIR defect is still real but is **masked by a second structuring layer on the AST**. gcc -O2 is the live weakness (goto soup, 11 gotos / 18 labels) |
| D3 | unmodelled instructions declare no register write | "28 mnemonics / 1,130 occurrences" | **24 mnemonics.** Confirmed and **worse than described**: the stale value not only propagates, it **manufactures phantom function parameters**, changing recovered arity. 12 of 158 scored x86 functions (7.6%) are exposed, essentially all via x87 |

The through-line: **we are measuring the wrong things, so our defect
descriptions rot silently.** Each of these was written from a real
investigation, was true when written, and is now misleading. §7.4 proposes the
gates that would have caught all three.

---

## 1. Method, and how to re-run this

Workspace used: `.scratch/decbench-defects/` (disposable — every source is
reproduced below, so this document is self-contained).

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"   # never /tmp
tools/build_guard.py                                            # must print "fresh"
# then, per case:
uv run glaurung decompile <stripped-binary> --vas <entry> \
    --style decbench --format json --timeout-ms 20000
```

Every binary below was **stripped** before decompiling, and entry addresses were
taken from an unstripped twin — the same discipline DecBench uses. Corpus
measurements are over the frozen sample-set eval kit
(`~/projects/personal/decbench-evalkit-sample-set`, 224 binaries / 250
functions). **The binaries were never executed** — they include compiled-from-
source malware; all analysis is static.

### A measurement trap hit twice in one session

The corpus census first reported **20,317** memory-operand indirect jumps. All
but 59 were **PLT stubs** (`jmp *0x…(%rip)`). A second census reported **1,804**
declared locals; the regex was matching `goto L_4011a0;` as `<type> <name>;`,
inflating the count by 20%. Both were caught only by looking at the matched
text.

This is the same class as HEAD commit `5e168798` — *"extbench: every `goto` was
counted as a declaration, and 31% of the figure was that."* **Print the matches,
not just the count.** Corrected figures only are used below.

A third trap: the first ARM census returned zero hits for every form, because
host `objdump` silently disassembles nothing for ARM (5 lines of header, exit 0).
`arm-none-eabi-objdump --disassembler-options=force-thumb` was required. **A tool
that produces no output is not evidence of absence.**

---

## 2. D1 — indirect dispatch. The roadmap points at the wrong form.

### 2.1 The reproduction source

```c
/* d1_jumptable.c — dense 8-case switch, forces a table on every target */
long dispatch(int op, long a, long b) {
    switch (op) {
    case 0:  return a + b;      case 1:  return a - b;
    case 2:  return a * b;      case 3:  return a ^ b;
    case 4:  return a | b;      case 5:  return a & b;
    case 6:  return a << (b & 31);
    case 7:  return a >> (b & 31);
    default: return -1;
    }
}
```

### 2.2 The measured matrix

| target | dispatch instruction | table | glaurung | corpus weight |
|---|---|---|---|---|
| x86-64 PIC (gcc **and** clang) | `lea`/`movslq`/`add`/`jmp *%rcx` | 4-byte table-relative | **RECOVERED**, 8 cases | 2,188 reg-indirect in 160 binaries |
| x86-64 non-PIE (gcc **and** clang) | `jmp *0x402008(,%rdi,8)` | 8-byte absolute | **NOT RECOVERED** | 7 in 3 binaries |
| ARM Thumb-2 (gcc **and** clang) | `tbb [pc, r0]` | inline byte offsets | **RECOVERED**, 8 cases + default | 827 in 31 binaries |
| ARM A32 (gcc) | `ldrb r0,[r3,r0]` / `add pc, pc, r0, lsl #2` | byte offsets, computed | **NOT RECOVERED** — empty body | 0 in corpus |
| **ARM A32 (clang)** | **`ldr pc, [r3, r0, lsl #2]`** | absolute words | **NOT RECOVERED** — empty body | **321 in 34 of 58 binaries** |
| AArch64 | compiler chose a compare tree at 8 cases | — | n/a | `DispatchTracker` has **no** `adrp`/`ldrsw`/`br` rules at all |
| PE (any arch) | — | — | `discover_jump_tables` **skipped entirely** (`src/analysis/cfg/seeds.rs:206`, `if !is_pe_image`) | 8 PE binaries |

**The split is PIC-vs-non-PIC and register-vs-memory operand — not gcc-vs-clang,
and not relative-vs-absolute.** `docs/design/decbench-submission-readiness.md:911-918`
attributes the failure to clang's relative form; that paragraph predates
`src/analysis/dispatch.rs` (created 2026-07-28 by `39d1b448`) and was never
revised. The relative form has a dedicated unit test
(`src/analysis/dispatch.rs:1744`) and a real-binary regression test
(`src/analysis/cfg.rs:2775`).

### 2.3 What the output actually looks like

x86-64 non-PIE, the whole switch gone:

```c
long sub_401140(unsigned int arg0) {
    if (((unsigned long)(7) < (unsigned long)(arg0))) { goto L_401020; }
    /* unrecovered indirect jump through *(long *)(((arg0 * 8) + 0x402008)) */
    L_401020: ;
}
```

ARM A32 clang, worse — not even the bounds check survives:

```c
long sub_8000000(int arg0) {
    goto L_80006a6;
    L_80006a6: ;
}
```

For contrast, Thumb-2 `tbb` produces the **best** output of any target we tested,
including a recovered `default:` arm that the x86 PIC lane loses.

### 2.4 Root-cause chain

Five independent gates, each of which alone is sufficient to lose the dispatch:

1. **`memory_operand_va` ignores the index register** —
   `src/analysis/cfg/ctrl_flow.rs:347-359`:
   ```rust
   pub(super) fn memory_operand_va(ins: &Instruction) -> Option<u64> {
       ins.operands.iter().find_map(|op| {
           let disp = op.displacement?;
           if disp < 0 { return None; }
           if op.base.as_deref() == Some("rip") || op.base.is_none() {
               Some(disp as u64)
           } else { None }
       })
   }
   ```
   `op.index` is never consulted. For `jmp *0x402008(,%rax,8)` this returns the
   **table base**, so `src/analysis/cfg.rs:1242-1250` records a
   `CallType::Tail` xref to `table[0]` and never attempts dispatch resolution —
   and the site does not even land in `stats.unresolved_indirect`, so the
   completeness census cannot see it.
2. **`resolve_with` keys on a register operand** — `src/analysis/dispatch.rs:940`
   does `ins.operands.first()?.register.as_deref()?`. A memory operand has no
   `register`, so the memory form can never be answered by this module even
   after fixing (1).
3. **`table_load_on_entry` refuses a nonzero displacement** —
   `src/analysis/dispatch.rs:421`, `if memory.displacement != Some(0) { return None; }`,
   plus a total-scale-exactly-4 rule. Excludes both absolute-displacement table
   reads and every 8-byte-stride table.
4. **`discover_jump_tables` knows exactly one entry encoding** —
   `src/analysis/jump_table.rs:544`, `target = table_va + (i32)entry`. 8-byte
   absolute tables are routed to `src/analysis/vtable.rs:58`, which produces
   **function-entry seeds only, never CFG edges**.
5. **No ARM A32 dispatch rules exist.** `dispatch.rs` handles Thumb `tbb`/`tbh`
   (`:880-914`) and x86; `ldr pc, [base, idx, lsl #2]` and `add pc, pc, idx, lsl #2`
   are modelled nowhere.

### 2.5 The reprioritization

The roadmap's jump-table item aims at x86 clang, which works. Ranked by measured
corpus weight, the real order is:

1. **ARM A32 indexed `ldr pc` / `add pc`** — 321 sites, 34 binaries, **59% of the
   ARM corpus and 15% of the whole sample-set**.
2. **PE table discovery** — currently zero coverage, 8 binaries.
3. **AArch64 `adrp`/`ldrsw`/`br`** — no rules at all; matters for the Windows-on-ARM
   and modern-Linux directions, not for this corpus.
4. **x86 memory-operand dispatch** — 7 sites, 3 binaries. Real, cheap, low value.

---

## 3. D2 — structuring. The named symptom is gone; the cause is not.

### 3.1 The reproduction source

Verbatim the DecBench corpus program (`tests/decbench_corpus/src/statemachine.c`):
a `for` loop containing a switch, **one arm of which returns** — which is what
makes the shared function epilogue the immediate post-dominator of every
conditional inside the loop.

```c
int fsm(const char *in, int n) {
    int st = 0;
    for (int i = 0; i < n; i++) {
        char c = in[i];
        switch (st) {
        case 0: st = (c=='a') ? 1 : 0; break;
        case 1: st = (c=='b') ? 2 : (c=='a' ? 1 : 0); break;
        case 2: st = (c=='c') ? 3 : 0; break;
        case 3: return 1;
        }
    }
    return st == 3;
}
```

### 3.2 Measured, four lanes

| lane | result |
|---|---|
| **gcc -O0** | **Recovered correctly.** Full `switch` with all four cases; `case 3: return 1;` intact; the counter increment lexically after the switch and still inside the loop; correct `return st == 3`. 2 gotos, both the loop back-edge. |
| gcc -O2 | Structurally recovered but **rendered as goto soup**: 11 gotos, 18 labels, no `switch`. Semantically plausible, structurally poor. **This is the live weakness.** |
| clang -O0 | Fails — `/* unrecovered indirect jump */`. **D1, not structuring.** |
| clang -O2 | Fails — same. **D1, not structuring.** |

`docs/design/decbench-submission-readiness.md` says of gcc -O0: *"the loop body
ends at the first case and the rest is stranded."* **That is no longer true.**

### 3.3 Why it is fixed, and why that is not reassuring

The LLIR structurer's defect is exactly as documented. `Cfg::ipostdom` is
computed **once per function against the function exit**
(`src/ir/structure.rs:327`, `compute_ipostdom` at `:396-451`) with no
loop-relative notion of a join. The corrective guard at
`src/ir/structure.rs:1613-1621` cannot fire for a gcc -O0 ladder:

- it requires `stop_at.is_some()`, but `build_full` calls
  `build(0, cfg, &mut visited, None)` (`:798`) — at function top level there is
  no boundary;
- it requires `!cfg.dominates(boundary, cond) || contains_multiway_before(...)`.
  Inside a loop the header **does** dominate the body conditional, and a gcc -O0
  comparison ladder has **no** `succs.len() >= 3` block — every rung is a
  2-successor `cmp`/`je`. The disjunction is false, so `distant_join` stays at
  the function epilogue.

What saves the lane is a **second, independent structuring layer on the AST**:
`src/ir/switch_ladder.rs:38 recover_switches` reconstructs the switch from the
comparison ladder after lowering, and runs **twice**
(`src/ir/ast/prepare.rs:186` and `:234`).

So the architecture is: an LLIR region structurer that gets this shape wrong,
and an AST pass that fixes the result afterwards. Neither layer is wrong on its
own terms. But:

- `switch_ladder.rs:20-21` is the only stated rationale for the split (*"there is
  no jump table here to recover… so this works on the structured AST rather than
  the CFG"*), and it justifies **that one pass**, not the layering.
- `docs/design/semantics-preserving-structuring.md:72-89` — the design intent —
  specifies the **opposite**: one total graph-aware structurer with the AST layer
  as pure renderers.
- Eight AST passes now restructure control flow (`loop_form`, `switch_ladder`,
  `guard_chain`, `guarded_switch`, `label_prune`, `select_fold`, `terminal_loop`,
  `latch_predicate`). **No document justifies two structuring layers.** It reads
  as accretion.

The gcc -O2 lane is what the compensation cannot reach: there is no comparison
ladder to re-recognise, so the LLIR structurer's output survives as-is.

### 3.4 Three whole-function bailouts are load-bearing

Because `Region::{While,DoWhile}` carry exactly one `exit` and
`Region::{IfThen,IfThenElse}` exactly one `join`, split ownership is
unrepresentable, and `build_full` refuses to run at all on three graph
silhouettes (`src/ir/structure.rs:775-790`) — dumping the entire function to
`Region::Unstructured`. `has_loop_conditional_with_join_beyond_loop` (`:947-1005`)
is the defect's negative image: it detects the situation with the same
`ipostdom` and gives up. Its own comment says *"`detect_if_shape` cannot encode
the split ownership yet."*

**Any redesign must grow the region algebra first.** Patching the predicate is
what was tried twice and reverted twice.

---

## 4. D3 — unmodelled instructions. Confirmed, and worse than documented.

### 4.1 The reproduction source

```c
/* d3_stale.c — rdtsc writes EDX:EAX. If the lifter declares no output,
 * a reader of RAX afterwards must incorrectly see the earlier multiply. */
static inline uint64_t rdtsc_(void){ uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi)); return ((uint64_t)hi<<32)|lo; }

uint64_t stale_after_rdtsc(uint64_t seed) {
    uint64_t poison = seed * 2654435761ULL;      /* lands in rax */
    __asm__ __volatile__("" :: "a"(poison) : );  /* force poison into rax */
    return rdtsc_();                             /* must be the timestamp */
}
```

Compiled `gcc -O1 -fno-pie`, seven instructions:

```
mov $0x9e3779b1,%eax ; imul %rdi,%rax ; rdtsc ; shl $0x20,%rdx
mov %eax,%eax ; or %rdx,%rax ; ret
```

### 4.2 What we emit

```c
unsigned long sub_401106(long arg0, long arg1, long arg2) {
    /* asm: rdtsc */
    return ((unsigned long)((unsigned int)((0x9e3779b1 * arg0))) | (arg2 << 32));
}
```

Three distinct failures in five lines:

1. **The stale value propagates.** `eax` still holds `seed * 0x9e3779b1`, so the
   multiply result appears as the low half of a timestamp.
2. **A phantom parameter is manufactured.** `rdx` is written by `rdtsc` and by
   nothing else, so prototype recovery concludes it is *incoming* and invents
   `arg2`. **A one-argument function is reported with three parameters.**
3. **It is silently plausible.** Nothing in the C marks the value as unknown; the
   `/* asm: rdtsc */` comment sits beside an expression that reads as real.

`cpuid` behaves identically — two phantom parameters (`arg2`, `arg3`) plus one
undefined local (`var3`).

Point 2 is not in any existing write-up and is the one that touches the
scoreboard: a wrong arity is a wrong prototype, which moves `type_match`
(argument correspondence), `byte_match` (recompiled signature), **and** the
def-use census, all at once.

### 4.3 Root cause

`Op::opaque` (`src/ir/types.rs:768-782`) builds
`Op::Intrinsic { ins: [], outs: [], reads_mem: true, writes_mem: true }`.
Its doc calls this "maximally-conservative". **That is true of memory and false
of registers.** `outs: []` is not an absence of information — it is a positive
claim that no register is written.

The propagation is short and total:

- `use_def::defs_uses` (`src/ir/use_def.rs:241-248`) → `[]` for the intrinsic
  shape, and `def_uses` (`:230`) → `None` for `Op::Unknown`.
- `ssa::write_regs` (`src/ir/ssa.rs:165-172`) is the *only* def source, so
  `def_blocks` (`:386-399`) places **no phi**, and the rename loop (`:511-544`)
  never bumps the version.
- The next reader's `top_version` returns the version pushed by the last
  *modelled* write. Stale value, by construction.

The asymmetry is visible in one file: `src/ir/memory_ssa.rs:548-562` maps the
same op to `unknown_effects(true, true)`, clobbering every mutable region.
**Memory: assume everything. Registers: assume nothing.**

`lower_unknowns` (`src/ir/lift_function.rs:864-875`) rewrites every residual
`Op::Unknown` to `Op::opaque` before the function leaves lifting, so the two
shapes are dataflow-identical and the corpus guard
`no_lifted_instruction_in_the_corpus_declares_no_footprint`
(`src/ir/effect_census_tests.rs:97`) passes while measuring nothing about
registers.

### 4.4 Scale, measured on the real corpus

`SILENT_REGISTER_WRITERS` is **24 mnemonics, not 28**
(`src/ir/lift_x86.rs:7930-7973`); `tzcnt`, `bts`, `popcnt`, `movlhps`, `btr`,
`btc`, `rcr`, `movhlps` have all been lifted since the roadmap text was written.
It is a `const` inside a unit test — not a lint, not a runtime check.

Across the 158 x86-64 sample-set binaries (5,276,905 instructions decoded):

| mnemonic | occurrences | binaries |
|---|---:|---:|
| `fstp` | 89,258 | 25 |
| `fxch` | 63 | 8 |
| `faddp` | 15 | 3 |
| `fmul` | 13 | 7 |
| `fsub` | 11 | 7 |
| `bsr` | 3 | 3 |
| **total** | **89,363** | 28 |

**99.997% is x87.** `syscall`, `cpuid`, `rdtsc`, `vpxor` — the headline entries
in the roadmap's occurrence list — do not appear in this corpus at all; those
counts came from `samples/binaries/platforms/linux/amd64`, a different corpus.

Restricted to the **250 scored functions**: **12 of 158 x86-64 targets (7.6%)
contain a silent-register-writer within 4 KB of entry, all `fstp`.** (The 4 KB
window is a proxy for function extent and is approximate in both directions.)

So the corpus-facing form of D3 is: **fix the x87 stack-depth model and 99.99% of
this defect disappears.** The general fallback still needs fixing, for
correctness and for every corpus that is not this one — but it is not what is
costing us score here.

---

## 5. Corrections owed to existing documents

| document | claim | correction |
|---|---|---|
| `decbench-submission-readiness.md:911-918` | clang's relative jump table is unrecognised; "structuring work cannot fix this lane" | The relative form is recognised (`dispatch.rs:774-853`, tests at `:1744`, `cfg.rs:2775`). The unrecovered forms are memory-operand x86 and ARM A32. |
| `decbench-submission-readiness.md` (statemachine) | gcc -O0 "loop body ends at the first case and the rest is stranded" | gcc -O0 now recovers a complete correct switch. gcc -O2 is the live weakness. |
| `decbench-submission-readiness.md:786-787` | "19 of `13_loop_early_exit`'s 24 cells fail" | All 24 cells pass in `baseline.json`. |
| `decompiler-roadmap.md:2751-2756` | `SILENT_REGISTER_WRITERS` is 28 mnemonics / 1,130 occurrences | 24 mnemonics. The occurrence figure is against a different corpus than DecBench's. |
| `python/glaurung/cli/commands/view.py:89-92` | pseudocode pane "highlights any line whose leading address matches the target" | `:154-155` is `text.splitlines()[:max_lines]`. No address is on any line. Docstring is false. |
| `structure_accounting.rs:41-49` | cites the clang jump table as its worked example of what it cannot see | The example is stale; the *principle* is correct and is why D1 was invisible. Re-point it at ARM A32. |

The `statemachine` `clang:O0` baseline cell — `ged 0.0` in
`tests/decbench_corpus/baseline.json` — is **not a success**. The arms never
enter the CFG, so a tiny surviving region scores perfectly against a graph that
is not the program. Any structuring metric that improves when coverage worsens
is measuring the wrong thing.

---

## 6. What connects all three to the scoreboard

The companion document measured our published profile: **highest perfect-count of
any deterministic decompiler, worst mean edit distance of any real backend**
(normalized GED mean 36.68; byte median 106 against a 49–81 field).

All three defects are **catastrophic-failure generators**, not
small-error generators — which is exactly the shape that produces that profile:

- D1 deletes an entire function body (ARM A32: `goto L_x; L_x: ;`).
- D2's residue is goto soup — semantically defensible, structurally distant.
- D3 changes a function's **arity**, which moves all three metrics at once.

A decompiler that is usually exactly right and occasionally catastrophically
wrong scores well on a perfect-rate leaderboard and serves an analyst badly.
Fixing these three is therefore not leaderboard work; it is the difference
between "best perfect-count" and "trustworthy".

---

## 7. The plan

Four workstreams. Each states the redesign, not a patch, and each names the
measurement that proves it.

### P1 — Dispatch-site-first indirect branch resolution

**The problem is architectural, not a missing pattern.** Today two systems
cooperate badly: a blind whole-binary `.rodata` scan
(`discover_jump_tables`, `src/analysis/jump_table.rs:479`) that has *no end
marker by construction* and takes the longest resolving run, and a per-site
abstract interpreter (`DispatchTracker`) that can only answer register-operand
sites. Everything else — memory operands, 8-byte strides, ARM A32, PE, AArch64 —
falls between them, silently.

`tests/decompiler_fixtures/src/204_adjacent_dispatch_tables.c:1-40` already
records that the compensating trim machinery fires **zero times** over 1,107
corpus binaries. The scan is carrying risk it never pays for.

**Design.** Invert the dependency. Make the *dispatch site* the unit of analysis
and the table scan a seeding hint only.

1. **One `DispatchSite` model**, arch-neutral: `{ site_va, index_expr, bound:
   Option<u64>, table: TableRef, entry: EntryEncoding, stride, base_policy }`.
2. **`EntryEncoding` becomes an enum, not an assumption**:
   `TableRelative(i32)`, `Absolute(u32|u64)`, `FunctionRelative(i32)`,
   `ByteOffsetFromPc { scale }`, `HalfwordOffsetFromPc { scale }`. Today only the
   first exists in `discover_jump_tables` and the docstring claims a second that
   is not implemented (`jump_table.rs:15-16`).
3. **Per-architecture recognizers implement one trait** and are the only
   arch-specific code: x86 (register form, memory form), ARM Thumb (`tbb`/`tbh`),
   **ARM A32 (`ldr pc, [base, idx, lsl #n]`, `add pc, pc, idx, lsl #n`)**,
   AArch64 (`adrp`/`add`/`ldrsw`/`br`). Each returns a `DispatchSite` or a typed
   `TableDecline`.
4. **Bound discovery stays fail-closed and stays shared.** The comment at
   `dispatch.rs:944-957` records that falling back to the scanned run cost
   `GED 10.24 → 12.73` across 56 cells. That rule is correct and must survive the
   redesign verbatim: no guard ⇒ no edges.
5. **Fix the two one-line lies as a precondition**, not as the fix:
   `memory_operand_va` (`ctrl_flow.rs:347-359`) must return `None` when
   `op.index.is_some()`, so an indexed dispatch stops being misfiled as a tail
   call and becomes a *visible* unresolved site. `table_load_on_entry`'s
   `displacement != Some(0)` refusal (`dispatch.rs:421`) must accept an absolute
   displacement as a table base.
6. **Every refusal is counted.** `TableDecline::label()` and
   `Unresolved::label()` already exist (`jump_table.rs:106`, `dispatch.rs:128`).
   Emit a per-binary histogram so "we lost a switch" is a number, not a surprise.

**Order of work, by measured weight:** ARM A32 → PE enablement
(`seeds.rs:206`) → AArch64 → x86 memory form.

**Proof:** a new fixture per encoding (there is currently **no fixture at all**
for the non-PIC absolute form, and none for ARM A32), each with a `manifest.py`
contract driving the exact case constants so a fabricated discriminant diverges
under execution — the discipline `04_switch_shapes.c` already uses. Plus the
refusal histogram going to zero on the forms we claim.

### P2 — An unmodelled instruction must declare its register footprint

**The contract is wrong, not the coverage.** Chasing mnemonics one at a time is
what took the list from 35 to 24; it does not close the hole, because ~242
fallback sites keep re-opening it.

**Design.** Make "I don't know what this computes" expressible without also
saying "and it writes nothing."

1. **The fallback must name the destination.** All ~240 form-refusal sites are
   local `unsupported()` closures *inside otherwise-modelled arms* (e.g.
   `src/ir/lift_x86/bit_ops.rs:124-128`) — they already hold the decoded
   instruction and know the destination register. The two terminal `_ =>` arms
   (`lift_arm64.rs:2004`, `lift_arm32.rs:1830`) can read the writes from the
   decoder's own operand-access info, which is exactly what the census test
   already does via `iced_x86::InstructionInfoFactory`
   (`lift_x86.rs:7772`). **The information is present at every site; it is
   discarded.**
2. **The template already exists and is documented.**
   `declare_xmm_register_effect_ops` (`src/ir/lift_x86/packed_string.rs:884-937`)
   emits one single-output `Op::Intrinsic` per destination lane — *"four
   single-output intrinsics say 'these four lanes are a function of these eight
   lanes' without claiming to know which function, and that is both honest and
   enough to stop the stale-value propagation."* Generalise that into a helper
   every fallback calls.
3. **Where even the inputs are unknown, emit `Op::Undef { dst, reason }`**
   (`src/ir/types.rs:289-299`) — a real SSA definition, already handled by
   `use_def.rs:113` and `def_mut:258`, already reported non-fatally by
   `verify.rs:124`. It is currently emitted **only for flags**
   (`lift_x86/flags.rs:96-98`). This is the primitive; it just has never been
   pointed at a general-purpose register.
4. **Retire `Op::Unknown`.** It is already documented as deprecated
   (`types.rs:496-505`) and already rewritten away by `lower_unknowns`. Delete
   the variant so the compiler enumerates the ~242 sites for us. This is the
   refactor that makes the change complete rather than best-effort.
5. **Constraint to respect:** `value_number.rs:541` retags only
   `Op::Intrinsic` with `outs.len() <= 1`; a multi-output intrinsic is silently
   left untagged. Either emit one intrinsic per output (the `packed_string`
   pattern) or fix the retagger. Do not add multi-output ops without doing one of
   the two.

**Corpus-facing priority:** the x87 stack-depth model
(`src/ir/x87.rs`, reached via `lift_x86.rs:2243-2252`) is **99.997% of this
defect in the DecBench corpus** — 9 of the 24 mnemonics are one problem. Fix the
contract first so the hole cannot reopen, then fix x87 because that is where the
score is.

**Proof:** the reproduction in §4.1 as a fixture — assert that the recovered
prototype of `stale_after_rdtsc` has **one** parameter. That single assertion
catches the stale value, the phantom parameter, and the arity error together.
Today **no test asserts conservative behaviour for an op with empty `outs`**; the
census guard pins the *size* of the hole, never the correctness of anything in
it.

### P3 — Structuring: grow the algebra before touching the predicates

Two local fixes have been tried and reverted. The reason is in the type
definitions: `Region::{While,DoWhile}` carry one `exit`,
`Region::{IfThen,IfThenElse}` carry one `join`. Split ownership — "this arm
leaves the region through X" — **cannot be spelled**. Every predicate patch is
therefore a trade between shapes.

**Design, in dependency order.**

1. **Compute a loop forest once, in `Cfg::from`.** Headers, bodies, nesting,
   exit sets. This deletes five separate all-header rescans
   (`structure.rs:869`, `:908`, `:954`, `:1021`, `path_predicates.rs:57`,
   `switch_shape.rs:379`) and gives `detect_if_shape` the fact it currently
   lacks. `switch_shape.rs` already proves the value of loop-bounded join search
   (`:339-343`); `detect_if_shape` has no equivalent.
2. **Replace `stop_at: Option<usize>` with a region context** — owned block set,
   boundary set, enclosing loop. The current API cannot distinguish "boundary is
   a loop header" from "boundary is a sibling join"; shape #6 has to re-derive it
   from scratch (`structure.rs:1515-1517`).
3. **Make the join oracle loop-relative.** `ipostdom` is read at exactly **two**
   sites — `structure.rs:1604` (the defect) and `:986` (the bailout that mirrors
   it). Replace with "nearest join within the enclosing loop, else the loop
   exit". Also fix two latent hazards in `compute_ipostdom`
   (`structure.rs:396-451`): the iteration cap `guard < n + 4` is a heuristic,
   not a proven fixpoint bound, and `max_by_key(pdom[p].len())` is a proxy for
   post-dom-tree depth that is only valid on a single-exit CFG.
4. **Split `visited`.** It currently conflates *emitted*, *temporarily fenced*,
   *cloned into an arm*, and *available* — which is why there are
   insert-then-remove hacks (`loop_shape.rs:205-209`, `:311-317`) and a
   clone-and-filter (`structure.rs:1635-1647`). Separate ownership from
   traversal state.
5. **Then, and only then, decide the layering question.** Either the LLIR
   structurer becomes total and the eight AST passes become renderers (the stated
   design intent in `semantics-preserving-structuring.md:72-89`), or the split is
   deliberate and gets written down with a rule for what belongs on each side.
   **Today it is neither.** Note that removing `switch_ladder` before P3 lands
   would regress the gcc -O0 lane that currently passes — the compensation is
   load-bearing until the cause is fixed.

**Proof:** gcc -O2 `statemachine` gaining a `switch`; the three `build_full`
bailouts (`structure.rs:775-790`) becoming reachable-but-unused; and the
distance gate below, since this is the workstream whose payoff is *mean* rather
than *perfect-count*.

### P4 — The gates that would have caught all of this

Every defect above was mis-described in our own docs, and every one of our
current gates stayed green. That is the meta-defect.

1. **A distance gate.** The fixture ratchet counts cells `fail → pass`; the
   def-use census counts violations. Both are perfect-count-shaped and neither can
   see "how wrong when wrong" — the axis we are worst on. Add median and mean
   GED/byte distance over a fixed corpus, ratcheted like the rest.
2. **An indirect-dispatch census**, per architecture and per encoding, using the
   `TableDecline`/`Unresolved` labels that already exist. D1 was invisible for a
   month because a misfiled dispatch does not even reach
   `stats.unresolved_indirect`.
3. **An empty-body guard.** A recovered function whose body is `goto L; L: ;`
   is a total loss and should be countable. Both ARM A32 lanes produce exactly
   that, and nothing reports it.
4. **A prototype-stability check.** Assert recovered arity against DWARF on the
   fixture corpus. This is what makes D3's phantom parameters visible, and it is
   cheap — the fixtures are built from source with debug info available.
5. **Re-point `report_effect_census`** (`src/ir/effect_census_tests.rs:247`,
   currently `#[ignore]`) at the DecBench corpus rather than
   `samples/binaries/platforms/linux/amd64`. The roadmap's occurrence figures
   describe a corpus we are not scored on, which is how `syscall`-at-310 came to
   look like a priority when it appears zero times in the sample-set.

---

## 8. Sequencing

| order | work | why first |
|---|---|---|
| 1 | P4.2 dispatch census, P4.3 empty-body guard | Cheap, and they turn D1 from anecdote into a tracked number before any fix moves. |
| 2 | P1 ARM A32 recognizer | Largest measured corpus weight (321 sites / 34 binaries / 59% of the ARM corpus). Self-contained: one recognizer against the existing bound machinery. |
| 3 | P2 fallback contract + `Op::Unknown` retirement | Correctness, not score. Retiring the variant makes the compiler enumerate the ~242 sites, so the fix is provably complete. |
| 4 | P2 x87 depth model | Where 99.997% of the corpus-facing D3 exposure is. |
| 5 | P4.1 distance gate, P4.4 prototype check | Needed *before* P3, because P3's payoff is a mean, and nothing currently measures means. |
| 6 | P3 structuring redesign | Largest and riskiest; two previous attempts were reverted for lack of exactly the measurement P4.1 provides. |
| 7 | P1 PE / AArch64 | Strategic (Windows port, modern Linux), not sample-set-facing. |

**Do not start P3 before P4.1.** That is the specific lesson of the two reverted
patches: without a distance metric, a structuring change that trades one shape
for another looks like noise, and the decision gets made on a perfect-count
delta that cannot see the regression.

---

## 10. What was implemented, and what the measurement changed about the plan

### 10a. The census that overturned §7's ordering

§2.5 ranked ARM jump tables first on **corpus-wide occurrence** — 321 sites in 34
of 58 ARM binaries. That was the wrong denominator, and it is the same error §1
warns about. Measured against the **250 scored functions** instead:

- **Zero** of the 84 scored ARM target functions contain `ldr pc` indexed
  dispatch or `tbb`/`tbh`, even with a generous 8 KB window. The 321 sites are
  all in unscored library/firmware code.
- The sample-set scores ~1.1 functions per binary; the **full corpus** scores
  ~108 per binary (86,671 across 803 groups), so the same sites do land in
  scored functions there. ARM tables are a full-corpus lever, not a sample one.

A failure census over all 250 scored functions (current master, fresh build):

| class | all 250 | x86-64 (158) | ARM32 (84) | PE (8) |
|---|---:|---:|---:|---:|
| structured | 52.4% | **41.1%** | 75.0% | 37.5% |
| **goto soup (≥6 gotos)** | **28.8%** | **40.5%** | 6.0% | 37.5% |
| some gotos (1–5) | 10.4% | 9.5% | 10.7% | 25.0% |
| unrecovered indirect jump | 5.6% | 7.6% | 2.4% | 0 |
| unmodelled instruction | 2.0% | 0 | 6.0% | 0 |
| empty / goto-only body | 0.8% | 1.3% | 0 | 0 |

**Structuring is 5× larger than jump tables and x86-64 is the disaster zone.**
ARM is our *strongest* architecture at 75% structured. This is the direct
explanation of the published "worst mean GED distance of any backend" finding in
[the companion document](decbench-native-provenance-2026-08-27.md) §4b: 28.8%
goto soup is what a bad mean distance looks like.

**P3 (structuring) should be first, not last.** §8's ordering is superseded.

### 10b. Delivered

| # | change | file | evidence |
|---|---|---|---|
| 1 | **ARM/AArch64 scaled-index operands lost their shift.** Capstone carries the shift on the *operand* (`ArmOperand::shift`), not inside `ArmOpMem`, so both ARM arms hardcoded `let scale = None`. Every effective address was `base + index` instead of `base + index * 2^n` — for `lsl #2`, wrong by 4× with no diagnostic. | `src/disasm/capstone.rs` | 2 new unit tests on real encodings (`e7921103`, `e7d21083`) |
| 2 | **ARM `adr` / `add rD, pc, #imm` materialises a table base.** New `ArmPcMode` declares how `pc` reads (A32 `+8`; Thumb `(+4) & !3`) — declared, never inferred, because an A32 reading of a Thumb `adr` names a table 4 bytes off and decodes garbage silently. | `src/analysis/dispatch.rs` | 5 new unit tests |
| 3 | **`ldr pc, [rBase, rIdx, lsl #2]` is now a recognised dispatch**, decoding an absolute word table with the Thumb bit masked. | `dispatch.rs`, `jump_table.rs` (`decode_absolute_word_table`) | end-to-end on real firmware |
| 4 | **`ldr pc` is now classified as an unconditional indirect branch.** `classify_ctrl_flow` sees only a mnemonic, so the sweep was decoding the table it reads as instructions. Narrow by construction: an index register is required, which excludes the `ldr pc, [sp], #4` pop and the `ldr pc, [pc, #imm]` veneer. | `src/analysis/cfg/ctrl_flow.rs` | integration test |
| 5 | **The post-CFG revalidation built a tracker with no ARM `pc` mode**, so it re-reported the dispatch unresolved and **deleted the edges the walker had correctly proved**. The arms were found and then thrown away. | `src/analysis/cfg.rs` (`replay_dispatch_block`) | this was the last of the three blockers |
| 6 | **The ARM lifter emits `Op::IndirectJump` for the table load**, mirroring the `tbb`/`tbh` arm, so the index reaches the structurer. | `src/ir/lift_arm32.rs` | |
| 7 | **New fixture `205_x87_long_double.c`** + manifest entries. | `tests/decompiler_fixtures/` | 20 cells, 16 failing |

**End-to-end proof, on real corpus firmware** (`bin_001.elf`, a Cortex-M image in
the frozen sample-set), at the dispatch this document reverse-engineered by hand
in §1:

```
before:  dispatch block 0x0800d494 -> []
after:   dispatch block 0x0800d494 -> [0x800d4b0, 0x800d500, 0x800d4e2, 0x800d452, 0x800d4f0]
```

All five arms, matching the five table words read from the file by hand.

### 10c. Two test-fidelity failures worth recording

Both of my first two unit tests **passed while the real thing failed**, for the
same reason: they were written from `objdump`'s rendering rather than from what
our decoder actually produces.

1. `dest_reg` requires `Access::Write` on operand 0. Capstone marks **every** ARM
   operand `Read` (the documented reason `kill_register` exists), so `dest_reg`
   returns `None` for every ARM instruction — but my test built operands with
   `Access::ReadWrite` and passed.
2. objdump renders the 16-bit Thumb encoding as `add r3, pc, #4`. **Capstone
   reports `adr r3, #4`** — two operands, `pc` implicit. My rule matched only the
   3-operand spelling, so it recognised a hand-written A32 reproduction and none
   of the real firmware.

The tests now use the real decoder's spelling and `Access::Read`, and the
integration test was verified RED (`got []`) by reverting one line of the fix.

### 10d. Regression evidence, and the environment's limits

Under an **identical toolchain** (the only valid comparison — the pinned Docker
toolchain cannot run on this host, see below):

| gate | result |
|---|---|
| `cargo test --features python-ext` | **2700 passed, 0 failed** |
| `scripts/feature-build-gate.sh` | **passed — all 11 feature configurations type-check** |
| **`tools/dectest.py @o0 @o2` under the PINNED toolchain** | **no regressions in scope**, 2,940 cells judged |
| `test_decompiler_fixture_matrix.py` + `..._structural.py` | **32 passed** |
| `test_decompiler_defuse_census.py -m ""` | **6 passed** |
| host lanes `@o0 @o2` (768) and arch lanes (1148), before-vs-after diff | **0 cells moved** |

All four baselines were refreshed under the pinned toolchain (gcc 11.4 /
clang 14.0), and each was diffed rather than trusted:

| baseline | change | verification |
|---|---|---|
| `baseline.json` | +28 | 0 removals, 0 modifications — all `205_*` |
| `structural_baseline.json` | +45 | all `205_*` |
| `defuse_baseline.json` | +118 | per-lane totals rise by exactly fixture 205's own counts (clang:O0 +14, clang:O2 +4, gcc:O0 +15, gcc:O2 +5); **`rustc:O0` and `rustc:O2` unmoved at 6,279 / 3,707** |
| `arch_baseline.json` | +60 cells | 60 added (all `205_*`), 0 removed, **1 changed** |

The single changed arch cell is
`112_recursion_shapes:armv7_a32:O2:tail_countdown`, `fail -> pass`. It is **not**
attributable to this work: the pre-change build passes it too (checked directly
in the before-run capture), so its baseline entry was stale drift that this
refresh corrects. Recorded here rather than claimed as an improvement.

The gate reports "71 regressions" (host) and "20 regressions" (arch) **against
`baseline.json`**, but the pre-change build reports exactly the same numbers —
they are the host-vs-pinned toolchain difference, which the harness itself warns
about (`qemu-arm … 3.2 here but the baseline recorded … 3.1`).

**On the environment.** The pinned fixture toolchain runs through Docker, and
this host's rootless daemon could not start containers at all — every `docker
run` died with `failed to create TTRPC connection: unsupported protocol: Yunix`,
a one-byte corruption of `unix`. The cause was a daemon left running against
upgraded binaries: `systemctl --user restart docker` took it from 29.6.1 to
29.7.2 and fixed it outright. Worth knowing because the symptom is confusing —
`docker info`, `docker ps` and existing containers all work fine, and only
`docker run` fails.

Before that was found, the gate was run through its documented
`GLAURUNG_FIXTURE_TOOLCHAIN=host` fallback, which regenerated **754 of the 1,548
artifacts** in the gitignored `tests/decompiler_fixtures/build/` with host
gcc 15.2 / clang 21.1.8 instead of the pinned gcc 11.4 / clang 14.0. That is a
mixed-toolchain build directory, and it is invisible to `git status`. Judging a
change against `baseline.json` in that state produces phantom regressions — 71 on
the host lanes, 20 on the arch lanes, all of which reproduce identically on the
**unmodified** tree. The pinned rebuild has since replaced them.

*It also surfaced a real pre-existing fragility, now fixed.*
`collects_pinned_switch_result_table_from_real_elf` pinned **absolute `.rodata`
addresses** in `04_switch_shapes-clang-O2.so`; host Clang lays that section out
one 4-byte slot over (`[0x20ac] = 399`, not `303` — verified by reading the file
directly), so it failed with no defect anywhere. A test that pins a compiler's
data layout from a gitignored, regenerable artifact is testing the compiler. It
is now `collects_readonly_regions_from_a_real_elf`, which asserts what the module
actually promises — every word round-trips to the region's own bytes, and an
address no region holds reads as `None` rather than as zero — against whatever
the artifact happens to contain.

### 10e. What fixture 205 proves

`long double` is the only portable route to x87 from C, and x87 is **99.997%** of
the measured unmodelled-instruction exposure. The corpus had **no `long double`
anywhere** before this file. First run: **16 of 20 cells fail.**

The mechanism is visible in the output — the arithmetic is simply gone:

```c
long sub_401106(int arg0) {          /* source: int64_t x87_accumulate(int32_t) */
    local_24 = arg0;
    /* asm: x87.fldz */
    /* asm: x87.fstp */
    if ((0 <= (long)(local_24))) { ...
        for (local_14 = 0; (local_14 < local_24); local_14++) {
            /* asm: x87.fild */
            /* asm: x87.fld */
```

Control flow is recovered correctly; every floating-point operation is a comment.
The GP-register form of the same defect is worse — §4.2's `rdtsc` case
manufactures two phantom parameters — but this is the form that is actually in
the corpus.

### 10f. The structuring gap, isolated — and a fourth local fix reverted

Following 10a's ordering, the next target was the dominant class. A second census
over the x86-64 goto-soup functions split them by how much of the function was
lost:

| | share |
|---|---:|
| whole-function bailout (labels ≥80% of blocks) | **2.6%** |
| heavy partial (40–80%) | 61.8% |
| light partial (<40%) | 35.5% |

So the three `build_full` bailouts at `structure.rs:775-790` are **not** the
cause. The loss is `detect_if_shape` declining shape by shape and taking the
remainder of the walk with it.

`bin_090.elf sub_7370` is the smallest instance — 15 blocks, 12 labelled. Its CFG
is now transcribed edge-for-edge into a deterministic structurer test
(`out_of_line_guard_handlers_are_still_lost_to_goto`) which reproduces the
collapse exactly: blocks 0–2 structure, then **block 3 fails and nine blocks land
in `Unstructured`**.

**The mechanism is one line.** `shared_return_chain` opens with
`if cfg.preds[entry].len() <= 1 { return None; }`, so a return chain is only
recognised when it is *shared*. That leaves a shape with no owner at all:

- a single terminal block → the early-exit shape (runs first);
- a **shared** multi-block chain to a return → this shape;
- an **exclusively owned** multi-block chain to a return → *nothing*.

A guard whose handler is its own and which exits through one further block falls
through every shape, and everything after it in the walk is lost.

#### The fix, and why it was reverted

Admitting the owned case (as `linear_return_chain`, guarded so the two arms must
genuinely diverge — without that guard it broke three existing shapes) took the
reproduction from **nine unstructured blocks to one** and kept all 91 structure
tests green.

It was reverted anyway, on measurement:

- **It does not move the corpus.** `sub_7370` itself stays at 12 labels, and the
  250-function census is flat on x86-64 (65 structured / 64 goto soup, before and
  after). The LLIR CFG these functions are structured from is not the analysis
  CFG the test transcribes — `lift_function` clips blocks to owned ranges and
  prunes edges — so the synthetic shape is fixed and the real one is not.
- **It costs correctness.** `tools/gen_defuse_baseline.py` refused the
  regeneration: `rustc:O0` +15 and `rustc:O2` +11 undefined reads, in fixture
  lanes that were **already tracked**. Attribution was confirmed by reverting and
  re-running — the counts return to exactly 6,279 and 3,707. Each one is a
  wrong-code bug: the recovered function reads a value the machine never
  produced.

No measured benefit, 26 new wrong-code defects. That is a net negative, so the
change is out and the gap is pinned as a ratchet instead.

**This is the third local fix to `detect_if_shape` reverted after measurement**,
and the third for the same reason the roadmap already gives: widening one
predicate trades one shape for another. The evidence now says plainly that the
answer is the region analysis in §7 P3 — a loop forest computed once, a region
context replacing `stop_at`, a loop-relative join oracle, and `visited` split
into ownership vs traversal — and that no fourth predicate will do.

It also says the next investigative step precisely: **find why the LLIR CFG
differs from the analysis CFG for these functions.** Until that is answered, a
structurer test transcribed from `analyze_functions_*` is testing a graph the
structurer never sees.

### 10g. Measured effect of the ARM dispatch work

Across 8 ARM binaries in the sample-set holding 104 `ldr pc` table dispatch
sites: **20 now resolve (19%), recovering 224 case arms** that previously
produced zero successors. The other 81% decline for reasons the
`TableDecline`/`Unresolved` labels already name — no proven bound, or a base this
rule does not materialise — which is the fail-closed contract working, and the
next place to look for ARM upside.

### 10h. Corpus-scale measurement: what the ARM work is actually worth

The 250-function eval kit is not the complete board, and the earlier claim that a
full-corpus measurement was out of reach was wrong. The **compiled corpus is on
this machine** — `decbench-glaurung-fresh-eval-20260808/results/fresh-source-tree-45b233c`
holds all 40 projects at O0 / O2 / O2-noinline with unstripped DWARF binaries
beside their stripped twins. Six of them are ARM firmware, which is exactly where
this work acts, and they carry **10,357 DWARF functions at O0 alone** against the
sample-set's 84.

Running the decompiler over every DWARF function address in those six projects
takes 75 seconds. A/B under an identical build (`git stash` of exactly the six
changed source files, rebuild, measure, restore, rebuild, measure):

| lane | functions | blocks before | blocks after | Δ | edges before | edges after | Δ |
|---|---:|---:|---:|---:|---:|---:|---:|
| O0 | 10,914 | 85,877 | 86,850 | **+973** | 113,678 | 115,879 | **+2,201** |
| O2 | 9,647 | 77,189 | 77,798 | **+609** | 103,261 | 104,582 | **+1,321** |
| O2-noinline | 11,880 | 72,766 | 73,269 | **+503** | 91,847 | 92,935 | **+1,088** |
| **total** | **32,441** | **235,832** | **237,917** | **+2,085 (+0.88%)** | **308,786** | **313,396** | **+4,610 (+1.49%)** |

**32,441 function instances; +2,085 basic blocks and +4,610 CFG edges of real
program that were previously absent from the graph entirely.** Same binaries,
same function set, same everything but the diff.

This is the class of loss `structure_accounting.rs:35-51` says it cannot see:

> *"A block that never entered the CFG is not 'dropped by the structurer' — it
> does not exist as far as this module is concerned … a clean accounting means
> 'the tree expresses this graph', never 'the graph is the program'."*

Those 2,085 blocks were not in the graph. GED is an edit distance between the
decompiled CFG and the source CFG, so a missing block is unavoidable cost, and
GED is where **69 of our 82 published Union points** come from. This is therefore
a real improvement to the complete board's dominant metric, on roughly an eighth
of its functions.

**What it is not:** a scored GED delta. That needs Joern, which this project does
not run without being asked. Recovering a block lowers a function's edit distance;
whether it lowers it to zero — which is what the leaderboard counts — depends on
the function. The honest claim is that the inputs to the ranking metric improved,
corpus-wide and measurably, not that a rank has flipped.

A secondary effect worth recording: at O0 the function-shape census over the same
10,009 functions moves 23 functions out of `goto soup` and into
`unrecovered indirect jump`. That is not a regression — it is the sweep no longer
walking into a jump table and decoding it as instructions. The function moves from
*silently wrong* to *honestly declined*, which is the fail-closed contract working.

### 10i. Next, in the order the measurement supports

1. **Structuring (P3).** 28.8% of scored functions, 40.5% on x86-64. Requires the
   region-algebra work in §7 P3 — and the distance gate (P4.1) *first*, because
   its payoff is a mean and nothing currently measures means.
2. **x87 register-effect modelling.** Fixture 205 is the ratchet; 16 cells to
   win, and it is 99.997% of the D3 corpus exposure.
3. **Rebuild `tests/decompiler_fixtures/build/` under the pinned toolchain**, then
   baseline fixture 205 and re-run the gate for real.
4. ARM `add pc, pc, rN, lsl #2` (the `armv7_a32` lane's form) — **0 corpus
   occurrences**, so genuinely last despite being the one remaining ARM gap.

---

## Appendix — reproduction commands

```bash
export TMPDIR="$HOME/.cache/glaurung/tmp"; mkdir -p "$TMPDIR"
W=.scratch/decbench-defects; mkdir -p "$W/src" "$W/bin"
# sources: §2.1 -> $W/src/d1_jumptable.c, §3.1 -> d2_fsm.c, §4.1 -> d3_stale.c

# D1 x86: PIC recovers, non-PIE does not
gcc -O2 -fPIC -shared              $W/src/d1_jumptable.c -o $W/bin/pic.so
gcc -O2 -fno-pie -no-pie -fcf-protection=none $W/src/d1_jumptable.c $W/src/d1_main.c -o $W/bin/nopie

# D1 ARM: tbb recovers, A32 does not
arm-none-eabi-gcc -O2 -mcpu=cortex-m4 -mthumb -nostdlib -nostartfiles -ffreestanding \
    -T $W/src/link.ld $W/src/d1_arm.c -o $W/bin/thumb.elf          # tbb  -> RECOVERED
clang --target=arm-none-eabi -mcpu=cortex-a9 -marm -O2 -ffreestanding -c \
    $W/src/d1_arm.c -o $W/bin/a32.o
arm-none-eabi-gcc -marm -mcpu=cortex-a9 -nostdlib -nostartfiles -ffreestanding \
    -T $W/src/link.ld $W/bin/a32.o -o $W/bin/a32.elf               # ldr pc -> NOT RECOVERED

# D3
gcc -O1 -fno-pie -no-pie -fcf-protection=none $W/src/d3_stale.c $W/src/d3_main.c -o $W/bin/d3

# strip, then decompile at the entry taken from the unstripped twin
uv run glaurung decompile <stripped> --vas <entry> --style decbench --format json
```

Linker script for the freestanding ARM builds:

```ld
MEMORY { FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 512K
         RAM   (rwx): ORIGIN = 0x20000000, LENGTH = 128K }
SECTIONS { .text : { *(.text*) *(.rodata*) } > FLASH
           .data : { *(.data*) } > RAM
           .bss  : { *(.bss*)  } > RAM }
```

Corpus censuses used `objdump` for x86-64/PE and
`arm-none-eabi-objdump --disassembler-options=force-thumb` for ARM32 — host
`objdump` disassembles **nothing** for these ARM images and exits 0.
