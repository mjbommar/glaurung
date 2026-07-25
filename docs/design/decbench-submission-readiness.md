# DecBench submission readiness

What has to be true before we open a PR against `Noelo-Lab/decbench`, what is
true today, and what we would be asking a reviewer to accept. Written by working
backwards from the submission rather than forwards from the code.

**Nothing here is public.** The fork branch exists locally and has never been
pushed; no PR, no issue, no reply upstream.

Last updated: 2026-07-25.

## 1. The artifact we would be submitting

Two decompiler backends on the fork branch `glaurung-decompiler`
(`decbench/decompilers/raw/`):

| file | what it is |
|------|------------|
| `glaurung_raw.py` | the native decompiler — deterministic, no network |
| `glaurung_agentic.py` | the LLM-refined tier on top of it |
| `docs/GLAURUNG.md` | integration notes, config, scope and limitations |
| `tests/test_glaurung_decompilers.py` | 5 tests, plugin registration + output shape |

The branch is rebased onto current upstream `main` (as of e7c10a0, 17 commits
past where the work started, including changes to `decompilers/raw/common.py`
and `models/decompilation.py`). The 5 tests pass before and after that rebase.

## 2. Status against the submission bar

| # | requirement | state |
|---|-------------|-------|
| A | output is clean C, no diagnostic noise | **done** — verifier comments are behind `GLAURUNG_VERIFY_DEFS` |
| B | harness works against *current* upstream, on a branch | **done** — rebased, 5/5 green |
| C | metrics measured, not remembered | **done** — gcc+clang × O0+O2, 56 evaluations each, angr control through the identical path |
| D | no panics / parseable output corpus-wide | **done** — re-run after the ET_REL fix: 1646 functions, 99.7 % gcc-parse, 0 panics |
| E | claims in the docs match what the code does | **done** — `docs/GLAURUNG.md` no longer advertises a blanket `long` signature |

## 3. What the numbers actually say

### Head-to-head, per lane (56 evaluations each, same harness, same corpus)

Bold is the better number. angr is run through the identical path, so harness or
metric drift would move both columns.

| lane | GED us | GED angr | type us | type angr | byte us | byte angr |
|------|--------|----------|---------|-----------|---------|-----------|
| gcc/O0 | **5.99** | 7.59 | **0.873** | 0.819 | 0.323 | **0.586** |
| clang/O0 | 9.79 | **3.19** | 0.760 | **0.848** | 0.158 | **0.184** |
| gcc/O2 | **17.29** | 17.51 | 0.404 | **0.543** | 0.216 | **0.291** |
| clang/O2 | 11.56 | **11.40** | **0.652** | 0.534 | 0.036 | 0.036 |
| **overall** | 11.16 | **9.93** | 0.678 | **0.694** | 0.183 | **0.274** |

By optimisation level: O0 7.89 / 0.816 / 0.240, O2 14.42 / 0.523 / 0.126.

Three binaries have no `type_match` on **either** side — `recursion` at gcc/O2 and
clang/O2, `matrix` at clang/O2. DecBench reports "No DWARF ground truth types"
despite `-g` and present `DW_TAG_subprogram` entries. Identical on both sides is
what makes it a ground-truth gap rather than a decompiler one; every other metric
is 56 of 56 for both.

**What this says, without spin.** angr wins the overall on all three metrics,
narrowly on GED (11.16 vs 9.93) and type (0.678 vs 0.694), clearly on byte (0.183
vs 0.274). We win **gcc/O0 on GED and type** — the single lane every change this
session was tuned against — and **clang/O2 on type** (0.652 vs 0.534). The two O2
GED lanes are ties. Our worst relative result by far is **clang/O0: GED 9.79
against angr's 3.19**, which is now the largest single opportunity on the board.

So the honest summary is: **competitive at gcc -O0, roughly level at O2, and well
behind on clang -O0 and on recompiled-byte similarity everywhere.**

## 4. What a reviewer would find if they looked hard

Stated here so it is not discovered instead.

* **clang -O0 is our worst lane and we do not know why.** GED 9.79 against
  angr's 3.19 — a bigger gap than anything at O2, on the *unoptimised* build where
  we should be strongest. Every structuring change this session was validated
  against gcc. Largest single opportunity on the board, and unexplained.
* **O2 costs type recovery.** 0.816 at O0 against 0.523 at O2; gcc/O2 type is
  0.404 against angr's 0.543. The width work lifted O2 type_match from the 0.413
  measured on 2026-07-24 but nowhere near the O0 figure: no spill slots to type
  from, and no O2 story in type recovery.
* **Aggregates are not recovered.** `structs` scores type 0.25 and `linkedlist`
  0.5 because struct and array types are not reconstructed; an aggregate
  parameter appears as a pointer to its element type.
* **Calls do not define their return register.** The new `11_call_shapes`
  fixture measures exactly this: all four callees pass, and every *caller* fails
  at -O0. Several pass at clang -O2 only because the callee is inlined and there
  is no call left. 32 of 48 executable lanes fail. This is recorded in the
  committed baseline, not hidden.
* **The fixture gate carries 246 known failures** against 215 passes. It is a
  ratchet, not a claim of correctness: it fails on NEW regressions while keeping
  known bugs visible per function per lane. It is green — the matrix and
  structural lanes both pass, meaning nothing in this series regressed anything
  the gate had already measured — but "green" here means "no new breakage", not
  "the decompiler is correct".
* **Relocatable objects are only partly handled.** Code addresses now resolve
  through executable sections, but under `-ffunction-sections` every `.text.*`
  still shares address 0 and the first one wins.

## 5. Corpus sweep (392 relocatable objects, 4 architectures)

Re-run after code addresses started resolving through executable sections. The
corpus is `.o` files, so it is exactly the population that fix affects.

| arch/compiler | objs | fns | empty | unk fns | gcc parse |
|---|---|---|---|---|---|
| aarch64/clang | 56 | 386 | 0 | 247 | 385/386 (99.7 %) |
| aarch64/gcc | 56 | 392 | 0 | 101 | 388/392 (99.0 %) |
| arm32/clang | 56 | 120 | 0 | 7 | 120/120 (100 %) |
| arm32/gcc | 56 | 120 | 0 | 14 | 120/120 (100 %) |
| cortexm/gcc | 56 | 120 | 0 | 12 | 120/120 (100 %) |
| x86-64/clang | 56 | 128 | 0 | 19 | 128/128 (100 %) |
| x86-64/gcc | 56 | 380 | 0 | 70 | 380/380 (100 %) |
| **total** | **392** | **1646** | **0** | **470** | **1641/1646 (99.7 %)**, 0 panics |

The previous run found **1368** functions at 99.6 %. The difference is not noise:
`aarch64/clang` went from 133 functions to 386 and `x86-64/clang` from 103 to
128, because those are the toolchains that list `.strtab` before `.text`. The
clearest evidence is in the unknown-mnemonic tail — `insb` (31) and `insd` (13)
were in the old top-15 and are simply gone. Those are what x86 decoding of ASCII
looks like. The remaining unknowns are real instructions we do not model yet
(`subs`, `sdiv`, `pshufd`, `umull`, NEON), and the rise in `unk fns` tracks
decoding three times as many genuine AArch64 functions.

## 6. Blocking work before a PR

1. ~~Finish the angr control across the full breadth.~~ **Done** — 56 evaluations
   each, per lane, both directions. It is what corrected the O2 GED figure and
   caught the `fib_localalias` naming bug. No blocking items remain; what is left
   is quality work, not honesty work.
2. ~~Decide on the GED regression.~~ **Done** — `ir::switch_ladder` landed:
   10.63 -> 5.99, ahead of angr and of our own previous 7.16, with zero changes
   against the fixture baseline.

## 7. Non-blocking, but worth doing first

* Call-result modelling (roadmap #11/#12) — the largest single block of known
  failures, now measurable per lane.
* `test_cli_explain`'s four failures: pre-existing, unrelated to decompilation,
  but they make "the suite is green" untrue as a sentence.
