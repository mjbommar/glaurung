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
| C | metrics measured, not remembered | **done** — gcc+clang × O0+O2, 55 evaluations; angr control running |
| D | no panics / parseable output corpus-wide | **done** — re-run after the ET_REL fix: 1646 functions, 99.7 % gcc-parse, 0 panics |
| E | claims in the docs match what the code does | **done** — `docs/GLAURUNG.md` no longer advertises a blanket `long` signature |

## 3. What the numbers actually say

### Breadth: gcc + clang, O0 + O2 (55 evaluations)

DecBench scores multiple optimisation levels, so a gcc/O0-only number would
flatter us. The honest picture:

| lane | n | GED (lower) | type_match | byte_match |
|------|---|-------------|------------|------------|
| O0 | 28 | 7.89 | 0.816 | 0.240 |
| O2 | 27 | 10.40 | 0.523 | 0.127 |
| **overall** | **55** | **9.12** | **0.678** | **0.184** |

One O2 binary is missing from the GED column (27 of 28), and it is named rather
than averaged away: **`recursion-gcc-O2`**. DecBench reports *"No DWARF ground
truth types … may not have been compiled with -g"* and scores only byte_match for
it — no GED, no type_match. It WAS built with `-g`, and DWARF subprograms for
`fib` and `ackermann` are present; at `-O2` gcc also emits `fib.localalias` and
`ackermann.localalias` at the *same addresses* as the exported symbols, which is a
plausible cause but is not confirmed.

What matters for the submission is that this is a ground-truth-side gap, not a
glaurung failure: any decompiler evaluated on that binary loses the same two
metrics. The angr control across the same 55 evaluations should therefore also
show 27 at O2 — if it shows 28, this diagnosis is wrong and the number is ours.

### The gcc/O0 slice, where the work of this session was done

| metric | glaurung | angr |
|--------|----------|------|
| GED (lower better) | **5.99** | 7.59 |
| type_match | **0.873** | 0.819 |
| byte_match | 0.323 | **0.586** |

The gap between the two tables is the point. On gcc/O0 we win two metrics of
three; across the full breadth every metric is materially worse, because **clang
is harder for us than gcc and O2 is harder than O0** — type_match falls from
0.816 to 0.523 between the levels, and byte_match roughly halves.

So: we would be submitting a decompiler that is competitive at -O0 on gcc, and
degrades on optimised and clang-built code. That is a defensible thing to submit
and an indefensible thing to misrepresent. An angr control across the same 55
evaluations is required before claiming anything comparative at O2 — the only
angr numbers we have at that level are from a gcc-only run and are not
comparable. See `decompiler-refactors.md` for the per-metric diagnosis.

## 4. What a reviewer would find if they looked hard

Stated here so it is not discovered instead.

* **O2 and clang are where we are weak.** type_match 0.816 at O0 against 0.523
  at O2; byte_match 0.240 against 0.127. The width work lifted O2 type_match from
  the 0.413 measured on 2026-07-24, but not to anywhere near the O0 figure. No
  spill slots to type from, heavy optimisation, and no O2 story in type recovery.
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

1. **Finish the angr control across the full breadth.** Our own 55-evaluation
   numbers are measured; the comparative claim at O2 is not, because the only
   angr O2 figure we hold is from a gcc-only run. Running now.
2. ~~Decide on the GED regression.~~ **Done** — `ir::switch_ladder` landed:
   10.63 -> 5.99, ahead of angr and of our own previous 7.16, with zero changes
   against the fixture baseline.

## 7. Non-blocking, but worth doing first

* Call-result modelling (roadmap #11/#12) — the largest single block of known
  failures, now measurable per lane.
* `test_cli_explain`'s four failures: pre-existing, unrelated to decompilation,
  but they make "the suite is green" untrue as a sentence.
