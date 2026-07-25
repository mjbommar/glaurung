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
| C | metrics measured, not remembered | **done for gcc/O0**; O2 and clang breadth outstanding |
| D | no panics / parseable output corpus-wide | **stale** — the 99.6 % figure predates the ET_REL fix |
| E | claims in the docs match what the code does | **done** — `docs/GLAURUNG.md` no longer advertises a blanket `long` signature |

## 3. What the numbers actually say

Local 14-program corpus, gcc -O0, angr run as a control through the identical
path (so harness or metric drift would move both columns):

| metric | glaurung | angr |
|--------|----------|------|
| GED (lower better) | 10.63 | **7.59** |
| type_match | **0.873** | 0.819 |
| byte_match | 0.314 | **0.586** |

We would be submitting a decompiler that **wins on type accuracy and loses on
structural distance and recompiled-byte similarity**. That is a defensible thing
to submit and an indefensible thing to misrepresent. See
`decompiler-refactors.md` for the per-metric diagnosis, including the fact that
GED is a real regression against our own recorded 7.16, concentrated in one
program (`switch_jt`), with an identified cause and a named fix.

## 4. What a reviewer would find if they looked hard

Stated here so it is not discovered instead.

* **O2 and clang are not re-measured.** The only current numbers are gcc -O0.
  The last O2 measurement (2026-07-24) had type_match collapsing to 0.413 — angr
  wins O2 — and that has not been re-run since the width work.
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
  known bugs visible per function per lane.
* **Relocatable objects are only partly handled.** Code addresses now resolve
  through executable sections, but under `-ffunction-sections` every `.text.*`
  still shares address 0 and the first one wins.

## 5. Blocking work before a PR

1. **Re-run the corpus-wide no-panic / parseability sweep.** The 99.6 % figure
   was measured before code addresses resolved through `.text`, so it includes
   function bodies decoded out of string tables. The number is probably better
   now, but it is currently unsupported either way.
2. **Measure O2 and clang.** Submitting O0-only numbers when DecBench scores
   multiple optimisation levels would misrepresent the result.
3. **Decide on the GED regression.** Either land the comparison-ladder-to-switch
   recovery (roadmap #13) or state the 10.63 plainly. Not both, and not neither.

## 6. Non-blocking, but worth doing first

* Call-result modelling (roadmap #11/#12) — the largest single block of known
  failures, now measurable per lane.
* `test_cli_explain`'s four failures: pre-existing, unrelated to decompilation,
  but they make "the suite is green" untrue as a sentence.
