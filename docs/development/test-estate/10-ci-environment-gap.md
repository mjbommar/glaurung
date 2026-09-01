# Phase 10 — The gap between "passes here" and "passes anywhere"

Opened 2026-09-01 by the first Python CI run in this repository's history that
ran to completion. It is not in the original plan because nothing could see it
before: with no workflow running the suite, "the tests pass" had only ever
meant "they pass on a developer's machine."

## The measurement

| | local | CI (`ubuntu-latest`) |
|---|---:|---:|
| passed | 3,606 | 3,438 |
| **failed** | **0** | **25** |
| skipped | 40 | 216 |
| xfailed | 39 | 34 |

Same commit (`cdbfd764`), same suite. **176 more skips and 25 failures**, none
of which is a product defect.

## What the 25 are

| n | cause | file(s) |
|---:|---|---|
| 5 | `No suspicious imports found` for riscv64/armhf/arm64 cross binaries | `test_suspicious_symbols.py` |
| 4 | `SystemExit: 2` from a CLI invocation | `test_frame_cli.py` |
| 3 | `FileNotFoundError: 'arm-linux-gnueabihf-gcc'` and relatives | `test_decompiler_arch_roundtrip.py`, `test_decompiler_ilp32_wide_return.py`, `test_decompile_vas_sources.py` |
| 3 | build-configuration invariants (`lto no longer emits a decidable guard`) | `test_build_configuration_invariants.py` |
| 2 | fixture-matrix comparisons | `test_decompiler_fixture_matrix.py` |
| 8 | assorted single assertions on recovered output | various |

## Progress, same day

Rather than wait 45 minutes per CI round trip, a PATH that mimics
`ubuntu-latest` -- gcc and clang present, every cross compiler absent --
reproduces two of the classes locally in seconds. `$TMPDIR/ci_path` with the
cross compilers omitted; run the failing files against it.

| n | what | status |
|---:|---|---|
| 3 | `FileNotFoundError` on a cross compiler | **FIXED** (`f0c1009c`) — `native_runner` used `check=False`, which covers a probe that FAILS and not one that cannot RUN; catching `OSError` fixed a second test by cascade |
| 5 | `No suspicious imports` on cross binaries | **FIXED** (`f0c1009c`) — the sample selection used `rglob` (filesystem order) over a pool containing `suspicious_win` builds cross-compiled for LINUX, which cannot import a Windows API. Now sorted and filtered |
| 4 | `SystemExit: 2` from the frame CLI | **FIXED** (`9bbfd50c`) — a real product bug: negative HEX offsets do not parse on Python 3.12/3.13, only on 3.14. `requires-python` is ">=3.12" |
| 11 | assertions on recovered output | **open**, and see the CORRECTION below |

### Correction: the remaining eleven are not about the fixture directory

The first version of this table said the remainder "need the gitignored
fixture build directory, which the runner does not have." **That was wrong**,
and it was wrong in the way this document exists to prevent -- a diagnosis
written from a plausible story rather than a measurement.

Tested by hiding `tests/decompiler_fixtures/build/` and running those files:
**zero failures.** They skip correctly without it.

The real cause is the one `CLAUDE.md` names for baselines and that this
session already met once: **these tests compile a fixture with the HOST
compiler and assert on the recovered output.**

    test_decompiler_control_flow_semantics.py   16 host-compiler refs, 0 pinned
    test_decompiler_curriculum_corpus.py         4 host-compiler refs, 0 pinned
    test_decompiler_lazy_call_select.py          2 host-compiler refs, 0 pinned
    test_decompiler_stripped_lane.py             1 host-compiler ref,  0 pinned

The compilers are not the same on the two machines:

| | this box | runner |
|---|---|---|
| gcc | 15.2.0 | 11.4.0 (in the pinned image) / 13.x on the host |
| clang | 21.1.8 | 18.x |

Different codegen, different recovered C, different assertion outcome. The
three `[lto]` cases are the same thing inverted: they are `xfail` for a known
`-flto` defect that does NOT reproduce on the runner's compiler, so the strict
xfail failed by PASSING.

`cfg.rs::clang_o2_statemachine_retains_cross_block_dispatch_edges` was this
exact defect and was fixed in `09f4d511` by splitting the claim: the
version-independent half stays asserted, the codegen-dependent half is scoped
to validated compiler majors and reports what it saw. That is the pattern the
remaining eight want, one at a time, each needing someone who knows which half
of its assertion is version-independent.

The alternative -- compiling them through the pinned toolchain image the way
the fixture matrix does -- is the more thorough fix and a much larger one.

Twelve of twenty-five fixed, each with a root cause rather than a suppression. The
`suspicious_symbols` and `frame` ones were real defects that a single machine
could not expose: one a test whose SUBJECT depended on directory iteration
order, the other a command broken across most of its supported interpreter
range.

## The shape of it

Most of these are one defect wearing several hats: **a test assumes a
toolchain exists and CRASHES instead of skipping when it does not.** The
runner has no `arm-linux-gnueabihf-gcc`, no `aarch64-linux-gnu-gcc`, and no
built `tests/decompiler_fixtures/build/`.

`test_decompiler_emission_invariants.py` had exactly this and was fixed in
`c5f7df15`: `shutil.which("gcc")` succeeded, so the i386 lane looked
available, and then `gcc -m32` failed at LINK time because multilib was
absent. Availability there is now decided by *compiling a two-line program
with the lane's real flags*, which is the only check that answers the
question being asked.

`test_decompiler_arch_roundtrip.py` carries 29 `shutil.which` guards and still
fails three tests, so the remaining paths are the ones the guards do not
cover — which is what makes a `which`-based guard fragile: it has to be
remembered at every call site, and the failure of forgetting is a crash rather
than a skip.

## What to do, in order

1. **Lift the compile-probe helper into something shared.** One
   `toolchain_available(target)` that attempts a real compile, cached, used by
   every file that shells out to a compiler. This is the fix that generalises;
   the rest is applying it.
2. **Triage the four `SystemExit: 2` in `test_frame_cli.py` separately.** A CLI
   exiting 2 is an argument error, not a missing toolchain, and it may be a
   real defect that only a clean environment exposes.
3. **Decide what CI should install versus skip.** 32-bit multilib installs
   cleanly and is already in the workflow. The aarch64/armv7 metapackages do
   NOT install on `ubuntu-latest` -- they depend on `gcc-13-*` builds that are
   not available, and an earlier attempt to install them exited 100 and took
   the whole job down before pytest ran. Either pin a runner image that carries
   them, or accept those lanes as visibly skipped.
4. **Investigate the five `suspicious_symbols` failures on their own.** They
   read committed sample binaries and assert an analysis result; a cross
   binary that yields no suspicious imports on a clean checkout is either an
   LFS fetch gap or a real analysis difference, and the two need telling
   apart.

## Why this is worth a phase rather than a patch

Every one of these tests was green on the machine that wrote it, for as long
as it has existed. The reason to run the suite somewhere else is not to find
product bugs -- `cargo test` found none, 2,944 green in CI and locally -- but
to find the assumptions that a single machine cannot see. Fixing them
individually and hastily would reproduce the thing this whole estate plan
exists to stop: tests that report a state nobody has checked.

## Appendix — the `Unstructured` dispatch loop, located and measured

The clang-14 `fsm` failure was traced to a single guard, and a candidate fix
was tried and **deliberately not landed**. Recording both, because the
measurement is the useful part.

### Where it is

`analyze_functions_path_with_stats` reports
`resolved_dispatches: [{va: 0x1166, arms: 4}]`, so jump-table recognition is
**not** the problem: the base (`lea 0xede(%rip),%r9`, materialised in the loop
preheader) is followed into `movslq (%r9,%rbx,4)` / `add %r9,%rbx` /
`jmp *%rbx`, and every arm becomes a CFG edge.

The recovered CFG:

```
[0] 0x1100 -> 8,1     [5] 0x1158 -> 6,7,2,9   <- 4-way dispatch, one arm exits
[1] 0x1109 -> 4       [6] 0x1168 -> 3
[2] 0x1130 -> 3       [7] 0x1180 -> 3
[3] 0x113b -> 9,4     [8] 0x1192 -> 9
[4] 0x1153 -> 3,5     [9] 0x1196 -> (exit)
```

Loop body `{2,3,4,5,6,7}`, header 4, back edge 3->4, `exits = {9}`.

`loop_shape::detect_raw_dispatch_loop` declines on `exits.len() < 3`. Its
comment justifies that: a lower count is "representable by the ordinary
structured loop/switch builder". **For this shape it is not** -- no structured
builder takes it, the back edge is owned by nothing,
`structure_accounting` reports `BackEdgeUnowned{from:3,to:4}`, and
`recover_verified` falls back to `Unstructured` for the whole function.
`GLAURUNG_ACCOUNT_STRUCTURE=1` prints that finding.

### The candidate fix, and why it is not landed

Relaxing the guard to `exits.is_empty()` works, and the fixture gate liked it:

    IMPROVEMENTS (4), no regressions
      145_control_flow_flattening:clang:O0:flattened_accumulate  fail -> pass
      145_control_flow_flattening:clang:O0:flattened_classify    fail -> pass
      150_obfuscation_composite:clang:O0:obfuscated_transform    fail -> pass
      206_aarch64_wide_dispatch:clang:O2:dispatch_in_loop        fail -> pass

Control-flow flattening is a dispatch-in-loop obfuscation, so those are
exactly the malware-relevant shapes.

**But it also degrades output the execution differential cannot see.** On the
same source built with clang 21, measured directly:

| | `switch` | `case` | `break;` | `goto` |
|---|---:|---:|---:|---:|
| baseline | 1 | 4 | **3** | 0 |
| with the relaxation | 1 | 4 | **0** | 8 |

Identical semantics -- so the differential reports no regression -- and
materially worse reading: arms become `goto` into labels after the loop
instead of inlined cases with `break;`.

Two attempts to keep both (declining when a better builder can take the shape,
probing `detect_natural_loop`, then all three structured builders on cloned
`visited` sets) did not work; the three-way probe broke BOTH compilers, which
means those detectors are not side-effect-free in the way that approach
assumed. Everything is reverted; the baseline is confirmed byte-restored.

### What landing it needs

The structural baseline at **-O2** (phase 7.5). This is precisely the change
that gate exists to judge: a real improvement on shapes nothing else recovers,
paid for in readability on shapes that already worked, and the only thing that
can weigh the two is a ratchet that measures `switch`/`goto`/`break` rather
than semantics. Landing it before that gate exists would trade a visible win
for an invisible loss.

### The verdict, once that gate existed — 2026-09-01

The census now spans **3,580 functions** (both corpora, `{gcc,clang}` x
`{O0,O2}`), and it answers the question the section above deferred. **Do not
land the relaxation as written.**

| lane | `switch` | `goto` | `break` |
|---|---|---|---|
| O0 | 61 -> 65 (+4) | 2300 -> 2462 (**+162**) | 155 -> 118 (**-37**) |
| O2 | 24 -> 27 (+3) | 2304 -> 2328 (+24) | 390 -> 390 (0) |

Seven functions gain a `switch`; seven **lose every `break` arm they had**:

    145_control_flow_flattening:flattened_accumulate:gcc:O0  break 8 -> 0, goto 0 -> 18
    145_control_flow_flattening:flattened_classify:gcc:O0    break 7 -> 0, goto 0 -> 19
    145_control_flow_flattening:flattened_search:gcc:O0      break 7 -> 0, goto 0 -> 17
    150_obfuscation_composite:obfuscated_transform:gcc:O0    break 8 -> 0, goto 0 -> 20
    206_aarch64_wide_dispatch:dispatch_in_loop:gcc:O0        break 1 -> 0, goto 6 -> 13
    212_loop_with_returning_arm:fsm_returns_from_arm:clang:O0 break 3 -> 0, goto 0 -> 12
    decbench/statemachine:fsm:clang:O0                       break 3 -> 0, goto 0 -> 12

Note the *same fixtures* appear on both sides of the trade: `145` and `150`
gain a switch on clang and lose all their breaks on gcc. The relaxation does
not convert unrecoverable shapes into good ones -- it converts *both* into
goto-dispatch, which is an improvement only where the alternative was nothing.
That is a net loss at the corpus scale, and the O0 `break` column is where it
shows.

A version worth landing must decline whenever a structured builder can take
the shape. The two attempts recorded above failed because the builders are not
side-effect-free; the ordering problem is real and unsolved, and this is the
open work, not the guard constant.

### How many wrong answers this took

Three, and the first two were the same shape of mistake:

1. Census over `tests/decompiler_fixtures/` only -> **"free."** Wrong: the
   regressing `statemachine.c` lives in `tests/decbench_corpus/`.
2. Both corpora, but `-O2` only -> **"free."** Wrong: every one of the seven
   regressions is at **-O0**, because O0 is where structured recovery already
   succeeds and therefore where there is something to lose.
3. Both corpora, both levels -> the table above.

The generalisation is in `structural.py` beside the constants: a readability
census answers only for the population it covers, and "no regressions" from a
partial population is indistinguishable from "no regressions". The execution
differential was green at every step of this -- all three times.
