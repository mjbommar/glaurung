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
