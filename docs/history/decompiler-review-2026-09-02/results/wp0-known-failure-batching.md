# WP0 known-failure batching evidence — 2026-09-04

> **Kind:** record · **Date:** 2026-09-04

## Outcome

`tools/gen_known_failures.py` now performs one native `decompile_many` call per
fixture object instead of spawning one CLI process per function and then
decompiling the same function a second time to recover its signature. It can
measure independent binaries with a bounded worker pool while retaining
deterministic, sorted output.

The generator now has real argument parsing and supports `--language`,
repeatable `--fixture` globs, `--jobs`, `--output`, progress control, and an
append-only per-object `--checkpoint`/`--resume` path. Consequently `--help`
prints help and exits instead of silently starting the full corpus run.

The strict-xfail consumer in
`python/tests/test_known_decompiler_failures.py` uses the same per-object batch
cache. It remains keyed by VA rather than function name because Rust closure
names are not unique.

## Timing

All commands used the debug extension already validated for the WP6 increment
and `TMPDIR=$HOME/.cache/glaurung/tmp`.

The legacy two-decompile loop was measured with the same
`diff_decompile.signatures()` and `diff_decompile.decompiled_c()` functions:

```text
02_integer_widths-gcc-O2.so, all 28 functions:
3.921 s (7.141 functions/s)

166_rust_generics-rustc-O0.so, first 20 functions only:
159.927 s (0.125 functions/s)
```

The batched implementation measured:

```text
02_integer_widths-gcc-O2.so, all 28 functions:
0.23 s wall, 83,940 KiB max RSS

166_rust_generics-rustc-O0.so, the complete object:
5.43 s wall, 199,456 KiB max RSS

four 166_rust_generics objects:
12.82 s with one worker
6.21 s with three workers
identical evidence after excluding elapsed_seconds

complete corpus, 1,676 objects, eight workers:
203.97 s wall, 831,140 KiB max RSS
```

The prior serial full run was stopped after 4,213 seconds because it was still
inside fixture 169 and had not written an inventory. The completed 203.97-second
run is therefore at least 20.7 times faster in wall time; the actual completed
legacy/full ratio would have been larger.

## Parser regression found during validation

The first complete batch exposed 1,594 apparent pointer losses. Comparison of
single-VA and batch output proved the product output identical. The inventory
parser was removing `*arg0` as one whitespace token after the renderer adopted
conventional `char *arg0` spelling. `strip_name()` now removes only the trailing
identifier and preserves adjacent pointer stars. A real-fixture regression test
pins both `char *arg0` and `char * arg0`; the corrected full inventory contains
zero pointer losses.

## Refreshed ground-truth inventory

The completed run regenerated `tests/open_defects/known_failures.json`:

| axis | prior raw | current raw | current deduplicated |
|---|---:|---:|---:|
| parameter types | 307 | 82 | 65 |
| unwanted-goto functions | 717 | 715 | 473 |
| return types | 92 | 41 | 33 |
| pointer losses | 0 | 0 | 0 |
| unrecovered constructs | 46 | 42 | 27 |
| no body | 0 | 0 | 0 |

Current type mismatches split into C `0` and Rust `82`; current return
mismatches split into C `15` and Rust `26`. These are current-state movements
since the prior inventory, not all attributable to the immediately preceding
WP6 commit because other validated decompiler increments landed between the
two full measurements.

## Validation

```text
uvx ruff check tools/gen_known_failures.py \
  python/tests/test_known_decompiler_failures.py
pass

focused generator, parser, checkpoint/resume, summary, and ratchet tests
9 passed

python/tests/test_known_decompiler_failures.py full strict-xfail file
11 passed, 880 xfailed; 891 collected in 130.20 s wall, 621,796 KiB max RSS
```

No DecBench run or upstream interaction was performed.
