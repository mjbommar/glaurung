# Call-site specifications and DecBench checkpoint

> **Kind:** record · **Date:** 2026-07-30

Date: 2026-07-30

Source checkpoint: `6ddf4ce778b4d780cfac69de0565aec6b0ed9bb3`

## Verdict

The DecBench package is mechanically ready to submit: it is valid, complete,
commit-addressed, and all 250 target functions compile through DecBench's
official byte-match metric. Glaurung is **not yet proven competitive overall**
with Ghidra, angr, or Kuna. The current sample tree has no source `.i` files, so
fresh GED and type-match evidence is unavailable, and compile success does not
establish semantic equivalence.

This sequence closes the immediate call-boundary architecture gap. Every call can
now retain both the stable callee contract and the exact recovered site
contract through later AST/type refinements, and the renderer consumes the same
contract when declaring, casting, and emitting the call. The final checkpoint
also makes imported non-returning contracts part of function discovery, so an
optimized `exit` path cannot absorb the next function and poison the recovered
call/return contract.

## Architecture and references

`Stmt::Call` owns an optional `CallSiteSpec` with two deliberately separate
facts:

- `callee_prototype` is the stable function/import declaration when one is
  known;
- `call_prototype` is the exact argument/result boundary recovered at this
  call site.

`recover_call_site_spec` attaches the site object only after ABI argument
reconstruction. `apply_known_call_contracts` applies authoritative fixed and
variadic contracts without inventing missing arguments. After AST and type
refinement, `refine_call_site_specs` refreshes the exact site boundary. Direct,
recursive, and indirect emission all consume that retained object.

The design was checked against primary source rather than inferred from output:

- [Ghidra `FuncCallSpecs` and `FuncProto`](https://github.com/NationalSecurityAgency/ghidra/blob/7a4100d54bff88530f11b577d4d2547d57630288/Ghidra/Features/Decompiler/src/decompile/cpp/fspec.hh)
  represent the per-call and function contracts; [its C printer](https://github.com/NationalSecurityAgency/ghidra/blob/7a4100d54bff88530f11b577d4d2547d57630288/Ghidra/Features/Decompiler/src/decompile/cpp/printc.cc)
  consumes the call specification.
- [angr's Clinic](https://github.com/angr/angr/blob/9e44beff69554a9cbb4bd6c69eecefd4991ca2b8/angr/analyses/decompiler/clinic.py#L1283-L1338)
  selects manual call-site, function, or recovered call-site prototypes and
  stores the result on the AIL call.
- [Kuna's `FuncCallSpecs`](https://github.com/Noelo-Lab/kuna/blob/d09f21ce73627f6bddfcb41c436d3235b114b945/decompiler/crates/kuna-decomp/src/p4_calls/fspec.rs#L6072-L6174)
  is retained in `Funcdata::qlst`, and [Kuna's P9 C printer](https://github.com/Noelo-Lab/kuna/blob/d09f21ce73627f6bddfcb41c436d3235b114b945/decompiler/crates/kuna-decomp/src/p9_emit/printc.rs#L4611-L4720)
  resolves that specification while emitting calls. Kuna commit
  `d09f21ce73627f6bddfcb41c436d3235b114b945` is now a pinned decompiler
  reference alongside Ghidra and angr.

Glaurung now has the same essential boundary, but not full parity. It still
lacks a complete calling-convention model, parameter storage maps, general
side-effect attributes, and the iterative interprocedural prototype/type fixed
point present in the mature designs. `noreturn` coverage is currently a small,
exact import-contract set rather than a general inferred attribute system.

## Real TDD witnesses

The change was driven by compiled ELF round trips, not mocked AST text alone.
The RED fixtures covered:

1. one external `free` called both correctly and with a missing argument;
2. mixed recursive call arities;
3. pointer literals crossing return, assignment, store, select, and call
   boundaries;
4. address-taken stack objects and stack-pointer arithmetic;
5. a pointer parameter reassigned from integer address arithmetic;
6. a stripped optimized ELF function ending in an imported `exit`, followed by
   an adjacent function with a distinct arithmetic body; and
7. an unknown local call result guarded by a zero check, with the failure path
   ending in `exit` and the success path returning the value unchanged.

Representative RED output was invalid C:

```c
free(arg0);
free();
arg0 = ((long)arg0 + local_8);
```

The final boundary is explicit and preserves the recovered address bits:

```c
free(arg0);
((void (*)(void))free)();
arg0 = (char *)((long)arg0 + local_8);
```

The final pointer-parameter fixture compiles a real shared ELF, decompiles the
target address through the installed Rust extension, and recompiles the result
with GCC 15, C23, and `-Werror=int-conversion`.

## Blinded DecBench evidence

The blinded binaries were statically analyzed only. They were never executed,
emulated, or made executable.

Final artifact:

- path:
  `/home/mjbommar/projects/personal/decbench-evalkit-sample-set/glaurung-results-6ddf4ce.zip`;
- source: `6ddf4ce778b4d780cfac69de0565aec6b0ed9bb3`;
- SHA-256:
  `bb8fac66dfc21022a35d57e45823b43302d62e0eb656c5a258fe049d34425d2d`;
- size: 286,926 bytes;
- coverage: 224/224 binaries and 250/250 target functions.

The first full package in this slice was ingested through DecBench with zero
dropped and zero missing functions. The final package has the same frozen
binary/address identity set. It was rescored directly with DecBench's official
`ByteMatchMetric`, using that verified identity map rather than repeating the
slow address/name ingestion pass.

| checkpoint | compilable | mean byte match |
|---|---:|---:|
| pre-slice `7a8c4b0` | 169/250 (67.6%) | 0.1096765047271132 |
| retained call specs `00b72e3` | 238/250 (95.2%) | 0.1500434576188256 |
| stack representation `4aa92ec` | 248/250 (99.2%) | 0.15454538383049354 |
| pointer boundary `d6882dc` | 250/250 (100%) | 0.15612902766757247 |
| noreturn CFG boundary `6ddf4ce` | **250/250 (100%)** | **0.16146020536865263** |

At `d6882dc`, against `7a8c4b0`, the pointer-boundary package had 81 compile
gains and zero compile losses. Byte match improved for 84 functions, declined
for 15, and was unchanged for 151; the mean delta was
`+0.046452522940459276`. Its largest retained per-function decline was
`libacl/getfacl:xquote`,
`0.2972972972972973 -> 0.225`. Those 15 score declines remain a triage queue;
the aggregate gain is not permission to hide them.

The noreturn checkpoint resolves that specific regression at its cause. The
original `xquote` is a 77-byte function whose error arm ends in `exit(1)`;
previous CFG discovery continued into two adjacent functions. The exact
single-function compile/disassemble loop now scores it at `0.6666666666666666`
(edit distance 7), while the canonical whole-package context scores it at
`0.5652173913043478` (distance 10), up from `0.225` (distance 31). Across all
250 functions relative to `d6882dc`, 50 improve, 27 decline, and 173 are
unchanged. The mean delta is `+0.00533117770108016` (`+3.41%` relative).

## Wall-clock changes

The safe edit loop no longer performs the whole evaluator pipeline after every
change:

| operation | measured wall time |
|---|---:|
| exact one-function extract, fixup, compile, disassemble, score loop | about 2.2 s |
| release Rust extension rebuild at `6ddf4ce` | 19.14 s |
| focused two-binary extraction | 2.05 s |
| focused 12-binary extraction | about 5 s |
| exact full 250-function score with retained identities/cache | 4.85-9.5 s |
| uncontended full 224-binary extraction | about 49-51 s |
| final full extraction while full pytest was also running | 61.66 s |
| package validation and ZIP creation | under 0.3 s |
| all 365 Python test files, serial attempt | stopped at 49% after about 15 min |
| all 365 Python test files, eight file shards | 305 s |

The default `evalkit ingest --evaluate` path attempted to fetch roughly
1.79 GB of Joern even though this sample tree has no `.i` source files and GED
cannot score. The fast loop uses `--no-evaluate`, a frozen identity check, the
exact affected binaries, and the official byte-match metric. One full extraction
is retained only at the immutable handoff commit.

## Gates and limits

- Rust library: 1,298 passed, zero failed.
- Real compiled decompiler fixture file: 49 passed, zero failed.
- Repository-wide Python collection: 2,638 tests across 365 files. The
  eight-shard run completed in about 305 s with 2,566 passed, 43 skipped, and
  29 failed. This broad gate is not green. The failures are outside the owned
  fixture file; one is the intentional stale-ratchet failure for the three
  retained behavioral improvements, while the others remain separate backlog
  requiring attribution rather than being relabeled as this slice's failures.
- Behavioral differential: 56/56 lanes, no regressions, with three retained
  `call_fold_wide_result` improvements.
- `cargo fmt --check` and `git diff --check`: passed.
- Ruff on the owned Python fixture file: passed.
- Clippy: exit 0 with the repository's existing warning backlog.
- `ty`: 3,320 repository-wide diagnostics, an existing broad backlog; not green.

This checkpoint proves complete recompile coverage and a substantial official
byte-match gain. It does not prove behavioral correctness on the blinded
functions, close the older GED/type gap, or establish full decompiler parity.
The package can be submitted for measurement, but it should not be presented as
evidence that Glaurung is already comparable overall.
