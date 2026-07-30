# Authoritative call-prototype checkpoint

Date: 2026-07-30

Source checkpoint: `7a8c4b08b6ce9d1ddbe90e618f482c7ef7bc3218`

## Verdict

Glaurung now selects one rendered prototype object for each resolved named
callee and preserves whether that object came from an authoritative library
catalog or recovered call-site evidence. Declarations, argument conversions,
and result representation conversions consume that same selection.

On a fresh static-only extraction of all 224 blinded DecBench binaries, the
official fixup/recompile path rises from **162/250 to 169/250 compilable
functions**: **seven gains and zero compile losses** in the same evaluator
environment. Mean byte match over all 250 functions rises from `0.1053502` to
`0.1096765`.

This is a real C-boundary and ABI improvement, not parity with Ghidra, angr, or
Kuna. The remaining 81 compilation failures and the larger structural and
semantic gaps still make a DecBench submission premature.

## Root cause

The prior checkpoint emitted evidence-derived prototypes for project-local
callees but deliberately excluded known library contracts. The call-contract
pass nevertheless used those library contracts to truncate arguments, suppress
void destinations, and cast arguments. That split produced three concrete
problems:

1. standalone output still depended on implicit library declarations;
2. catalog types such as `size_t` were not valid without their source headers;
3. adding a true pointer-return prototype made assignments to conservative
   machine-word locals invalid without an explicit representation conversion.

A second issue appeared in the blinded round trip. If even one call site lacked
the required authoritative parameter prefix, a function-wide true declaration
made the recovered call invalid C. Suppressing the declaration was not enough:
under the evaluator's current C23 compiler, `long f();` means zero parameters.
The renderer now downgrades that function-wide declaration to the recovered
common prefix instead of inventing missing arguments.

## Reference architecture

The design was checked against all three requested reference decompilers:

- Ghidra commit `7a4100d54bff88530f11b577d4d2547d57630288` stores a
  `FuncCallSpecs` object per call, derives it from `FuncProto`, and renders
  inputs and outputs from that semantic call specification.
- angr commit `9e44beff69554a9cbb4bd6c69eecefd4991ca2b8` has
  `CallSiteMaker` select a manually supplied call-site prototype, a known
  function prototype, or an automatically recovered call-site prototype, then
  attaches the selection to the AIL call.
- [Noelo-Lab/kuna](https://github.com/Noelo-Lab/kuna) follows Ghidra's
  `FuncCallSpecs`/`FuncProto` split and renders prototypes and inputs through its
  C printer rather than rediscovering them from final text.

Glaurung does not yet have a full per-call call-spec object. This slice makes
the existing function-scoped C boundary internally consistent: authoritative
catalog declarations win when every site satisfies their required prefix;
otherwise the declaration is downgraded to a recovered common prefix. Catalog
types are converted to headerless ABI-preserving spellings, and unknown scalar
typedefs fail closed.

## Real round trip

The RED fixture compiles a real shared ELF importing `memcpy`, resolves its
export, decompiles it through the native binary/LLIR/SSA/AST pipeline, and
strictly recompiles the generated standalone C. The final output is:

```c
long copy_known_bytes(long arg0, long arg1, long arg2) {
    extern void * memcpy(void *, const void *, __SIZE_TYPE__);
    long ret;
    long rsp;
    rsp = (rsp - 32);
    ret = (long)memcpy((void *)(arg0), (const void *)(arg1),
                       (__SIZE_TYPE__)(arg2));
    return ret;
}
```

`__SIZE_TYPE__` preserves the target ABI width without requiring `<stddef.h>`.
The explicit `(long)` states the current middle layer's pointer-to-machine-word
representation conversion. The unit compiles with strict C11 prototype checks,
implicit-declaration errors, and pointer/integer-conversion errors enabled.

The independent compiled behavior corpus remains green at 56/56 lanes. Three
wide-result call-fold lanes that fail on the retained baseline now pass for GCC
O0, GCC O2, and Clang O0.

## Blinded DecBench A/B

The blinded binaries were statically analyzed only. They were never executed,
emulated, or made executable.

A fresh 16-worker extraction emitted all 250 requested functions across all 224
binaries with zero adapter errors. The same materialized evaluator tree, Python
environment, compiler selection, producer flags, diagnostic fixup, and byte
match implementation were used for both sides.

| optimization | functions | prior compile | new compile |
|---|---:|---:|---:|
| O0 | 100 | 86 | 88 |
| O2-noinline | 100 | 49 | 52 |
| O2 | 50 | 27 | 29 |
| **total** | **250** | **162** | **169** |

The seven compile gains are:

- O0 `base-passwd/update-passwd/read_shadow`;
- O0 `diffutils/diff3/try_help`;
- O2 `bzip2/bzip2recover/bsOpenReadStream`;
- O2 `diffutils/diff3/try_help`;
- O2-noinline `grep/grep/finalize_input`;
- O2-noinline `rsyslog/rsyslogd/janitorCB`;
- O2-noinline `zlib/minigzipsh/main`.

There are zero compile losses. Six of the gains also add positive byte-match
scores; `zlib/minigzipsh/main` now compiles but still scores `0.0` because its
recompiled assembly has no shared normalized lines.

Four already-compiling functions have lower byte-match scores:

- `libacl/getfacl/xquote`: `0.40625` to `0.29730`;
- `coreutils/chown/usage`: `0.27273` to `0.24809`;
- `libacl/libacl.so.1.1/acl_equiv_mode`: `0.20270` to `0.18919`;
- `coreutils/chgrp/describe_change`: `0.36015` to `0.35361`.

The exact C diffs show true pointer returns (`dcgettext`,
`__errno_location`), true void/no-return-family declarations
(`__stack_chk_fail`, `exit`, `abort`), and correct format-argument types
replacing evidence-derived `long` declarations. The lower assembly similarity
is therefore retained and reported rather than hidden; the next call-spec slice
must carry attributes such as `noreturn` so the compiler can eliminate the same
unreachable tails as the original binary.

The immutable submission artifact is `glaurung-results-7a8c4b0.zip`, SHA-256
`99478e4ef12881aff5f9d90ee821a63f68b3a72149dab8afd47ecfcbcbf3e12c`.
Its 224 generated C members have the same combined SHA-256 as the officially
scored WIP artifact: `50f92fcf4ff85b2fe20f86b4999758e8dcea6c1fed79aa88dbe007f0546f552b`.

## Remaining failure frontier

The official path now has 81 noncompilable functions. A fresh diagnostic replay
finds 15 residual arity-failure functions:

- four recursive/internal call-recovery failures: `i2cWait`,
  `modinfo_name_do`, `check_init_fifo`, and `ensure_single_instance`;
- eleven mixed-arity external-call failures involving `__printf_chk`, `error`,
  `dcgettext`, `free`, `acl_from_text`, `__snprintf_chk`, `strchr`, and
  `__assert_fail`.

The external cases have no single non-contradictory function-wide C prototype:
the same recovered function contains both zero-argument and nonzero-argument
sites. The next architectural slice should attach a selected call spec to each
`Stmt::Call`, including provenance, required parameters, variadic state,
calling convention, return type, and behavioral attributes. That matches the
reference architectures and avoids another function-wide textual heuristic.

## Gates

- Rust library tests: 1,290 passed, zero failed.
- Real compiled fixture harness: passed in full.
- Compiled behavior corpus: 56/56 lanes, three improvements, zero regressions.
- Native extension rebuilt after the final Rust change.
- `cargo clippy --all-targets`: exit 0 with the existing warning backlog.
- `cargo fmt --check` and `git diff --check`: passed.
- Ruff on the owned Python test file: passed.
- Blinded extraction: 224/224 binaries and 250/250 functions.
- Official recompilation overlay: 169/250, seven gains, zero losses.

Repository-wide `ty` remains outside this slice's evidence because the retained
baseline already has 3,320 unrelated diagnostics. The known broad Python-suite
failures remain the stale binary-size expectation, existing C-render parse
coverage, and the offline LLM-path selection; the complete real decompiler
fixture harness is green.

## Wall-clock findings

The final full extraction takes about 55 seconds with 16 workers. The official
250-function recompile overlay takes about two seconds. Native rebuilds take
about four to seven seconds, and the full Rust library suite takes about two
seconds once built. The dominant cost is DecBench eval-kit ingestion, which is
silent and takes roughly 80-90 seconds per package.

The practical fast loop is therefore:

1. one real compiled RED;
2. one native rebuild;
3. focused gates;
4. one full 16-worker extraction after code stabilizes;
5. one final ingestion only;
6. overlap ingestion with independent Rust/Python/behavior gates;
7. run the two-second recompile overlay;
8. retain diagnostics and restamp the immutable commit artifact without
   re-extracting.

Further wall-clock improvement belongs in the evaluator: incremental ingestion
of changed binaries would remove most iteration latency. Glaurung's batch
decompilation and the parallel recompile path are no longer the bottlenecks.

## Submission decision

Do not submit yet. The zero-loss compile gain is material, but 67.6%
compilability, unresolved per-call prototype conflicts, and the outstanding
structural/GED and behavioral-semantic gaps are not competitive enough for a
credible Ghidra/angr/Kuna parity claim.
