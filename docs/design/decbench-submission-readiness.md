# DecBench submission readiness

What has to be true before we open a PR against `Noelo-Lab/decbench`, what is
true today, and what we would be asking a reviewer to accept. Written by working
backwards from the submission rather than forwards from the code.

The native DecBench adapter is preserved and pushed to the Glaurung owner's
DecBench fork as `codex/glaurung-external-eval` at `e110ad7`. It is not merged
into `Noelo-Lab/decbench`: there is no upstream PR, issue, or submission.

Last updated: 2026-08-02.

## Current decision: do not submit

### Current output checkpoint: `a374669` + uncommitted working tree, compile regression repaired (2026-08-02, later)

The 26-function compile regression recorded in the checkpoint below is **fixed**.
The holdout was re-extracted from the repaired tree, re-packaged, re-ingested as
column `glaurung-fix1`, and re-scored on all three official metrics with the same
DecBench checkout (`efc5d5a`). Static-only throughout: nothing in the extraction
or scoring path executes an input binary.

**Package.** SHA-256
`94963501e902af20908ab49c0575f16cd4a28e7f76fda774c1a8f6bed939e42b`, 258,248
bytes, 225 files. Coverage 224/224 binaries and 250/250 target functions, zero
adapter or decompilation errors; extraction 52.9 s wall at 12 workers. Retained
at `~/projects/personal/decbench-evalkit-sample-set/glaurung-results-fix1.zip`
and `.../glaurung-evidence-fix1/`.

| official metric | baseline `5f8b933` | regressed `wt9c0ba99` | repaired `fix1` |
|---|---:|---:|---:|
| byte match (mean, n=250) | 0.1866975601529133 | 0.2285033717892795 | **0.2391510254904763** |
| byte-match compile coverage | 250/250 | 224/250 | **250/250** |
| type match (mean, n=235) | 0.1284714912163488 | 0.1814063697206141 | **0.1814063697206141** |
| type match, perfect | 8 | 15 | 15 |
| GED (mean, n=239, lower is better) | 29.807531380753137 | 28.527196652719667 | **28.527196652719667** |
| GED, perfect | 52/239 | 56/239 | 56/239 |

type_match and GED are bit-identical to the regressed checkpoint — the repair is
confined to C emission and changes no recovered type or control-flow structure.
byte match rises a further `+0.0107` on top of it, and all 26 lost functions
compile again. Against the baseline: byte match improved on 139 functions,
declined on 44, unchanged on 67 (was 131/52/67); functions with a nonzero byte
match move `194 -> 204`. Per architecture, every lane now compiles 100 %:

| | n | byte base | byte `wt9c0ba99` | byte `fix1` | compiles |
|---|---:|---:|---:|---:|---|
| ELF64-x86-64 | 158 | 0.2356 | 0.2720 | **0.2799** | 158 -> 146 -> **158** |
| ELF32-ARM | 84 | 0.1013 | 0.1576 | **0.1660** | 84 -> 72 -> **84** |
| PE32-i386 | 8 | 0.1180 | 0.1137 | **0.2027** | 8 -> 6 -> **8** |

The PE32 lane — the one lane that moved the wrong way at `wt9c0ba99` — is now the
largest relative gain, because both of its lost functions were the `__int128`
ones.

**The regression had five causes, not three.** The three named below are real and
account for 22 of the 26; the full stderr classification is:

1. **A void call assigned — 11 functions, all ARM32** (10 `void value not ignored
   as it ought to be`, plus `cleanflight:m25p16_enable`, whose cast made it
   `invalid use of void expression`). Root cause: `recover_direct_callee_layouts`
   (`src/python_bindings/ir.rs`) analyses each direct callee's own body and
   supplies a recovered `CallPrototype`; when that prototype's return is `void`,
   `apply_recovered_callee_prototypes` installed it as the callee declaration but
   left the caller's `dst` in place. It runs **only** for `CallConv::ArmHardFloat`,
   which is exactly why the class is ARM-only. Fixed by dropping the destination,
   the same authority rule `apply_known_call_contracts` already applies to catalog
   contracts (`a5149a1`): the callee's definition-site evidence outranks the
   caller's observation that a *caller-saved* result register was live out of the
   call. Occurrences `18 -> 0`.
2. **A portable global address in an integer slot — 9 functions.** Not "undeclared
   globals": the compile error occurs even with Glaurung's own declaration
   present. `Expr::Addr(va)` began rendering as `&glaurung_global_X[0]` — a real C
   pointer — while `expression_has_pointer_representation` still classified
   `Expr::Addr` as an integer (`Expr::Named`, its twin spelling, was already
   classified as a pointer). Every integer-typed consumer therefore got a pointer
   with no conversion. Fixed by making the classifier agree with the printer;
   32 `(long)(&glaurung_global_...)` conversions now appear.
   *Separately*, the declaration genuinely did not survive DecBench's per-function
   slicing (`decbench.evalkit.ingest` keeps only the function definition, so the
   file-scope `static` is dropped and the fixup pass injects `long g[1024]`). The
   renderer now also emits `extern unsigned char glaurung_global_X[16];` inside
   the body — legal against the file-scope `static` (C11 6.2.2p4), so whole-file
   sharing is preserved and the sliced fragment declares everything it names.
   Measured cost of self-declaring: on the 88 affected functions the mean is
   0.26558 with the declaration against 0.27125 without (~0.002 on the 250-function
   mean). The alternative of a block-scope `static` *definition* was also measured
   and is much worse (0.19179) — it loses the shared object.
3. **`__int128` on a 32-bit target — 2 PE32 functions.** `write_wide_arithmetic_dec`
   hard-coded the 128-bit intermediate regardless of operand width. The
   double-width type belongs to the operand width, so it is now derived
   (`double_width_ctype`): 4-byte operands widen to `long long`, 8-byte operands
   keep `__int128`. Occurrences `54 -> 40`, and all 40 remaining are on
   ELF64-x86-64. `RandStrA` 0.0250 -> 0.2119 and `RandStrW` 0.0600 -> 0.5000
   against the *baseline*, not just against zero.
4. **16-byte transport builtins passed integers — 3 functions**
   (`coreutils/sort:mergelines_node`, `libbsd:r_sort_a`, `shadow/groupmod:grp_update`).
   `__builtin_memcpy`/`memmove`/`memset` take `void *`; their address operands were
   written with the raw machine-word printer. They now go through the same
   representation conversion as every other pointer boundary.
5. **A recovered pointer parameter contradicted by the argument — 1 function**
   (`crazyflie/cf2:write_power_mode`). The emitted declaration said `int *` and the
   call passed a `char *`; "renders as a pointer" was treated as sufficient to skip
   the boundary cast. Two *different* pointer types are still a type error, so the
   declared parameter type is now reasserted when the argument's declared pointer
   spelling differs.

**Coverage added for defect 3.** `tools/arch_roundtrip.py` cannot catch it by
construction — it declares `__int128` an *unsupported source* on its 32-bit lanes
and rebuilds recovered C at the host pointer width, where the type exists.
`python/tests/test_decompiler_wide_arithmetic_width.py` builds a real i386 and a
real ARM32 shared object of constant divisions and a widening multiply, asserts no
`__int128` in the recovered C, asserts the double-width intermediate was in fact
recovered (non-vacuity), and **recompiles the recovered C for that same 32-bit
target** — the only compile that can reject the type. An x86-64 control asserts a
genuine 64x64 multiply-high still uses `__int128`.

**Gates at this checkpoint.** `cargo test --lib` 1,657 passed / 0 failed (1,651 +
6 new); `tools/fixture_harness.py` 656 pass / 0 fail / 67 structural;
`pytest -m slow python/tests/test_decompiler_fixture_structural.py` 23 passed;
`tools/arch_roundtrip.py --check` matches the recorded baseline exactly (x86-64
328/328 = 100 % control lane clean, i386 244/272 = 89.7 %, aarch64 261/318 = 82.1 %,
armv7 183/262 = 69.8 %); `tools/decbench_matrix.py --check` reports `FULL MATRIX:
no per-cell regressions across 56 of 56 cells`; `tools/dectest.py @smoke` reports
`SCOPED: 4 lanes of 120 (3%) — no regressions in scope`.

**Verdict: unchanged — still do not submit.** The blocking gap is competitive,
not mechanical: on pairwise-common keys type match and GED remain behind Ghidra,
angr and Kuna. What has changed is that the package no longer scores worse than
the one it replaces on DecBench's own compile oracle.

### Superseded: output checkpoint `a374669` + uncommitted working tree (2026-08-02)

Re-measured on the frozen 250-function / 224-binary `sample-set` holdout with
the DecBench checkout at `efc5d5a`. Static-only: no blinded binary was executed,
emulated, or made executable, and nothing in the scoring path executes one
either — the only subprocesses are compilers run over Glaurung's own decompiled
C and `objdump -h` reading input headers.

**Package.** SHA-256
`ea86525a638eaabba3ad5d7a73fc85573ac9bdaacc442559d28c45ed4d622709`,
256,800 bytes, 225 files, 1,158,153 uncompressed bytes. Coverage is 224/224
binaries and 250/250 target functions with zero adapter or decompilation errors,
matching the standing coverage bar. Extraction took 74.7 s wall at 12 workers
(883 s of summed per-binary work); the slowest binary was 4.66 s, against a
206.52 s outlier at `19dde75`. The package and its scoring artifacts are retained
at `~/projects/personal/decbench-evalkit-sample-set/glaurung-results-wt9c0ba99.zip`
and `.../glaurung-evidence-wt9c0ba99/`.

**The baseline is `5f8b933`, not `d6882dc`.** The `d6882dc` figure recorded
below was superseded five times on 2026-07-30 without this document being
updated. The last checkpoint with a full recorded official byte-match score is
`5f8b933` (`byte_match_5f8b933.json`, 2026-07-30 07:24) at
`0.1866975601529133`, 250/250 compiling. The intervening measured values were
`6ddf4ce` 0.16146020536865263, `6175a19` 0.16206524218413854, `e4bbbef`
0.18422828241317493, and `bd2d13c` 0.18421191793090594. Seven further packages
(`923d740`, `afc2d64`, `ef303d2`, `f3ddcec`, `8ea9686`, `f7ce61d`, `b241e40`)
were built and never scored at all. Quoting `d6882dc` as the reference would have
overstated this checkpoint's byte-match gain by roughly 0.031.

**Baseline reproduction.** `glaurung-results-5f8b933.zip` was re-ingested into a
fresh column and re-scored with today's checkout. All 250 byte-match values and
compilable flags, and all 235 type-match values, are bit-identical to the
retained artifacts, with and without `DECBENCH_NO_CACHE=1`. The tooling
reference point is therefore trustworthy and the A/B below is same-tooling.

| official metric | baseline `5f8b933` | this checkpoint | delta |
|---|---:|---:|---|
| byte match (mean, n=250) | 0.1866975601529133 | 0.2285033717892795 | **+0.0418** (+22.4%) |
| byte-match compile coverage | 250/250 | **224/250** | **-26 — regression** |
| type match (mean, n=235) | 0.1284714912163488 | 0.1814063697206141 | **+0.0529** (+41.2%) |
| type match, perfect | 8 | 15 | +7 |
| GED (mean, n=239, lower is better) | 29.807531380753137 | 28.527196652719667 | **-1.2803** (-4.3%) |
| GED, perfect | 52/239 | 56/239 | +4 |

Byte match improved on 131 functions, declined on 52 and was unchanged on 67.
Perfect byte matches stayed at 6; functions with a nonzero byte match moved
`194 -> 191`, because 26 functions that used to compile no longer do and score 0.
Type match improved on 44, declined on 20 and was unchanged on 171. GED improved
on 58, worsened on 39 and was unchanged on 142; the largest single GED
regression is `gnutls/certtool:yyparse` at `195 -> 357`.

**Per architecture.** The holdout is 158 x86-64 ELF functions (158 binaries,
13 of them shared objects), 84 ELF32-ARM functions (58 binaries) and 8 PE32-i386
functions (8 binaries). It contains **no AArch64 and no ELF32 i386 at all**.

| | n | byte base | byte new | byte delta | type base | type new | type delta | compiles |
|---|---:|---:|---:|---|---:|---:|---|---|
| ELF64-x86-64 | 158 | 0.2356 | 0.2720 | +0.0364 (+15.5%) | 0.1587 | 0.1698 | +0.0111 | 158 -> 146 |
| ELF32-ARM | 84 | 0.1013 | 0.1576 | **+0.0563 (+55.6%)** | 0.0712 | 0.2192 | **+0.1480 (+208%)** | 84 -> 72 |
| PE32-i386 | 8 | 0.1180 | 0.1137 | **-0.0043** | 0.1012 | 0.0417 | **-0.0595** | 8 -> 6 |

GED does **not** show the same ARM concentration; it improves near-uniformly and
slightly everywhere: x86-64 `33.7898 -> 32.3885` (n=157), ARM32
`22.4865 -> 21.4054` (n=74), PE32 `19.3750 -> 18.6250` (n=8).

The ARM32 hypothesis holds, decisively on type match and clearly on byte match,
and the effect concentrates at `-O0` (ARM32 byte match `0.0978 -> 0.1648`,
+68.5%). It is corroborated structurally: across the ARM32 payloads only,
emitted `int` declarations move `135 -> 338` while `long` declarations move
`790 -> 517`, and leaked condition-flag temporaries move `145 -> 18`. The PE32
slice regressed on both metrics; it is only eight functions, but it is the one
lane that moved the wrong way.

**Attribution limit — the gain is not the lifter fixes alone.** The A/B spans
131 committed commits (47 on 2026-07-30, 77 on 2026-07-31, 7 on 2026-08-01;
157 files, ~46k lines) *plus* the uncommitted working tree (~7.2k inserted lines
across 21 core files). Many of the 2026-07-30 commits are themselves ARM- and
DecBench-targeted (`recover ARM hard-float scalar expressions`, `recover ARM
frame-backed results`, `preserve ARM narrow parameter semantics`). No isolation
run was performed, so the holdout movement cannot be attributed to the
cross-architecture execution differential's lifter work specifically. Note also
that one of the shared-IR fixes credited for it — the `expr_reconstruct`
`Expr::Lea` register-slot bug — is documented in its own regression test as
"latent until AArch64", and the holdout contains no AArch64.

**The compile regression is real and has three named causes.** (Superseded — see
the repaired checkpoint above: the classification below is right about three of
the five actual causes, and "undeclared globals" is the wrong root cause for the
second.) 26 functions that compiled at `5f8b933` no longer do; zero moved the
other way. Twelve of them had
a nonzero byte match that is now 0, including `gnutls/systemkey:get_organization_crt_set`
(0.3086 -> 0), `shadow/groupmod:grp_update` (0.2703 -> 0) and
`cleanflight:m25p16_enable` (0.2500 -> 0). Classified from full compiler stderr:

1. **`void value not ignored as it ought to be` — 10 functions, 9 of them ARM.**
   The renderer emits `var58 = ((void (*)(int))sub_8000258)(0x80010e0);`: the
   recovered callee prototype says `void` and the call is still assigned to a
   result. This is the exact defect `a5149a1` drove to zero for *imported* void
   callees, reappearing for locally recovered `sub_XXXX` callees. Occurrences of
   the pattern move `0 -> 18` across the package.
2. **Undeclared globals in integer slots — 14 functions.** The new work emits
   `&glaurung_global_XXXX[0]` 1,100 times (from 0) and **never declares them**.
   DecBench's fixup compiler injects `long glaurung_global_XXXX[1024];`, so the
   expression is `long *`, and every use in a `long` slot fails
   (`assignment to 'long int' from 'long int *'`, `passing argument 1 of
   'sub_3506d' makes integer from pointer`, `__builtin_memcpy`, `pam_start`,
   several `gnutls_*_allocate_*`). Emitting an identifier the payload does not
   declare is the defect; the fixup compiler's `long[1024]` guess is only what
   makes it visible.
3. **`__int128` on a 32-bit target — 2 functions**, both PE32
   (`dexter:RandStrA`, `dexter:RandStrW`). `__int128` occurrences move `0 -> 54`.
   `tools/arch_roundtrip.py` declares this a *skip* on 32-bit lanes rather than a
   failure, so its four green lanes cannot see it.

**Like-for-like comparison — and a correction to the table further down.** The
reference decompilers were only byte-match-scored on the 158 x86-64 functions;
they have no score at all on the 84 ARM32 and 8 PE32 functions. Comparing
Glaurung's 250-denominator compile count against their 152-158 denominators, as
this document has been doing, is not a like comparison. On pairwise-common keys:

| metric | n | Glaurung base | Glaurung new | Ghidra | angr | Kuna | IDA | Binja |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| byte match (x86-64 only) | 158 | 0.2356 | **0.2720** | 0.3106 | 0.3261 | 0.3322 | 0.3448 | 0.2350 |
| compiles (x86-64 only) | 158 | 158 | **146** | 125 | 120 | 131 | 131 | 94 |
| type match | ~217 | 0.1369 | **0.1941** | 0.2307 | 0.2798 | 0.1933 | 0.1895 | 0.3041 |
| GED, lower better | ~225 | 30.556 | **29.236** | 20.431 | 22.212 | 18.951 | 20.640 | 30.975 |

(Each column is restricted to the keys that reference scored, so `n` differs per
pair; the byte-match row is 158 because the references have **no** byte-match
score on the 84 ARM32 or 8 PE32 functions at all.)

> **CORRECTION, 2026-08-04 — the two sentences that followed here were FALSE
> and caused a real misdirection. Re-measured live with the current metric:**
>
> | column | x86-64 | ARM32 | PE32 | total |
> |---|---:|---:|---:|---:|
> | `glaurung-fix1` | **158/158** | 84/84 | 8/8 | 250/250 |
> | current build | 133/158 | 48/84 | 4/8 | 185/250 |
> | `glaurung-24b3826` | **15/158** | 74/84 | 8/8 | 97/250 |
>
> The claim "leads every reference decompiler **and always has**" is false: at
> `24b3826` — the very build the 97/250 line describes — Glaurung compiled
> **15/158 = 9.5 %** on x86-64, against Ghidra's 79.1 %. And "97/250
> under-reported it" is backwards: counting the 84 ARM32 and 8 PE32 functions,
> which no reference decompiler is scored on at all, *inflated* that build's
> headline from 9.5 % to 38.8 %. The 97/250 line OVER-reported.
>
> Glaurung's compile rate did lead every reference at `fix1` (158/158 vs Ghidra
> 125/158) — and 65 of those functions have since regressed (task #70).
>
> Reference denominators are also NOT uniformly 158: ghidra 158, kuna 158,
> ida 154, angr 152, binja 153, r2dec 133. The table above prints them under one
> `n=158` header, which is wrong; ranking is unaffected, the rates are not. On byte match Glaurung is now ahead of Binja and has halved
the gap to Ghidra (`-0.075 -> -0.039`). On type match it has drawn level with
Kuna and IDA and halved the gap to Ghidra (`-0.094 -> -0.037`), while angr and
Binja remain ahead. On GED it is now ahead of Binja and the gap to Ghidra has
narrowed from roughly 2x to about 1.43x — real progress, still not parity.

**GED is measurable on this tree, contrary to the record.** The claim recorded
under `d6882dc` that "the current sample tree cannot produce fresh GED/type-match
values" is wrong on both counts: type match recomputes from `checkpoints/*.pkl`
via `scripts/reeval_typematch.py` in about 4m20s, and GED scores from the tree's
221 published `source_cfgs/*.json` via `decbench evaluate-tree` (about 65 min at
16 workers) without needing the absent `.i` files. Only nuttx (3 binaries) has no
source CFG, which is why GED scores 239 of 250 rather than 250. A second stale
figure falls out of this: the retained GED of `41.335` for `f02ecb9` in the
comparison table below is several days of work out of date — the reproduced
`5f8b933` baseline already scores `29.808`, so the "roughly 2x GED gap" repeated
throughout this document was already stale before this checkpoint.

**Gates at this checkpoint.** `cargo test --lib` 1,651 passed / 0 failed;
`tools/fixture_harness.py` 656 pass / 0 fail / 67 structural;
`tools/arch_roundtrip.py --check` matches the recorded baseline exactly
(x86-64 328/328 = 100%, i386 244/272 = 89.7%, aarch64 261/318 = 82.1%,
armv7 183/262 = 69.8%); `tools/decbench_matrix.py --check` reports
`FULL MATRIX: no per-cell regressions across 56 of 56 cells`.

**Verdict: still do not submit.** All three official metrics moved in the right
direction, the ARM hypothesis is confirmed on two of them, and compile rate leads
the field on the common set. But the two axes this document has named as blocking
are still short: on pairwise-common keys type match is 0.194 against Ghidra's
0.231 and angr's 0.280, and GED is 29.24 against Ghidra's 20.43, angr's 22.21 and
Kuna's 18.95. Against that, this checkpoint *introduces* a
26-function compile regression from three defects that are ordinary emission
bugs, not architectural limits — undeclared globals, a void result assigned, and
`__int128` on a 32-bit target. Submitting a package that scores worse on
DecBench's own compile oracle than the one it replaces, while two headline
metrics are still behind the production reference, is not a submission. Fix the
three defects, re-measure, and reconsider.

### Previous output checkpoint: `d6882dc`

The call-site specification, stack representation, and pointer-boundary slices
now produce a valid static-only package covering all 250 target functions in
224 binaries. DecBench's official byte-match metric compiles 250/250 functions
with mean `0.15612902766757247`, up from 169/250 and
`0.1096765047271132` at the immutable pre-slice checkpoint. The final package
SHA-256 is
`4005d09a7ad411002f30c4a1550771cf488994667a570819a5ab9f89936eb9ef`.

The package is mechanically ready to submit for measurement. The competitive
decision remains **do not claim parity or publication readiness**: the current
sample tree cannot produce fresh GED/type-match values, byte-match has 15
per-function declines despite its large net gain, and compile success is not a
behavioral oracle. Full architecture, TDD, wall-clock, package, and comparison
evidence is in
[`2026-07-30-call-site-specs-and-decbench.md`](../analysis/decompiler/2026-07-30-call-site-specs-and-decbench.md).

### Previous output checkpoint: `7abdc82`

DWARF return contracts now remain locked across machine-code output recovery
and later type refinements. This restores both optimized `cpp_raii_guard`
behavioral lanes while leaving stripped-binary output inference unchanged. The
complete evidence, real round trip, reference comparison, and artifact audit
are in
[`2026-07-30-dwarf-locked-return-contracts.md`](../analysis/decompiler/2026-07-30-dwarf-locked-return-contracts.md).

The reproducible static-only artifact covers 250/250 functions in 224/224
binaries with zero adapter errors. Its SHA-256 is
`54ae5b6098c9afbf0e3a52a49404fe5632551ce205ff2a774af29f4564d206da`.
Its C payload is byte-identical to a clean isolated rebuild of the preceding
source checkpoint `7bee103`, so the change itself has zero blinded output
delta.

That audit also found that the older archive labeled `7bee103` is not
reproducible from its named source object in the current pinned environment: it
differs in five stripped ARM files only by explicit narrow store casts. The
prior 127/250 compile result is therefore not relabeled as a current score.
Fresh official GED, byte-match, type-match, and compile/fixup measurements are
still required before submission.

### Previous output checkpoint: `a5149a1`

The native pipeline now applies known source-level call contracts after ABI
argument/result reconstruction. It loads the canonical libc/POSIX and WinAPI
prototype bundles once, normalizes ELF/PLT, Mach-O, and imported-name
decorations, truncates only fixed non-variadic calls, preserves variadic tails,
and removes impossible result destinations from declared-`void` functions. The
DecBench renderer uses the same contract for fixed-parameter conversions, so a
machine-word local passed to `free(void *)` is emitted as an explicit pointer
conversion instead of forcing the benchmark compiler to discard the real
prototype.

This is the same authority rule used by Ghidra's locked `FuncProto`, angr's
callee-prototype-first `CallSiteMaker`, and Kuna's P4 call/prototype phase. It is
still a bounded step rather than parity with them: Glaurung does not yet persist
the contract on every call node, distinguish imported from same-named internal
symbols, or iterate interprocedural prototypes with SSA and dead-code recovery.

The TDD witness is a real GCC-built ELF import. Before the change,
`report_and_test` rendered `var1 = perror(arg0);` and the strict C round trip
failed with `void value not ignored`. It now renders
`perror((const char *)(arg0));` and recompiles under `-std=gnu11 -Werror` without
warning suppression. This crosses binary compilation, symbol resolution,
native lifting, AST passes, C rendering, and recompilation; it is not a
generated-text-only assertion.

The exact blinded artifact covers 250/250 target functions in 224/224 binaries
with zero adapter or decompilation errors. Its SHA-256 is
`62ddd3ea87bd56e9739a0e90b278af1f40ade09dfd5fbe46f866ff0145070e64`.
The 224 C payloads are byte-identical to the measured pre-commit candidate; only
the package metadata was relabeled to immutable commit `a5149a1`. Blinded
binaries were statically analyzed only and were never executed, emulated, or
made executable.

Against `8aeba47`, 100 of 224 C payloads change. Across the complete holdout,
the number of known calls whose first fixed parameter is explicitly typed moves
`69 -> 642`, while invalid assignments from known void calls move `196 -> 0`
(`free` 125, `exit` 60, `perror` 7, `abort` 3, `_exit` 1). The official fixup
compiler A/B moves coverage `116/250 -> 123/250`: ARM remains `80/84`, host GCC
moves `28/158 -> 35/158`, and MinGW remains `8/8`. Seven functions become
compilable and zero regress. On this metric alone, the checkpoint is now above
the retained angr count (`120/250`) and two functions behind Ghidra (`125/250`).

The same-revision official byte-match A/B moves
`0.06508961626342266 -> 0.07416449761048222`. Eight functions improve, zero
regress, nonzero matches move `76 -> 83`, and perfect matches remain four. Full
GED and type-match were not rerun: their retained values remain substantially
behind Ghidra and angr, so the submission decision is still **do not submit**.

Local gates for this checkpoint are: 1,276/1,276 Rust library tests plus every
integration/example/benchmark target; Clippy exit 0 with the existing warning
backlog; 36/36 focused Python fixture/harness tests; and the full 56-lane
behavioral matrix with the same two pre-existing `cpp_raii_guard` baseline
deltas in functions containing no calls. The owned Python test passes Ruff.
Repository-wide Ruff and `ty` remain red on the pre-existing backlog (3,516 and
1,988 diagnostics respectively) and are not claimed green.

### Previous output checkpoint: `8aeba47`

The prior native slice gave every unresolved indirect call a concrete
call-site prototype instead of the legacy `((long (*)())(...))` escape hatch.
That old spelling is not a prototype in C11 and means zero parameters in C23;
GCC 15 therefore rejected calls with arguments. The replacement derives the
return and parameter spellings from the call destination and recovered value
types, uses `(void)` for a real zero-argument call, and preserves pointer values
at the call boundary. This is the same contract boundary represented explicitly
by Ghidra's `FuncCallSpecs`, angr's `CallSiteMaker`, and Kuna's P4 call/prototype
phase, although Glaurung still lacks their full interprocedural model.

The exact blinded artifact covers 250/250 target functions in 224/224 binaries
with zero adapter or decompilation errors. Its SHA-256 is
`c49ff3ce10fc1645eff759750176604793f1a301acc7d0f9509f03bd52751664`.
The 224 C payloads are byte-identical to the measured candidate package; only
the package version/timestamp metadata was relabeled after commit. A 16-worker
static-only extraction took about 47.8 seconds, versus 58.49 seconds at four
workers for the prior checkpoint. More workers helped only modestly because the
individual analysis processes slowed under contention.

This change removes all 1,795 empty-parameter function-pointer casts from the
holdout output and changes 174 of 224 C files. On one DecBench revision, a
controlled full-package A/B through the official fixup compiler moves compile
coverage `97/250 -> 116/250`: ARM `74/84 -> 80/84`, host GCC `15/158 -> 28/158`,
and MinGW remains `8/8`. The remaining 134 failures classify as 48 named-call
arity failures, 37 pointer/integer type conflicts, 31 invalid void-result uses,
and 18 other or truncated diagnostics. The same-revision official byte-match
A/B moves `0.0497107312 -> 0.0650896163`, with 15 functions improving, zero
regressing, and nonzero matches increasing `62 -> 76`.

Those byte-match values deliberately do **not** replace the retained published
checkpoint below: the local DecBench evaluator has moved, so only their
same-revision delta is comparable. Full GED and type-match were not rerun for
this 174-binary change. Compile coverage is now four functions behind angr and
nine behind Ghidra on this slice, but the prior roughly 2x GED gap and weak type
recovery remain. Submission is still blocked on those semantic gaps, structured
variables/high variables, named-callee prototypes, and the measured
`void`/hidden-sret classification failures.

The real execution-differential fixture matrix remains 459 behavioral passes,
82 failures, and 82 structural-only results, identical to the documented
pre-change checkpoint. Its two differences from the older checked-in baseline
are both `cpp_raii_guard` return-type failures in functions containing no call,
so they are pre-existing typed-return debt rather than an effect of this slice.

### Previous retained score checkpoint: `f02ecb9` (harness `4f80682`)

The previous native slice normalized ARM Thumb ELF entry points and propagated
typed floating-point ABI results into emitted prototypes. Its exact blinded
artifact covers 250/250 target functions in 224/224 binaries with zero adapter
or decompilation errors. Static extraction took 58.49 seconds wall clock; the
slowest binary took 5.046 seconds. Its SHA-256 is
`14d13778324ae5c31fcf70fe7f3a69c1288b162c3cba41630c41fe4cdf7cb5d2`;
it contains 225 files and 1,711,445 uncompressed bytes.

The 23 changed binaries (42 target functions) were rescored with the official
GED and byte-match evaluators, then merged by exact function key into the prior
complete checkpoint. Type match was recomputed across all 235 scoreable
functions. That gives GED `41.3347280335`, byte match `0.0423607691`, compile
coverage `97/250`, and type match `0.1271417040`. This is an exact delta merge,
not a relabeled partial mean. It improves two additional functions to perfect
GED, but keeps compile coverage flat: `uart_wakeup` becomes compilable while the
newly correct floating prototype makes `pidUpdate` stop compiling under the
benchmark harness.

The prior complete checkpoint was rebuilt from Glaurung commit `24b3826`, run
over all 224 blinded binaries (250 target functions), packaged, ingested into a
fresh DecBench tree, and scored from the resulting decompilations. The package
SHA-256 is
`a12f335ea9cb78b59749566cea310e95c614ac6b340863b6ba245b8bd06d6cc8`.
There were no adapter or decompilation errors, so the scores below are coverage
complete rather than a successful subset. The package contains 225 files and
1,717,203 uncompressed bytes.

| blinded gate | Glaurung | angr | Ghidra | decision |
|---|---:|---:|---:|---|
| GED, lower is better | 41.335 | 21.774 | 20.281 | not competitive |
| compile rate | 97/250 (38.8%) | 120/250 (48.0%) | 125/250 (50.0%) | not competitive |
| type match | 0.127 | 0.280 | 0.231 | not competitive |

Against `24b3826`, GED moves `41.5481171548 -> 41.3347280335`, byte match moves
`0.0423053591 -> 0.0423607691`, compile coverage stays `97/250`, and type match
is bit-for-bit unchanged across all 235 scoreable functions. Seven changed
functions move in GED: five improve and two worsen. The small net gain and the
compile trade are evidence that the present bottleneck is the decompiler's
middle architecture, not another isolated rendering rewrite.

The 56 public cells look materially better, but they are not a submission
signal on their own:

| public aggregate | Glaurung | angr | Ghidra |
|---|---:|---:|---:|
| GED, lower is better | 8.116 | 9.926 | 11.426 |
| type match | 0.743 | 0.694 | 0.903 |
| byte match | 0.266 | 0.274 | 0.306 |

That reversal between public and blinded data is a holdout-generalization
failure. The current 56-cell public run also has two byte-match ratchet failures
despite improving the aggregate: `arrays:clang:O0` moves `0.06 -> 0.05` and
`sort:gcc:O2` moves `0.20 -> 0.17`. The worst public failures remain GCC `-O2`
recursion, state-machine, and loop recovery; optimized struct cases can obtain
GED 0 while type match is 0, which exposes the missing object/type model
directly.

### Wall-clock checkpoint

`tools/diff_decompile.py` used to import and invoke Glaurung separately for each
function. Commit `4f80682` batches the exact requested seeds once per isolated
fixture lane while retaining per-function worker isolation for executing the
recompiled result. On the same 56-lane fixture matrix, old and new code produced
identical outcomes (459 behavioral passes, 82 behavioral failures, and 82
structural results), while wall time fell `196.89s -> 34.52s` (**5.70x**) and CPU
time fell by about 17x.

The remaining long pole is scoring, not native extraction. Ingesting the current
blinded package took 114.10 seconds; scoring the 23-binary GED delta took 376.75
seconds and full type match took 107.42 seconds. The public 56-cell matrix took
6:28 with eight isolated workers, 5,078 user CPU seconds, and 1.37 GB peak RSS,
because it launches many Joern/JVM scoring jobs. More decompiler batching will
not remove that external scorer cost; changed-cell selection and retained
checkpoint merges are the safe wall-clock lever.

For the `8aeba47` call-prototype slice, compile-only A/B over both 250-function
packages took 3.8 seconds with 16 workers. Exact byte-match initially wasted a
full serial DWARF pass per package; resolving each binary identity once, using
the manifest directly for the 215 single-function binaries, and walking DWARF
only for the nine multi-function binaries reduced the complete baseline and
candidate A/B to 26.2 seconds. Keep that shared-address-map workflow. Do not run
full GED inside the edit loop; its Joern cost belongs at a stable checkpoint.

Behavioral evidence remains useful and is kept separate from textual scores.
The current fixture run is red: 459 behavioral passes, 82 behavioral failures,
and 82 structural results. Batching preserved every old/new result exactly, but
did not turn those known failures into successes.

The repository-wide release gate is not green. At the current native output
checkpoint, the Rust library suite is 1,271/1,271, the focused float round-trip
fixtures are 4/4, the type suite is 33/33, and the ARM lifter suite is 7/7.
Default library Clippy exits 0 with the existing warning backlog; all-features
Clippy is blocked by the absent external `BITWUZLA_LIB_DIR`. The Python fixture
harness is 32/32. The broad Python suite was not rerun, and the public matrix is
red on the two byte-match cells above. These categories remain independent; a
green focused gate does not make the repository release-ready.

Submission should stay blocked until the typed middle is rebuilt around an
authoritative SSA/value identity, recovered prototypes, type/value facts, and
storage-backed high variables, with those stages iterating to a fixed point
before region structuring. This is also the architecture used by Ghidra at pinned
revision `7a4100d54bff88530f11b577d4d2547d57630288` and made especially explicit by
[Kuna's P0-P9 phase model](https://github.com/Noelo-Lab/kuna/blob/main/docs/phases.md)
at audited revision `5834b3009cbcec3f3bddf1d5cafe50bb03e15474`.
Each slice must preserve the behavioral gates and improve an unseen holdout,
not merely the 56 public cells.

The remainder of this document records the earlier July 25 submission audit.

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

## 1a. Validation state (kept separate on purpose)

Different gates prove different things, and collapsing them into one word is how
"green" starts meaning less than it should. As of `8a6993b`:

| gate | state | what it covers |
|------|-------|----------------|
| `cargo test --lib` | **1024 pass** | Rust core |
| Fixture matrix + structural (local) | **pass**, delta NONE, baselines refreshed | 4 lanes, execution-differential per function; `scripts/decbench-local-gate.sh` |
| Round-trip execution differential | **24 of 26 correct (92%)**, gcc -O0 | does the emitted C actually behave like the original |
| Decompiler Fixture Gate (remote) | **success** at `8a6993b` | the same gate on a clean checkout with a pinned toolchain |
| General CI (remote) | **QUEUED — not green, not red** at `8a6993b` | the light lanes; hosted-runner backlog, so nothing about it is known |
| DecBench 56-cell metric ratchet | **NOT RUN — `DECBENCH_DIR` unset** | per-cell GED / type_match / byte_match regressions |

The last row is the one to read carefully. There is no DecBench checkout in this
environment, so lane 3 of the local gate has been SKIPPED on every run — the script
prints "Skipping is a gap, not a pass" and I read past it for a whole session. Every
"no regressions" statement made during that session therefore covers BEHAVIOUR only.
There is currently no metric evidence at all, and the last measured head-to-head
(GED 10.24 vs angr 9.93, type_match 0.678 vs 0.694, byte_match 0.183 vs 0.274 —
behind on all three) predates every fix described below.

A second, larger caveat about that comparison: angr is the only decompiler we have
ever measured against, and it is the weakest credible baseline in the set. Ghidra is
the production reference. Choosing the comparator that makes the numbers look
survivable is a way of not asking the question.

The earlier fixture-gate failures at `82283b4` and `ddddb8b` were real: the first
because the branch was pushed before the improvements it created were recorded, the
second because of a second hardcoded fixture count, a harness link failure
reported as a compile failure, and the host-dependent `cpp_ctor_dtor` verdict. All
three are fixed at `b8b09ac`.

## 1b. Behavioural correctness — and a figure I had to correct

DecBench scores GED, `type_match`, and `byte_match`. None of them knows whether
the code is right. `structs:dist2` scores a *perfect* graph edit distance of 0.0
while its body reads two locals nothing assigns; `fixedpoint` scored GED 0.0 and
`type_match` 1.0 with none of its three functions returning the right answer. So
the execution differential — recompile our C, run it against the original on the
same inputs — was pointed at the DecBench corpus, and `tools/roundtrip_review.py`
puts source, our C, and the verdict side by side.

The first number that produced was **9 of 25 functions correct (36%)**, against
metrics reading as competitive with angr. That figure was wrong, and wrong in our
disfavour.

The DecBench corpus had no input manifest, so the harness invented the scalar
arguments. `sum_array(const int *a, int n)` was handed a 16-element buffer and
`n = 100`: both binaries read 84 elements past the end, disagreed about the
garbage, and the differential said WRONG — with a *different* wrong value on every
run, which is the signature of reading uninitialised memory, not of a logic error.
`reverse` and `matmul` wrote past the end and segfaulted. `str_len` walked off a
buffer with no NUL and agreed only because both libraries happened to read the same
heap in the same process. The decompiled `sum_array` was, in fact, correct.

Declaring the contracts (`DECBENCH_OVERRIDES` in
`tests/decompiler_fixtures/manifest.py`, plus a `ptr_elem: "cstr"` element kind that
guarantees a NUL and varies the string length) gives the honest number:

**24 of 26 executed functions behave correctly at gcc -O0 (92%)**, measured at
`8a6993b`. The declaration alone took it from 36% to 84% at `0cf6ff6`; the three
lifter fixes and the out-of-SSA translation took it from 84% to 92%.

Both remaining failures are `bsearch_i` and `fsm`, and both are the single Phase B
structuring defect described below — so the behavioural backlog at gcc -O0 is now
one bug, not four. `signs` and `fletcher16` are confirmed correct by execution, which
is what makes the two lifter fixes real rather than plausible.

The four `not checked` are not passes: `list_sum`/`list_find` are `skip_exec` (the
harness cannot construct a linked list), and `dist2`/`rect_area` take a by-value
struct, which stops the harness building a call signature at all. Those are exactly
where the struct bugs are — `dist2` scores a perfect GED of 0.0 while reading two
locals nothing assigns.

Ten of the fourteen "failures" were the harness misusing the function. That is a
measurement bug I introduced by pointing a differential at a corpus without
declaring what its functions accept, and `python/tests/test_decbench_corpus_contracts.py`
now fails closed on it: a corpus function taking a pointer and an integral scalar
must declare `len_args` or `arg_values`, and a `char *` with no length must declare
`cstr`. It found one case I had missed on its first run (`linkedlist:list_find`,
where the scalar is a search value and the pointer is a data structure the harness
cannot build at all — now `skip_exec`).

Both directions of the lesson are worth stating. Metrics that look competitive can
sit on top of code that does not work; and a correctness harness that fails open
reports noise as signal, in this case making the decompiler look 48 points worse
than it was. Neither is discoverable without reading the output.

### The four real failures, and what they were

| function | verdict | root cause | state |
|---|---|---|---|
| `checksum:fletcher16` | wrong answer | `mov $imm32,%eax` sign-extended instead of zero-extended | **fixed** |
| `arith:signs` | wrong answer | `cmovcc` modelled as a conditional def; `neg` defined no flags | **fixed** |
| `sort:bsearch_i` | wrong answer | structurer used a post-dominator outside the enclosing loop as a join | open |
| `statemachine:fsm` | wrong answer | not yet diagnosed | open |

`fletcher16` was one bit. `mov $0x80808081,%eax` zero-extends into `rax`, and we
read the imm32 as `as i32 as i64`, producing 0xffffffff80808081. The two agree in
the low 32 bits, so nothing showed until a 64-bit `imul %rdx,%rax` read the parent.
0x80808081 is the magic reciprocal for division by 255 — so **every `x % 255`
decompiled into different arithmetic**, emitting C that compiled, ran, and returned
the wrong answer. `mod255` is now a one-line regression case.

`signs` was two defects in one function. `Op::CondAssign` treats its destination as
a pure def, so dataflow could not see that the false path keeps the destination's
prior value; the producer had no reader, dead-code elimination removed it, and the
emitted C conditionally assigned a variable nothing else wrote. `cmovcc` now lifts
to `Op::Ite` — the same operation stated honestly, as a three-input select — which
also renders as a two-armed `if` instead of a one-armed one. Separately, `neg`
defined no flags at all, so the following `cmovs` read a stale one from an unrelated
later comparison; the emitted C tested `sf` several statements before anything
assigned it. `neg` now defines SF and ZF from the result **sign-extended at the
operand's width**: the first attempt took the 64-bit temp at face value, which
computes `-(u32)x` in 64 bits, and for `x = -1` gives -4294967295 (SF set) where the
machine gives 1 (SF clear) — so `abs(-1)` came out as 4294967295. CF and OF are
deliberately left undefined rather than guessed, since the conditions that read them
need OF, which is not modelled; an approximate flag turns a visibly missing
definition into a silently wrong branch.

### Where those fixes actually landed: the -O2 lanes

The fixture matrix reports **23 functions moving fail→pass, and 21 of them are at
-O2**:

| lane | fail→pass |
|---|---|
| `01_conditional_polarity` clang:O2 | 7 |
| `01_conditional_polarity` gcc:O2 | 6 |
| `03_loop_shapes` gcc:O2 | 6 |
| `03_loop_shapes` clang:O2 | 2 |
| `01_conditional_polarity` clang:O0 | 2 |

That distribution is the diagnosis. -O2 is where the compiler emits `cmov` instead of
a branch and where values merge without a spill slot to carry them — precisely the
two things `Op::CondAssign` and the missing out-of-SSA translation got wrong. The
functions that moved are named for it: `ternary`, `ternary_nested`, `cmp_signed`,
`cmp_unsigned`, `early_return`, `early_return_ge`, `nested`, `elseif`. The optimised
lanes were not weak for some diffuse reason about optimisation; they were weak because
of three specific defects, none of which was visible in GED, `type_match`, or
`byte_match`.

The two clang:O0 gains (`ternary`, `ternary_nested`) are the same `cmov` fix — clang
emits `cmov` even at -O0 for a ternary.

Nothing regressed in any lane. Both gate failures were the improvement ratchet
demanding a baseline refresh, which is the mechanism working.

### Two structural defects the same corpus exposed

`signs` also needed the missing **out-of-SSA translation**. `compute_ssa` places
phis on the dominance frontier and hands each merged read the phi's result version,
but nothing ever emitted a definition for that result: the merged read named a value
no instruction produced, the arm definitions became dead, and DCE removed them. The
emitted C was an `if/else` with two empty arms returning uninitialised stack. Phi
results are now materialised as copies at the end of each predecessor, and the
`b > a ? b - a : a - b` diamond recovers exactly.

Notably, **the Phase A structural accounting verifier stayed silent on that one, and
was right to** — every block and edge *was* accounted for. The defect was one layer
down, in the dataflow. On `bsearch_i` the same verifier fired precisely:
`EdgeUnaccounted{7→8, Linear}` plus `ImpliedEdgeAbsent{4→8}` and `{5→8}` — the
structurer emitted the function's return block as the join of an `if/else` whose arms
actually branch back to the loop header, so the loop cannot iterate and the trailing
`return -1` lost its `return`. That is the general post-dominator fallback in
`detect_if_shape` accepting a join outside the enclosing loop. It is the first defect
the verifier caught that the metrics scored fine, which is the argument for having
built it diagnostic-first.

`statemachine:fsm` is the same defect, worse: an unconditional `return ret;` at the
bottom of the loop plus the whole switch ladder scattered as gotos after it. So this
one join rule accounts for two of the four remaining failures, and plausibly the
gcc -O0 half of the `statemachine` lane too.

**The obvious fix does not work, and that is worth recording.** Requiring both arms
to reach the join by forward edges only — the `ImpliedEdgeAbsent` finding promoted
from a diagnostic to a precondition — does remove the bad implied edges. But
declining the shape does not produce an honest `goto`: it leaves the whole inner
conditional unstructured, and the accounting goes from 3 findings to 9, including a
*different* pair of absent implied edges (`2→1`, `2→7`) from the enclosing `Seq`. It
also broke a pre-existing switch case
(`structure_accounting::tests::switch_arm_edges_are_attributed_to_the_epilogue_instead_of_the_latch`),
because a switch arm inside a loop legitimately relies on that same fallback. Cost: a
working shape, for no correctness gain. Reverted.

The reason it cannot be patched here is structural. What the shape needs is to be
recognised as an *early return through the shared `-O0` epilogue* — `if (found) {
ret = m; return ret; }` with the sibling arm as the continuation — and the epilogue
block is reached from several places, so it has to be duplicated into each returning
arm rather than owned by one of them. `detect_if_shape` already has a narrow version
of this (`body_is_shared_exit`) that only fires when the arm block *is* the exit. The
general case needs the region model to answer "which blocks does this arm own, and
where does it leave", which is #13 Phase B — interval/SESE analysis — not a fourth
predicate on top of three.

`tests/decompiler_fixtures/src/13_loop_early_exit.c` pins the shape six ways, and
recording its baseline immediately corrected two things I had asserted about it.

I wrote the `break` and `continue` cases as counterexamples that must KEEP working.
They do not work. 19 of the fixture's 24 cells (6 functions x 4 lanes) fail, and the
two "controls" are among them — for two entirely different reasons:

* `sum_until_zero` (`break`) is the same epilogue defect as `bisect`: an
  unconditional `return` at the bottom of the loop and a `goto` to an empty label.
* `sum_positive` (`continue`) is not a structuring problem at all. gcc -O0 emits the
  guard as `test %eax,%eax ; jle`; our `test` lifting defines `Flag::Z` and
  `Flag::S` but **not `Flag::Sle`**, so the `jle` reads the stale `Sle` left by the
  loop's own `cmp`. The emitted C shows it directly — `sle = (local_4 <= arg1)`, the
  loop condition, standing in for the element test. Then the inverted form renders as
  `~sle`, and bitwise NOT of a 0/1 flag is `-1` or `-2`, both true, so the guard can
  never skip and the function sums every element.

Neither of those has anything to do with early exits. The fixture found them by
accident, which is the argument for corpus fixtures over cases written to match a
diagnosis: a case written to prove a theory can only confirm or deny that theory.

It is also the second and third instance of one pattern — an instruction that sets
flags a later branch reads, which our lifter does not define. `neg` defined none at
all; `test` defines three of the four that matter. Two independent discoveries of the
same shape is evidence the gap is systemic, so the flag-setting mnemonics deserve an
audit rather than a third individual fix.

The consequence for Phase B: a green fixture 13 will NOT by itself demonstrate that
region ownership works, because two of its cells fail for unrelated reasons. Check
which cells moved.

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
| gcc/O0 | **5.99** | 7.59 | **0.873** | 0.819 | 0.346 | **0.586** |
| clang/O0 | 6.23 | **3.19** | 0.760 | **0.848** | 0.143 | **0.184** |
| gcc/O2 | **17.18** | 17.51 | 0.404 | **0.543** | 0.205 | **0.291** |
| clang/O2 | 11.56 | **11.40** | **0.652** | 0.534 | **0.038** | 0.036 |
| **overall** | 10.24 | **9.93** | 0.678 | **0.694** | 0.183 | **0.274** |

Movement on 2026-07-26, all measured: **clang/O0 GED 9.79 -> 6.23** from the
rotated-loop fix (that lane was our worst and the fix was aimed at it), overall
**GED 11.16 -> 10.24**, gcc/O0 byte 0.323 -> 0.346 from call arguments finally
appearing. type_match did not move: the call and loop work changes control flow
and operands, not declared types.

Three binaries have no `type_match` on **either** side — `recursion` at gcc/O2 and
clang/O2, `matrix` at clang/O2. DecBench reports "No DWARF ground truth types"
despite `-g` and present `DW_TAG_subprogram` entries. Identical on both sides is
what makes it a ground-truth gap rather than a decompiler one; every other metric
is 56 of 56 for both.

**What this says, without spin.** angr still wins the overall on all three
metrics: GED 10.24 vs 9.93, type 0.678 vs 0.694, byte 0.183 vs 0.274. The first two
are close and the third is not. We win **gcc/O0 on GED and type**, **gcc/O2 on
GED**, and **clang/O2 on type and byte**.

clang/O0 was our worst lane at GED 9.79 against angr's 3.19; the rotated-loop fix
took it to 6.23. It is still the largest single gap, and its worst program is
`statemachine` at 25.0 against angr's 5.0 — which turns out to be a CFG-discovery
failure rather than a structuring one (§4).

So the honest summary is: **competitive at gcc, closing at clang, and well behind
on recompiled-byte similarity everywhere.** byte_match is the one metric where no
work this session moved the overall number at all.

## 4. What a reviewer would find if they looked hard

Stated here so it is not discovered instead.

* **clang -O0 is still our worst lane, GED 6.23 against angr's 3.19** — down from
  9.79, and still the largest single gap. Two defects were found by reading the
  simplest program in that lane, and both are now fixed; the distinction between
  them is worth keeping:
    - a lifter bug (`add eax,-1` read as `+255`, since iced's `immediate32()`
      returns the raw byte for an `Immediate8to32`) — fixed, repaired six fixture
      functions, and moved these metrics by *nothing*: GED measures graph structure
      and a wrong constant is not graph structure.
    - clang emits **rotated** loops (test at the top with a branch out, jump back
      at the bottom) where gcc tests at the bottom. We used the exit test as the
      loop condition and lowered the back-edge as a `goto` past the `return`, so
      `factorial` returned the wrong value for every input. Fixed: 19 fixture
      functions fail->pass and clang/O0 GED 9.79 -> 6.23. This was graph structure,
      which is why it moved the metric.
  `statemachine` is the worst program left in that lane, and it turns out to be a
  DIFFERENT bug from the gcc one — see the next bullet.
* **O2 costs type recovery.** 0.816 at O0 against 0.523 at O2; gcc/O2 type is
  0.404 against angr's 0.543. The width work lifted O2 type_match from the 0.413
  measured on 2026-07-24 but nowhere near the O0 figure: no spill slots to type
  from, and no O2 story in type recovery.
* **Aggregates are not recovered.** `structs` scores type 0.25 and `linkedlist`
  0.5 because struct and array types are not reconstructed; an aggregate
  parameter appears as a pointer to its element type.
* **`statemachine` is two different bugs, and they are on different layers.** Per
  lane, GED ours against angr's: gcc/O0 **36.0 vs 25.0**, clang/O0 **25.0 vs 5.0**,
  gcc/O2 **14.0 vs 34.0**, clang/O2 **20.0 vs 36.0**. We lose both -O0 lanes and win
  both -O2 lanes decisively.
    - **gcc -O0 is a structuring failure.** `detect_if_shape` tries shapes in a fixed
      order and consults a `visited` set to decide what is still available, so which
      pattern runs first decides what later ones can see. Once one ladder arm
      returns, the immediate post-dominator is the FUNCTION EXIT — not a join for a
      region inside a loop — so the loop body ends at the first case and the rest is
      stranded. Two local fixes were attempted and both reverted after measurement:
      guarding the join cost three clang -O2 sparse switches (271 -> 268), and a
      terminating-arm predicate broke a genuine diamond. Each patch fixes one shape
      by breaking another; the answer is a region analysis, not a third predicate.
    - **clang -O0 is a CFG-discovery failure, one layer earlier.** clang emits a real
      jump table (`movslq (%rax,%rcx,4)`, `add`, `jmp *%rax` — 4-byte RELATIVE
      offsets). `discover_jump_tables` does not recognise that form, so the indirect
      jump contributes no successors and the case arms — thirty instructions of state
      machine — never enter the CFG at all; the dispatch renders as an indirect CALL
      through a table entry. The region over the seven blocks that DID make it is
      genuinely faithful. Structuring work cannot fix this lane, and a structural
      verifier cannot see it: it accounts for the region against the CFG, not against
      the program.
* **Call results are recovered now.** `11_call_shapes` was written to measure the
  gap and then measured the fix: 21 functions fail->pass, including `fib`,
  `forward_sum6` and `tailcall_to_sum4`. Calls carry their arguments (nested and
  stack-spilling included), a call's result satisfies a bare `return`, and PLT
  stubs resolve to the function they forward to. What is left in that fixture:
  `fact_mod`, `call_fold_wide_result` and `call_into_spill` still fail at -O0.
* **The fixture gate carries 220 known failures** against 271 passes and 80
  structural. It is a ratchet, not a claim of correctness: it fails on NEW
  regressions while keeping known bugs visible per function per lane, so "green"
  means "no new breakage", not "the decompiler is correct".
* **One function's verdict was host-dependent and is now excluded from execution
  at -O0.** `cpp_ctor_dtor` failed on a developer machine and passed in CI on the
  same commit: it builds a `Tracer` on the stack, and we pass `rbp - 32` as the
  `this` pointer where `rbp` is declared and never assigned, so whether that
  garbage address is mapped decided the result. It is now `skip_exec_lanes` for the
  two -O0 lanes — deterministic everywhere, still executed at -O2 where the
  constructor inlines and it genuinely passes. The defect is recorded, not fixed.
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

## Submission checklist — added 2026-08-04

Written after a 16 % `byte_match` regression reached `master` and survived four
commits because nothing scored the population the leaderboard scores. Every item
below is a gate that has caught something real.

### Before any submission

1. `cargo test --lib` — the Rust logic gate.
2. `tools/fixture_harness.py` — 656 execution-differential cases, x86-64.
3. `tools/arch_roundtrip.py --check` — the same differential for i386, AArch64
   and ARMv7. **The control lane must be 328/328.** If x86-64 is not clean, no
   verdict on any other lane means anything.
4. `pytest -m slow python/tests/test_decompiler_emission_invariants.py` — 52
   cases: self-consistency properties of the emitted unit (disjoint frame
   slots, no unassigned value reaching an observable use, prototypes agreeing
   with their call sites, recovered arity matching source, determinism,
   declared-vs-used, join-defined pointers). These exist because every other
   gate asks what the code *does*, and a regression can live entirely in what
   the code *claims about itself*.
5. `tools/decbench_matrix.py --check` — 56 synthetic fixture cells.
6. **`tools/decbench_holdout.py --check`** — the 250-function holdout, which is
   what the leaderboard actually scores. Lanes 5 and 6 measure different
   populations and have moved in opposite directions; passing 5 is not evidence
   about 6.

Lanes 1-5 are `scripts/decbench-local-gate.sh`; lane 6 joins it under
`GLAURUNG_RUN_HOLDOUT=1` (opt-in only because the cycle is ~30 min).

### Rules learned the hard way

* **A metric reading 0.00 deserves the same suspicion as one reading 1.00.**
  Two of this project's largest quality defects were reported as perfect scores
  by regexes that could not match their own targets.
* **An empty result must announce itself.** `callcheck` scored zero functions on
  an entire tier while printing a well-formed table of dashes.
* **Check the denominator before believing a rate.** A per-binary mean of
  per-function means manufactured a prototype "regression" that was an
  improvement, and made RetDec look worst on strings when it is best.
* **Check the sign before believing an ordering.** `local_<hex>` is a distance
  BELOW the frame pointer, so a larger label is a lower address; sorting by the
  label made correctly-tiled frames look like overlapping ones and produced a
  confident, wrong root cause.
* **Attribute before fixing.** The `byte_match` drop was blamed on the string
  work; scoring three trees showed the string work was 11 improved / 0 worse and
  the loss belonged to earlier commits.
* **`reeval_typematch.py` prints an empty table for a newly ingested column** —
  it only aggregates ids already in `function_results.json`. Use `--emit` and
  read `type_match_new.json`, or you will read "no change" as "no effect".
* **A lifter that is exact about the machine can still be wrong about the
  program.** `bsr`/`bsf` preserved the destination on a zero source, which is
  AMD's behaviour and which Intel explicitly leaves undefined. The self-read
  that modelling required made the destination live-in, and parameter recovery
  promotes a live-in argument-slot register to a parameter — so a
  one-parameter function was emitted with four. Exactness is only worth what it
  costs everything downstream.
* **A pass is only as sound as its weakest oracle.** `collapse_undefined_select_arms`
  was a correct rule (an undefined arm permits any value) resting on
  `count_assignments`, which was written for a narrower job and does not see a
  frame slot's definition. It silently rewrote the signed divide-by-4 rounding
  idiom and broke the control lane. Reusing a helper across purposes needs the
  helper's *completeness*, not just its correctness, re-checked.
* **Widen an invariant to the corpus, not just to the fixture it was written
  for.** Emission invariant #2 forbids exactly the unassigned read the `bsr`
  defect produced, and did not fire: it compiles one fixture, and the defect was
  in another. A property gate that runs on one input is a unit test wearing a
  property's name.

## Measurement defects found on 2026-08-04 — read before citing any figure

Four of the day's most damaging problems were in the *measurement*, not the
decompiler. Each is reproducible; each had already produced a wrong conclusion
before it was found.

### 1. Our holdout tool never scored anything

`tools/decbench_holdout.py:152` invokes `scripts/reeval_bytematch.py` bare. That
script hardcodes `DECOMPILERS = ("angr","ghidra","ida","binja","kuna","r2dec","dewolf")`
and globs `{dec}_*.c`. **No glaurung column is ever in that list**, so it finds
zero tasks and writes `{}`. A three-hour run ended with
`no byte_match rows for column ...`.

Correct invocation — **1.2 s per column**, not hours:

```sh
DECBENCH_REEVAL_DECOMPILERS=<column> \
  /nas4/data/workspace-infosec/decbench/.venv/bin/python \
  scripts/reeval_bytematch.py /tmp/decbench-holdout/tree 16
```

The hours were `decbench evalkit ingest --evaluate`, which **defaults to true**
and runs Joern per binary for GED. Re-pickling all 38 checkpoints takes 0.1 s;
the cost was never the ingest.

### 2. `byte_match`'s cache does not key on compiler version

`ByteMatchMetric._cached_value` keys on the recompiler **name** (`"gcc"`) and
flags, not the version. Score with gcc-15, re-score with gcc-13, and the second
run silently returns the first run's numbers. A measured instance: RetDec on zlib
read 0.1543 cached against a true 0.2960.

**Set `DECBENCH_NO_CACHE=1` for any comparison that varies the compiler.**

### 3. The host compiler dominates the apparent ranking

zlib, 1272 functions, mean byte_match:

| decompiler | gcc-15.2 | gcc-13.4 |
|---|---|---|
| glaurung | 0.3072 | 0.3459 |
| angr | 0.0977 | 0.3369 |
| RetDec | 0.0956 | 0.3105 |

Under gcc-15 we appear to lead by ~3.2x. Under gcc-13 the spread is ~10%. Two
post-GCC-13 tightenings do it: C23 makes `long f();` mean *zero* parameters, so
the fixup's fallback prototype errors; and `-Wint-conversion` became an error in
GCC 14. On diffutils, **83.9% of all compile failures under the default host
compiler are toolchain artifacts, not decompiler defects** — and our own share is
100% artifact (42 gcc-15 failures, 0 failing under both).

Our robustness there is genuine and worth having: we emit real prototypes for
every callee, so the fixup never has to synthesise the K&R form. But it is a
different claim from better decompilation, and the two must not be conflated.

### 4. The harness discards everything above a function's signature

`split_c_functions` (`decbench/decompilers/dockerized.py:156`) cuts each snippet
at the `_FUNC_DEF_RE` match — the signature line. Anything above it is gone
before the compiler sees it. This cost 43 holdout functions when the
stack-protector suppression was emitted as a `#define` preamble: the macro was
correct, was discarded, and left a bare undefined token.

**Rule: everything a function needs must sit at or below its signature line.**
Enforced by emission invariant #9.

A related trap in the same family, three instances in one day: **signature-matching
regexes that cannot skip a leading attribute.** DecBench's splitter, our own
`tools/diff_decompile.py:_FUNCTION_DEFINITION`, and two regexes in the emission
invariants all required an identifier-only prefix, so `__attribute__((...)) int f(`
was invisible where `MACRO int f(` matched.

### 5. DecBench's own repair pass corrupts valid C

`fixup.sanitize_tokens`'s `_ARRAY_RET` rule, meant to repair array-return-type
declarations, rewrites a file-scope array with a trailing attribute:

```c
static unsigned char g[16] __attribute__((aligned(16)));
  ->  static unsigned char g *__attribute__((aligned(16)));   // syntax error
```

Verified directly against the sanitizer. Leading with the attribute passes
through byte-identical. The `^`-anchored regex means the indented, function-local
spelling was never affected.

### 6. Two artefacts that penalise every decompiler equally

* At `-O2`, GCC places `main` in `.text.startup`; `binfmt.object_text_bytes`
  reads `.text`, finds it empty, and returns zero bytes. **`main` scores 0.0 at
  -O2 for every tool**, even when it compiles perfectly. Confirmed on three
  independent samples.
* `object_text_bytes` silently falls back to the ENTIRE `.text` when the
  requested symbol is absent. Harmless in the one-function-per-object path;
  it quietly corrupts any whole-TU measurement without an `nm` presence check.

### 7. RetDec is scored at a fraction of its real recovery

`DockerizedDecompiler._build_result` resolves function names via
`elf_function_symbols()`, which returns **zero symbols on a stripped
executable**. RetDec names functions `function_<lowpc>`. Measured on zlib:
DecBench records **176/1272 (13.8%)** where RetDec actually recovers
**1242/1272 (97.6%)**. Only `.so` files survive, via `.dynsym`. `R2DecDecompiler`
already has the address-keyed lookup that would fix it.

Any published RetDec figure should be treated as unverified until this is ruled
out for the run that produced it.

### The rule that prevents all of this

Every DecBench figure needs three tags: **build**, **metric-version**, and
**population** — and, since 2026-08-04, a fourth: **compiler version**. Two
numbers that differ in any of them are not comparable, however similar their
names.
