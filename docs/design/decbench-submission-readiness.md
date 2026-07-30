# DecBench submission readiness

What has to be true before we open a PR against `Noelo-Lab/decbench`, what is
true today, and what we would be asking a reviewer to accept. Written by working
backwards from the submission rather than forwards from the code.

The native DecBench adapter is preserved and pushed to the Glaurung owner's
DecBench fork as `codex/glaurung-external-eval` at `e110ad7`. It is not merged
into `Noelo-Lab/decbench`: there is no upstream PR, issue, or submission.

Last updated: 2026-07-30.

## Current decision: do not submit

### Current output checkpoint: `d6882dc`

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
