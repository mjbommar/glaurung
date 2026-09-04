# WP4 corpus shadow-coverage evidence — 2026-09-04

> **Kind:** record · **Date:** 2026-09-04

## Outcome

`decompile_many(..., shadow_v2=True)` now declines one unsupported function
locally instead of aborting every requested function in the binary. The caller
can compare requested and returned VAs and count the refusal explicitly. Caller
contract errors, such as requesting shadow-v2 with a non-`decbench` style,
remain hard errors.

`tools/structure_v2_compare.py` uses that contract to compare production and
verified shadow output for every function in the current ground-truth
`structure` inventory. It batches each side per binary, runs a bounded number
of binaries concurrently, and emits deterministic JSON containing coverage,
goto counts, output sizes, timings, RSS, and per-function status.

## Complete exploratory census

The first complete run covered all 715 current structure rows across 436
fixture objects:

| status | functions |
|---|---:|
| improved | 180 |
| unchanged | 38 |
| regressed | 29 |
| shadow declined | 468 |
| production missing | 0 |

Thus shadow-v2 returned a comparable candidate for 247/715 rows (34.5%). Of
those candidates, 180 reduced goto count, 38 tied, and 29 increased it.
Comparable goto totals fell from 2,166 to 1,570, but this aggregate does not
override the 29 individual regressions. Comparable rendered size grew from
900,025 to 1,479,556 bytes (64.4%). Summed per-object time was 308.706 seconds
for production and 262.057 seconds for shadow; four workers completed the
comparison in 142.787 seconds with 892,176 KiB maximum RSS.

This is useful rejection evidence, **not promotion evidence**. The shadow
structurer remains opt-in because it has individual goto regressions, declines
65.5% of the target universe, and substantially increases output size. The
largest observed regressions include wide switches, Duff-style control flow,
flattened control flow, and dispatch nested in loops. Those families are the
next focused WP4 inputs.

## Nested-join repair

The first regression investigation found an ownership-order bug. When a
nested conditional's immediate post-dominator was exactly its enclosing stop
boundary, recovery discarded that boundary. The first visited arm then owned
the shared continuation and nested it under itself; siblings reached the
misplaced continuation with artificial gotos. Commit `1e0f41c7` retains the
join as the arms' stop while leaving its single emission to the enclosing
region.

On `07_packet_parser-gcc-O0.so::parse_packet`, the stack-canary/return epilogue
moved from a 20-space-deep branch to function scope and candidate size fell
from 3,572 to 3,492 bytes. Two avoidable transfers to that correctly placed
join remain and are pinned as explicit debt.

A second complete exploratory census measured the generic effect:

- among previously comparable candidates, 57 functions lost gotos, 173 tied,
  and 17 gained gotos;
- their aggregate goto count fell by 100 and output size fell by 122,459 bytes;
- 21 previously declined rows became renderable: 18 improved and 3 regressed;
- overall coverage rose from 247 to 268 candidates, with 217 improved, 10
  unchanged, 41 regressed, and 447 declined.

The apparent increase from 29 to 41 regressed rows is concentrated partly in
one Rust runtime `get_backtrace_style` body repeated across many fixtures, but
it remains a real blocker rather than being erased as duplication. The next
WP4 step is to eliminate or locally refuse those 17 worsened existing
candidates and the three newly renderable regressions, then rerun from a clean
native build.

## Structured-fallthrough repair

The new Rust regression was not an honest goto. Its two added transfers were
the final statements of nested `if` arms and targeted the exact label reached
after their closing braces. Commit `a6a31eb1` adds a conservative AST rule that
removes only that exact lexical fallthrough. It does not carry an outer
destination into loops, switches, or exception regions, and it refuses when an
effect lies between the branch and label.

The focused real outputs now show:

| function | production gotos | shadow before | shadow after |
|---|---:|---:|---:|
| `07_packet_parser-gcc-O0::parse_packet` | 2 | 4 | 2 |
| `166_rust_generics-rustc-O0::get_backtrace_style` | 3 | 5 | 3 |

The complete 715-row exploratory rerun changed no candidate for the worse:

- 41 of the 268 comparable candidates lost gotos and 227 were unchanged;
- aggregate shadow gotos fell by 89 and output size fell by 5,877 bytes;
- 22 regressions became ties and two became improvements;
- the census moved from 217/10/41/447 to **219 improved, 32 unchanged, 17
  regressed, and 447 declined**.

This closes the artificial-fallthrough family exposed by the nested-join
repair. The 17 remaining regression rows are different shapes and remain a
promotion blocker.

## Switch suffix-entry rendering follow-up

Commit `9ab097f1` handles a distinct switch shape without changing CFG
ownership. When a case arm consists only of a `goto` into a labelled suffix
already owned by another arm, the C renderers place that case label at the
existing suffix label and omit only the redundant case-entry `goto`. The
ordinary machine label remains, because branches from within other arms may
still target it. This is the direct C spelling of both entry mechanisms; it
does not duplicate effects or infer fallthrough from case order.

The complete 715-row exploratory comparison changed five rows and no shadow
candidate became worse relative to the preceding report:

- aggregate shadow gotos fell from 1,434 to **1,006** (-428) and rendered bytes
  fell from 1,429,580 to **1,416,752** (-12,828);
- the census moved to **222 improved / 30 unchanged / 16 regressed / 447
  declined / 0 production-missing**;
- clang-O2 `wide154_dense_effects` fell from 220 to 87 gotos in both debug and
  stripped objects, while retaining all 256 cases and passing host C syntax;
- gcc-O0 `wide154_dense_effects` fell from 219 to 63 gotos, changing that row
  from regressed to improved;
- both clang-O0 and gcc-O0 `fallthrough_no_default` rows fell from three gotos
  to zero and changed from unchanged to improved.

The focused synthetic test also retains an ordinary non-case `goto` and its
label when they share the same suffix target. Both wide real-fixture render
tests pass, including deterministic output and host `cc -fsyntax-only`.
The full report took 145.76 seconds with four workers and peaked at 910,120 KiB
RSS. Its JSON is local at
`$HOME/.cache/glaurung/tmp/structure-v2-suffix-full.json`.

## Duff local-region placement follow-up

Commit `e4130d20` uses the verifier's existing single-ownership boundary for
Duff's device. When at least two typed switch arms enter the same verified
multi-entry local region, the adapter embeds that region in one switch arm
instead of appending it after the switch. The local block order is rotated to
the owner's real entry; displaced machine fallthroughs remain explicit gotos,
so the placement does not erase CFG edges or duplicate effects.

The complete 715-row exploratory comparison changed exactly the four Duff
rows and no others:

| object | production | shadow before | shadow after | result after |
|---|---:|---:|---:|---|
| clang O0 | 2 | 10 | 2 | unchanged |
| gcc O0 | 1 | 9 | 1 | unchanged |
| gcc O2 | 4 | 9 | 8 | regressed |
| gcc O2 stripped | 4 | 9 | 8 | regressed |

The corpus census moved to **222 improved / 32 unchanged / 14 regressed / 447
declined / 0 production-missing**. Aggregate comparable shadow gotos fell from
1,006 to **988** (-18). Output grew by 1,545 bytes because the honest local
region is now nested under its switch rather than emitted at function scope.
Both real O0 fixtures have regression tests proving all eight case entries are
labels at their owned blocks, no same-address entry becomes a self-loop, the
tree verifier remains green, and the prepared output passes host C syntax.
The full report took 148.51 seconds with four workers and peaked at 902,704 KiB
RSS; its local JSON is
`$HOME/.cache/glaurung/tmp/structure-v2-duff-full.json`.

## Bounded linear return-tail follow-up

The next cleanup increment generalizes terminal-block duplication to a maximum
four-block straight-line chain ending in return. The eight-instruction per-tail
and 64-instruction per-function ceilings remain unchanged. Provenance now names
the complete cloned block sequence, and the independent verifier rejects a
branch, cycle/repeated block, non-return terminal, forged count, wrong clone
site, or any exceeded bound. Clone sites within a separately owned local-labelled
region are not planned because those exits are definitions, not tree-builder
materialization sites.

The real gcc-O0 `hybrid_switch` is the fixture-backed regression case. Its
verified shadow output fell from four gotos to one, tying production. The
remaining label preserves the real `selector == 4` path (`total = 20`, then the
shared `total += 5`, then return); the other short shared return paths are
rendered directly. Prepared C remains parseable and recovery is deterministic.

The release-mode 715-row exploratory comparison changed ten rows relative to
the preceding Duff report and made no previously comparable candidate worse:

- `hybrid_switch` moved from regressed (4 versus production 1) to unchanged
  (1 versus 1);
- clang-O0 `trie_insert` moved from regressed (8 versus 4) to improved (1
  versus 4);
- `sc_mixed`, clang-O0 Duff, and both `lru_access` copies each lost one goto;
- two `bitset_select` and two optimized `trie_insert` rows changed from local
  decline to verified output.

The census is **230 improved / 30 unchanged / 12 regressed / 443 declined / 0
production-missing**. Comparable shadow gotos are **980**. Because four rows
joined the comparable denominator, aggregate production gotos and bytes cannot
be compared directly with the preceding run. The exact command was:

```bash
uv run maturin develop --release
uv run python tools/structure_v2_compare.py --jobs 4 \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-linear-tails.json"
```

The comparison exited 0 in 21.49 seconds and peaked at 896,840 KiB RSS. This
timing is release-build evidence and is not compared with the preceding
debug/shared-build timing.

## Shared switch-join follow-up

The next recovery increment stops switch arms at their shared immediate
post-dominator, emits that continuation once after the switch, and passes its
block identity to the existing `Region::Switch` lowering boundary. The lowerer
then removes only the trailing jump to that exact join and emits the ordinary C
case `break`. Effects in the join are neither cloned nor moved into an arm.

The rule is loop-scoped. When recovery is already inside a natural loop, the
switch join must be another block in that loop and cannot be the loop header.
This restriction came from a deliberately retained RED case: the first version
made both optimized `flattened_accumulate` objects decline by trying to own the
enclosing loop exit inside the switch. The final version keeps those outputs
renderable and has fixture tests for both the accepted in-loop join and rejected
outer-loop exit.

Nine rows changed relative to the bounded-linear-tail report, with no added
goto or new decline:

- clang-O0 `flattened_accumulate`, `flattened_search`, and
  `flattened_classify` moved from regressed to improved, at 0, 1, and 1 shadow
  gotos respectively;
- clang-O0 `obfuscated_transform` moved from 7 gotos to **0**, versus six in
  production, while retaining the recovered six-way state-machine switch that
  production leaves as an unrecovered indirect jump;
- gcc-O2 `wide154_dense_effects`, debug and stripped, moved from regressed to
  improved (208 to 75 shadow gotos versus 203 in production);
- clang-O2 wide debug and stripped remained regressions but fell from 87 to 54;
- gcc-O0 wide fell from 63 to 22 and remained improved.

The complete census is **236 improved / 30 unchanged / 6 regressed / 443
declined / 0 production-missing**. Comparable shadow gotos fell from **980 to
581**. The release command was:

```bash
uv run maturin develop --release
uv run python tools/structure_v2_compare.py --jobs 4 \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-switch-join-final.json"
```

It exited 0 in 28.17 seconds and peaked at 843,068 KiB RSS. Independent
execution differentials passed all 34 deterministic cases for each of
`flattened_accumulate`, `flattened_search`, `flattened_classify`, and
`obfuscated_transform`. The latter also reported one verified render, zero
undefined uses, and zero dropped verdicts.

## Provenance limitation

The report named committed revision
`54628f5af2d27fa91376e2a79ea22f06e623784f`, which contains the batch-local
decline and measurement tool. However, the native extension was built in the
shared worktree while unrelated, uncommitted CFG, Joern, and metrics changes
were present. Its dirty-source diff hashed to
`889ec323453d8683155e349959b0ba0a195c9efbf9ab48dd41bb1c75d09b0b89` when
recorded. The JSON remains in the local cache and is deliberately not committed
as a pinned benchmark result. Re-run from a clean native build after those
lanes land before accepting timing, output-size, or exact per-function counts
as promotion evidence.

The nested-join follow-up report likewise ran in the shared worktree before
the fix was committed, so its JSON revision field is `9a741786` rather than
`1e0f41c7`. Its before/after deltas are exploratory engineering evidence, not
a replacement for the required clean pinned run.

The structured-fallthrough report records revision `cf575e2e`, the concurrent
C-source improvement that became `master` while the run was active. The WP4
change itself was still uncommitted and the native extension also contained
uncommitted parser/metrics work, so this result has the same exploratory-only
status. A clean build pinned at or after `a6a31eb1` remains required.

The suffix-entry report similarly records `c3877d53` because the measured code
was not committed until `9ab097f1`, and the native extension still shared
uncommitted parser sources. Its exact deltas are useful regression evidence,
but the required promotion run remains a clean native build pinned at or after
`9ab097f1`.

The Duff placement report records `963f8992` because the measured adapter was
committed immediately afterward as `e4130d20`. It also used the shared dirty
native build. Treat its exact four-row delta as exploratory engineering
evidence and retain the clean pinned rerun requirement.

The linear-tail report records `74481815` because this increment was still
uncommitted. Its release extension also contained the concurrent parser lane's
uncommitted Rust sources. The per-row structural deltas and focused real-binary
test are useful engineering evidence, but exact totals remain unpinned until a
clean native build reruns the same command after both lanes land.

The shared-switch-join report records `a81f7f00` because this increment was
still uncommitted, and its release extension likewise contained the concurrent
parser lane. Its no-worse per-row comparison and execution differentials are
valid engineering evidence, but the exact corpus totals remain unpinned.

## Switch-arm loop-exit materialization follow-up

Execution differential exposed a semantic defect that structural verification
could not: in both GCC-O0 and clang-O0 `dispatch_in_loop`, case 3 exits the loop
through a shared return block. `MultiExitLoop` lowering replaced those exit
gotos inside `if` statements, but did not recurse into `Stmt::Switch`. The raw
goto survived, label repair appended its now-unowned destination as an empty
label after the final function return, and that input returned an uninitialized
value.

The lowerer now recursively materializes verified exit paths in every switch
case and its default arm. A real-binary regression covers both O0 compilers and
requires case 3 to contain a return rather than a goto. After a release rebuild,
the ordinary execution comparator, locally directed at shadow-v2 output, passed
all **34 cases** for each binary.

The full 436-object / 715-function comparison then reported **236 improved / 32
unchanged / 4 regressed / 443 declined / 0 production-missing**. Comparable
shadow gotos fell from 581 to **571**. The two O0 dispatch-loop rows moved from
regressed (8 versus 6 production gotos) to unchanged (6 versus 6), and both
clang-O2 `flattened_accumulate` rows fell from 8 to 5 shadow gotos. No row
declined or gained a goto. The run exited 0 in 29.51 seconds and recorded
873,496 KiB peak RSS at:

```text
$HOME/.cache/glaurung/tmp/structure-v2-switch-exit-final.json
```

The report names the preceding committed revision `ead42e38` because this fix
was not committed when measured. The extension also included the concurrent
uncommitted parser lane, so these exact totals remain exploratory rather than
clean promotion evidence.

## Remaining-regression execution audit

The four raw goto regressions are two debug/stripped pairs, not four independent
defects. GCC-O2 `duff_copy` retains eight shadow gotos versus four in production.
The shadow form recovers the indirect dispatch and uses verified suffix entries
into one shared Duff body; production's smaller count accompanies an
`unrecovered indirect jump` placeholder. The shadow output recompiles and
matches the original across all **34 cases**, so this row needs evidence-backed
honest-control-flow classification rather than edge deletion.

For clang-O2 `wide154_dense_effects`, a local experiment recursively converted
switch-arm jumps to the shared post-dominator into C `break`. It reduced each
row from 54 to 32 gotos, exactly removing 22 join transfers, and the focused
structural fixture remained green. The execution differential then crashed the
rebuilt function on vector selector 1. An A/B release rebuild of the committed
form passed all 34 cases, so the experiment was rejected and fully reverted.

The accepted implementation moves this rewrite to the final semantic AST
boundary, after every copy, fallthrough, type, naming, and frame pass. It acts
only when a switch is immediately followed by the target label, descends only
through conditionals inside that switch's arms, and refuses an intervening
effect or a transfer inside a nested loop/switch. Unit tests pin all three
boundaries. The resulting C is equivalent to the independently tested textual
rewrite rather than exposing `Break` to earlier semantic consumers.

After a release rebuild, clang-O2 `wide154_dense_effects` passed all **34
execution cases** and fell from 54 to 32 gotos; gcc-O0 fell from 22 to zero.
The full comparison retained **236 improved / 32 unchanged / 4 regressed / 443
declined / 0 production-missing**, while comparable shadow gotos fell from 571
to **505**. Production output also lost six redundant join gotos. No row gained
a goto, declined, or changed to a worse status. The run exited 0 in 26.92
seconds, peaked at 885,408 KiB RSS, and is archived locally at:

```text
$HOME/.cache/glaurung/tmp/structure-v2-late-switch-breaks-final.json
```

The report names `fa762545` because the final-boundary implementation was still
uncommitted, and the native extension included the concurrent parser lane.
These totals therefore remain exploratory until the required clean pinned run.

## Validation

```text
focused local-decline, invalid-style, and comparison-tool tests
3 passed

ruff check + format check over the three touched Python files
pass

complete comparison command
uv run python tools/structure_v2_compare.py --jobs 4 \
  --output "$HOME/.cache/glaurung/tmp/structure-v2-54628f5a.json"
exit 0
```

The required broad Rust gate was also attempted. It recorded a failure in the
concurrently added `metrics::byte_match` tests and one property test continued
growing past 17 GiB RSS, so the already-failed run was stopped. That result is
neither attributed to WP4 nor reported as a green gate. A clean full Rust gate,
the full Python suite, execution differential, block/edge accounting, and GED
remain required.

After the metrics lane repaired that test, the complete Rust gate was rerun
after `a6a31eb1`:

```text
cargo test --features python-ext
main library: 3,951 passed, 0 failed, 4 ignored
all integration binaries and doc tests: passed
exit 0
```

The required full Python suite was also started. It was stopped at 19% after
32 failures because the gate was already decisively red; continuing could not
certify the increment. The failures were spread across pre-existing/current
master analyst overlays, build-configuration invariants, ARM32 semantics, and
control-flow fixtures. The focused fallthrough and shadow-v2 tests were green,
and the corpus comparison found no candidate made worse by the new pass. The
Python result is nevertheless recorded as a red, incomplete broad gate, not
waived or called green.

No DecBench run or upstream interaction was performed.

For the linear-tail increment, focused and scoped validation additionally
recorded:

```text
cargo test --features python-ext --lib 'ir::'
2,103 passed, 0 failed, 3 ignored

python/tests/test_structure_v2_compare.py
1 passed

shadow-focused tests from python/tests/test_decompiler_render_styles.py
3 passed
```

The complete Rust gate was attempted but could not finish in the shared dirty
tree: `csource::parse::decl::tests::a_convention_inside_a_declarator_names_the_pointer`
continued past three minutes, alongside several older orphaned parser-test
processes consuming CPU. Only the gate process started for this increment was
stopped; the other lane and its files were not modified. The focused Python
group also retained one current fixed-width spelling failure (`int` versus the
test's `int32_t`) and three fitness-ratchet failures caused by broader current
tree growth. None is reported as green or attributed to the return-tail change.

For the shared-switch-join increment:

```text
cargo test --features python-ext structure_v2
34 passed, 0 failed

cargo test --features python-ext --lib 'ir::'
2,105 passed, 0 failed, 3 ignored

python/tests/test_structure_v2_compare.py
1 passed

shadow-focused tests from python/tests/test_decompiler_render_styles.py
3 passed

four real-function shadow execution differentials
4 functions x 34 cases: pass
```
