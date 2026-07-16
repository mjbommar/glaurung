# Glaurung QF_BV real-query corpus capture (for axeyum GQ1/GQ10)

Reproducible procedure for producing the lifter-shaped QF_BV query pack that
axeyum's `axeyum-bench` (manifest v1) ingests as its client-performance
corpus. The deduplicated corpus and the ordered native profile below are
complementary GQ1/GQ10 artifacts: the former controls cold policy comparisons;
the latter preserves occurrence order and client-boundary costs.

## What it produces

A manifest-v1 corpus (`.smt2` files + `manifest-representative-v1.json`):
distinct, deduplicated, well-typed QF_BV queries that glaurung's symbolic
engine actually issues while analyzing real Windows drivers, with each
query's **trusted verdict** (from the z3 oracle) and a structural `family`.

## Procedure

1. **Build glaurung with the trusted oracle** (z3 gives the authoritative
   verdict recorded in the manifest):
   ```
   cargo build --release --example ioctlance --features solver-z3
   ```

2. **Capture into a new raw directory** (the `GLAURUNG_DUMP_QUERIES` hook in
   `solve()` publishes each DECIDED query as `<sha256>.smt2`, then appends
   `<sha256>\t<verdict>` to `index.tsv`):
   ```
   export GLAURUNG_DUMP_QUERIES=/path/to/new-raw-corpus
   export IOCTLANCE_DEADLINE_SECS=400 IOCTLANCE_SOLVE_BUDGET=1000000 IOCTLANCE_SOLVE_SECS=600
   for drv in win10-vwififlt sqfs-intel-DptfDevGen windows-update-intel-audio-IntcSST; do
     cargo run --release --example ioctlance --features solver-z3 -- \
       samples/binaries/platforms/windows/vendor/realworld/$drv.sys >/dev/null 2>&1
   done
   ```
   Query bytes are published collision-safely before the index observation.
   Separate driver processes may append duplicate observations; the builder
   below reconciles them and fails on any verdict conflict. Never append a new
   experiment to an old raw directory.

   Historical 2026-07-13 capture: 15,687 distinct queries, 1,797 sat / 13,913
   unsat, ~290 MB, sizes 30 B - 220 KB, p50 ~9 KB; 97% contain `extract`,
   89% `concat` -- the width-mixed, extract/concat-heavy target distribution.

3. **Build separate strict capture-index packs.** `build_corpus.py` validates
   every index row, verdict, filename/content SHA-256, UTF-8 query, and complete
   raw-directory inventory before structural classification and deterministic
   representative selection. It emits Axeyum's hash-free capture-index schema;
   there is deliberately no exclusion mechanism. A rejected wide assertion is
   a producer or consumer defect, not a benchmark result.

   ```
   revision=$(git rev-parse HEAD)
   source="Glaurung revision $revision; trusted solver-z3 capture; drivers win10-vwififlt, sqfs-intel-DptfDevGen, windows-update-intel-audio-IntcSST"
   python3 build_corpus.py /path/to/new-raw-corpus /path/to/representative-pack 6 \
     --tier representative --full-out /path/to/full-pack --jobs 8 --source "$source"
   ```

   Both output directories must be absent or empty. `--full-out` emits the two
   independent packs from one complete raw validation pass, avoiding duplicate
   reads of a large access-controlled payload. `--jobs` bounds independent
   hash/UTF-8 validators while preserving hash-sorted output. Files are
   hard-linked when possible and copied only when the filesystem requires it.
   Run the focused fail-closed tests with
   `python3 -m unittest test_build_corpus.py`.

   If a widened full tier exceeds one process's bounded memory, partition the
   already reconciled full pack into deterministic physical process shards:

   ```
   python3 shard_corpus.py /path/to/full-pack /path/to/full-shards --shards 4
   ```

   `shard-set-v1.json` fixes the parent capture-index digest, modulo rule, exact
   disjoint shard sizes, and each child capture-index digest. Every child still
   passes through Axeyum's independent manifest generator; sharding never
   changes a verdict or treats a partial run as full coverage. Test it with
   `python3 -m unittest test_shard_corpus.py`.

4. **Generate byte-owning manifests and validate ingestion** in Axeyum. This
   second step makes Axeyum, rather than the untrusted producer, hash the exact
   bytes it will benchmark:

   ```
   cd ~/projects/personal/axeyum
   just generate-glaurung-manifest \
     /path/to/representative-pack \
     /path/to/representative-pack/capture-index-v1.json \
     /path/to/representative-pack/manifest-v1.json
   just generate-glaurung-manifest \
     /path/to/full-pack \
     /path/to/full-pack/capture-index-v1.json \
     /path/to/full-pack/manifest-v1.json

   cargo run --release -p axeyum-bench --features z3 -- \
     /path/to/representative-pack \
     --corpus-manifest /path/to/representative-pack/manifest-v1.json \
     --corpus-tier representative --backend sat-bv --compare-z3
   ```

## Historical result (2026-07-13, representative tier, 128 queries)

- **100% decided, 0 unsupported, 0 disagreements** (`manifest_agree=128`) --
  passes axeyum's full acceptance gate (exit 0).
- **Axeyum/Z3 ratio: 2.10x** (axeyum 272 ms, z3 130 ms) -- confirms the
  1.7-3.2x real-workload gap, measured through axeyum's own harness.
- **Cold-path attribution: bit_blast 42% + cnf_encode 42% = 84%, SAT 15%,
  model_lift 1%** (`sat_dominates: false`). The gap is in term->AIG->CNF
  lowering, NOT SAT search -- ranking axeyum's roadmap toward GQ3
  (coercion peepholes) / GQ4 (bit-slice) / GQ5 (AIG->CNF), deprioritizing
  GQ6 (SAT tuning).

## Hand-off

The historical representative pack is placed (uncommitted) at
`~/projects/personal/axeyum/corpus/glaurung-qfbv/` ready to ingest. The
full ~290 MB tier is regenerable via steps 1-3 (too large to commit; keep
access-controlled). New packs use the strict capture-index → Axeyum manifest
boundary above; `family`/`tiers`/`content_hash`/`expected` then conform to
`docs/user-guide/corpus-manifests.md`.

## Ordered native Axeyum profile

Build both backends so Z3 remains the authoritative exploration/model-choice
path while Axeyum receives the exact same query stream. On hosts where
`z3-sys` bindgen cannot find GCC's `stdbool.h`, include the GCC header path as
shown:

```sh
export BINDGEN_EXTRA_CLANG_ARGS=-I/usr/lib/gcc/x86_64-linux-gnu/15/include
cargo build --release --example ioctlance --features solver-z3,solver-axeyum

profile_dir=$(mktemp -d /tmp/glaurung-axeyum-profile.XXXXXX)
GLAURUNG_SHADOW_DIFF=1 \
GLAURUNG_AXEYUM_PROFILE_DIR="$profile_dir" \
IOCTLANCE_DEADLINE_SECS=400 \
IOCTLANCE_SOLVE_BUDGET=1000000 \
IOCTLANCE_SOLVE_SECS=600 \
target/release/examples/ioctlance \
  samples/binaries/platforms/windows/vendor/realworld/win10-vwififlt.sys
```

`GLAURUNG_AXEYUM_PROFILE_DIR` must be set before the process's first native
check. Without warm reuse it preserves the raw one-shot policy and writes the
`glaurung-axeyum-native-profile-v1` schema. With snapshot or lineage reuse it
selects Axeyum's profiling constructor and writes
`glaurung-axeyum-warm-profile-v7` (v1 through v6 remain accepted historical inputs).
Both use one
`axeyum-profile-<pid>.jsonl` file per process. Every record carries the SHA-256
of the exact bytes produced by the existing SMT-LIB capture renderer, a
monotone process-local sequence, outcome/completeness, phase durations, and
AIG/CNF sizes. Warm records additionally carry path ownership/creation,
prefix/add/pop root traffic, session creation, structural deltas, exact
incremental CNF gate/root-family deltas, and explicit unattributed time. Query
rendering/hash and JSON output are diagnostic overhead and are deliberately
outside `total_nanos`.

V4 adds two exact per-check maps for the next GQ5 attribution boundary. The
five `aig_construction` counters partition every primitive AND request into a
trivial simplification, absorption/consensus simplification, unique-table hit,
or newly allocated AND node. The eleven `lowering_work` counters expose term
memo lookup/reuse, newly retained terms, operand/root literal-vector copies,
term-bit lift-map writes, and symbol-input allocation. Together with
`bit_blast_nanos` and `aig_nodes_added`, these support cost-per-added-node and
work-per-added-node analysis without placing a wall-clock read inside every
AIG operation. The maps are diagnostic only and do not select a lowering or
solving policy.

V5 adds the exact per-check `replay_sat_cache` boundary selected by ADR-0192.
It records enablement and fixed per-path bounds, counter deltas for the one
check, and the owning solver's current entry/value/bit gauges. An enabled
complete record partitions into exactly one hit, miss, or replay failure; a
miss further partitions into insertion or one declined-result class. These
counters explain work avoided by exact duplicate reuse without conflating it
with prefix/delta lowering. Axeyum's summarizer rejects incomplete fields,
policy drift, invalid partitions, and gauges beyond their independent bounds.

V6 adds ADR-0194's exact per-check `model_lift_work` map. Three nested timers
separate retained-AIG forward recomputation, AIG validation/symbol-assignment
reconstruction, and complete public-model construction. Five counters record
recomputed AIG nodes, scanned symbol-bit inputs, reconstructed symbols, scanned
arena symbols, and completed model values. The summarizer requires the exact
field set, rejects nested time beyond `model_lift_nanos`, and validates the
symbol/node count bounds. These diagnostics select no model policy and do not
authorize skipping validation, completion, or original replay.

V7 adds Axeyum ADR-0202's entry contract for first-class direct deltas. Every
record names `entry_mode` as `snapshot` or `direct_delta` and partitions the
complete query into persistent assertions and temporary assumptions. Separate
counters report persistent and temporary roots translated in this check and
persistent versus temporary root encodings. Snapshot mode must translate the
complete persistent set and has zero temporary work. Direct mode must translate
exactly the newly added persistent roots plus every temporary assumption;
temporary root encoding may be zero on a replay-cache hit, but can never exceed
the translated assumptions. The strict summarizer rejects invalid query/root
partitions and reports entry-mode plus entry-structure totals, while retaining
v1--v6 as historical formats.

Two producer smokes establish the boundary before real-driver measurement. The
four-check direct sequence validates with three SAT, one UNSAT, one owner,
two persistent roots translated/encoded, one temporary root
translated/encoded, one pop, and one exact cache hit. The six-check snapshot
sequence validates with four SAT, two UNSAT, twelve complete persistent roots
translated, six persistent roots encoded, and zero temporary work. These debug
smokes prove schema/counter consistency, not performance.

The first v6 SurfacePen lineage run decides and agrees on all 2,551 checks
(2,282 SAT / 269 UNSAT), with zero unknown splits or replay failures. Of
175.049 ms in model lift, complete-model construction consumes 165.192 ms
(94.37%), assignment reconstruction/validation 7.146 ms (4.08%), and retained-
AIG recomputation 2.427 ms (1.39%). Exactly 5,066 reconstructed symbols become
5,066 completed values. This rejects duplicate AIG traversal as the next lever
and selects a causal test of Axeyum's empty warm-theory projection discovery on
scalar QF_BV. That test must preserve complete user-symbol defaults and replay
of every original root.

ADR-0195 accepts that exact empty-theory gate. On the identical v6 stream,
model completion falls 165.192 to 1.088 ms (-99.34%), total model lift falls
175.049 to 10.379 ms (-94.07%), and profiled internal total falls 20.52%, with
identical outcomes, models, AIG/CNF structure, path/cache traffic, and replay.
The same-current unprofiled three-process gate improves median Axeyum time
636.6 to 474.6 ms (-25.45%) and the ratio from about 0.147x to 0.108x Z3;
median RSS falls 0.06% and Z3 drift is +1.19%. All 15,306 combined checks agree.
Every non-empty array/UF projection class still takes the unchanged complete
projection path.

The held-out three-process NETwtw10 comparison also passes: median Axeyum time
falls 17,765.2 to 16,996.6 ms (-4.33%), normalized ratio about 0.342x to 0.328x
Z3 (-3.99%), and median RSS 261,428 to 257,796 KiB (-1.39%); Z3 drift is
-0.36%. All 170,136 combined checks agree, findings and exact warm/cache
traffic repeat, and replay failures remain zero. These causal repetitions do
not substitute for the production-policy gate.

The production-policy refresh is now committed as
`lineage-adaptive-model-completion-baseline-v1.json` (SHA-256
`21b9522725650ab4ffe47347d97b310d861a6fa92779ec6b82377bea6c1f7c07`) and
`lineage-adaptive-model-completion-candidate-v1.json` (SHA-256
`9ac47b7c77d8ebf60672eed12432e26081adbdb0af6495f994a654ec308f015d`).
Both use the same clean Glaurung revision, adaptive/cache-on policy, driver
bytes, system identity, and three repetitions. The guarded comparison keeps
all 185,442 checks, findings, warm/cache traffic, and cleanup exact. SurfacePen
mean Axeyum time/ratio improve 23.82%/24.99%; NETwtw10 improve 3.55%/4.04%.
Median RSS changes +1.13%/+0.97%, and absolute Z3 drift is 1.56%/0.52%; every
3% Axeyum, 3% ratio, 5% RSS, and 2% Z3 alarm passes.

The first v5 SurfacePen profile changes the residual priority: replay is
447.046 ms / 38.82% of internal time because the incremental solver formerly
created a new ground-evaluator memo for every original root. Axeyum ADR-0193
and commit `d3d95299` share only same-assignment values within one replay and
clear accumulated cross-root values at a fixed 4,096-entry threshold. On the
identical 2,551-check profile, replay falls 87.78% to 54.643 ms and attributed
total falls 33.51%, with every decision, cache counter, structure, and replay
gate unchanged. A same-current-client causal three-process gate improves
SurfacePen Axeyum 1,070.267 to 674.933 ms (-36.94%) and median RSS 78,888 to
77,976 KiB (-1.16%). The clean-Axeyum two-driver candidate keeps all 92,721
checks agreed and measures NETwtw10 at 17.328 seconds / 0.333x Z3. Do not use
it to overwrite the committed artifact yet: the older SurfacePen baseline has
an unrelated/stale RSS control that fails by 6.52%, so a clean same-current
two-driver baseline/candidate pair remains required.

ADR-0175 accepts the first v4-selected AIG change at Axeyum `6779db6a`.
On Dptf, 39.61% of primitive AND requests reach the old ordered unique table
and 88.77% of those probes insert. A deterministic 70%-load open-addressed
table preserves every outcome, AIG/CNF total, gate-family counter, and
lowering-work counter; profiled Dptf bit blast falls 40.989 to 26.196 ms
(-36.09%). Three order-balanced unprofiled pairs on each established driver
decide and agree 20,958/20,958 checks per policy with identical path/root
traffic and no fallbacks or resets. The weighted three-driver Axeyum round
falls 5.487 to 5.067 seconds (-7.66%), and the same-stream actual-client ratio
improves 0.742x to 0.680x; per-driver median RSS changes -1.27%, -2.62%, and
+0.41%. The accepted-table v4 profile validates all 6,986 records and moves
bit blast to 18.21%, behind CNF at 46.55% and SAT at 18.48%. Profiled timing
remains diagnostic; the repeated unprofiled result is the performance claim.

`GLAURUNG_AXEYUM_INTERNAL_AND_FLATTENING=1` enables ADR-0173's bounded,
off-by-default positive internal AND-tree half-flattening candidate. V3 adds
exact eligible nodes, applied halves, and immediate primitive clauses avoided;
run controls without the variable and candidates with it in separate
processes. This option changes the CNF policy and is not implied by profiling.

The first Dptf gate rejects the candidate. The control observes 3,642 bounded
opportunities spanning 106,850 fresh nodes. Enabling the policy applies 2,597
flattenings over 86,141 nodes and avoids 83,544 primitive clauses immediately,
but later helper reuse emits ordinary definitions anyway: cumulative added
clauses rise 429,432 to 505,090 (+17.62%) and profiled CNF time rises 119.8 to
129.6 ms (+8.19%). Three alternating unprofiled runs remain 561/561 agreed
with identical path/root traffic, but Axeyum mean rises 239.5 to 248.3 ms
(+3.65%). Keep the option off. The next admissible design needs retained
future-use evidence or a rollback/replacement mechanism; current-use freshness
and immediate clause reduction are insufficient in a growing AIG.

Profiled timing is attribution-only and must not replace an unprofiled
performance gate. Phase clocks and per-check JSON output add observable cost.
Run profiles separately, require the record count to equal the shadow-query
count, and require 100% decisions. A homogeneous warm control must have zero
cap fallbacks so it does not mix warm and one-shot schemas. From the Axeyum
checkout:

```sh
python3 scripts/summarize-glaurung-warm-profile.py \
  "$profile_dir"/axeyum-profile-*.jsonl \
  --require-records 561 \
  --require-100-percent-decided
```

The accepted adaptive production policy deliberately writes native one-shot
records for bounded path-cap fallbacks into the same occurrence-ordered file.
Do not split or delete them. ADR-0197's separate mixed summarizer delegates
each record to the current warm-v7 or native-v1 validator, validates the
global process/sequence order, and keeps retained, created-owner, and fallback
costs separate:

```sh
python3 scripts/summarize-glaurung-adaptive-profile.py \
  "$profile_dir"/axeyum-profile-*.jsonl \
  --require-records 2551 \
  --require-native-fallbacks 16 \
  --require-100-percent-decided \
  --out "$profile_dir/adaptive-summary.json"
```

The first post-ADR-0196 SurfacePen default profile validates 2,535 warm plus
16 native fallback records and 100% decisions. Its 509.677 ms internal total
is SAT 28.01%, CNF 21.39%, translation 14.77%, bit blast 14.31%, replay 11.19%,
unattributed 8.11%, and setup 0.16%. Fallbacks are 0.63% of checks but 6.02% of
time. The 207 created warm owners consume 78.4% of warm bit blast and 70.7% of
warm CNF; retained owners consume 94.7% of warm SAT. This is diagnostic
attribution, not a replacement for the repeated unprofiled ADR-0196 gate.

ADR-0198 tests the obvious admission response without adding a new policy knob.
On SurfacePen the fixed-lineage ceiling peaks at exactly three live owners, so
it has the same observed admission behavior as an adaptive initial cap of
three: zero fallbacks, 207 created/closed owners, and zero terminal state.
Three order-balanced runs improve mean Axeyum time 436.733→412.733 ms (-5.50%)
and ratio 6.30%, but median RSS rises 78,708→84,736 KiB (+7.66%) and fails the
5% alarm. The adaptive initial cap remains two. Do not spend a held-out gate or
new configuration surface on this rejected candidate; fresh-sibling/fallback
reuse must avoid retaining or sharing a third mutable solver.

The first clean three-driver lineage profile at Glaurung `49f1fe2` plus the
profiling worktree records exactly 6,986/6,986 decided checks, 5,102 unique
query hashes, 2,103 created path sessions, 88,476 added roots, 8,758,247 new
AIG nodes, and 11,734,335 new CNF clauses. Weighted internal phase shares are
CNF encoding 43.78%, bit blast 22.86%, SAT 17.45%, replay 5.79%, translation
3.74%, model lift 3.41%, unattributed adapter work 2.70%, session creation
0.21%, and model extraction 0.04%. The profile totals 7.106 seconds internally;
the same profiled processes measure 9.441 seconds at the client timer because
rendering and JSON output are intentionally excluded. Compare performance only
to the repeated unprofiled 5.537-second lineage median.

The v2 rerun preserves all 6,986 decisions and exact structural totals while
partitioning the 11,734,335 added clauses. Definitions account for 8,419,041
(71.75%) and guarded roots for 3,313,208 (28.24%); constants account for the
remaining 2,086. Of 5,697,696 emitted implication halves, 3,070,411 (53.89%)
are AND-tree shaped, 1,452,816 (25.50%) are inverted-AND shaped, 705,066
(12.37%) are XOR shaped, and 469,403 (8.24%) are primitive binary ANDs. Every
measured positive-root opportunity already takes the existing fusion path;
the duplicate and tautology counters remain zero. This rejects another
root-dedup or broad root-fusion tranche and selects internal positive AND-tree
half flattening for the next bounded experiment. It is not yet a performance
claim: profile clocks and clause-index diagnostics remain enabled.

Validate and summarize from the Axeyum checkout:

```sh
python3 scripts/summarize-glaurung-native-profile.py \
  "$profile_dir"/axeyum-profile-*.jsonl \
  --manifest /path/to/pack/manifest-v1.json \
  --require-100-percent-decided \
  --out "$profile_dir/summary.json"
```

The summarizer fails closed on schema/order/completeness/count/policy drift and
on any overlapping manifest verdict conflict. Keep every JSONL occurrence:
deduplication would destroy the exact-repeat frequency and first-use/order
evidence needed by warm GQ7/GQ8 work. Run the same shadow command without
`GLAURUNG_AXEYUM_PROFILE_DIR` for an ordinary-wrapper timing control; do not
compare an Axeyum-authoritative run because different SAT models can change
Glaurung's exploration and query stream.

## Native warm policies (ADR-0164 / ADR-0170 / ADR-010)

For an Axeyum explorer solve with explicit path ownership, an unset
`GLAURUNG_AXEYUM_WARM_REUSE` selects the accepted pressure-adaptive policy:
start with two live sessions and expand once to the hard cap nine at 128
low-cap pressure events. Set the variable to `off`, `false`, or `0` for
one-shot behavior. Calls outside explorer path ownership always remain
one-shot. This is downstream Glaurung scheduling; it does not change Axeyum's
framework-level solver defaults.

Glaurung commits `016935d` and `b09ec6b` add the first real warm GQ7 bridge.
The public `Solver` trait still submits complete assertion snapshots, but
`GLAURUNG_AXEYUM_WARM_REUSE=1` (equivalently `snapshot`) sends those snapshots through one retained
Axeyum arena/solver per explorer thread. The adapter translates structurally,
keeps the longest common assertion-root prefix active, pops the divergent
suffix, and asserts only the new suffix. It does not compare raw `ExprId`s
across cloned path pools, where sibling IDs may collide.

`GLAURUNG_AXEYUM_WARM_REUSE=lineage` selects the explicit path-owned control.
The explorer assigns an internal logical owner to every root and fork. Each
worker lazily creates one independent arena/solver for a path's first check,
then retains that path's assertion prefix and asserts only later deltas. Sibling
paths never share mutable SAT state; their common roots are replayed into
separate solvers. Terminal paths release their sessions, and stateful restarts
receive a fresh owner. A solve outside the explorer's explicit path context
falls back to one-shot rather than guessing ownership.

ADR-0196's accepted fork-topology policy defaults
`GLAURUNG_AXEYUM_WARM_OWNER_TRANSFER` to `on`; set it to `off`, `false`, or `0`
for the prior fresh-owner control. At a symbolic fork, only the last-pushed successor —
the one the DFS worklist executes next — inherits the terminal parent's
retained solver owner. The earlier sibling receives a fresh owner, so mutable
SAT/scopes/cache state is never shared. The parent swaps to an unused fresh ID,
allowing ordinary terminal cleanup without closing the transferred solver.
Invalid values fail closed to off, and non-Axeyum builds retain fresh owners for
both children.

The first ownership-only v1 transferred to the earlier child and failed: that
session sat dormant behind the sibling subtree, drove adaptive pressure, put
SurfacePen above its RSS alarm, and regressed NETwtw10 Axeyum time about 9.4%.
The LIFO-aligned v2 calibration reverses the mechanism. SurfacePen fallbacks
drop 87→16 and Axeyum measures 446.0 ms / 77,580 KiB; NETwtw10 fallbacks drop
7,976→2,536 and Axeyum measures 11,020.0 ms / 259,044 KiB. All 30,907 combined
calibration checks agree and replay failures are zero.

The clean repeated acceptance artifact is
`lineage-adaptive-owner-transfer-v1.json` (SHA-256
`7478f60827e2cedbabb2bbe2c8ba07ae7d3b024f5676b61728c5dfc98a137de2`).
Against the committed adaptive/cache-on off control, all 185,442 checks,
findings, exact transfer traffic, cache partitions, and terminal cleanup pass.
SurfacePen mean Axeyum time/ratio improve 14.71%/15.04% with +0.76% median RSS
and +0.39% Z3 drift. NETwtw10 improves 34.77%/34.36%, RSS falls 0.36%, and Z3
drift is -0.62%. Every alarm passes, so LIFO transfer is the downstream default
with explicit off retained. The lineage gate exposes `--warm-owner-transfer`
and a named comparison flag for future family revalidation.

ADR-0199's accepted continuation policy defaults
`GLAURUNG_AXEYUM_WARM_SERIAL_SIBLING_REUSE` to `on` under adaptive warm reuse;
set it to `off`, `false`, or `0` for ADR-0196's exclusive next-child control.
Invalid values fail closed to off. Because Glaurung's DFS worklist executes one
state at a time, sibling
continuations may serially lease one logical owner while the existing snapshot
adapter restores each complete assertion vector through exact LCP/pop/push.
Reference counting prevents parent or infeasible-child cleanup from closing a
session while a queued sibling remains. No solver executes concurrently, every
check and original replay still runs, and `[axeyum-serial-owner]` must finish
with zero tracked owners/references.

The first SurfacePen smoke is 2,551/2,551 agreed with zero replay failures,
43 created/closed sessions, peak one live session, 165 share events, peak 11
logical references, and zero terminal session/cache/reference gauges. Axeyum
measures 369.6 ms at 74,288 KiB RSS. The diagnostic profile attributes the
mechanism against the no-fallback ADR-0196 lineage control: created sessions
fall 79.2%, AIG nodes 88.0%, clauses 77.0%, bit blast 82.4%, CNF 66.8%, and
internal total 15.2%. SAT rises 36.2% in the larger retained database and is
47.2% of candidate time.

The clean repeated acceptance artifact is
`lineage-adaptive-serial-sibling-v1.json` (SHA-256
`3218a1cd6ac4119647b3b4572b909bc3fd868077282cf0802dfede4f9161a362`).
Against ADR-0196's adaptive/cache-on transfer control, all 185,442 checks,
findings, exact warm/cache/lease traffic, and terminal cleanup pass with zero
replay failures. SurfacePen mean Axeyum time/ratio improve 17.08%/18.53% and
median RSS falls 6.11%, with +1.79% Z3 drift. NETwtw10 improves 0.72%/0.35%
while RSS falls 13.36%, with -0.37% Z3 drift. Every alarm passes, so serial
sibling leasing is the adaptive downstream default with explicit off retained.
The lineage gate exposes `--serial-sibling-reuse` and
`--allow-serial-sibling-reuse-enablement` for future family revalidation.

`GLAURUNG_AXEYUM_WARM_REUSE=auto` is GQ9's retained low-memory
detected-reuse control.
The first check on a path stays one-shot and retains only the explorer-owned
path ID. A second check on that same live path initializes the existing bounded
lineage solver from the current complete snapshot; subsequent checks reuse
prefixes/deltas normally. Terminal paths remove unpromoted IDs as well as warm
sessions. `[axeyum-auto] probes=... activations=...` separates first-check
probes from promoted sessions. This candidate is not a default or performance
claim; measure it against fixed off and `lineage` on exact-work streams.

The first single-process calibration keeps exact findings and 100% agreement.
On SurfacePen, off/auto/lineage Axeyum time is 1.995/1.154/1.062 seconds and RSS
is 64,228/65,136/82,480 KiB; auto probes 358 paths and promotes 191. On
fixed-budget NETwtw10, auto partitions all 28,356 checks into 10,687 first-path
probes plus 17,669 warm checks, promotes 4,099 paths, and measures 19.595
seconds / 216,016 KiB versus the clean lineage baseline's 18.751 seconds /
257,632 KiB. These are calibration runs, not repeated acceptance evidence.
Extend the versioned runner with auto-policy identity and repeat both families
before changing the default.

That repeat is now committed as `lineage-auto-candidate-v1.json` (SHA-256
`bcc6b5cfce173af23b6ad81b9b412cd96dedc002af94b03a4500f53379c04fdf`).
All 92,721 checks agree and every probe/warm/lifecycle counter repeats exactly.
SurfacePen auto is 1.141 seconds / 65,404 KiB; NETwtw10 auto is 19.554 seconds /
216,580 KiB. Relative to the clean lineage baseline, Axeyum time is
7.37%/4.28% higher and median RSS is 20.66%/15.93% lower. The time regression
fails the existing 3% alarm on both families. Z3 drift is -2.21%/+2.63%, also
outside its 2% environment guard, so do not interpret the cross-run normalized
ratio as causal. Auto remains an explicit memory-optimized option; it is not
the default. Only the exact atomic JSON is committed; process logs remain
local.

Run the same Z3-authoritative shadow stream with warm reuse enabled:

```sh
GLAURUNG_SHADOW_DIFF=1 \
GLAURUNG_AXEYUM_WARM_REUSE=1 \
IOCTLANCE_DEADLINE_SECS=400 \
IOCTLANCE_SOLVE_BUDGET=1000000 \
IOCTLANCE_SOLVE_SECS=600 \
target/release/examples/ioctlance \
  samples/binaries/platforms/windows/vendor/realworld/win10-vwififlt.sys
```

The footer adds `[axeyum-warm]` counters for checks, consecutive exact
snapshots, retained prefix roots, added roots, popped roots, and error resets.
Lineage mode also reports created, closed, current-live, and peak-live path
sessions. These counters describe solver ownership and root traffic; process
RSS remains the memory acceptance measurement.

Axeyum's GQ8 replay-checked SAT cache is enabled by default only inside a
path-owned `lineage`, `auto`, or `adaptive` warm policy. Set
`GLAURUNG_AXEYUM_REPLAY_SAT_CACHE=off` for the fixed control. Each retained path
solver then owns an independent same-arena cache bounded to 64 exact entries,
4,096 scalar model values, and 262,144 Bool/BV payload bits. Snapshot mode and
all one-shot fallbacks remain cache-free; exact entries never cross paths,
arenas, threads, or processes. Only SAT models are retained, every hit still
passes Axeyum's original-term replay, and UNSAT, unknown, oversized, or
non-scalar results are counted but not cached. Unset selects the accepted
bounded policy; `off`, `false`, `0`, and unrecognized values select the
conservative disabled override.

The `[axeyum-sat-cache]` footer records the selected per-path bounds, exact
hits/misses, insertions, deterministic evictions, replay failures, each
declined-result class, and current entry/value/bit gauges. Terminal path
cleanup must leave all three gauges at zero. The lineage gate accepts an
explicit `--replay-sat-cache off|on` control, requires exact cache traffic to
repeat, partitions every retained warm check into a hit or miss, requires zero
replay failures, and preserves the existing verdict, unknown-split, finding,
RSS, and timing gates. Compare a newly captured off/on pair only with the named
transition:

```sh
python3 docs/axeyum-integration/capture/lineage_gate.py compare \
  /path/to/cache-off/lineage-gate-v1.json \
  /path/to/cache-on/lineage-gate-v1.json \
  --allow-replay-sat-cache-enablement
```

The clean repeated adaptive-policy gate at Glaurung `d5475f6` and Axeyum
`2b6e264c` executes 92,721 checks per cache policy with identical work and
findings. Cache-on improves Axeyum time 1.16% on SurfacePen and 2.38% on
NETwtw10, normalized ratio 0.67%/2.08%, and median RSS 6.88%/1.52%; absolute Z3
drift stays below 0.50%. SurfacePen records 154 exact replay-checked hits and
NETwtw10 2,464, repeated exactly in all three processes, with zero replay
failures and zero terminal gauges. Every ordinary 3%/3%/5% plus 2% alarm
passes, admitting the bounded path-owned default. Prefix extensions continue
to reuse retained AIG/CNF/SAT state through GQ7 and are never treated as
verdict-cache hits.

The exact clean controls are committed as
`lineage-adaptive-cache-off-v1.json` (SHA-256
`95eefcb669f4f1a4c22109fcef8a40c6d0fb50476747627c1f43f132b6a8f132`)
and `lineage-adaptive-cache-on-v1.json` (SHA-256
`9c010538b579d36e20fdc02a92af8e6f02ea43887354ca55397256a19eba74e3`).
Only the compact atomic artifacts are committed; child logs remain local.

Lineage mode can also enforce explicit resource ceilings. Set
`GLAURUNG_AXEYUM_WARM_MAX_LIVE_PATHS` for a process-wide retained-session cap
and `GLAURUNG_AXEYUM_WARM_MAX_ASSERTIONS_PER_PATH` for a per-snapshot root cap.
When either limit would be exceeded, that check runs through the ordinary
one-shot Axeyum path; an over-limit retained path is closed before the one-shot
check. Invalid limit values fail closed as zero. The footer exposes
`path-cap-fallbacks`, `assertion-cap-fallbacks`, `max-live-paths`, and
`max-assertions-per-path`. Lineage remains opt-in, but its unset limits now
select the measured bounded defaults of 9 retained paths and 512 assertions per
path. Explicit decimal values override either limit; `18446744073709551615`
reproduces the former effectively unbounded ceiling.

The focused Dptf smoke confirms the limits at the live boundary. A live-path
cap of one holds `paths-peak=1`, retains 155 checks, and sends 406 checks
one-shot; a cap of zero sends all 561 checks one-shot. An assertion cap of zero
sends all 555 nonempty checks one-shot while allowing six empty snapshots. All
three processes remain 561/561 agreed with Z3 and finish with zero live paths.

The post-ADR-0175 admission gate calibrates those defaults on the faster
open-addressed AIG baseline. Assertion-count distributions are
register/lifter-shaped rather than synthetic: the observed maxima are 123 roots
on `win10-vwififlt`, 78 on Dptf, and 51 on IntcSST, so 128 is a no-fallback
structural ceiling on the established tier. Live path peaks are 11/5/11.
Cap sweeps reject 4 paths (1,934/4,753 vwififlt checks fall back and Axeyum
rises to 7.755 seconds) and show that 12 is behaviorally equivalent to
unbounded. Nine paths is the measured knee.

Three order-balanced cap-9/cap-12 rounds decide and agree all 20,958 checks per
policy with zero assertion fallbacks, resets, unknown splits, or finding
changes. Cap 9 sends only 45/4,753 vwififlt and 4/1,672 IntcSST checks one-shot;
Dptf never reaches the limit. Weighted mean Axeyum time is unchanged within
noise (5.088 versus 5.091 seconds), while median RSS falls 125,812 versus
136,804 KiB on vwififlt (-8.0%) and 120,076 versus 128,164 KiB on IntcSST
(-6.3%); Dptf is flat (76,532 versus 76,884 KiB). The largest observed RSS
falls from 137,968 to 126,860 KiB. This admits a bounded default for the
explicit lineage mode, not automatic warm selection: GQ9 still requires wider
drivers and a topology/cost policy before setting `GLAURUNG_AXEYUM_WARM_REUSE`
implicitly.

The first GQ10 widening pass supersedes only the 128-assertion component. The
held-out 320 KiB SurfacePen driver reaches 479 assertions (p90 352, p95 416,
p99 467): 128 sends 965/2,551 checks one-shot, while 256 still sends 446.
Raising the assertion ceiling to 512 eliminates every assertion fallback and
improves unprofiled Axeyum 1.633 to 1.063 seconds; 512 and the effectively
unbounded control have the same warm traffic, approximately 1.064-second
Axeyum time, and approximately 83.3 MiB RSS. Every run agrees 2,551/2,551 with
Z3. Glaurung therefore defaults explicit lineage to 9/512 after ADR-0177; the
9-path conclusion and the requirement for explicit warm selection are
unchanged.

The 4.8 MiB held-out NETwtw10 driver then exercises the opposite boundary under
a 60-second analysis deadline and hard 4 GiB process cap. With 512 assertions
it has zero assertion fallbacks, but cap 9 sends 8,325/23,797 checks one-shot;
all 23,797 agree, Axeyum takes 16.840 seconds versus Z3's 47.613, and RSS peaks
at 257,280 KiB. Cap 12 recovers only 417 checks and 1.5% Axeyum time while RSS
rises to 267,232 KiB. This retains nine as the conservative live-session
default and demonstrates that its fallback count is a deliberate memory/time
tradeoff, not an error or undecided result.

The wall-deadline process above is admission evidence, not a variance gate: a
repeat fits 22,132 rather than 23,797 checks before the cutoff. The repeatable
held-out tier instead uses `IOCTLANCE_SOLVE_BUDGET=20000`, a 400-second analysis
deadline, the same 600-second per-analysis solver budget, and the hard 4 GiB
cap. Three processes execute exactly 28,356 checks each with identical warm
traffic: 20,031 retained checks, 1,285 exact snapshots, 529,071 prefix roots,
247,311 added roots, 2,228 popped roots, 5,961 created/closed sessions, peak 9,
8,325 path fallbacks, zero assertion fallbacks, and zero resets. All 85,068
occurrences agree with Z3. Mean Axeyum/Z3 time is 18.771/52.086 seconds
(0.360x); Axeyum population CV is 0.44%. Median RSS is 257,736 KiB (range
257,512--257,996), and wall time is 79.05--79.22 seconds.

SurfacePen also has a three-process default-policy tier. All 7,653 occurrences
agree and every lifecycle/root/fallback counter is identical; there are zero
fallbacks. Mean Axeyum/Z3 time is 1.069/4.409 seconds (0.243x), Axeyum
population CV is 0.34%, and median RSS is 83,140 KiB. Together these repeated
held-out tiers accept 9/512 as the explicit lineage envelope on every available
driver that issues solver queries; they still do not select lineage
automatically.

The committed runner turns that boundary into a fail-closed per-commit
artifact. Run it from the Glaurung repository root with a release binary that
contains both backends:

```sh
gate_dir=$(mktemp -d /tmp/glaurung-lineage-gate.XXXXXX)/artifact
python3 docs/axeyum-integration/capture/lineage_gate.py run \
  --binary target/release/examples/ioctlance \
  --axeyum-repo /home/mjbommar/projects/personal/axeyum \
  --output "$gate_dir"

python3 docs/axeyum-integration/capture/lineage_gate.py validate \
  "$gate_dir/lineage-gate-v1.json"
```

The default full tier runs three SurfacePen and three fixed-budget NETwtw10
processes. Each child receives a hard 4 GiB address-space limit. The artifact
records both git revisions and dirty paths, the binary/driver hashes, platform
and Rust identity, every command policy, exact query/traffic/fallback counters,
finding-output hashes, time, and RSS. Dirty repositories fail unless
`--allow-dirty` is supplied for an explicitly exploratory artifact. Output is
published atomically only after every run passes the expected-work,
agreement/unknown, lifecycle, finding, and resource-identity gates.

Pass `--warm-reuse auto` to run ADR-008's detected-reuse policy instead of the
default fixed `lineage` control. Schema v1 remains backward-compatible, but
policy identity selects a distinct exact-work contract: the auto footer must
match per-driver probe/activation counts, and `warm checks + probes + path
fallbacks + assertion fallbacks` must equal every shadow query. A lineage
baseline and auto candidate intentionally fail homogeneous `compare` on policy
identity; summarize the validated artifacts side by side until a separately
specified cross-policy production objective is accepted.

Pass `--warm-reuse adaptive` to run ADR-010's bounded-pressure candidate. It
starts with at most two live path-owned sessions and expands once to the
configured hard cap after 128 failed low-cap reservation attempts. The
`[axeyum-adaptive]` footer records pressure, expansion count, initial cap, and
threshold; the runner requires exact per-driver values in addition to the
ordinary warm/fallback partition. The policy is accepted by the repeated gate
below; explicit `--allow-lineage-to-adaptive` is required to compare it with the
fixed control, so ordinary homogeneous comparisons remain fail-closed.

Compare two homogeneous artifacts fail-closed; source revisions and binary
hashes may differ, while system, policy, driver bytes, work, findings, and
repetition identity must match:

```sh
python3 docs/axeyum-integration/capture/lineage_gate.py compare \
  /path/to/baseline/lineage-gate-v1.json \
  /path/to/candidate/lineage-gate-v1.json
```

The only permitted heterogeneous comparison is the named fixed-lineage →
adaptive GQ9 transition. Every other policy field remains identical, and the
same alarms apply:

```sh
python3 docs/axeyum-integration/capture/lineage_gate.py compare \
  docs/axeyum-integration/capture/lineage-baseline-v1.json \
  docs/axeyum-integration/capture/lineage-adaptive-candidate-v1.json \
  --allow-lineage-to-adaptive
```

The comparator fails on a greater-than-3% Axeyum mean regression, greater-than-
3% normalized Axeyum/Z3 ratio regression, greater-than-5% median-RSS
regression, or greater-than-2% absolute Z3 drift. All four percentage ceilings
are explicit `--max-*-regression`/`--max-z3-drift` options. Z3 drift is an
environment alarm in either direction; Axeyum/ratio/RSS alarms are one-sided so
improvements pass. Thresholds never relax correctness, exact-work, finding, or
identity validation.

`lineage-adaptive-candidate-v1.json` is the clean repeated GQ9 acceptance
artifact from Glaurung `95c43cb` and Axeyum `f91fb232` (SHA-256
`0255d0ed2a0c5bc078e478cb951561d4de1460c11333a646f3e150b15281e716`).
All 92,721 checks agree with zero unknown splits. SurfacePen averages 1.085
seconds with 79,424 KiB median RSS and does not expand; NETwtw10 averages
18.558 seconds with 255,364 KiB and expands once at pressure 128. Against the
clean fixed-lineage baseline, Surface time/ratio/RSS change
+2.07%/+2.28%/-3.65%; NETwtw10 changes -1.03%/-0.89%/-0.88%; absolute Z3
drift is at most 0.21%. Every alarm passes and Axeyum CV is 0.19%/0.40%.

`lineage-baseline-v1.json` is the first clean release baseline for that
comparator. It was rebuilt and captured from clean detached Glaurung
`a0e5f9f` and Axeyum `486b7e28` sources; both recorded dirty-path arrays are
empty. All 92,721 shadow checks across the six processes agree with Z3, with
zero disagreements or unknown splits. SurfacePen measures 1.063 seconds
Axeyum versus 4.395 seconds Z3 (0.242x, 0.50% Axeyum CV, 82,432 KiB median
RSS). NETwtw10 measures 18.751 versus 52.149 seconds (0.360x, 0.09% Axeyum
CV, 257,632 KiB median RSS). The artifact's SHA-256 is
`ba615467b3956d21b512841335e6bb495e88f586fbb10cfdf8159cfd3153ff5b`;
the recorded release binary has SHA-256
`721b435ef0cb98857db8fb1f5ec25c054670ae6b4e9d93bbda3b4a3428a41659`.
Future homogeneous candidates compare directly against the committed file:

```sh
python3 docs/axeyum-integration/capture/lineage_gate.py compare \
  docs/axeyum-integration/capture/lineage-baseline-v1.json \
  /path/to/candidate/lineage-gate-v1.json
```

Only the compact JSON is committed. Per-process stdout/stderr/time files stay
local; their finding hashes and parsed timing/RSS records are embedded in the
artifact. The absolute paths are provenance, not inputs to comparison identity;
driver content hashes and byte lengths are the enforced inputs.

Use `--driver surface --repetitions 1 --allow-dirty` only as a fast plumbing
smoke. It is not the repeated release gate. The exact traffic constants are
schema-v1 acceptance identity; a deliberate Glaurung exploration change needs
a new schema/evidence decision rather than silently comparing different work.

The runner's currently calibrated first-class direct-delta policy is the
ADR-012 exclusive-transfer control: adaptive reuse plus owner transfer, with
serial sibling leasing off:

```sh
python3 docs/axeyum-integration/capture/lineage_gate.py run \
  --binary target/release/examples/ioctlance \
  --axeyum-repo /home/mjbommar/projects/personal/axeyum \
  --output /path/to/direct-artifact \
  --warm-reuse adaptive \
  --warm-owner-transfer on \
  --serial-sibling-reuse off \
  --direct-delta on
```

The validator has exact SurfacePen and NETwtw10 traffic contracts for this
historical control and rejects uncalibrated direct topology. Build a topology-equivalent
snapshot artifact with the same options except `--direct-delta off`, then use
`--allow-direct-delta-enablement` for the causal snapshot-reconstruction test.
For the actual production admission question, compare the current serial-
snapshot baseline (`--serial-sibling-reuse on --direct-delta off`) to the
exclusive direct candidate with
`--allow-serial-snapshot-to-direct-delta`. That named transition permits only
those two policy changes; driver bytes, revisions, repetitions, work, findings,
system identity, and all alarms remain fail-closed.

The one-process runner smokes are promising but not acceptance evidence.
Against exclusive-transfer snapshot, direct SurfacePen improves Axeyum 439.0
to 393.4 ms and ratio 9.25%, while RSS falls 2.25% and Z3 drift is 1.25%.
An independent NETwtw10 direct smoke is 28,356/28,356 agreed at 10.640 seconds
Axeyum versus 52.653 seconds Z3, 259,320 KiB RSS. The clean repeated result
below supersedes these smokes.

ADR-012 records the clean dual-control decision. Each artifact runs three
SurfacePen and three NETwtw10 processes: 92,721 checks, 100% Z3 agreement, zero
unknown splits/replay failures, identical findings, exact traffic, terminal
zero gauges, and 4 GiB child limits.

- Against exclusive-transfer snapshot, direct improves SurfacePen Axeyum
  438.600→390.433 ms (-10.98%), ratio 11.61%, and RSS 0.05%. NETwtw10 improves
  11.148→10.582 seconds (-5.08%) and ratio 4.84%, with RSS +1.21%. Z3 drift is
  +0.71%/-0.25%; the causal comparator passes every alarm.
- Against same-current serial snapshot, direct regresses SurfacePen Axeyum
  362.067→390.433 ms (+7.83%) and ratio 9.54%; RSS rises 4.88%. NETwtw10 time
  improves 10.868→10.582 seconds (-2.64%) and ratio 3.78%, but RSS rises
  224,860→262,484 KiB (+16.73%). The production comparator rejects SurfacePen
  time/ratio and NETwtw10 RSS.

The committed artifacts are `lineage-direct-transfer-baseline-v1.json`
(`b7585adf8d4caf62dd2989ac352018bcf64bbf145a7a63affc4bdd9293b55713`),
`lineage-direct-candidate-v1.json`
(`798c5dd2a6426592c84f255844b1cd7ceaf1d7fc488d3ff18c26d8ee1c832ceb`), and
`lineage-direct-serial-baseline-v1.json`
(`c9502152efa155a8d3f32c8a947ce7e75b45c2538b37d01a4bd95c6c8243ef47`).
Direct entry is a proven causal win and remains an opt-in control; serial
snapshot stays the production default.

Three alternating baseline/warm processes on 2026-07-15 each ran 13,126
same-stream checks with 13,126 agreements, zero disagreements/unknown splits,
identical findings, and zero warm resets. Median Axeyum time fell from 17.784
to 9.426 seconds (-47.0%); median paired Axeyum/Z3 fell from 2.648x to 1.462x.
Every warm run retained 679,870 prefix roots while adding 8,027 and popping
8,026; 5,609 snapshots exactly matched the immediately preceding snapshot.

Both policies remain opt-in. Snapshot order alone cannot prove worker/path
lineage, explicit scope history, non-consecutive-fork reuse, or which model
reads drove exploration. Lineage ownership supplies that execution boundary,
but it can pay heavily to rebuild sibling prefixes and retain more memory. Run
both against the ordered trace and publish same-stream p50/p95, memory, root
traffic, and repeated variance before default enablement or verdict caching.

The first direct-delta P5 route is additionally available behind the strict
opt-in below:

```sh
GLAURUNG_AXEYUM_WARM_REUSE=lineage \
GLAURUNG_AXEYUM_DIRECT_DELTA=1 \
GLAURUNG_AXEYUM_WARM_SERIAL_SIBLING_REUSE=off \
GLAURUNG_SHADOW_DIFF=1 \
target/release/examples/ioctlance <driver>
```

Unlike the snapshot lineage adapter, this route does not rediscover the common
prefix from a translated complete snapshot. The explorer supplies an absolute
confirmed retain depth, the complete persistent vector, and a trailing
temporary-assumption partition. The backend fully materializes a missing owner,
translates only the persistent suffix for an existing owner, and acknowledges
successful synchronization before the explorer advances its marker. Invalid
partitions and operational errors drop the retained session. Forks get distinct
mutable sessions; they inherit only the parent's confirmed depth, so their first
check safely rematerializes. The full query is still emitted to the ordered
trace and sent to the Z3 shadow authority.

The first implementation intentionally disabled serial sibling leasing even if
the serial environment switch was left on. Its direct contract carried only an
absolute depth, so equal-depth siblings with opposite branch roots produced
497/2,551 SurfacePen disagreements. Forcing exclusive ownership restored
2,551/2,551 agreement and established the ADR-012 control above.

ADR-013 replaces depth authority with exact immutable source ancestry. Each
persistent append owns a node pointing to its prior prefix; forks share only
the node `Arc`. A serial direct session computes the true common ancestor by
node identity, pops to it, and translates only the target suffix. Cloned pools
may reuse an `ExprId`, but independently appended sibling nodes cannot alias.
The adapter and explorer tests are 42/42 and 12/12 green, including a stale
equal-depth sibling that correctly changes the model from `x=5` to `x=7` after
one pop. Direct+serial runtime functionality is now sound and the gate names it
`source-prefix-v1`. Run it with:

```sh
python3 docs/axeyum-integration/capture/lineage_gate.py run \
  --binary target/release/examples/ioctlance \
  --axeyum-repo /home/mjbommar/projects/personal/axeyum \
  --output /path/to/source-direct-artifact \
  --warm-reuse adaptive \
  --warm-owner-transfer on \
  --serial-sibling-reuse on \
  --direct-delta on
```

The artifact records `direct_sibling_identity=source-prefix-v1`. Exact traffic
is calibrated for both drivers. SurfacePen records 2,551 checks, 125 exact
reuses, 307,592 prefix roots, 2,398 additions, 940 pops, and one peak live
session. NETwtw10 records 28,356 checks, 2,597 exact reuses, 1,220,938 prefix
roots, 23,884 additions, 20,393 pops, and one peak live session. Both have zero
resets/fallbacks and terminal-zero ownership/cache gauges.

One process per driver passes the complete validator at 100% agreement with
zero unknown/replay failures and identical findings. SurfacePen measures
298.6 ms Axeyum versus 4,490.9 ms Z3 at 74,384 KiB RSS; NETwtw10 measures
10.383 versus 52.531 seconds at 224,712 KiB. This is calibration, not release
evidence. Compare the exclusive direct control using
`--allow-direct-source-sibling-enablement`, and the production serial snapshot
using `--allow-serial-snapshot-to-source-direct`. The clean three-process result
follows.

The clean repeated source-prefix artifact is
`lineage-direct-source-candidate-v1.json`
(`ba006d2f8edfdf7754f09702ff172112c5ea3e1134669a7855f5a0a3343660cc`).
Its six processes execute 92,721 checks with exact traffic and findings, 100%
Z3 agreement, zero unknown/replay failures, terminal-zero gauges, and the 4 GiB
child cap. Against the committed serial-snapshot production baseline:

- SurfacePen Axeyum time improves 362.067→303.733 ms (-16.11%), normalized
  ratio 17.39%, and median RSS 0.36%; Z3 drift is +1.55%.
- NETwtw10 improves 10.868→10.209 seconds (-6.07%), ratio 6.61%, and median RSS
  1.72%; Z3 drift is +0.58%.

Every production alarm passes. A same-revision exclusive-direct control also
shows large candidate gains (SurfacePen time/RSS -23.17%/-5.33%; NETwtw10
-4.40%/-15.81%), but its SurfacePen Z3 drift is +4.06%, so the causal comparator
correctly rejects it. Do not waive that alarm or claim the causal control
accepted.

Comparison identity now excludes only the absolute driver `path`; content hash,
byte length, solve budget, driver membership, system, and repetitions remain
exact. This matches the standing provenance contract and lets clean detached
worktrees compare to main-worktree artifacts without weakening byte identity.

The next widening tier is the reported `tcpip` (33,501 checks, 2.5x one-process
speedup) and `dxgkrnl` (17,572 checks, 4.7x) streams. Their initial 51,073 checks
have zero disagreements but are not repeated/RSS-gated. `win32k`/`pciidex` emit
zero solver queries and are excluded from solver evidence; inspect dispatch
recovery before attempting to admit them.

The full gate budget changes the `tcpip` conclusion materially. With
`IOCTLANCE_SOLVE_SECS=600`, source-prefix direct explores 70,639 queries:
SAT/UNSAT disagreements remain zero, but Z3 reports 43 non-decisions, Axeyum
936, and 973 queries are decided by exactly one backend. The run also records
925 warm resets and 480 assertion-cap fallbacks. Axeyum remains 1.7x faster
(141.388 versus 240.161 seconds) at 440,384 KiB RSS, but this is not an
admissible correctness/performance row. The reported 33,501-query/2.5x result
uses the 60-second per-function ceiling and is a truncated distribution.

ADR-015 adds a separate diagnostic hook for this boundary:

```sh
export GLAURUNG_DUMP_SHADOW_SPLITS=/path/to/new-split-corpus
```

In combined Z3+Axeyum shadow mode, only occurrences where one backend returns
SAT/UNSAT and the other returns `Unknown`/`Error` are serialized. Exact SMT-LIB
bytes are published atomically as `<sha256>.smt2`; `shadow-splits.tsv` records
`sha256`, Z3 class, and Axeyum class. Error text is deliberately excluded from
identity. Same-process duplicate `(hash,z3-class,axeyum-class)` observations are
suppressed; byte collisions fail closed. The hook is inactive outside explicit
capture. Build the 60-second split corpus first, then decide whether a complete
600-second tier is affordable and useful.

Validate every captured byte before using or publishing the corpus:

```sh
python3 validate_shadow_splits.py /path/to/new-split-corpus \
  --summary-out /path/to/new-split-corpus/summary-v1.json \
  --capture-index-out /path/to/new-split-corpus/capture-index-v1.json \
  --name glaurung-driver-shadow-splits-v1 \
  --source 'Glaurung and Axeyum revisions, driver, and exact policy'
python3 -m unittest test_validate_shadow_splits.py
```

The validator fails closed on malformed or empty indexes, invalid result
classes, rows without exactly one decided backend, duplicate/conflicting hashes,
missing or orphaned scripts, non-UTF-8 bytes, and filename/content SHA-256
mismatches. Its summary counts distinct queries by stable backend-class pair and
deciding backend. Captured `.smt2` payloads under `shadow-splits/` are Git LFS
objects; the TSV index and JSON summary remain reviewable ordinary Git text.
The optional hash-free capture index assigns the only decided result as the
diagnostic expectation and exposes `diagnostic`, deciding-backend,
`axeyum-error`, and smallest-per-class representative tiers. Axeyum must still
generate and re-read `manifest-v1.json` so byte identity belongs to the
consumer, not this producer.

The current 60-second `tcpip` capture at Glaurung `a6a5cc0` validates 784
distinct formulas / 234,463,502 bytes. Axeyum decides 48 formulas that Z3 does
not; Z3 decides 736 formulas that Axeyum does not. The latter split is 733
Axeyum `error` results and only three Axeyum `unknown` results, so the immediate
functional target is adapter/warm-session error attribution rather than SAT
search. This corpus is diagnostic evidence and does not make `tcpip` a green
lineage-gate `DriverSpec`.

Glaurung `d60ed0f` enforces each concat child's declared half-width in the text,
Z3, and Axeyum consumers. The exact 60-second rerun confirms the attribution:
`tcpip` warm resets fall 925→0, Axeyum nondecisions 931→15, and split
occurrences 977→55 across 72,291 queries. The 52 distinct residual formulas
contain no errors: Axeyum decides 43 formulas where Z3 is unknown, while Z3
decides nine formulas where Axeyum is unknown. Axeyum remains 1.9x faster at
447,888 KiB RSS. `dxgkrnl` resets fall 2→0 and Axeyum nondecisions 2→0 across
17,712 queries; its two distinct residual formulas are both Axeyum SAT versus
Z3 unknown, and Axeyum is 2.7x faster at 341,732 KiB RSS. Both post-fix split
packs are archived separately with strict indexes and Axeyum-generated
manifests. Query topology changed after the soundness fix, so these one-process
runs are functionality evidence rather than a causal performance comparison or
DriverSpec admission.

Axeyum's independent manifest runner resolves the remaining tcpip direction.
With a 30-second diagnostic cap, cold `sat-bv` decides all nine Z3-decided
formulas (1 SAT / 8 UNSAT) with 9/9 manifest agreement; SAT search is 93.2% of
pipeline time, total p50/max are 213.7/399.0 ms. Repeating under Glaurung's
250 ms per-check cap decides 5/9 and returns four explicit
`Unknown(Timeout)` results. Thus the residual live Axeyum nondecisions are
budgeted SAT-search timeouts, not unsupported syntax, translation failure, or
wrong verdict. Keep them visible while evaluating warm-state SAT behavior or a
sound fallback policy; do not relabel them agreement.

ADR-017's first explicit candidate retries only a synchronized direct-warm
`Unknown` through one fresh Axeyum solver with the same 250 ms cap:

```sh
export GLAURUNG_AXEYUM_WARM_TIMEOUT_COLD_RETRY=1
```

The candidate is off by default. Its footer
`[axeyum-warm-timeout-cold-retry]` partitions retries into recovered decisions,
repeated unknowns, and hidden retry errors. It never retries an existing
one-shot resource fallback or an unsynchronized/error session. Measure the
exact tcpip stream before proposing any default change.

The first tcpip measurement rejects default admission. Fifteen retries recover
only four decisions and leave eleven `Unknown`; time rises 2.38%, while RSS
rises 10.46% and fails the 5% alarm. There are zero retry errors or SAT/UNSAT
disagreements, but query-count drift makes the single process non-causal. Keep
the switch as an explicit diagnostic only; do not repeat whole-snapshot cold
retry without a memory-safe topology or a predictor that selects recoverable
formulas before paying the rebuild.
The dxgkrnl no-timeout control performs zero retries and preserves the exact
17,712-query structural traffic, confirming that the opt-in branch is inert
when the retained solver decides.

ADR-018 tests the memory-safe alternative behind a separate explicit switch:

```sh
export GLAURUNG_AXEYUM_WARM_TIMEOUT_CONTINUE=1
```

It grants one synchronized retained solver a second `check` with a fresh
250 ms deadline, retaining CNF/learned state and reusing already-translated
temporary assumptions. The footer `[axeyum-warm-timeout-continuation]`
partitions continuations into recovered decisions, repeated unknowns, and
errors. Do not combine it with the cold-retry flag in a causal measurement.

The first tcpip evidence keeps this candidate explicit/off. A 60-second run
performs 14 continuations (6 recoveries, 8 repeated unknowns, 0 errors), reduces
Axeyum nondecisions from 15 to 8, and stays inside the time/RSS alarms, but the
wall-time tier has query drift. A 600-second control/candidate pair performs 14
continuations (5 recoveries, 9 repeated unknowns, 0 errors), reduces
nondecisions 14→9, changes Axeyum time +1.98% and RSS +0.034%, and remains free
of SAT/UNSAT disagreements and warm resets. It also executes 19 more queries
and reaches two additional high-confidence null-dereference findings before
the common 400-second analysis deadline. All 780 control findings are retained,
but the 782-finding candidate is not an exact-work comparison. Require a
fixed-work or repeated gate before default admission; do not interpret the two
extra findings as a solver semantic disagreement.

Warm-profile v7 and the repeated gate establish direct entry as a valid causal
control, but ADR-012 rejects production admission. It wins against topology-
equivalent snapshot and loses the current serial-snapshot policy on SurfacePen
time and NETwtw10 RSS. `GLAURUNG_AXEYUM_DIRECT_DELTA` therefore stays unset by
default; the next candidate needs source-identity/COW sibling-prefix sharing or
another bounded topology and must repeat both comparisons. ADR-013 supplies
that next candidate; it does not supersede ADR-012 until those measurements
clear every alarm.

The native path-owned control at `b9febbd`/`950cca4` completes that first
bounded comparison. Three alternating rounds on `win10-vwififlt`,
`sqfs-intel-DptfDevGen`, and `windows-update-intel-audio-IntcSST` execute 6,986
checks per policy per round. All 41,916 combined checks agree with Z3, with zero
unknown splits, warm resets, deadline hits, or finding changes. Weighted median
Axeyum/Z3 is 2.093x for consecutive snapshot and 0.746x for explicit lineage;
lineage cuts Axeyum time 65.5% and wins every live driver. It remains opt-in:
median RSS rises 31.0%, 6.3%, and 15.8% on the three drivers respectively, and
the largest observed high-water mark is 141,124 KiB. Bound live sessions,
inherited-prefix construction, memory, and deterministic fallback before any
automatic selection or cache work.

## Ordered lineage/scope/model trace v1

`GLAURUNG_ORDERED_TRACE_DIR` enables the separate GQ7 functionality artifact.
It must point at a parent directory, not at a shared output file. Each
`ioctlance` process writes a unique hidden temporary directory and publishes a
`glaurung-ordered-trace-<pid>-<uuid>/` child with one atomic rename only after
all paths are terminal and all repeated decided-query outcomes agree.

```sh
trace_root=$(mktemp -d /tmp/glaurung-ordered-trace.XXXXXX)
GLAURUNG_ORDERED_TRACE_DIR="$trace_root" \
GLAURUNG_TRACE_ORACLE_VERSION="$(z3 --version 2>/dev/null || printf unavailable)" \
GLAURUNG_SHADOW_DIFF=1 \
IOCTLANCE_DEADLINE_SECS=30 \
IOCTLANCE_SOLVE_BUDGET=20000 \
IOCTLANCE_SOLVE_SECS=60 \
target/release/examples/ioctlance \
  samples/binaries/platforms/windows/vendor/realworld/win10-vwififlt.sys

trace=$(find "$trace_root" -mindepth 1 -maxdepth 1 -type d \
  -name 'glaurung-ordered-trace-*' -print -quit)
python3 docs/axeyum-integration/capture/validate_ordered_trace.py "$trace"
```

The published directory contains `trace-manifest-v1.json`, the non-deduplicated
`events-v1.ndjson`, content-addressed exact scripts under `queries/`, and
`query-index-v1.json`. Every asserted root is also persisted independently as
`assertions/<sha256>.smt2`, including terminal branches that never reach a
check; assert events bind the canonical relative path and the manifest records
the distinct assertion count. The same event carries the assertion's sorted
free-symbol names and widths plus `assertion_width`, so a consumer can
type-check a root that never appears in a complete query. Assertion bytes use
the native backends' arbitrary-width truthiness contract (`term != 0@width`
for true, `term == 0@width` for false). Every event has contiguous
process/worker/path order.
Explorer roots and symbolic forks carry explicit parent lineage; every
persistent branch/concretization and temporary probe has matching
push/assert/check/pop history; SAT/UNSAT/unknown/error occurrences are retained;
and concretized/evaluated expressions that steer execution emit a model read
and named choice policy. Each model read carries the exact rendered expression,
its width, content hash, and ordered free-symbol declarations so an independent
consumer can append `expression = chosen-value` to the exact query and check
that the recorded choice remains SAT. Full query bytes come from the same
`solver::pipe::build_script` renderer as the cold corpus.

Each check now carries `z3_nanos` and `axeyum_nanos` in addition to the total
`backend_nanos`. In dual-backend shadow mode the first two fields time the same
query independently while the total includes shadow-wrapper work. A missing
backend is represented by `null`; never use the combined total as a Z3-only
baseline.

The validator fails on manifest/file hash drift, sequence gaps, missing path
terminals, broken lineage, scope underflow/digest mismatch, assertion/query
reconstruction mismatch, missing/unreferenced assertion bytes, inconsistent
per-backend timings, conflicting decided duplicates, query-index drift, or a
model read/choice that does not refer to a SAT check on the same path. This is
the producer-side T1 structural gate. Axeyum's independent strict QF_BV parse,
sort, replay, and model-choice satisfiability check remains the T2 consumer gate;
do not use a structurally valid producer trace alone to enable warm reuse by
default.

The first bounded real-driver sample on 2026-07-15 used the dual-backend shadow
path and a five-second new-function deadline. It published 8,153 events over
526 paths: 1,953 ordered checks (1,372 SAT, 581 UNSAT), 1,180 unique exact
queries, 1,404 push/assert pairs, 508 pops, 915 exploration-driving model
reads/choices, and 83 explicit UNSAT prunes. All 1,953 Z3/Axeyum verdicts agreed
with zero unknown splits, and the standalone validator accepted the artifact.
The unique-query count versus check count confirms exact repeats survive.

An earlier attempt was correctly retained as unpublished `.failed` evidence.
It exposed a Glaurung explorer bug: the feasibility shortcut treated a
symbol-free but syntactically nonconstant branch DAG as an independent symbolic
predicate, preserving a semantically UNSAT child until a later model read. The
shortcut now requires at least one free symbol before it may skip a check, with
a focused regression test.

The wider IntcSST capture then found a second independent fail-closed defect:
`eval_concrete` and `concretize_addr` evaluated an empty model after UNSAT,
unknown, unavailable, or failed checks and allowed the resulting zero/default
value to steer exploration. Commit `57c6c09` makes both operations return no
value unless the immediately preceding check is SAT, propagates that result
through memory operations and API summaries, and terminates a path whose next
step requires the unavailable model. Its regression verifies that an UNSAT
evaluation neither produces a value nor adds a concretization assertion. The
validator remains strict; it was not weakened to hide the producer bug.

That repaired trace exposed a separate width-contract defect rather than a
solver defect: extension nodes could declare a 32-bit source around a 64-bit
child. Z3's AST adapter had normalized such children implicitly, while the
strict SMT-LIB capture and Axeyum adapter correctly rejected the inconsistent
sort. Commit `d450d2a` now coerces every zero/sign-extension child to its
declared source width in the renderer and both native adapters. A clean bounded
IntcSST run then published 7,840 events, 566 paths, 1,672 checks, 1,272 unique
queries, and 838 model reads; all 1,672 same-stream Z3/Axeyum checks decided and
agreed with zero unknown splits. These are Glaurung correctness and capture
repairs, not Axeyum performance claims.
