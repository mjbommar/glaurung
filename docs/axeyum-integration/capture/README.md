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

2. **Capture** (the `GLAURUNG_DUMP_QUERIES` hook in `solve()` writes each
   DECIDED query once as `<sha256>.smt2`, appends `<sha256>\t<verdict>` to
   `index.tsv`, dedup by content hash):
   ```
   export GLAURUNG_DUMP_QUERIES=/path/to/raw-corpus
   export IOCTLANCE_DEADLINE_SECS=400 IOCTLANCE_SOLVE_BUDGET=1000000 IOCTLANCE_SOLVE_SECS=600
   for drv in win10-vwififlt sqfs-intel-DptfDevGen windows-update-intel-audio-IntcSST; do
     cargo run --release --example ioctlance --features solver-z3 -- \
       samples/binaries/platforms/windows/vendor/realworld/$drv.sys >/dev/null 2>&1
   done
   ```
   (2026-07-13 capture: 15,687 distinct queries, 1,797 sat / 13,913 unsat,
   ~290 MB, sizes 30 B - 220 KB, p50 ~9 KB; 97% contain `extract`, 89%
   `concat` -- the width-mixed, extract/concat-heavy target distribution.)

3. **Build the manifest + tiers** (`build_corpus.py`: structural family
   classification, stratified `representative` tier + `full` tier, manifest
   in axeyum's v1 schema; `excluded-hashes.txt` drops the rare
   declared-vs-actual width edge cases axeyum's strict parser rejects):
   ```
   python3 build_corpus.py /path/to/raw-corpus /path/to/pack 6 excluded-hashes.txt
   ```

4. **Validate ingestion + profile** in axeyum:
   ```
   cd ~/projects/personal/axeyum
   cargo run --release -p axeyum-bench --features z3 -- \
     /path/to/pack --corpus-manifest /path/to/pack/manifest-representative-v1.json \
     --corpus-tier representative --backend sat-bv --compare-z3
   ```

## Result (2026-07-13, representative tier, 128 queries)

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

The representative pack is placed (uncommitted) at
`~/projects/personal/axeyum/corpus/glaurung-qfbv/` ready to ingest. The
full ~290 MB tier is regenerable via steps 1-3 (too large to commit; keep
access-controlled). `family`/`tiers`/`content_hash`/`expected` all conform
to `docs/user-guide/corpus-manifests.md`.

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
`glaurung-axeyum-warm-profile-v4` (v1/v2/v3 remain accepted historical inputs).
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
count, require 100% decisions, and require zero cap fallbacks so a warm stream
does not mix warm and one-shot schemas. From the Axeyum checkout:

```sh
python3 scripts/summarize-glaurung-warm-profile.py \
  "$profile_dir"/axeyum-profile-*.jsonl \
  --require-records 561 \
  --require-100-percent-decided
```

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
