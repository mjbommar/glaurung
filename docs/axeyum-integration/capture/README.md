# Glaurung QF_BV real-query corpus capture (for axeyum GQ1/GQ10)

Reproducible procedure for producing the lifter-shaped QF_BV query pack that
axeyum's `axeyum-bench` (artifact v17, manifest v1) ingests as its
client-performance corpus. This is the enabling artifact axeyum's GQ1
("capture and profile real queries first") is blocked on.

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
