# WP3 adjacent-movement expression origins

> **Kind:** record · **Date:** 2026-09-07

## Outcome

Commit `86ac95a6` completes expression-origin transfer for the four related
definition-removal proofs owned by `src/ir/copy_prop/adjacent.rs`:

- moving an effectful scratch expression into its sole adjacent consumer;
- substituting an adjacent promoted-stack value;
- substituting a physical scratch into its sole eager guard use; and
- substituting a pure predicate/value into the assignment that consumes and
  overwrites it.

Each transformation already deleted the defining statement and unioned its
owner onto the consumer statement. It now also attaches that owner to the exact
source expression before moving or substituting it. Existing evaluation-count,
alias, select, width, and whole-function-read refusal proofs are unchanged.

This is a bounded WP3 production migration, not universal expression
attribution or completion of authoritative SSA consumption.

## Observed-red evidence

One ownership test for each transformation was observed red before the repair.
In every case the consumer statement had the expected definition/consumer
union, while the substituted expression reported no origin.

After the common transfer rule landed, the complete touched module passes:

```text
cargo test --features python-ext 'ir::copy_prop::adjacent::tests::' --lib
19 passed; 0 failed
```

The required release extension rebuild completed in 35.86 seconds. A focused
parent/tip comparison covered the purpose-built effectful-select fixture, both
host O2 guarded-dispatch functions, and both host O0 conditional functions:

```text
uv run python tools/dectest.py \
  189_effectful_select \
  '204_adjacent_dispatch_tables:*:O2:adt204_guarded_control' \
  '01_conditional_polarity:*:O0:classify' \
  --jobs 4 --full

8 lanes, 24 functions, all passed; no scoped regressions
```

The pre-change run used the deliberately stale prior release extension and was
labeled as such by the harness. The post-change run used a fresh extension with
SHA-256 `a8401a0ded270e9d06e1e4733c29531120876e00e28e14fd17570db17cfb0053`.

No full Rust, Python, architecture, fixture, or DecBench sweep was run at this
bounded iteration boundary.

## Next boundary

Audit the next production transformation that deletes or replaces an
expression-defining statement. Add an observed-red ownership test for every
related proof in its owning module, preserve exact evaluation semantics, and
continue using module plus representative-fixture validation until a coherent
WP3 integration boundary warrants broad gates.
