# WP3 type-recovery internal identity authority

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `fda323fb` replaces type recovery's internal
`Option<&ValueIdentities>` mode switch with a closed `TypeRecoveryAuthority`:

- `RawMachineRegisters` accepts architectural register names only before value
  numbering;
- `Exact` accepts semantic storage only from the pipeline-owned identity
  sidecar and fails closed when identity is missing or ambiguous.

The authority now reaches register-width defaults, scalar-float recognition,
frame-base and spill-slot matching, pointer-arithmetic propagation, and return
refinement. Production raw entry points are explicitly named
`recover_raw_types*`; the old ambiguous spellings are test-only. The rendered
pipeline continues to call `recover_types_for_with_identities`.

## Focused evidence

```text
cargo check --features python-ext
pass

cargo test --features python-ext ir::types_recover:: --lib -- --test-threads=1
100 passed; 0 failed; 4745 filtered out

uv run python tools/build_guard.py
fresh

uv run python tools/dectest.py @smoke \
  --arch i386 --arch armv7 --arch aarch64 --arch x86_64_gcc15
SCOPED: 16 lanes of 3304 (0%) -- no regressions in scope
```

The required whole-Python fail-fast gate passed every earlier test and stopped
at 17% on the existing committed-ledger disagreement in
`test_the_committed_baseline_is_valid_and_has_a_clean_control_lane` for fixture
157 (`vis_fold_with_biases`, `vis_read_bias`, `vis_set_biases`), fixture 172
(`double_precision_horner`), and fixture 81
(`two_decrements_one_scratch`). This commit changes neither baseline.

The focused Python observable-parameter-width test currently renders two
pointer parameters as `long`. A controlled A/B rebuilt the extension and
reproduced the identical failure with this three-file patch removed, proving
it is not caused by this authority refactor. The shared checkout has concurrent
stack-local work in the affected path, so this increment does not claim or
modify that lane.

This closes the type-recovery internal authority seam. It does not complete
WP3's remaining semantic-reader audit, mutation invalidation, origin coverage,
or WP6's constraint solver, and it makes no output-quality improvement claim.
