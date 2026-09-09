# WP3 coalesced frame-coordinate identity

Status: bounded production consumer migration landed at `3871bcad` on
`master`.

## Result

Call-argument substitution now classifies stack/frame-coordinate storage from
the identity sidecar's unambiguous physical base rather than requiring one
exact SSA value. Legal coalescing of multiple versions of `rsp`, `rbp`, `sp`,
or a target-equivalent base therefore retains the frame-coordinate phase guard.

Mixed physical bases and missing identity evidence still decline the proof.
Identity-aware production paths do not fall back to display spelling;
no-sidecar compatibility callers retain the old spelling behavior.

## Focused evidence

```text
TMPDIR=/home/mjbommar/.cache/glaurung/tmp \
  cargo test --features python-ext --lib 'ir::call_args::tests::' --quiet
129 passed; 0 failed; 4,627 filtered out; 0.20 s

VIRTUAL_ENV=/home/mjbommar/projects/personal/glaurung/.venv \
  uvx maturin develop --release
release build completed in 37.07 s

PYTHONPATH=/home/mjbommar/.cache/glaurung/verify-b04e0b78/python \
  python tools/dectest.py \
  '11_call_shapes:clang:O0:call_into_spill' --show --allow-stale
1 of 838 lanes selected; no regression in scope
```

The coalesced-same-base unit contract was observed red before the production
change. The focused module slice also covers mixed-base, missing-evidence, and
misleading-display-name refusals.

The real-binary check imported
`/home/mjbommar/.cache/glaurung/verify-b04e0b78/python/glaurung/_native.cpython-312-x86_64-linux-gnu.so`
from detached commit `3871bcad`; its SHA-256 is
`0f058727bf2ebafd4e8caeca802023bc753680fa694d30d120735c649ba37187`.
The main-tree timestamp guard required `--allow-stale` because concurrent main
sources were newer than this detached extension. Commit identity, import path,
and module hash were checked directly before accepting the result.

## Measurement boundary

Only the owning Rust module and one directly related Clang O0 x86-64 fixture
lane ran. No broad Rust/Python suite, fixture matrix, DecBench, Joern, GED,
performance, or corpus-wide measurement ran. The last periodic Hello checkpoint
remains the six passing x86-64/AArch64/ARMv7 O0/O2 cells recorded at
`29b202a9`/`57a6b936`; this identity-only increment did not change rendered
output and did not spend another matrix run.

## Remaining scope

This closes the physical-storage classification boundary in
`is_frame_coordinate_storage`. WP3 remains open: exact value equality must stay
distinct from physical-storage identity, entry/version-specific semantics must
remain exact, and remaining production consumers need the same case-by-case
migration with mixed/missing-evidence refusals.
