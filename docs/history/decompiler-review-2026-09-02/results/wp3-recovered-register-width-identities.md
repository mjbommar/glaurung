# WP3 recovered register-width identities

Commit `630595f9` removes display spelling from production register-view width
recovery when the pipeline-owned `ValueIdentities` sidecar is present.

## Defect and repair

The observed-red contract assigned the display name `edi#7` to a value whose
authoritative physical base was `rax`. Before the repair, type recovery parsed
the misleading display spelling and inferred a four-byte integer. It now uses
the unambiguous physical base from the sidecar and infers eight bytes. Missing
or ambiguous sidecar evidence declines to the machine-word default instead of
parsing `base#version`. The old spelling parser remains only for explicit
no-sidecar compatibility calls.

The same identity-aware lookup now supplies default value tags, index and shift
widths, constant demotion, scalar floating-register classification, and the
fallback width in ABI return refinement.

## Focused validation

- `cargo test --lib --features python-ext 'ir::types_recover::tests::'`:
  93 passed, 0 failed, including the new misleading-name regression and the
  existing `value_number_tags_do_not_change_register_view_width` control.
- `uv run maturin develop --release`: passed. The installed native extension
  SHA-256 was
  `7ee2474a523eb7cd55eafc2a71d25d760b2189fb6e271a23d898cbeddc4cf7ad`.
- `uv run --no-sync python tools/build_guard.py`: reported `fresh`.
- `uv run --no-sync python tools/dectest.py @widths --show`: all four scoped
  lanes passed with no regressions.
- `git diff --check`: passed before the code commit.

The committed census moves by exactly the one owned Rust test: total declared
tests 5,350 to 5,351 and `ir` tests 2,616 to 2,617. Other source changes in the
shared worktree were not staged. No broad Rust, Python, or corpus suite was run
for this bounded increment.

## Remaining boundary

This closes production type recovery's direct dependence on numbered physical
register spelling for register-view widths. It does not finish WP3 or make
`tag_phys` removable: the remaining typed semantic readers and explicit
compatibility-only parsers still require separate classification and migration.
