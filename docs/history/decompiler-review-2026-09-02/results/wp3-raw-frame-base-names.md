# WP3: raw frame bases require exact architectural names

> **Kind:** record · **Date:** 2026-09-13

## Outcome

Commit `f7065f89` removes SSA-suffix parsing from raw frame-base
classification. Identity-free type recovery now recognizes only exact machine
register names such as `rbp`, `rsp`, `r7`, `r11`, `x29`, and `sp`. A value
merely spelled `rbp#1` can no longer impersonate raw machine frame storage.

Numbered and renamed values retain the stronger behavior through
`ValueIdentities`: their unambiguous physical base and complete candidate set
must establish frame ownership. Same-frame coalesced identities therefore
continue to transport spill-slot pointer facts, while different SSA frame
versions remain distinct.

Raw type recovery remains supported because it runs before value numbering in
prototype recovery and declaration projection. This change narrows that
legitimate compatibility surface instead of incorrectly deleting it.

## Red/green evidence

The existing raw-frame test previously required numbered spellings to be
accepted. It was renamed and inverted before the implementation change, and
was observed red on `rbp#1`:

```text
cargo test -q --features python-ext --lib \
  raw_frame_bases_require_exact_architectural_names
FAILED: a numbered spelling must not impersonate the raw rbp frame base
```

After removing the suffix parser, these focused contracts pass:

```text
raw_frame_bases_require_exact_architectural_names
frame_base_uses_exact_identity_not_display_spelling
spill_pointer_does_not_cross_frame_ssa_versions
spill_pointer_crosses_equal_coalesced_frame_identities
spilled_pointer_arg_recovered_through_address_add
real_gcc_o0_spills_propagate_both_string_pointer_live_ins
arm_spilled_pointer_plus_local_index_refines_the_live_in
lone_spilled_pointer_fact_is_not_yet_a_rendered_parameter_refinement
```

`cargo check -q --features python-ext --lib` also exits zero.

## Measurement boundary

This is a fail-closed authority change. Exact raw production inputs are
intended to remain unchanged, and no output or timing movement is claimed. No
fixture matrix, DecBench, Joern, or corpus sweep was run. The required native
rebuild and post-source-commit fail-fast Python gate are recorded after they
run. WP3's remaining display-name and origin/invalidation audit stays open.

