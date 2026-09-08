# WP3 multi-output SSA identities

Commit `8bc75c71` closes the first-output-only gap between SSA construction and
value-numbered LLIR.

`SsaInfo` already assigned a distinct identity to every output of an intrinsic,
but the value-numbering tagger accepted one definition version and deliberately
left multi-output intrinsics untagged. The tagger now consumes positional
definition versions, tags every intrinsic output, and records every numbered
definition in `ValueIdentities`. A later read of the second output therefore
uses the same numbered value and exact identity as its producer.

The new contract was observed red with both outputs left as raw `rax`/`rdx`.
Focused validation after implementation:

```text
every_multi_output_intrinsic_definition_keeps_its_ssa_identity
1 passed; 4,418 filtered out

single_output_intrinsic_uses_the_reaching_ssa_value
1 passed; 4,418 filtered out

effect_only_intrinsic_uses_every_reaching_ssa_value
1 passed; 4,418 filtered out
```

Each case used `cargo test --features python-ext --lib
ir::value_number::tests::<name> -- --exact`. No broad Rust, Python, fixture,
DecBench, or Joern suite was run. Multi-output width propagation and the wider
AST-native identity consumer audit remain separate WP3 work.

## Follow-up: positional output widths

Commit `ad81c123` closes the adjacent width gap. Definition-site widths are now
keyed by `(instruction, output index)` rather than by instruction alone, and
value numbering records each intrinsic output's machine width beside its
numbered value and exact SSA identity. Coalescing visits every definition and
consumes the corresponding positional width, so mixed 32/64-bit outputs do not
inherit one another's declaration constraint.

The strengthened multi-output test was observed red with output one incorrectly
reported as eight bytes and output two absent. It now proves four and eight
bytes respectively. That test, the single-output control, and three directly
adjacent coalescing-width contracts pass individually with 4,418 unrelated
tests filtered out. No broad suite or external benchmark ran.
