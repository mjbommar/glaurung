# WP5 i386 GOT-relative switch evidence — 2026-09-05

> **Kind:** record · **Date:** 2026-09-05

## Outcome

Behavioral commit `b84233ec` recovers GCC's i386 PIC jump-table form. Unlike
x86-64's usual relative tables, the table bytes and the base used by each
stored offset are different:

```text
call __x86.get_pc_thunk.ax
add  eax, GOT_delta
cmp  edx, bound; ja default
add  eax, [eax + edx*4 + table_from_got]
jmp  eax
```

The CFG now proves the PC-thunk body from image bytes, materialises its exact
return address, carries the checked GOT address through the immediate add, and
decodes each table entry relative to that GOT base. The table address remains a
separate fact. This recovers eight i386 O2 cells that previously lost their
case blocks:

- `04_switch_shapes::dense_compute`
- `08_indirect_dispatch::dispatch_switch`
- `126_x_macros::apply_opcode`
- `151_wide_branch_ladder::big151_branch_ladder`
- `186_defaultless_guarded_switch::fallthrough_no_default`
- `204_adjacent_dispatch_tables::adt204_guarded_control`
- `206_aarch64_wide_dispatch::dense_dispatch`
- `206_aarch64_wide_dispatch::dispatch_in_loop`

All eight changes are recorded as `fail` to `pass` in
`tests/decompiler_fixtures/arch_baseline.json`. The last cell proves this is not
only a top-level-switch repair: typed case evidence survives inside a loop with
a returning arm.

## Production boundary

- `src/target/registers.rs` is the shared owner of the exact
  `mov reg,[esp]; ret` PC-thunk byte contract. Both lifting and CFG analysis use
  it; symbol names are unnecessary and stripped objects behave identically.
- `src/analysis/cfg/dispatch_flow.rs` supplies only the proved
  `register = return_address` fact to the instruction-level tracker and repeats
  the same observation during post-CFG replay.
- `src/analysis/dispatch.rs` normalises encoded signed disp32 only for i386,
  uses checked address arithmetic, and represents table address and target base
  separately. It accepts both a load followed by an add and GCC's folded
  add-from-memory form.
- `src/analysis/jump_table.rs` decodes exactly the guard-proved entry count
  relative to the distinct target base and retains the existing executable-
  target and arithmetic-overflow refusals.

This is not a heuristic table scan. A missing PC-thunk proof, missing range
bound, unsupported scale, unmapped table extent, arithmetic overflow, or
non-executable target still declines without adding CFG successors.

## Validation

All commands used `TMPDIR=$HOME/.cache/glaurung/tmp` in an isolated worktree
stacked on the completed AArch64 WP5 slice.

- `cargo test --features python-ext`: 4,102 library tests passed, zero failed,
  and five were ignored; every integration and documentation target passed.
- Focused dispatch tests: 43 passed; focused jump-table tests: 22 passed.
- `uv run maturin develop --release`: built a fresh worktree-local extension.
- `uv run pytest python/tests/test_decompiler_arch_roundtrip.py -k
  'i386_o2_got_relative_switches' -q`: passed both real target-worker execution
  comparisons under `qemu-i386`.
- `uv run pytest python/tests/test_dectest_selection.py -q`: 68 passed.
- `uv run python tools/dectest.py @o0 @o2 --arch i386`: 410 lanes. Parent and
  tip report the exact same four older regressions and 25 older unrecorded
  improvements after the eight reviewed movements are accepted. The four
  regressions are `195::bv195_pair_roundtrip`, `201::f201_f64_slot_bits`,
  `203::mv203_by_value_narrow`, and `207::quad_stride_sum`; none is attributable
  to this increment.
- Census commit `86d224f5` records two added Rust test declarations, moving
  4,617 to 4,619 while leaving the never-executed pool at zero. Its focused
  six-test suite passes.

The isolated parent/tip fitness comparison records 173 added product lines.
Product mean moves 414.0254 to 414.3186, median 302 to 303.5, and LOC in files
already above 1,000 moves 52,222 to 52,284. No file crosses a 1,000- or
2,000-line threshold, the number of oversized files is unchanged, and maximum
file size is unchanged. The growth is accepted for this bounded recovery, but
the 77-line net growth in `analysis/dispatch.rs` strengthens WP9's case for
moving the remaining encoding facts behind target-owned queries.

The required whole Python suite has not yet run at this commit, so this record
makes no release-green claim. No DecBench run or upstream interaction was
performed.
