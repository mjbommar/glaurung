# WP9 Rust scalar source-type evidence

Date: 2026-09-03

## Defect

The real `167_rust_trait_objects` fixture declares `rust_dyn_apply` as
`#[no_mangle] pub extern "C" fn rust_dyn_apply(sel: u32, x: i32) -> i32`.
Its DWARF faithfully records `u32`, `i32`, and `i32`, but those Rust spellings
are not standalone C tokens. The renderer rejected them and fell back to a
machine-width recovered signature:

```c
long rust_dyn_apply(unsigned int arg0, unsigned int arg1)
```

That widened a proven 32-bit source result to 64 bits and discarded the source
parameter signedness and names.

## Change and trust boundary

`src/python_bindings/ir/dwarf_contracts.rs` now translates only exact Rust
scalar aliases at the debug-to-render boundary: `i8..i128`, `u8..u128`,
`isize`, and `usize` receive self-contained, representation-preserving C
spellings. Known C and platform types still pass through the existing
`standalone_c_type` conversion, while unknown language types remain untouched
for the aggregate/type-environment machinery.

The conversion does not change calling-convention selection and does not teach
the generic C catalog normalizer that arbitrary Rust pointers or aggregates
are C ABI types. A first implementation at that broader boundary caused the
independent `i32 *` fallback test to change from `void *` to `int *`; it was
rejected and replaced with the narrower debug-render boundary.

## TDD and real-fixture evidence

The new real-fixture test was first run against the previous release extension
and failed on the O0 lane with the exact old signature:

```text
python/tests/test_decompiler_rust_source_types.py::
  test_exported_rust_i32_return_uses_exact_c_width[O0]
AssertionError: long rust_dyn_apply(unsigned int arg0, unsigned int arg1) {
```

An isolated clone of commit `6c18440b` plus only this increment was then built
in release mode and tested against the existing real O0/O2 binaries:

```text
cargo test --features python-ext --lib \
  rust_fixed_width_scalars_have_standalone_c_spellings -- --nocapture
1 passed; 0 failed

python -m pytest python/tests/test_decompiler_rust_source_types.py -xvs
2 passed
```

The clean O2 output begins:

```c
int rust_dyn_apply(unsigned int sel, int x) {
    extern unsigned __int128 ...choose(unsigned int);
```

and retains the recovered vtable-slot call and final return from the preceding
WP9 increments. The same fixture test also rejects a returned
`unrecovered indirect jump`, so a later type/declaration change cannot silently
undo that control-flow recovery while keeping only the corrected signature.

## Concurrent-worktree limitation

The shared worktree contained extensive unrelated, uncommitted decompiler work.
A release build of that whole snapshot rendered the corrected signature but
lost the previously recovered O2 virtual call. The isolated `6c18440b` snapshot
did not reproduce that regression, proving it is not caused by this scalar
spelling increment. The shared snapshot is therefore not cited as a green
integration gate, and only the isolated patch is eligible for this commit.

Debug tracing localized that concurrent regression further: `choose` still
proved `callee_defines_pair=true`, but a declaration merge copied authoritative
parameter types and then marked the entire prototype authoritative. The
single prototype-wide authority bit consequently locked its unrelated,
body-recovered `long` result before the caller-specific two-word proof could
upgrade it. The durable repair belongs in that concurrent declaration-merge
lane as field-level authority (or an equivalent return-specific fact), not as a
weaker vtable heuristic here.

The required post-commit full Python suite was also started in the isolated
clone. By 12% it had already accumulated numerous errors and failures because
the clone did not contain the complete gitignored generated fixture corpus. It
then produced no progress for several minutes in an integration lane and was
interrupted. This is recorded as an invalid/incomplete broad gate, not a pass;
the two real Rust binaries needed by the focused test were copied explicitly
from the existing corpus and are the only fixture-level evidence claimed here.
