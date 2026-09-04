# WP8 PDB nominal-pointer result evidence

Date: 2026-09-03

## Defect

The committed clang-cl PE32+/PDB fixture declares
`record_value(struct Record *r)`, but the decompiler rendered its authoritative
parameter as `void *arg0`. PDB parsing already retained `struct Record *`; the
loss happened when the debug adapter reused `standalone_c_type`, whose correct
policy for guessed library-catalog types is to lower an unknown aggregate
pointer to the ABI-safe `void *`.

That catalog policy is not correct for trusted debug declarations. It discarded
nominal information that the PDB had proved and prevented the renderer from
selecting the matching `Record` alias.

## Change

`src/python_bindings/ir/dwarf_contracts.rs` now keeps normalized, explicitly
tagged `struct` and `union` spellings at the authoritative debug boundary. All
other scalar and source-language conversions retain their previous behavior;
the inferred library-catalog fallback is unchanged.

A focused Rust test covers a plain struct pointer and a qualified union
pointer. The real fixture expectation follows the renderer's existing
conventional pointer declarator spacing (`Record *arg0`).

## Validation

Base revision before the patch:
`29f6843f9b47175728f74b0882c2e1969e5a3dc5`. The native extension was rebuilt
from the working tree with the required debug command.

```text
cargo test --features python-ext authoritative_tagged_pointers_keep_their_nominal_type --lib -- --nocapture
1 passed; 0 failed

uv run maturin develop
completed successfully

uv run pytest python/tests/test_pdb_type_recovery.py -q
11 passed; 0 failed

uv run python -m glaurung.cli decompile tests/pdb_types/types.dll \
  --func record_value --style decbench --no-color \
  --pdb-cache tests/pdb_types > "$TMPDIR/record_value.c"
cc -std=c11 -Wall -Wextra -Werror -fsyntax-only "$TMPDIR/record_value.c"
completed successfully

cargo test --features python-ext
3,782 library tests passed; 4 ignored; 0 failed
all integration targets passed
2 doc tests passed; 1 ignored; 0 failed
```

The emitted boundary is now:

```c
typedef struct Record Record;
int record_value(Record *arg0)
```

No committed fixture baseline was changed. This is narrow WP8 evidence, not a
green release-profile claim. The same function still reports one
definition-before-use violation in its body; resolving that independent
correctness defect remains future work.

The fail-closed def-use census was also run. Four of six tests passed; the new-
violation and improvement ratchets failed on broad current-tip drift across the
shared corpus (including substantial decreases in every C and Rust lane, plus
21 functions with new or shifted findings). The PDB fixture is not part of that
census, and no baseline was refreshed. This result is recorded as a red broad
gate, not attributed to this nominal-type change and not represented as release
evidence.
