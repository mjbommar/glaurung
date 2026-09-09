# WP3 canonical split-string expression origins

Commit `7bee91ff` closes the outer-expression carrier boundary in
`strings_fold`.

ARM targets commonly form a string address as page plus offset. The existing
fold retained the owners of both operands, but when the enclosing addition also
had an owner it left a nested origin carrier. Direct ownership queries then saw
only the outer instruction and omitted the two address-building contributors
from structured line mappings.

Recursive string folding now flattens any replacement carrier into its parent.
The resulting string literal has one deterministic, deduplicated origin set
covering the addition, page, and offset instructions. Address arithmetic,
readonly-pool membership, printable-string, and length-cap rules are unchanged.

## Focused evidence

The existing split-address test was strengthened and observed red: only the
addition owner was directly visible. After repair:

```text
cargo test --features python-ext --lib \
  ir::strings_fold::tests::originated_split_address_folds_and_unions_ownership \
  -- --exact --quiet
1 passed; 4,735 filtered out

cargo test --features python-ext --lib ir::strings_fold::tests:: --quiet
12 passed; 4,724 filtered out
```

An exact detached release build of `7bee91ff` passed the build guard with native
SHA-256 `81c0a5bc01d965a8cac12296a00ccffb43f31f17ee005d63f97c12a2df52de2a`.
The directly relevant ARM Hello slice remained green:

```text
pytest -q python/tests/test_linux_arm_hello_canonical.py \
  -k 'symbols and (O0 or O2)'
8 passed across AArch64 and ARMv7, PIE/non-PIE, O0/O2
```

No broad Rust, Python, fixture, architecture, DecBench, or Joern suite ran.
