# WP3 promoted-store address expression origins

Commit `b836edd9` closes the promoted-store address boundary in
`typed_simplify`.

Type-directed cleanup removes an unobservable machine-parent extension when an
identity-owned promoted stack object has a narrower recovered integer type.
The store recognizer previously required a bare register address, so attaching
instruction-origin evidence to that address silently disabled the cleanup and
left noisier wide casts in rendered C.

The recognizer now inspects the semantic address while retaining the complete
owned address expression unchanged. The exact promoted-object identity and
destination-width proofs are still required; an arbitrary indirect store does
not become eligible.

## Focused evidence

The new attributed-address contract was observed red first: the 64-bit outer
extension remained. After the repair:

```text
cargo test --features python-ext --lib \
  ir::typed_simplify::tests::attributed_promoted_store_address_still_consumes_machine_extension \
  -- --exact --quiet
1 passed; 4,734 filtered out

cargo test --features python-ext --lib ir::typed_simplify::tests:: --quiet
7 passed; 4,728 filtered out
```

An exact detached release build of `b836edd9` passed the build guard with native
SHA-256 `a194dea4041fb386880e23d79258042079d45a11c1f5d1e64f407f9a83f1c3e8`.
The directly owning narrow-width fixture remained green:

```text
python tools/dectest.py \
  '194_narrow_return_widths:*:*:nrw194_u8_mix' --jobs 2 --full --show
4 passed across Clang/GCC O0/O2; no regressions in scope
```

No broad Rust, Python, fixture, architecture, DecBench, or Joern suite ran.
The periodic 12-cell cross-architecture Hello checkpoint remained recent and
was not repeated for this local typed consumer.
