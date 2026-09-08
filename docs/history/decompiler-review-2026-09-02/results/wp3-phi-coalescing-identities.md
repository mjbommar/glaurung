# WP3 phi-copy coalescing identities

Commit `a4853187` removes production phi-copy coalescing's dependency on the
serialized `register#version` spelling.

The value-numbering transaction already owns a `ValueIdentities` sidecar before
it leaves SSA. Coalescing nevertheless split each candidate's display name to
decide three semantic facts: whether the value was eligible, which source
register lifetime applied, and which SSA version should represent a merged
class. That made the sidecar advisory at the exact point where it should be
authoritative.

Production now passes the sidecar into the coalescer. A candidate must have one
exact, nonzero SSA identity and must not be a kept-bare ABI carrier. Source
lifetime matching uses the identity's physical base, and representative choice
uses its typed version. The identity-free parser remains only behind the
test-only compatibility helpers for hand-written legacy LLIR.

The paired boundary tests establish both directions:

- opaque values `opaque_first` and `opaque_second`, owned as `rax` versions 1
  and 2, coalesce and select version 1 without any encoded name;
- unowned values spelled `rax#1` and `rax#2` do not coalesce in the production
  identity path.

Focused validation used the debug Rust build and a freshly rebuilt Python
extension:

```text
cargo test --features python-ext ir::value_number::tests::production_phi_coalescing_uses_opaque_ssa_identity -- --exact
1 passed

cargo test --features python-ext ir::value_number::tests::production_phi_coalescing_rejects_unowned_version_spelling -- --exact
1 passed

cargo test --features python-ext 'ir::value_number::tests::' --lib
58 passed; 4,600 filtered out; test execution 0.10s

uv run maturin develop
success

uv run python tools/dectest.py 03_loop_shapes:gcc:O2:nested_carry --show
1 scoped lane of 838; no regressions in scope

python3 tools/gen_test_census.py
5,188 declared; 0 never executed by any gate

python -m pytest python/tests/test_test_census.py -q
6 passed in an isolated archive of the exact pushed source commit
```

No broad suite, DecBench run, or corpus sweep was run. This closes the
production phi-coalescer's display-name reader; it does not complete WP3's
remaining AST consumer migration, origin closure, or naming-as-render-mapping
work.
