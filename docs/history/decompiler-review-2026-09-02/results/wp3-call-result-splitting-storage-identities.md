# WP3 call-result splitting storage identities

Commit `37fb9aa7` removes production call-result lifetime splitting's dependency
on serialized register names.

The earlier call-result attribution migration decided whether a call consumed a
machine result through `ValueIdentities`, but the later lifetime splitter still
reparsed names such as `rax#7`. It used that spelling both to classify the
result bank and to mint subsequent values. This left a semantic reader on the
display-name compatibility path and meant newly synthesized result values had
no typed storage provenance.

`ValueIdentities` now carries canonical physical-storage bases as a separate
fact from exact SSA identity. Several non-interfering SSA versions may therefore
remain explicitly non-exact while still agreeing on one machine storage base;
conflicting bases remain ambiguous. Role projection and transactional renames
union this fact with the same conservative collision behavior as SSA identity.

The production pipeline passes the mutable sidecar into the splitter. It uses
only the typed physical-storage fact for result-bank classification and copies
the owned SSA/storage facts to each fresh scalar result. ABI-proven values that
the pass itself creates—missing declared destinations, wide high halves, SSE
lanes and pairs, AAPCS HFA members, and split-bank values—receive explicit
storage provenance at creation. The spelling parser remains only in the
identity-free compatibility entry point.

The paired boundary tests prove both directions:

- an opaque value owned as SSA `rax` version 7 is split, its reached use is
  rewritten, and its fresh lifetime retains both exact SSA and physical-storage
  facts;
- an unowned value merely spelled `rax#convincing_but_unowned` is not treated as
  semantic result storage by the production entry point.

Focused validation used the debug Rust build:

```text
cargo test --features python-ext --lib ir::call_result_split::tests::
17 passed; 4,643 filtered out

cargo test --features python-ext --lib ir::value_number::tests::
59 passed; 4,602 filtered out

uv run maturin develop
success

uv run python tools/dectest.py \
  11_call_shapes:gcc:O0:call_result_drives_branch \
  11_call_shapes:gcc:O2:call_result_drives_branch \
  --full --show --allow-stale
2 passed

uv run python tools/dectest.py \
  11_call_shapes:gcc:O0:call_twice_and_combine \
  11_call_shapes:gcc:O2:call_twice_and_combine \
  --full --show --allow-stale
2 passed

python3 tools/gen_test_census.py
5,191 declared; 0 never executed by any gate

python -m pytest python/tests/test_test_census.py -q
6 passed in an isolated archive of exact source commit 37fb9aa7
```

The extension rebuild completed after this change. A concurrent lane then
touched uncommitted `src/disasm/native_aarch64.rs`, so `dectest` correctly
reported the repository as globally newer than the extension. The explicit
override above tests the already-built call-result code but is not evidence for
that concurrent disassembler edit.

No broad suite, DecBench run, or corpus sweep ran. This closes one production
display-name reader; it does not complete copy-propagation migration, universal
consumer attribution, origin closure, or WP3.
