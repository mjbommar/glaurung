# WP3 x86 prologue expression origins

Date: 2026-09-08

Commit: `ef95b49a`

## Defect and repair

The canonical x86 frame recognizer collapses `push rbp; rbp = rsp; rsp -= N`
into one source-level prologue annotation. Its statement-level provenance was
already preserved, but several shape checks inspected raw expressions.
Attaching an origin carrier to the pushed value, frame-pointer source,
stack-adjust base, or allocation width made the same prologue fail to match and
left machine frame setup visible in decompiled C.

`src/ir/x86_prologue.rs` now classifies those values through their semantic
expression. The same treatment covers the promoted two-statement save form and
the shared positive `rsp` adjustment readers. Register identity, promoted-slot
authority, exact store width, adjacency, and positive allocation constraints
remain unchanged.

## Focused validation

The end-to-end contract `expression_attributed_full_prologue_still_collapses`
was observed red with all four input statements surviving. It passes after the
repair with the canonical 32-byte frame comment and return. The complete owning
module passes:

```text
running 45 tests
test result: ok. 45 passed; 0 failed; 0 ignored; 4651 filtered out
```

No repository-wide Rust or Python suite ran. Release validation used a detached
clean worktree at the implementation commit and cache-backed build directories:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-arm-anchor-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/build_guard.py
uv run pytest \
  'python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O0-gcc]' \
  'python/tests/test_linux_x86_64_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O2-gcc]' \
  -q
```

Results:

```text
native extension: fresh
2 passed
```

These are two exact release-built Hello World cells, not the full Hello
collection or repository suite. This increment closes the canonical frame
setup path, not every specialized x86/cdecl prologue form or universal WP3
expression attribution.
