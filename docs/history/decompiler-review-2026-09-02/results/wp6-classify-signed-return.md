# WP6 `classify` signed-result recovery

> **Kind:** record · **Date:** 2026-09-05

## Result

The increment containing this record completes the remaining O0 signed-result
part of the review's `classify` vertical slice. The result-type join now treats
an x86-64 32-bit-to-64-bit zero-extension as ABI transport and consults the
exact SSA source fact. An all-ones result constant is explicitly ambiguous: it
adopts an independently proved same-width signed or unsigned interpretation,
but never chooses signedness by itself.

The final typed-AST cleanup consumes that resolved result fact. For a signed
32-bit result it removes both the machine-wide zero-extension and the redundant
unsigned 32-bit transport view. It retains the source-width cast for a genuinely
unsigned result. No rendered name or folded predicate shape participates in
the type decision.

Across GCC and Clang O0, with DWARF and after `strip --strip-debug`, the signed
fixture now has the same essential output:

```c
int classify(int arg0) {
    if (0 <= arg0) {
        while (100 < arg0) {
            arg0 -= 100;
        }
        return arg0;
    } else {
        return -1;
    }
}
```

Commit `2be036eb` completed the adjacent expression/type cleanup. The typed
comparison renderer now removes a signed widening only when the operand's
selected declaration is a narrower signed integer and the other operand is a
literal representable at that narrower width. The same cast is retained for a
wider literal, unsigned declaration, unsigned relation, or non-register
expression. This is a destination-declaration rule, not a spelling rewrite.

## Production boundaries

- `src/ir/types_recover/result_hint.rs` preserves the exact forwarded source
  interpretation through a result-register zero-extension and defers the
  signedness of an all-ones constant to the multi-return join.
- `src/ir/types_recover.rs` supplies exact SSA source evidence and records
  whether a branch-local literal is null or all-ones.
- `src/ir/ast/return_ctype.rs` removes only ABI transport casts consistent with
  the resolved declaration.
- `src/ir/ast.rs` contains signed-removal and unsigned-preservation contracts.

## Focused proof and refusal evidence

```bash
cargo test --features python-ext result_hint::tests --lib
cargo test --features python-ext typed_signed_return_conversion --lib
cargo test --features python-ext typed_unsigned_return_conversion --lib
```

Results: four result-join/source-transport tests and both AST cast-boundary
tests passed. They cover signed and unsigned forwarded sources, a mismatched
source width, all-ones with independently signed or unsigned evidence,
all-ones without other evidence, and conflicting widths.

## Release-built compiler evidence

```bash
uv run maturin develop --release
uv run pytest -q python/tests/test_classify_signed_loop.py -vv
```

Result: 2 parameterized compiler tests passed. Each test checks debug and
stripped binaries, for eight rendered function cells in total:

| compiler | debug state | signed result | unsigned control |
|---|---|---|---|
| GCC | DWARF | signed, 34/34 differential | unsigned, 31/31 differential |
| GCC | stripped | signed, 34/34 differential | unsigned, 31/31 differential |
| Clang | DWARF | signed, 34/34 differential | unsigned, 31/31 differential |
| Clang | stripped | signed, 34/34 differential | unsigned, 31/31 differential |

Every signed cell requires `int classify(...)`, the simplified relational
loop, direct `return n`, `return -1`, no redundant unsigned return cast,
parseable C, and execution agreement. The sibling `classify_unsigned` includes
an unsigned relation and unsigned shift; every cell must retain an unsigned
parameter and return and pass its execution differential.

The release scoped corpus command was:

```bash
uv run python tools/dectest.py \
  @loops @polarity @switch @widths --jobs 8 --full
```

Result: 24 of 838 fixture lanes selected, all printed verdicts passed, and the
harness reported zero regressions in scope.

## Repository gates

The implementation landed in `5fdd0c8f`; the exact validation checkout was
`74f425fe`, which also contains the adjacent source-metrics and internal-doc
commits. In that clean detached worktree, after `uv sync --locked --dev` and
`uv run maturin develop --release`, the required Rust command was:

```bash
cargo test --features python-ext
```

Result: **green** -- 4,314 passed, 0 failed, and 17 ignored across the library,
integration, and doc-test targets.

The required whole Python command was:

```bash
uv run pytest python/tests/ -q \
  --junitxml="$TMPDIR/pytest-74f425fe.xml"
```

Result: **red** -- 5,695 tests collected; 4,599 passed, 121 failed, and 975
skipped in 2,610.881 seconds. The two parameterized
`test_classify_signed_loop.py` tests passed in this full run as well as in the
focused run. The failures span many independent repository groups, including
baseline improvement ratchets, architecture fixtures, declaration authority,
documentation manifests, fitness limits, and existing decompiler invariants.
They are not silently reclassified as success and no baseline was refreshed.

This evidence completes the focused `classify` behavior and its exact-commit
Rust gate, but it does **not** establish a repository-wide green release. The
JUnit report is retained at the command's path above for failure triage.

## Follow-on cast-cleanup evidence

At source commit `2be036eb`, after a release extension rebuild:

- the focused GCC/Clang test passed both parameterized cases, covering all
  eight signed/unsigned debug/stripped function cells and their 34/31-case
  execution differentials;
- all 216 `ir::ast::tests` passed;
- `tools/dectest.py @loops @polarity @switch @widths --jobs 8 --full`
  selected 24 of 838 lanes and reported zero scoped regressions;
- `cargo test --features python-ext` passed 4,315 tests with 0 failures and 17
  ignored.

The whole Python suite at that exact source commit collected 5,695 tests:
4,615 passed, 115 failed, and 965 skipped in 2,732.810 seconds. Compared with
the preceding exact run at `74f425fe`, seven failure identities disappeared
and one appeared. The one addition was the expected stale generated test
census after adding the Rust refusal test; commit `8e3fb83d` refreshes only
that census (4,574 to 4,575 total declarations; `ir` 2,069 to 2,070), and all
six census tests then pass. The remaining broad Python failures are still not
a green release claim.
