# WP3 ARM32 frame expression origins

Date: 2026-09-08

Commit: `4b748faa`

## Defect and repair

The ARM32 frame pass is transactional: it removes A32 or Thumb frame
bookkeeping only when save widths, promoted storage identities, teardown order,
and every lexical return path balance. Statement origins were already
transparent, but origins on child expressions prevented those same proofs from
being recognized and left the complete machine frame in decompiled C.

`src/ir/arm32_prologue.rs` now uses `Expr::semantic()` for saved values,
promoted save addresses, stack arithmetic and operands, frame-pointer setup and
deallocation, promoted-record locations, and restored values. None of the
transaction's width, register-role, identity, ordering, or all-return-path
requirements were relaxed.

## Focused validation

The existing attributed Thumb-frame ownership contract now gives independent
origins to the stack-adjust expression and operands, save addresses and values,
frame-pointer address, and restored dereference. It was observed red before the
repair with all eight input statements surviving. After the repair, the owning
module passes:

```text
running 12 tests
............
test result: ok. 12 passed; 0 failed; 0 ignored; 4684 filtered out
```

No repository-wide Rust or Python suite ran. Release validation used a detached
clean worktree at the implementation commit and a cache-backed build directory:

```bash
export TMPDIR=/home/mjbommar/.cache/glaurung/tmp
export CARGO_TARGET_DIR=/home/mjbommar/.cache/glaurung/wp3-arm-anchor-release-target
uv sync --locked --dev
uv run maturin develop --release
uv run python tools/build_guard.py
uv run pytest \
  'python/tests/test_linux_arm_hello_canonical.py::test_dynamic_hello_is_canonical[symbols-pie-O0-armv7]' \
  -q
```

The extension was fresh. The exact Hello World cell remains non-canonical: it
still emits `__attribute__((no_stack_protector))`, an eight-byte local frame
object, and an `lr` local around the otherwise recovered `puts` call and zero
return. This is the previously recorded ARMv7 known-red class, not a passing
result and not evidence of broad ARM32 closure.

This increment closes the ARM32 frame recognizer's known raw-expression
readers. The Hello failure shows that adjacent ARM32 frame/local presentation
work remains, alongside universal WP3 attribution and explicit invalidation.
