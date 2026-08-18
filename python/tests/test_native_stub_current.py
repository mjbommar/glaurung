"""The `glaurung._native` stubs must match the extension that is built.

`glaurung._native` is a compiled PyO3 `.so`. No type checker can read it, so
without stubs every attribute reached through it -- which is most of the
analysis surface -- is invisible. `python/glaurung/_native/*.pyi` supplies
that surface, generated from the built module by `tools/gen_native_stub.py`.

A stub that drifts is worse than no stub: it makes the checker confidently
wrong about code that changed underneath it. This repository has already
paid for that twice over.

  * `python/glaurung/__init__.pyi` was a hand-written 1,532-line stub of the
    native surface. By 2026-08-18 it had drifted far enough to account for
    roughly 1,400 of the 2,004 diagnostics `ty` reported -- reporting real
    functions as missing while silently vouching for signatures nobody had
    checked in months.
  * `python/pytest/__init__.pyi` was a five-line hand stub that shadowed the
    real, fully typed pytest on the first-party search path, blanking the
    entire `pytest` module and producing 417 further diagnostics.

Both were deleted. This test is what stops the replacement from going the
same way: it regenerates every stub from the module that is actually
imported and fails on any difference, so a Rust signature change cannot land
with a stale stub still describing the old one.

When this fails, the fix is never to edit the `.pyi` by hand::

    uv run maturin develop --release
    uv run python tools/gen_native_stub.py

The generator only ever reports arity, parameter names and defaults --
everything is typed `Any` -- because PyO3 exposes no type information. That
keeps the stub sound: it can catch a call with the wrong argument count or a
misspelled keyword, and it never invents a constraint the Rust side does not
impose.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
GENERATOR = ROOT / "tools" / "gen_native_stub.py"
STUB_PKG = ROOT / "python" / "glaurung" / "_native"


def _load_generator():
    spec = importlib.util.spec_from_file_location("_gen_native_stub", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generated() -> dict[Path, str]:
    gen = _load_generator()
    return gen._generate()


def test_generator_is_present() -> None:
    """The stubs are generated output; the generator must ship with them."""
    assert GENERATOR.is_file(), f"missing {GENERATOR}"
    assert STUB_PKG.is_dir(), f"missing {STUB_PKG}"


def test_the_comparison_is_not_vacuous() -> None:
    """A stale `.so` would let a stale stub match it.

    Everything below compares the stubs against the extension that is
    *imported*. If that extension predates the Rust it was built from, the
    comparison is between two equally old descriptions and passes while both
    are wrong -- the same stale-build trap `tools/build_guard.py` exists to
    close for fixture verdicts. Report it rather than pass quietly.
    """
    sys.path.insert(0, str(ROOT / "tools"))
    import build_guard  # ty: ignore[unresolved-import]

    reason = build_guard.stale_reason(build_guard.native_so())
    if reason is not None:
        pytest.skip(
            f"stub/extension comparison would be vacuous: {reason}; "
            "rebuild with `uv run maturin develop --release`"
        )


def test_every_stub_matches_the_built_module(generated: dict[Path, str]) -> None:
    """Regenerate from the imported `.so` and require a byte-for-byte match."""
    stale: list[str] = []
    for path, expected in sorted(generated.items()):
        rel = path.relative_to(ROOT)
        if not path.exists():
            stale.append(f"{rel}: missing")
            continue
        actual = path.read_text()
        if actual != expected:
            stale.append(
                f"{rel}: {len(actual.splitlines())} lines on disk vs "
                f"{len(expected.splitlines())} generated"
            )
    assert not stale, (
        "native stubs are stale against the built extension:\n  "
        + "\n  ".join(stale)
        + "\n\nregenerate with:\n"
        "  uv run maturin develop --release\n"
        "  uv run python tools/gen_native_stub.py"
    )


def test_no_stub_outlives_the_submodule_it_described(
    generated: dict[Path, str],
) -> None:
    """A stub for a submodule that no longer exists is drift too.

    Same shape as `test_no_review_entry_outlives_the_file_it_reviewed` in
    `test_large_module_review.py`: removing the subject must remove the
    record, or the record starts lying.
    """
    orphans = [
        str(p.relative_to(ROOT))
        for p in sorted(STUB_PKG.glob("*.pyi"))
        if p not in generated
    ]
    assert not orphans, (
        "stub files describe submodules the extension no longer exports: "
        + ", ".join(orphans)
    )


def test_public_surface_is_fully_covered(generated: dict[Path, str]) -> None:
    """Every public name on the built module appears in its stub.

    Byte equality above already implies this, but it is the property that
    actually matters, and it fails with a message naming the missing symbol
    rather than a line count.
    """
    import types

    import glaurung._native as native

    def public(obj: object) -> set[str]:
        return {
            k
            for k in vars(obj)
            if not k.startswith("_") and not isinstance(vars(obj)[k], types.ModuleType)
        }

    checks: list[tuple[str, Path, set[str]]] = [
        ("glaurung._native", STUB_PKG / "__init__.pyi", public(native))
    ]
    for name, value in vars(native).items():
        if isinstance(value, types.ModuleType):
            checks.append(
                (f"glaurung._native.{name}", STUB_PKG / f"{name}.pyi", public(value))
            )

    missing: list[str] = []
    for mod_name, stub_path, names in checks:
        text = generated.get(stub_path, "")
        for symbol in sorted(names):
            if not symbol.isidentifier():
                # Exported under a name Python cannot spell; the generator
                # reports these separately and cannot stub them.
                continue
            if symbol not in text:
                missing.append(f"{mod_name}.{symbol}")
    assert not missing, "stub omits public names: " + ", ".join(missing)
