"""Recovered wide arithmetic must name a type its own target can spell.

`__int128` is a 64-bit-target extension. A 32x32 multiply-high — which is what
every division by a constant lowers to — is the *most common* place the
renderer reaches for a double-width intermediate, and it happens overwhelmingly
on 32-bit targets (i386, ARM32, PE32).

`tools/arch_roundtrip.py` cannot see this defect by construction: it declares
`__int128` an *unsupported source* on its 32-bit lanes (a fixture whose C uses
the type has no i386/armv7 form at all), and it rebuilds recovered C at the
host pointer width, where the type exists. So its four green lanes are
compatible with the renderer emitting `__int128` for every 32-bit binary in the
corpus — which is exactly what it did.

These tests close that hole from the other side: a REAL 32-bit binary is built,
decompiled, and the recovered C is recompiled *as 32-bit code*, which is the
only compile that can reject the type.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
sys.path.insert(0, str(ROOT / "tools"))

import diff_decompile as D  # ty: ignore[unresolved-import]  # added above
import manifest as M  # ty: ignore[unresolved-import]  # added above

pytestmark = pytest.mark.slow  # ty: ignore[unresolved-attribute]

#: Constant divisors and a widening multiply: every one of these lowers to a
#: 32x32 multiply-high or a double-width divide on a 32-bit target.
_SOURCE = """
unsigned int div_by_ten(unsigned int value) { return value / 10u; }
int div_by_three(int value) { return value / 3; }
unsigned int mul_high(unsigned int a, unsigned int b) {
    return (unsigned int)(((unsigned long long)a * (unsigned long long)b) >> 32);
}
unsigned int mod_by_seven(unsigned int value) { return value % 7u; }
"""

#: ``(arch, compiler, flags, recovers_double_width)``. Both lifters retain the
#: multiply-high operation as a typed double-width intermediate. This makes the
#: same-target rebuild non-vacuous on ARM32 as well as i386: signedness and the
#: target's available C integer widths must survive the IR boundary.
_TARGETS = (
    ("i386", "gcc", ("-m32",), True),
    (
        "armv7",
        "arm-linux-gnueabihf-gcc",
        ("-march=armv7-a", "-mfpu=vfpv3-d16", "-mthumb"),
        True,
    ),
)


def _toolchain(compiler: str, extra: tuple[str, ...]) -> str | None:
    """The compiler, only if it can actually produce this 32-bit object here."""
    if shutil.which(compiler) is None:
        return None
    with tempfile.TemporaryDirectory(dir=M.tmpdir() or None) as directory:
        probe = Path(directory) / "probe.c"
        probe.write_text("int probe(int x){ return x + 1; }\n")
        built = subprocess.run(
            [
                compiler,
                *extra,
                "-O2",
                "-shared",
                "-fPIC",
                str(probe),
                "-o",
                str(Path(directory) / "probe.so"),
            ],
            capture_output=True,
            check=False,
        )
    return compiler if built.returncode == 0 else None


def _build(compiler: str, extra: tuple[str, ...], directory: Path) -> Path:
    source = directory / "wide.c"
    source.write_text(_SOURCE)
    target = directory / "wide.so"
    built = subprocess.run(
        [
            compiler,
            *extra,
            "-O2",
            "-shared",
            "-fPIC",
            "-g",
            str(source),
            "-o",
            str(target),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert built.returncode == 0, built.stderr
    return target


@pytest.mark.parametrize(  # ty: ignore[unresolved-attribute]
    ("arch", "compiler", "extra", "recovers_double_width"), _TARGETS
)
def test_wide_arithmetic_never_names_int128_on_a_32_bit_target(
    arch: str, compiler: str, extra: tuple[str, ...], recovers_double_width: bool
) -> None:
    """The recovered C must compile *as 32-bit code*, which rejects `__int128`."""
    available = _toolchain(compiler, extra)
    if available is None:
        pytest.skip(f"no working {arch} toolchain ({compiler}) on this host")

    with tempfile.TemporaryDirectory(prefix=f"glaurung-wide-{arch}-") as directory:
        workdir = Path(directory)
        binary = _build(available, extra, workdir)
        functions = D.exported_functions(str(binary))
        assert functions, f"no exported functions in the {arch} fixture"

        recovered: dict[str, str] = {}
        for name, va in sorted(functions.items()):
            code = D.decompiled_c(str(binary), va)
            if code:
                recovered[name] = code
        assert recovered, f"nothing decompiled from the {arch} fixture"

        for name, code in recovered.items():
            assert "__int128" not in code, (
                f"{arch}/{name} names a type that does not exist on a 32-bit "
                f"target:\n{code}"
            )

        # Non-vacuity: on a target whose lifter does recover the double-width
        # intermediate, it must be present — otherwise "no `__int128`" is
        # satisfied by recovering nothing at all.
        if recovers_double_width:
            assert any("long long" in code for code in recovered.values()), (
                f"{arch} recovered no double-width arithmetic at all, so the "
                f"absence of `__int128` proves nothing:\n{recovered}"
            )

        # The real oracle: recompile the recovered C for the SAME target. A
        # host-width rebuild would accept `__int128` and prove nothing.
        fragment = workdir / "recovered.c"
        fragment.write_text("\n".join(recovered.values()) + "\n")
        rebuilt = subprocess.run(
            [
                available,
                *extra,
                "-O2",
                "-c",
                "-fno-builtin",
                "-w",
                str(fragment),
                "-o",
                str(workdir / "recovered.o"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert rebuilt.returncode == 0, (
            f"{arch} recovered C does not build for its own target:\n"
            f"{rebuilt.stderr}\n{fragment.read_text()}"
        )


def test_x86_64_wide_arithmetic_still_uses_the_128_bit_intermediate() -> None:
    """The control: 64-bit operands genuinely need `__int128`, and keep it."""
    source = (
        "unsigned long mul_high64(unsigned long a, unsigned long b) {\n"
        "    return (unsigned long)(((unsigned __int128)a * b) >> 64);\n"
        "}\n"
    )
    with tempfile.TemporaryDirectory(prefix="glaurung-wide-x86_64-") as directory:
        workdir = Path(directory)
        path = workdir / "wide64.c"
        path.write_text(source)
        binary = workdir / "wide64.so"
        built = subprocess.run(
            ["gcc", "-O2", "-shared", "-fPIC", "-g", str(path), "-o", str(binary)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert built.returncode == 0, built.stderr

        va = D.exported_functions(str(binary))["mul_high64"]
        code = D.decompiled_c(str(binary), va)
        assert code is not None
        assert "__int128" in code, (
            f"a genuine 64x64 multiply-high still needs the 128-bit type:\n{code}"
        )
