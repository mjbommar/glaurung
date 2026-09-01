"""Mach-O at x86-64 and ARM64: identity, and where the ABIs diverge.

Why a two-architecture lane
---------------------------

Mach-O coverage was a single tracked x86-64 sample with reachable triage and no
decompiler-semantic assertions at all -- no ARM64, no recovered prototypes.
Building the *same three functions* for both architectures makes the ABI the
only variable, and that is immediately worth something: `mix_float` recovers
exactly on x86-64 and recovered as `void(void)` on ARM64, from identical source.

zig builds these with its bundled darwin linker, so the lane needs no macOS
machine and no Xcode.

The `_` prefix, and why it matters here
---------------------------------------

Mach-O decorates C symbols with a leading underscore, exactly as i386 cdecl
does. The DecBench resolver's `_name` fallback therefore resolves these without
knowing anything about Mach-O -- which is worth asserting, because it is the
one piece of the i386 decoration ladder that generalises to another format, and
a future change that narrows the fallback to PE would silently break Mach-O.

The CLI does NOT apply that fallback: `--func local_body` errors and suggests
`_local_body`. Pinned below as current behaviour rather than asserted as
correct.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURE_DIR = ROOT / "tests" / "macho_lane"
sys.path.insert(0, str(ROOT / "tools"))

import decbench_symbols as S  # ty: ignore[unresolved-import]  # added above

ARCHES = ["x86_64", "aarch64"]
FUNCS = ["local_body", "calls_local", "mix_float"]


def dylib(arch: str) -> Path:
    return FIXTURE_DIR / f"lib_{arch}.dylib"


@pytest.fixture(scope="module", params=ARCHES, ids=ARCHES)
def target(request) -> tuple[str, Path]:
    p = dylib(request.param)
    if not p.is_file():
        pytest.skip(f"{p.name} absent")
    return request.param, p


def decompile(path: Path, func: str) -> str:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "glaurung.cli",
            "decompile",
            str(path),
            "--func",
            func,
            "--style",
            "decbench",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=600,
        check=False,
    )
    return proc.stdout if proc.returncode == 0 else ""


def signature(path: Path, func: str) -> str:
    for line in decompile(path, func).splitlines():
        if func + "(" in line and not line.startswith("//"):
            return line.split("{")[0].strip()
    raise AssertionError(f"no signature for {func} in {path.name}")


def test_the_fixtures_match_their_manifest():
    m = json.loads((FIXTURE_DIR / "MANIFEST.json").read_text())
    for name, rec in m.items():
        if not isinstance(rec, dict):
            continue
        p = FIXTURE_DIR / name
        assert p.is_file(), f"{name} is committed; the checkout is broken"
        assert hashlib.sha256(p.read_bytes()).hexdigest() == rec["sha256"], name


def test_the_symbol_table_is_read(target):
    _, p = target
    rows = [e for e in S.load_entries(str(p)) if e.is_code and e.defined]
    names = {e.name for e in rows}
    assert {"_local_body", "_calls_local", "_mix_float"} <= names, sorted(names)


@pytest.mark.parametrize("func", FUNCS)
def test_the_underscore_fallback_generalises_to_macho(target, func):
    """The i386 cdecl rule resolves Mach-O too, and must keep doing so."""
    _, p = target
    r = S.resolve(func, S.load_entries(str(p)))
    assert r.ok, f"{func}: {r.disposition}"
    assert r.decoration is S.Decoration.CDECL
    assert r.raw_symbol == "_" + func


@pytest.mark.parametrize("func", FUNCS)
def test_every_function_decompiles_to_a_body(target, func):
    """No function may be lost. This is the floor the lane defends."""
    arch, p = target
    code = decompile(p, "_" + func)
    assert code, f"{arch}: _{func} produced no output"
    assert code.count("\n") >= 3, f"{arch}: _{func} is a stub:\n{code}"


def test_integer_prototypes_agree_across_the_two_abis(target):
    """`local_body(int,int)` has no float, and both ABIs must recover it."""
    _, p = target
    sig = signature(p, "_local_body")
    assert sig.count(",") == 1, f"expected two parameters: {sig}"
    assert "int" in sig, sig


def test_x86_64_recovers_the_float_prototype_exactly():
    """The control for the ARM64 case below: identical source, correct here."""
    p = dylib("x86_64")
    if not p.is_file():
        pytest.skip("fixture absent")
    assert signature(p, "_mix_float") == (
        "double _mix_float(double arg0, float arg1)"
    ), "x86-64 used to recover this exactly; a change here is a real regression"


def test_arm64_float_prototype_is_pinned_as_the_open_defect():
    """ARM64 loses the signature of a function ending in `fmadd`.

    `double mix_float(double d, float f)` lowers on ARM64 to
    `fcvt d1,s1; fmov d2,#2.0; fmadd d0,d0,d2,d1`. The `fmov` immediate is
    recovered (it used to be dropped by the operand decoder), but `fmadd`
    is not lifted, so `d0` -- the return register -- has no definition and the
    whole prototype collapses.

    **Lifting `fmadd` is not on its own the fix, and this is the interesting
    part.** Mapping it to an opaque intrinsic was tried and measured: it
    recovered the full signature AND broke
    `217_complex_arithmetic:aarch64:O2:complex_add_conj` from pass to fail,
    because the emitted C then calls `__unknown(0)` and uses its result. A
    definition the renderer cannot express is worse than no definition. FMA
    needs a ternary form in `float_gate`'s operator table -- it is neither
    `Binary` nor `Move` -- before it can be lifted.
    """
    p = dylib("aarch64")
    if not p.is_file():
        pytest.skip("fixture absent")
    sig = signature(p, "_mix_float")
    assert sig == "void _mix_float(void)", (
        f"ARM64 float prototype changed: {sig!r}\n"
        "If FMA rendering landed, update this pin -- and re-run "
        "`dectest 217_complex_arithmetic --arch aarch64`, which is the cell "
        "that caught the naive version."
    )


def test_the_float_constant_is_recovered_on_arm64():
    """`fmov d2, #2.0` must survive the decoder.

    Capstone reports a scalar FP immediate as `Arm64OperandType::Fp`, which the
    operand extractor dropped into its catch-all -- so the instruction arrived
    with one operand, failed its arity check and lifted to nothing. Same shape
    as the ARM32 `SysReg` drop.
    """
    p = dylib("aarch64")
    if not p.is_file():
        pytest.skip("fixture absent")
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "glaurung.cli",
            "decompile",
            str(p),
            "--func",
            "_mix_float",
            "--style",
            "c",
            "--no-color",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        timeout=600,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    assert "2.0" in proc.stdout, (
        "the float immediate was dropped by the operand decoder:\n" + proc.stdout
    )
