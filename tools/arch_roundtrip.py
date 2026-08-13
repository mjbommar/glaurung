#!/usr/bin/env python3
"""Execution differential for EVERY architecture the lifters claim to support.

    tools/arch_roundtrip.py                     # the required matrix, summary
    tools/arch_roundtrip.py --check             # ratchet against arch_baseline.json
    tools/arch_roundtrip.py --write-baseline    # regenerate arch_baseline.json
    tools/arch_roundtrip.py --arch aarch64 --opt O0 03_loop_shapes   # one cell

WHY THIS EXISTS
---------------
`tools/fixture_harness.py` is the behavioural gate, and every lane of its matrix
(`{gcc, clang} x {O0, O2}`) is x86-64 on the host. Glaurung lifts three
architecture families — x86/x86-64 (`src/ir/lift_x86.rs`), ARM32
(`src/ir/lift_arm32.rs`) and AArch64 (`src/ir/lift_arm64.rs`) — so two of the
three had *no* execution coverage at all, and 32-bit x86 had none either. ARM32
is exercised in both Thumb-2 and A32 encodings because sharing a lifter does not
make their decode paths interchangeable. A
change that inverted a branch in every ARM binary would have left all 656 cases
green. This lane closes that hole.

HOW EXECUTION IS KEPT ABI-HONEST
--------------------------------
For 64-bit targets the recovered artifact is portable C, so it does not have to
run on the target.  Both sides of that comparison build for the host:

    fixture.c --(cross cc)--> target .so --(glaurung)--> recovered.c --(cc)--> B
    fixture.c ---------------------(cc)-------------------------------------> A

A and B are called with identical seeded vectors and every full-width return and
mutated buffer is compared.  This is ABI-honest for x86-64 and AArch64 because
both sides are LP64.

For i386 and ARMv7, rebuilding a target C++ object at LP64 is not portable: its
pointer fields, aggregate offsets, and exported helper ABI change.  A generated,
dependency-free C worker therefore rebuilds the recovery for the target, loads
the original target object and recovery together, and compares them under
`qemu-i386`/`qemu-arm`.  The worker currently supports integer scalars and
integer/byte buffers; richer aggregate signatures retain the audited portable-C
fallback below.  Runner command lines and versions are baseline fingerprints,
so an emulator change cannot silently redefine the ratchet.

WHAT IS BORROWED, AND WHY NOTHING IS REIMPLEMENTED
--------------------------------------------------
Judging is `tools/diff_decompile.py` — invoked as a subprocess exactly the way
`fixture_harness._run_lane` invokes it, with `--reference-so` naming the host
build. An earlier prototype hand-rolled the per-function loop and skipped the
manifest overrides, the structural classification, and local-callee inclusion; it
produced 50 "AArch64 failures" that were entirely its own. This file therefore
owns exactly two things `fixture_harness` cannot: which compiler builds the
fixture, and which object the recovery is executed against.

THE 32-BIT FALLBACK, AND WHAT IS DONE ABOUT IT
----------------------------------------------
The target worker gives supported scalar/pointer signatures a genuine ILP32
verdict.  Signatures outside that generated subset still rebuild at the host's
pointer width, so that explicit residue is attacked from three sides:

1. `incomparable` — the host reference's own DWARF prototype is now compared
   against the target's, and a function whose ABI types differ between the two
   builds gets NO execution verdict. `long` is 4 bytes on i386/ARM32 and 8 on
   the host, so `long count_up(int)` was being called with a 32-bit argument
   through a 64-bit prototype and its 64-bit return truncated before comparison;
   16 measurements per 32-bit lane were `pass` for that reason alone. They are
   not passes. See `diff_decompile.abi_incomparable`.
2. `nonportable` — every recovered body is now ALSO compiled with the target's
   own driver (`gcc -m32`, `arm-linux-gnueabihf-gcc`), object only. The host
   rebuild accepts C no 32-bit target can compile — `__int128` above all, which
   the renderer emitted for every 32-bit multiply-high until `double_width_ctype`
   fixed it, a defect DecBench caught and four green lanes here could not. See
   `diff_decompile.native_rebuild_diagnostic`.
3. `--width-audit` splits the surviving 32-bit failures into those whose
   recovered C names a type whose size changes between ILP32 and LP64 (a
   possible portability artifact) and those that name none (a real semantic
   defect, since a 64-bit rebuild of such a fragment is value-identical to a
   32-bit one). See `diff_decompile.width_sensitive`.

The 64-bit lanes carry no such caveat.  For 32-bit signatures the result detail
distinguishes target-worker verdicts from the host fallback, and
`--width-audit` quantifies only fallback failures; it must never relabel one as a
pass.  The generated worker has real i386 non-vacuity coverage that proves both
return and buffer mismatches are detected, while the x86-64 control remains the
independent whole-harness control.

TOOLCHAIN
---------
The reference build and the rebuild of our own decompiled C always run under the
pinned image (`tests/decompiler_fixtures/toolchain/Dockerfile`), exactly as the
x86-64 gate does. The FIXTURE build does too — for `x86_64`, with byte-identical
flags to `fixture_harness.compile_fixture`, which is what lets
`control_gate_disagreements` demand that the control lane reproduce
`tests/decompiler_fixtures/baseline.json` function for function. The image ships
no cross toolchains and no multilib, so the other five lanes are built
by host compilers; each version string is recorded per-arch in `__toolchain__`,
tagged `pinned:`/`host:`, and asserted by `--check`. An upgrade therefore fails
loudly with a refresh instruction instead of silently moving what the baseline
means.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
DIFF = ROOT / "tools" / "diff_decompile.py"
BASELINE = ROOT / "tests" / "decompiler_fixtures" / "arch_baseline.json"
#: The x86-64 gate's committed verdicts. The control lane must reproduce them
#: exactly — see `control_gate_disagreements`.
X86_BASELINE = ROOT / "tests" / "decompiler_fixtures" / "baseline.json"

sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import build_guard as BG
import fixture_harness as H
import fixture_toolchain as TC
import manifest as M  # ty: ignore[unresolved-import]


@dataclass(frozen=True)
class Arch:
    """One target architecture and the flags that pick the lifter path."""

    cc: str
    #: Flags that decide which lifter path the produced binary exercises.
    cflags: tuple[str, ...]
    #: Pointer width in bytes, as built. 4 means the 32-bit confound above.
    pointer_bytes: int
    #: Build the fixture under the PINNED image rather than with host compilers.
    #: Only possible where the image has the compiler: it ships plain x86-64
    #: gcc/g++/clang with no multilib and no cross toolchains, so this is true for
    #: `x86_64` alone — and that is exactly what makes the control lane
    #: bit-comparable to `tests/decompiler_fixtures/baseline.json`.
    pinned: bool
    why: str


#: `-mfloat-abi=hard` is the armhf toolchain default and cc1 refuses outright
#: unless an FPU is named. Thumb-2 remains the primary distro-shaped lane; A32
#: is deliberately separate so a decode/convention defect cannot hide behind
#: Thumb-only coverage.
TARGETS: dict[str, Arch] = {
    "x86_64": Arch(
        "gcc",
        (),
        8,
        True,
        "the CONTROL lane: same architecture on both sides, built by the same "
        "pinned compiler with the same flags as `fixture_harness`, so its "
        "verdicts must equal that gate's `gcc:{opt}` verdicts function for "
        "function. Nothing about a foreign lifter is involved; if it is not "
        "clean, no verdict on any other lane means anything.",
    ),
    "x86_64_gcc15": Arch(
        "gcc",
        (),
        8,
        False,
        "the host-GCC shape control: same x86-64 lifter and flags as the pinned "
        "control, but the GCC 15 compiler used by the foreign host-built lanes. "
        "Differences isolated here are compiler-shape effects, not architecture "
        "gaps.",
    ),
    "i386": Arch(
        "gcc",
        ("-m32",),
        4,
        False,  # the pinned image has no gcc-multilib
        "32-bit x86 — the other half of src/ir/lift_x86.rs, which the x86-64 "
        "gate never exercises.",
    ),
    "aarch64": Arch(
        "aarch64-linux-gnu-gcc",
        ("-march=armv8-a",),
        8,
        False,
        "src/ir/lift_arm64.rs",
    ),
    "armv7": Arch(
        "arm-linux-gnueabihf-gcc",
        ("-march=armv7-a", "-mfpu=vfpv3-d16", "-mthumb"),
        4,
        False,
        "src/ir/lift_arm32.rs, Thumb-2",
    ),
    "armv7_a32": Arch(
        "arm-linux-gnueabihf-gcc",
        ("-march=armv7-a", "-mfpu=vfpv3-d16", "-marm"),
        4,
        False,
        "src/ir/lift_arm32.rs, A32",
    ),
}

#: The control lane proves the apparatus. It is first-class, it is always run,
#: and it is required to be clean — see `control_problems`.
CONTROL_ARCH = "x86_64"

REQUIRED_ARCHES = (
    "x86_64",
    "x86_64_gcc15",
    "i386",
    "aarch64",
    "armv7",
    "armv7_a32",
)
REQUIRED_OPTS = ("O0", "O2")
REQUIRED_MATRIX = [(arch, opt) for arch in REQUIRED_ARCHES for opt in REQUIRED_OPTS]

#: Prefix of the `__lane__` value marking a lane whose SOURCE cannot exist for the
#: target at all (see `detect_unsupported`). Every such lane is probed, and
#: `_run_lane` asserts the build genuinely fails — it is a declared gap, never a
#: silent skip. Any other `__lane__` value is a hard failure.
UNSUPPORTED_PREFIX = "unsupported: "


def lane_key(fixture: str, arch: str, opt: str) -> str:
    return f"{fixture}:{arch}:{opt}"


def sources() -> list[Path]:
    return sorted(list(SRC.glob("*.c")) + list(SRC.glob("*.cpp")))


def compiler_for(arch: str, src: Path) -> str:
    """The driver that builds `src` for `arch` (C++ fixtures need the C++ one)."""
    cc = TARGETS[arch].cc
    if src.suffix != ".cpp":
        return cc
    return re.sub(r"gcc$", "g++", cc)


def _build_argv(compiler: str, src: Path, opt: str, out: Path, cflags=()) -> list[str]:
    """The fixture compile command line.

    Deliberately IDENTICAL to `fixture_harness.compile_fixture`'s execution build
    (`-shared -fPIC -g -O{opt} -w`) plus whatever selects the target. No extra
    flags — not even `-fno-stack-protector`, which the prototype added: the
    x86-64 gate compiles WITH the distribution's default
    `-fstack-protector-strong`, so turning it off here would mean the control
    lane was measuring a code shape the real gate never sees, and the other
    architectures were measuring a code shape no distro ships.
    """
    return [
        compiler,
        "-shared",
        "-fPIC",
        "-g",
        f"-{opt}",
        "-w",
        *cflags,
        "-o",
        str(out),
        str(src),
    ]


def _compiler_available(arch: str, compiler: str) -> bool:
    """A pinned arch's compiler lives in the image, not on `PATH`."""
    return TARGETS[arch].pinned or shutil.which(compiler) is not None


def native_cc(arch: str) -> list[str] | None:
    """The target's own driver + flags, for `diff_decompile.native_rebuild_diagnostic`.

    `None` for the control lane alone: there the "target" compiler IS the host
    one, so the probe would only re-ask a question the pinned rebuild already
    answered — and would do it with a DIFFERENT gcc (host 15.x vs the pinned
    11.4), which could turn a pinned-toolchain acceptance into a host-toolchain
    rejection and make the control lane's cleanliness a property of this machine.
    """
    if arch == CONTROL_ARCH:
        return None
    return [TARGETS[arch].cc, *TARGETS[arch].cflags]


def native_runner(arch: str) -> list[str] | None:
    """Command prefix that executes an ILP32 worker at the target ABI.

    Host-side portable-C execution remains the simpler oracle for both 64-bit
    lanes.  It is not sound for an ILP32 recovery that constructs a target C++
    object and then calls an exported target helper: recompiling that object at
    LP64 changes both pointer fields and aggregate layout.  Those lanes use a
    generated target-native C worker instead.
    """
    if TARGETS[arch].pointer_bytes != 4:
        return None
    if arch == "i386":
        return ["qemu-i386", "-L", "/"]
    if arch in {"armv7", "armv7_a32"}:
        loader = subprocess.run(
            [TARGETS[arch].cc, "-print-file-name=ld-linux-armhf.so.3"],
            capture_output=True,
            text=True,
            check=False,
        )
        if loader.returncode != 0 or not loader.stdout.strip():
            return ["qemu-arm", "-L", "/usr/arm-linux-gnueabihf"]
        sysroot = Path(loader.stdout.strip()).resolve().parent.parent
        return ["qemu-arm", "-L", str(sysroot)]
    raise ValueError(f"no native runner for 32-bit architecture {arch}")


def _cross_build(arch: str, src: Path, opt: str, out: Path) -> tuple[bool, str]:
    """Build the fixture FOR the target.

    Under the pinned image where the image has that compiler (`x86_64` only —
    see `Arch.pinned`), otherwise with host compilers, whose versions are then
    recorded per-arch in `__toolchain__` and asserted by `--check`.
    """
    compiler = compiler_for(arch, src)
    argv = _build_argv(compiler, src, opt, out, TARGETS[arch].cflags)
    if TARGETS[arch].pinned:
        r = TC.run(argv)
    else:
        if shutil.which(compiler) is None:
            return False, f"no such compiler: {compiler}"
        r = subprocess.run(argv, capture_output=True, text=True, check=False)
    return r.returncode == 0, " ".join((r.stderr or "no compiler output").split())


def _reference_build(src: Path, opt: str, out: Path) -> tuple[bool, str]:
    """Build the ground-truth side FOR THE HOST, under the pinned toolchain.

    This is the object whose behaviour the recovery is diffed against, so it is
    pinned for the same reason `fixture_harness` pins its compiles: a reference
    built by whatever compiler a developer happens to ship makes the recorded
    verdict a property of that machine.
    """
    compiler = "g++" if src.suffix == ".cpp" else "gcc"
    r = TC.run(_build_argv(compiler, src, opt, out))
    return r.returncode == 0, " ".join((r.stderr or "no compiler output").split())


# ---------------------------------------------------------------------------
# Declared, probed gaps
# ---------------------------------------------------------------------------


def _supports_int128(arch: str) -> bool:
    with tempfile.TemporaryDirectory(dir=M.tmpdir()) as td:
        src = Path(td) / "p.c"
        src.write_text("__int128 probe(long a){ return (__int128)a * a; }\n")
        ok, _ = _cross_build(arch, src, "O0", Path(td) / "p.so")
        return ok


def _cxx_runtime_ok(arch: str) -> bool:
    """Can this target's C++ driver build+link a program that throws? Probed the
    same way `fixture_harness._cxx_runtime_ok` probes clang's, so a gap recorded
    here is a REAL gap on this host and disappears where the runtime exists."""
    with tempfile.TemporaryDirectory(dir=M.tmpdir()) as td:
        src = Path(td) / "p.cpp"
        src.write_text(
            "int f(int x){ if(x<0) throw x; return x; }\n"
            'extern "C" int probe(int x){ try{ return f(x); }'
            "catch(int e){ return e; } }\n"
        )
        ok, _ = _cross_build(arch, src, "O0", Path(td) / "p.so")
        return ok


def detect_unsupported(arches) -> dict[tuple[str, str], str]:
    """`(arch, fixture) -> reason` for sources that CANNOT exist on a target.

    Two real cases, both probed rather than asserted from a list of names:

    * `__int128` does not exist on a 32-bit target — gcc rejects the type
      outright, so `02_integer_widths` has no i386 or armv7 form at all.

      This is a statement about the SOURCE, and it is the whole statement. It
      used to be conflated with a second, much more serious one — whether
      GLAURUNG may emit `__int128` for a 32-bit target — and that conflation is
      why a real defect (every 32-bit multiply-high rendered with a type the
      target cannot spell, caught by DecBench, invisible here) could sit behind
      four green lanes. The two are now separate: this exemption covers only the
      fixture that cannot be built, while every recovered body on every 32-bit
      lane is compiled for its own architecture and reported `nonportable` if it
      names a type that target does not have. See `native_cc` and
      `python/tests/test_decompiler_wide_arithmetic_width.py`.
    * a C++ fixture needs a C++ driver and runtime for the target; Debian's
      `aarch64-linux-gnu-gcc` ships without `aarch64-linux-gnu-g++`.

    Deriving these from a probe plus the source text (rather than a hardcoded
    fixture list) means a new fixture using `__int128`, or a host that installs
    the missing cross C++ toolchain, changes the answer automatically instead of
    quietly inheriting a stale exemption.
    """
    out: dict[tuple[str, str], str] = {}
    srcs = sources()
    for arch in arches:
        if not _compiler_available(arch, TARGETS[arch].cc):
            continue  # a missing compiler is a FAILURE, decided in `_run_lane`
        if not _supports_int128(arch):
            for src in srcs:
                if "__int128" in src.read_text():
                    out[(arch, src.stem)] = f"__int128 is not a type on {arch}"
        cpp = [s for s in srcs if s.suffix == ".cpp"]
        if cpp and not _cxx_runtime_ok(arch):
            driver = compiler_for(arch, cpp[0])
            for src in cpp:
                out[(arch, src.stem)] = (
                    f"no working C++ toolchain for {arch} ({driver})"
                )
    return out


# ---------------------------------------------------------------------------
# Lane execution
# ---------------------------------------------------------------------------


def _run_lane(
    src: Path,
    arch: str,
    opt: str,
    fuzz: int,
    unsupported: str | None,
    detail: bool = False,
) -> dict:
    """One (fixture, arch, opt) lane: `{func: status}` or a `__lane__` error.

    Fail-closed at every step. A missing cross compiler, a failed cross build, a
    failed reference build, and zero recovered signatures are all lane ERRORS —
    the architecture is then unverified, and unverified must never read as
    "passed". The single exception is a declared `unsupported` gap, whose
    unbuildability is ASSERTED here before it is recorded.
    """
    compiler = compiler_for(arch, src)
    with tempfile.TemporaryDirectory(
        dir=M.tmpdir(), prefix=f"arch-{arch}-{opt}-"
    ) as td:
        work = Path(td)
        target_so = work / f"{src.stem}-{arch}-{opt}.so"
        if unsupported is not None:
            ok, _ = _cross_build(arch, src, opt, target_so)
            assert not ok, (
                f"declared-unsupported lane {lane_key(src.stem, arch, opt)} "
                f"built successfully — the exemption is stale, remove it"
            )
            return {"__lane__": f"{UNSUPPORTED_PREFIX}{unsupported}"}
        if not _compiler_available(arch, compiler):
            return {"__lane__": f"missing-compiler: {compiler}"}
        ok, err = _cross_build(arch, src, opt, target_so)
        if not ok:
            return {"__lane__": f"cross-build-failed: {err[-200:]}"}
        reference_so = work / f"{src.stem}-host-{opt}.so"
        ok, err = _reference_build(src, opt, reference_so)
        if not ok:
            return {"__lane__": f"reference-build-failed: {err[-200:]}"}
        cmd = [
            BG.python_bin(),
            str(DIFF),
            str(target_so),
            str(src),
            "--fixture",
            src.stem,
            "--fuzz",
            str(fuzz),
            "--reference-so",
            str(reference_so),
            "--lane",
            f"{arch}:{opt}",
            "--json",
        ]
        native = native_cc(arch)
        if native is not None:
            cmd += ["--native-cc", json.dumps(native)]
        runner = native_runner(arch)
        if runner is not None:
            cmd += ["--native-runner", json.dumps(runner)]
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,
            check=False,
            env=BG.export_bin_to_path(),
        )
        try:
            fns = json.loads(r.stdout)
        except json.JSONDecodeError:
            return {"__lane__": f"gate-crashed: {r.stderr.strip()[-160:]}"}
    if "__error__" in fns:
        return {"__lane__": fns["__error__"]}
    if not fns:
        # Zero functions is the silent-green shape this whole tool exists to
        # eliminate. `diff_decompile` already errors on a stripped or
        # signature-less object; this is the belt to that braces.
        return {"__lane__": "no functions executed"}
    if detail:
        return fns
    return {name: v["status"] for name, v in fns.items()}


def fingerprint(arches) -> dict:
    """Identity of every compiler that shaped these verdicts.

    `rebuild` is the pinned toolchain (`fixture_toolchain`) that builds the
    reference object and recompiles our decompiled C. `fixture` is the compiler
    that built the object being decompiled, per architecture — pinned for
    `x86_64` and unavoidably host-side for the rest, because the image has no
    cross toolchains and no multilib. Each entry is tagged `pinned:`/`host:` so
    a baseline can never be silently compared across the two.
    """
    fixture_cc: dict[str, str] = {}
    runners: dict[str, str] = {}
    for arch in sorted(arches):
        cc = TARGETS[arch].cc
        if TARGETS[arch].pinned:
            r = TC.run([cc, "--version"])
            version = (r.stdout.strip().splitlines() or ["?"])[0]
            fixture_cc[arch] = f"pinned: {version}"
            continue
        if shutil.which(cc) is None:
            fixture_cc[arch] = "host: MISSING"
            continue
        r = subprocess.run(
            [cc, "--version"], capture_output=True, text=True, check=False
        )
        fixture_cc[arch] = f"host: {(r.stdout.strip().splitlines() or ['?'])[0]}"
        runner = native_runner(arch)
        if runner is not None:
            version = subprocess.run(
                [runner[0], "--version"],
                capture_output=True,
                text=True,
                check=False,
            )
            first_line = (version.stdout.strip().splitlines() or ["MISSING"])[0]
            runners[arch] = f"{' '.join(runner)} :: {first_line}"
    # A recovery that reads an uninitialised local dereferences whatever the
    # stack happened to hold. `aslr` records whether randomization is off; the
    # matching fixed-environment rule (`build_guard.worker_env`) is unconditional
    # and needs no flag. See `build_guard` for the function that forced both.
    return {
        "rebuild": TC.fingerprint(),
        "fixture": fixture_cc,
        "runner": runners,
        "aslr": BG.aslr_mode(),
    }


def run_matrix(
    matrix, fuzz: int, jobs: int | None = None, fixtures=None, detail: bool = False
) -> dict:
    """`{f"{fixture}:{arch}:{opt}": {func: status}}` plus `__toolchain__`.

    `detail` keeps `diff_decompile`'s full per-function dict (status, detail and
    `width_sensitive`) instead of the status alone. Only `--width-audit` uses it;
    a baseline must stay a map of verdicts.
    """
    if jobs is None:
        jobs = H.default_jobs()
    arches = sorted({arch for arch, _ in matrix})
    unsupported = detect_unsupported(arches)
    srcs = [s for s in sources() if fixtures is None or s.stem in fixtures]
    if fixtures is not None:
        unknown = sorted(set(fixtures) - {s.stem for s in srcs})
        if unknown:
            raise FileNotFoundError(f"no fixture source for {unknown} in {SRC}")
    result: dict = {H.TOOLCHAIN_KEY: fingerprint(arches)}
    work = [
        (
            lane_key(src.stem, arch, opt),
            src,
            arch,
            opt,
            unsupported.get((arch, src.stem)),
        )
        for src in srcs
        for arch, opt in matrix
    ]
    if jobs == 1:
        for key, src, arch, opt, unsup in work:
            result[key] = _run_lane(src, arch, opt, fuzz, unsup, detail)
        return result
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(_run_lane, src, arch, opt, fuzz, unsup, detail): key
            for key, src, arch, opt, unsup in work
        }
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                result[key] = fut.result()
            except Exception as e:  # noqa: BLE001 — a lane crash is a lane error
                result[key] = {"__lane__": f"harness-crashed: {type(e).__name__}: {e}"}
    return result


# ---------------------------------------------------------------------------
# Pure predicates (unit-testable without compiling anything)
# ---------------------------------------------------------------------------


def is_unsupported(lane: dict) -> bool:
    return str(lane.get("__lane__", "")).startswith(UNSUPPORTED_PREFIX)


def summarize(result: dict) -> dict:
    c = {k: 0 for k in H.STATUS_KINDS}
    c["lane"] = c["unsupported"] = 0
    for fns in H.lanes(result).values():
        if "__lane__" in fns:
            c["unsupported" if is_unsupported(fns) else "lane"] += 1
            continue
        for st in fns.values():
            c[st] = c.get(st, 0) + 1
    return c


def per_arch(result: dict) -> dict[str, dict]:
    """`{arch: counts}` — the table this tool exists to print."""
    out: dict[str, dict] = {}
    for key, fns in H.lanes(result).items():
        arch = key.split(":")[1]
        c = out.setdefault(
            arch, {**{k: 0 for k in H.STATUS_KINDS}, "lane": 0, "unsupported": 0}
        )
        if "__lane__" in fns:
            c["unsupported" if is_unsupported(fns) else "lane"] += 1
            continue
        for st in fns.values():
            c[st] = c.get(st, 0) + 1
    return out


def width_audit(detailed: dict) -> dict[str, dict]:
    """Split every 32-bit failure into portability residue and real defect.

    `{arch: {"artifact": [...], "real": [...], "nonportable": [...]}}`.

    A failing recovery whose C names no type that changes size between ILP32 and
    LP64 computes the same values at either width, so executing the host rebuild
    of it *is* executing the 32-bit semantics: `real`. One that does name such a
    type cannot be separated from the confound without a genuine 32-bit run, so
    it is `artifact` — the residue, quantified rather than asserted away.

    Deliberately one-sided. `artifact` does not claim the recovery is correct; it
    claims this apparatus cannot tell. Treating it as "probably fine" is how the
    confound gets laundered into a number.
    """
    out: dict[str, dict] = {}
    for key, fns in sorted(H.lanes(detailed).items()):
        fixture, arch, opt = key.split(":")
        if TARGETS[arch].pointer_bytes != 4 or "__lane__" in fns:
            continue
        bucket = out.setdefault(arch, {"artifact": [], "real": [], "nonportable": []})
        for name, record in sorted(fns.items()):
            status = record["status"]
            if status == "nonportable":
                bucket["nonportable"].append(f"{fixture}:{opt}:{name}")
            elif status == "fail":
                where = "artifact" if record.get("width_sensitive") else "real"
                bucket[where].append(f"{fixture}:{opt}:{name}")
    return out


def control_gate_disagreements(result: dict, x86_baseline: dict) -> list[str]:
    """Function-for-function, the control lane must equal the x86-64 gate.

    This is the strongest statement available about the apparatus. The control
    lane compiles the same source with the same pinned compiler and the same
    flags as `fixture_harness.compile_fixture`, so `fixture:x86_64:{opt}` and the
    committed `fixture:gcc:{opt}` are asking the identical question through a
    different code path. Any disagreement is THIS tool — the cross-compile
    plumbing, `--reference-so`, `--lane`, the export filter — and would otherwise
    be invisible until it silently mis-attributed a harness artifact to a lifter.

    Compare it against `tests/decompiler_fixtures/baseline.json` rather than a
    live matrix run so the check costs nothing: 656 verdicts are already
    committed. It follows that refreshing that baseline requires refreshing this
    one, which is the correct coupling.
    """
    disagreements = []
    for key, fns in sorted(H.lanes(result).items()):
        fixture, arch, opt = key.split(":")
        if arch != CONTROL_ARCH or "__lane__" in fns:
            continue
        gate = H.lanes(x86_baseline).get(f"{fixture}:gcc:{opt}")
        if gate is None or "__lane__" in gate:
            continue
        for func in sorted(set(fns) | set(gate)):
            ours, theirs = fns.get(func), gate.get(func)
            if ours != theirs:
                disagreements.append(
                    f"{key}:{func}: control says {ours!r}, the x86-64 gate's "
                    f"baseline says {theirs!r}"
                )
    return disagreements


def control_problems(
    result: dict, matrix=None, x86_baseline: dict | None = None
) -> list[str]:
    """The control lane must be present, complete, and AGREE WITH THE GATE.

    `x86_64` decompiles a host-architecture object and diffs it against a
    host-architecture reference, so nothing about a foreign lifter is involved:
    every failure it reports is either this harness or a genuine x86-64
    decompiler bug that the main gate would also see. Until it is trustworthy, a
    number from any other architecture is uninterpretable — which is exactly how
    the prototype's "AArch64 is 37% correct" figure came to include 11 failures
    that were the harness passing `static` functions it should never have
    executed.

    "Trustworthy" is agreement with `baseline.json`, not absence of failure, and
    the difference is what unblocked this lane. Requiring every control verdict
    to be `pass` conflates two things:

      * the HARNESS is sound — the control lane reproduces the x86-64 gate
        function for function. This is what makes a foreign-architecture verdict
        interpretable, and it is checked exactly (see
        `control_gate_disagreements`).
      * the DECOMPILER is perfect on x86-64. This is not required for an ARM
        number to mean something: a function whose x86-64 result is a known,
        recorded failure still has a meaningful ARM comparison — against that
        recorded result.

    Demanding the second tied cross-architecture coverage to x86-64 perfection,
    and that is why the committed baseline covered 30 of 175 fixtures. Every
    fixture beyond it contains at least one function the x86-64 decompiler gets
    wrong (`36_quicksort`, `54_sha256_block`, `87_variable_length_array`, …), so
    no amount of running this tool could ever record one. The ARM and i386 gaps
    for the other 145 were unmeasurable by construction.

    A control failure that the gate's baseline also records as a failure is
    therefore accepted here; one the gate does not record is still a problem,
    and is reported by `control_gate_disagreements` with the exact mismatch.
    """
    if matrix is None:
        matrix = REQUIRED_MATRIX
    opts = sorted({opt for arch, opt in matrix if arch == CONTROL_ARCH})
    if not opts:
        return [
            (
                f"the {CONTROL_ARCH} control lane is absent from the matrix — it "
                f"is what proves the harness itself is sound and is never optional"
            )
        ]
    problems = []
    for key, fns in sorted(H.lanes(result).items()):
        _fixture, arch, _opt = key.split(":")
        if arch != CONTROL_ARCH:
            continue
        if "__lane__" in fns:
            if not is_unsupported(fns):
                problems.append(f"control lane {key}: {fns['__lane__']}")
            continue
        fixture, _arch, opt = key.split(":")
        gate = (
            H.lanes(x86_baseline).get(f"{fixture}:gcc:{opt}", {})
            if x86_baseline is not None
            else {}
        )
        bad = sorted(
            f
            for f, st in fns.items()
            if st not in ("pass", "structural") and gate.get(f) != st
        )
        if bad:
            problems.append(
                f"control lane {key}: {', '.join(f'{f}={fns[f]}' for f in bad)}"
            )
    return problems


def baseline_problems(result: dict) -> list[str]:
    """Reasons a result must NOT be written as a baseline: a lane error that is
    not a declared gap, or any infrastructure status (a required function gone
    missing, a function with no cases, or a worker TIMEOUT — which says the
    machine was slow, not that the decompilation is wrong). Known decompiler
    fails are exactly what a baseline is for and are fine to record."""
    problems = []
    for key, fns in sorted(H.lanes(result).items()):
        if "__lane__" in fns:
            if not is_unsupported(fns):
                problems.append(f"{key}: lane error ({fns['__lane__']})")
            continue
        for func, st in sorted(fns.items()):
            if st in ("missing", "nocases", "timeout"):
                problems.append(f"{key}:{func}: {st}")
    return problems


def schema_problems(result: dict, matrix) -> list[str]:
    """Every declared fixture present in every matrix lane, every status a known
    kind, and a toolchain fingerprint attached.

    The comparison is against the fixtures this tool CAN cross-build, which is
    `sources()` — C and C++. The manifest also declares Rust fixtures
    (`166_rust_generics` and friends); `TARGETS` configures no cross-`rustc`, so
    they are out of scope here and their absence is not a disagreement. Checking
    the raw manifest instead made every `--write-baseline` refuse with six
    "only declared" entries that no amount of building could satisfy.
    """
    problems = []
    stems = sorted(p.stem for p in sources())
    # Declared fixtures this tool is responsible for: those with a C/C++ source.
    declared = {name for name in M.REQUIRED_FUNCTIONS if name in set(stems)} | {
        name
        for name in M.REQUIRED_FUNCTIONS
        if (SRC / f"{name}.c").exists() or (SRC / f"{name}.cpp").exists()
    }
    if set(stems) != declared:
        problems.append(
            f"fixture sources and the manifest disagree: "
            f"only on disk {sorted(set(stems) - declared)}, "
            f"only declared {sorted(declared - set(stems))}"
        )
    if H.TOOLCHAIN_KEY not in result:
        problems.append(
            f"no {H.TOOLCHAIN_KEY} fingerprint — the verdicts are not attributable "
            f"to a toolchain; regenerate with `--write-baseline`"
        )
    for stem in stems:
        for arch, opt in matrix:
            key = lane_key(stem, arch, opt)
            if key not in result:
                problems.append(f"missing lane {key}")
                continue
            fns = result[key]
            if "__lane__" in fns:
                continue
            for func, st in fns.items():
                if st not in H.STATUS_KINDS:
                    problems.append(f"{key}:{func}: bad status {st!r}")
    return problems


def toolchain_problems(recorded, current) -> list[str]:
    """Reasons a baseline's compilers are not comparable to this run's. Pure and
    dict-driven so the fast lane can test the rule without docker or a cross
    compiler."""
    if not recorded:
        return [
            (
                "baseline records no `__toolchain__` fingerprint — regenerate it "
                "with `python tools/arch_roundtrip.py --write-baseline`"
            )
        ]
    problems = TC.fingerprint_problems(recorded.get("rebuild"), current.get("rebuild"))
    problems = [f"rebuild {p}" for p in problems]
    want, got = recorded.get("fixture") or {}, current.get("fixture") or {}
    for arch in sorted(set(want) | set(got)):
        if want.get(arch) != got.get(arch):
            problems.append(
                f"fixture cc[{arch}]: baseline {want.get(arch)!r} != "
                f"current {got.get(arch)!r}"
            )
    want_runners = recorded.get("runner") or {}
    got_runners = current.get("runner") or {}
    for arch in sorted(set(want_runners) | set(got_runners)):
        if want_runners.get(arch) != got_runners.get(arch):
            problems.append(
                f"target runner[{arch}]: baseline {want_runners.get(arch)!r} != "
                f"current {got_runners.get(arch)!r}"
            )
    if recorded.get("aslr") != current.get("aslr"):
        problems.append(
            f"aslr: baseline {recorded.get('aslr')!r} != current "
            f"{current.get('aslr')!r} — a recovery that reads an uninitialised "
            f"local gives a different answer under each setting, so the two runs "
            f"are not comparable. Install `setarch` (util-linux)."
        )
    return problems


def comparison_problems(current: dict, baseline: dict) -> list[str]:
    """Ratchet. Every direction of change is a failure that demands a decision:

    * a lane or function the baseline knows about that has vanished, or a lane
      that newly errors — fail closed, the coverage silently shrank;
    * a function the run produced that the baseline does not record — it would be
      completely ungated until somebody happened to refresh;
    * `pass` -> anything else — a regression;
    * anything else -> `pass` — an IMPROVEMENT, reported as a failure so the
      baseline is refreshed after the differential is verified. That is what
      makes the gate ratchet: an improvement absorbed silently can regress later
      with nothing to notice.
    """
    problems: list[str] = []
    base_lanes, cur_lanes = H.lanes(baseline), H.lanes(current)
    for lane, base in sorted(base_lanes.items()):
        cur = cur_lanes.get(lane)
        if cur is None:
            problems.append(f"{lane}: lane disappeared from the run (fail-closed)")
            continue
        base_unsup, cur_unsup = is_unsupported(base), is_unsupported(cur)
        if base_unsup and not cur_unsup:
            problems.append(
                f"{lane}: baseline records it unsupported but this environment "
                f"built and ran it — verify the results, then refresh the baseline"
            )
            continue
        if cur_unsup and not base_unsup:
            problems.append(
                f"{lane}: baseline records real results but this environment "
                f"reports {cur['__lane__']!r} — provision the toolchain instead of "
                f"dropping the lane"
            )
            continue
        if base_unsup and cur_unsup:
            continue
        if "__lane__" in cur:
            problems.append(f"{lane}: newly broken ({cur['__lane__']})")
            continue
        if "__lane__" in base:
            problems.append(
                f"{lane}: baseline records a lane error ({base['__lane__']!r}) — "
                f"a baseline must never contain one"
            )
            continue
        for func, base_status in sorted(base.items()):
            cur_status = cur.get(func)
            if cur_status is None:
                problems.append(f"{lane}:{func}: result missing (fail-closed)")
            elif base_status == "pass" and cur_status != "pass":
                problems.append(
                    f"{lane}:{func}: REGRESSION {base_status} -> {cur_status}"
                )
            elif base_status != "pass" and cur_status == "pass":
                problems.append(
                    f"{lane}:{func}: IMPROVEMENT {base_status} -> pass "
                    f"(verify, then refresh the baseline)"
                )
            elif base_status != cur_status:
                # Neither side is `pass`, so it is neither a regression nor an
                # improvement — but `fail -> nonportable` and
                # `structural -> fail` are still the gate learning something new
                # about that function, and letting them through unremarked is how
                # a reclassification gets absorbed with nobody looking at it.
                problems.append(
                    f"{lane}:{func}: RECLASSIFIED {base_status} -> {cur_status} "
                    f"(verify, then refresh the baseline)"
                )
        for func in sorted(cur):
            if func not in base:
                problems.append(
                    f"{lane}:{func}: not in the baseline ({cur[func]}) — ungated "
                    f"until the baseline is refreshed"
                )
    for lane in sorted(set(cur_lanes) - set(base_lanes)):
        problems.append(f"{lane}: lane is not in the baseline (ungated)")
    return problems


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_report(result: dict, per_lane: bool = True) -> None:
    """The summary. `per_lane` is off for `--check`, whose 240 lane lines would
    otherwise push the problem list — the only part that needs reading — past the
    tail the gate script captures."""
    fp = result[H.TOOLCHAIN_KEY]
    print(f"rebuild toolchain[{fp['rebuild']['mode']}]: {fp['rebuild']['gcc']}")
    for arch, ver in sorted(fp["fixture"].items()):
        print(f"  fixture cc {arch:8s} {ver}")
    for arch, ver in sorted(fp.get("runner", {}).items()):
        print(f"  target run {arch:8s} {ver}")
    print(f"  aslr                {fp.get('aslr', '?')}")
    print()
    for key, fns in sorted(H.lanes(result).items()) if per_lane else []:
        if "__lane__" in fns:
            tag = "SKIP" if is_unsupported(fns) else "LANE"
            print(f"{key:48s}  {tag}: {fns['__lane__']}")
            continue
        pf = sum(1 for st in fns.values() if st == "pass")
        ff = sum(1 for st in fns.values() if st == "fail")
        sf = sum(1 for st in fns.values() if st == "structural")
        flag = "" if ff == 0 else "  <-- FAILURES"
        print(f"{key:48s}  {pf:3d} pass {ff:3d} fail {sf:3d} struct{flag}")

    print(
        f"\n{'arch':10s} {'judged':>7s} {'pass':>6s} {'fail':>6s} {'nonport':>8s} "
        f"{'incomp':>7s} {'struct':>7s} {'lane':>5s} {'skip':>5s}   correctness"
    )
    for arch in sorted(
        per_arch(result),
        key=lambda a: REQUIRED_ARCHES.index(a) if a in REQUIRED_ARCHES else 99,
    ):
        c = per_arch(result)[arch]
        # `nonportable` is in the denominator — it is a verdict about the C we
        # emitted. `incomparable` is not — it is this harness declining to
        # measure, and counting a refusal as either a pass or a fail is how a
        # lane goes green for a reason that has nothing to do with the lifter.
        judged = c["pass"] + c["fail"] + c["nonportable"]
        pct = f"{100.0 * c['pass'] / judged:5.1f}%" if judged else "    n/a"
        if arch == CONTROL_ARCH:
            marker = "  (CONTROL — must be clean)"
        elif TARGETS[arch].pointer_bytes == 4:
            # Simple scalar/pointer signatures execute at the actual target ABI;
            # richer aggregate signatures retain the explicitly audited portable-C
            # fallback until the generated worker supports their materializer.
            marker = "  (32-bit: target ABI where supported; --width-audit fallback)"
        else:
            marker = ""
        print(
            f"{arch:10s} {judged:7d} {c['pass']:6d} {c['fail']:6d} "
            f"{c['nonportable']:8d} {c['incomparable']:7d} {c['structural']:7d} "
            f"{c['lane']:5d} {c['unsupported']:5d}   {pct}{marker}"
        )
    c = summarize(result)
    print(
        f"\n=== TOTAL: {c['pass']} pass, {c['fail']} fail, "
        f"{c['nonportable']} non-portable, {c['incomparable']} ABI-incomparable, "
        f"{c['structural']} structural, {c['missing']} missing, "
        f"{c['nocases']} no-cases, {c['timeout']} timeout; "
        f"{c['lane']} lane error(s), {c['unsupported']} declared-unsupported ==="
    )


def _x86_baseline() -> dict:
    if not X86_BASELINE.is_file():
        raise FileNotFoundError(
            f"{X86_BASELINE} is missing — the control lane is validated against "
            f"the x86-64 gate's committed verdicts; regenerate it with "
            f"`python tools/fixture_harness.py --write-baseline`"
        )
    return json.loads(X86_BASELINE.read_text())


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Execution differential across every lifted architecture."
    )
    ap.add_argument("fixtures", nargs="*", help="fixture stems (default: all)")
    ap.add_argument("--arch", action="append", choices=sorted(TARGETS))
    ap.add_argument("--opt", action="append", choices=["O0", "O1", "O2", "O3", "Os"])
    ap.add_argument("--fuzz", type=int, default=M.FIXTURE_FUZZ)
    ap.add_argument("--jobs", type=int, default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--check", action="store_true", help="ratchet against the baseline")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument(
        "--width-audit",
        action="store_true",
        help="run the 32-bit lanes only and split their failures into "
        "portability residue vs real semantic defects (see `width_audit`)",
    )
    args = ap.parse_args()

    if args.width_audit:
        thirty_two = [a for a in REQUIRED_ARCHES if TARGETS[a].pointer_bytes == 4]
        matrix = [(arch, opt) for arch in thirty_two for opt in REQUIRED_OPTS]
        detailed = run_matrix(
            matrix,
            args.fuzz,
            jobs=args.jobs,
            fixtures=set(args.fixtures) or None,
            detail=True,
        )
        audit = width_audit(detailed)
        for arch in thirty_two:
            b = audit.get(arch, {"artifact": [], "real": [], "nonportable": []})
            print(f"\n=== {arch} ===")
            print(
                f"  {len(b['real']):3d} REAL semantic defect(s) — recovered C names "
                f"no width-varying type, so the host rebuild is the 32-bit semantics"
            )
            for f in b["real"]:
                print(f"        {f}")
            print(
                f"  {len(b['artifact']):3d} UNSEPARABLE — recovered C names a type "
                f"whose size changes at LP64; this apparatus cannot tell defect "
                f"from artifact"
            )
            for f in b["artifact"]:
                print(f"        {f}")
            print(f"  {len(b['nonportable']):3d} NON-PORTABLE — see the run report")
            for f in b["nonportable"]:
                print(f"        {f}")
        return 0

    arches = args.arch or list(REQUIRED_ARCHES)
    if CONTROL_ARCH not in arches:
        # Not a courtesy: an ARM number produced without the control lane is not
        # interpretable, so refuse rather than print one.
        arches = [CONTROL_ARCH, *arches]
    opts = args.opt or list(REQUIRED_OPTS)
    matrix = [(arch, opt) for arch in arches for opt in opts]
    scoped = bool(args.fixtures) or matrix != REQUIRED_MATRIX

    if (args.check or args.write_baseline) and scoped:
        print(
            "--check/--write-baseline run the full required matrix; drop the "
            "--arch/--opt/fixture filters.",
            file=sys.stderr,
        )
        return 2

    result = run_matrix(
        matrix, args.fuzz, jobs=args.jobs, fixtures=set(args.fixtures) or None
    )

    if args.write_baseline:
        problems = (
            baseline_problems(result)
            + schema_problems(result, matrix)
            + control_problems(result, matrix, _x86_baseline())
            + control_gate_disagreements(result, _x86_baseline())
        )
        if problems:
            print("REFUSING to write baseline:", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            return 1
        BASELINE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"wrote {BASELINE}")
        _print_report(result)
        return 0

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if not baseline_problems(result) else 2

    _print_report(result, per_lane=not args.check)

    if args.check:
        if not BASELINE.is_file():
            print(
                f"\nNO BASELINE at {BASELINE} — regenerate with "
                f"`tools/arch_roundtrip.py --write-baseline`",
                file=sys.stderr,
            )
            return 1
        baseline = json.loads(BASELINE.read_text())
        problems = (
            toolchain_problems(baseline.get(H.TOOLCHAIN_KEY), result[H.TOOLCHAIN_KEY])
            + control_problems(result, matrix, _x86_baseline())
            + control_gate_disagreements(result, _x86_baseline())
            + schema_problems(result, matrix)
            + comparison_problems(result, baseline)
        )
        if problems:
            print(f"\nARCH ROUND-TRIP: FAILED ({len(problems)} problem(s))")
            for p in problems:
                print(f"  {p}")
            return 1
        print("\nARCH ROUND-TRIP: matches the baseline exactly")
        return 0

    c = summarize(result)
    return 1 if (c["lane"] or c["missing"] or c["nocases"] or c["timeout"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
