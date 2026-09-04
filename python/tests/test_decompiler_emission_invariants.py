"""Cross-architecture invariants on the emitted translation unit.

These came out of a DecBench `byte_match` regression that ran undetected for
four commits: the score fell 0.2392 -> 0.2005 while the behavioural execution
differential, the Rust suite and the 56-cell fixture ratchet all stayed green.
The reason none of them saw it is that every one of those gates asks *what the
recovered code does*, and the regression was in *what the recovered code claims
about itself*.

The properties below are deliberately NOT a copy of any benchmark metric. Each
is a self-consistency property of the emitted C — something that must hold for
the output to be a coherent description of some machine code, whatever the
input was:

  * declared frame locals occupy disjoint byte ranges (an over-long recovered
    array that swallows its neighbours cannot be recompiled to the original
    frame — this is the defect that caused the regression, and it was present
    in 52 of 224 holdout translation units before it and 95 after);
  * a value read is a value assigned;
  * an emitted prototype agrees with how the same unit calls it;
  * the recovered signature agrees with the source it was built from;
  * decompiling the same bytes twice gives the same answer.

They are checked on every architecture the lifter supports, because a frame or
ABI model that is right on x86-64 and wrong on AArch64 is exactly the failure
this project keeps rediscovering.

Marked `slow`: cross-compiles fixtures for four targets. Run with `-m slow`.
"""

from __future__ import annotations

import re
import functools
import shutil
import tempfile
import subprocess
import sys
from itertools import pairwise
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

pytestmark = pytest.mark.slow

#: Deliberately NOT under `decompiler_fixtures/src`: that directory is the
#: shared execution-differential corpus with an exact manifest and a
#: committed baseline, and dropping a file into it silently enlarges that
#: gate. This fixture is compiled by this module alone.
SRC = ROOT / "tests" / "decompiler_fixtures" / "invariants" / "frame_and_arity_shapes.c"

#: Same four lanes as `tools/arch_roundtrip.py`, and for the same reason: three
#: of the four lifter families are invisible to any x86-64-only gate.
TARGETS: dict[str, tuple[str, tuple[str, ...]]] = {
    "x86_64": ("gcc", ()),
    "i386": ("gcc", ("-m32",)),
    "aarch64": ("aarch64-linux-gnu-gcc", ("-march=armv8-a",)),
    "armv7": (
        "arm-linux-gnueabihf-gcc",
        ("-march=armv7-a", "-mfpu=vfpv3-d16", "-mthumb"),
    ),
}

#: `local_<hex>` is the frame-offset spelling; `stack_<n>` is the appearance
#: -order spelling used where no offset was proven. Only the former carries a
#: layout claim, so only the former can contradict another one.
FRAME_LOCAL = re.compile(
    r"^[ \t]+(?:const\s+)?"
    r"(unsigned char|signed char|char|unsigned int|int|unsigned long|long|"
    r"unsigned short|short|float|double|void\s*\*)\s+"
    r"local_([0-9a-fA-F]+)\s*(?:\[(\d+)\])?\s*;",
    re.MULTILINE,
)

#: Width of a scalar local, for the disjointness computation. A pointer is
#: target-width; everything else is its C width. Over-estimating would create
#: false overlaps, so where the width is genuinely ambiguous we take the
#: SMALLEST plausible size and let the test under-report rather than invent a
#: failure.
SCALAR_BYTES = {
    "unsigned char": 1,
    "signed char": 1,
    "char": 1,
    "unsigned short": 2,
    "short": 2,
    "unsigned int": 4,
    "int": 4,
    "float": 4,
    "double": 8,
    "unsigned long": 4,
    "long": 4,
}


@functools.lru_cache(maxsize=None)
def _have(arch: str) -> bool:
    """Whether this machine can actually BUILD the fixture for `arch`.

    `shutil.which` is not enough and CI proved it. On a `ubuntu-latest`
    runner `gcc` is present, so the i386 lane looked available -- and then
    `gcc -m32` failed at link time with "cannot find crti.o", because 32-bit
    multilib is not installed. The lane ERRORED instead of skipping, and the
    whole Python job went red for a reason that had nothing to do with the
    decompiler.

    So availability is decided by compiling something trivial with the exact
    flags the lane uses, cached per arch. A toolchain that cannot link a
    two-line program cannot build the fixture either, and saying so as a SKIP
    is the honest answer -- the alternative is a permanently red gate on every
    machine that lacks a cross toolchain.
    """
    compiler, cflags = TARGETS[arch]
    if shutil.which(compiler) is None:
        return False
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "probe.c"
        probe.write_text("int probe(void) { return 0; }\n")
        done = subprocess.run(
            [
                compiler,
                "-shared",
                "-fPIC",
                *cflags,
                "-o",
                str(Path(tmp) / "probe.so"),
                str(probe),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return done.returncode == 0


def _compile(arch: str, opt: str, out: Path) -> None:
    cc, cflags = TARGETS[arch]
    argv = [cc, "-shared", "-fPIC", "-g", opt, "-w", *cflags, "-o", str(out), str(SRC)]
    done = subprocess.run(
        argv, capture_output=True, text=True, timeout=120, check=False
    )
    assert done.returncode == 0, f"{arch} {opt}: {done.stderr}"


def _decompile(binary: Path, func: str | None = None) -> str:
    argv = ["glaurung", "decompile", str(binary), "--style", "decbench", "--no-color"]
    # A `-shared` fixture has entry VA 0, so the default single-function mode
    # fails outright; these invariants are about the whole unit anyway.
    argv += ["--func", func] if func is not None else ["--all", "--limit", "64"]
    done = subprocess.run(
        argv, capture_output=True, text=True, timeout=600, check=False
    )
    assert done.returncode == 0, done.stderr
    return done.stdout


def _units(text: str) -> dict[str, str]:
    """Split rendered output into one body per emitted function."""
    out: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []
    for line in text.splitlines():
        marker = re.match(r"//\s*glaurung:\s*(\S+)", line)
        if marker:
            if current:
                out[current] = "\n".join(buf)
            current, buf = marker.group(1), []
        buf.append(line)
    if current:
        out[current] = "\n".join(buf)
    return out


def _fixture_units(text: str) -> dict[str, str]:
    """Only the functions this fixture defines — see FIXTURE_FUNCTIONS."""
    return {k: v for k, v in _units(text).items() if k in FIXTURE_FUNCTIONS}


def _frame_extents(body: str, pointer_bytes: int) -> list[tuple[int, int, str]]:
    """Ascending (start, end, spelling) frame spans, relative to the frame pointer.

    `local_<hex>` names a slot by the ABSOLUTE VALUE of a NEGATIVE displacement:
    `alloc_name` formats `disp.unsigned_abs()` under `disp < 0`, so `local_50`
    is `[rbp-0x50]` — eighty bytes BELOW the frame pointer. The stack grows
    down, so a LARGER label is a LOWER address, and ascending memory order is
    descending label order.

    Getting this backwards makes a correctly-tiled frame look like a pile of
    overlaps: `local_70[32]` at fp-112 runs up to exactly fp-80, where
    `local_50[80]` begins and runs to fp. Sorting by the label instead of the
    address inverts every comparison.
    """
    spans: list[tuple[int, int, str]] = []
    for ctype, off, count in FRAME_LOCAL.findall(body):
        if ctype.strip().endswith("*"):
            width = pointer_bytes
        else:
            width = SCALAR_BYTES.get(" ".join(ctype.split()), 1)
        size = width * int(count) if count else width
        start = -int(off, 16)
        spans.append((start, start + size, f"local_{off}"))
    return sorted(spans)


def _overlaps(spans: list[tuple[int, int, str]]) -> list[str]:
    bad = []
    for (lo_a, hi_a, name_a), (lo_b, _, name_b) in pairwise(spans):
        if hi_a > lo_b:
            bad.append(
                f"{name_a} spans [fp{lo_a:+}, fp{hi_a:+}) which overlaps "
                f"{name_b} starting at fp{lo_b:+}"
            )
    return bad


#: The functions this fixture defines. Whole-unit invariants are scoped to
#: these, because CRT glue and PLT stubs are not functions with source-level
#: semantics: a PIC PLT stub legitimately reads the GOT-base register its caller
#: set up, which is unassigned in the stub by construction. Including them would
#: make every property here fire on code we never claimed to recover.
FIXTURE_FUNCTIONS = frozenset(
    {
        "buffer_adjacent_scalars",
        "many_parameters",
        "join_selected_length",
        "two_buffers_and_a_scalar",
        "conditionally_initialised",
        # Shapes whose OPTIMISED form is an instruction that defines its
        # destination conditionally — bit scan, conditional move — or an idiom
        # built from a live conditional, such as the bias-and-shift used for
        # signed division by a power of two. Added because every property in
        # this module was previously compiled from the five shapes above only,
        # and the defect they exist to catch appeared in a different fixture.
        "shift_until_zero_shape",
        "trailing_zero_shape",
        "signed_halving",
        "signed_remainder",
        "fused_guard",
        "conditional_move_shape",
    }
)


#: A recovered definition may lead with a GNU attribute — the stack-protector
#: suppression is spelled bare (a `#define` above the signature is discarded by
#: DecBench's per-function split). Signature matching has to step over it.
ATTR = r"(?:__attribute__\(\(.*?\)\)\s*)*"

ARCHES = sorted(TARGETS)
OPTS = ("-O0", "-O2")


def _arches_xfail(failing: str, reason: str) -> list:
    """`ARCHES` with one architecture marked as a known-failing invariant.

    An invariant these fixtures violate on exactly one target is a recorded
    defect, not a reason to drop the whole test: the other targets keep
    ratcheting. `strict=True` so the marker itself fails once the defect is
    fixed, which is what forces the reason text to be removed rather than left
    to rot into a lie.
    """
    return [
        pytest.param(arch, marks=pytest.mark.xfail(reason=reason, strict=True))
        if arch == failing
        else arch
        for arch in ARCHES
    ]


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> dict[tuple[str, str], Path]:
    """One shared object per (arch, opt); skipped lanes are simply absent."""
    root = tmp_path_factory.mktemp("emission-invariants")
    out: dict[tuple[str, str], Path] = {}
    for arch in ARCHES:
        if not _have(arch):
            continue
        for opt in OPTS:
            binary = root / f"frame-{arch}{opt}.so"
            _compile(arch, opt, binary)
            out[(arch, opt)] = binary
    assert out, "no cross compiler available at all"
    return out


# --------------------------------------------------------------------------
# 1. The defect that caused the regression.
# --------------------------------------------------------------------------
#: Lanes where the frame model is known to emit overlapping slots. EMPTY, and
#: it should stay that way: a correctly recovered frame tiles exactly, so any
#: entry here is a real defect awaiting repair. The test fails if a listed lane
#: starts passing, so the set can only shrink.
FRAME_OVERLAP_KNOWN_BAD: set[tuple[str, str]] = set()


@pytest.mark.parametrize("arch", ARCHES)
@pytest.mark.parametrize("opt", OPTS)
def test_frame_locals_occupy_disjoint_byte_ranges(built, arch, opt) -> None:
    """Two named frame slots may not claim the same byte.

    A recovered array whose length is wrong swallows the slots above it. The
    emitted C then describes a frame that could not have produced the machine
    code it came from, and recompiling it necessarily shifts every later stack
    access. Nothing about *behaviour* changes, which is why the execution
    differential cannot see this — and why a 16% `byte_match` drop survived four
    commits with every other gate green.
    """
    if (arch, opt) not in built:
        pytest.skip(f"no compiler for {arch}")
    pointer_bytes = 8 if arch in ("x86_64", "aarch64") else 4
    text = _decompile(built[(arch, opt)])
    problems: list[str] = []
    for name, body in _fixture_units(text).items():
        for message in _overlaps(_frame_extents(body, pointer_bytes)):
            problems.append(f"{name}: {message}")
    if (arch, opt) in FRAME_OVERLAP_KNOWN_BAD:
        assert problems, (
            f"{arch} {opt} no longer emits overlapping frame locals — remove it "
            "from FRAME_OVERLAP_KNOWN_BAD so the gate ratchets and cannot slide "
            "back."
        )
        pytest.xfail(f"{arch} {opt} frame overlap is a known open defect")
    assert not problems, (
        f"{arch} {opt} emitted overlapping frame locals:\n" + "\n".join(problems)
    )


# --------------------------------------------------------------------------
# 2. A value read is a value assigned.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "arch",
    _arches_xfail(
        "aarch64",
        "OPEN DEFECT (aarch64, both -O0 and -O2): `signed_remainder` renders "
        "`slt_0 ? (arg0 & 7) : (-(var3 & 7))` — the NEGATIVE arm of the "
        "remainder reads `var3`, which nothing assigns. C truncates toward "
        "zero, so the remainder carries the dividend's sign and that arm must "
        "negate the same dividend the positive arm masks; the recovery loses "
        "the operand's definition on the way through the select. -O0 loses a "
        "second one (`var9`). Every other architecture is clean, so this is "
        "aarch64 remainder lowering, not the select recovery itself.",
    ),
)
@pytest.mark.parametrize("opt", OPTS)
def test_no_recovered_local_is_read_without_ever_being_assigned(
    built, arch, opt
) -> None:
    """An unassigned value must not be able to influence the result.

    Not every unassigned name is a defect. Spilling a callee-saved register on
    entry is modelled as `slot = varN` where `varN` stands for the *caller's*
    value: it is unassigned by construction, it is meaningful, and every
    architecture emits it. Flagging that would make this test fire on every
    function ever compiled, including `_init` and PLT stubs.

    The defect is an unassigned value that reaches something observable — an
    operand, a condition, a call argument, a return. That is the shape behind
    the ARMv7 function where a single never-assigned name was the argument to
    ten different callees: the recovered code's behaviour there is not merely
    unknown, it is unspecified.
    """
    if (arch, opt) not in built:
        pytest.skip(f"no compiler for {arch}")
    #: `slot = varN;` — the whole RHS, nothing else. This is the entry spill.
    spill = re.compile(r"^[ \t]*(?:\*?\(?[^=;]*?\)?)\s*=\s*(var\d+)\s*;\s*$")
    text = _decompile(built[(arch, opt)])
    problems: list[str] = []
    for name, body in _fixture_units(text).items():
        declared = set(
            re.findall(r"^[ \t]+[\w \*]+?\b(var\d+)\s*;", body, re.MULTILINE)
        )
        for var in sorted(declared):
            if re.search(rf"^[ \t]*{var}\s*=[^=]", body, re.MULTILINE):
                continue  # assigned somewhere: fine
            observable = [
                line
                for line in body.splitlines()
                if re.search(rf"\b{var}\b", line)
                and not re.match(rf"^[ \t]+[\w \*]+?\b{var}\s*;", line)
                and (spill.match(line) is None or spill.match(line).group(1) != var)
            ]
            if observable:
                problems.append(
                    f"{name}: {var} is never assigned yet reaches "
                    f"{len(observable)} observable use(s), e.g. "
                    f"{observable[0].strip()[:70]}"
                )
    assert not problems, f"{arch} {opt} reads undefined locals:\n" + "\n".join(problems)


# --------------------------------------------------------------------------
# 3. The unit agrees with itself about how a callee is called.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("arch", ARCHES)
@pytest.mark.parametrize("opt", OPTS)
def test_emitted_prototype_arity_agrees_with_its_call_sites(built, arch, opt) -> None:
    """An `extern` prototype and the calls to it must agree on argument count.

    This is pure internal consistency: the same translation unit declares the
    callee and then calls it, so a mismatch means the argument-recovery and the
    prototype-recovery disagreed with each other. Variadic declarations are
    exempt by definition.
    """
    if (arch, opt) not in built:
        pytest.skip(f"no compiler for {arch}")
    text = _decompile(built[(arch, opt)])
    problems: list[str] = []
    for name, body in _fixture_units(text).items():
        protos: dict[str, int] = {}
        for line in body.splitlines():
            m = re.match(r"\s*extern\s+[\w \*]+?\b(\w+)\s*\(([^)]*)\)\s*;", line)
            if not m:
                continue
            callee, params = m.group(1), m.group(2).strip()
            if "..." in params:
                continue
            protos[callee] = 0 if params in ("", "void") else len(params.split(","))
        for callee, want in protos.items():
            for call in re.finditer(rf"(?<![\w.])({callee})\s*\(", body):
                if re.search(rf"extern\s[^\n]*\b{callee}\s*\($", body[: call.end()]):
                    continue
                depth, args, start = 0, 0, call.end()
                seen_any = False
                for i in range(start, len(body)):
                    ch = body[i]
                    if ch in "([":
                        depth += 1
                    elif ch in ")]":
                        if depth == 0:
                            break
                        depth -= 1
                    elif ch == "," and depth == 0:
                        args += 1
                    if not ch.isspace() and ch != ")":
                        seen_any = True
                got = (args + 1) if seen_any else 0
                if got != want:
                    problems.append(
                        f"{name}: {callee} declared with {want} parameter(s) "
                        f"but called with {got}"
                    )
                break  # one report per callee is enough to fail
    assert not problems, f"{arch} {opt} prototype/call disagreement:\n" + "\n".join(
        problems
    )


# --------------------------------------------------------------------------
# 4. The recovered signature agrees with the source it was built from.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("arch", ARCHES)
def test_recovered_arity_matches_the_source_for_a_stack_argument_function(
    built, arch
) -> None:
    """`many_parameters` takes eight arguments on every target here.

    Eight exceeds the register-argument budget of all four ABIs, so the tail
    necessarily arrives on the stack: recovering it requires modelling the
    incoming argument area, not just the argument registers. Under-reporting is
    as wrong as over-reporting, so this asserts equality rather than a bound.
    """
    if (arch, "-O0") not in built:
        pytest.skip(f"no compiler for {arch}")
    text = _decompile(built[(arch, "-O0")], func="many_parameters")
    signature = re.search(
        rf"^{ATTR}\w[\w \*]*\bmany_parameters\s*\(([^)]*)\)", text, re.MULTILINE
    )
    assert signature, f"{arch}: no recovered signature for many_parameters\n{text}"
    params = signature.group(1).strip()
    count = 0 if params in ("", "void") else len(params.split(","))
    assert count == 8, (
        f"{arch}: recovered {count} parameter(s) for a function the source "
        f"declares with 8 — signature was ({params})"
    )


#: `name -> parameter count`, read from the fixture source itself so a shape
#: added to the .c file is covered here without a second edit.
def _source_arity() -> dict[str, int]:
    text = SRC.read_text()
    out: dict[str, int] = {}
    for match in re.finditer(
        r"^[A-Za-z_][\w \*]*?\b(\w+)\s*\(([^)]*)\)\s*\n?\{", text, re.MULTILINE
    ):
        name, params = match.group(1), match.group(2).strip()
        if name in FIXTURE_FUNCTIONS:
            out[name] = 0 if params in ("", "void") else len(params.split(","))
    return out


@pytest.mark.parametrize("arch", ARCHES)
@pytest.mark.parametrize("opt", OPTS)
def test_no_function_recovers_more_parameters_than_its_source_declares(
    built, arch, opt
) -> None:
    """A recovered parameter that the source does not have is always a defect.

    The asymmetry is deliberate. Recovering FEWER parameters can be legitimate:
    at -O2 an argument that is never read leaves no trace in the machine code,
    and no analysis can invent it. Recovering MORE cannot be legitimate under
    any optimisation — it means something the function never received was
    modelled as incoming.

    That is not a hypothetical. A physical register read before it is written
    is live-in, and a live-in register sitting in an argument slot is what
    parameter recovery promotes to a parameter. So any lowering that reads a
    destination it has not yet defined — modelling an instruction as preserving
    a value the architecture leaves undefined is the usual way — manufactures
    parameters. `shift_until_zero_shape` takes one argument and was emitted with
    four, three of them fictional, because `bsr` was lowered as
    `dst = src ? count : dst`.

    This runs at both -O0 and -O2 because the manufacturing instruction only
    appears once the optimiser selects it.
    """
    if (arch, opt) not in built:
        pytest.skip(f"no compiler for {arch}")
    expected = _source_arity()
    assert expected, "no fixture arities parsed from the source"
    text = _decompile(built[(arch, opt)])
    problems: list[str] = []
    for name, body in _fixture_units(text).items():
        if name not in expected:
            continue
        signature = re.search(
            rf"^{ATTR}\w[\w \*]*\b{name}\s*\(([^)]*)\)", body, re.MULTILINE
        )
        if not signature:
            continue
        params = signature.group(1).strip()
        count = 0 if params in ("", "void") else len(params.split(","))
        if count > expected[name]:
            problems.append(
                f"{name}: recovered {count} parameter(s) for a source that "
                f"declares {expected[name]} — ({params})"
            )
    assert not problems, f"{arch} {opt} invented parameters:\n" + "\n".join(problems)


# --------------------------------------------------------------------------
# 5. Same bytes in, same answer out.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("arch", ARCHES)
def test_decompiling_the_same_binary_twice_is_deterministic(built, arch) -> None:
    """Non-determinism would make every other gate here unfalsifiable."""
    if (arch, "-O2") not in built:
        pytest.skip(f"no compiler for {arch}")
    first = _decompile(built[(arch, "-O2")])
    second = _decompile(built[(arch, "-O2")])
    assert first == second, f"{arch}: two runs over identical bytes disagreed"


# --------------------------------------------------------------------------
# 6. The output is as self-contained as it claims to be.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("arch", ARCHES)
@pytest.mark.parametrize("opt", OPTS)
def test_every_local_used_is_also_declared(built, arch, opt, request) -> None:
    """The decbench style claims to stand alone; an undeclared local breaks it.

    This is the compile-time half of the byte-match precondition: a unit that
    does not compile scores zero regardless of how good the recovery was.
    """
    if (arch, opt) not in built:
        pytest.skip(f"no compiler for {arch}")
    # `aarch64 -O2` carried a strict xfail here until 2026-08-16:
    # `two_buffers_and_a_scalar` used `stack_4` with nothing declaring it, which
    # meant the slot was referenced without being promoted to a declared local or
    # folded into an enclosing frame object, so the unit did not compile. The
    # marker was written strict precisely so that fixing the defect would fail
    # this test and force the marker out rather than let the reason rot — and
    # that is what happened. Removed on the XPASS, not on a hunch.
    text = _decompile(built[(arch, opt)])
    problems: list[str] = []
    for name, body in _fixture_units(text).items():
        declared = set(
            re.findall(
                r"^[ \t]+[\w \*]+?\b((?:var|local_|stack_)\w+)\s*[;\[]",
                body,
                re.MULTILINE,
            )
        )
        used = set(re.findall(r"\b((?:var\d+|local_[0-9a-fA-F]+|stack_\d+))\b", body))
        missing = sorted(used - declared)
        if missing:
            problems.append(f"{name}: uses undeclared {', '.join(missing[:4])}")
    assert not problems, f"{arch} {opt} uses undeclared locals:\n" + "\n".join(problems)


# --------------------------------------------------------------------------
# 7. A value chosen on two paths must be defined on both.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("arch", ARCHES)
@pytest.mark.parametrize("opt", OPTS)
def test_a_join_selected_pointer_is_defined_on_every_path_to_its_use(
    built, arch, opt
) -> None:
    """`join_selected_length` picks a pointer in two predecessors, then reads it.

    Whatever name the decompiler gives the merged value, it must either be
    assigned in both arms or receive one complete conditional expression.
    Merging two definitions into one name and keeping only one predecessor is
    the defect family behind lost string arguments and mis-coalesced phis alike.
    """
    if (arch, opt) not in built:
        pytest.skip(f"no compiler for {arch}")
    text = _decompile(built[(arch, opt)], func="join_selected_length")
    body = next(iter(_units(text).values()), text)
    signature = next(
        line for line in body.splitlines() if "join_selected_length(" in line
    )
    parameter_fields = signature.split("(", 1)[1].rsplit(")", 1)[0].split(",")
    parameters = {
        match.group(1)
        for field in parameter_fields
        if (match := re.search(r"\b([A-Za-z_]\w*)\s*$", field.strip()))
    }
    pointer_parameters = {
        match.group(1)
        for field in parameter_fields
        if "*" in field and (match := re.search(r"\b([A-Za-z_]\w*)\s*$", field.strip()))
    }
    pointer_locals = set(
        re.findall(
            r"^[ \t]*(?:const\s+)?[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*\s*\*\s*"
            r"([A-Za-z_]\w*)\s*(?:=|;)",
            body,
            re.MULTILINE,
        )
    )
    pointer_candidates = pointer_parameters | pointer_locals
    #: Find pointer candidates used by an indexed or explicit dereference.
    dereference_lines = [
        line for line in body.splitlines() if "[" in line or "*(" in line
    ]
    value_names = (
        set(re.findall(r"\b(?:var\d+|arg\d+|stack_\d+|local_[0-9a-fA-F]+)\b", body))
        | pointer_candidates
    )
    deref = [
        value
        for value in value_names
        if any(re.search(rf"\b{value}\b", line) for line in dereference_lines)
    ]
    assert deref, f"{arch} {opt}: no pointer dereference recovered\n{body}"
    problems = []
    for value in sorted(set(deref)):
        if value in parameters:
            continue  # a parameter is defined on entry by definition
        assignment_lines = [
            line
            for line in body.splitlines()
            if re.search(rf"\b{value}\s*=(?!=)", line)
        ]
        conditional_assign = any(
            "?" in line and ":" in line for line in assignment_lines
        )
        if len(assignment_lines) < 2 and not conditional_assign:
            problems.append(
                f"{value} is dereferenced but assigned {len(assignment_lines)} time(s); "
                "a value merged from two predecessors needs a definition on each "
                "or one complete conditional assignment"
            )
    assert not problems, f"{arch} {opt} join-selected pointer:\n" + "\n".join(problems)


# --------------------------------------------------------------------------
# 8. The rebuild must not acquire protection the original never had.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("arch", ARCHES)
def test_a_recovered_frame_array_does_not_invite_a_stack_protector(built, arch) -> None:
    """A frame slot spelled as `unsigned char name[N]` must not add a canary.

    `-fstack-protector-strong` is the default in every mainstream distro
    toolchain and protects any function containing an array. A recovered spill
    rendered as an array therefore makes the REBUILD grow a guard load, a guard
    compare and a failure branch that the original function never had — on
    `sum_arg1` the rebuild went from 11 instructions to 39, and across the ARM
    fixture corpus this cost 0.0346 of recompilation fidelity.

    So a unit that declares a frame array and does NOT call `__stack_chk_fail`
    (i.e. the original had no protector) must carry the suppression attribute.
    Where the original DID have one, we must stay silent and let the rebuild add
    its own, because that matches the code being compared against.
    """
    if (arch, "-O0") not in built:
        pytest.skip(f"no compiler for {arch}")
    text = _decompile(built[(arch, "-O0")])
    problems: list[str] = []
    for name, body in _units(text).items():
        declares_array = re.search(
            r"^[ \t]+unsigned char \w+\[\d+\];", body, re.MULTILINE
        )
        original_had_canary = "__stack_chk_fail" in body
        # A BARE attribute, deliberately: a `#define` above the signature is
        # discarded by DecBench's `split_c_functions`, which starts each
        # snippet at the signature line. The macro spelling cost 43 holdout
        # functions their compile by leaving an undefined token behind.
        suppressed = "__attribute__((no_stack_protector))" in body
        if declares_array and not original_had_canary and not suppressed:
            problems.append(
                f"{name}: declares a frame array with no canary and no suppression"
            )
        if original_had_canary and suppressed:
            problems.append(f"{name}: suppresses a protector the original actually had")
    assert not problems, f"{arch} stack-protector handling:\n" + "\n".join(problems)


# --------------------------------------------------------------------------
# 9. Nothing a function needs may sit above its signature line.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("arch", ARCHES)
@pytest.mark.parametrize("opt", OPTS)
def test_no_function_depends_on_text_above_its_signature(built, arch, opt) -> None:
    """A per-function preamble is invisible to the benchmark that scores us.

    DecBench does not compile the translation unit we emit. `split_c_functions`
    cuts each snippet starting at the *signature line* and discards everything
    above it, so any `#define`, `#include`, `#if`, or declaration we place there
    is silently dropped before the compiler ever sees it.

    That is not hypothetical. Suppressing the stack protector was emitted as::

        #if defined(__has_attribute)
        #if __has_attribute(no_stack_protector)
        #define GLAURUNG_NO_SSP __attribute__((no_stack_protector))
        ...
        GLAURUNG_NO_SSP void rcc_periph_clock_enable(int arg0) {

    The `#define`s were correct and were thrown away, leaving a bare undefined
    token in front of the return type. **43 holdout functions stopped compiling**,
    and the diagnostic pointed at our line, so it read as our defect. The fix was
    to spell the attribute directly on the signature line.

    So: everything a function needs must be at or below its signature. This test
    forbids the shape rather than that one instance, because the next preamble
    would fail the same way and the benchmark would again blame us.
    """
    if (arch, opt) not in built:
        pytest.skip(f"no compiler for {arch}")
    text = _decompile(built[(arch, opt)])
    #: The signature line of a fixture-defined function, allowing leading
    #: attributes (see ATTR) but nothing that needs a preprocessor.
    problems: list[str] = []
    for name, body in _fixture_units(text).items():
        lines = body.splitlines()
        signature_at = next(
            (
                i
                for i, line in enumerate(lines)
                if re.match(rf"^{ATTR}\w[\w \*]*\b{name}\s*\(", line)
            ),
            None,
        )
        if signature_at is None:
            continue
        for line in lines[:signature_at]:
            stripped = line.strip()
            # The `// glaurung: <name> @ <va>` banner is a comment: harmless,
            # because a discarded comment changes nothing.
            if not stripped or stripped.startswith("//"):
                continue
            # A file-scope OBJECT definition above the signature is also
            # discarded, and that is a real defect — `compile_with_fixup` has to
            # guess a definition for it, and guesses wrong for `test_compress`
            # and `main` on zlib. But it is survivable: the function body also
            # carries its own `extern` for the same object, so the snippet still
            # names something. A PREPROCESSOR directive is not survivable — the
            # token it defines simply vanishes, which is what cost 43 functions.
            # Gate the fatal class here; the definition case is tracked
            # separately so this test stays a wall rather than a warning.
            if not stripped.startswith("#") and "GLAURUNG_" not in stripped:
                continue
            problems.append(f"{name}: {stripped[:70]!r} sits above the signature")
    assert not problems, (
        f"{arch} {opt}: text above a signature is discarded by DecBench's "
        f"per-function split and cannot be relied on:\n" + "\n".join(problems)
    )
