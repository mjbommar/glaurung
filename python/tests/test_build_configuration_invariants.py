"""Recovery invariants across BUILD AND LINK CONFIGURATION.

`test_decompiler_emission_invariants.py` varies the ARCHITECTURE and holds the
build fixed. `tests/decompiler_fixtures/` varies the SOURCE and holds the build
fixed. Nothing varies the build. Every one of the 1,676 artifacts in that
corpus is produced by ``gcc|clang -shared -fPIC -g -O{0,2} -w``, so every one is
an ELF ``DYN`` with a PLT, a GOT, a full ``.eh_frame``, an entry VA of zero and
no ``main``. There is not one executable, not one static link, not one
alternative codegen configuration anywhere in the matrix.

That is a gap in what the matrix can prove, not a gap in its size. A binary's
LINK AND CODEGEN CONFIGURATION is chosen independently of its source, it touches
every stage of recovery, and real binaries are overwhelmingly executables:

  * where the image loads (PIE vs fixed-address) changes every absolute VA;
  * whether calls leave through a PLT at all (``-static`` has neither PLT nor
    GOT, so the entire import model is different);
  * whether ``.eh_frame`` describes the function (commit 7fd894e6 made function
    discovery consult ``PT_GNU_EH_FRAME``, so ``-fno-asynchronous-unwind-tables``
    is what exercises the fallback);
  * whether a frame pointer exists to anchor slot naming;
  * whether every frame carries a stack-protector canary;
  * whether the DWARF describing a function sits on the DIE at its ``low_pc``
    or is reached indirectly (``-flto`` always splits it).

The properties below are self-consistency and cross-configuration invariance
properties, deliberately NOT a copy of any benchmark metric. Each one follows
from a single first-principles fact: **the configuration is not part of the
program.** The same source, built two ways, is two encodings of one set of
functions with one set of interfaces. Anything a correct recovery reports about
*the program* must therefore be identical in both; anything that moves with the
flags is the recovery describing the encoding and calling it the program.

Marked `slow`: it compiles eleven configurations and analyses each of them.
Run with ``-m ""`` or ``-m slow``.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from itertools import pairwise
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow

ROOT = Path(__file__).resolve().parent.parent.parent

#: Deliberately NOT under `decompiler_fixtures/src`, for the reason the
#: emission-invariants module gives: that directory is the shared
#: execution-differential corpus with an exact manifest and four committed
#: baselines, and dropping a file into it silently enlarges that gate. This
#: source is compiled by this module alone.
SRC = (
    ROOT
    / "tests"
    / "decompiler_fixtures"
    / "invariants"
    / "link_configuration_shapes.c"
)

#: One compiler, many link/codegen configurations. Holding the compiler fixed is
#: the point: any difference observed below is attributable to the configuration
#: and to nothing else. `-g -w` and the source file are appended to all of them.
#:
#: The four "linkage" lanes at the top differ ONLY in how the image is linked;
#: the rest differ in one codegen decision each, against a `-pie -fPIE -O2`
#: baseline, so that a failing lane names its own cause.
CONFIGS: dict[str, tuple[str, ...]] = {
    # --- linkage, identical codegen intent -------------------------------
    "shared_pic": ("-shared", "-fPIC", "-O2"),
    "pie_exe": ("-pie", "-fPIE", "-O2"),
    "nopie_exe": ("-no-pie", "-fno-pie", "-O2"),
    "static_exe": ("-static", "-no-pie", "-O2"),
    # --- one codegen decision each, against `pie_exe` ---------------------
    #: No FDE for our functions in `.eh_frame`, so discovery cannot lean on
    #: `PT_GNU_EH_FRAME` for them. Verified on this host: `.eh_frame_hdr` drops
    #: from ten entries to four, and the six that leave reappear only in
    #: `.debug_frame`, which `strip -s` then removes as well.
    "no_unwind_tables": ("-pie", "-fPIE", "-O2", "-fno-asynchronous-unwind-tables"),
    "frame_pointer": ("-pie", "-fPIE", "-O2", "-fno-omit-frame-pointer"),
    "omit_frame_pointer": ("-pie", "-fPIE", "-O2", "-fomit-frame-pointer"),
    "size_opt": ("-pie", "-fPIE", "-Os"),
    "lto": ("-pie", "-fPIE", "-O2", "-flto"),
    "stack_protector": ("-pie", "-fPIE", "-O2", "-fstack-protector-strong"),
    #: The contrast lane, and the informative one on a distro toolchain: Ubuntu's
    #: GCC enables `-fstack-protector-strong` by default, so `stack_protector`
    #: above is a no-op here and the only way to obtain a guard-free frame is to
    #: ask for one explicitly. Probed at runtime by
    #: `test_the_stack_guard_is_never_part_of_the_recovered_interface`, which
    #: refuses to run vacuously.
    "no_stack_protector": ("-pie", "-fPIE", "-O2", "-fno-stack-protector"),
}

CONFIG_NAMES = list(CONFIGS)

#: Everything but the shared object. An executable has a real entry point; an
#: ET_DYN library does not, and that difference is a property of the link, so
#: the two are not interchangeable for entry-point questions.
EXECUTABLE_CONFIGS = [name for name in CONFIG_NAMES if name != "shared_pic"]

#: The configuration every other one is compared against. It is the modern
#: default for a Linux executable (PIE, -O2) and is the closest lane to the
#: `-shared -fPIC -O2` the whole fixture matrix already uses.
REFERENCE = "pie_exe"

COMPILER = "gcc"

#: See `test_decompiler_emission_invariants.py`: `local_<hex>` is the
#: frame-offset spelling and the only one that carries a layout claim.
FRAME_LOCAL = re.compile(
    r"^[ \t]+(?:const\s+)?"
    r"(unsigned char|signed char|char|unsigned int|int|unsigned long|long|"
    r"unsigned short|short|float|double|void\s*\*)\s+"
    r"local_([0-9a-fA-F]+)\s*(?:\[(\d+)\])?\s*;",
    re.MULTILINE,
)

#: Widths for the disjointness computation. Where a width is ambiguous we take
#: the SMALLEST plausible size, so this test under-reports rather than inventing
#: an overlap. All lanes here are x86-64, so a pointer is eight bytes.
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
    "unsigned long": 8,
    "long": 8,
}
POINTER_BYTES = 8

#: A recovered definition may lead with a GNU attribute spelled bare on the
#: signature line (`no_stack_protector` is emitted that way on purpose).
ATTR = r"(?:__attribute__\(\(.*?\)\)\s*)*"


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _source_interfaces() -> dict[str, int]:
    """`name -> declared parameter count`, read from the fixture source itself.

    Parsed rather than hard-coded so that a shape added to the .c file is
    covered here without a second edit, exactly as the emission-invariants
    module does it.
    """
    text = SRC.read_text()
    out: dict[str, int] = {}
    for match in re.finditer(
        r"^BC_KEEP\s+[\w \*]+?\b(bc_\w+)\s*\(([^)]*)\)", text, re.MULTILINE
    ):
        name, params = match.group(1), match.group(2).strip()
        out[name] = 0 if params in ("", "void") else len(params.split(","))
    return out


SOURCE_ARITY = _source_interfaces()
FIXTURE_FUNCTIONS = frozenset(SOURCE_ARITY)


def _compile(config: str, out: Path) -> subprocess.CompletedProcess:
    argv = [COMPILER, "-g", "-w", *CONFIGS[config], "-o", str(out), str(SRC)]
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=300, check=False
    )


def _symbol_vas(binary: Path) -> dict[str, int]:
    """`bc_*` entry addresses straight out of the symbol table.

    Ground truth for this module comes from `nm`, not from Glaurung: a test that
    asked the tool under test where the functions are could not detect the tool
    losing one.
    """
    done = subprocess.run(
        ["nm", str(binary)], capture_output=True, text=True, timeout=120, check=True
    )
    out: dict[str, int] = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in ("T", "t") and parts[2] in FIXTURE_FUNCTIONS:
            out[parts[2]] = int(parts[0], 16)
    return out


def _decompile_by_va(binary: Path, vas: dict[str, int]) -> dict[str, str]:
    """Recover exactly the requested entries, in one analysis pass.

    Seeding by VA is what keeps this cheap enough to run over eleven
    configurations (the static lane alone discovers a thousand functions), and it
    separates the concerns cleanly: DISCOVERY is tested on its own below, from
    the symbol table, so the recovery properties do not silently depend on it.
    """
    argv = [
        "glaurung",
        "decompile",
        str(binary),
        "--style",
        "decbench",
        "--no-color",
        "--json",
        "--vas",
        ",".join(hex(va) for va in vas.values()),
    ]
    done = subprocess.run(
        argv, capture_output=True, text=True, timeout=900, check=False
    )
    assert done.returncode == 0, f"{binary.name}: {done.stderr}"
    return {rec["name"]: rec["pseudocode"] for rec in json.loads(done.stdout)}


def _discovered_vas(binary: Path) -> set[int]:
    argv = [
        "glaurung",
        "cfg",
        str(binary),
        "--json",
        "--max-functions",
        "0",
        "--total-timeout-ms",
        "300000",
    ]
    done = subprocess.run(
        argv, capture_output=True, text=True, timeout=900, check=False
    )
    assert done.returncode == 0, f"{binary.name}: {done.stderr}"
    return {fn["entry_point"] for fn in json.loads(done.stdout).get("functions", [])}


def _signature(body: str, name: str) -> str | None:
    match = re.search(rf"^{ATTR}(\w[\w \*]*\b{name}\s*\([^)]*\))", body, re.MULTILINE)
    return re.sub(r"\s+", " ", match.group(1)) if match else None


def _arity(signature: str) -> int:
    params = signature[signature.index("(") + 1 : signature.rindex(")")].strip()
    return 0 if params in ("", "void") else len(params.split(","))


def _frame_extents(body: str) -> list[tuple[int, int, str]]:
    """Ascending (start, end, spelling) frame spans, relative to the frame pointer.

    `local_<hex>` names a slot by the ABSOLUTE VALUE of a NEGATIVE displacement,
    so a LARGER label is a LOWER address and ascending memory order is descending
    label order. Sorting by the label instead of the address inverts every
    comparison and makes a correctly tiled frame look like a pile of overlaps —
    see the long note in `test_decompiler_emission_invariants._frame_extents`.
    """
    spans: list[tuple[int, int, str]] = []
    for ctype, off, count in FRAME_LOCAL.findall(body):
        width = (
            POINTER_BYTES
            if ctype.strip().endswith("*")
            else SCALAR_BYTES.get(" ".join(ctype.split()), 1)
        )
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


#: `slot = varN;` — the whole right-hand side and nothing else. This is the
#: ENTRY SPILL idiom, where `varN` stands for the CALLER's value of a
#: callee-saved register: unassigned by construction, meaningful, and emitted on
#: every architecture. Flagging it would make the undefined-read property fire on
#: every function ever compiled.
SPILL = re.compile(r"^[ \t]*(?:\*?\(?[^=;]*?\)?)\s*=\s*(var\d+)\s*;\s*$")


def _is_observable_use(line: str, var: str, spill: re.Pattern[str]) -> bool:
    """True when `line` lets `var` influence something other than its own spill."""
    if not re.search(rf"\b{var}\b", line):
        return False
    if re.match(rf"^[ \t]+[\w \*]+?\b{var}\s*;", line):
        return False  # the declaration itself
    match = spill.match(line)
    return match is None or match.group(1) != var


def _declared_locals(body: str) -> set[str]:
    return set(
        re.findall(
            r"^[ \t]+[\w \*]+?\b((?:var\d+|local_[0-9a-fA-F]+|rsp|rbp))\s*;",
            body,
            re.MULTILINE,
        )
    )


def _unassigned_reads(body: str) -> list[str]:
    """Locals whose value is never established yet reach an observable use.

    Two shapes, and the second is the one a naive check misses. A name with no
    assignment at all is obviously undefined. A name whose ONLY assignments read
    itself — `rsp = (rsp - 88);` and nothing else — is equally undefined: no
    statement gives it a first value, so the arithmetic is over whatever the
    declaration left there. A legitimate accumulator or induction variable always
    has at least one assignment that does not read itself (its initialiser), so
    requiring one is not a constraint on correct output.
    """
    out: list[str] = []
    for var in sorted(_declared_locals(body)):
        assignments = re.findall(rf"^[ \t]*{var}\s*=\s*([^;]+);", body, re.MULTILINE)
        establishes = [rhs for rhs in assignments if not re.search(rf"\b{var}\b", rhs)]
        if assignments and establishes:
            continue
        observable = [
            line for line in body.splitlines() if _is_observable_use(line, var, SPILL)
        ]
        if not observable:
            continue
        how = (
            "is never assigned"
            if not assignments
            else f"is only ever assigned from itself ({var} = {assignments[0].strip()})"
        )
        out.append(
            f"{var} {how} yet reaches {len(observable)} observable use(s), "
            f"e.g. {observable[0].strip()[:70]}"
        )
    return out


def _configs_xfail(failing: set[str], reason: str) -> list:
    """`CONFIG_NAMES` with some configurations marked as known-failing.

    `strict=True`, for the reason the emission-invariants module gives: the
    marker itself fails once the defect is fixed, which forces the reason text
    to be removed rather than left to rot into a lie.
    """
    return [
        pytest.param(name, marks=pytest.mark.xfail(reason=reason, strict=True))
        if name in failing
        else name
        for name in CONFIG_NAMES
    ]


# --------------------------------------------------------------------------
# Build. A configuration that cannot build on this host is recorded, never
# silently dropped: a skip that does not say what it skipped is how an axis
# stops being tested without anyone noticing.
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> dict:
    if not _have(COMPILER):
        pytest.skip(f"DECLARED SKIP: no {COMPILER} on this host")
    if not _have("nm"):
        pytest.skip("DECLARED SKIP: no `nm`; ground-truth addresses are unavailable")
    root = tmp_path_factory.mktemp("build-configuration-invariants")
    binaries: dict[str, Path] = {}
    stripped: dict[str, Path] = {}
    failures: dict[str, str] = {}
    for name in CONFIG_NAMES:
        target = root / name
        done = _compile(name, target)
        if done.returncode != 0:
            failures[name] = (done.stderr.strip() or "no diagnostic").splitlines()[-1]
            continue
        binaries[name] = target
        if _have("strip"):
            copy = root / f"{name}.stripped"
            copy.write_bytes(target.read_bytes())
            copy.chmod(0o755)
            if (
                subprocess.run(
                    ["strip", "-s", str(copy)],
                    capture_output=True,
                    timeout=120,
                    check=False,
                ).returncode
                == 0
            ):
                stripped[name] = copy
    assert binaries, f"no configuration built at all: {failures}"
    return {"binaries": binaries, "stripped": stripped, "failures": failures}


@pytest.fixture(scope="module")
def recovered(built) -> dict[str, dict[str, str]]:
    """`config -> {function name -> recovered body}`, one analysis pass each."""
    out: dict[str, dict[str, str]] = {}
    for name, binary in built["binaries"].items():
        vas = _symbol_vas(binary)
        assert set(vas) == FIXTURE_FUNCTIONS, (
            f"{name}: the symbol table itself is missing "
            f"{sorted(FIXTURE_FUNCTIONS - set(vas))} — the build, not the tool"
        )
        out[name] = _decompile_by_va(binary, vas)
    return out


def _require(built, config: str) -> Path:
    if config in built["failures"]:
        pytest.skip(
            f"DECLARED SKIP: `{COMPILER} {' '.join(CONFIGS[config])}` does not build "
            f"on this host: {built['failures'][config]}"
        )
    return built["binaries"][config]


# --------------------------------------------------------------------------
# 1. Discovery invariance.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("config", CONFIG_NAMES)
def test_every_source_function_is_discovered_in_every_configuration(
    built, config
) -> None:
    """A function exists because its code exists, not because of how it linked.

    Each of these functions is `noinline` and has its address taken, so it is
    present, whole and out-of-line in every configuration; `nm` says exactly
    where. Finding it in one configuration and not another is a defect whichever
    way round it falls, because nothing about the *program* differs between the
    two — only the link.

    This is the property the `-fno-asynchronous-unwind-tables` lane exists for.
    Discovery consults `PT_GNU_EH_FRAME` (7fd894e6), and under that flag our
    functions have no FDE at all; a discovery that has quietly become dependent
    on the unwind tables loses them here and nowhere else.
    """
    binary = _require(built, config)
    want = _symbol_vas(binary)
    assert set(want) == FIXTURE_FUNCTIONS, (
        f"{config}: the symbol table itself is missing "
        f"{sorted(FIXTURE_FUNCTIONS - set(want))} — nothing can be proved about "
        "discovery from a build that did not emit the functions"
    )
    found = _discovered_vas(binary)
    missing = sorted(name for name, va in want.items() if va not in found)
    assert not missing, (
        f"{config}: {', '.join(missing)} present in the symbol table but not "
        f"discovered ({len(found)} functions found)"
    )


@pytest.mark.parametrize("config", CONFIG_NAMES)
def test_stripping_removes_no_function_in_any_configuration(built, config) -> None:
    """`strip` removes names, not code, so it cannot remove a function.

    The unstripped run above may be reading the symbol table; this one cannot,
    because there is no symbol table left. It is therefore the actual test of
    discovery, and it is what makes the `no_unwind_tables` lane bite: `strip -s`
    also removes `.debug_frame`, so in that configuration our functions are
    described by no symbol, no FDE and no debug frame, and discovery has to find
    them from the code alone. Ground truth still comes from `nm` on the
    UNstripped copy of the same link.
    """
    _require(built, config)
    if config not in built["stripped"]:
        pytest.skip(f"DECLARED SKIP: `strip` unavailable or failed for {config}")
    want = _symbol_vas(built["binaries"][config])
    assert set(want) == FIXTURE_FUNCTIONS, f"{config}: incomplete ground truth {want}"
    found = _discovered_vas(built["stripped"][config])
    missing = sorted(name for name, va in want.items() if va not in found)
    assert not missing, (
        f"{config} stripped: {', '.join(missing)} at "
        f"{', '.join(hex(want[m]) for m in missing)} not discovered "
        f"({len(found)} functions found)"
    )


# --------------------------------------------------------------------------
# 2. Arity invariance.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("config", CONFIG_NAMES)
def test_recovered_arity_matches_the_source_in_every_configuration(
    built, recovered, config
) -> None:
    """The machine code differs between configurations; the interface does not.

    Every function here is `noinline` and has its address escape through a
    `volatile` function pointer, which pins the ABI-level interface: GCC may not
    apply IPA-SRA, cloning or constant propagation to a function whose address
    escapes, so the parameter list really is the same list in all eleven
    binaries. A recovered arity that moves is therefore the recovery reading the
    prologue rather than the interface.

    Equality, not a bound. Under-reporting is as wrong as over-reporting here:
    an unused argument could legitimately vanish at -O2, but every parameter of
    every function in this fixture is used in its return value, so none of them
    can be optimised out of existence.
    """
    _require(built, config)
    bodies = recovered[config]
    problems = []
    for name, want in sorted(SOURCE_ARITY.items()):
        body = bodies.get(name)
        if body is None:
            problems.append(f"{name}: recovered no body at all")
            continue
        signature = _signature(body, name)
        if signature is None:
            problems.append(f"{name}: no parseable signature")
            continue
        got = _arity(signature)
        if got != want:
            problems.append(
                f"{name}: recovered {got} parameter(s) for a source that "
                f"declares {want} — {signature}"
            )
    assert not problems, f"{config} arity:\n" + "\n".join(problems)


# --------------------------------------------------------------------------
# 3. Interface invariance, types included.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("config", CONFIG_NAMES)
def test_the_recovered_interface_is_identical_in_every_configuration(
    built, recovered, config
) -> None:
    """A function's return type and parameter types come from its source.

    Arity is the coarsest half of an interface. The types are the other half,
    and they are just as much a property of the program rather than of the
    build: `bc_leaf_add` returns `int` whether or not the link was static,
    whether or not a frame pointer survived, and whether or not the compiler
    was asked to optimise for size.

    So the whole recovered signature is compared, character for character, with
    the same signature recovered from the reference configuration. This is a
    pure invariance property: it does not assert that the reference is RIGHT,
    only that eleven encodings of one program are described one way. A tool that
    is uniformly wrong passes; a tool whose answer depends on the build cannot.
    """
    _require(built, config)
    if REFERENCE in built["failures"]:
        pytest.skip(f"DECLARED SKIP: reference configuration {REFERENCE} did not build")
    if config == REFERENCE:
        pytest.skip("the reference configuration is compared against, not with")
    problems = []
    for name in sorted(FIXTURE_FUNCTIONS):
        want = _signature(recovered[REFERENCE].get(name, ""), name)
        got = _signature(recovered[config].get(name, ""), name)
        assert want is not None, (
            f"{REFERENCE}: no parseable signature for {name}, so there is "
            "nothing to compare against and this test would pass vacuously"
        )
        if want != got:
            problems.append(f"{name}:\n    {REFERENCE}: {want}\n    {config}: {got}")
    assert not problems, (
        f"{config} recovers a different interface from {REFERENCE} for the same "
        f"source:\n" + "\n".join(problems)
    )


# --------------------------------------------------------------------------
# 4. Frame disjointness.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("config", CONFIG_NAMES)
def test_frame_locals_occupy_disjoint_byte_ranges(built, recovered, config) -> None:
    """Two named frame slots may not claim the same byte, in any configuration.

    The property is the one the emission-invariants module states, applied to a
    different axis. It matters here because two of these configurations attack
    the frame model from opposite directions: `-fomit-frame-pointer` removes the
    register the `local_<hex>` naming is anchored to, so every slot has to be
    named relative to a moving stack pointer instead, and
    `-fstack-protector-strong` inserts an extra eight-byte slot at the top of the
    frame that the source never declared. Either can shift a recovered extent
    without changing behaviour, which is precisely the class of defect no
    execution differential can see.

    `bc_buffer_and_scalars` stores its array's address into a `volatile` global
    specifically so that the array survives -O2 and -Os: without that escape the
    optimiser scalarises the function completely, it touches no stack at all, and
    this test passes vacuously in the two configurations that need it most.
    """
    _require(built, config)
    problems: list[str] = []
    declared_any = 0
    for name, body in sorted(recovered[config].items()):
        spans = _frame_extents(body)
        declared_any += len(spans)
        for message in _overlaps(spans):
            problems.append(f"{name}: {message}")
    assert declared_any >= 1, (
        f"{config}: no frame slot was recovered in any function, so this test "
        "would pass by describing nothing. Every configuration allocates a real "
        "frame here — `bc_buffer_and_scalars` stores its array's address into a "
        "`volatile` global precisely so the optimiser cannot remove it."
    )
    assert not problems, f"{config} overlapping frame locals:\n" + "\n".join(problems)


# --------------------------------------------------------------------------
# 5. Determinism.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("config", CONFIG_NAMES)
def test_decompiling_the_same_binary_twice_is_deterministic(built, config) -> None:
    """Non-determinism would make every other property here unfalsifiable.

    Checked per configuration rather than once, because the analyses that differ
    between configurations are exactly the ones that could introduce it: address
    ordering under a fixed load address, PLT-free call resolution in a static
    link, and unwind-table-seeded discovery all take different code paths.
    """
    binary = _require(built, config)
    vas = _symbol_vas(binary)
    first = _decompile_by_va(binary, vas)
    second = _decompile_by_va(binary, vas)
    assert first == second, f"{config}: two runs over identical bytes disagreed"


# --------------------------------------------------------------------------
# 6. The stack guard is not part of the interface.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("config", CONFIG_NAMES)
def test_the_stack_guard_is_never_part_of_the_recovered_interface(
    built, recovered, config
) -> None:
    """A canary is scaffolding the compiler added; the source never mentions it.

    `-fstack-protector-strong` gives a protected function an extra live-in value
    (a load from thread-local storage), an extra frame slot and an extra
    comparison. None of that is part of what the function receives from its
    caller. Two ways for it to leak into the interface, and both are checked:

      * as a PARAMETER. A physical location read before it is written is
        live-in, and a live-in that lands where the ABI puts an argument is what
        parameter recovery promotes. The guard load is read-before-written by
        construction, so any model that puts it in an argument location
        manufactures an argument.
      * as an unassigned LOCAL that reaches something observable. If the guard
        slot is declared but its defining load is dropped, the emitted function
        branches on a value nothing gave it.

    The entry-spill idiom `slot = varN`, where `varN` stands for the caller's
    value of a callee-saved register, is exempt for the reason the
    emission-invariants module gives: it is unassigned by construction, it is
    meaningful, and every architecture emits it.

    Non-vacuity is enforced, not assumed: the test refuses to pass in a
    configuration where nothing was actually protected. That matters on this
    host, where the distro GCC turns `-fstack-protector-strong` on by default
    and the flag lane is a no-op.
    """
    _require(built, config)
    bodies = recovered[config]
    protected = [name for name, body in bodies.items() if "__stack_chk" in body]
    if not protected:
        pytest.skip(
            f"DECLARED SKIP: {config} emitted no stack guard at all, so there is "
            "no guard to keep out of an interface"
        )
    problems: list[str] = []
    for name in sorted(protected):
        body = bodies[name]
        signature = _signature(body, name)
        if signature and _arity(signature) != SOURCE_ARITY[name]:
            problems.append(
                f"{name}: protected function recovered with "
                f"{_arity(signature)} parameter(s), source declares "
                f"{SOURCE_ARITY[name]} — {signature}"
            )
        declared = set(
            re.findall(
                r"^[ \t]+[\w \*]+?\b((?:var\d+|local_[0-9a-fA-F]+))\s*;",
                body,
                re.MULTILINE,
            )
        )
        for var in sorted(declared):
            if re.search(rf"^[ \t]*{var}\s*=[^=]", body, re.MULTILINE):
                continue
            observable = [
                line
                for line in body.splitlines()
                if _is_observable_use(line, var, SPILL)
            ]
            if observable:
                problems.append(
                    f"{name}: {var} is never assigned yet reaches "
                    f"{len(observable)} observable use(s), e.g. "
                    f"{observable[0].strip()[:70]}"
                )
    assert not problems, (
        f"{config} stack guard leaked into the interface:\n" + "\n".join(problems)
    )


# --------------------------------------------------------------------------
# 7. A recovered branch describes a branch that was really there.
# --------------------------------------------------------------------------
#: Configurations in which the recovery is known to emit a statically decidable
#: guard. Every lane whose frame carries a canary is here, which on this host is
#: every lane except the one that explicitly asks for no protector: the defect is
#: in how the guard LOAD is modelled, so it appears wherever a guard appears and
#: is unrelated to linkage, frame pointers or optimisation level. The set can
#: only shrink — a listed lane that stops exhibiting it fails this test.
DECIDABLE_GUARD_KNOWN_BAD = {
    "shared_pic",
    "pie_exe",
    "nopie_exe",
    "static_exe",
    "no_unwind_tables",
    "frame_pointer",
    "omit_frame_pointer",
    "size_opt",
    "lto",
    "stack_protector",
}


@pytest.mark.parametrize("config", CONFIG_NAMES)
def test_no_recovered_condition_is_decidable_from_the_emitted_code_alone(
    built, recovered, config
) -> None:
    """A conditional in the output stands for a conditional branch in the code.

    The argument is short and does not depend on knowing what the source said.
    A conditional branch only reaches the recovered output because the machine
    code contained one. If the compiler had been able to prove the condition
    constant it would not have emitted the branch. So a recovered `if` whose
    condition can be decided from the emitted text alone — a variable
    unconditionally assigned one literal and then compared against that same
    literal — cannot be describing the branch that was there. Something the
    condition depended on was replaced by a constant, and the recovered function
    now has a provably dead arm where the original had a runtime decision.

    Recompiled, such a function simply loses the check. That is invisible to an
    execution differential on any input that does not take the arm, and it is
    invisible to every arity, frame and prototype property in this file.

    The instance that motivates the shape is the stack-protector prologue.
    `mov %fs:0x28, %rax` loads an opaque per-thread value; modelling the
    segment-relative load as the literal offset `0x28` turns the epilogue's
    `if (slot != 0x28)` into `if (0x28 != 0x28)`. But the property is written
    against the SHAPE, not against the canary: any load from memory the analysis
    cannot see is an unknown value, and rendering an unknown as a literal
    produces exactly this signature.
    """
    _require(built, config)
    problems: list[str] = []
    for name, body in sorted(recovered[config].items()):
        declared = re.findall(
            r"^[ \t]+[\w \*]+?\b((?:var\d+|local_[0-9a-fA-F]+))\s*;",
            body,
            re.MULTILINE,
        )
        for var in sorted(set(declared)):
            assignments = re.findall(
                rf"^[ \t]*{var}\s*=\s*([^;]+);", body, re.MULTILINE
            )
            if len(assignments) != 1:
                continue  # more than one definition: not decidable from the text
            literal = re.fullmatch(
                r"\(?\s*(?:\(\s*[\w ]+\s*\)\s*)?\(?\s*(0x[0-9a-fA-F]+|\d+)\s*\)?\s*\)?",
                assignments[0].strip(),
            )
            if not literal:
                continue
            value = literal.group(1)
            if re.search(rf"if\s*\(\(?\s*{var}\s*[!=]=\s*{value}\b", body):
                problems.append(
                    f"{name}: {var} is assigned {value} exactly once and then "
                    f"compared against {value}, so the guard it protects is "
                    "dead in the recovered code"
                )
    guarded = any("__stack_chk" in body for body in recovered[config].values())
    if config in DECIDABLE_GUARD_KNOWN_BAD and not guarded:
        pytest.skip(
            f"DECLARED SKIP: this host's toolchain emitted no stack guard in "
            f"{config}, so the recorded defect has nothing to appear in. On the "
            "host this set was measured, Ubuntu GCC 15.2 defaults to "
            "-fstack-protector-strong and every lane but `no_stack_protector` "
            "carried a guard."
        )
    if config in DECIDABLE_GUARD_KNOWN_BAD:
        assert problems, (
            f"{config} no longer emits a statically decidable guard — remove it "
            "from DECIDABLE_GUARD_KNOWN_BAD so the gate ratchets and cannot "
            "slide back."
        )
        pytest.xfail(f"{config}: decidable guard is a known open defect")
    assert not problems, f"{config} emitted a decidable condition:\n" + "\n".join(
        problems
    )


# --------------------------------------------------------------------------
# 8. An executable has an entry point and a shared object does not.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("config", EXECUTABLE_CONFIGS)
def test_the_default_entry_point_decompile_works_for_an_executable(
    built, config
) -> None:
    """Recovery driven from the entry point must work on the shape that has one.

    The whole fixture corpus is `-shared`, so the entry VA is zero and the CLI's
    default single-function mode cannot run on any of it — the
    emission-invariants module says so in a comment and passes `--all` to work
    around it. That means the default path a user actually types,
    `glaurung decompile <binary>`, is exercised by no fixture in the tree
    against any link configuration.

    An `ET_EXEC`/PIE image has a real `e_entry`, so the default path must reach a
    function and recover a body there, in all four linkage lanes and under every
    codegen flag. The shared object is excluded rather than xfailed because its
    absence of an entry point is correct, not a defect.
    """
    binary = _require(built, config)
    done = subprocess.run(
        ["glaurung", "decompile", str(binary), "--style", "decbench", "--no-color"],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    assert done.returncode == 0, (
        f"{config}: entry-point decompile failed: {done.stderr}"
    )
    assert re.search(r"^// glaurung: \S+ @ 0x[0-9a-f]+", done.stdout, re.MULTILINE), (
        f"{config}: entry-point decompile produced no function banner:\n"
        f"{done.stdout[:400]}"
    )


# --------------------------------------------------------------------------
# 9. A stack object that exists in the machine code is recovered as one.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "config",
    _configs_xfail(
        {"lto"},
        "OPEN DEFECT (-flto): `bc_buffer_and_scalars` recovers NO frame object "
        "at all. The 64-byte array becomes `long rsp; rsp = (rsp - 88);` — the "
        "stack pointer modelled as an ordinary local that is read before it is "
        "written — and every write to the array is then `*(signed char *)(var5 - "
        "1)` off that undefined value. Same root cause as the interface defect: "
        "with the DWARF facts unreachable through the cross-CU "
        "`DW_AT_abstract_origin`, nothing establishes the frame, so the prologue "
        "`sub $0x58,%rsp` is lifted as arithmetic on an unknown rather than as a "
        "frame allocation.",
    ),
)
def test_a_frame_object_is_recovered_wherever_the_machine_code_allocates_one(
    built, recovered, config
) -> None:
    """An address computed from the frame register and stored away IS a local.

    `bc_buffer_and_scalars` puts the address of a 64-byte automatic array into a
    `volatile` global, so in every one of these eleven links the compiler must
    emit a real frame allocation and a real frame-relative address computation —
    there is no configuration in which that array can be scalarised away. A
    recovery that declares no frame object for it has not merely named the slot
    badly: it has no model of the frame at all, and every access through that
    address is then arithmetic on something the emitted C never defines.

    This is separate from disjointness on purpose. Disjointness asks whether the
    slots that WERE recovered can coexist; it is trivially satisfied by
    recovering none. This asks whether they were recovered.
    """
    _require(built, config)
    body = recovered[config].get("bc_buffer_and_scalars")
    assert body, f"{config}: bc_buffer_and_scalars recovered no body"
    arrays = [
        f"local_{off}[{count}]"
        for _, off, count in FRAME_LOCAL.findall(body)
        if count and int(count) > 1
    ]
    assert arrays, (
        f"{config}: bc_buffer_and_scalars declares no frame array, though its "
        "source array's address escapes into a volatile global and therefore "
        f"cannot have been optimised out. Recovered:\n{body}"
    )


# --------------------------------------------------------------------------
# 10. A value read is a value assigned, in every configuration.
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "config",
    _configs_xfail(
        {"lto"},
        "OPEN DEFECT (-flto): `bc_buffer_and_scalars` emits `long rsp;` and then "
        "`rsp = (rsp - 88);` as its first statement, so the stack pointer is read "
        "before anything defines it and that undefined value reaches a store to a "
        "global and every write into the buffer. The recovered function's "
        "behaviour is not merely unknown, it is unspecified. Same mechanism as "
        "the interface defect above: no DWARF reaches the concrete DIE, so no "
        "frame is established.",
    ),
)
def test_no_recovered_local_is_read_without_ever_being_assigned(
    built, recovered, config
) -> None:
    """An unassigned value must not be able to influence the result.

    The emission-invariants module checks this across ARCHITECTURES; it belongs
    on this axis too, and for a sharper reason. Whether a frame pointer exists,
    whether the image is position-independent, and whether the DWARF is reachable
    are all configuration decisions, and each of them can remove the thing that
    would have defined a value — leaving a name in the output that nothing
    assigns. A configuration in which some value stops having a definition is
    exactly a configuration in which the recovery stopped having a model.

    The entry-spill idiom `slot = varN` is exempt (see `SPILL`): `varN` stands
    for the caller's value of a callee-saved register, it is unassigned by
    construction, and every target emits it.
    """
    _require(built, config)
    problems: list[str] = []
    for name, body in sorted(recovered[config].items()):
        for message in _unassigned_reads(body):
            problems.append(f"{name}: {message}")
    assert not problems, f"{config} reads undefined locals:\n" + "\n".join(problems)
