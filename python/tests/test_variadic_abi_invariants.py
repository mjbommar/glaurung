"""Recovery invariants for the x86-64 VARIADIC REGISTER SAVE AREA.

WHERE THIS CAME FROM
--------------------
Decompiling `/usr/bin/bash` (stripped, `-O2`, PIE, no DWARF) reports
definition-before-use violations in 304 of 2,953 rendered functions, 1,152
undefined reads. Classifying all 1,152 by mechanism put **555 of them (48.2%),
spread over just 17 functions, in a single class**: the x86-64 SysV variadic
register save area. Every one of those seventeen is a `printf`-style forwarder
-- `fatal_error`, `internal_error`, `internal_warning`, `sys_error`,
`builtin_error`, `parser_error`, `rl_message`, ... -- and each contributes
almost exactly the same 32 or 33 violations, because what it contributes is not
a bug per function but the fixed size of an ABI structure.

THE MECHANISM
-------------
`va_start` cannot know how many variadic arguments arrived, so the prologue
spills the whole incoming argument register file into a save area:

    *(long *)(&local_38[0] + 8)  = var0;   // rsi
    *(long *)(&local_38[0] + 16) = var1;   // rdx
    ...                          = var4;   // r9
    if (((unsigned char)((ret & 255))) != 0) {   // test al, al
        local_90 = var1; ... local_14 = var32;   // xmm0..xmm7, 4 halves each
    }

`var0..var4` are the incoming INTEGER argument registers, `var1..var32` the
eight incoming VECTOR registers, and `ret` is `al` -- the count of vector
registers the caller used, which lives in `rax` and is therefore given the ABI
RETURN-role name by the recovery. All of them are incoming ABI state. The
recovered prototype, however, names only the FIXED parameters (`int f(int
arg0)`), because the variadic ones have no fixed arity to recover -- so nothing
in the emitted C defines any of them, and the save area is built out of
uninitialised variables.

THIS IS WRONG CODE, NOT COSMETIC NOISE. The save area is not dead: the
`va_list` points into it and `va_arg` reads it straight back --
`*(int *)(&local_38[0] + var19)` in the very same function. Recompiled, every
`va_arg` in the function returns garbage.
`test_the_undefined_values_are_read_back_out_of_the_save_area` asserts exactly
that, so the finding cannot be dismissed as a naming artefact.

WHY NO EXISTING GATE SEES IT
----------------------------
`113_varargs.c` is the ONLY fixture in the 219-fixture corpus that mentions
`stdarg.h`, and it cannot exhibit the shape. Both of its variadic functions are
`static` and are called only with compile-time-constant counts, so `-O2` inlines
them and no variadic body survives; and both use `va_arg(ap, int32_t)` only, so
GCC proves the vector half of the save area dead and never emits the `test al,
al` guard or the eight `movaps`. The corpus therefore contains the *word*
`varargs` and none of the recovery problem.

Note what this means: the class does NOT require the stripped, optimised,
no-DWARF executable it was found in. It reproduces in `gcc|clang -shared -fPIC
-g -O{0,2}` -- the exact configuration all 1,676 existing fixture artifacts are
built with -- in all four lanes. The gap is in the SOURCE corpus, not the build
matrix.

WHY THIS IS A SELF-CONTAINED MODULE AND NOT A NUMBERED FIXTURE
--------------------------------------------------------------
Adding `220_variadic_register_save_area.c` to `tests/decompiler_fixtures/src/`
would require refreshing four committed baselines (`baseline.json`,
`structural_baseline.json`, `arch_baseline.json`, `defuse_baseline.json`) and,
because the shape produces 5-38 undefined reads per function in every lane,
would land in `defuse_baseline.json` as a large accepted regression -- recording
the defect as the expected number rather than stating it as a property. This
module states the property instead, follows
`test_build_configuration_invariants.py`'s precedent of compiling its own
purpose-built source, and touches no baseline.

Compiles four small lanes and decompiles each; deliberately NOT `slow`-marked,
so it runs in the ordinary suite. The whole module is a few seconds, and the
lesson of `defuse_baseline.json` is that a `slow`-marked gate is a gate people
do not run.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent

#: Deliberately NOT under `decompiler_fixtures/src`: that directory is the
#: execution-differential corpus with an exact manifest and four committed
#: baselines, and dropping a file into it silently enlarges that gate. Same
#: reasoning, and same directory, as `link_configuration_shapes.c`.
SRC = (
    ROOT
    / "tests"
    / "decompiler_fixtures"
    / "invariants"
    / "variadic_register_save_area.c"
)

#: The corpus's own build configuration, in both compilers and both
#: optimisation levels. Holding this identical to what every one of the 1,676
#: fixture artifacts is built with is the point: it is what makes "the existing
#: corpus could have caught this and does not" a demonstrated claim rather than
#: an assertion.
LANES = [("gcc", "O0"), ("gcc", "O2"), ("clang", "O0"), ("clang", "O2")]

#: Functions that ARE variadic, and must therefore materialise a save area.
VARIADIC = ("vsa_forward", "vsa_int_only", "vsa_double_args")

#: Functions that are NOT variadic. Same translation unit, same command, same
#: incoming argument registers -- so a violation here is the harness or the
#: general register model, never the `...`.
CONTROLS = ("vsa_control_fixed", "vsa_control_mixed")

#: `// glaurung: <name> @ 0x<va>` -- the provenance header every rendered
#: function begins with, and what every consumer splits multi-function output on.
HEADER = re.compile(r"(?m)^// glaurung: (\S+) @ (0x[0-9a-fA-F]+)\s*$")

#: One reported definition-before-use violation, spliced in by
#: `GLAURUNG_VERIFY_DEFS=1` immediately after the header.
VERIFY = re.compile(r"(?m)^// glaurung-verify: (.+)$")

#: The name at the front of a violation message, whatever the violation kind.
VIOLATION_NAME = re.compile(r"^(\S+) (?:is|reads)\b")

#: A store whose SOURCE is a bare invented value: `<anything> = varN;`. This is
#: the save-area spill idiom -- and, for a name with no definition, the whole of
#: the mechanism this module is about.
SPILL = re.compile(r"^\s*(?P<dst>[^=;]+?)\s*=\s*(?P<src>var\d+|ret)\s*;\s*$")

#: `if ((... (ret & 255) ...) != 0)` -- the `test al, al` that guards the VECTOR
#: half of the save area. `al` lives in `rax`, so the recovery gives it the ABI
#: return-role name `ret`; this is the one place an undefined value is read by
#: something other than a spill, and it is part of the same ABI structure.
VECTOR_COUNT_GUARD = re.compile(r"^\s*(?:\}\s*else\s*)?if\s*\(.*\bret\b.*&\s*255")


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def _compile(cc: str, opt: str, out: Path) -> subprocess.CompletedProcess:
    argv = [cc, "-shared", "-fPIC", "-g", "-w", f"-{opt}", "-o", str(out), str(SRC)]
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=300, check=False
    )


def _decompile(binary: Path) -> dict[str, str]:
    """`{function name -> full rendered block}` for one shared object.

    `GLAURUNG_VERIFY_DEFS=1` is what splices the `// glaurung-verify:` lines in.
    They are instrumentation and are off by default -- the decbench render is an
    artifact other tools score -- so this module asks for them explicitly, the
    same way `tests/decompiler_fixtures/structural.py` does.
    """
    argv = [
        "glaurung",
        "decompile",
        str(binary),
        "--all",
        "--limit",
        "60",
        "--style",
        "decbench",
        "--no-color",
    ]
    done = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
        # Instrumentation is opt-in; `os.environ` first so a caller's own
        # setting of it cannot be clobbered by this default.
        env={**os.environ, "GLAURUNG_VERIFY_DEFS": "1"},
    )
    assert done.returncode == 0, f"{binary.name}: {done.stderr[-400:]}"
    parts = list(HEADER.finditer(done.stdout))
    return {
        m.group(1): done.stdout[
            m.start() : (
                parts[i + 1].start() if i + 1 < len(parts) else len(done.stdout)
            )
        ]
        for i, m in enumerate(parts)
    }


def _violations(block: str) -> list[str]:
    """The undefined NAMES reported for one rendered function."""
    out = []
    for message in VERIFY.findall(block):
        match = VIOLATION_NAME.match(message)
        if match:
            out.append(match.group(1))
    return out


def _code(block: str) -> list[str]:
    return [
        line
        for line in block.splitlines()
        if line.strip() and not line.strip().startswith("//")
    ]


def _uses(block: str, name: str) -> list[str]:
    """Lines that READ `name`, excluding its declaration and its definitions.

    `ret` is both the incoming `al` and the ABI return register, so a variadic
    function contains real DEFINITIONS of it (`ret = (unsigned int)(total);`)
    alongside the undefined read in the vector-count guard. A line that only
    assigns the name is not a use of it, and counting it as one would make the
    mechanism characterisation below unsatisfiable for `ret` in every lane.
    """
    word = re.compile(rf"\b{re.escape(name)}\b")
    out = []
    for line in _code(block):
        stripped = line.strip()
        if not word.search(stripped):
            continue
        if re.fullmatch(rf"(?:[\w \*]+?)\b{re.escape(name)}\s*;", stripped):
            continue  # the declaration
        assignment = re.match(rf"^{re.escape(name)}\s*=\s*(?P<rhs>.+);$", stripped)
        if assignment and not word.search(assignment.group("rhs")):
            continue  # a definition of this name, not a read of it
        out.append(stripped)
    return out


def _signature(block: str, name: str) -> str | None:
    match = re.search(rf"(?m)^[\w][\w \*]*\b{re.escape(name)}\s*\([^)]*\)", block)
    return re.sub(r"\s+", " ", match.group(0)) if match else None


# --------------------------------------------------------------------------
# Build once for all four lanes. A lane that cannot build is recorded, never
# silently dropped -- a skip that does not say what it skipped is how an axis
# stops being tested without anyone noticing.
# --------------------------------------------------------------------------
@pytest.fixture(scope="module")
def recovered(tmp_path_factory: pytest.TempPathFactory) -> dict:
    if not SRC.exists():  # pragma: no cover - the source ships with this module
        pytest.skip(f"DECLARED SKIP: missing {SRC}")
    root = tmp_path_factory.mktemp("variadic-abi-invariants")
    lanes: dict[tuple[str, str], dict[str, str]] = {}
    failures: dict[tuple[str, str], str] = {}
    for cc, opt in LANES:
        if not _have(cc):
            failures[(cc, opt)] = f"no {cc} on this host"
            continue
        target = root / f"{cc}_{opt}.so"
        done = _compile(cc, opt, target)
        if done.returncode != 0:
            failures[(cc, opt)] = (done.stderr.strip() or "no diagnostic").splitlines()[
                -1
            ]
            continue
        lanes[(cc, opt)] = _decompile(target)
    if not lanes:
        pytest.skip(f"DECLARED SKIP: no lane built: {failures}")
    return {"lanes": lanes, "failures": failures}


def _lane(recovered: dict, cc: str, opt: str) -> dict[str, str]:
    functions = recovered["lanes"].get((cc, opt))
    if functions is None:
        pytest.skip(
            f"DECLARED SKIP: lane {cc}:{opt} did not build "
            f"({recovered['failures'].get((cc, opt))})"
        )
    return functions


def _require(functions: dict[str, str], name: str) -> str:
    assert name in functions, (
        f"{name} was not recovered at all, so nothing below is being tested. "
        f"Recovered: {sorted(functions)}"
    )
    return functions[name]


# --------------------------------------------------------------------------
# 1. THE CONTROL. Must pass, in every lane.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("cc,opt", LANES)
@pytest.mark.parametrize("name", CONTROLS)
def test_a_non_variadic_control_reads_no_undefined_value(
    recovered, cc, opt, name
) -> None:
    """A fixed-arity function in the same unit must recover clean.

    `vsa_control_fixed` consumes exactly the six incoming integer argument
    registers the save area spills, and `vsa_control_mixed` takes a
    floating-point parameter in `xmm0`, so between them every register class the
    variadic functions read is also read here -- as a DECLARED parameter.

    That is what makes the property below attributable. If this test fails, the
    finding is in the harness, the build, or the general register model, and the
    variadic shape is exonerated.
    """
    block = _require(_lane(recovered, cc, opt), name)
    problems = _violations(block)
    assert not problems, (
        f"{cc}:{opt} {name} is NOT variadic yet reads undefined values "
        f"{problems}. Every property in this module is about the variadic "
        f"shape; a control that fails means the cause is elsewhere.\n{block}"
    )


# --------------------------------------------------------------------------
# 2. THE DEFECT.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("cc,opt", LANES)
@pytest.mark.parametrize("name", VARIADIC)
@pytest.mark.xfail(
    reason=(
        "OPEN DEFECT (x86-64 variadic register save area): the recovered "
        "prototype of a variadic function names only its FIXED parameters, so "
        "the `va_start` prologue spills incoming argument registers "
        "(rsi/rdx/rcx/r8/r9, xmm0-7, and `al` under the ABI return-role name "
        "`ret`) that nothing in the emitted C defines. 5 to 38 undefined reads "
        "per function in every lane. In /usr/bin/bash this is 555 of 1,152 "
        "violations (48.2%) across 17 functions. Not cosmetic: see "
        "test_the_undefined_values_are_read_back_out_of_the_save_area."
    ),
    strict=True,
)
def test_a_variadic_function_reads_no_undefined_value(recovered, cc, opt, name) -> None:
    """An unassigned value must not be able to influence the result.

    Being variadic is a property of the function's INTERFACE, not of its body.
    A recovery that models the interface correctly knows the incoming argument
    registers are live-in and has a definition for each; one that does not
    reads them out of nowhere. Nothing about `...` makes a register's arrival
    less certain than a declared parameter's -- the ABI delivers both the same
    way -- so there is no reading on which these values are legitimately
    undefined.

    `strict=True` for the reason the emission-invariants module gives: the
    marker itself fails once the defect is fixed, which forces the reason text
    to be removed rather than left to rot into a lie.
    """
    block = _require(_lane(recovered, cc, opt), name)
    problems = _violations(block)
    assert not problems, (
        f"{cc}:{opt} {name} reads {len(problems)} undefined value(s): "
        f"{sorted(problems)}"
    )


# --------------------------------------------------------------------------
# 3. THE MECHANISM. Passes today, and pins WHY test 2 fails.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("cc,opt", LANES)
@pytest.mark.parametrize("name", VARIADIC)
def test_every_undefined_value_in_a_variadic_function_is_a_save_area_spill(
    recovered, cc, opt, name
) -> None:
    """Each undefined name is spilled, and does nothing else.

    This is the characterisation that makes the xfail above a statement about a
    KNOWN mechanism rather than an unexplained count. Exactly two shapes are
    admissible, and both are parts of the same ABI structure:

      * the SOURCE of a store -- `<somewhere> = varN;` -- which is a
        register-save-area spill;
      * the `test al, al` vector-count guard, `if ((ret & 255) != 0)`, which is
        the only read of `al` and decides whether the vector half is spilled.

    Restricted to the `varN` names, and `ret` is checked only where it IS the
    guard. `ret` is the ABI return-role name for `rax`, so it carries two
    meanings at once, and at `clang -O2` a third: the `va_arg` accumulator of
    `vsa_int_only` and `vsa_double_args` lives in `rax`, is itself read before
    it is defined, and has nothing to do with the save area. That is a real and
    separate violation -- one of the "definition lost at a join" class that
    accounts for the rest of the bash census -- and folding it in here would
    make this characterisation claim a mechanism it had not established.

    It also guards the fix. A change that merely renamed or reordered these
    values, or that suppressed the diagnostic without giving the registers a
    definition, would leave test 2 still failing but would break this one, and
    the pair together say which happened.
    """
    block = _require(_lane(recovered, cc, opt), name)
    problems = _violations(block)
    assert problems, (
        f"{cc}:{opt} {name} reported no undefined reads. If the defect is "
        "fixed, test 2's strict xfail says so; this test must then be rewritten "
        "rather than left asserting a mechanism that no longer exists."
    )
    save_area = [name for name in problems if re.fullmatch(r"var\d+", name)]
    assert save_area, (
        f"{cc}:{opt} {name}: every undefined read was `ret`, so no save-area "
        f"register is among them and this lane establishes nothing about the "
        f"variadic mechanism. Reported: {sorted(problems)}"
    )
    unexplained: list[str] = []
    for undefined in save_area:
        for use in _uses(block, undefined):
            spill = SPILL.match(use)
            if spill is not None and spill.group("src") == undefined:
                continue
            unexplained.append(f"{undefined}: {use[:100]}")
    if "ret" in problems:
        guards = [u for u in _uses(block, "ret") if VECTOR_COUNT_GUARD.match(u)]
        spills = [
            u
            for u in _uses(block, "ret")
            if (m := SPILL.match(u)) is not None and m.group("src") == "ret"
        ]
        assert guards or spills, (
            f"{cc}:{opt} {name}: `ret` is read before it is defined but neither "
            f"in the vector-count guard nor as a save-area spill, so it is a "
            f"different defect wearing the same name: {_uses(block, 'ret')[:4]}"
        )
    assert not unexplained, (
        f"{cc}:{opt} {name}: an undefined value is used for something OTHER "
        f"than a save-area spill or the vector-count guard, so this is not "
        f"(only) the variadic mechanism:\n  " + "\n  ".join(unexplained)
    )


# --------------------------------------------------------------------------
# 4. IT IS WRONG CODE, NOT NOISE.
# --------------------------------------------------------------------------
def test_the_undefined_values_are_read_back_out_of_the_save_area(recovered) -> None:
    """The save area the undefined values are stored into is READ by va_arg.

    This is the difference between "an uninitialised variable appears in the
    output" and "the recompiled function returns garbage", and it is why this
    class cannot be dismissed as a naming artefact. The undefined values are
    stored into the save area, the `va_list` is initialised to point at it, and
    the `va_arg` loop loads straight back out of it:

        *(long *)(&local_38[0] + 8) = var0;      // nothing defines var0
        ...
        var23 = var18 + *(int *)(&local_38[0] + var19);   // ... and here it is

    NOT parametrized over lanes, deliberately. The argument needs the save area
    to be recovered as ONE object, which is a property of the build, not of the
    recovery: at `-O2` GCC allocates it as a single 56-byte buffer, while at
    `-O0` it is spilled into thirty-odd individually named scalar slots and the
    `va_arg` loads go through a computed pointer with no textual link back to
    them. Asserting this per-lane would therefore fail on a shape difference
    that is not the defect. One lane demonstrating it is enough to establish
    that the values are live, so the test requires that SOME lane does, and
    names every lane it examined if none can.
    """
    examined: list[str] = []
    for (cc, opt), functions in sorted(recovered["lanes"].items()):
        block = functions.get("vsa_int_only")
        if block is None:
            continue
        problems = _violations(block)
        if not problems:
            continue
        examined.append(f"{cc}:{opt}")

        # The named frame objects the undefined values are spilled INTO.
        targets: set[str] = set()
        spill_lines: set[str] = set()
        for undefined in problems:
            for use in _uses(block, undefined):
                spill = SPILL.match(use)
                if spill is None or spill.group("src") != undefined:
                    continue
                spill_lines.add(use)
                found = re.search(
                    r"\b(local_[0-9a-fA-F]+|stack_\w+)\b", spill.group("dst")
                )
                if found:
                    targets.add(found.group(1))
        if not targets:
            continue

        # ... loaded from somewhere that is not one of those spills.
        read_back = [
            line.strip()
            for line in _code(block)
            if line.strip() not in spill_lines
            and any(
                re.search(rf"\*\s*\([^;]*\b{re.escape(t)}\b", line) for t in targets
            )
        ]
        if read_back:
            return  # demonstrated

    pytest.fail(
        "No lane showed the variadic save area being written from undefined "
        "values and then read back. Either the defect is fixed (test 2's strict "
        "xfail then says so and this test should be retired), or the recovered "
        "shape changed and this argument needs rewriting. Lanes examined: "
        + (", ".join(examined) or "none")
    )


# --------------------------------------------------------------------------
# 5. THE ROOT CAUSE, stated as its own property.
# --------------------------------------------------------------------------
@pytest.mark.parametrize("cc,opt", LANES)
@pytest.mark.parametrize("name", VARIADIC)
@pytest.mark.xfail(
    reason=(
        "OPEN DEFECT (interface model): a variadic function's recovered "
        "prototype is indistinguishable from a fixed-arity one -- "
        "`int vsa_forward(const char * arg0)`. Nothing in the emitted "
        "declaration records that further arguments arrive, which is precisely "
        "why the save-area registers have no definition. This is the CAUSE of "
        "the undefined reads in test 2, stated separately so that a fix which "
        "silences the reads without modelling the interface is still visible."
    ),
    strict=True,
)
def test_a_recovered_variadic_prototype_declares_itself_variadic(
    recovered, cc, opt, name
) -> None:
    """`f(fixed, ...)` in the source must not recover as `f(fixed)`.

    An emitted prototype is a claim about how the function may be called. For a
    variadic function the claim `int f(const char *)` is false: calling it that
    way is exactly what leaves the save area holding whatever the caller happened
    to leave in `rsi`. The recovered declaration has to carry the ellipsis for
    the emitted translation unit to be self-consistent.
    """
    block = _require(_lane(recovered, cc, opt), name)
    signature = _signature(block, name)
    assert signature is not None, f"{cc}:{opt} no prototype recovered for {name}"
    assert signature.rstrip(")").rstrip().endswith("..."), (
        f"{cc}:{opt} {name} is variadic in the source but recovers as "
        f"`{signature}`, which declares a fixed arity."
    )
