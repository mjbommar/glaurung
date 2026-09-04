"""What our C front end recovers from each decompiler backend's house style.

DecBench's headline CFG metric is `vj_ged(published source CFG, CFG of the
stored decompiled C)`, and the second half of that pair has to be *parsed out
of whatever the backend printed*. Ghidra, IDA, Binary Ninja, angr, r2dec and
dewolf each print something that is not standard C, and Joern only survives
them because DecBench rewrites five quirks first
(`decbench/utils/cfg.py::sanitize_decompiled_c`) and, for IDA alone, deletes
the IDA-isms in the adapter before storage
(`decbench/decompilers/raw/ida_raw.py::_CODE_REPLACEMENTS`).

Our own parity evidence has been one-sided: every decompiled artifact in the
materialized tree is Glaurung's own output. These tests close that gap with
fixtures that are, wherever possible, *captured* text from other backends --
see `tests/fixtures/decompiler_dialects/` and
`docs/design/source-front-ends/decompiler-dialects.md`.

Every case in every fixture declares what it expects, including the ones we
cannot parse: a dialect we lose gets a case whose `expect` is `-`, because an
absent test is indistinguishable from a passing one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.core

csource = pytest.importorskip("glaurung._native").csource

FIXTURES = (
    Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "decompiler_dialects"
)

_CASE_START = re.compile(r"^/\* case: ", re.M)
_META = re.compile(r"^(?: \*|/\*) (case|provenance|source|expect|gap): (.*)$", re.M)

#: Provenance values a fixture case may declare. ``captured`` means the text was
#: produced by the named backend and copied verbatim; ``RECONSTRUCTION`` means it
#: was hand-written in that backend's documented style because the backend is not
#: available here. Nothing else is allowed, so a fake sample cannot pass silently.
_PROVENANCE = frozenset({"captured", "RECONSTRUCTION"})

#: The gap ledger. Each entry is a construct our front end does not recover
#: today, keyed by a short name, with a minimal reproduction. It is asserted in
#: BOTH directions: a construct that starts parsing fails this test just as
#: loudly as one that stops. When a fix lands, delete the entry -- do not relax
#: the assertion. The reproduction bodies are minimal by design; the realistic
#: captured text for each lives in the fixture file named in the comment.
KNOWN_GAPS: dict[str, str] = {
    # ghidra.c :: _start -- Ghidra's own calling-convention name, not an MSVC one.
    "ghidra-processEntry": "void processEntry _start(undefined8 p1)\n{\n  g(p1);\n  return;\n}\n",
    # ghidra.c :: FUN_00108540 -- quirk 1 of DecBench's sanitize_decompiled_c.
    "aggregate-array-return": "undefined1 [16] f(void)\n{\n  undefined1 a [16];\n  return a;\n}\n",
    # ghidra.c :: Base::op -- Ghidra emits __thiscall in C output for PE and C++.
    "ghidra-thiscall": "int __thiscall C::f(C *this)\n{\n  return 1;\n}\n",
    # ghidra.c :: switchD_001011b2::caseD_0 -- jump-table stubs carry '::'.
    "qualified-name": "int A::b(int x)\n{\n  return x;\n}\n",
    # binja.c :: usage, handler -- 33 of our 34 binja losses in the sample set.
    "trailing-attribute-noreturn": "void f() __noreturn\n{\n  g();\n}\n",
    # binja.c :: bi_reverse -- same shape, different attribute.
    "trailing-attribute-pure": "unsigned long long f(unsigned int a) __pure\n{\n  return a >> 1;\n}\n",
    # dewolf.c :: history_def_last -- 201 of our 295 dewolf losses.
    "dewolf-double-parameter-list": "long int64_t f(void* a)(void * a)\n{\n  return 0L;\n}\n",
    # dewolf.c :: usage -- a trailing attribute that itself takes a parameter list.
    "dewolf-attribute-parameter-list": "void void f() __noreturn(){ g(); }\n",
    # ida.c :: dis_func1 -- the one IDA-ism DecBench's adapter does not delete.
    "ida-spoils": "void __spoils<R1,R2,R3,R12,LR> f(char a1)\n{\n  g(a1);\n}\n",
    # Not observed in any captured corpus here, kept because C89 allows it and
    # Ghidra prints it when it cannot determine a return type.
    "implicit-int-definition": "f(int a, int b)\n{\n  return a;\n}\n",
}

#: Constructs that DO parse today and must keep parsing. Several were gaps until
#: the lexer/parser calling-convention work landed; they are regression cases now.
RECOVERED_CONSTRUCTS: dict[str, str] = {
    "msvc-cdecl": "int __cdecl f(char *fmt, ...)\n{\n  return 0;\n}\n",
    "msvc-stdcall": "long __stdcall f(void)\n{\n  return 0;\n}\n",
    "msvc-fastcall": "__int64 __fastcall f(__int64 a1)\n{\n  return a1;\n}\n",
    "ida-usercall-register-slots": "int __usercall f@<eax>(int a@<ecx>)\n{\n  return a;\n}\n",
    "binja-register-annotation": "long long f(long long a @ rax)\n{\n  return a;\n}\n",
    "ida-int128": "__int128 f(int a)\n{\n  return a;\n}\n",
    "ghidra-undefined-types": "undefined8 f(undefined8 *p)\n{\n  return *p;\n}\n",
    "ghidra-code-pointer": "void f(void)\n{\n  code *p;\n  p = (code *)0x0;\n  (*p)();\n  return;\n}\n",
    "gnu-computed-goto": "int f(int a)\n{\n  void *p = &&L;\n  goto *p;\nL:\n  return a;\n}\n",
    "unbalanced-body": "int f(int a) { if (a) { return 1; }",
    "garbage-tail": "int f(int a) { return a; }  ###!!! not c at all",
    "dewolf-doubled-return-type": "void void f(void)\n{\n  return;\n}\n",
    "angr-aggregate-return": "unsigned long long [4] f(void)\n{\n  return 0;\n}\n",
}


class DialectCase:
    """One declared case inside a dialect fixture file.

    Attributes:
        fixture: Fixture file name, e.g. ``ghidra.c``.
        name: The case label from its ``case:`` line.
        provenance: ``captured`` or ``RECONSTRUCTION``.
        source: Where the text came from, as declared.
        expect: The function name we expect in the recovered CFG map, or ``-``
            when the case records a gap.
        gap: The gap class, present exactly when ``expect`` is ``-``.
        body: The C text of the case, with its metadata comment removed.
    """

    __slots__ = ("body", "expect", "fixture", "gap", "name", "provenance", "source")

    def __init__(
        self,
        fixture: str,
        name: str,
        provenance: str,
        source: str,
        expect: str,
        gap: str | None,
        body: str,
    ) -> None:
        """Build a case.

        Args:
            fixture: Fixture file name.
            name: Case label.
            provenance: ``captured`` or ``RECONSTRUCTION``.
            source: Declared origin of the text.
            expect: Expected recovered function name, or ``-``.
            gap: Gap class when ``expect`` is ``-``, else ``None``.
            body: The case's C text.
        """
        self.fixture = fixture
        self.name = name
        self.provenance = provenance
        self.source = source
        self.expect = expect
        self.gap = gap
        self.body = body

    @property
    def id(self) -> str:
        """A stable pytest parameter id."""
        return f"{self.fixture[:-2]}:{self.name}"


def _parse_fixture(path: Path) -> list[DialectCase]:
    """Split one dialect fixture into its declared cases.

    Args:
        path: The fixture file.

    Returns:
        Every case in file order.

    Raises:
        ValueError: If a case omits a required metadata key, or declares a gap
            without naming it.
    """
    text = path.read_text()
    starts = [m.start() for m in _CASE_START.finditer(text)]
    ends = starts[1:] + [len(text)]
    cases: list[DialectCase] = []
    for start, end in zip(starts, ends):
        chunk = text[start:end]
        header, sep, body = chunk.partition(" */\n")
        if not sep:
            raise ValueError(f"{path.name}: unterminated case header at offset {start}")
        meta = dict(_META.findall(header))
        missing = {"case", "provenance", "source", "expect"} - set(meta)
        if missing:
            raise ValueError(
                f"{path.name}: case at offset {start} is missing {sorted(missing)}"
            )
        gap = meta.get("gap")
        if (meta["expect"] == "-") != (gap is not None):
            raise ValueError(
                f"{path.name}: case {meta['case']!r} must declare a gap iff expect is '-'"
            )
        cases.append(
            DialectCase(
                fixture=path.name,
                name=meta["case"],
                provenance=meta["provenance"],
                source=meta["source"],
                expect=meta["expect"],
                gap=gap,
                body=body,
            )
        )
    return cases


def _fixture_paths() -> list[Path]:
    """Every dialect fixture, in a deterministic order."""
    return sorted(FIXTURES.glob("*.c"))


def _all_cases() -> list[DialectCase]:
    """Every case of every dialect fixture, in a deterministic order."""
    return [case for path in _fixture_paths() for case in _parse_fixture(path)]


ALL_CASES = _all_cases()


def test_the_fixture_corpus_covers_every_named_backend() -> None:
    """One fixture per backend dialect, and none of them empty.

    A missing dialect file is indistinguishable from a dialect that passes, so
    the roster is asserted rather than discovered.
    """
    found = {path.name for path in _fixture_paths()}
    assert found == {
        "angr.c",
        "binja.c",
        "dewolf.c",
        "ghidra.c",
        "ida.c",
        "r2dec.c",
        "retdec.c",
    }
    for path in _fixture_paths():
        assert _parse_fixture(path), f"{path.name} declares no cases"


@pytest.mark.parametrize("case", ALL_CASES, ids=[case.id for case in ALL_CASES])
def test_a_case_recovers_exactly_what_it_declares(case: DialectCase) -> None:
    """Each fixture case recovers its function, or records that it does not.

    The negative half is the point. A dialect we cannot parse is asserted to
    yield *nothing*, so the day it starts parsing this test fails and the
    fixture and the design doc get updated together.
    """
    recovered = sorted(csource.parity_cfgs(case.body))
    if case.expect == "-":
        assert recovered == [], (
            f"{case.id} is recorded as a gap ({case.gap}) but recovered {recovered}. "
            f"If this is a fix, update the case's expect/gap lines, KNOWN_GAPS, and "
            f"docs/design/source-front-ends/decompiler-dialects.md."
        )
    else:
        assert case.expect in recovered, (
            f"{case.id} declares expect={case.expect!r} but recovered {recovered}"
        )


@pytest.mark.parametrize("case", ALL_CASES, ids=[case.id for case in ALL_CASES])
def test_every_case_declares_an_allowed_provenance(case: DialectCase) -> None:
    """No fixture may present invented text as captured output.

    `CLAUDE.md` forbids fake fixtures; an honestly-labelled reconstruction is
    fine. This test is what makes the label load-bearing rather than decorative.
    """
    assert case.provenance in _PROVENANCE, (
        f"{case.id} declares provenance={case.provenance!r}; allowed: {sorted(_PROVENANCE)}"
    )
    assert case.source.strip(), f"{case.id} declares no source"


def test_most_of_the_corpus_is_captured_not_reconstructed() -> None:
    """The corpus must stay evidence, not illustration.

    RetDec is not installed here and has no column in the published DecBench
    run, so its two cases are reconstructions, as are the two raw Hex-Rays cases
    that show what IDA prints before DecBench's adapter rewrites it. Everything
    else is captured. If that ratio inverts, the corpus has stopped being a
    measurement.
    """
    captured = [case for case in ALL_CASES if case.provenance == "captured"]
    reconstructed = [case for case in ALL_CASES if case.provenance == "RECONSTRUCTION"]
    assert len(captured) >= 3 * len(reconstructed), (
        f"{len(captured)} captured vs {len(reconstructed)} reconstructed"
    )
    assert {case.fixture for case in reconstructed} == {"ida.c", "retdec.c"}


@pytest.mark.parametrize("path", _fixture_paths(), ids=lambda p: p.name)
def test_a_dialect_gap_never_costs_the_rest_of_the_file(path: Path) -> None:
    """Losing one function must not lose its neighbours.

    This is the property the whole front end exists for. Joern's failure mode on
    an unparseable construct is documented by DecBench as losing the *whole
    function*, and for `@` annotations "the whole file"; ours must be strictly
    per-function. Parsing the fixture as one translation unit has to recover
    exactly the union of what the cases recover in isolation.
    """
    cases = _parse_fixture(path)
    isolated: set[str] = set()
    for case in cases:
        isolated |= set(csource.parity_cfgs(case.body))
    whole = set(csource.parity_cfgs(path.read_text()))
    assert whole == isolated, (
        f"{path.name}: parsing the file whole recovered {sorted(whole)} but the cases "
        f"in isolation recover {sorted(isolated)}; a gap is leaking across functions"
    )


@pytest.mark.parametrize("name", sorted(KNOWN_GAPS), ids=sorted(KNOWN_GAPS))
def test_a_known_gap_is_still_a_gap(name: str) -> None:
    """The gap ledger, asserted so a fix cannot land unrecorded.

    A construct that starts parsing makes this fail on purpose: delete its
    KNOWN_GAPS entry, flip the matching fixture case, and update the design doc
    in the same change.
    """
    recovered = sorted(csource.parity_cfgs(KNOWN_GAPS[name]))
    assert recovered == [], (
        f"{name} now recovers {recovered}. That is good news: remove it from "
        f"KNOWN_GAPS, update the matching case in tests/fixtures/decompiler_dialects/, "
        f"and update docs/design/source-front-ends/decompiler-dialects.md."
    )


@pytest.mark.parametrize(
    "name", sorted(RECOVERED_CONSTRUCTS), ids=sorted(RECOVERED_CONSTRUCTS)
)
def test_a_supported_dialect_construct_stays_supported(name: str) -> None:
    """Constructs we already handle, held as regression cases.

    Several of these (the MSVC conventions, IDA's `@<reg>` slots) were gaps
    until recently. The unbalanced-body and garbage-tail cases are the error
    recovery that keeps a truncated decompiler dump scoreable at all.
    """
    recovered = sorted(csource.parity_cfgs(RECOVERED_CONSTRUCTS[name]))
    assert recovered == ["f"], f"{name} regressed: recovered {recovered}"


def test_parsing_a_dialect_fixture_is_deterministic() -> None:
    """The same bytes give the same CFGs, run to run.

    Every gate downstream of this front end is a diff, and a diff against
    non-deterministic output is not a gate.
    """
    for path in _fixture_paths():
        text = path.read_text()
        first = csource.parity_cfgs(text)
        second = csource.parity_cfgs(text)
        assert first == second, f"{path.name} parsed differently on a second run"
