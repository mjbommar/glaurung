"""A function's identity must survive having its metadata removed.

The KB keys every annotation on `(binary_id, absolute entry VA)`, where
`binary_id` is the SHA-256 of the whole file. Rebuild the binary and the hash
changes, so every stored name, comment, type and stack variable is orphaned;
rebase it and the VAs are silently wrong. `src/program/call_graph.rs:51` says so
outright: *"Not stable across a re-link, and it does not pretend to be."*

A content-derived identifier already exists —
`python/glaurung/llm/kb/structural_fingerprint.py`, which masks call and jump
targets, IAT displacements, register identity and stack displacements. It is
recomputed on every `glaurung diff` and **persisted nowhere**: there is not one
hash column across the KB's 34 tables.

These tests pin that it is fit for the job, using the realistic corpus, where
`strip` and `sstrip` produce files whose executable bytes are byte-identical to
the control and differ only in metadata. If the fingerprint is stable there, it
is a usable key; if it drifts, persisting it would be worse than useless because
the drift would be invisible.

Measured after fixing the fast-path guard (task #106): 97 distinct fingerprints
over 110 functions, 104/104 identical across `strip`, and 95/101 across
`sstrip` — five of those six differing because *discovery* recovered a
different number of basic blocks, not because the hash disagreed about the same
code.

**Stability alone would not have caught the bug this file was written during.**
The fast path was hashing empty token streams, which is perfectly stable and
perfectly useless: 62 functions of 26 different sizes shared one fingerprint.
That is why `test_the_fingerprint_distinguishes_different_functions` exists and
why it is not optional — an identifier is only useful if it is stable *and*
discriminating, and the two failure modes look nothing alike.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import realistic_corpus  # noqa: E402

pytestmark = pytest.mark.skipif(
    bool(realistic_corpus.missing_tools()),
    reason="needs " + ", ".join(realistic_corpus.missing_tools() or ["-"]),
)

#: `sstrip` costs discovery a few basic blocks on PLT stubs and `_start`, which
#: legitimately changes their fingerprints. This bounds how much of that is
#: tolerable before the identifier stops being usable as a key.
SSTRIP_DRIFT_ALLOWANCE = 10


def _fingerprints(variant: str) -> dict[int, tuple[str, int]]:
    """Fingerprint every function of one variant, keyed by entry VA.

    Keyed by VA only because these variants share an address space — that is
    what makes them comparable at all, and is exactly the property the
    fingerprint exists to stop us depending on in general.
    """
    import glaurung
    from glaurung.llm.kb import structural_fingerprint as sf

    path = str(realistic_corpus.variant_path(variant))
    data = Path(path).read_bytes()
    va_table, _ = sf.build_va_table(data)
    disassembler = glaurung.disasm.disassembler_for_path(path)
    functions, _ = glaurung.analysis.analyze_functions_path(path)

    out: dict[int, tuple[str, int]] = {}
    for function in functions:
        structure = sf.structural_fingerprint(
            func=function,
            path=path,
            iat_by_va={},
            data=data,
            va_table=va_table,
            disassembler=disassembler,
        )
        if structure is not None:
            blocks = len(list(function.basic_blocks or []))
            out[int(function.entry_point.value)] = (structure.fingerprint, blocks)
    return out


@pytest.fixture(scope="module")
def control() -> dict[int, tuple[str, int]]:
    return _fingerprints("dwarf")


def test_stripping_symbols_does_not_change_any_function_identity(control):
    """`strip` removes `.symtab` and DWARF and touches no instruction.

    Nothing here may move at all: this is the same code, and an identifier that
    changed would mean the fingerprint was reading metadata.
    """
    stripped = _fingerprints("strip")
    shared = set(control) & set(stripped)
    assert shared, "no functions in common; the corpus build is wrong"
    drifted = {
        f"{va:#x}": (control[va][0], stripped[va][0])
        for va in sorted(shared)
        if control[va][0] != stripped[va][0]
    }
    assert not drifted, (
        f"{len(drifted)} function identities changed when only symbols were "
        f"removed: {list(drifted)[:5]}"
    )


def test_removing_section_headers_leaves_identity_substantially_intact(control):
    """`sstrip` additionally deletes the section header table.

    Some drift is legitimate here and is *not* the fingerprint's fault:
    discovery recovers a different number of basic blocks for PLT stubs and
    `_start` without section headers, and a different body honestly is a
    different body. The bound is what makes the identifier usable as a key.
    """
    sectionless = _fingerprints("sstrip")
    shared = set(control) & set(sectionless)
    assert shared, "no functions in common; the corpus build is wrong"
    drifted = [va for va in shared if control[va][0] != sectionless[va][0]]
    same_shape = [va for va in drifted if control[va][1] == sectionless[va][1]]
    assert len(drifted) <= SSTRIP_DRIFT_ALLOWANCE, (
        f"{len(drifted)} of {len(shared)} identities drifted without section "
        f"headers (allowance {SSTRIP_DRIFT_ALLOWANCE}). "
        f"{len(same_shape)} of them have the SAME basic-block count, which "
        "would point at the fingerprint rather than at discovery: "
        f"{[hex(v) for v in same_shape[:5]]}"
    )


def test_the_fingerprint_distinguishes_different_functions(control):
    """An identifier that collides is not an identifier.

    The corpus deliberately contains near-duplicate shapes — several PLT stubs
    and a family of obfuscated dispatchers — so this is a real check rather
    than a formality.
    """
    fingerprints = [fp for fp, _blocks in control.values()]
    distinct = len(set(fingerprints))
    assert distinct >= len(fingerprints) * 0.8, (
        f"only {distinct} distinct fingerprints across {len(fingerprints)} "
        "functions; too many collide to key annotations on"
    )
