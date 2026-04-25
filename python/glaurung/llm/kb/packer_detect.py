"""Packer / obfuscator detection (#187 v0).

Deterministic, file-only heuristics for spotting obvious packers and
runtime obfuscators. Designed to be the *first* thing the agent does
when triaging an unknown sample — if the binary is packed, every
downstream analysis (FLIRT, decompile, vtable walker) operates on
encrypted code and produces noise. The agent should report `packed:
yes (UPX 3.96)` and stop, or run an unpacker, before doing anything
deeper.

v0 covers the dominant families by section/string-pool fingerprint;
the entropy gate catches everything else generically. Targeted
unpackers are out of scope for v0 — that's a separate roadmap item.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class PackerSignature:
    """One known packer's fingerprint."""
    name: str
    family: str
    indicators: tuple   # tuple of bytes; any one match counts
    confidence: float = 0.85


# Known-packer fingerprints. Each indicator is a byte string we expect
# to find anywhere in the file. Section names (with their leading dot)
# are the strongest signal because they live in the binary's section
# table directly; magic strings + library names are looser.
_PACKER_SIGS: List[PackerSignature] = [
    PackerSignature(
        name="UPX", family="upx", confidence=0.95,
        indicators=(
            b"UPX!",
            b"UPX0\x00",        # section name (PE/ELF)
            b"UPX1\x00",
            b"UPX2\x00",
            b"$Info: This file is packed with the UPX",
        ),
    ),
    PackerSignature(
        name="Themida", family="themida", confidence=0.9,
        indicators=(
            b".themida",
            b"Themida",
            b"WinLicense",       # Oreans-stack sibling
        ),
    ),
    PackerSignature(
        name="VMProtect", family="vmprotect", confidence=0.9,
        indicators=(
            b".vmp0",
            b".vmp1",
            b".vmp2",
            b"VMProtect",
        ),
    ),
    PackerSignature(
        name="ASPack", family="aspack", confidence=0.85,
        indicators=(
            b".aspack",
            b".adata",
            b"aPLib",
        ),
    ),
    PackerSignature(
        name="MPRESS", family="mpress", confidence=0.85,
        indicators=(
            b".MPRESS1",
            b".MPRESS2",
            b"MPRESS",
        ),
    ),
    PackerSignature(
        name="PECompact", family="pecompact", confidence=0.85,
        indicators=(
            b"PEC2TO",
            b"PEC2MO",
            b"PECompact2",
        ),
    ),
    PackerSignature(
        name="FSG", family="fsg", confidence=0.85,
        indicators=(
            b"FSG!",
        ),
    ),
    PackerSignature(
        name="Petite", family="petite", confidence=0.85,
        indicators=(
            b".petite",
            b"petite",
        ),
    ),
    PackerSignature(
        name="Enigma", family="enigma", confidence=0.85,
        indicators=(
            b".enigma1",
            b".enigma2",
            b"Enigma protector",
        ),
    ),
    PackerSignature(
        name="Obsidium", family="obsidium", confidence=0.85,
        indicators=(
            b"Obsidium",
        ),
    ),
]


@dataclass
class PackerVerdict:
    """Result of `detect_packer`."""
    is_packed: bool
    packer_name: Optional[str] = None     # None when only entropy is suspicious
    family: Optional[str] = None
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    overall_entropy: float = 0.0
    notes: List[str] = field(default_factory=list)


def detect_packer(binary_path: str) -> PackerVerdict:
    """Run packer-detection heuristics on `binary_path`.

    Decision tree:
      1. Read raw bytes; scan for known-packer indicators.
      2. If any signature matches, return is_packed=True with the
         strongest-confidence match.
      3. Otherwise compute overall byte entropy; if > 7.2 flag as
         "likely packed" with no specific family.
      4. If neither, return is_packed=False.

    Pure file-only — does not parse the binary, run any analyser, or
    require a KB. Safe to call before triage on a fresh sample.
    """
    p = Path(binary_path)
    if not p.exists():
        return PackerVerdict(
            is_packed=False,
            notes=[f"file not found: {binary_path}"],
        )

    try:
        raw = p.read_bytes()
    except OSError as e:
        return PackerVerdict(
            is_packed=False,
            notes=[f"read failed: {e}"],
        )

    matches: List[tuple] = []  # (PackerSignature, indicator_str)
    for sig in _PACKER_SIGS:
        for ind in sig.indicators:
            if ind in raw:
                ind_str = ind.decode("latin-1", errors="replace").rstrip("\x00")
                matches.append((sig, ind_str))
                break  # one indicator per signature is enough

    # Sort matches by confidence desc; the first wins.
    matches.sort(key=lambda t: t[0].confidence, reverse=True)

    overall_entropy = _shannon_entropy(raw)

    if matches:
        sig, ind_str = matches[0]
        notes: List[str] = []
        if len(matches) > 1:
            others = ", ".join(s.name for s, _ in matches[1:])
            notes.append(f"additional matches: {others}")
        return PackerVerdict(
            is_packed=True,
            packer_name=sig.name,
            family=sig.family,
            confidence=sig.confidence,
            indicators=[ind_str],
            overall_entropy=round(overall_entropy, 4),
            notes=notes,
        )

    # No known signature; consult the entropy gate.
    if overall_entropy > 7.2:
        return PackerVerdict(
            is_packed=True,
            packer_name=None,  # unknown family
            family="generic",
            confidence=0.6,
            indicators=[f"high overall entropy {overall_entropy:.3f}"],
            overall_entropy=round(overall_entropy, 4),
            notes=["no known packer signature matched; "
                   "entropy alone suggests packed/encrypted code"],
        )

    return PackerVerdict(
        is_packed=False,
        overall_entropy=round(overall_entropy, 4),
        notes=["no packer indicators found"],
    )


def _shannon_entropy(data: bytes) -> float:
    """Plain Shannon entropy in bits/byte across the whole file. We
    do NOT use Glaurung's Rust EntropySummary here because that one
    operates on overlapping sliding windows and reports a single
    average; for packer detection we want the file-wide value with
    no smoothing."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    import math
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy
