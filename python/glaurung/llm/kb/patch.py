"""Binary patcher (#185 v0).

Writes hex bytes at a given VA, producing a new binary file. v0 is
intentionally minimal — no assembly engine, no relocation patching,
no overflow protection beyond "don't write past EOF". Real assembly
support (NASM-style mnemonic input → bytes via iced-x86) is filed as
the v1 follow-up.

Use cases for v0:
  - One-byte CFG patches (`jne` → `je`).
  - NOP-out a check (`90 90 90`).
  - Replace a constant (32-bit immediate substitution).

Reads the original bytes at the target VA before writing the patch
so callers can record the original bytes in their KB for undo /
audit-trail purposes.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class PatchResult:
    """Outcome of applying one patch."""
    output_path: str
    va: int
    file_offset: int
    original_hex: str   # bytes that were at the target before patch
    patched_hex: str    # bytes that were written
    notes: List[str]


def _parse_hex(s: str) -> bytes:
    """Parse `"48 8b 45 f8"` / `"48 8b ?? f8"` (no wildcards in patch
    input, but tolerate spaces / commas). Reject malformed input
    early — silently writing the wrong bytes would produce a
    corrupted binary that's hard to debug."""
    cleaned = re.sub(r"[\s,]+", "", s)
    if not cleaned:
        raise ValueError("empty patch payload")
    if len(cleaned) % 2 != 0:
        raise ValueError(
            f"hex payload has odd nibble count ({len(cleaned)}): {s!r}"
        )
    if not re.match(r"^[0-9a-fA-F]+$", cleaned):
        raise ValueError(
            f"non-hex characters in payload: {s!r}"
        )
    return bytes.fromhex(cleaned)


def patch_at_va(
    input_path: str,
    output_path: str,
    va: int,
    payload: str,
    *,
    overwrite_output: bool = False,
) -> PatchResult:
    """Copy `input_path` to `output_path`, then overwrite bytes at
    the file offset corresponding to virtual-address `va` with the
    decoded `payload` (hex string).

    The byte-length of `payload` is exact — the caller is responsible
    for matching the original instruction's size when patching code,
    so the surrounding instruction stream stays valid. Emitting
    junk bytes that span instruction boundaries will produce a
    decode-misaligned binary; v0 doesn't attempt to detect that.
    """
    import glaurung as g

    inp = Path(input_path)
    out = Path(output_path)
    if not inp.exists():
        raise FileNotFoundError(f"input not found: {input_path}")
    if out.exists() and not overwrite_output:
        raise FileExistsError(
            f"output already exists: {output_path} (pass overwrite_output=True to clobber)"
        )

    payload_bytes = _parse_hex(payload)
    if not payload_bytes:
        raise ValueError("patch payload decoded to zero bytes")

    # Resolve VA → file offset.
    try:
        off = g.analysis.va_to_file_offset_path(
            str(inp), int(va), 100_000_000, 100_000_000,
        )
    except Exception as e:
        raise RuntimeError(f"va_to_file_offset failed: {e}")
    if off is None:
        raise ValueError(f"VA {va:#x} does not map to a file offset")
    foff = int(off)

    raw = inp.read_bytes()
    if foff + len(payload_bytes) > len(raw):
        raise ValueError(
            f"patch would extend past EOF: file_offset={foff}, "
            f"payload_len={len(payload_bytes)}, file_len={len(raw)}"
        )
    original = raw[foff : foff + len(payload_bytes)]

    # Build the patched bytes and write to output.
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(inp, out)
    # Re-open for in-place modification (avoids rewriting the whole
    # file when the patch is short).
    with open(out, "r+b") as f:
        f.seek(foff)
        f.write(payload_bytes)

    return PatchResult(
        output_path=str(out),
        va=int(va),
        file_offset=foff,
        original_hex=original.hex(),
        patched_hex=payload_bytes.hex(),
        notes=[
            f"patched {len(payload_bytes)} bytes at VA {va:#x} "
            f"(file offset {foff:#x})",
        ],
    )


def render_patch_markdown(result: PatchResult, *, input_path: str = "") -> str:
    """Pretty-print a PatchResult."""
    lines = [
        f"# Patch applied",
        "",
        f"- input:  `{input_path}`" if input_path else "",
        f"- output: `{result.output_path}`",
        f"- VA: `{result.va:#x}` (file offset `{result.file_offset:#x}`)",
        "",
        f"  before: `{result.original_hex}`",
        f"  after:  `{result.patched_hex}`",
        "",
    ]
    for n in result.notes:
        lines.append(f"_{n}_")
    return "\n".join(line for line in lines if line is not None) + "\n"
