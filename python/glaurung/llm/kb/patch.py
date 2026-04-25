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


def _instruction_at(file_path: str, va: int):
    """Disassemble exactly one instruction at ``va`` and return it.
    Raises ValueError when nothing decodes — the caller can't safely
    patch over an unknown-length region."""
    import glaurung as g
    try:
        ins = g.disasm.disassemble_window_at(
            file_path, int(va), window_bytes=16, max_instructions=1,
        )
    except Exception as e:
        raise ValueError(f"disassembly failed at {va:#x}: {e}")
    if not ins:
        raise ValueError(f"no instruction decoded at {va:#x}")
    return ins[0]


# Compact x86_64 mnemonic-shorthand encoders. Used by the patch CLI's
# nop / jmp / force-branch flows so the analyst doesn't need to hand-
# encode JMP relatives. Other architectures raise; iced-x86-driven
# encoding for arm64 lands in the v1 follow-up.

def _check_x86_64(file_path: str) -> None:
    """Raise unless the binary is x86_64 — the manual encoders below
    only emit x86_64 bytes. Use the existing disassembler probe to
    determine the architecture."""
    import glaurung as g
    try:
        cfg = g.disasm.disassembler_for_path(file_path)
        arch_val = cfg.arch() if callable(getattr(cfg, "arch", None)) else cfg.arch
    except Exception:
        return  # let downstream patch attempt fail with a clearer error
    arch = str(arch_val).lower()
    if "x86" in arch and "64" in arch:
        return
    raise NotImplementedError(
        f"patch shorthands (nop/jmp/force-branch) are x86_64 only; "
        f"detected arch={arch!r}"
    )


def encode_nop(n: int) -> bytes:
    """Return ``n`` x86_64 NOP bytes (single-byte 0x90 form). The
    multi-byte NOP variants are valid but a sequence of 0x90s is
    just as correct and trivially analysable."""
    if n <= 0:
        raise ValueError(f"nop count must be positive (got {n})")
    return b"\x90" * n


def encode_jmp(from_va: int, target_va: int, want_size: int = 0) -> bytes:
    """Encode a near-relative JMP from ``from_va`` to ``target_va``.

    If ``want_size`` is 0 (default), pick the shortest form that fits
    (2 bytes for rel8, 5 bytes for rel32). Pass want_size=2 or 5 to
    force a specific encoding — needed when overwriting an existing
    instruction whose size must be preserved exactly.
    """
    # rel8 first if possible.
    rel8 = target_va - (from_va + 2)
    if want_size in (0, 2) and -128 <= rel8 <= 127:
        return bytes([0xEB, rel8 & 0xFF])
    rel32 = target_va - (from_va + 5)
    if -(1 << 31) <= rel32 <= (1 << 31) - 1:
        return bytes([0xE9]) + rel32.to_bytes(4, "little", signed=True)
    raise ValueError(
        f"JMP from {from_va:#x} to {target_va:#x} too far for any "
        f"near-relative encoding (rel32 = {rel32})"
    )


def patch_nop(
    input_path: str, output_path: str, va: int, *,
    overwrite_output: bool = False,
) -> PatchResult:
    """Replace the instruction at ``va`` with NOP bytes of the same
    length, so the surrounding stream stays decode-aligned."""
    _check_x86_64(input_path)
    ins = _instruction_at(input_path, va)
    n = len(ins.bytes or b"")
    if n == 0:
        raise ValueError(f"instruction at {va:#x} has zero length")
    payload = encode_nop(n).hex()
    return patch_at_va(
        input_path, output_path, va, payload,
        overwrite_output=overwrite_output,
    )


def patch_jmp(
    input_path: str, output_path: str, from_va: int, target_va: int,
    *, overwrite_output: bool = False, preserve_length: bool = True,
) -> PatchResult:
    """Replace the instruction at ``from_va`` with `jmp target_va`. By
    default, the new instruction's size matches the original (NOP-pad
    if smaller, refuse if larger) so the stream stays aligned.
    """
    _check_x86_64(input_path)
    if preserve_length:
        ins = _instruction_at(input_path, from_va)
        orig_size = len(ins.bytes or b"")
        if orig_size == 0:
            raise ValueError(f"instruction at {from_va:#x} has zero length")
        # Pick the JMP encoding that fits in orig_size, NOP-pad if
        # short. If even the shortest doesn't fit, fail loudly.
        for size in (2, 5):
            if size > orig_size:
                continue
            try:
                jmp_bytes = encode_jmp(from_va, target_va, want_size=size)
            except ValueError:
                continue
            pad = orig_size - len(jmp_bytes)
            payload = (jmp_bytes + encode_nop(pad) if pad else jmp_bytes).hex()
            return patch_at_va(
                input_path, output_path, from_va, payload,
                overwrite_output=overwrite_output,
            )
        raise ValueError(
            f"cannot fit any JMP form into {orig_size} bytes "
            f"at {from_va:#x} → {target_va:#x}"
        )
    payload = encode_jmp(from_va, target_va).hex()
    return patch_at_va(
        input_path, output_path, from_va, payload,
        overwrite_output=overwrite_output,
    )


# Conditional-branch opcodes whose target we need to read for
# force-branch true. Each entry maps the short-form prefix byte to
# (mnemonic, displacement-size). x86_64 J<cc> rel8 = 7x; J<cc> rel32 =
# 0F 8x. We cover the common ones; less-common predicates fall
# through and the function refuses to force-branch them with a clear
# "unsupported branch" error, instead of silently mis-patching.
_JCC_REL8 = set(range(0x70, 0x80))   # JO/JNO/JB/JNB/JZ/JNZ/JBE/JA/JS/JNS/JP/JNP/JL/JNL/JLE/JG
_JCC_REL32_PREFIX = 0x0F             # next byte 0x80..0x8F


def _conditional_branch_target(ins) -> Optional[int]:
    """Return the absolute VA target of a conditional branch, or
    None if the instruction isn't a recognized conditional branch.
    Walks the encoded bytes directly so we don't depend on the
    operand-string format."""
    raw = bytes(ins.bytes or b"")
    if not raw:
        return None
    base = int(ins.address.value)
    if raw[0] in _JCC_REL8:
        if len(raw) < 2:
            return None
        rel = int.from_bytes(raw[1:2], "little", signed=True)
        return base + 2 + rel
    if raw[0] == _JCC_REL32_PREFIX and len(raw) >= 6 and 0x80 <= raw[1] <= 0x8F:
        rel = int.from_bytes(raw[2:6], "little", signed=True)
        return base + 6 + rel
    return None


def patch_force_branch(
    input_path: str, output_path: str, va: int, taken: bool,
    *, overwrite_output: bool = False,
) -> PatchResult:
    """Force the conditional branch at ``va`` to either always-taken
    (``taken=True``: replace J<cc> with JMP to the original target,
    NOP-padded to preserve length) or always-not-taken
    (``taken=False``: replace J<cc> with NOPs of the same length)."""
    _check_x86_64(input_path)
    ins = _instruction_at(input_path, va)
    if not taken:
        return patch_nop(
            input_path, output_path, va,
            overwrite_output=overwrite_output,
        )
    target = _conditional_branch_target(ins)
    if target is None:
        raise ValueError(
            f"instruction at {va:#x} is not a recognized conditional "
            f"branch (mnemonic={ins.mnemonic})"
        )
    return patch_jmp(
        input_path, output_path, va, target,
        overwrite_output=overwrite_output, preserve_length=True,
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
