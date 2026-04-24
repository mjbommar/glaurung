"""Tool: detect cryptographic algorithms by constant / S-box fingerprints.

A "does this binary contain crypto?" pass that looks for the
fingerprint constants embedded in stock reference implementations —
the AES forward S-box, MD5's A/B/C/D init words, SHA-256's round
constants, ChaCha20's ``expand 32-byte k`` nonce, DES's PC tables, etc.
These are effectively unique: if a binary contains the first 64 bytes
of the AES S-box at a ``.rodata``-aligned offset, it has AES in it.

We pair the constant scan with a symbol-level check — imports like
``EVP_EncryptInit``, ``AES_encrypt``, ``crypto_box_keypair``, or
``BCryptOpenAlgorithmProvider`` are strong circumstantial evidence
even when the table itself isn't inlined (OpenSSL, libsodium, or CNG
is being called through a shared library).

Confidence is HIGH when a unique S-box or init-constant hits, MEDIUM
when only API symbols match, LOW otherwise.
"""

from __future__ import annotations

import re
from typing import Dict, List

from pydantic import BaseModel, Field

import glaurung as g

from ..context import MemoryContext
from ..kb.store import KnowledgeBase
from .base import MemoryTool, ToolMeta


# First 32 bytes of the AES forward S-box — distinctive enough on its own.
_AES_SBOX_32 = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
)

# MD5 init words (A B C D little-endian) as they appear contiguously in
# reference implementations.
_MD5_INIT = bytes.fromhex("0123456789abcdeffedcba9876543210")
_MD5_INIT_LE = bytes.fromhex("01234567" "89abcdef" "fedcba98" "76543210")

# SHA-256 first four round constants (K[0..3]), packed big-endian, which
# is how most C reference tables store them.
_SHA256_K_BE = bytes.fromhex("428a2f98" "71374491" "b5c0fbcf" "e9b5dba5")

# SHA-1 IV H[0..4]
_SHA1_IV = bytes.fromhex("67452301" "efcdab89" "98badcfe" "10325476" "c3d2e1f0")

# ChaCha20/Salsa20 nonce — "expand 32-byte k" — universal marker.
_CHACHA_MAGIC = b"expand 32-byte k"
_SALSA_MAGIC = b"expand 16-byte k"

# DES SBOX1 first row (hex of ref impl — borrowed from RFC 4772-era code).
_DES_SBOX1 = bytes.fromhex("0e" "04" "0d" "01" "02" "0f" "0b" "08")

# Blowfish P-box first four words.
_BLOWFISH_P = bytes.fromhex("243f6a88" "85a308d3" "13198a2e" "03707344")


_CONSTANT_MARKERS: List[tuple[str, bytes]] = [
    ("AES (S-box)", _AES_SBOX_32),
    ("MD5 (init BE)", _MD5_INIT),
    ("MD5 (init LE)", _MD5_INIT_LE),
    ("SHA-256 (K[0..3])", _SHA256_K_BE),
    ("SHA-1 (H[0..4])", _SHA1_IV),
    ("ChaCha20/Salsa20", _CHACHA_MAGIC),
    ("Salsa20", _SALSA_MAGIC),
    ("Blowfish (P-box)", _BLOWFISH_P),
]

# Symbol hits — each entry yields (algo_label, regex).
_SYMBOL_MARKERS: List[tuple[str, re.Pattern[str]]] = [
    ("AES", re.compile(r"\bAES_(?:encrypt|decrypt|set_(?:encrypt|decrypt)_key)\b")),
    ("EVP (OpenSSL)", re.compile(r"\bEVP_(?:Encrypt|Decrypt|Digest|MD|CIPHER)")),
    ("RSA (OpenSSL)", re.compile(r"\bRSA_(?:public|private)_")),
    ("SHA-256", re.compile(r"\bSHA256_(?:Init|Update|Final)\b")),
    ("SHA-512", re.compile(r"\bSHA512_(?:Init|Update|Final)\b")),
    ("MD5", re.compile(r"\bMD5_(?:Init|Update|Final)\b")),
    ("HMAC", re.compile(r"\bHMAC_(?:Init|Update|Final|CTX)")),
    ("libsodium", re.compile(r"\bcrypto_(?:box|sign|secretbox|generichash|aead)_")),
    (
        "BCrypt (CNG)",
        re.compile(r"\bBCrypt(?:OpenAlgorithmProvider|Encrypt|Decrypt|Hash)"),
    ),
    ("CryptoAPI", re.compile(r"\bCrypt(?:Encrypt|Decrypt|AcquireContext|Hash)")),
    ("mbedTLS", re.compile(r"\bmbedtls_(?:aes|sha|md5|rsa|pk)_")),
]


class DetectCryptoArgs(BaseModel):
    max_scan_bytes: int | None = Field(
        None,
        description="Cap on raw-file bytes scanned for constant fingerprints.",
    )


class CryptoHit(BaseModel):
    algorithm: str
    source: str = Field(..., description="'constant' or 'symbol'")
    detail: str
    offset: int | None = Field(
        None,
        description="File offset of the matched constant (populated for "
                    "constant-fingerprint hits only).",
    )


class DetectCryptoResult(BaseModel):
    hits: List[CryptoHit]
    algorithms: List[str] = Field(
        ..., description="Deduplicated set of detected algorithms."
    )
    confidence: str = Field("LOW", description="HIGH / MEDIUM / LOW")


class DetectCryptoUsageTool(MemoryTool[DetectCryptoArgs, DetectCryptoResult]):
    def __init__(self) -> None:
        super().__init__(
            ToolMeta(
                name="detect_crypto_usage",
                description="Detect crypto algorithms by scanning for S-box / "
                            "IV / round-constant fingerprints and matching "
                            "well-known library API imports.",
                tags=("triage", "crypto"),
            ),
            DetectCryptoArgs,
            DetectCryptoResult,
        )

    def run(
        self,
        ctx: MemoryContext,
        kb: KnowledgeBase,
        args: DetectCryptoArgs,
    ) -> DetectCryptoResult:
        max_bytes = args.max_scan_bytes or ctx.budgets.max_read_bytes
        try:
            with open(ctx.file_path, "rb") as f:
                data = f.read(max_bytes)
        except FileNotFoundError:
            data = b""

        hits: List[CryptoHit] = []
        const_hit = False
        for algo, needle in _CONSTANT_MARKERS:
            pos = data.find(needle)
            if pos >= 0:
                const_hit = True
                hits.append(
                    CryptoHit(
                        algorithm=algo,
                        source="constant",
                        detail=f"{len(needle)}-byte fingerprint",
                        offset=pos,
                    )
                )

        # Symbol-based hits — cheap supplement.
        sym_hit = False
        try:
            summ = g.symbols.list_symbols_demangled(
                ctx.file_path,
                ctx.budgets.max_read_bytes,
                ctx.budgets.max_file_size,
            )
            syms = list(summ.import_names or []) + list(
                summ.demangled_import_names or []
            )
        except Exception:
            syms = []
        for sym in syms:
            for algo, pat in _SYMBOL_MARKERS:
                if pat.search(sym):
                    sym_hit = True
                    hits.append(
                        CryptoHit(
                            algorithm=algo,
                            source="symbol",
                            detail=sym,
                            offset=None,
                        )
                    )
                    break  # avoid multi-tagging the same symbol

        algos: Dict[str, None] = {}
        for h in hits:
            algos[h.algorithm] = None

        if const_hit:
            confidence = "HIGH"
        elif sym_hit:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return DetectCryptoResult(
            hits=hits, algorithms=list(algos.keys()), confidence=confidence
        )


def build_tool() -> MemoryTool[DetectCryptoArgs, DetectCryptoResult]:
    return DetectCryptoUsageTool()
