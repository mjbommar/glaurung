#!/usr/bin/env python
"""Build the adversarial-sample corpus for the embedded-content tools.

Produces files under samples/adversarial/embedded/ deterministically
from existing hello-* binaries plus a few synthetic constructions.
Re-runnable; outputs are derived artifacts that can be regenerated
on demand and don't need to live in git in their full form.

Each sample exercises one or more of the tool tiers described in
docs/llm/EMBEDDED_CONTENT_TOOLS.md. Output ordering mirrors the
sprint plan.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import io
import os
import shutil
import struct
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELLO_C = ROOT / "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-c-gcc-O2"
HELLO_CPP = ROOT / "samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-cpp-g++-O2"
OUT_DIR = ROOT / "samples/adversarial/embedded"


def _ensure_dirs() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)


def build_nested_zip_in_zip() -> Path:
    """Sprint 1 — zip-inside-zip nesting; exercises recursive_unpack."""
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(HELLO_C, arcname="hello")
    inner_bytes = inner.getvalue()
    out = OUT_DIR / "nested_zip_in_zip.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("inner.zip", inner_bytes)
        zf.writestr("README.txt", b"the real hello is in inner.zip\n")
    return out


def build_pe_with_overlay() -> Path:
    """Sprint 1 — fake PE stub with an appended zip overlay.

    We don't need a real PE — the embedded-magic scanner just needs an
    MZ header and a payload after the formal end. Build a minimal MZ
    + PE header structure followed by a zip overlay.
    """
    mz_hdr = b"MZ" + b"\x90" * 0x3a + struct.pack("<I", 0x40)
    pe_hdr = b"PE\x00\x00" + struct.pack("<HH", 0x14c, 0)  # i386, 0 sections
    pe_hdr += b"\x00" * 16  # timestamp, ptr to symbols, num symbols
    pe_hdr += struct.pack("<HH", 0xe0, 0x102)  # opt header size, characteristics
    pe_hdr += b"\x00" * 0xe0  # opt header padding
    stub = mz_hdr + b"\x00" * (0x40 - len(mz_hdr)) + pe_hdr
    overlay = io.BytesIO()
    with zipfile.ZipFile(overlay, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.txt", b"this came from the overlay\n")
        zf.write(HELLO_C, arcname="hello")
    out = OUT_DIR / "pe_with_overlay.exe"
    out.write_bytes(stub + overlay.getvalue())
    return out


def build_b64_payload_in_elf() -> Path:
    """Sprint 2 — append a base64-encoded ELF after a real ELF.

    The original ELF is unchanged so the OS can still execute it; the
    base64 payload sits in the file's tail (effectively an "overlay"
    on an ELF, which the linker doesn't care about). Embedded-content
    tools should:
      1. find_base64_blobs flags the trailing run as a long b64 blob
      2. decode_at(base64) yields the inner ELF bytes
      3. find_embedded_executables on the decoded blob detects ELF
    """
    payload = HELLO_C.read_bytes()
    encoded = base64.b64encode(payload)
    out = OUT_DIR / "b64_payload_in_elf.elf"
    out.write_bytes(payload + b"\n# embedded-payload-marker\n" + encoded + b"\n")
    return out


def build_xor_url_in_elf() -> Path:
    """Sprint 2 — single-byte XOR-encoded URL appended to an ELF.

    Key 0x42, plaintext "https://c2.example.invalid/beacon". XOR brute
    should find the key by scoring printable-ASCII output.
    """
    plaintext = b"https://c2.example.invalid/beacon"
    key = 0x42
    encoded = bytes(b ^ key for b in plaintext)
    payload = HELLO_C.read_bytes()
    out = OUT_DIR / "xor_url_in_elf.elf"
    out.write_bytes(
        payload + b"\n# c2-marker\n" + encoded + b"\n# c2-marker-end\n"
    )
    return out


def build_recursively_nested() -> Path:
    """Sprint 4 — base64( zip( xor(hello, key=0x55) ) ).

    The end-to-end test for the recursive triage orchestrator. To get
    back to a real ELF the pipeline must:
      1. base64-decode the file body
      2. unzip the result
      3. XOR-decode the inner entry
      4. detect ELF and run triage
    """
    elf = HELLO_C.read_bytes()
    xored = bytes(b ^ 0x55 for b in elf)
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.bin", xored)
    encoded = base64.b64encode(inner.getvalue())
    out = OUT_DIR / "recursively_nested.bin"
    out.write_bytes(encoded)
    return out


def build_gzip_with_hello() -> Path:
    """Sprint 1 / 2 — plain gzipped hello, simple positive control."""
    payload = HELLO_C.read_bytes()
    out = OUT_DIR / "hello.elf.gz"
    out.write_bytes(gzip.compress(payload))
    return out


def build_tar_with_two_hellos() -> Path:
    """Sprint 1 — tar with two binaries, one C and one C++.

    Exercises the multi-entry path of extract_archive_all.
    """
    out = OUT_DIR / "two_hellos.tar"
    with tarfile.open(out, "w") as tf:
        tf.add(HELLO_C, arcname="bin/hello-c")
        tf.add(HELLO_CPP, arcname="bin/hello-cpp")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--clean", action="store_true",
        help="Remove existing samples before building",
    )
    args = ap.parse_args()

    if args.clean and OUT_DIR.exists():
        shutil.rmtree(OUT_DIR)
    _ensure_dirs()

    if not HELLO_C.exists():
        print(f"missing dependency: {HELLO_C}", file=sys.stderr)
        return 1

    builders = [
        build_nested_zip_in_zip,
        build_pe_with_overlay,
        build_b64_payload_in_elf,
        build_xor_url_in_elf,
        build_recursively_nested,
        build_gzip_with_hello,
        build_tar_with_two_hellos,
    ]
    for fn in builders:
        path = fn()
        size = path.stat().st_size
        print(f"  built {path.relative_to(ROOT)}  ({size:,} bytes)")
    print(f"done — {len(builders)} samples in {OUT_DIR.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
