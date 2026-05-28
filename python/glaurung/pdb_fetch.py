"""Microsoft symbol-server PDB fetcher.

glaurung's PDB symbol resolver (``g.symbols.pdb_symbol_map``) reads a
Microsoft-style local PDB cache but never *fills* it. This module is the
missing piece: it reads a PE's CodeView RSDS record, computes the
symbol-server key (``<GUID><AGE>``), and downloads the matching PDB into
the cache in the canonical layout the resolver expects::

    <cache_dir>/<pdb_name>/<GUID><AGE>/<pdb_name>

Pure standard-library (struct + urllib); no pefile / external deps so it
can be a first-class part of the kickoff pipeline.
"""
from __future__ import annotations

import struct
import urllib.error
import urllib.request
from pathlib import Path
from typing import NamedTuple, Optional

MSDL_BASE = "https://msdl.microsoft.com/download/symbols"
# MS symbol server historically gates on a symbol-server-style UA.
_UA = "Microsoft-Symbol-Server/10.0.0.0"

IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DEBUG_TYPE_CODEVIEW = 2


class CodeView(NamedTuple):
    pdb_name: str          # basename, e.g. "srvnet.pdb"
    guid_age_key: str      # "<GUID><AGE>" symbol-server key
    pdb_path: str          # full path embedded in the PE


def _rva_to_off(rva: int, sections: list[tuple[int, int, int, int]]) -> Optional[int]:
    for va, vsz, praw, rsz in sections:
        # accept anything inside the virtual span; clamp to raw size
        if va <= rva < va + max(vsz, rsz):
            return praw + (rva - va)
    return None


def read_codeview(pe_path: str | Path) -> Optional[CodeView]:
    """Parse a PE's CodeView RSDS record. Returns None if the file has no
    RSDS debug record (e.g. fully stripped, or non-PE)."""
    data = Path(pe_path).read_bytes()
    if data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is_pe32_plus = magic == 0x20B
    # NumberOfRvaAndSizes precedes the data directories; debug dir is index 6.
    # Data directories start after the fixed optional-header body.
    dd_off = opt + (112 if is_pe32_plus else 96)
    dbg_rva, dbg_size = struct.unpack_from("<II", data, dd_off + IMAGE_DIRECTORY_ENTRY_DEBUG * 8)
    if dbg_rva == 0 or dbg_size == 0:
        return None
    # section headers follow the optional header
    sec_off = opt + opt_size
    sections = []
    for i in range(num_sections):
        s = sec_off + i * 40
        vsz, va, rsz, praw = struct.unpack_from("<IIII", data, s + 8)
        sections.append((va, vsz, praw, rsz))
    dbg_off = _rva_to_off(dbg_rva, sections)
    if dbg_off is None:
        return None
    n = dbg_size // 28
    for i in range(n):
        ent = dbg_off + i * 28
        dtype = struct.unpack_from("<I", data, ent + 12)[0]
        praw = struct.unpack_from("<I", data, ent + 24)[0]
        if dtype != IMAGE_DEBUG_TYPE_CODEVIEW or praw == 0:
            continue
        if data[praw:praw + 4] != b"RSDS":
            continue
        guid = data[praw + 4:praw + 20]
        age = struct.unpack_from("<I", data, praw + 20)[0]
        # GUID string in Microsoft symbol-server spelling.
        d1 = struct.unpack_from("<I", guid, 0)[0]
        d2 = struct.unpack_from("<H", guid, 4)[0]
        d3 = struct.unpack_from("<H", guid, 6)[0]
        rest = guid[8:]
        guid_string = (
            f"{d1:08X}{d2:04X}{d3:04X}" + "".join(f"{b:02X}" for b in rest)
        )
        key = f"{guid_string}{age:X}"
        end = data.index(b"\0", praw + 24)
        pdb_path = data[praw + 24:end].decode("utf-8", "replace")
        pdb_name = pdb_path.replace("\\", "/").rsplit("/", 1)[-1]
        return CodeView(pdb_name=pdb_name, guid_age_key=key, pdb_path=pdb_path)
    return None


def cache_path_for(cv: CodeView, cache_dir: str | Path) -> Path:
    return Path(cache_dir) / cv.pdb_name / cv.guid_age_key / cv.pdb_name


def ensure_pdb_cached(
    pe_path: str | Path,
    cache_dir: str | Path,
    *,
    download: bool = True,
    timeout: float = 60.0,
) -> Optional[Path]:
    """Return the local cached PDB path for ``pe_path``, downloading it from
    the Microsoft symbol server if absent. Returns None when the PE has no
    CodeView record or the download fails."""
    cv = read_codeview(pe_path)
    if cv is None:
        return None
    dest = cache_path_for(cv, cache_dir)
    if dest.is_file() and dest.stat().st_size > 0:
        return dest
    if not download:
        return None
    url = f"{MSDL_BASE}/{cv.pdb_name}/{cv.guid_age_key}/{cv.pdb_name}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None
    if not body:
        return None
    tmp = dest.with_suffix(dest.suffix + ".part")
    tmp.write_bytes(body)
    tmp.replace(dest)
    return dest
