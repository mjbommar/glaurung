"""Windows PE analysis helpers built on Glaurung's structured facts."""

from __future__ import annotations

import json
import struct
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

import bisect

from . import _native, analysis, disasm, symbols  # ty: ignore[unresolved-import]
from .windows_config import WindowsAnalysisConfig


_DEFAULT_CONFIG = WindowsAnalysisConfig()
DEFAULT_MAX_READ_BYTES = _DEFAULT_CONFIG.max_read_bytes
DEFAULT_MAX_FILE_SIZE = _DEFAULT_CONFIG.max_file_size
DEFAULT_MAX_FUNCTIONS = _DEFAULT_CONFIG.max_functions
DEFAULT_MAX_BLOCKS = _DEFAULT_CONFIG.max_blocks
DEFAULT_MAX_INSTRUCTIONS = _DEFAULT_CONFIG.max_instructions
DEFAULT_TIMEOUT_MS = _DEFAULT_CONFIG.timeout_ms


def _hex(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def _enum_name(value: Any) -> str:
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    return str(value)


def _addr_value(value: Any) -> int:
    return int(getattr(value, "value", value))


def _maybe_call(value: Any) -> Any:
    return value() if callable(value) else value


def _range_to_dict(range_obj: Any) -> dict[str, Any]:
    start = _addr_value(range_obj.start)
    end = _addr_value(_maybe_call(range_obj.end))
    return {
        "start_va": start,
        "start": _hex(start),
        "end_va": end,
        "end": _hex(end),
        "size": int(range_obj.size),
    }


def _block_to_dict(block: Any) -> dict[str, Any]:
    start = _addr_value(block.start_address)
    end = _addr_value(_maybe_call(block.end_address))
    return {
        "id": str(block.id),
        "start_va": start,
        "start": _hex(start),
        "end_va": end,
        "end": _hex(end),
        "size": int(_maybe_call(block.size_bytes)),
        "instructions": int(_maybe_call(block.instruction_count)),
        "predecessors": [str(item) for item in block.predecessor_ids],
        "successors": [str(item) for item in block.successor_ids],
        "is_entry": bool(_maybe_call(block.is_entry_block)),
        "is_exit": bool(_maybe_call(block.is_exit_block)),
    }


def function_to_dict(function: Any, seed_kind: str | None = None) -> dict[str, Any]:
    """Convert a native Function object into stable Python facts."""

    entry_va = _addr_value(function.entry_point)
    size = function.size if function.size is not None else function.calculate_size()
    return {
        "entry_va": entry_va,
        "entry": _hex(entry_va),
        "name": function.name,
        "kind": _enum_name(function.kind),
        "seed_kind": seed_kind,
        "size": int(size),
        "total_size": int(function.total_size()),
        "ranges": [_range_to_dict(item) for item in function.all_ranges()],
        "basic_blocks": [_block_to_dict(item) for item in function.basic_blocks],
    }


def _code_pointer_tuple_to_dict(item: tuple[Any, ...]) -> dict[str, Any]:
    pointer_va, target_va, section, slot_size, table_index, table_length, confidence = (
        item
    )
    return {
        "pointer_va": int(pointer_va),
        "pointer": _hex(int(pointer_va)),
        "target_va": int(target_va),
        "target": _hex(int(target_va)),
        "section": str(section),
        "slot_size": int(slot_size),
        "table_index": int(table_index),
        "table_length": int(table_length),
        "confidence": str(confidence),
    }


def _code_label_to_dict(item: dict[str, Any]) -> dict[str, Any]:
    va = int(item["va"])
    function_va = int(item["function_va"])
    kind = str(item["kind"])
    if kind == "epilogue_label":
        name = f"EPILOGUE_{va:x}"
    elif kind == "simd_block_label":
        name = f"LAB_SIMD_{va:x}"
    else:
        name = f"LAB_{va:x}"
    return {
        "va": va,
        "address": _hex(va),
        "function_va": function_va,
        "function": _hex(function_va),
        "name": name,
        "kind": kind,
        "provenance": {
            "kind": kind,
            "source_va": function_va,
            "source": _hex(function_va),
            "detail": "cfg_basic_block_label",
        },
    }


def find_code_pointers(
    path: str | Path,
    *,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> list[dict[str, Any]]:
    """Find PE data slots that point at plausible executable code starts."""

    relocated_slots = {
        int(item["slot_va"])
        for item in _relocation_entries(path)
        if item.get("type_name") in {"dir64", "highlow"}
    }
    pointers = [
        _code_pointer_tuple_to_dict(item)
        for item in analysis.find_code_pointers_path(
            str(path),
            max_read_bytes,
            max_file_size,
        )
    ]
    for pointer in pointers:
        pointer["relocation_backed"] = int(pointer["pointer_va"]) in relocated_slots
    return pointers


def _analyze(
    path: str | Path,
    *,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> tuple[list[Any], Any, dict[str, Any]]:
    funcs, callgraph, stats = analysis.analyze_functions_path_with_stats(
        str(path),
        max_read_bytes,
        max_file_size,
        max_functions,
        max_blocks,
        max_instructions,
        timeout_ms,
    )
    return funcs, callgraph, dict(stats)


def functions_by_seed_kind(
    path: str | Path,
    *,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> dict[str, list[dict[str, Any]]]:
    """Group discovered functions by discovery seed/confidence class."""

    funcs, _callgraph, stats = _analyze(
        path,
        max_read_bytes=max_read_bytes,
        max_file_size=max_file_size,
        max_functions=max_functions,
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
    )
    seed_by_va = {
        int(item["va"]): str(item["kind"])
        for item in stats.get("function_seed_kinds", [])
    }
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for function in funcs:
        entry_va = _addr_value(function.entry_point)
        seed_kind = seed_by_va.get(entry_va, "unknown")
        grouped[seed_kind].append(function_to_dict(function, seed_kind))
    return dict(sorted(grouped.items()))


def xrefs_to(
    path: str | Path,
    va: int,
    *,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> list[dict[str, Any]]:
    """Return provenance entries that target an address."""

    _funcs, _callgraph, stats = _analyze(
        path,
        max_read_bytes=max_read_bytes,
        max_file_size=max_file_size,
        max_functions=max_functions,
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
    )
    return [
        {
            **dict(item),
            "target": _hex(int(item["target_va"])),
            "source": _hex(item.get("source_va")),
        }
        for item in stats.get("seed_provenance", [])
        if int(item.get("target_va", -1)) == int(va)
    ]


def pdata_at(
    path: str | Path,
    va: int,
    *,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> dict[str, Any]:
    """Return the current unwind-start view for an address."""

    _funcs, _callgraph, stats = _analyze(
        path,
        max_read_bytes=max_read_bytes,
        max_file_size=max_file_size,
        max_functions=max_functions,
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
    )
    records = _pdata_records(path)
    matching = [
        record
        for record in records
        if int(record["begin_va"]) <= int(va) < int(record["end_va"])
    ]
    provenance = [
        dict(item)
        for item in stats.get("seed_provenance", [])
        if int(item.get("target_va", -1)) == int(va)
        and item.get("kind") == "trusted_pdata"
    ]
    return {
        "va": int(va),
        "address": _hex(int(va)),
        "is_pdata_start": any(
            int(record["begin_va"]) == int(va) for record in matching
        ),
        "containing_pdata": matching[:4],
        "provenance": provenance,
        "pdata_entries": int(stats.get("pdata_entries", 0)),
        "pdata_body_overlap_starts": int(stats.get("pdata_body_overlap_starts", 0)),
    }


def containing_function(
    path: str | Path,
    va: int,
    *,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> dict[str, Any] | None:
    """Return the discovered function containing a VA, if any."""

    funcs, _callgraph, stats = _analyze(
        path,
        max_read_bytes=max_read_bytes,
        max_file_size=max_file_size,
        max_functions=max_functions,
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
    )
    seed_by_va = {
        int(item["va"]): str(item["kind"])
        for item in stats.get("function_seed_kinds", [])
    }
    for function in funcs:
        if function.contains_va(int(va)):
            entry_va = _addr_value(function.entry_point)
            return function_to_dict(function, seed_by_va.get(entry_va))
    return None


def import_callers(
    path: str | Path,
    import_name: str | None = None,
    *,
    pdb_cache: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Group PE import call/jmp sites by the function that contains them.

    This is xrefs-to-an-imported-symbol: ``analysis.pe_import_call_sites_path``
    finds every ``call``/``jmp`` through an IAT slot, and -- when a ``pdb_cache``
    is supplied -- each call site is attributed to its containing function via
    the PDB public-symbol map (parsed once) plus a sorted-entry bisect, so the
    whole binary is answered without per-VA CFG recovery.

    Args:
        path: PE binary.
        import_name: restrict to one imported symbol (e.g.
            ``"SHLoadIndirectString"``); ``None`` returns callers for every
            import.
        pdb_cache: Microsoft-style PDB cache dir for function-name attribution.
            Without it, ``function``/``function_va`` are ``None`` and sites are
            grouped per import only.

    Returns:
        A list of ``{import_name, function, function_va, call_sites, count}``
        dicts, sorted by descending ``count``.
    """

    sites = analysis.pe_import_call_sites_path(str(path))
    if import_name is not None:
        sites = [row for row in sites if row[2] == import_name]

    symmap: dict[int, str] = {}
    if pdb_cache:
        cache_dir = Path(pdb_cache)
        if cache_dir.is_dir():
            symmap = {
                int(va): str(name)
                for va, name in symbols.pdb_symbol_map(str(path), str(cache_dir)).items()
            }
    entries = sorted(symmap)

    def _containing(site_va: int) -> tuple[int | None, str | None]:
        if not entries:
            return (None, None)
        idx = bisect.bisect_right(entries, site_va) - 1
        if idx < 0:
            return (None, None)
        entry_va = entries[idx]
        return (entry_va, symmap[entry_va])

    groups: dict[tuple[str, int | None, str | None], list[int]] = defaultdict(list)
    for site_va, _iat_va, name in sites:
        entry_va, func_name = _containing(int(site_va))
        groups[(str(name), entry_va, func_name)].append(int(site_va))

    out = [
        {
            "import_name": name,
            "function": func_name,
            "function_va": entry_va,
            "function_hex": _hex(entry_va),
            "call_sites": sorted(call_sites),
            "count": len(call_sites),
        }
        for (name, entry_va, func_name), call_sites in groups.items()
    ]
    out.sort(key=lambda row: (-row["count"], row["import_name"], row["function_va"] or 0))
    return out


def bytes_at(
    path: str | Path,
    va: int,
    size: int = 16,
    *,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
) -> dict[str, Any]:
    """Return file bytes at a VA using the native PE VA mapper."""

    offset = analysis.va_to_file_offset_path(
        str(path),
        int(va),
        max_read_bytes,
        max_file_size,
    )
    if offset is None:
        return {"va": int(va), "address": _hex(int(va)), "file_offset": None, "hex": ""}
    data = Path(path).read_bytes()
    raw = data[int(offset) : int(offset) + int(size)]
    return {
        "va": int(va),
        "address": _hex(int(va)),
        "file_offset": int(offset),
        "hex": raw.hex(),
        "size": len(raw),
    }


def disasm_at(
    path: str | Path,
    va: int,
    count: int = 8,
    *,
    window_bytes: int = 128,
    max_time_ms: int = 50,
) -> list[dict[str, Any]]:
    """Disassemble a short window at a VA."""

    instructions = disasm.disassemble_window_at(
        str(path),
        int(va),
        window_bytes=window_bytes,
        max_instructions=count,
        max_time_ms=max_time_ms,
    )
    return [
        {
            "address_va": _addr_value(ins.address),
            "address": _hex(_addr_value(ins.address)),
            "mnemonic": ins.mnemonic,
            "operands": [str(op) for op in ins.operands],
        }
        for ins in instructions
    ]


def _pe_sections(path: str | Path) -> list[dict[str, Any]]:
    data = Path(path).read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 >= len(data) or data[pe_off : pe_off + 4] != b"PE\0\0":
        return []
    section_count = struct.unpack_from("<H", data, pe_off + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    optional_header = pe_off + 24
    magic = struct.unpack_from("<H", data, optional_header)[0]
    image_base = (
        struct.unpack_from("<Q", data, optional_header + 24)[0]
        if magic == 0x20B
        else struct.unpack_from("<I", data, optional_header + 28)[0]
    )
    section_table = optional_header + optional_header_size
    sections = []
    for index in range(section_count):
        section = section_table + index * 40
        if section + 40 > len(data):
            break
        raw_name = data[section : section + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, section + 8
        )
        characteristics = struct.unpack_from("<I", data, section + 36)[0]
        size = max(int(virtual_size), int(raw_size))
        start = int(image_base) + int(virtual_address)
        sections.append(
            {
                "name": name,
                "start_va": start,
                "start": _hex(start),
                "end_va": start + size,
                "end": _hex(start + size),
                "raw_pointer": int(raw_pointer),
                "raw_size": int(raw_size),
                "virtual_size": int(virtual_size),
                "characteristics": int(characteristics),
                "readable": bool(characteristics & 0x4000_0000),
                "writable": bool(characteristics & 0x8000_0000),
                "executable": bool(characteristics & 0x2000_0000),
            }
        )
    return sections


def _pe_hardening(path: str | Path) -> dict[str, Any]:
    data = Path(path).read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {}
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 >= len(data) or data[pe_off : pe_off + 4] != b"PE\0\0":
        return {}
    optional_header = pe_off + 24
    if optional_header + 0x48 > len(data):
        return {}
    dll_characteristics_offset = optional_header + 0x46
    if dll_characteristics_offset + 2 > len(data):
        return {}
    dll_characteristics = struct.unpack_from("<H", data, dll_characteristics_offset)[0]
    return {
        "dll_characteristics": dll_characteristics,
        "high_entropy_va": bool(dll_characteristics & 0x0020),
        "dynamic_base": bool(dll_characteristics & 0x0040),
        "force_integrity": bool(dll_characteristics & 0x0080),
        "nx_compat": bool(dll_characteristics & 0x0100),
        "no_seh": bool(dll_characteristics & 0x0400),
        "guard_cf": bool(dll_characteristics & 0x4000),
        "terminal_server_aware": bool(dll_characteristics & 0x8000),
    }


def _pdata_records(path: str | Path) -> list[dict[str, Any]]:
    data = Path(path).read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 >= len(data) or data[pe_off : pe_off + 4] != b"PE\0\0":
        return []
    section_count = struct.unpack_from("<H", data, pe_off + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    optional_header = pe_off + 24
    magic = struct.unpack_from("<H", data, optional_header)[0]
    image_base = (
        struct.unpack_from("<Q", data, optional_header + 24)[0]
        if magic == 0x20B
        else struct.unpack_from("<I", data, optional_header + 28)[0]
    )
    section_table = optional_header + optional_header_size
    records = []
    for index in range(section_count):
        section = section_table + index * 40
        if section + 40 > len(data):
            break
        name = (
            data[section : section + 8]
            .split(b"\0", 1)[0]
            .decode("ascii", errors="replace")
        )
        if name.lower() != ".pdata":
            continue
        _virtual_size, _virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, section + 8
        )
        raw_start = int(raw_pointer)
        raw_end = min(raw_start + int(raw_size), len(data))
        cursor = raw_start
        while cursor + 12 <= raw_end:
            begin_rva, end_rva, unwind_rva = struct.unpack_from("<III", data, cursor)
            cursor += 12
            if begin_rva == 0 and end_rva == 0 and unwind_rva == 0:
                continue
            if begin_rva == 0 or end_rva <= begin_rva:
                continue
            begin_va = int(image_base) + int(begin_rva)
            end_va = int(image_base) + int(end_rva)
            records.append(
                {
                    "begin_va": begin_va,
                    "begin": _hex(begin_va),
                    "end_va": end_va,
                    "end": _hex(end_va),
                    "unwind_va": _hex(int(image_base) + int(unwind_rva)),
                    "size": end_va - begin_va,
                }
            )
    return records


def _relocation_entries(path: str | Path) -> list[dict[str, Any]]:
    data = Path(path).read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 >= len(data) or data[pe_off : pe_off + 4] != b"PE\0\0":
        return []
    section_count = struct.unpack_from("<H", data, pe_off + 6)[0]
    optional_header_size = struct.unpack_from("<H", data, pe_off + 20)[0]
    optional_header = pe_off + 24
    magic = struct.unpack_from("<H", data, optional_header)[0]
    image_base = (
        struct.unpack_from("<Q", data, optional_header + 24)[0]
        if magic == 0x20B
        else struct.unpack_from("<I", data, optional_header + 28)[0]
    )
    section_table = optional_header + optional_header_size
    reloc_ranges = []
    for index in range(section_count):
        section = section_table + index * 40
        if section + 40 > len(data):
            break
        name = (
            data[section : section + 8]
            .split(b"\0", 1)[0]
            .decode("ascii", errors="replace")
        )
        if name.lower() != ".reloc":
            continue
        _virtual_size, _virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, section + 8
        )
        reloc_ranges.append(
            (int(raw_pointer), min(int(raw_pointer) + int(raw_size), len(data)))
        )
    type_names = {
        0: "absolute",
        3: "highlow",
        10: "dir64",
    }
    entries = []
    for raw_start, raw_end in reloc_ranges:
        cursor = raw_start
        while cursor + 8 <= raw_end:
            page_rva, block_size = struct.unpack_from("<II", data, cursor)
            if block_size < 8 or cursor + block_size > raw_end:
                break
            cursor += 8
            entry_end = cursor + block_size - 8
            while cursor + 2 <= entry_end:
                raw = struct.unpack_from("<H", data, cursor)[0]
                cursor += 2
                reloc_type = raw >> 12
                reloc_off = raw & 0x0FFF
                if reloc_type == 0:
                    continue
                slot_va = int(image_base) + int(page_rva) + int(reloc_off)
                entries.append(
                    {
                        "slot_va": slot_va,
                        "slot": _hex(slot_va),
                        "type": reloc_type,
                        "type_name": type_names.get(reloc_type, f"type_{reloc_type}"),
                    }
                )
            cursor = entry_end
    return entries


def _section_for_va(sections: list[dict[str, Any]], va: int) -> dict[str, Any] | None:
    for section in sections:
        if int(section["start_va"]) <= int(va) < int(section["end_va"]):
            return section
    return None


def _imports(path: str | Path) -> list[dict[str, Any]]:
    try:
        return [
            {"iat_va": int(va), "iat": _hex(int(va)), "name": str(name)}
            for va, name in analysis.pe_iat_map_path(str(path))
        ]
    except Exception:
        return []


def _strings(
    path: str | Path, max_read_bytes: int, max_file_size: int
) -> dict[str, Any]:
    try:
        artifact = _native.triage.analyze_path(
            str(path),
            max_read_bytes,
            max_file_size,
            1,
        )
        string_summary = getattr(artifact, "strings", None)
    except Exception:
        return {"strings": [], "samples": [], "ioc_counts": {}}
    if string_summary is None:
        return {"strings": [], "samples": [], "ioc_counts": {}}
    rows = []
    for item in list(getattr(string_summary, "strings", []) or [])[:256]:
        rows.append(
            {
                "text": getattr(item, "text", ""),
                "offset": getattr(item, "offset", None),
                "encoding": str(getattr(item, "encoding", "")),
                "confidence": getattr(item, "confidence", None),
                "language": getattr(item, "language", None),
                "script": getattr(item, "script", None),
            }
        )
    return {
        "strings": rows,
        "samples": list(getattr(string_summary, "samples", []) or [])[:64],
        "ioc_counts": dict(getattr(string_summary, "ioc_counts", {}) or {}),
    }


@lru_cache(maxsize=1)
def _winapi_prototype_index() -> dict[str, dict[str, Any]]:
    path = Path(__file__).resolve().parents[2] / "data/types/stdlib-winapi-protos.json"
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    index = {}
    for proto in bundle.get("prototypes", []):
        name = str(proto.get("name", ""))
        if name:
            index[name.lower()] = proto
    return index


def _winapi_prototypes_for_imports(
    imports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    index = _winapi_prototype_index()
    rows = []
    for import_row in imports:
        name = str(import_row.get("name", ""))
        keys = [name.lower()]
        if name.startswith("imp_"):
            keys.append(name[4:].lower())
        proto = next((index[key] for key in keys if key in index), None)
        if proto is not None:
            rows.append(
                {
                    "iat": import_row.get("iat"),
                    "name": name,
                    "prototype": proto,
                }
            )
    return rows


def map_windows_driver_surface(
    path: str | Path,
    *,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> dict[str, Any]:
    """Map likely Windows driver entrypoints, callback tables, and imports."""

    entry = analysis.detect_entry_path(str(path), max_read_bytes, max_file_size)
    entry_va = int(entry[3]) if entry else None
    code_pointers = find_code_pointers(
        path,
        max_read_bytes=max_read_bytes,
        max_file_size=max_file_size,
    )
    funcs, _callgraph, stats = _analyze(
        path,
        max_read_bytes=max_read_bytes,
        max_file_size=max_file_size,
        max_functions=max_functions,
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
    )
    seed_by_va = {
        int(item["va"]): str(item["kind"])
        for item in stats.get("function_seed_kinds", [])
    }
    data_ref_functions = [
        function_to_dict(function, seed_by_va.get(_addr_value(function.entry_point)))
        for function in funcs
        if seed_by_va.get(_addr_value(function.entry_point)) == "data_ref"
    ]
    grouped_tables: dict[tuple[str, int], dict[str, Any]] = {}
    for pointer in code_pointers:
        key = (pointer["section"], pointer["table_index"])
        table = grouped_tables.setdefault(
            key,
            {
                "section": pointer["section"],
                "table_index": pointer["table_index"],
                "slot_size": pointer["slot_size"],
                "table_length": pointer["table_length"],
                "targets": [],
            },
        )
        table["targets"].append(pointer["target"])
    import_rows = _imports(path)
    import_names = [row["name"] for row in import_rows]
    hardening = _pe_hardening(path)
    return {
        "path": str(path),
        "is_driver": Path(path).suffix.lower() == ".sys",
        "entrypoint_va": entry_va,
        "entrypoint": _hex(entry_va),
        "driver_entry": _hex(entry_va),
        "dispatch_table_candidates": sorted(
            grouped_tables.values(),
            key=lambda item: (-int(item["table_length"]), str(item["section"])),
        )[:32],
        "data_ref_callback_functions": data_ref_functions,
        "wdf_imports": [
            name for name in import_names if name.lower().startswith("wdf")
        ],
        "io_imports": [name for name in import_names if name.startswith("Io")],
        "pnp_power_imports": [
            name
            for name in import_names
            if any(token in name.lower() for token in ("pnp", "power", "plugplay"))
        ],
        "security_cookie_imports": [
            name
            for name in import_names
            if "security" in name.lower() or "cookie" in name.lower()
        ],
        "verifier_imports": [
            name for name in import_names if "verifier" in name.lower()
        ],
        "hardening": hardening,
        "imports": import_rows,
    }


def collect_windows_facts(
    path: str | Path,
    *,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> dict[str, Any]:
    """Collect structured Windows PE facts for scripts, rules, and agents."""

    funcs, callgraph, stats = _analyze(
        path,
        max_read_bytes=max_read_bytes,
        max_file_size=max_file_size,
        max_functions=max_functions,
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
    )
    seed_by_va = {
        int(item["va"]): str(item["kind"])
        for item in stats.get("function_seed_kinds", [])
    }
    sections = _pe_sections(path)
    import_rows = _imports(path)
    return {
        "path": str(path),
        "sections": sections,
        "hardening": _pe_hardening(path),
        "imports": import_rows,
        "winapi_prototypes": _winapi_prototypes_for_imports(import_rows),
        "strings": _strings(path, max_read_bytes, max_file_size),
        "pdata_records": _pdata_records(path),
        "relocations": _relocation_entries(path),
        "functions": [
            function_to_dict(
                function, seed_by_va.get(_addr_value(function.entry_point))
            )
            for function in funcs
        ],
        "callgraph": {
            "function_count": int(callgraph.function_count()),
            "edge_count": int(callgraph.edge_count()),
        },
        "stats": stats,
        "code_pointers": find_code_pointers(
            path,
            max_read_bytes=max_read_bytes,
            max_file_size=max_file_size,
        ),
        "code_labels": [
            _code_label_to_dict(item) for item in stats.get("code_labels", [])
        ],
        "seed_provenance": list(stats.get("seed_provenance", [])),
        "section_by_function": {
            _hex(function["entry_va"]): (
                _section_for_va(sections, int(function["entry_va"])) or {}
            ).get("name")
            for function in [
                function_to_dict(item, seed_by_va.get(_addr_value(item.entry_point)))
                for item in funcs
            ]
        },
        "driver_surface": map_windows_driver_surface(
            path,
            max_read_bytes=max_read_bytes,
            max_file_size=max_file_size,
            max_functions=max_functions,
            max_blocks=max_blocks,
            max_instructions=max_instructions,
            timeout_ms=timeout_ms,
        ),
    }


def explain_va_from_facts(
    facts: dict[str, Any], va: int, *, byte_count: int = 16
) -> dict[str, Any]:
    """Explain an address using an already collected fact bundle."""

    path = facts["path"]
    va = int(va)
    containing = None
    for function in facts.get("functions", []):
        for range_row in function.get("ranges", []):
            if int(range_row["start_va"]) <= va < int(range_row["end_va"]):
                containing = function
                break
        if containing:
            break
    labels = [
        item for item in facts.get("code_labels", []) if int(item.get("va", -1)) == va
    ]
    provenance = [
        item
        for item in facts.get("seed_provenance", [])
        if int(item.get("target_va", -1)) == va
    ]
    pdata_records = [
        item
        for item in facts.get("pdata_records", [])
        if int(item.get("begin_va", -1)) <= va < int(item.get("end_va", -1))
    ]
    code_pointer_refs = [
        item
        for item in facts.get("code_pointers", [])
        if int(item.get("target_va", -1)) == va
    ]
    section = _section_for_va(facts.get("sections", []), va)
    return {
        "va": va,
        "address": _hex(va),
        "section": None if section is None else section.get("name"),
        "bytes": bytes_at(path, va, byte_count),
        "containing_function": containing,
        "labels": labels,
        "provenance": provenance,
        "code_pointer_refs": code_pointer_refs,
        "pdata": {
            "is_pdata_start": any(
                int(item.get("begin_va", -1)) == va for item in pdata_records
            ),
            "containing_pdata": pdata_records[:4],
            "pdata_body_overlap_starts": facts.get("stats", {}).get(
                "pdata_body_overlap_starts", 0
            ),
        },
    }


def classify_function_start_from_facts(
    facts: dict[str, Any],
    va: int,
    *,
    byte_count: int = 16,
) -> dict[str, Any]:
    """Classify one VA as a function, label, candidate, reject, or unknown.

    This is the public Python helper behind the agent-facing state model.
    It deliberately separates strict function entries from code labels and
    low-confidence candidates so agents do not treat every useful address
    as a top-level function.
    """

    va = int(va)
    explanation = explain_va_from_facts(facts, va, byte_count=byte_count)
    function_entry = next(
        (
            function
            for function in facts.get("functions", [])
            if int(function.get("entry_va", -1)) == va
        ),
        None,
    )
    labels = explanation.get("labels") or []
    provenance = explanation.get("provenance") or []
    code_pointer_refs = explanation.get("code_pointer_refs") or []
    pdata = explanation.get("pdata") or {}
    hex_bytes = str((explanation.get("bytes") or {}).get("hex") or "").lower()
    reason_codes = _function_start_reason_codes(
        function_entry=function_entry,
        labels=labels,
        provenance=provenance,
        code_pointer_refs=code_pointer_refs,
        pdata=pdata,
        hex_bytes=hex_bytes,
    )
    state = _function_start_state(
        function_entry=function_entry,
        labels=labels,
        provenance=provenance,
        code_pointer_refs=code_pointer_refs,
        pdata=pdata,
        hex_bytes=hex_bytes,
    )
    return {
        "va": va,
        "address": _hex(va),
        "state": state,
        "confidence": _function_start_confidence(state, reason_codes),
        "is_function_entry": function_entry is not None,
        "is_code_label": bool(labels),
        "seed_kind": None
        if function_entry is None
        else function_entry.get("seed_kind"),
        "containing_function": explanation.get("containing_function"),
        "label_count": len(labels),
        "provenance_count": len(provenance),
        "code_pointer_ref_count": len(code_pointer_refs),
        "pdata": pdata,
        "bytes": explanation.get("bytes"),
        "reason_codes": reason_codes,
        "recommended_action": _function_start_action(state, reason_codes),
    }


def classify_function_start(
    path: str | Path,
    va: int,
    *,
    byte_count: int = 16,
    **kwargs: Any,
) -> dict[str, Any]:
    """Collect Windows facts and classify one potential function start."""

    return classify_function_start_from_facts(
        collect_windows_facts(path, **kwargs),
        va,
        byte_count=byte_count,
    )


def explain_va(path: str | Path, va: int, *, byte_count: int = 16) -> dict[str, Any]:
    """Collect facts and explain a single address."""

    return explain_va_from_facts(collect_windows_facts(path), va, byte_count=byte_count)


def _function_start_state(
    *,
    function_entry: dict[str, Any] | None,
    labels: list[dict[str, Any]],
    provenance: list[dict[str, Any]],
    code_pointer_refs: list[dict[str, Any]],
    pdata: dict[str, Any],
    hex_bytes: str,
) -> str:
    if function_entry is not None:
        return "strict_function"
    if labels:
        return "code_label"
    if _is_padding_run(hex_bytes):
        return "rejected_start"
    if provenance or code_pointer_refs or pdata.get("is_pdata_start"):
        return "candidate"
    return "no_evidence"


def _function_start_reason_codes(
    *,
    function_entry: dict[str, Any] | None,
    labels: list[dict[str, Any]],
    provenance: list[dict[str, Any]],
    code_pointer_refs: list[dict[str, Any]],
    pdata: dict[str, Any],
    hex_bytes: str,
) -> list[str]:
    codes: list[str] = []
    if function_entry is not None:
        codes.append("function_entry")
        seed_kind = function_entry.get("seed_kind")
        if seed_kind:
            codes.append(f"{seed_kind}_seed")
    if labels:
        codes.append("code_label")
    if provenance:
        codes.append("seed_provenance")
        for item in provenance:
            kind = item.get("kind")
            if kind:
                codes.append(f"{kind}_provenance")
    if code_pointer_refs:
        codes.append("code_pointer_ref")
    if pdata.get("is_pdata_start"):
        codes.append("pdata_start")
    if int(pdata.get("pdata_body_overlap_starts") or 0) > 0:
        codes.append("pdata_body_overlap")
    if hex_bytes.startswith("48ff25"):
        codes.append("rex_import_jump_thunk")
    elif hex_bytes.startswith("ff25"):
        codes.append("import_jump_thunk")
    if hex_bytes.startswith("0f10"):
        codes.append("simd_head")
    if _is_padding_run(hex_bytes):
        codes.append("padding_run")
    return _dedupe_strings(codes)


def _function_start_confidence(state: str, reason_codes: list[str]) -> str:
    if state == "strict_function":
        return "high"
    if state == "rejected_start" and "padding_run" in reason_codes:
        return "high"
    if state in {"code_label", "candidate"}:
        return "medium"
    return "unknown"


def _function_start_action(state: str, reason_codes: list[str]) -> str:
    if state == "strict_function":
        return "keep_strict_function"
    if state == "code_label":
        return "keep_code_label"
    if state == "rejected_start":
        return "keep_rejected_start"
    if state == "candidate":
        if "pdata_start" in reason_codes or "code_pointer_ref" in reason_codes:
            return "collect_boundary_or_xref_evidence"
        return "collect_more_evidence"
    return "no_action_without_evidence"


def _is_padding_run(hex_bytes: str) -> bool:
    return hex_bytes.startswith("cccccc") or hex_bytes.startswith("000000")


def _dedupe_strings(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _load_ghidra_rows(ghidra_json: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(ghidra_json).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [dict(item) for item in data]
    if isinstance(data, dict) and "rows" in data and isinstance(data["rows"], list):
        return [dict(item) for item in data["rows"]]
    if isinstance(data, dict):
        return [data]
    raise ValueError(f"unsupported Ghidra JSON shape: {type(data).__name__}")


def _row_matches_path(row: dict[str, Any], path: Path) -> bool:
    names = {
        str(path),
        path.name,
    }
    try:
        names.add(str(path.resolve()))
    except OSError:
        pass
    for key in ("path", "file", "name"):
        value = row.get(key)
        if value is not None and (
            str(value) in names or Path(str(value)).name == path.name
        ):
            return True
    return False


def _load_ghidra_functions(row: dict[str, Any]) -> list[dict[str, Any]]:
    if "ghidra" in row and isinstance(row["ghidra"], dict):
        functions = row["ghidra"].get("functions", [])
    else:
        functions = row.get("functions", [])
    return [dict(item) for item in functions]


def _ghidra_entries_for_path(
    path: str | Path, ghidra_json: str | Path
) -> list[dict[str, Any]]:
    path_obj = Path(path)
    rows = _load_ghidra_rows(ghidra_json)
    if len(rows) == 1:
        return _load_ghidra_functions(rows[0])
    for row in rows:
        if _row_matches_path(row, path_obj):
            return _load_ghidra_functions(row)
    raise ValueError(f"no Ghidra row matched {path_obj.name} in {ghidra_json}")


def diff_ghidra(
    path: str | Path,
    ghidra_json: str | Path,
    *,
    limit: int = 32,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> dict[str, Any]:
    """Compare Glaurung function starts against a Ghidra parity JSON report."""

    facts = collect_windows_facts(
        path,
        max_read_bytes=max_read_bytes,
        max_file_size=max_file_size,
        max_functions=max_functions,
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
    )
    ghidra_functions = _ghidra_entries_for_path(path, ghidra_json)
    gl_entries = {int(function["entry_va"]) for function in facts["functions"]}
    gh_entries = {int(str(function["entry"]), 16) for function in ghidra_functions}
    missing = sorted(gh_entries - gl_entries)
    extra = sorted(gl_entries - gh_entries)
    seed_by_va = {
        int(function["entry_va"]): function.get("seed_kind")
        for function in facts.get("functions", [])
    }
    return {
        "path": str(path),
        "glaurung_functions": len(gl_entries),
        "ghidra_functions": len(gh_entries),
        "missing_count": len(missing),
        "extra_count": len(extra),
        "stats": _stats_summary(facts["stats"]),
        "missing": [
            _missing_diff_row(facts, ghidra_functions, va) for va in missing[:limit]
        ],
        "extra": [_extra_diff_row(facts, seed_by_va, va) for va in extra[:limit]],
    }


def _missing_diff_row(
    facts: dict[str, Any],
    ghidra_functions: list[dict[str, Any]],
    va: int,
) -> dict[str, Any]:
    explanation = explain_va_from_facts(facts, va)
    return {
        **explanation,
        "ghidra": next(
            (item for item in ghidra_functions if int(str(item["entry"]), 16) == va),
            {},
        ),
        "function_start_classification": _classification_summary(
            classify_function_start_from_facts(facts, va)
        ),
        "suspected_cause": _suspect_missing_cause(explanation),
    }


def _extra_diff_row(
    facts: dict[str, Any],
    seed_by_va: dict[int, Any],
    va: int,
) -> dict[str, Any]:
    explanation = explain_va_from_facts(facts, va)
    return {
        **explanation,
        "seed_kind": seed_by_va.get(va),
        "function_start_classification": _classification_summary(
            classify_function_start_from_facts(facts, va)
        ),
        "suspected_cause": _suspect_extra_cause(seed_by_va.get(va), explanation),
    }


def _classification_summary(classification: dict[str, Any]) -> dict[str, Any]:
    return {
        "state": classification.get("state"),
        "confidence": classification.get("confidence"),
        "recommended_action": classification.get("recommended_action"),
        "reason_codes": list(classification.get("reason_codes") or []),
        "is_function_entry": bool(classification.get("is_function_entry")),
        "is_code_label": bool(classification.get("is_code_label")),
        "seed_kind": classification.get("seed_kind"),
        "label_count": int(classification.get("label_count") or 0),
        "provenance_count": int(classification.get("provenance_count") or 0),
        "code_pointer_ref_count": int(
            classification.get("code_pointer_ref_count") or 0
        ),
    }


def _stats_summary(stats: dict[str, Any]) -> dict[str, Any]:
    omitted = {"function_seed_kinds", "seed_provenance", "code_labels"}
    return {key: value for key, value in stats.items() if key not in omitted}


def _suspect_missing_cause(explanation: dict[str, Any]) -> str:
    if explanation.get("code_pointer_refs"):
        return "data_ref_candidate_not_seeded"
    if explanation.get("containing_function"):
        return "inside_existing_function_or_label"
    if explanation.get("labels"):
        return "known_code_label_not_function"
    return "unseeded_function_start"


def _suspect_extra_cause(seed_kind: str | None, explanation: dict[str, Any]) -> str:
    if seed_kind == "data_ref":
        return "data_reference_promoted"
    if explanation.get("labels"):
        return "label_or_block_boundary_promoted"
    if seed_kind in {"direct_call", "indirect_call", "tail_call"}:
        return "xref_promoted"
    return "glaurung_only_start"


def run_fact_rules(
    path: str | Path,
    rules: Iterable[Callable[[dict[str, Any]], Any]],
    *,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_functions: int = DEFAULT_MAX_FUNCTIONS,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
) -> list[Any]:
    """Run Python callables over one structured Windows fact bundle."""

    facts = collect_windows_facts(
        path,
        max_read_bytes=max_read_bytes,
        max_file_size=max_file_size,
        max_functions=max_functions,
        max_blocks=max_blocks,
        max_instructions=max_instructions,
        timeout_ms=timeout_ms,
    )
    results: list[Any] = []
    for rule in rules:
        value = rule(facts)
        if value is None:
            continue
        if isinstance(value, list):
            results.extend(value)
        else:
            results.append(value)
    return results
