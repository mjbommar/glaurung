import json
import struct
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
BASELINE = (
    REPO / "docs" / "windows-port" / "glaurung_vs_ghidra_vendor_windows.json"
)
CORPUS_MANIFEST = (
    REPO
    / "samples"
    / "binaries"
    / "platforms"
    / "windows"
    / "vendor"
    / "realworld"
    / "MANIFEST.json"
)


def _pe_sections(data: bytes):
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
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
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, section + 8
        )
        sections.append(
            (
                virtual_address,
                max(virtual_size, raw_size),
                raw_pointer,
            )
        )
    return image_base, sections


def _pe_va_to_file_offset(data: bytes, va: int) -> int | None:
    image_base, sections = _pe_sections(data)
    rva = va - image_base
    for virtual_address, virtual_size, raw_pointer in sections:
        if virtual_address <= rva < virtual_address + virtual_size:
            return raw_pointer + (rva - virtual_address)
    return None


def _is_simd_continuation_head(head: bytes) -> bool:
    return (
        len(head) >= 2
        and head[0] == 0x0F
        and head[1] in {0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F}
    ) or bool(head and head[0] in {0xC4, 0xC5, 0x62})


def test_windows_ghidra_parity_baseline_tracks_real_corpus():
    rows = json.loads(BASELINE.read_text(encoding="utf-8"))
    manifest = json.loads(CORPUS_MANIFEST.read_text(encoding="utf-8"))
    manifest_files = {row["file"] for row in manifest["fixtures"]}

    assert len(rows) == 10
    assert {row["file"] for row in rows} <= manifest_files
    assert not any(str(row["path"]).startswith("/") for row in rows)
    assert not any(row["glaurung"]["stats"]["truncated"] for row in rows)
    assert all(
        len(row["ghidra"]["functions"])
        == row["ghidra"]["metrics"]["internal_functions"]
        for row in rows
    )
    assert all(row["ghidra"]["metrics"]["external_functions"] > 0 for row in rows)
    assert all(row["ghidra"]["metrics"]["instructions"] > 0 for row in rows)
    assert sum(row["ghidra"]["metrics"]["thunk_functions"] for row in rows) > 0
    assert sum(row["ghidra"]["metrics"]["le8_body_bytes"] for row in rows) > 0
    assert sum(row["ghidra"]["metrics"]["le32_body_bytes"] for row in rows) > 0

    glaurung_funcs = sum(row["glaurung"]["functions"] for row in rows)
    ghidra_internal = sum(row["ghidra"]["metrics"]["internal_functions"] for row in rows)
    assert glaurung_funcs / ghidra_internal >= 0.96

    glaurung_thunks = sum(
        row["glaurung"]["stats"]["thunk_functions"] for row in rows
    )
    ghidra_thunks = sum(row["ghidra"]["metrics"]["thunk_functions"] for row in rows)
    assert glaurung_thunks / ghidra_thunks >= 0.95

    assert sum(row["glaurung"]["stats"]["pdata_seeds_inserted"] for row in rows) > 0
    assert sum(row["glaurung"]["stats"]["pdata_entries"] for row in rows) >= sum(
        row["glaurung"]["stats"]["pdata_function_starts"] for row in rows
    )
    assert all(
        "pdata_zero_size_rejected" in row["glaurung"]["stats"] for row in rows
    )
    assert all(
        "pdata_overlapping_entries" in row["glaurung"]["stats"] for row in rows
    )
    assert sum(
        row["glaurung"]["stats"]["pdata_chained_unwind_parsed"] for row in rows
    ) > 0
    assert (
        sum(row["glaurung"]["stats"]["pdata_chained_unwind_parse_failed"] for row in rows)
        == 0
    )
    assert sum(row["glaurung"]["stats"]["tail_call_seeds_added"] for row in rows) > 0
    assert sum(row["glaurung"]["stats"]["indirect_call_targets"] for row in rows) > 0
    assert sum(
        row["glaurung"]["stats"]["tiny_stub_scan_seeds_inserted"] for row in rows
    ) > 0
    assert sum(
        row["glaurung"]["stats"]["raw_call_target_seeds_inserted"] for row in rows
    ) > 0
    assert sum(
        row["glaurung"]["stats"]["raw_call_target_body_split_seeds_inserted"]
        for row in rows
    ) > 0
    assert all(
        "data_ref_code_pointer_candidates" in row["glaurung"]["stats"] for row in rows
    )
    assert all("seed_kind_counts" in row["glaurung"]["stats"] for row in rows)
    assert all("code_label_count" in row["glaurung"]["stats"] for row in rows)
    assert sum(
        row["glaurung"]["stats"]["data_ref_code_pointer_candidates"] for row in rows
    ) > 0
    assert sum(
        row["glaurung"]["stats"]["data_ref_code_pointer_seeds_inserted"]
        for row in rows
    ) >= 8
    assert sum(row["glaurung"]["stats"]["code_label_count"] for row in rows) > 1000
    assert sum(row["address_gap"]["missing_entries"] for row in rows) < 10
    assert sum(row["address_gap"]["missing_le32"] for row in rows) > 0
    surface_pen = next(
        row
        for row in rows
        if row["file"] == "windows-update-SurfacePenBleLcAddrAdaptationDriver.sys"
    )
    assert surface_pen["address_gap"]["missing_entries"] == 0
    assert surface_pen["address_gap"]["extra_entries"] == 0
    assert surface_pen["glaurung"]["stats"]["seed_kind_counts"]["data_ref"] >= 8
    assert all("trend" in row for row in rows)


def test_windows_ghidra_parity_extra_entries_do_not_start_on_simd_continuations():
    rows = json.loads(BASELINE.read_text(encoding="utf-8"))

    for row in rows:
        data = (REPO / row["path"]).read_bytes()
        ghidra_entries = {
            str(function["entry"]).lower() for function in row["ghidra"]["functions"]
        }
        extra_entries = sorted(
            set(row["glaurung"]["entry_vas"]) - ghidra_entries,
            key=lambda entry: int(entry, 16),
        )
        for entry in extra_entries:
            file_offset = _pe_va_to_file_offset(data, int(entry, 16))
            assert file_offset is not None, (row["file"], entry)
            assert not _is_simd_continuation_head(data[file_offset : file_offset + 3]), (
                row["file"],
                entry,
            )
