import hashlib
import json
from pathlib import Path

import glaurung as g


CORPUS = (
    Path(__file__).resolve().parents[2]
    / "samples"
    / "binaries"
    / "platforms"
    / "windows"
    / "vendor"
    / "realworld"
)


FUNCTION_COUNT_FLOORS = {
    "win10-vwififlt.sys": 120,
    "win10-audmigplugin.dll": 170,
    "win10-dismapi.dll": 3000,
    "win10-dismcore.dll": 700,
    "win10-webservices.dll": 3000,
    "win10-netsetupapi.dll": 450,
    "win10-wdscore.dll": 750,
    "win11-SyncInfrastructureps.dll": 65,
    "win11-acledit.dll": 35,
    "win11-dismapi.dll": 3500,
    "win11-webservices.dll": 3200,
    "win11-netsetupapi.dll": 450,
    "win11-wdscore.dll": 750,
    "win8-pciidex.sys": 150,
    "windows-update-keysink.exe": 400,
    "windows-update-SurfacePenBleLcAddrAdaptationDriver.sys": 700,
    "windows-update-intel-npu-ze_loader.dll": 1800,
    "windows-update-intel-npu-npu_level_zero_umd.dll": 3000,
    "windows-update-intel-npu-npu_d3d12_umd.dll": 2500,
    "windows-update-intel-ipf-ipfcore.dll": 2000,
    "windows-update-intel-audio-IntcSST.sys": 1300,
    "windows-update-intel-audio-MultiChannelWoV.dll": 1800,
    "windows-update-realtek-RtkApi64U.dll": 1500,
    "windows-update-realtek-RtkAudUService64.exe": 1600,
    "windows-update-amd-xilinx-xrt_core.dll": 3500,
    "windows-update-amd-xilinx-xrt_coreutil.dll": 7500,
    "windows-update-intel-wifi-NETwtw10.sys": 8000,
    "sqfs-amd-clinfo.exe": 650,
    "sqfs-intel-DptfParticipantDisplayService.exe": 280,
    "sqfs-intel-DptfDevGen.sys": 120,
}

THUNK_COUNT_FLOORS = {
    "win11-SyncInfrastructureps.dll": 40,
    "windows-update-SurfacePenBleLcAddrAdaptationDriver.sys": 45,
    "sqfs-amd-clinfo.exe": 20,
}

TINY_STUB_SEED_CEILINGS = {
    "windows-update-intel-npu-ze_loader.dll": 200,
    "windows-update-intel-npu-npu_level_zero_umd.dll": 300,
    "windows-update-intel-npu-npu_d3d12_umd.dll": 300,
    "windows-update-amd-xilinx-xrt_core.dll": 700,
    "windows-update-amd-xilinx-xrt_coreutil.dll": 1300,
}


def _fixtures():
    return json.loads((CORPUS / "MANIFEST.json").read_text(encoding="utf-8"))[
        "fixtures"
    ]


def test_realworld_windows_vendor_manifest_hashes():
    fixtures = _fixtures()

    assert len(fixtures) == 30
    assert {Path(row["file"]).suffix.lower() for row in fixtures} == {
        ".dll",
        ".exe",
        ".sys",
    }

    for row in fixtures:
        path = CORPUS / row["file"]
        data = path.read_bytes()
        assert data[:2] == b"MZ", f"{path} is missing PE bytes; is Git LFS hydrated?"
        assert len(data) == row["size_bytes"]
        assert hashlib.sha256(data).hexdigest() == row["sha256"]


def test_realworld_windows_vendor_corpus_triages_as_pe():
    for row in _fixtures():
        artifact = g.triage.analyze_path(
            str(CORPUS / row["file"]),
            max_read_bytes=16_000_000,
            max_file_size=16_000_000,
            max_depth=1,
        )
        assert artifact.verdicts, row["file"]
        verdict = artifact.verdicts[0]
        assert str(verdict.format) == "PE", row["file"]
        assert verdict.bits == 64, row["file"]


def test_realworld_windows_vendor_default_function_discovery_is_not_preview_capped():
    for row in _fixtures():
        funcs, _cg, stats = g.analysis.analyze_functions_path_with_stats(
            str(CORPUS / row["file"])
        )
        assert len(funcs) >= FUNCTION_COUNT_FLOORS[row["file"]], row["file"]
        assert len(funcs) != 16, row["file"]
        thunk_count = sum(1 for func in funcs if func.kind == g.FunctionKind.Thunk)
        tiny_le8 = sum(1 for func in funcs if func.total_size() <= 8)
        tiny_le32 = sum(1 for func in funcs if func.total_size() <= 32)
        assert stats["max_functions"] == 0, row["file"]
        assert stats["thunk_functions"] == thunk_count, row["file"]
        assert stats["tiny_functions_le8"] == tiny_le8, row["file"]
        assert stats["tiny_functions_le32"] == tiny_le32, row["file"]
        assert stats["pdata_entries"] >= stats["pdata_function_starts"], row["file"]
        assert stats["pdata_function_starts"] >= stats["pdata_seeds_inserted"], row[
            "file"
        ]
        assert stats["pdata_function_starts"] > 0, row["file"]
        assert stats["pdata_entries"] >= (
            stats["pdata_function_starts"]
            + stats["pdata_zero_begin_rejected"]
            + stats["pdata_zero_size_rejected"]
            + stats["pdata_chained_unwind_rejected"]
            + stats["pdata_nonexec_rejected"]
        ), row["file"]
        assert stats["pdata_chained_unwind_rejected"] == (
            stats["pdata_chained_unwind_parsed"]
            + stats["pdata_chained_unwind_parse_failed"]
        ), row["file"]
        assert stats["prologue_scan_candidates"] >= stats[
            "prologue_scan_seeds_inserted"
        ], row["file"]
        assert stats["thunk_scan_candidates"] >= stats["thunk_scan_seeds_inserted"], row[
            "file"
        ]
        assert stats["tiny_stub_scan_candidates"] >= stats[
            "tiny_stub_scan_seeds_inserted"
        ], row["file"]
        if row["file"] in TINY_STUB_SEED_CEILINGS:
            assert (
                stats["tiny_stub_scan_seeds_inserted"]
                <= TINY_STUB_SEED_CEILINGS[row["file"]]
            ), row["file"]
        assert stats["raw_call_target_candidates"] >= stats[
            "raw_call_target_seeds_inserted"
        ], row["file"]
        assert stats["raw_call_target_seeds_inserted"] >= stats[
            "raw_call_target_body_split_seeds_inserted"
        ], row["file"]
        assert stats["data_ref_code_pointer_candidates"] >= stats[
            "data_ref_code_pointer_seeds_inserted"
        ], row["file"]
        assert stats["data_ref_code_pointer_table_count"] >= 0, row["file"]
        assert stats["pdata_body_overlap_starts"] >= 0, row["file"]
        assert stats["code_label_count"] == len(stats["code_labels"]), row["file"]
        assert stats["code_label_count"] > 0, row["file"]
        assert stats["seed_kind_counts"], row["file"]
        assert len(stats["function_seed_kinds"]) == len(funcs), row["file"]
        assert stats["seed_provenance"], row["file"]
        assert stats["xref_seeds_added"] >= (
            stats["direct_call_seeds_added"]
            + stats["tail_call_seeds_added"]
            + stats["indirect_call_seeds_added"]
        ), row["file"]
        assert stats["direct_call_targets"] >= stats["direct_call_seeds_added"], row[
            "file"
        ]
        assert stats["tail_call_targets"] >= stats["tail_call_seeds_added"], row[
            "file"
        ]
        assert stats["indirect_call_targets"] >= stats[
            "indirect_call_seeds_added"
        ], row["file"]
        if row["file"] in THUNK_COUNT_FLOORS:
            assert thunk_count >= THUNK_COUNT_FLOORS[row["file"]], row["file"]
        if row["file"] == "windows-update-SurfacePenBleLcAddrAdaptationDriver.sys":
            assert stats["data_ref_code_pointer_seeds_inserted"] >= 8
            assert stats["seed_kind_counts"].get("data_ref", 0) >= 8
        assert stats["hit_function_limit"] is False, row["file"]
        assert stats["truncated"] is False, row["file"]


def test_realworld_windows_vendor_explicit_preview_budget_reports_truncation():
    row = next(item for item in _fixtures() if item["file"] == "sqfs-amd-clinfo.exe")

    funcs, _cg, stats = g.analysis.analyze_functions_path_with_stats(
        str(CORPUS / row["file"]),
        max_functions=16,
    )

    assert len(funcs) == 16
    assert stats["hit_function_limit"] is True
    assert stats["truncated"] is True
    assert stats["seeds_remaining"] > 0

    funcs, _cg, stats = g.analysis.analyze_functions_path_with_stats(
        str(CORPUS / row["file"]),
        max_functions=64,
    )
    assert len(funcs) == 64
    assert stats["hit_function_limit"] is True
    assert stats["truncated"] is True
    assert stats["seeds_remaining"] > 0

    funcs, _cg, stats = g.analysis.analyze_functions_path_with_stats(
        str(CORPUS / row["file"]),
        max_functions=4096,
    )
    assert len(funcs) >= FUNCTION_COUNT_FLOORS[row["file"]]
    assert stats["hit_function_limit"] is False
    assert stats["truncated"] is False
