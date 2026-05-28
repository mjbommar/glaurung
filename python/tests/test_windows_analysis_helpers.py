import json
from pathlib import Path

from glaurung import windows_analysis as wa


REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "samples/binaries/platforms/windows/vendor/realworld"
BASELINE = REPO / "docs/windows-port/glaurung_vs_ghidra_vendor_windows.json"
SURFACE_PEN = CORPUS / "windows-update-SurfacePenBleLcAddrAdaptationDriver.sys"


def test_windows_code_pointer_helpers_recover_rva_callback_table():
    pointers = wa.find_code_pointers(SURFACE_PEN)
    wanted = {
        0x1400074B0,
        0x1400074D0,
        0x14000C350,
        0x1400119C0,
        0x140012A90,
        0x14001CA60,
        0x14001CA70,
        0x14001E2B0,
    }
    hits = {item["target_va"] for item in pointers if item["target_va"] in wanted}

    assert hits == wanted
    assert all(
        item["slot_size"] == 4
        and item["section"] == ".rdata"
        and item["table_length"] >= 8
        and item["relocation_backed"] is False
        for item in pointers
        if item["target_va"] in wanted
    )
    assert sum(1 for item in pointers if item["relocation_backed"]) > 0


def test_windows_structured_fact_helpers_cover_seed_provenance_and_pdata():
    grouped = wa.functions_by_seed_kind(SURFACE_PEN)
    assert len(grouped["data_ref"]) >= 8
    assert len(grouped["trusted_pdata"]) > 500

    xrefs = wa.xrefs_to(SURFACE_PEN, 0x1400074B0)
    assert any(item["kind"] == "data_ref" for item in xrefs)
    assert any("slot4" in item["detail"] for item in xrefs)

    pdata = wa.pdata_at(SURFACE_PEN, 0x140006A30)
    assert pdata["is_pdata_start"] is True
    assert pdata["containing_pdata"][0]["begin"] == "0x140006a30"

    owner = wa.containing_function(SURFACE_PEN, 0x140006A30)
    assert owner is not None
    assert owner["entry"] == "0x140006a30"

    assert wa.bytes_at(SURFACE_PEN, 0x1400074B0, 4)["hex"] == "488b4c24"
    assert wa.disasm_at(SURFACE_PEN, 0x1400074B0, 2)[0]["mnemonic"] == "mov"


def test_windows_function_start_state_classifier_splits_functions_labels_candidates():
    facts = wa.collect_windows_facts(SURFACE_PEN)

    strict = wa.classify_function_start_from_facts(facts, 0x1400074B0)
    assert strict["state"] == "strict_function"
    assert strict["seed_kind"] == "data_ref"
    assert "function_entry" in strict["reason_codes"]
    assert "code_pointer_ref" in strict["reason_codes"]

    label_va = facts["code_labels"][0]["va"]
    label = wa.classify_function_start_from_facts(facts, label_va)
    assert label["state"] == "code_label"
    assert label["label_count"] >= 1
    assert "code_label" in label["reason_codes"]

    candidate = wa.classify_function_start_from_facts(facts, 0x1400074B1)
    assert candidate["state"] in {"candidate", "no_evidence", "rejected_start"}
    assert candidate["is_function_entry"] is False


def test_windows_driver_surface_and_rule_runner_use_structured_facts():
    surface = wa.map_windows_driver_surface(SURFACE_PEN)

    assert surface["is_driver"] is True
    assert surface["entrypoint"] == "0x140006a30"
    assert "WdfVersionBind" in surface["wdf_imports"]
    assert surface["dispatch_table_candidates"]

    results = wa.run_fact_rules(
        SURFACE_PEN,
        [
            lambda facts: {
                "data_ref_functions": len(
                    [
                        item
                        for item in facts["functions"]
                        if item["seed_kind"] == "data_ref"
                    ]
                ),
                "code_labels": len(facts["code_labels"]),
                "imports": len(facts["imports"]),
                "strings": len(facts["strings"]["strings"]),
                "prototypes": len(facts["winapi_prototypes"]),
                "relocations": len(facts["relocations"]),
                "nx": facts["hardening"]["nx_compat"],
            }
        ],
    )
    assert results[0]["data_ref_functions"] >= 8
    assert results[0]["code_labels"] > 1000
    assert results[0]["imports"] > 0
    assert results[0]["strings"] > 0
    assert results[0]["prototypes"] > 0
    assert results[0]["relocations"] > 0
    assert results[0]["nx"] is True

    facts = wa.collect_windows_facts(SURFACE_PEN)
    scan_rejections = facts["stats"]["scan_rejection_counts"]
    assert isinstance(scan_rejections, dict)
    assert scan_rejections["data_ref:weak_pointer"] > 0
    assert scan_rejections["body_overlap:tiny_stub"] > 0
    scan_rejection_records = facts["stats"]["scan_rejections"]
    assert any(
        item["reason"] == "data_ref:weak_pointer" and item["source_va"] is not None
        for item in scan_rejection_records
    )
    assert any(
        item["reason"] == "body_overlap:tiny_stub"
        and isinstance(item["va"], int)
        and item["detail"]
        for item in scan_rejection_records
    )
    assert facts["code_labels"][0]["name"].startswith(("LAB_", "EPILOGUE_"))
    assert facts["code_labels"][0]["provenance"]["detail"] == "cfg_basic_block_label"


def test_windows_diff_ghidra_report_and_cli_json(capsys):
    report = wa.diff_ghidra(SURFACE_PEN, BASELINE, limit=2)
    assert report["missing_count"] == 0
    assert report["extra_count"] == 0
    assert report["stats"]["data_ref_code_pointer_seeds_inserted"] >= 8
    assert "code_labels" not in report["stats"]

    from glaurung.cli.main import GlaurungCLI

    cli = GlaurungCLI()
    rc = cli.run(
        [
            "windows",
            "diff-ghidra",
            str(SURFACE_PEN),
            "--ghidra-json",
            str(BASELINE),
            "--limit",
            "2",
            "--format",
            "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["missing_count"] == 0
    assert payload["extra_count"] == 0
    assert payload["stats"]["seed_kind_counts"]["data_ref"] >= 8


def test_windows_diff_ghidra_rows_include_function_start_classification(tmp_path):
    facts = wa.collect_windows_facts(SURFACE_PEN)
    label_va = int(facts["code_labels"][0]["va"])
    ghidra_json = tmp_path / "ghidra-with-label.json"
    ghidra_json.write_text(
        json.dumps(
            {
                "file": SURFACE_PEN.name,
                "functions": [
                    {"entry": item["entry"], "name": item["name"]}
                    for item in facts["functions"]
                ]
                + [{"entry": f"0x{label_va:x}", "name": "ghidra_label_as_function"}],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    report = wa.diff_ghidra(SURFACE_PEN, ghidra_json, limit=1)

    assert report["missing_count"] == 1
    assert report["extra_count"] == 0
    classification = report["missing"][0]["function_start_classification"]
    assert classification["state"] == "code_label"
    assert classification["is_function_entry"] is False
    assert classification["is_code_label"] is True
    assert "code_label" in classification["reason_codes"]
