from __future__ import annotations

import base64
import importlib.util
import hashlib
import json
import os
import signal
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "tools" / "runtime_sample_harness.py"
SPEC = importlib.util.spec_from_file_location("runtime_sample_harness", HARNESS_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


def test_runtime_corpus_has_balanced_real_sources() -> None:
    samples = HARNESS.load_samples()
    assert len(samples) == 60
    assert {sample.category for sample in samples} == {
        "normal",
        "crash",
        "memory_corruption",
        "dangerous",
    }
    for category in {sample.category for sample in samples}:
        assert sum(sample.category == category for sample in samples) == 15
    assert len({sample.source.read_bytes() for sample in samples}) == 60


def test_runtime_manifest_has_paired_outcome_oracles() -> None:
    for sample in HARNESS.load_samples():
        assert sample.good == "good"
        assert sample.bad == "bad"
        assert sample.expected_good == "exit:0"
        assert sample.expected_bad.startswith(("exit:", "signal:"))
        if sample.category == "crash":
            assert sample.expected_bad.startswith("signal:")


def test_semantic_oracles_cover_all_120_scenarios() -> None:
    samples = HARNESS.load_samples()
    oracles = HARNESS.load_semantic_oracles(samples=samples, require_complete=True)
    expected = {
        (sample.id, scenario) for sample in samples for scenario in ("good", "bad")
    }
    assert set(oracles) == expected
    for key, oracle in oracles.items():
        assert oracle.id == f"{key[0]}.{key[1]}"
        assert oracle.assertions
        assert all(assertion.independent_oracle for assertion in oracle.assertions)
        if key[1] == "good":
            assert any(assertion.kind == "negative" for assertion in oracle.assertions)


def test_semantic_oracle_process_outcomes_must_match_manifest(tmp_path: Path) -> None:
    text = HARNESS.SEMANTIC_ORACLES.read_text().replace(
        'process_outcome = "signal:SIGSEGV"',
        'process_outcome = "exit:0"',
        1,
    )
    path = tmp_path / "semantic-oracles.toml"
    path.write_text(text)
    with pytest.raises(ValueError, match="process outcome disagrees"):
        HARNESS.load_semantic_oracles(path, HARNESS.load_samples())


def semantic_result_for(
    oracle: Any, *, compiler: str = "gcc", opt: str = "O0", link: str = "pie"
) -> dict[str, Any]:
    assertions = HARNESS.assertions_for_lane(
        oracle, compiler=compiler, opt=opt, link=link
    )
    return {
        "schema": "glaurung-runtime-semantic-result-v1",
        "sample": oracle.sample,
        "scenario": oracle.scenario,
        "lane": {"compiler": compiler, "optimization": opt, "link": link},
        "facts": [
            {
                "kind": assertion.kind,
                "subject": assertion.subject,
                "predicate": assertion.predicate,
                "status": "observed",
                "value": assertion.expected,
            }
            for assertion in assertions
        ],
    }


def test_semantic_evaluator_keeps_lane_and_incompleteness_fail_closed() -> None:
    sample = next(
        item
        for item in HARNESS.load_samples()
        if item.id == "memory_struct_field_overwrite"
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, "bad")]
    gcc_result = semantic_result_for(oracle, compiler="gcc", opt="O2")
    assert HARNESS.evaluate_semantic_result(gcc_result, oracle)["passed"]

    gcc_result["lane"]["compiler"] = "clang"
    lane_evaluation = HARNESS.evaluate_semantic_result(gcc_result, oracle)
    assert not lane_evaluation["passed"]
    assert lane_evaluation["failures"]

    unavailable = semantic_result_for(oracle, compiler="gcc", opt="O2")
    unavailable["facts"][0] = {
        key: unavailable["facts"][0][key] for key in ("kind", "subject", "predicate")
    } | {"status": "unavailable", "reason": "capture omitted required bytes"}
    incomplete = HARNESS.evaluate_semantic_result(unavailable, oracle)
    assert not incomplete["passed"]
    assert incomplete["incomplete"][0]["status"] == "unavailable"

    inferred = semantic_result_for(oracle, compiler="gcc", opt="O2")
    inferred["facts"][0]["status"] = "inferred"
    assert HARNESS.evaluate_semantic_result(inferred, oracle)["passed"]


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_process_result_producer_is_oracle_independent_and_explicitly_partial(
    tmp_path: Path,
) -> None:
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "crash_null_read"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    record = HARNESS.run_one(binary, sample, "bad", 5.0)
    result = HARNESS.process_semantic_result(
        record, compiler="gcc", opt="O0", link="pie"
    )
    assert result["sample"] == sample.id
    assert (
        result["evidence"]["sha256"]
        == hashlib.sha256(HARNESS.canonical_json(record).encode()).hexdigest()
    )
    signal_fact = next(
        fact
        for fact in result["facts"]
        if (fact["kind"], fact["subject"], fact["predicate"])
        == ("terminal", "terminal_fault", "signal")
    )
    assert signal_fact["value"] == "SIGSEGV"
    access = next(
        fact
        for fact in result["facts"]
        if (fact["kind"], fact["subject"], fact["predicate"])
        == ("memory", "faulting_access", "access")
    )
    assert access["status"] == "unsupported"

    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, "bad")]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert not evaluation["passed"]
    assert evaluation["failures"] == []
    assert evaluation["matched"] == 1
    assert evaluation["incomplete"][0]["fact"] == (
        "memory",
        "faulting_access",
        "access",
    )


def test_analyzer_input_record_excludes_semantic_oracle() -> None:
    samples = HARNESS.load_samples()
    sample = next(sample for sample in samples if sample.id == "normal_open_file")
    record = HARNESS.analyzer_input_record(
        sample, "good", Path("/fixture/binary"), "abc123"
    )
    serialized = json.dumps(record, sort_keys=True)
    assert "oracle" not in serialized
    assert "expected" not in serialized
    assert record["scenario_argument"] == "good"


def test_matrix_ledger_is_canonical_and_hash_bound() -> None:
    sample = next(
        sample for sample in HARNESS.load_samples() if sample.id == "normal_open_file"
    )
    oracles = HARNESS.load_semantic_oracles(samples=[sample])
    record = {
        "sample": sample.id,
        "category": sample.category,
        "scenario": "good",
        "returncode": 0,
        "signal": None,
        "timed_out": False,
        "stdout": "RESULT open_ok 1\n",
        "stderr": "",
        "elapsed_ms": 91.3,
        "binary_sha256": "b" * 64,
    }
    ledger = HARNESS.make_matrix_ledger(
        entries=[
            HARNESS.ledger_entry(
                sample=sample,
                scenario="good",
                compiler="gcc",
                compiler_id="gcc fixture",
                opt="O2",
                link="pie",
                binary=Path("/ignored/build/normal_open_file"),
                record=record,
                semantic_oracle=oracles[(sample.id, "good")],
            )
        ],
        requested={"compilers": ["gcc"], "opts": ["O2"], "links": ["pie"]},
        process_manifest_sha256="m" * 64,
        oracle_sha256="o" * 64,
    )
    first = HARNESS.canonical_json(ledger)
    second = HARNESS.canonical_json(ledger)
    assert first == second
    assert "elapsed_ms" not in first
    assert "/ignored" not in first
    assert '"binary_sha256":"' + "b" * 64 + '"' in first
    assert '"process_manifest_sha256":"' + "m" * 64 + '"' in first
    assert '"semantic_oracle_sha256":"' + "o" * 64 + '"' in first


def test_environment_inventory_never_persists_plaintext_values() -> None:
    inventory = HARNESS.environment_inventory(b"TOKEN=secret-value\0EMPTY=\0")
    assert [entry["name"] for entry in inventory] == ["EMPTY", "TOKEN"]
    assert "secret-value" not in repr(inventory)
    assert inventory[1]["value_size"] == len("secret-value")


def test_process_capsule_binding_rejects_non_capsule_json() -> None:
    from glaurung import runtime_analysis

    with pytest.raises(ValueError, match="parse process capsule"):
        runtime_analysis.validate_process_capsule_json('{"schema":"wrong","version":1}')

    with pytest.raises(ValueError, match="parse ELF64 core"):
        runtime_analysis.import_elf_core(b"not a core", b"exact executable")


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_build_and_run_real_control_and_crash(tmp_path: Path) -> None:
    samples = {sample.id: sample for sample in HARNESS.load_samples()}
    normal = samples["normal_open_file"]
    crash = samples["crash_null_write"]
    normal_binary = HARNESS.compile_sample(normal, "gcc", "O2", "pie", tmp_path)
    crash_binary = HARNESS.compile_sample(crash, "gcc", "O2", "pie", tmp_path)
    good = HARNESS.run_one(normal_binary, normal, "good", 5.0)
    bad = HARNESS.run_one(crash_binary, crash, "bad", 5.0)
    assert HARNESS.observed_outcome(good) == normal.expected_good
    assert good["stdout"] == "RESULT open_ok 1\n"
    assert HARNESS.observed_outcome(bad) == crash.expected_bad


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_undefined_memory_sample_has_lane_specific_oracles(tmp_path: Path) -> None:
    sample = next(
        sample
        for sample in HARNESS.load_samples()
        if sample.id == "memory_struct_field_overwrite"
    )
    unoptimized = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    optimized = HARNESS.compile_sample(sample, "gcc", "O2", "pie", tmp_path)
    o0_bad = HARNESS.run_one(unoptimized, sample, "bad", 5.0)
    o2_bad = HARNESS.run_one(optimized, sample, "bad", 5.0)
    assert o0_bad["stdout"] == "RESULT canary 287454122\n"
    assert o2_bad["stdout"] == "RESULT canary 287454020\n"
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, "bad")]
    assert {
        selector for assertion in oracle.assertions for selector in assertion.applies_to
    } == {
        "opt:O0",
        "compiler:clang,opt:O2",
        "compiler:gcc,opt:O2",
    }
    gcc_o2 = HARNESS.assertions_for_lane(oracle, compiler="gcc", opt="O2", link="pie")
    clang_o2 = HARNESS.assertions_for_lane(
        oracle, compiler="clang", opt="O2", link="pie"
    )
    assert [assertion.predicate for assertion in gcc_o2] == ["materialized_write"]
    assert [assertion.predicate for assertion in clang_o2] == [
        "changed_interval",
        "bounds_violation",
    ]


@pytest.mark.skipif(
    not Path("/proc/self/maps").exists(), reason="requires Linux procfs"
)
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_live_capture_records_real_proc_metadata(tmp_path: Path) -> None:
    sample = next(
        sample
        for sample in HARNESS.load_samples()
        if sample.id == "normal_heap_lifecycle"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = HARNESS.capture_live(binary, sample, "bad", tmp_path, 5.0)
    assert (capture / "manifest.json").is_file()
    assert (capture / "maps").read_text()
    assert (capture / "status").read_text()
    capsule_path = capture / "process-capsule.json"
    capsule_text = capsule_path.read_text()
    capsule = json.loads(capsule_text)
    assert capsule["schema"] == "glaurung-process-capsule-v1"
    assert capsule["executable"]["sha256"] == HARNESS.sha256(binary)
    assert capsule["provenance"]["input_bytes"] == [
        {
            "name": "argv[1]",
            "sha256": hashlib.sha256(b"bad").hexdigest(),
            "byte_len": 3,
            "sensitivity": "public",
        }
    ]
    artifact_hashes = {
        artifact["sha256"] for artifact in capsule["provenance"]["input_artifacts"]
    }
    assert capsule["executable"]["sha256"] in artifact_hashes
    manifest = json.loads((capture / "manifest.json").read_text())
    assert {record["sha256"] for record in manifest["files"].values()}.issubset(
        artifact_hashes
    )
    assert capsule["modules"][0]["mapping_ids"]
    assert capsule["pages"] == []
    assert (
        next(
            item for item in capsule["completeness"] if item["evidence"] == "registers"
        )["status"]
        == "unsupported"
    )
    from glaurung import runtime_analysis

    assert (
        runtime_analysis.canonicalize_process_capsule_json(capsule_text) == capsule_text
    )
    assert not (capture / ".process-capsule.json.part").exists()

    victim = tmp_path / "must-not-change"
    victim.write_text("original")
    (capture / ".process-capsule.json.part").symlink_to(victim)
    with pytest.raises(FileExistsError):
        HARNESS.publish_process_capsule(capture, capsule)
    assert victim.read_text() == "original"


@pytest.mark.skipif(
    not Path("/proc/self/maps").exists(), reason="requires Linux procfs"
)
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_product_capture_owns_and_redacts_stopped_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from glaurung.runtime_capture import (
        capture_stopped_child,
        stable_live_capture_projection,
    )

    sample = next(
        sample
        for sample in HARNESS.load_samples()
        if sample.id == "normal_heap_lifecycle"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    environment = HARNESS.fixture_environment(sample)
    environment["GLAURUNG_RUNTIME_CHECKPOINT"] = "1"
    capture = capture_stopped_child(
        binary,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=environment,
        cwd=binary.parent,
        checkpoint="exit",
        public_input=b"bad",
    )
    capsule = json.loads(capture.capsule_json)
    assert capsule["identity"]["acquisition"] == "live"
    assert capsule["executable"]["sha256"] == HARNESS.sha256(binary)
    assert capsule["executable"]["build_id"]
    main_module = next(
        module for module in capsule["modules"] if module["id"] == "module-main"
    )
    assert capsule["executable"]["build_id"] == main_module["artifact"]["build_id"]
    assert len(capsule["modules"]) >= 3
    assert all(module["artifact"]["sha256"] for module in capsule["modules"])
    assert all(module["artifact"]["build_id"] for module in capsule["modules"])
    module_hashes = {module["artifact"]["sha256"] for module in capsule["modules"]}
    provenance_hashes = {
        artifact["sha256"] for artifact in capsule["provenance"]["input_artifacts"]
    }
    assert module_hashes <= provenance_hashes
    assert {
        mapping["backing"]["artifact_sha256"]
        for mapping in capsule["mappings"]
        if mapping["backing"]["kind"] == "file"
    } == module_hashes
    assert capsule["processes"][0]["terminal"] == {"kind": "running"}
    assert capsule["modules"][0]["mapping_ids"]
    assert capsule["threads"]
    assert all(len(thread["registers"]) == 27 for thread in capsule["threads"])
    assert all(
        {register["provider_name"] for register in thread["registers"]}
        >= {"rip", "rsp", "rbp"}
        for thread in capsule["threads"]
    )
    assert capsule["pages"]
    payloads = dict(capture.payloads)
    assert len(payloads) == len(capsule["pages"])
    for page in capsule["pages"]:
        reference = page["content"]["payload"]
        data = payloads[reference["id"]]
        assert len(data) == page["byte_len"] == reference["byte_len"]
        assert hashlib.sha256(data).hexdigest() == reference["sha256"]
    assert all(
        descriptor["redacted"] and "target" not in descriptor
        for descriptor in capsule["descriptors"]
    )
    completeness = {item["evidence"]: item for item in capsule["completeness"]}
    assert completeness["mappings"]["status"] == "complete"
    assert completeness["threads"]["status"] == "complete"
    assert completeness["module_backings"]["status"] == "complete"
    assert completeness["module_backings"]["obtained"] == len(capsule["modules"])
    assert completeness["registers"]["status"] == "complete"
    assert completeness["registers"]["obtained"] == 27 * len(capsule["threads"])
    assert completeness["pages"]["status"] == "complete"
    assert completeness["pages"]["obtained"] == len(capsule["pages"])
    outcomes = capsule["provider.procfs"]["acquisition_outcomes"]
    assert set(outcomes) == {
        "proc_files",
        "registers",
        "pages",
        "module_backings",
        "mapping_revalidation",
        "thread_revalidation",
        "descriptors",
    }
    assert outcomes["mapping_revalidation"]["status"] == "complete"
    assert (
        outcomes["mapping_revalidation"]["before_sha256"]
        == outcomes["mapping_revalidation"]["after_sha256"]
    )
    assert outcomes["thread_revalidation"] == {
        "status": "complete",
        "disappeared_tids": [],
        "appeared_tids": [],
    }
    assert all(item["status"] == "captured" for item in outcomes["registers"].values())
    assert all(item["status"] == "captured" for item in outcomes["pages"].values())
    assert all(
        item["status"] == "captured" for item in outcomes["module_backings"].values()
    )
    assert all(
        item.get("prior_attempt_status") in {None, "denied"}
        for item in outcomes["module_backings"].values()
    )
    from glaurung import runtime_analysis

    identities = json.loads(
        runtime_analysis.process_capsule_runtime_identities(
            capture.capsule_json, "process-main"
        )
    )
    assert identities["capture_id"] == capsule["identity"]["capture_id"]
    assert len(identities["modules"]) == len(capsule["modules"])
    assert len(identities["mappings"]) == len(capsule["mappings"])
    assert any(
        mapping["module_id"] is None
        and mapping["backing"]["kind"] in {"anonymous", "special"}
        for mapping in identities["mappings"]
    )
    with pytest.raises(ValueError, match="no process"):
        runtime_analysis.process_capsule_runtime_identities(
            capture.capsule_json, "missing-process"
        )
    classified_pages = json.loads(
        runtime_analysis.classify_process_capsule_pages(
            capture.capsule_json,
            list(capture.payloads),
            binary.read_bytes(),
            "process-main",
        )
    )
    assert len(classified_pages) == len(capsule["pages"])
    assert any(
        page["kind"]["kind"] == "file_backed_unchanged" for page in classified_pages
    )
    assert all(
        page["kind"]["kind"] in {"file_backed_unchanged", "anonymous", "unknown"}
        for page in classified_pages
    )
    assert not Path(f"/proc/{capsule['processes'][0]['os_pid']}").exists()

    repeated = capture_stopped_child(
        binary,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=environment,
        cwd=binary.parent,
        checkpoint="exit",
        public_input=b"bad",
    )
    assert repeated.capsule_json != capture.capsule_json
    assert stable_live_capture_projection(
        repeated.capsule_json
    ) == stable_live_capture_projection(capture.capsule_json)

    from glaurung.llm.kb.models import Node, NodeKind
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase
    from glaurung.llm.kb.runtime_relations import (
        analyze_and_persist_crash,
        compare_runtime_captures_json,
        list_runtime_analysis_reports,
        list_runtime_captures,
        list_runtime_descriptors,
        list_runtime_events,
        list_runtime_mappings,
        list_runtime_modules,
        list_runtime_object_snapshots,
        list_runtime_objects,
        list_runtime_outputs,
        list_runtime_pages,
        list_runtime_processes,
        list_runtime_runs,
        list_runtime_threads,
        load_process_capsule,
        persist_process_capsule,
        runtime_capture_summary_json,
    )

    database = tmp_path / "runtime-identities.glaurung"
    with PersistentKnowledgeBase.open(database, binary_path=binary) as kb:
        manual = Node(kind=NodeKind.note, label="manual evidence", text="keep me")
        kb.add_node(manual)
        with pytest.raises(ValueError, match="missing referenced IDs"):
            persist_process_capsule(kb, capture.capsule_json)
        referenced_payload_id = next(
            page["content"]["payload"]["id"]
            for page in capsule["pages"]
            if page["content"]["status"] == "captured"
        )
        tampered_payloads = [
            (payload_id, b"tampered" if payload_id == referenced_payload_id else data)
            for payload_id, data in capture.payloads
        ]
        with pytest.raises(ValueError, match="disagrees with its reference"):
            persist_process_capsule(kb, capture.capsule_json, tampered_payloads)
        first = persist_process_capsule(
            kb, capture.capsule_json, list(capture.payloads)
        )
        repeated_first = persist_process_capsule(
            kb, capture.capsule_json, list(capture.payloads)
        )
        second = persist_process_capsule(
            kb, repeated.capsule_json, list(repeated.payloads)
        )
        assert repeated_first.capture_pk == first.capture_pk
        assert first.capture_id != second.capture_id
        assert first.run_id == first.capture_id
        assert second.run_id == second.capture_id
        assert len(list_runtime_runs(kb)) == 2
        assert [item.capture_id for item in list_runtime_captures(kb)] == sorted(
            [first.capture_id, second.capture_id]
        )
        persisted_processes = list_runtime_processes(kb, first.capture_id)
        assert [item.process_id for item in persisted_processes] == sorted(
            item["id"] for item in capsule["processes"]
        )
        assert {
            item.process_id: (item.os_pid, item.parent_process_id, item.terminal)
            for item in persisted_processes
        } == {
            item["id"]: (
                item["os_pid"],
                item.get("parent_id"),
                item.get("terminal"),
            )
            for item in capsule["processes"]
        }
        persisted_modules = {
            item.module_id: item for item in list_runtime_modules(kb, first.capture_id)
        }
        assert set(persisted_modules) == {item["id"] for item in capsule["modules"]}
        for module in capsule["modules"]:
            persisted = persisted_modules[module["id"]]
            assert persisted.process_id == module["process_id"]
            assert persisted.artifact == module["artifact"]
            assert persisted.load_bias == module.get("load_bias")
            assert persisted.mapping_ids == module["mapping_ids"]
        persisted_mappings = {
            item.mapping_id: item
            for item in list_runtime_mappings(kb, first.capture_id)
        }
        assert set(persisted_mappings) == {item["id"] for item in capsule["mappings"]}
        for mapping in capsule["mappings"]:
            persisted = persisted_mappings[mapping["id"]]
            assert persisted.process_id == mapping["process_id"]
            assert (persisted.start_va, persisted.end_va) == (
                mapping["start"],
                mapping["end"],
            )
            assert persisted.permissions == mapping["permissions"]
            assert persisted.backing == mapping["backing"]
            assert persisted.module_id == mapping.get("module_id")
            assert persisted.file_offset == mapping.get("file_offset")
        persisted_threads = {
            item.thread_id: item for item in list_runtime_threads(kb, first.capture_id)
        }
        assert set(persisted_threads) == {item["id"] for item in capsule["threads"]}
        for thread in capsule["threads"]:
            persisted = persisted_threads[thread["id"]]
            assert persisted.process_id == thread["process_id"]
            assert persisted.os_tid == thread["os_tid"]
            assert persisted.registers == thread["registers"]
            assert persisted.fault == thread.get("fault")
        persisted_events = list_runtime_events(kb, first.capture_id)
        assert {
            (
                item.process_id,
                item.thread_id,
                item.sequence,
                item.kind,
                item.address,
                tuple(sorted(item.fields.items())),
            )
            for item in persisted_events
        } == {
            (
                item["process_id"],
                item.get("thread_id"),
                item["sequence"],
                item["kind"],
                item.get("address"),
                tuple(sorted(item["fields"].items())),
            )
            for item in capsule["events"]
        }
        assert sorted(
            list_runtime_pages(kb, first.capture_id),
            key=lambda item: HARNESS.canonical_json(item),
        ) == sorted(capsule["pages"], key=lambda item: HARNESS.canonical_json(item))
        assert sorted(
            list_runtime_objects(kb, first.capture_id),
            key=lambda item: HARNESS.canonical_json(item),
        ) == sorted(
            capsule["runtime_objects"],
            key=lambda item: HARNESS.canonical_json(item),
        )
        assert sorted(
            list_runtime_object_snapshots(kb, first.capture_id),
            key=lambda item: HARNESS.canonical_json(item),
        ) == sorted(
            capsule["object_snapshots"],
            key=lambda item: HARNESS.canonical_json(item),
        )
        assert sorted(
            list_runtime_outputs(kb, first.capture_id),
            key=lambda item: HARNESS.canonical_json(item),
        ) == sorted(capsule["outputs"], key=lambda item: HARNESS.canonical_json(item))
        assert sorted(
            list_runtime_descriptors(kb, first.capture_id),
            key=lambda item: HARNESS.canonical_json(item),
        ) == sorted(
            capsule["descriptors"], key=lambda item: HARNESS.canonical_json(item)
        )
        persisted_report = analyze_and_persist_crash(
            kb, first.capture_id, binary.read_bytes()
        )
        second_report = analyze_and_persist_crash(
            kb, second.capture_id, binary.read_bytes()
        )
        assert second_report.report_schema == persisted_report.report_schema
        repeated_report = analyze_and_persist_crash(
            kb, first.capture_id, binary.read_bytes()
        )
        assert repeated_report == persisted_report
        assert persisted_report.report_schema == ("glaurung-runtime-crash-analysis-v1")
        assert json.loads(persisted_report.report_json) == {
            "outcome": "no_crash",
            "process_id": "process-main",
        }
        with pytest.raises(ValueError, match="executable bytes disagree"):
            analyze_and_persist_crash(kb, first.capture_id, b"not the executable")
        persisted_summary = runtime_capture_summary_json(kb, first.capture_id)
        summary = json.loads(persisted_summary)
        assert summary["schema"] == "glaurung-runtime-project-summary-v1"
        assert summary["capture"]["capture_id"] == first.capture_id
        assert summary["counts"]["analysis_reports"] == 1
        assert summary["analysis_reports"] == [
            {
                "analyzer": "runtime-crash",
                "schema": "glaurung-runtime-crash-analysis-v1",
                "sha256": persisted_report.report_sha256,
                "outcome": "no_crash",
            }
        ]
        assert summary["observed_operations"] == []
        assert '"registers":[' not in persisted_summary
        assert '"record_json"' not in persisted_summary
        assert '"start_va"' not in persisted_summary
        assert '"captured_at"' not in persisted_summary
        from glaurung.llm.tools.runtime_project_summary import (
            build_tool as build_runtime_project_summary,
        )

        runtime_tool = build_runtime_project_summary()
        ignored_context: Any = None
        ignored_kb: Any = None
        tool_result = runtime_tool.run(
            ignored_context,
            ignored_kb,
            runtime_tool.input_model(
                project_path=str(database), capture_id=first.capture_id
            ),
        )
        assert tool_result.summary_schema == summary["schema"]
        assert tool_result.capture_id == first.capture_id
        assert tool_result.summary == summary
        repeated_comparison = json.loads(
            compare_runtime_captures_json(kb, first.capture_id, second.capture_id)
        )
        assert repeated_comparison["same_executable"] is True
        assert set(repeated_comparison["count_delta_right_minus_left"].values()) == {0}
        assert set(
            repeated_comparison["event_kind_delta_right_minus_left"].values()
        ) <= {0}
        assert (
            repeated_comparison["analysis_outcomes"]["left"]
            == (repeated_comparison["analysis_outcomes"]["right"])
        )
        assert repeated_comparison["observed_static_operations"] == {
            "common": [],
            "left_only": [],
            "right_only": [],
        }
        assert kb.get_node(manual.id) == manual
        runtime_tables = {
            "runtime_runs",
            "runtime_captures",
            "runtime_payloads",
            "runtime_processes",
            "runtime_modules",
            "runtime_mappings",
            "runtime_threads",
            "runtime_events",
            "runtime_pages",
            "runtime_objects",
            "runtime_object_snapshots",
            "runtime_outputs",
            "runtime_descriptors",
            "runtime_operation_occurrences",
            "runtime_operation_occurrence_evidence",
            "runtime_analysis_reports",
            "runtime_address_relations",
        }
        for table in runtime_tables:
            columns = {
                row[1] for row in kb._conn.execute(f"PRAGMA table_info({table})")
            }
            assert "set_by" not in columns
            foreign_tables = {
                row[2] for row in kb._conn.execute(f"PRAGMA foreign_key_list({table})")
            }
            assert foreign_tables <= runtime_tables

        rollback_capsule = json.loads(capture.capsule_json)
        rollback_capsule["identity"]["capture_id"] = "capture-rollback-fixture"
        from glaurung.llm.kb import runtime_relations

        def fail_identity_graph(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("injected identity graph failure")

        with monkeypatch.context() as patch:
            patch.setattr(
                runtime_relations,
                "_persist_runtime_identity_graph",
                fail_identity_graph,
            )
            with pytest.raises(RuntimeError, match="injected identity graph failure"):
                persist_process_capsule(
                    kb,
                    HARNESS.canonical_json(rollback_capsule),
                    list(capture.payloads),
                    run_id="run-rollback-fixture",
                )
        assert not any(
            item.run_id == "run-rollback-fixture" for item in list_runtime_runs(kb)
        )
        assert not any(
            item.capture_id == "capture-rollback-fixture"
            for item in list_runtime_captures(kb)
        )

        conflicting = json.loads(capture.capsule_json)
        conflicting["identity"]["captured_at"] = "2000-01-01T00:00:00Z"
        with pytest.raises(
            ValueError,
            match="capture identity already names different persisted evidence",
        ):
            persist_process_capsule(
                kb, HARNESS.canonical_json(conflicting), list(capture.payloads)
            )

    with PersistentKnowledgeBase.open(database, binary_path=binary) as reopened:
        assert reopened.get_node(manual.id) == manual
        assert len(list_runtime_runs(reopened)) == 2
        assert len(list_runtime_captures(reopened)) == 2
        assert len(list_runtime_processes(reopened, first.capture_id)) == len(
            capsule["processes"]
        )
        assert len(list_runtime_modules(reopened, first.capture_id)) == len(
            capsule["modules"]
        )
        assert len(list_runtime_mappings(reopened, first.capture_id)) == len(
            capsule["mappings"]
        )
        assert len(list_runtime_threads(reopened, first.capture_id)) == len(
            capsule["threads"]
        )
        assert len(list_runtime_events(reopened, first.capture_id)) == len(
            capsule["events"]
        )
        assert len(list_runtime_pages(reopened, first.capture_id)) == len(
            capsule["pages"]
        )
        assert len(list_runtime_objects(reopened, first.capture_id)) == len(
            capsule["runtime_objects"]
        )
        assert len(list_runtime_object_snapshots(reopened, first.capture_id)) == len(
            capsule["object_snapshots"]
        )
        assert len(list_runtime_outputs(reopened, first.capture_id)) == len(
            capsule["outputs"]
        )
        assert len(list_runtime_descriptors(reopened, first.capture_id)) == len(
            capsule["descriptors"]
        )
        assert list_runtime_analysis_reports(reopened, capture_id=first.capture_id) == [
            persisted_report
        ]
        assert runtime_capture_summary_json(reopened, first.capture_id) == (
            persisted_summary
        )
        loaded_capsule, loaded_payloads = load_process_capsule(
            reopened, first.capture_id
        )
        assert loaded_capsule == capture.capsule_json
        assert loaded_payloads == sorted(capture.payloads)
        reclassified_pages = json.loads(
            runtime_analysis.classify_process_capsule_pages(
                loaded_capsule,
                loaded_payloads,
                binary.read_bytes(),
                "process-main",
            )
        )
        assert reclassified_pages == classified_pages


@pytest.mark.skipif(
    not Path("/proc/self/maps").exists(), reason="requires Linux procfs"
)
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_product_capture_reads_every_stopped_thread_register_set(
    tmp_path: Path,
) -> None:
    from glaurung.runtime_capture import capture_stopped_child

    source = ROOT / "tests/runtime_samples/support/stopped_threads.c"
    binary = tmp_path / "stopped_threads"
    subprocess.run(
        ["gcc", "-std=c11", "-pthread", str(source), "-o", str(binary)],
        check=True,
    )
    capture = capture_stopped_child(binary)
    capsule = json.loads(capture.capsule_json)
    assert len(capsule["threads"]) == 2
    assert all(len(thread["registers"]) == 27 for thread in capsule["threads"])
    assert capsule["pages"]
    assert len(capture.payloads) == len(capsule["pages"])
    completeness = next(
        item for item in capsule["completeness"] if item["evidence"] == "registers"
    )
    assert completeness == {
        "evidence": "registers",
        "status": "complete",
        "requested": True,
        "obtained": 54,
        "expected": 54,
    }


@pytest.mark.skipif(
    not Path("/proc/self/maps").exists(), reason="requires Linux procfs"
)
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_runtime_cli_reads_only_persisted_redacted_contracts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from glaurung.cli.main import main as cli_main
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase
    from glaurung.llm.kb.runtime_relations import (
        analyze_and_persist_crash,
        compare_runtime_captures_json,
        persist_process_capsule,
        runtime_capture_summary_json,
        runtime_crash_explanation_json,
        runtime_evidence_packet_json,
    )
    from glaurung.runtime_capture import capture_stopped_child

    source = ROOT / "tests/runtime_samples/support/stopped_threads.c"
    binary = tmp_path / "stopped_threads"
    subprocess.run(
        ["gcc", "-std=c11", "-pthread", str(source), "-o", str(binary)],
        check=True,
    )
    monkeypatch.setenv("GLAURUNG_TEST_CAPTURE_SECRET", "must-not-reach-child")
    captured_database = tmp_path / "runtime-cli-captured.glaurung"
    assert (
        cli_main(
            [
                "runtime",
                "--json",
                "capture",
                "--timeout",
                "10",
                "--run-id",
                "run-cli-capture",
                "--env",
                "GLAURUNG_TEST_CAPTURE_ALLOWED=yes",
                str(captured_database),
                str(binary),
                "--",
                "require-env",
            ]
        )
        == 0
    )
    captured_summary_text = capsys.readouterr().out
    captured_summary = json.loads(captured_summary_text)
    assert captured_summary["schema"] == "glaurung-runtime-project-summary-v1"
    assert captured_summary["capture"]["run_id"] == "run-cli-capture"
    assert captured_summary["capture"]["acquisition"] == "live"
    with PersistentKnowledgeBase.open(captured_database) as captured_project:
        assert (
            runtime_capture_summary_json(
                captured_project, captured_summary["capture"]["capture_id"]
            )
            == captured_summary_text
        )
    assert (
        cli_main(
            [
                "runtime",
                "capture",
                "--env",
                "missing-separator",
                str(tmp_path / "must-not-exist.glaurung"),
                str(binary),
            ]
        )
        == 1
    )
    assert "--env must be a non-empty NAME=VALUE" in capsys.readouterr().err
    assert not (tmp_path / "must-not-exist.glaurung").exists()
    monkeypatch.delenv("GLAURUNG_TEST_CAPTURE_SECRET")
    capture = capture_stopped_child(binary)
    metadata = tmp_path / "process-capsule.json"
    metadata.write_text(capture.capsule_json)
    payload_directory = tmp_path / "payloads"
    payload_directory.mkdir()
    for payload_id, data in capture.payloads:
        (payload_directory / f"{payload_id}.bin").write_bytes(data)
    database = tmp_path / "runtime-cli.glaurung"
    with PersistentKnowledgeBase.open(database, binary_path=binary) as kb:
        persisted = persist_process_capsule(
            kb, capture.capsule_json, list(capture.payloads)
        )
        expected_import_summary = runtime_capture_summary_json(kb, persisted.capture_id)
        expected_crash = analyze_and_persist_crash(
            kb, persisted.capture_id, binary.read_bytes()
        ).report_json
        assert (
            runtime_crash_explanation_json(kb, persisted.capture_id) == expected_crash
        )
        expected_summary = runtime_capture_summary_json(kb, persisted.capture_id)
        expected_evidence = runtime_evidence_packet_json(kb, persisted.capture_id)
        expected_sensitive_evidence = runtime_evidence_packet_json(
            kb, persisted.capture_id, include_sensitive=True
        )
        sensitive_evidence = json.loads(expected_sensitive_evidence)
        assert sensitive_evidence["export_policy"] == "include_sensitive"
        assert sensitive_evidence["capsule"]["document"] == json.loads(
            capture.capsule_json
        )
        assert {
            item["id"]: item["data_base64"] for item in sensitive_evidence["payloads"]
        } == {
            payload_id: base64.b64encode(data).decode("ascii")
            for payload_id, data in capture.payloads
        }
        expected_comparison = compare_runtime_captures_json(
            kb, persisted.capture_id, persisted.capture_id
        )

    imported_database = tmp_path / "runtime-cli-imported.glaurung"
    assert (
        cli_main(
            [
                "runtime",
                "--json",
                "import",
                str(imported_database),
                str(metadata),
                str(payload_directory),
                "--binary",
                str(binary),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == expected_import_summary

    assert (
        cli_main(
            [
                "runtime",
                "--json",
                "crash",
                str(database),
                persisted.capture_id,
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == expected_crash + "\n"

    assert cli_main(["runtime", "crash", str(database), persisted.capture_id]) == 0
    crash_text = capsys.readouterr().out
    assert "Glaurung runtime crash analysis" in crash_text
    assert "Outcome: no crash" in crash_text
    assert "Process: process-main" in crash_text

    assert (
        cli_main(
            [
                "runtime",
                "--json",
                "summary",
                str(database),
                persisted.capture_id,
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == expected_summary

    assert (
        cli_main(
            [
                "runtime",
                "--json",
                "evidence",
                str(database),
                persisted.capture_id,
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == expected_evidence
    redacted_evidence = json.loads(expected_evidence)
    assert redacted_evidence["schema"] == "glaurung-runtime-evidence-packet-v1"
    assert redacted_evidence["export_policy"] == "redacted"
    assert redacted_evidence["capsule"]["included"] is False
    assert all(item["included"] is False for item in redacted_evidence["payloads"])
    assert all(
        item["document_included"] is False
        for item in redacted_evidence["analysis_reports"]
    )
    assert '"registers":[' not in expected_evidence
    assert '"data_base64"' not in expected_evidence

    assert (
        cli_main(
            [
                "runtime",
                "--json",
                "evidence",
                str(database),
                persisted.capture_id,
                "--include-sensitive",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == expected_sensitive_evidence

    assert (
        cli_main(
            [
                "runtime",
                "--json",
                "observed-xrefs",
                str(database),
                persisted.capture_id,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == []

    assert (
        cli_main(
            [
                "runtime",
                "--json",
                "compare",
                str(database),
                persisted.capture_id,
                persisted.capture_id,
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == expected_comparison

    with PersistentKnowledgeBase.open(imported_database) as imported:
        with pytest.raises(KeyError, match="no persisted runtime crash analysis"):
            runtime_crash_explanation_json(imported, persisted.capture_id)

    with PersistentKnowledgeBase.open(database) as corrupted:
        corrupted._conn.execute(
            "UPDATE runtime_analysis_reports SET report_sha256 = ? "
            "WHERE binary_id = ? AND capture_id = ? AND analyzer = 'runtime-crash'",
            ("0" * 64, corrupted.binary_id, persisted.capture_id),
        )
        with pytest.raises(ValueError, match="hash mismatch"):
            runtime_crash_explanation_json(corrupted, persisted.capture_id)
        with pytest.raises(ValueError, match="analysis report.*hash mismatch"):
            runtime_evidence_packet_json(corrupted, persisted.capture_id)
        corrupted._conn.execute(
            "UPDATE runtime_analysis_reports SET report_sha256 = ? "
            "WHERE binary_id = ? AND capture_id = ? AND analyzer = 'runtime-crash'",
            (
                hashlib.sha256(expected_crash.encode()).hexdigest(),
                corrupted.binary_id,
                persisted.capture_id,
            ),
        )
        corrupted._conn.execute(
            "UPDATE runtime_analysis_reports SET report_schema = ? "
            "WHERE binary_id = ? AND capture_id = ? AND analyzer = 'runtime-crash'",
            ("tampered-schema", corrupted.binary_id, persisted.capture_id),
        )
        with pytest.raises(ValueError, match="schema disagrees"):
            runtime_evidence_packet_json(corrupted, persisted.capture_id)
        corrupted._conn.execute(
            "UPDATE runtime_analysis_reports SET report_schema = ? "
            "WHERE binary_id = ? AND capture_id = ? AND analyzer = 'runtime-crash'",
            (
                "glaurung-runtime-crash-analysis-v1",
                corrupted.binary_id,
                persisted.capture_id,
            ),
        )
        corrupted._conn.execute(
            "UPDATE runtime_captures SET capsule_sha256 = ? "
            "WHERE binary_id = ? AND capture_id = ?",
            ("0" * 64, corrupted.binary_id, persisted.capture_id),
        )
        with pytest.raises(ValueError, match="process capsule hash mismatch"):
            runtime_evidence_packet_json(corrupted, persisted.capture_id)
        corrupted._conn.execute(
            "UPDATE runtime_captures SET capsule_sha256 = ? "
            "WHERE binary_id = ? AND capture_id = ?",
            (
                hashlib.sha256(capture.capsule_json.encode()).hexdigest(),
                corrupted.binary_id,
                persisted.capture_id,
            ),
        )
        corrupted._conn.commit()


@pytest.mark.slow
@pytest.mark.skipif(
    not Path("/proc/self/maps").exists(), reason="requires Linux procfs"
)
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_product_live_capture_covers_runtime_corpus_population(
    tmp_path: Path,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_stopped_child

    failures: list[str] = []
    attempts = 0
    for sample in HARNESS.load_samples():
        binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
        for scenario in ("good", "bad"):
            for checkpoint in (
                ("entry",) if sample.category == "crash" else ("entry", "exit")
            ):
                environment = HARNESS.fixture_environment(sample)
                variable = (
                    "GLAURUNG_RUNTIME_CHECKPOINT_ENTRY"
                    if checkpoint == "entry"
                    else "GLAURUNG_RUNTIME_CHECKPOINT"
                )
                environment[variable] = "1"
                attempts += 1
                try:
                    capture = capture_stopped_child(
                        binary,
                        [HARNESS.scenario_arg(sample, scenario)],
                        environment=environment,
                        cwd=binary.parent,
                        checkpoint=checkpoint,
                        public_input=scenario.encode(),
                    )
                    capsule = json.loads(capture.capsule_json)
                    assert (
                        runtime_analysis.canonicalize_process_capsule_json(
                            capture.capsule_json
                        )
                        == capture.capsule_json
                    )
                    assert capsule["threads"]
                    assert capsule["pages"]
                    assert capture.payloads
                except Exception as error:  # noqa: BLE001 - population ledger
                    failures.append(
                        f"{sample.id}.{scenario}.{checkpoint}: "
                        f"{type(error).__name__}: {error}"
                    )
    assert attempts == 210
    assert not failures, "\n".join(failures)


@pytest.mark.skipif(
    not Path("/proc/self/maps").exists(), reason="requires Linux procfs"
)
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_entry_capture_can_stop_a_crashing_scenario(tmp_path: Path) -> None:
    sample = next(
        sample for sample in HARNESS.load_samples() if sample.id == "crash_null_write"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O2", "pie", tmp_path)
    capture = HARNESS.capture_live(binary, sample, "bad", tmp_path, 5.0, "entry")
    assert (capture / "manifest.json").is_file()
    assert "crash_null_write" in (capture / "cmdline").read_text()


@pytest.mark.skipif(
    not Path("/proc/self/maps").exists(), reason="requires Linux procfs"
)
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_live_and_core_capsules_agree_on_stable_identity(tmp_path: Path) -> None:
    sample = next(
        sample for sample in HARNESS.load_samples() if sample.id == "crash_null_write"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    live_capture = HARNESS.capture_live(binary, sample, "bad", tmp_path, 5.0, "entry")
    core_capture = HARNESS.capture_core(binary, sample, "bad", tmp_path, 5.0)
    core_manifest = json.loads((core_capture / "manifest.json").read_text())
    if not core_manifest["core_captured"]:
        pytest.skip(core_manifest["core_absence_reason"])

    live = json.loads((live_capture / "process-capsule.json").read_text())
    core = json.loads((core_capture / "process-capsule.json").read_text())
    for capsule in (live, core):
        assert capsule["target"] == {
            "architecture": "X86_64",
            "endianness": "Little",
            "address_bits": 64,
            "os_abi": "linux",
        }
        assert capsule["executable"]["sha256"] == HARNESS.sha256(binary)
        assert capsule["executable"]["byte_len"] == binary.stat().st_size
        assert capsule["executable"]["build_id"]
        assert capsule["modules"][0]["artifact"]["sha256"] == HARNESS.sha256(binary)
        assert capsule["provenance"]["input_bytes"][0]["sha256"] == (
            hashlib.sha256(b"bad").hexdigest()
        )

    assert live["identity"]["acquisition"] == "live"
    assert live["processes"][0]["terminal"] == {"kind": "running"}
    assert core["identity"]["acquisition"] == "core"
    assert core["processes"][0]["terminal"]["kind"] == "signaled"
    assert live["executable"]["build_id"] == core["executable"]["build_id"]


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_real_null_write_core_imports_to_canonical_capsule(tmp_path: Path) -> None:
    sample = next(
        sample for sample in HARNESS.load_samples() if sample.id == "crash_null_write"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = HARNESS.capture_core(binary, sample, "bad", tmp_path, 5.0)
    manifest = json.loads((capture / "manifest.json").read_text())
    if not manifest["core_captured"]:
        pytest.skip(manifest["core_absence_reason"])
    capsule_text = (capture / "process-capsule.json").read_text()
    capsule = json.loads(capsule_text)
    assert capsule["processes"][0]["terminal"] == {
        "kind": "signaled",
        "signal": signal.SIGSEGV,
        "core_dumped": True,
    }
    assert len(capsule["threads"]) == 1
    assert capsule["threads"][0]["fault"]["address"] == 0
    assert capsule["threads"][0]["fault"]["signal"] == signal.SIGSEGV
    assert (
        next(
            register
            for register in capsule["threads"][0]["registers"]
            if register["provider_name"] == "rip"
        )["value_hex"]
        != "0000000000000000"
    )
    assert len(capsule["modules"]) == 1
    assert len(capsule["modules"][0]["mapping_ids"]) == 5
    assert capsule["modules"][0]["artifact"]["build_id"]
    assert capsule["provenance"]["input_bytes"] == [
        {
            "name": "argv[1]",
            "sha256": hashlib.sha256(b"bad").hexdigest(),
            "byte_len": len(b"bad"),
            "sensitivity": "public",
        }
    ]
    provenance_artifacts = capsule["provenance"]["input_artifacts"]
    assert {artifact["sha256"] for artifact in provenance_artifacts} == {
        HARNESS.sha256(binary),
        manifest["core_files"][0]["sha256"],
    }
    payload_directory = capture / manifest["process_capsule"]["payload_directory"]
    payloads = list(payload_directory.glob("*.bin"))
    assert len(payloads) == manifest["process_capsule"]["payload_count"]
    assert payloads
    expected_payloads = {
        page["content"]["payload"]["id"]: page["content"]["payload"]
        for page in capsule["pages"]
        if page["content"]["status"] == "captured"
    }
    expected_payloads.update(
        {output["payload"]["id"]: output["payload"] for output in capsule["outputs"]}
    )
    assert set(expected_payloads) == {payload.stem for payload in payloads}
    for payload in payloads:
        reference = expected_payloads[payload.stem]
        data = payload.read_bytes()
        assert payload.stat().st_mode & 0o777 == 0o600
        assert len(data) == reference["byte_len"]
        assert hashlib.sha256(data).hexdigest() == reference["sha256"]

    from glaurung import runtime_analysis

    canonical, imported_count = runtime_analysis.import_process_capsule_bundle(
        str(capture / "process-capsule.json"), str(payload_directory)
    )
    assert canonical == capsule_text
    assert imported_count == len(payloads)

    rip = int(
        next(
            register["value_hex"]
            for register in capsule["threads"][0]["registers"]
            if register["provider_name"] == "rip"
        ),
        16,
    )
    payload_bytes = [(payload.stem, payload.read_bytes()) for payload in payloads]
    resolution = json.loads(
        runtime_analysis.resolve_process_capsule_address(
            capsule_text,
            payload_bytes,
            binary.read_bytes(),
            capsule["processes"][0]["id"],
            rip,
        )
    )
    assert resolution["verdict"] == "exact"
    assert resolution["address"]["runtime"]["raw_va"] == rip
    assert resolution["address"]["image_sha256"] == HARNESS.sha256(binary)
    # This host omits clean file-backed code from the core. Correlation proves
    # the address relation but does not silently substitute executable bytes.
    assert resolution["address"]["byte_status"] == {
        "status": "omitted",
        "reason": "provider_unsupported",
        "detail": "PT_LOAD memory range has no bytes in the core file",
    }

    crash_report = json.loads(
        runtime_analysis.analyze_process_capsule_crash(
            capsule_text, payload_bytes, binary.read_bytes()
        )
    )
    assert crash_report["outcome"] == "crash"
    report = crash_report["report"]
    assert report["schema"] == "glaurung-runtime-crash-report-v1"
    assert report["process_id"] == capsule["processes"][0]["id"]
    assert report["thread_id"] == capsule["threads"][0]["id"]
    assert report["signal"] == signal.SIGSEGV
    assert report["pc"] == {
        "status": "observed",
        "value": rip,
        "source": "thread register rip",
    }
    assert report["sp"]["status"] == "observed"
    assert report["fault_address"]["value"] == 0
    assert report["access"] == {
        "status": "inferred",
        "value": "write",
        "source": "exact static LLIR operation",
    }
    assert report["class"]["value"] == "null_write"
    assert report["fault_mapping"] == {
        "status": "unknown",
        "reason": "fault address is unmapped",
    }
    assert report["static_location"]["value"]["verdict"] == "exact"

    rendered = runtime_analysis.render_process_capsule_crash(
        capsule_text, payload_bytes, binary.read_bytes()
    )
    assert rendered.startswith("Glaurung runtime crash analysis\nOutcome: crash\n")
    assert "Class: inferred null_write" in rendered
    assert "Access: inferred write" in rendered
    assert "Location: " in rendered and "!main block " in rendered
    assert "Sensitive bytes: redacted; use typed JSON explicitly" in rendered
    observed_windows = [
        window["bytes_hex"]["value"]
        for window in report["memory_windows"]
        if window["bytes_hex"]["status"] == "observed"
    ]
    assert observed_windows
    assert all(window_bytes not in rendered for window_bytes in observed_windows)

    wrong_sample = next(
        item for item in HARNESS.load_samples() if item.id == "crash_null_read"
    )
    wrong_binary = HARNESS.compile_sample(wrong_sample, "gcc", "O0", "pie", tmp_path)
    wrong = json.loads(
        runtime_analysis.resolve_process_capsule_address(
            capsule_text,
            payload_bytes,
            wrong_binary.read_bytes(),
            capsule["processes"][0]["id"],
            rip,
        )
    )
    assert wrong["verdict"] == "wrong_image"

    selected = payloads[0]
    original = selected.read_bytes()
    selected.write_bytes(original[:-1])
    with pytest.raises(ValueError, match="length"):
        runtime_analysis.import_process_capsule_bundle(
            str(capture / "process-capsule.json"), str(payload_directory)
        )
    selected.write_bytes(bytes([original[0] ^ 0xFF]) + original[1:])
    with pytest.raises(ValueError, match="SHA-256"):
        runtime_analysis.import_process_capsule_bundle(
            str(capture / "process-capsule.json"), str(payload_directory)
        )
    selected.write_bytes(original)

    extra = payload_directory / "unreferenced.bin"
    extra.write_bytes(b"not referenced")
    with pytest.raises(ValueError, match="payload set"):
        runtime_analysis.import_process_capsule_bundle(
            str(capture / "process-capsule.json"), str(payload_directory)
        )
    extra.unlink()

    backup = tmp_path / selected.name
    selected.rename(backup)
    selected.symlink_to(backup)
    with pytest.raises(ValueError, match="non-symlink regular file"):
        runtime_analysis.import_process_capsule_bundle(
            str(capture / "process-capsule.json"), str(payload_directory)
        )
    selected.unlink()
    backup.rename(selected)

    tampered = json.loads(capsule_text)
    captured_page = next(
        page for page in tampered["pages"] if page["content"]["status"] == "captured"
    )
    captured_page["content"]["payload"]["id"] = "../escape"
    tampered_path = capture / "traversal-capsule.json"
    tampered_path.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="unsafe capsule payload id"):
        runtime_analysis.import_process_capsule_bundle(
            str(tampered_path), str(payload_directory)
        )

    metadata_link = capture / "capsule-link.json"
    metadata_link.symlink_to(capture / "process-capsule.json")
    with pytest.raises(ValueError, match="non-symlink regular file"):
        runtime_analysis.import_process_capsule_bundle(
            str(metadata_link), str(payload_directory)
        )

    directory_link = capture / "payload-directory-link"
    directory_link.symlink_to(payload_directory, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink directory"):
        runtime_analysis.import_process_capsule_bundle(
            str(capture / "process-capsule.json"), str(directory_link)
        )


@pytest.mark.slow
@pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("clang") is None,
    reason="GCC and Clang are required for the correlation matrix",
)
def test_null_write_core_pc_correlates_across_build_matrix(tmp_path: Path) -> None:
    """Prove exact PIE/non-PIE PC normalization across split ELF mappings."""
    samples = {sample.id: sample for sample in HARNESS.load_samples()}
    sample = samples["crash_null_write"]
    wrong_sample = samples["crash_null_read"]
    captures: list[tuple[str, str, str, Path, Path, dict[str, Any]]] = []
    missing: list[str] = []

    for compiler in ("gcc", "clang"):
        for opt in ("O0", "O2"):
            for link in ("pie", "no-pie"):
                lane = f"{compiler}-{opt}-{link}"
                binary = HARNESS.compile_sample(sample, compiler, opt, link, tmp_path)
                capture = HARNESS.capture_core(binary, sample, "bad", tmp_path, 10.0)
                manifest = json.loads((capture / "manifest.json").read_text())
                if not manifest["core_captured"]:
                    missing.append(lane)
                    continue
                captures.append((compiler, opt, link, binary, capture, manifest))

    if not captures:
        pytest.skip("host core policy suppressed every build-matrix core")
    assert not missing, f"host produced some but not all matrix cores: {missing}"
    assert len(captures) == 8

    from glaurung import runtime_analysis
    from glaurung.llm.kb import xref_db
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase
    from glaurung.llm.kb.runtime_relations import (
        analyze_and_persist_crash,
        compare_runtime_summaries_json,
        list_address_relations,
        list_runtime_analysis_reports,
        persist_process_capsule,
        resolve_and_persist_address,
        runtime_capture_summary_json,
        runtime_crash_explanation_json,
        runtime_evidence_packet_json,
    )

    build_summaries: dict[tuple[str, str, str], str] = {}
    for compiler, opt, link, binary, capture, manifest in captures:
        capsule_text = (capture / "process-capsule.json").read_text()
        capsule = json.loads(capsule_text)
        faulting = [thread for thread in capsule["threads"] if "fault" in thread]
        assert len(faulting) == 1
        rip = int(
            next(
                register["value_hex"]
                for register in faulting[0]["registers"]
                if register["provider_name"] == "rip"
            ),
            16,
        )
        payload_directory = capture / manifest["process_capsule"]["payload_directory"]
        payloads = [
            (payload.stem, payload.read_bytes())
            for payload in sorted(payload_directory.glob("*.bin"))
        ]
        resolution = json.loads(
            runtime_analysis.resolve_process_capsule_address(
                capsule_text,
                payloads,
                binary.read_bytes(),
                capsule["processes"][0]["id"],
                rip,
            )
        )
        assert resolution["verdict"] == "exact"
        address = resolution["address"]
        assert address["runtime"]["raw_va"] == rip
        assert address["image_sha256"] == HARNESS.sha256(binary)
        assert address["function"]["verdict"] in {"exact", "interior"}
        assert address["function"]["name"] == "main"
        assert (
            address["function"]["entry_va"]
            <= address["static_va"]
            < address["function"]["end_va"]
        )
        assert address["code"]["verdict"] == "resolved"
        assert address["code"]["instruction_relation"] == "exact"
        assert (
            address["code"]["block_start"]
            <= address["code"]["instruction_va"]
            == address["static_va"]
            < address["code"]["instruction_end"]
            <= address["code"]["block_end"]
        )
        assert address["code"]["operations"]["verdict"] == "resolved"
        assert "store" in {
            operation["kind"]
            for operation in address["code"]["operations"]["operations"]
        }
        for operation in address["code"]["operations"]["operations"]:
            assert operation["image_sha256"] == address["image_sha256"]
            assert operation["function_entry"] == address["function"]["entry_va"]
            assert operation["machine_va"] == address["static_va"]
            assert operation["lift_profile"] == "glaurung-raw-llir-v1"

        crash = json.loads(
            runtime_analysis.analyze_process_capsule_crash(
                capsule_text, payloads, binary.read_bytes()
            )
        )
        assert crash["outcome"] == "crash"
        report = crash["report"]
        assert report["pc"]["value"] == rip
        assert report["sp"]["status"] == "observed"
        assert report["registers"]["status"] == "observed"
        assert {
            register["provider_name"] for register in report["registers"]["value"]
        } >= {
            "rip",
            "rsp",
        }
        assert [window["role"] for window in report["memory_windows"]] == [
            "program_counter",
            "stack_pointer",
            "fault_address",
        ]
        assert all(window["requested_len"] == 32 for window in report["memory_windows"])
        stack_window = report["memory_windows"][1]
        assert stack_window["anchor"]["value"] == report["sp"]["value"]
        assert stack_window["bytes_hex"]["status"] == "observed"
        assert len(stack_window["bytes_hex"]["value"]) == 64
        assert report["native_stack"]["status"] == "inferred"
        assert report["native_stack"]["value"]["frames"][0] == {
            "index": 0,
            "pc": rip,
            "frame_pointer": int(
                next(
                    register["value_hex"]
                    for register in report["registers"]["value"]
                    if register["provider_name"] == "rbp"
                ),
                16,
            ),
            "return_slot": None,
            "confidence": "observed_program_counter",
            "location": report["location"],
        }
        assert len(report["native_stack"]["value"]["frames"]) <= 32
        assert report["fault_address"]["value"] == 0
        assert report["access"] == {
            "status": "inferred",
            "value": "write",
            "source": "exact static LLIR operation",
        }
        assert report["class"]["value"] == "null_write"
        assert report["location"]["status"] == "inferred"
        assert report["location"]["value"] == {
            "module_id": address["runtime"]["module_id"],
            "mapping_id": address["runtime"]["mapping_id"],
            "runtime_va": rip,
            "image_sha256": address["image_sha256"],
            "static_va": address["static_va"],
            "function_entry": address["function"]["entry_va"],
            "function_name": "main",
            "block_start": address["code"]["block_start"],
            "instruction_va": address["code"]["instruction_va"],
            "instruction_end": address["code"]["instruction_end"],
            "mnemonic": address["code"]["mnemonic"],
        }
        assert report["static_location"]["value"]["verdict"] == "exact"
        if link == "pie":
            assert address["static_va"] == address["module_relative"]
            assert address["static_va"] != rip
        else:
            assert address["static_va"] == rip
            assert address["module_relative"] < address["static_va"]

        project_path = tmp_path / f"{compiler}-{opt}-{link}.glaurung"
        with PersistentKnowledgeBase.open(project_path, binary_path=binary) as kb:
            persisted_capture = persist_process_capsule(kb, capsule_text, payloads)
            persisted_crash = analyze_and_persist_crash(
                kb, persisted_capture.capture_id, binary.read_bytes()
            )
            assert json.loads(persisted_crash.report_json) == crash
            assert persisted_crash.report_schema == ("glaurung-runtime-crash-report-v1")
            assert (
                runtime_crash_explanation_json(kb, persisted_capture.capture_id)
                == persisted_crash.report_json
            )
            if (compiler, opt, link) == ("gcc", "O0", "pie"):
                packet = json.loads(
                    runtime_evidence_packet_json(
                        kb, persisted_capture.capture_id, include_sensitive=True
                    )
                )
                exported_payloads = {
                    item["id"]: base64.b64decode(item["data_base64"])
                    for item in packet["payloads"]
                }
                assert exported_payloads == dict(payloads)
                payload_id, payload_data = payloads[0]
                kb._conn.execute(
                    "UPDATE runtime_payloads SET data = ? WHERE binary_id = ? "
                    "AND capture_id = ? AND payload_id = ?",
                    (
                        payload_data + b"tampered",
                        kb.binary_id,
                        persisted_capture.capture_id,
                        payload_id,
                    ),
                )
                with pytest.raises(ValueError, match="payload.*hash mismatch"):
                    runtime_evidence_packet_json(kb, persisted_capture.capture_id)
                kb._conn.execute(
                    "UPDATE runtime_payloads SET data = ? WHERE binary_id = ? "
                    "AND capture_id = ? AND payload_id = ?",
                    (
                        payload_data,
                        kb.binary_id,
                        persisted_capture.capture_id,
                        payload_id,
                    ),
                )
                kb._conn.commit()
            build_summaries[(compiler, opt, link)] = runtime_capture_summary_json(
                kb, persisted_capture.capture_id
            )
            xref_db.set_comment(
                kb, address["static_va"], "analyst-owned", set_by="manual"
            )
            persisted = resolve_and_persist_address(
                kb,
                capsule_text,
                payloads,
                binary.read_bytes(),
                capsule["processes"][0]["id"],
                rip,
            )
            repeated = resolve_and_persist_address(
                kb,
                capsule_text,
                payloads,
                binary.read_bytes(),
                capsule["processes"][0]["id"],
                rip,
            )
            assert repeated.relation_id == persisted.relation_id
            assert persisted.capture_id == capsule["identity"]["capture_id"]
            assert persisted.process_id == capsule["processes"][0]["id"]
            assert persisted.raw_va == rip
            assert persisted.static_va == address["static_va"]
            assert persisted.module_relative == address["module_relative"]
            assert persisted.runtime_file_offset == address["runtime_file_offset"]
            assert persisted.function == address["function"]
            assert persisted.code == address["code"]
            assert persisted.claim_kind == "inferred"
            assert len(list_address_relations(kb)) == 1
            assert xref_db.get_comment(kb, address["static_va"]) == "analyst-owned"

        reopened = PersistentKnowledgeBase.open(project_path, binary_path=binary)
        try:
            rows = list_address_relations(
                reopened,
                capture_id=capsule["identity"]["capture_id"],
                static_va=address["static_va"],
            )
            assert rows == [persisted]
            assert list_runtime_analysis_reports(
                reopened, capture_id=capsule["identity"]["capture_id"]
            ) == [persisted_crash]
        finally:
            reopened.close()

        if (compiler, opt, link) == ("gcc", "O0", "pie"):
            repeat_capture = HARNESS.capture_core(
                binary, sample, "bad", tmp_path / "repeat", 10.0
            )
            repeat_manifest = json.loads((repeat_capture / "manifest.json").read_text())
            assert repeat_manifest["core_captured"]
            repeat_capsule_text = (repeat_capture / "process-capsule.json").read_text()
            repeat_capsule = json.loads(repeat_capsule_text)
            repeat_faulting = [
                thread for thread in repeat_capsule["threads"] if "fault" in thread
            ]
            assert len(repeat_faulting) == 1
            repeat_rip = int(
                next(
                    register["value_hex"]
                    for register in repeat_faulting[0]["registers"]
                    if register["provider_name"] == "rip"
                ),
                16,
            )
            repeat_payload_directory = (
                repeat_capture / repeat_manifest["process_capsule"]["payload_directory"]
            )
            repeat_payloads = [
                (payload.stem, payload.read_bytes())
                for payload in sorted(repeat_payload_directory.glob("*.bin"))
            ]
            with PersistentKnowledgeBase.open(project_path, binary_path=binary) as kb:
                repeat_relation = resolve_and_persist_address(
                    kb,
                    repeat_capsule_text,
                    repeat_payloads,
                    binary.read_bytes(),
                    repeat_capsule["processes"][0]["id"],
                    repeat_rip,
                )
                both_runs = list_address_relations(kb, static_va=address["static_va"])
                assert len(both_runs) == 2
                assert {row.capture_id for row in both_runs} == {
                    persisted.capture_id,
                    repeat_relation.capture_id,
                }
                assert {row.static_va for row in both_runs} == {address["static_va"]}
                assert repeat_relation.raw_va == repeat_rip
                assert repeat_relation.capture_id != persisted.capture_id

        wrong_binary = HARNESS.compile_sample(
            wrong_sample, compiler, opt, link, tmp_path
        )
        wrong = json.loads(
            runtime_analysis.resolve_process_capsule_address(
                capsule_text,
                payloads,
                wrong_binary.read_bytes(),
                capsule["processes"][0]["id"],
                rip,
            )
        )
        assert wrong["verdict"] == "wrong_image"

        wrong_project_path = tmp_path / f"wrong-{compiler}-{opt}-{link}.glaurung"
        with PersistentKnowledgeBase.open(
            wrong_project_path, binary_path=wrong_binary
        ) as wrong_kb:
            with pytest.raises(
                ValueError, match="image identity disagrees with project binary"
            ):
                resolve_and_persist_address(
                    wrong_kb,
                    capsule_text,
                    payloads,
                    binary.read_bytes(),
                    capsule["processes"][0]["id"],
                    rip,
                )

    build_comparison = json.loads(
        compare_runtime_summaries_json(
            build_summaries[("gcc", "O0", "pie")],
            build_summaries[("gcc", "O2", "pie")],
        )
    )
    assert build_comparison["same_executable"] is False
    assert set(build_comparison["analysis_outcomes"]["left"].values()) == {"crash"}
    assert set(build_comparison["analysis_outcomes"]["right"].values()) == {"crash"}
    assert build_comparison["limits"][-1] == (
        "cross-build operation alignment requires a stable cross-build identity"
    )


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_real_threaded_core_attaches_fault_to_worker(tmp_path: Path) -> None:
    sample = HARNESS.Sample(
        id="threaded_worker_fault",
        category="crash",
        source=ROOT
        / "tests"
        / "runtime_samples"
        / "support"
        / "threaded_worker_fault.c",
        good="good",
        bad="bad",
        expected_good="exit:0",
        expected_bad="signal:SIGSEGV",
        cflags=("-pthread",),
        ldflags=("-pthread",),
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = HARNESS.capture_core(binary, sample, "bad", tmp_path, 5.0)
    manifest = json.loads((capture / "manifest.json").read_text())
    if not manifest["core_captured"]:
        pytest.skip(manifest["core_absence_reason"])
    capsule = json.loads((capture / "process-capsule.json").read_text())
    assert len(capsule["threads"]) == 2
    faulting = [thread for thread in capsule["threads"] if "fault" in thread]
    assert len(faulting) == 1
    assert faulting[0]["fault"]["signal"] == signal.SIGSEGV
    assert faulting[0]["fault"]["address"] == 0
    assert faulting[0]["os_tid"] != capsule["processes"][0]["os_pid"]
    assert all(
        "fault" not in thread
        for thread in capsule["threads"]
        if thread["id"] != faulting[0]["id"]
    )
    assert not any(
        "faulting thread is ambiguous" in warning
        for warning in capsule["provenance"]["warnings"]
    )


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_all_good_crash_controls_produce_terminal_capsules_without_crash(
    tmp_path: Path,
) -> None:
    samples = [
        sample for sample in HARNESS.load_samples() if sample.category == "crash"
    ]
    assert len(samples) == 15
    from glaurung import runtime_analysis

    for sample in samples:
        binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
        record = HARNESS.run_one(binary, sample, "good", 5.0)
        assert HARNESS.observed_outcome(record) == "exit:0"
        invocation = HARNESS.scenario_arg(sample, "good").encode()
        capsule_text, payloads = HARNESS.terminal_process_capsule(
            binary, record, invocation
        )
        capsule = json.loads(capsule_text)
        assert capsule["processes"][0]["terminal"] == {
            "kind": "exited",
            "code": 0,
        }
        assert len(capsule["outputs"]) == 2
        analyzed = json.loads(
            runtime_analysis.analyze_process_capsule_crash(
                capsule_text, payloads, binary.read_bytes()
            )
        )
        assert analyzed == {
            "outcome": "no_crash",
            "process_id": "process-main",
        }


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_all_bad_crash_cores_import_with_expected_signal(tmp_path: Path) -> None:
    samples = [
        sample for sample in HARNESS.load_samples() if sample.category == "crash"
    ]
    assert len(samples) == 15
    captures: list[
        tuple[HARNESS.Sample, Path, Path, dict[str, Any], dict[str, Any]]
    ] = []
    missing: list[str] = []
    for sample in samples:
        binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
        capture = HARNESS.capture_core(binary, sample, "bad", tmp_path, 10.0)
        manifest = json.loads((capture / "manifest.json").read_text())
        if not manifest["core_captured"]:
            missing.append(sample.id)
            continue
        capsule = json.loads((capture / "process-capsule.json").read_text())
        captures.append((sample, binary, capture, manifest, capsule))
    if not captures:
        pytest.skip("host core policy suppressed every crash core")
    assert not missing, f"host produced some but not all requested cores: {missing}"
    from glaurung import runtime_analysis

    evidence_class = {
        "crash_abort": "explicit_abort",
        "crash_null_read": "null_read",
        "crash_null_write": "null_write",
        "crash_guard_read": "read_protection_fault",
        "crash_guard_write": "write_protection_fault",
        "crash_readonly_write": "write_protection_fault",
        "crash_execute_nonexec": "execute_protection_fault",
        "crash_bad_function_pointer": "invalid_control_target",
        "crash_stack_overflow": "recursive_stack_exhaustion",
        "crash_trap": "deliberate_signal:SIGTRAP",
        "crash_raise_segv": "deliberate_signal:SIGSEGV",
        "crash_raise_bus": "deliberate_signal:SIGBUS",
        "crash_raise_fpe": "deliberate_signal:SIGFPE",
        "crash_raise_ill": "deliberate_signal:SIGILL",
        "crash_assert": "assertion_failure",
    }

    for sample, binary, capture, manifest, capsule in captures:
        expected_name = sample.expected_bad.removeprefix("signal:")
        expected_signal = signal.Signals[expected_name].value
        assert manifest["signal"] == expected_signal
        assert capsule["processes"][0]["terminal"]["signal"] == expected_signal
        assert len(capsule["modules"]) == 1
        faulting = [thread for thread in capsule["threads"] if "fault" in thread]
        assert len(faulting) == 1
        assert faulting[0]["fault"]["signal"] == expected_signal
        payload_directory = capture / manifest["process_capsule"]["payload_directory"]
        payloads = [
            (payload.stem, payload.read_bytes())
            for payload in sorted(payload_directory.glob("*.bin"))
        ]
        analyzed = json.loads(
            runtime_analysis.analyze_process_capsule_crash(
                json.dumps(capsule), payloads, binary.read_bytes()
            )
        )
        assert analyzed["outcome"] == "crash"
        report = analyzed["report"]
        assert report["process_id"] == capsule["processes"][0]["id"]
        assert report["thread_id"] == faulting[0]["id"]
        assert report["signal"] == expected_signal
        assert report["signal_code"]["status"] == "observed"
        assert report["stdout"]["status"] == "observed"
        assert report["stderr"]["status"] == "observed"
        assert report["pc"]["status"] == "observed"
        assert report["sp"]["status"] == "observed"
        assert report["registers"]["status"] == "observed"
        assert len(report["memory_windows"]) == 3
        assert all(window["requested_len"] == 32 for window in report["memory_windows"])
        assert report["native_stack"]["status"] == "inferred"
        frames = report["native_stack"]["value"]["frames"]
        assert 1 <= len(frames) <= 32
        assert frames[0]["pc"] == report["pc"]["value"]
        assert frames[0]["confidence"] == "observed_program_counter"
        assert all(frame["confidence"] == "frame_pointer_chain" for frame in frames[1:])
        if sample.id in {
            "crash_abort",
            "crash_assert",
            "crash_trap",
            "crash_raise_segv",
            "crash_raise_bus",
            "crash_raise_fpe",
            "crash_raise_ill",
        }:
            assert report["signal_code"]["value"] <= 0
            assert (
                report["signal_sender_pid"]["value"]
                == capsule["processes"][0]["os_pid"]
            )
        if sample.id == "crash_assert":
            tampered_payloads = [
                (
                    payload_id,
                    b"tampered" if payload_id == "process-output-stderr" else data,
                )
                for payload_id, data in payloads
            ]
            tampered = json.loads(
                runtime_analysis.analyze_process_capsule_crash(
                    json.dumps(capsule), tampered_payloads, binary.read_bytes()
                )
            )["report"]
            assert tampered["stderr"]["status"] == "unknown"
            assert tampered["class"]["status"] == "unknown"
        if expected_class := evidence_class.get(sample.id):
            assert report["class"]["value"] == expected_class, (
                sample.id,
                report,
            )
        else:
            assert report["class"]["status"] == "unknown", (sample.id, report)
        semantic_result = HARNESS.crash_semantic_result(
            analyzed,
            sample=sample.id,
            scenario="bad",
            compiler="gcc",
            opt="O0",
            link="pie",
        )
        semantic_class = next(
            fact
            for fact in semantic_result["facts"]
            if (fact["kind"], fact["subject"], fact["predicate"])
            == ("terminal", "terminal_fault", "class")
        )
        assert semantic_class["status"] == report["class"]["status"]
        if sample.id in {
            "crash_null_read",
            "crash_abort",
            "crash_assert",
            "crash_trap",
            "crash_raise_segv",
            "crash_raise_bus",
            "crash_raise_fpe",
            "crash_raise_ill",
        }:
            oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, "bad")]
            assert HARNESS.evaluate_semantic_result(semantic_result, oracle)["passed"]
            if sample.id == "crash_null_read":
                mutated = json.loads(json.dumps(semantic_result))
                access = next(
                    fact
                    for fact in mutated["facts"]
                    if (fact["kind"], fact["subject"], fact["predicate"])
                    == ("memory", "faulting_access", "access")
                )
                access["value"] = "read:null:width=8"
                mutation_evaluation = HARNESS.evaluate_semantic_result(mutated, oracle)
                assert mutation_evaluation["passed"] is False
                assert mutation_evaluation["failures"] == [
                    {
                        "fact": ("memory", "faulting_access", "access"),
                        "error": "value_mismatch",
                        "expected": "read:null:width=4",
                        "observed": "read:null:width=8",
                    }
                ]
        good_record = HARNESS.run_one(binary, sample, "good", 5.0)
        assert HARNESS.observed_outcome(good_record) == "exit:0"
        good_capsule, good_payloads = HARNESS.terminal_process_capsule(
            binary, good_record, HARNESS.scenario_arg(sample, "good").encode()
        )
        comparison = json.loads(
            runtime_analysis.compare_process_capsule_crashes(
                good_capsule,
                good_payloads,
                json.dumps(capsule),
                payloads,
                binary.read_bytes(),
            )
        )
        assert comparison["schema"] == "glaurung-runtime-crash-comparison-v1"
        assert comparison["good"]["outcome"] == "no_crash"
        assert comparison["bad"]["outcome"] == "crash"
        assert comparison["contrast"] == {
            "verdict": "bad_only",
            "class": report["class"],
        }
        if sample.id == "crash_null_read":
            from glaurung.llm.kb.persistent import PersistentKnowledgeBase
            from glaurung.llm.kb.runtime_relations import (
                analyze_and_persist_crash,
                compare_runtime_captures_json,
                persist_process_capsule,
            )

            project = tmp_path / "crash-null-read-good-bad.glaurung"
            with PersistentKnowledgeBase.open(project, binary_path=binary) as kb:
                good_identity = persist_process_capsule(
                    kb, good_capsule, good_payloads, run_id="good"
                )
                bad_identity = persist_process_capsule(
                    kb, json.dumps(capsule), payloads, run_id="bad"
                )
                analyze_and_persist_crash(
                    kb, good_identity.capture_id, binary.read_bytes()
                )
                analyze_and_persist_crash(
                    kb, bad_identity.capture_id, binary.read_bytes()
                )
                persisted_comparison = json.loads(
                    compare_runtime_captures_json(
                        kb, good_identity.capture_id, bad_identity.capture_id
                    )
                )
            assert persisted_comparison["same_executable"] is True
            assert persisted_comparison["analysis_outcomes"] == {
                "left": {
                    "runtime-crash:glaurung-runtime-crash-analysis-v1": "no_crash"
                },
                "right": {"runtime-crash:glaurung-runtime-crash-report-v1": "crash"},
            }
            assert persisted_comparison["terminal_states"] == {
                "left": [{"kind": "exited", "code": 0}],
                "right": [capsule["processes"][0]["terminal"]],
            }
    for sample, _binary, _capture, _manifest, capsule in captures:
        if sample.id in {"crash_raise_segv", "crash_raise_bus", "crash_raise_ill"}:
            fault = next(
                thread["fault"] for thread in capsule["threads"] if "fault" in thread
            )
            assert "address" not in fault


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize(
    ("sample_id", "expected_class"),
    [
        ("crash_guard_read", "guard_page_read"),
        ("crash_guard_write", "guard_page_write"),
    ],
)
def test_traced_guard_fault_requires_ordered_mapping_transition(
    tmp_path: Path, sample_id: str, expected_class: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_traced_child_core

    sample = next(item for item in HARNESS.load_samples() if item.id == sample_id)
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_traced_child_core(
        binary,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=HARNESS.fixture_environment(sample),
        timeout=10.0,
        public_input=b"bad",
    )
    capsule = json.loads(capture.capsule_json)
    assert capsule["identity"]["acquisition"] == "trace"
    assert capsule["provider.strace"]["event_scope"] == [
        "mmap",
        "mprotect",
        "munmap",
    ]
    assert any(event["kind"] == "mapping_create" for event in capsule["events"])
    assert any(event["kind"] == "mapping_protect" for event in capsule["events"])

    analysis = json.loads(
        runtime_analysis.analyze_process_capsule_crash(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    assert analysis["outcome"] == "crash"
    assert analysis["report"]["class"] == {
        "status": "inferred",
        "value": expected_class,
        "source": "fault access plus ordered successful mapping create/protect events",
    }

    without_events = capsule.copy()
    without_events["events"] = []
    without_events_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(without_events, separators=(",", ":"))
    )
    weakened = json.loads(
        runtime_analysis.analyze_process_capsule_crash(
            without_events_json, list(capture.payloads), binary.read_bytes()
        )
    )
    generic_class = (
        "read_protection_fault"
        if expected_class.endswith("read")
        else "write_protection_fault"
    )
    assert weakened["report"]["class"]["value"] == generic_class


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize(
    ("sample_id", "scenario", "expected_history", "expected_finding"),
    [
        ("danger_rw_to_rx", "good", "RW->unmapped", None),
        (
            "danger_rw_to_rx",
            "bad",
            "RW->RX->unmapped",
            "writable_to_executable",
        ),
        ("danger_rwx_mapping", "good", "RW->unmapped", None),
        (
            "danger_rwx_mapping",
            "bad",
            "RWX->unmapped",
            "writable_executable_mapping",
        ),
    ],
)
def test_mapping_trace_produces_oracle_independent_permission_history(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sample_id: str,
    scenario: str,
    expected_history: str,
    expected_finding: str | None,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.cli.main import main as cli_main
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase
    from glaurung.llm.kb.runtime_relations import (
        analyze_and_persist_mapping_behavior,
        persist_process_capsule,
        runtime_mapping_history_json,
    )
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(item for item in HARNESS.load_samples() if item.id == sample_id)
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
    )
    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_mapping_behavior(capture.capsule_json)
    )
    assert behavior["schema"] == "glaurung-runtime-mapping-behavior-report-v1"
    assert behavior["event_scope"]["status"] == "observed"
    if expected_finding is not None:
        assert len(behavior["findings"]) == 1
        finding = behavior["findings"][0]
        assert finding["kind"] == expected_finding
        assert finding["conclusion"]["status"] == "inferred"
        lifetime = behavior["lifetimes"][finding["lifetime_index"]]
        assert lifetime["anonymous"] is True
        if expected_finding == "writable_to_executable":
            transition = behavior["transitions"][finding["transition_index"]]
            assert transition["from_permissions"] == "read|write"
            assert transition["to_permissions"] == "read|execute"
            assert transition["anonymous"] is True
        else:
            assert finding["transition_index"] is None
            assert lifetime["created_permissions"] == "read|write|execute"
    else:
        assert behavior["findings"] == []

    project = tmp_path / f"mapping-{sample_id}-{scenario}.glaurung"
    with PersistentKnowledgeBase.open(project, binary_path=binary) as kb:
        persisted_capture = persist_process_capsule(
            kb, capture.capsule_json, list(capture.payloads)
        )
        with pytest.raises(KeyError, match="no persisted runtime mapping history"):
            runtime_mapping_history_json(kb, persisted_capture.capture_id)
        persisted_mapping = analyze_and_persist_mapping_behavior(
            kb, persisted_capture.capture_id
        )
        assert (
            analyze_and_persist_mapping_behavior(kb, persisted_capture.capture_id)
            == persisted_mapping
        )
        assert json.loads(persisted_mapping.report_json) == behavior
        assert (
            runtime_mapping_history_json(kb, persisted_capture.capture_id)
            == persisted_mapping.report_json
        )
    with PersistentKnowledgeBase.open(project) as reopened:
        assert (
            runtime_mapping_history_json(reopened, persisted_capture.capture_id)
            == persisted_mapping.report_json
        )
    if sample_id == "danger_rw_to_rx" and scenario == "bad":
        assert (
            cli_main(
                [
                    "runtime",
                    "--json",
                    "mapping-history",
                    str(project),
                    persisted_capture.capture_id,
                ]
            )
            == 0
        )
        assert capsys.readouterr().out == persisted_mapping.report_json + "\n"
        assert (
            cli_main(
                [
                    "runtime",
                    "mapping-history",
                    str(project),
                    persisted_capture.capture_id,
                ]
            )
            == 0
        )
        rendered = capsys.readouterr().out
        assert "mapping 0:" in rendered
        assert "read|write -> read|execute -> unmapped" in rendered
        with PersistentKnowledgeBase.open(project) as corrupted:
            corrupted._conn.execute(
                "UPDATE runtime_analysis_reports SET report_sha256 = ? "
                "WHERE binary_id = ? AND capture_id = ? "
                "AND analyzer = 'runtime-mapping-behavior'",
                ("0" * 64, corrupted.binary_id, persisted_capture.capture_id),
            )
            with pytest.raises(ValueError, match="hash mismatch"):
                runtime_mapping_history_json(corrupted, persisted_capture.capture_id)
            corrupted._conn.execute(
                "UPDATE runtime_analysis_reports SET report_sha256 = ? "
                "WHERE binary_id = ? AND capture_id = ? "
                "AND analyzer = 'runtime-mapping-behavior'",
                (
                    hashlib.sha256(persisted_mapping.report_json.encode()).hexdigest(),
                    corrupted.binary_id,
                    persisted_capture.capture_id,
                ),
            )
            corrupted._conn.commit()
    if sample_id == "danger_rw_to_rx" and scenario == "bad":
        partial_capsule = json.loads(capture.capsule_json)
        mapping_completeness = next(
            record
            for record in partial_capsule["completeness"]
            if record["evidence"] == "mapping_events"
        )
        mapping_completeness["status"] = "partial"
        mapping_completeness["reason"] = "negative-control event loss"
        partial_json = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(partial_capsule)
        )
        partial_behavior = json.loads(
            runtime_analysis.analyze_process_capsule_mapping_behavior(partial_json)
        )
        assert partial_behavior["event_scope"]["status"] == "unknown"
        assert partial_behavior["findings"] == behavior["findings"]
    result = HARNESS.mapping_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    permission_fact = next(
        fact
        for fact in result["facts"]
        if (fact["kind"], fact["subject"], fact["predicate"])
        == ("mapping", "anonymous_mapping", "permission_history")
    )
    assert permission_fact == {
        "kind": "mapping",
        "subject": "anonymous_mapping",
        "predicate": "permission_history",
        "status": "observed",
        "value": expected_history,
        "source": "complete normalized mmap/mprotect/munmap event stream",
    }
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["failures"] == []
    if sample_id == "danger_rwx_mapping":
        assert evaluation["passed"]
        assert evaluation["matched"] == 2
    else:
        assert evaluation["matched"] == 1
        assert len(evaluation["incomplete"]) == 1

    permission_fact["value"] += ":mutated"
    mutated = HARNESS.evaluate_semantic_result(result, oracle)
    assert mutated["failures"] == [
        {
            "fact": ("mapping", "anonymous_mapping", "permission_history"),
            "error": "value_mismatch",
            "expected": expected_history,
            "observed": expected_history + ":mutated",
        }
    ]


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize(
    ("scenario", "path", "expected_result"),
    [
        ("good", "input.txt", "success"),
        ("bad", "missing-runtime-sample", "failure:ENOENT"),
    ],
)
def test_file_trace_produces_redacted_or_authorized_open_facts(
    tmp_path: Path, scenario: str, path: str, expected_result: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "normal_open_file"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    HARNESS.prepare_fixture_cwd(sample, tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_paths=[path],
    )
    capsule = json.loads(capture.capsule_json)
    file_events = [event for event in capsule["events"] if event["kind"] == "file_open"]
    assert file_events
    public_events = [
        event for event in file_events if event["fields"]["path_redacted"] == "false"
    ]
    assert len(public_events) == 1
    assert public_events[0]["fields"]["path"] == path
    assert all(
        "path" not in event["fields"]
        for event in file_events
        if event["fields"]["path_redacted"] == "true"
    )

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(capture.capsule_json)
    )
    assert behavior["schema"] == "glaurung-runtime-file-behavior-report-v1"
    assert behavior["event_scope"]["status"] == "observed"
    assert behavior["dangerous_findings"] == []
    public_opens = [
        opened for opened in behavior["opens"] if opened["path"]["status"] == "observed"
    ]
    assert len(public_opens) == 1
    assert public_opens[0]["path"]["value"] == path

    result = HARNESS.file_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"]
    assert evaluation["matched"] == 2

    open_fact = next(fact for fact in result["facts"] if fact["kind"] == "os_event")
    assert open_fact["value"] == expected_result
    open_fact["value"] += ":mutated"
    assert not HARNESS.evaluate_semantic_result(result, oracle)["passed"]

    if scenario == "bad":
        partial_capsule = json.loads(capture.capsule_json)
        file_completeness = next(
            record
            for record in partial_capsule["completeness"]
            if record["evidence"] == "file_events"
        )
        file_completeness["status"] = "partial"
        file_completeness["reason"] = "negative-control event loss"
        partial_json = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(partial_capsule)
        )
        partial_behavior = json.loads(
            runtime_analysis.analyze_process_capsule_file_behavior(partial_json)
        )
        assert partial_behavior["event_scope"]["status"] == "unknown"
        assert partial_behavior["opens"] == behavior["opens"]
        partial_result = HARNESS.file_semantic_result(
            partial_json,
            sample=sample.id,
            scenario=scenario,
            compiler="gcc",
            opt="O0",
            link="pie",
        )
        partial_evaluation = HARNESS.evaluate_semantic_result(partial_result, oracle)
        assert partial_evaluation["failures"] == []
        assert partial_evaluation["matched"] == 1
        assert len(partial_evaluation["incomplete"]) == 1


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize("scenario", ["good", "bad"])
@pytest.mark.parametrize(
    ("sample_id", "path", "content_hex", "written_len", "expected_lifecycle"),
    [
        (
            "normal_create_file",
            "created.txt",
            "6f6b",
            2,
            "open:create|truncate:0600->write:2:bytes=6f6b->close",
        ),
        (
            "normal_write_file",
            "written.bin",
            "676c617572756e67",
            8,
            "open:create|truncate:0600->write:8:bytes=676c617572756e67->close",
        ),
    ],
)
def test_file_trace_correlates_authorized_create_write_close_lifecycle(
    tmp_path: Path,
    scenario: str,
    sample_id: str,
    path: str,
    content_hex: str,
    written_len: int,
    expected_lifecycle: str,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(item for item in HARNESS.load_samples() if item.id == sample_id)
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_paths=[path],
        public_content_paths=[path],
    )
    capsule = json.loads(capture.capsule_json)
    file_events = [
        event for event in capsule["events"] if event["kind"].startswith("file_")
    ]
    public_open = next(
        event
        for event in file_events
        if event["kind"] == "file_open" and event["fields"].get("path") == path
    )
    resource_id = public_open["fields"]["resource_id"]
    linked = [
        event
        for event in file_events
        if event["fields"].get("resource_id") == resource_id
    ]
    assert [event["kind"] for event in linked] == [
        "file_open",
        "file_write",
        "file_close",
    ]
    assert public_open["fields"]["mode"] == "0600"
    assert linked[1]["fields"]["content_hex"] == content_hex
    assert linked[1]["fields"]["content_redacted"] == "false"
    assert all(
        "path" not in event["fields"]
        for event in file_events
        if event["kind"] == "file_open" and event["fields"]["path_redacted"] == "true"
    )

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(capture.capsule_json)
    )
    public_create = next(
        opened for opened in behavior["opens"] if opened["path"].get("value") == path
    )
    assert public_create["mode"] == "0600"
    assert "O_CREAT" in public_create["flags"].split("|")
    assert behavior["dangerous_findings"] == []
    write = next(
        item for item in behavior["writes"] if item["resource_id"] == resource_id
    )
    assert write["content"] == {
        "status": "observed",
        "value": content_hex,
        "source": "hash-verified caller-authorized public content in normalized file_write event",
    }
    assert write["outcome"]["value"] == written_len
    assert any(item["resource_id"] == resource_id for item in behavior["closes"])

    result = HARNESS.file_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"]
    assert evaluation["matched"] == 2
    lifecycle = next(
        fact for fact in result["facts"] if fact["predicate"] == "lifecycle"
    )
    assert lifecycle["value"] == expected_lifecycle
    lifecycle["value"] += ":mutated"
    assert not HARNESS.evaluate_semantic_result(result, oracle)["passed"]

    tampered = json.loads(capture.capsule_json)
    tampered_write = next(
        event
        for event in tampered["events"]
        if event["kind"] == "file_write"
        and event["fields"].get("resource_id") == resource_id
    )
    tampered_write["fields"]["content_hex"] = "00" * written_len
    tampered_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(tampered)
    )
    tampered_behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(tampered_json)
    )
    tampered_native_write = next(
        item
        for item in tampered_behavior["writes"]
        if item["resource_id"] == resource_id
    )
    assert tampered_native_write["content"]["status"] == "unknown"
    tampered_result = HARNESS.file_semantic_result(
        tampered_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    tampered_evaluation = HARNESS.evaluate_semantic_result(tampered_result, oracle)
    assert not tampered_evaluation["passed"]
    assert tampered_evaluation["matched"] == 1


def test_file_trace_rejects_unnormalizable_tracked_resource_operation() -> None:
    from glaurung.runtime_capture import _parse_os_trace

    capsule = {
        "processes": [{"id": "process-main", "os_pid": 123}],
        "threads": [],
    }
    trace = "\n".join(
        [
            '123 openat(AT_FDCWD, "created.txt", O_WRONLY|O_CREAT|O_TRUNC, 0600) = 3',
            '123 write(3, "aaaaaaaa"..., 300) = 300',
        ]
    )
    with pytest.raises(
        ValueError,
        match="in-scope operation on a tracked file resource could not be normalized",
    ):
        _parse_os_trace(trace, capsule, public_paths=["created.txt"])


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize("scenario", ["good", "bad"])
def test_file_trace_derives_append_semantics_from_linked_resource(
    tmp_path: Path, scenario: str
) -> None:
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "normal_append_file"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_paths=["append.txt"],
        public_content_paths=["append.txt"],
    )
    result = HARNESS.file_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"]
    assert evaluation["matched"] == 2
    append_fact = next(
        fact
        for fact in result["facts"]
        if (fact["subject"], fact["predicate"]) == ("file:append.txt", "write")
    )
    assert append_fact["value"] == "O_APPEND:length=1:bytes=78"
    append_fact["value"] += ":mutated"
    assert not HARNESS.evaluate_semantic_result(result, oracle)["passed"]


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize("scenario", ["good", "bad"])
def test_file_trace_normalizes_selected_descriptor_read(
    tmp_path: Path, scenario: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "normal_read_file"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_paths=["/dev/zero"],
        public_content_paths=["/dev/zero"],
    )
    capsule = json.loads(capture.capsule_json)
    public_open = next(
        event
        for event in capsule["events"]
        if event["kind"] == "file_open" and event["fields"].get("path") == "/dev/zero"
    )
    reads = [event for event in capsule["events"] if event["kind"] == "file_read"]
    assert len(reads) == 1
    assert reads[0]["fields"]["resource_id"] == public_open["fields"]["resource_id"]
    assert reads[0]["fields"]["offset"] == "0"
    assert reads[0]["fields"]["requested_byte_len"] == "16"
    assert reads[0]["fields"]["read_byte_len"] == "16"
    assert reads[0]["fields"]["content_hex"] == "00" * 16
    input_name = reads[0]["fields"]["input_source_name"]
    provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(capture.capsule_json)
    )
    input_source = next(
        source for source in provenance["sources"] if source["name"] == input_name
    )
    assert input_source["sha256"] == reads[0]["fields"]["content_sha256"]
    assert input_source["byte_len"] == 16
    assert input_source["sensitivity"] == "public"
    first_input_byte = json.loads(
        runtime_analysis.resolve_process_capsule_input_byte(
            capture.capsule_json, input_name, 0
        )
    )
    last_input_byte = json.loads(
        runtime_analysis.resolve_process_capsule_input_byte(
            capture.capsule_json, input_name, 15
        )
    )
    assert first_input_byte["source_id"] == input_source["id"]
    assert first_input_byte["id"] != last_input_byte["id"]

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(capture.capsule_json)
    )
    assert len(behavior["reads"]) == 1
    native_read = behavior["reads"][0]
    assert native_read["offset"] == 0
    assert native_read["content"]["status"] == "observed"
    assert native_read["outcome"]["value"] == 16
    assert native_read["input_source_name"] == input_name
    assert native_read["user_frame_artifact_sha256"] == HARNESS.sha256(binary)

    relations = json.loads(
        runtime_analysis.correlate_process_capsule_input_events(
            capture.capsule_json, binary.read_bytes()
        )
    )
    assert relations["schema"] == "glaurung-runtime-input-event-relation-v1"
    assert len(relations["relations"]) == 1
    relation = relations["relations"][0]
    assert relation["event_kind"] == "file_read"
    assert relation["input_source"]["value"] == input_source
    occurrence = relation["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    assert occurrence["value"]["static_operation"]["kind"] == "call"
    assert occurrence["value"]["introduced_input_sources"] == [input_source]
    assert occurrence["value"]["output"]["value"] == 16

    tampered = json.loads(capture.capsule_json)
    tampered_read = next(
        event for event in tampered["events"] if event["kind"] == "file_read"
    )
    tampered_read["fields"]["input_source_name"] = "missing-source"
    tampered_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(tampered)
    )
    tampered_relation = json.loads(
        runtime_analysis.correlate_process_capsule_input_events(
            tampered_json, binary.read_bytes()
        )
    )["relations"][0]
    assert tampered_relation["input_source"]["status"] == "unknown"
    assert tampered_relation["operation_occurrence"]["status"] == "unknown"

    result = HARNESS.file_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"]
    assert evaluation["matched"] == 2
    read_fact = next(fact for fact in result["facts"] if fact["predicate"] == "read")
    assert read_fact["value"] == "offset=0:length=16:result=16:all_zero"
    read_fact["value"] += ":mutated"
    assert not HARNESS.evaluate_semantic_result(result, oracle)["passed"]

    tampered = json.loads(capture.capsule_json)
    tampered_read = next(
        event for event in tampered["events"] if event["kind"] == "file_read"
    )
    tampered_read["fields"]["content_hex"] = "01" + "00" * 15
    tampered_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(tampered)
    )
    tampered_behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(tampered_json)
    )
    assert tampered_behavior["reads"][0]["content"]["status"] == "unknown"
    tampered_result = HARNESS.file_semantic_result(
        tampered_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    tampered_evaluation = HARNESS.evaluate_semantic_result(tampered_result, oracle)
    assert not tampered_evaluation["passed"]
    assert tampered_evaluation["matched"] == 1


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize("compiler", ["gcc", "clang"])
@pytest.mark.parametrize("opt", ["O0", "O2"])
@pytest.mark.parametrize("link", ["pie", "no-pie"])
def test_file_input_event_correlates_to_llir_call_across_default_matrix(
    tmp_path: Path, compiler: str, opt: str, link: str
) -> None:
    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "normal_read_file"
    )
    binary = HARNESS.compile_sample(sample, compiler, opt, link, tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, "good")],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=b"good",
        public_paths=["/dev/zero"],
        public_content_paths=["/dev/zero"],
    )
    report = json.loads(
        runtime_analysis.correlate_process_capsule_input_events(
            capture.capsule_json, binary.read_bytes()
        )
    )
    assert len(report["relations"]) == 1
    relation = report["relations"][0]
    assert relation["input_source"]["status"] == "observed"
    assert relation["operation_occurrence"]["status"] == "inferred", relation
    occurrence = relation["operation_occurrence"]["value"]
    assert occurrence["static_operation"]["kind"] == "call"
    assert len(occurrence["introduced_input_sources"]) == 1


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
def test_stdin_bytes_become_bounded_input_event_and_llir_occurrence(
    tmp_path: Path,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "normal_stdin_read"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    supplied = b"hello"
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, "good")],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=b"good",
        stdin_bytes=supplied,
        public_stdin_content=True,
    )
    capsule = json.loads(capture.capsule_json)
    event = next(
        event for event in capsule["events"] if event["kind"] == "descriptor_stdin_read"
    )
    assert event["fields"]["provider"] == "pipe"
    assert event["fields"]["descriptor"] == "0"
    assert event["fields"]["requested_byte_len"] == "8"
    assert event["fields"]["read_byte_len"] == str(len(supplied))
    assert event["fields"]["content_hex"] == supplied.hex()
    destination_address = int(event["fields"]["destination_address"])
    assert destination_address > 0
    source_name = event["fields"]["input_source_name"]
    provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(capture.capsule_json)
    )
    source = next(
        source for source in provenance["sources"] if source["name"] == source_name
    )
    assert source["byte_len"] == len(supplied)
    assert source["sensitivity"] == "public"

    descriptor_report = json.loads(
        runtime_analysis.analyze_process_capsule_descriptor_behavior(
            capture.capsule_json
        )
    )
    stdin_resource = next(
        resource
        for resource in descriptor_report["resources"]
        if resource["kind"] == "standard_input"
    )
    assert stdin_resource["resource_id"] == event["fields"]["resource_id"]
    assert stdin_resource["endpoints"] == [{"descriptor": 0, "role": "stdin"}]
    stdin_transfer = next(
        transfer
        for transfer in descriptor_report["transfers"]
        if transfer["endpoint"] == "stdin"
    )
    assert stdin_transfer["input_source_name"] == source_name
    assert stdin_transfer["outcome"]["value"] == len(supplied)
    assert stdin_transfer["destination_address"] == destination_address

    report = json.loads(
        runtime_analysis.correlate_process_capsule_input_events(
            capture.capsule_json, binary.read_bytes()
        )
    )
    relation = next(
        relation
        for relation in report["relations"]
        if relation["event_kind"] == "descriptor_stdin_read"
    )
    assert relation["input_source"]["value"] == source
    occurrence = relation["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    assert occurrence["value"]["static_operation"]["kind"] == "call"
    assert occurrence["value"]["introduced_input_sources"] == [source]
    assert occurrence["value"]["effects"] == [
        {
            "kind": "descriptor_stdin_read",
            "resource_id": event["fields"]["resource_id"],
            "errno": None,
            "address": destination_address,
            "byte_len": len(supplied),
            "input_source_id": source["id"],
        }
    ]

    private_capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, "good")],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=b"good",
        stdin_bytes=supplied,
    )
    private_capsule = json.loads(private_capture.capsule_json)
    private_event = next(
        event
        for event in private_capsule["events"]
        if event["kind"] == "descriptor_stdin_read"
    )
    assert private_event["fields"]["content_redacted"] == "true"
    assert "content_hex" not in private_event["fields"]
    private_provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(private_capture.capsule_json)
    )
    private_source = next(
        source
        for source in private_provenance["sources"]
        if source["name"] == private_event["fields"]["input_source_name"]
    )
    assert private_source["sensitivity"] == "sensitive"
    assert private_source["sha256"] == source["sha256"]
    assert (
        private_capsule["identity"]["capture_id"] != capsule["identity"]["capture_id"]
    )

    with pytest.raises(ValueError, match="stdin bytes exceed acquisition budget"):
        capture_mapping_trace_child(binary, stdin_bytes=b"x" * (1024 * 1024 + 1))


@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize(
    ("compiler", "opt", "link", "static_base", "static_offset"),
    [
        ("gcc", "O0", "pie", "dwarf_call_frame_cfa", -36),
        ("gcc", "O0", "no-pie", "dwarf_call_frame_cfa", -36),
        ("gcc", "O2", "pie", "dwarf_call_frame_cfa", -52),
        ("gcc", "O2", "no-pie", "dwarf_call_frame_cfa", -52),
        ("clang", "O0", "pie", "dwarf_register_6_rbp", -28),
        ("clang", "O0", "no-pie", "dwarf_register_6_rbp", -28),
        ("clang", "O2", "pie", "dwarf_register_6_rbp", -48),
        ("clang", "O2", "no-pie", "dwarf_register_6_rbp", -48),
    ],
)
@pytest.mark.parametrize(("scenario", "expected_len"), [("good", 8), ("bad", 12)])
def test_pipe_read_overflow_retains_source_to_concrete_memory_effect(
    tmp_path: Path,
    compiler: str,
    opt: str,
    link: str,
    scenario: str,
    expected_len: int,
    static_base: str,
    static_offset: int,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_read_overflow"
    )
    binary = HARNESS.compile_sample(sample, compiler, opt, link, tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_ipc_content=True,
        capture_read_destinations=True,
        capture_read_checkpoint=True,
    )
    capsule = json.loads(capture.capsule_json)
    read_event = next(
        event for event in capsule["events"] if event["kind"] == "descriptor_read"
    )
    assert read_event["fields"]["read_byte_len"] == str(expected_len)
    assert read_event["fields"]["content_hex"] == b"abcdefghijkl"[:expected_len].hex()
    destination = int(read_event["fields"]["destination_address"])
    assert destination > 0
    source_name = read_event["fields"]["input_source_name"]
    provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(capture.capsule_json)
    )
    source = next(
        source for source in provenance["sources"] if source["name"] == source_name
    )
    assert source["byte_len"] == expected_len

    report = json.loads(
        runtime_analysis.correlate_process_capsule_input_events(
            capture.capsule_json, binary.read_bytes()
        )
    )
    relation = next(
        relation
        for relation in report["relations"]
        if relation["event_kind"] == "descriptor_read"
    )
    occurrence = relation["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    assert occurrence["value"]["effects"] == [
        {
            "kind": "descriptor_read",
            "resource_id": read_event["fields"]["resource_id"],
            "errno": None,
            "address": destination,
            "byte_len": expected_len,
            "input_source_id": source["id"],
        }
    ]

    stack_mapping = next(
        mapping
        for mapping in capsule["mappings"]
        if mapping["backing"] == {"kind": "special", "name": "[stack]"}
    )
    assert stack_mapping["backing"] == {"kind": "special", "name": "[stack]"}
    assert stack_mapping["start"] <= destination < stack_mapping["end"]
    runtime_object = next(
        item
        for item in capsule["runtime_objects"]
        if item["id"] == "object-checkpoint-stack-mapping"
    )
    assert runtime_object["kind"] == "mapping"
    assert runtime_object["mapping_id"] == stack_mapping["id"]
    assert capsule["modules"] == [
        {
            "id": "module-main",
            "process_id": "process-main",
            "artifact": capsule["executable"],
            "mapping_ids": [
                mapping["id"]
                for mapping in capsule["mappings"]
                if mapping.get("module_id") == "module-main"
            ],
        }
    ]
    checkpoint_thread = capsule["threads"][0]
    assert checkpoint_thread["os_tid"] == capsule["processes"][0]["os_pid"]
    registers = {
        register["provider_name"]: int(register["value_hex"], 16)
        for register in checkpoint_thread["registers"]
    }
    assert set(registers) == {"rip", "rsp"}
    assert stack_mapping["start"] <= registers["rsp"] < stack_mapping["end"]
    stack_page = capsule["pages"][0]
    assert stack_page["mapping_id"] == stack_mapping["id"]
    assert stack_page["start"] == registers["rsp"]
    assert stack_page["start"] + stack_page["byte_len"] == stack_mapping["end"]
    payloads = dict(capture.payloads)
    snapshots = sorted(
        (
            item
            for item in capsule["object_snapshots"]
            if item["object_id"] == "object-checkpoint-stack-mapping"
        ),
        key=lambda item: item["point"]["sequence"],
    )
    assert [item["id"] for item in snapshots] == [
        "snapshot-checkpoint-before-read-bytes",
        "snapshot-checkpoint-after-read-bytes",
    ]
    for snapshot in snapshots:
        assert snapshot["object_offset"] == destination - stack_mapping["start"]
        assert snapshot["byte_len"] == 64
        payload = snapshot["content"]["payload"]
        assert payload["sha256"] == hashlib.sha256(payloads[payload["id"]]).hexdigest()
    before_payload = payloads[snapshots[0]["content"]["payload"]["id"]]
    after_payload = payloads[snapshots[1]["content"]["payload"]["id"]]
    assert before_payload[:12] == bytes(8) + bytes.fromhex("cdab3412")
    assert after_payload[:expected_len] == b"abcdefghijkl"[:expected_len]
    assert after_payload[8:12] == (
        bytes.fromhex("cdab3412") if scenario == "good" else b"ijkl"
    )
    stack_payload = stack_page["content"]["payload"]
    assert len(payloads[stack_payload["id"]]) == stack_page["byte_len"]
    assert (
        stack_payload["sha256"]
        == hashlib.sha256(payloads[stack_payload["id"]]).hexdigest()
    )
    checkpoint_completeness = next(
        item
        for item in capsule["completeness"]
        if item["evidence"] == "read_checkpoint_memory"
    )
    assert checkpoint_completeness["status"] == "complete"
    assert checkpoint_completeness["obtained"] == 2

    stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    assert stack_report["schema"] == "glaurung-runtime-stack-write-report-v1"
    stack_relation = next(
        item
        for item in stack_report["relations"]
        if item["event_kind"] == "descriptor_read"
    )
    assert stack_relation["frame"]["status"] == "inferred", stack_relation
    assert stack_relation["operation_occurrence"]["status"] == "inferred"
    assert (
        stack_relation["operation_occurrence"]["value"]["static_operation"]["kind"]
        == "call"
    )
    assert (
        stack_relation["operation_occurrence"]["value"]["effects"][0]["address"]
        == destination
    )
    assert stack_relation["frame"]["value"]["function_name"] == "main"
    assert stack_relation["object"]["status"] == "inferred", stack_relation
    assert stack_relation["object"]["value"] == {
        "source_name": "b",
        "c_type": "struct box",
        "static_base": static_base,
        "static_offset": static_offset,
        "runtime_start": destination,
        "byte_len": 12,
        "aggregate": True,
    }
    assert stack_relation["field"]["status"] == "inferred", stack_relation
    assert stack_relation["field"]["value"] == {
        "name": "dst",
        "c_type": "char[]",
        "object_offset": 0,
        "runtime_start": destination,
        "byte_len": 8,
    }
    assert stack_relation["bounds"]["status"] == "inferred", stack_relation
    assert stack_relation["bounds"]["value"] == {
        "write_start": destination,
        "write_byte_len": expected_len,
        "object_bytes_exceeded": 0,
        "field_bytes_exceeded": 0 if scenario == "good" else 4,
        "classification": "within_field"
        if scenario == "good"
        else "crosses_field_boundary",
    }
    assert stack_relation["field_changes"]["status"] == "inferred"
    changes = {
        change["field"]["name"]: change
        for change in stack_relation["field_changes"]["value"]
    }
    assert set(changes) == {"dst", "canary"}
    assert changes["dst"]["before_hex"] == "00" * 8
    assert changes["dst"]["after_hex"] == b"abcdefgh".hex()
    assert changes["dst"]["changed_intervals"] == [
        {
            "field_offset_start": 0,
            "field_offset_end": 8,
            "before_hex": "00" * 8,
            "after_hex": b"abcdefgh".hex(),
        }
    ]
    assert changes["canary"]["before_hex"] == "cdab3412"
    assert changes["canary"]["after_hex"] == (
        "cdab3412" if scenario == "good" else b"ijkl".hex()
    )
    assert changes["canary"]["changed_intervals"] == (
        []
        if scenario == "good"
        else [
            {
                "field_offset_start": 0,
                "field_offset_end": 4,
                "before_hex": "cdab3412",
                "after_hex": b"ijkl".hex(),
            }
        ]
    )
    input_field_effects = stack_relation["input_field_effects"]
    assert input_field_effects["status"] == "inferred", input_field_effects
    expected_field_effects = [
        {
            "input_source_id": source["id"],
            "source_offset_start": 0,
            "source_offset_end": 8,
            "runtime_start": destination,
            "runtime_end": destination + 8,
            "object_offset_start": 0,
            "object_offset_end": 8,
            "field": stack_relation["field"]["value"],
            "field_offset_start": 0,
            "field_offset_end": 8,
        }
    ]
    if scenario == "bad":
        expected_field_effects.append(
            {
                "input_source_id": source["id"],
                "source_offset_start": 8,
                "source_offset_end": 12,
                "runtime_start": destination + 8,
                "runtime_end": destination + 12,
                "object_offset_start": 8,
                "object_offset_end": 12,
                "field": changes["canary"]["field"],
                "field_offset_start": 0,
                "field_offset_end": 4,
            }
        )
    assert input_field_effects["value"] == expected_field_effects
    semantic_result = HARNESS.stack_write_semantic_result(
        stack_report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt=opt,
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(semantic_result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert evaluation["matched"] == 2

    if scenario == "bad":
        assert any(
            fact["predicate"] == "bounds_violation"
            and fact["value"] == "read:length=12:declared_length=8"
            for fact in semantic_result["facts"]
        )
        if compiler == "gcc" and opt == "O0" and link == "pie":
            bounds_fact = next(
                fact
                for fact in semantic_result["facts"]
                if fact["predicate"] == "bounds_violation"
            )
            bounds_fact["value"] = "read:length=11:declared_length=8"
            mutated = HARNESS.evaluate_semantic_result(semantic_result, oracle)
            assert any(
                failure["error"] == "value_mismatch" for failure in mutated["failures"]
            )

    if compiler == "gcc" and opt == "O0" and link == "pie" and scenario == "bad":
        without_source = json.loads(capture.capsule_json)
        without_source["provenance"]["input_bytes"] = [
            item
            for item in without_source["provenance"]["input_bytes"]
            if item["name"] != source_name
        ]
        without_source_json = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(without_source)
        )
        without_source_report = json.loads(
            runtime_analysis.analyze_process_capsule_stack_writes(
                without_source_json, list(capture.payloads), binary.read_bytes()
            )
        )
        without_source_relation = next(
            item
            for item in without_source_report["relations"]
            if item["event_kind"] == "descriptor_read"
        )
        assert without_source_relation["input_field_effects"] == {
            "status": "unknown",
            "reason": "input field effects require an exact operation occurrence",
        }

    if compiler == "gcc" and opt == "O0" and link == "pie" and scenario == "good":
        before_snapshot_payload_id = snapshots[0]["content"]["payload"]["id"]
        without_before_snapshot = [
            item for item in capture.payloads if item[0] != before_snapshot_payload_id
        ]
        incomplete_diff = json.loads(
            runtime_analysis.analyze_process_capsule_stack_writes(
                capture.capsule_json,
                without_before_snapshot,
                binary.read_bytes(),
            )
        )["relations"][0]
        assert incomplete_diff["frame"]["status"] == "inferred"
        assert incomplete_diff["object"]["status"] == "inferred"
        assert incomplete_diff["field_changes"] == {
            "status": "unknown",
            "reason": (
                f"mapping snapshot payload {before_snapshot_payload_id} is unavailable"
            ),
        }

        without_stack_payload = [
            item
            for item in capture.payloads
            if item[0] != stack_page["content"]["payload"]["id"]
        ]
        incomplete = json.loads(
            runtime_analysis.analyze_process_capsule_stack_writes(
                capture.capsule_json, without_stack_payload, binary.read_bytes()
            )
        )["relations"][0]
        assert incomplete["frame"]["status"] == "unknown"
        assert incomplete["object"]["status"] == "unknown"

        wrong_image = bytearray(binary.read_bytes())
        wrong_image[-1] ^= 1
        wrong = json.loads(
            runtime_analysis.analyze_process_capsule_stack_writes(
                capture.capsule_json, list(capture.payloads), bytes(wrong_image)
            )
        )["relations"][0]
        assert wrong["frame"] == {
            "status": "unknown",
            "reason": "capsule executable identity disagrees with static image",
        }


def test_read_checkpoint_requires_destination_capture(tmp_path: Path) -> None:
    from glaurung.runtime_capture import capture_mapping_trace_child

    with pytest.raises(
        ValueError, match="read checkpoint requires captured read destinations"
    ):
        capture_mapping_trace_child(
            tmp_path / "does-not-need-to-exist", capture_read_checkpoint=True
        )


def test_instruction_trace_rejects_overlapping_heap_representations(
    tmp_path: Path,
) -> None:
    from glaurung.runtime_capture import capture_instruction_trace_child

    with pytest.raises(
        ValueError,
        match="capture_heap_timeline and heap_interposer are mutually exclusive",
    ):
        capture_instruction_trace_child(
            tmp_path / "does-not-need-to-exist",
            capture_heap_timeline=True,
            heap_interposer=tmp_path / "does-not-need-to-exist-either",
        )


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_instruction_trace_attributes_real_unsupported_operation(
    tmp_path: Path,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_command_argument"
    )
    unsupported_sample = replace(
        sample,
        cflags=sample.cflags + ("-DGLAURUNG_RUNTIME_REPLAY_UNSUPPORTED_FIXTURE",),
    )
    binary = HARNESS.compile_sample(unsupported_sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        ["bad"],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
        public_input=b"bad",
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    unsupported_seeds = [
        item["seed"]["value"]
        for item in report["replay_seeds"]
        if item["seed"]["status"] == "inferred"
        and item["seed"]["value"]["first_divergence"] is not None
        and item["seed"]["value"]["first_divergence"]["kind"] == "unsupported_operation"
    ]
    assert unsupported_seeds, report["replay_seeds"]
    seed = unsupported_seeds[0]
    assert seed["bounded_replay"]["status"] == "unknown"
    divergence = seed["first_divergence"]
    assert divergence["kind"] == "unsupported_operation"
    assert divergence["reason"] == "opaque memory intrinsic has no bounded replay model"
    assert divergence["operation"]["operation_kind"] == "intrinsic"
    assert divergence["operation"]["event_sequence"] == seed["sequence"]


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_instruction_trace_selects_only_input_tainted_branch(tmp_path: Path) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_command_argument"
    )
    branch_sample = replace(
        sample,
        cflags=sample.cflags + ("-DGLAURUNG_RUNTIME_REPLAY_BRANCH_FIXTURE",),
    )
    binary = HARNESS.compile_sample(branch_sample, "gcc", "O0", "pie", tmp_path)
    supplied = b"cad"
    capture = capture_instruction_trace_child(
        binary,
        [supplied.decode()],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
        public_input=supplied,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    candidates = report["solver_query_candidates"]
    assert len(candidates) == 1, candidates
    candidate = candidates[0]
    assert candidate["source_name"] == "argv[1]"
    assert candidate["static_operation"]["kind"] == "cond_jump"
    assert candidate["predicate_registers"]
    assert candidate["input_spans"] == [
        {
            "source_id": candidate["source_id"],
            "source_offset": 0,
            "byte_len": 1,
        }
    ]
    assert candidate["observed_edge"]["branch_taken"]
    assert candidate["selection_reason"] == (
        "observed LLIR branch condition consumes input-tainted state"
    )
    counterfactual = candidate["counterfactual"]
    if counterfactual["status"] == "unknown":
        assert counterfactual == {
            "status": "unknown",
            "reason_kind": "no_solver",
            "reason": (
                "runtime counterfactuals require a build with the symbolic feature"
            ),
            "proposition_status": "not_constructed",
        }
        return
    assert counterfactual["status"] == "satisfiable", counterfactual
    assert counterfactual["backend"] == "axeyum-native"
    assert counterfactual["asserted_path_conditions"] >= 1
    assert counterfactual["predicted_branch_taken"] is False
    assert counterfactual["mutations"] == [
        {
            "source_id": candidate["source_id"],
            "source_offset": 0,
            "replacement_hex": "62",
        }
    ]

    neighboring = bytearray(supplied)
    for mutation in counterfactual["mutations"]:
        neighboring[mutation["source_offset"]] = bytes.fromhex(
            mutation["replacement_hex"]
        )[0]
    neighboring_capture = capture_instruction_trace_child(
        binary,
        [neighboring.decode()],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
        public_input=bytes(neighboring),
    )
    neighboring_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            neighboring_capture.capsule_json,
            list(neighboring_capture.payloads),
            binary.read_bytes(),
        )
    )
    neighboring_candidates = neighboring_report["solver_query_candidates"]
    assert len(neighboring_candidates) == 1, neighboring_candidates
    neighboring_candidate = neighboring_candidates[0]
    assert neighboring_candidate["static_operation"] == candidate["static_operation"]
    assert neighboring_candidate["observed_edge"]["branch_taken"] is False
    assert (
        neighboring_candidate["observed_edge"]["target_static_va"]
        == counterfactual["predicted_target_static_va"]
    )

    capsule = json.loads(capture.capsule_json)
    stack_snapshot = next(
        snapshot
        for snapshot in capsule["object_snapshots"]
        if snapshot["id"] == "snapshot-instruction-trace-before"
    )
    stack_payload_id = stack_snapshot["content"]["payload"]["id"]
    missing_stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json,
            [item for item in capture.payloads if item[0] != stack_payload_id],
            binary.read_bytes(),
        )
    )
    missing_stack_candidate = missing_stack_report["solver_query_candidates"][0]
    assert missing_stack_candidate["counterfactual"]["status"] == "unknown"
    assert missing_stack_candidate["counterfactual"]["reason_kind"] == (
        "missing_environment"
    )

    for extra_flag, expected_reason in [
        (
            "-DGLAURUNG_RUNTIME_REPLAY_UNSUPPORTED_FIXTURE",
            "unsupported_semantics",
        ),
        (
            "-DGLAURUNG_RUNTIME_REPLAY_SYMBOLIC_POINTER_FIXTURE",
            "symbolic_pointer",
        ),
    ]:
        boundary_sample = replace(
            sample,
            cflags=sample.cflags
            + ("-DGLAURUNG_RUNTIME_REPLAY_BRANCH_FIXTURE", extra_flag),
        )
        boundary_binary = HARNESS.compile_sample(
            boundary_sample, "gcc", "O0", "pie", tmp_path
        )
        boundary_capture = capture_instruction_trace_child(
            boundary_binary,
            [supplied.decode()],
            environment=HARNESS.fixture_environment(sample),
            cwd=tmp_path,
            timeout=10,
            public_input=supplied,
        )
        boundary_report = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                boundary_capture.capsule_json,
                list(boundary_capture.payloads),
                boundary_binary.read_bytes(),
            )
        )
        boundary_candidates = boundary_report["solver_query_candidates"]
        assert len(boundary_candidates) == 1, boundary_candidates
        assert boundary_candidates[0]["counterfactual"]["status"] == "unknown"
        assert boundary_candidates[0]["counterfactual"]["reason_kind"] == (
            expected_reason
        )


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_counterfactual_neighbor_reaches_real_index_corruption(tmp_path: Path) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_index_write"
    )
    counterfactual_sample = replace(
        sample,
        cflags=sample.cflags + ("-DGLAURUNG_RUNTIME_COUNTERFACTUAL_SINK_FIXTURE",),
    )
    binary = HARNESS.compile_sample(counterfactual_sample, "gcc", "O0", "pie", tmp_path)
    supplied = b"cad"
    capture = capture_instruction_trace_child(
        binary,
        [supplied.decode()],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
        public_input=supplied,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    candidates = report["solver_query_candidates"]
    assert len(candidates) == 1, candidates
    counterfactual = candidates[0]["counterfactual"]
    if counterfactual["status"] == "unknown":
        assert counterfactual["reason_kind"] == "no_solver", counterfactual
        pytest.skip("native counterfactual solver is not compiled into this extension")
    assert counterfactual["status"] == "satisfiable", counterfactual
    assert counterfactual["mutations"] == [
        {
            "source_id": candidates[0]["source_id"],
            "source_offset": 0,
            "replacement_hex": "62",
        }
    ]
    neighboring = bytearray(supplied)
    neighboring[0] = int(counterfactual["mutations"][0]["replacement_hex"], 16)
    assert bytes(neighboring) == b"bad"
    neighboring_capture = capture_instruction_trace_child(
        binary,
        [neighboring.decode()],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
        public_input=bytes(neighboring),
    )
    neighboring_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            neighboring_capture.capsule_json,
            list(neighboring_capture.payloads),
            binary.read_bytes(),
        )
    )
    neighboring_candidates = neighboring_report["solver_query_candidates"]
    assert len(neighboring_candidates) == 1, neighboring_candidates
    assert (
        neighboring_candidates[0]["static_operation"]
        == candidates[0]["static_operation"]
    )
    assert (
        neighboring_candidates[0]["observed_edge"]["branch_taken"]
        == (counterfactual["predicted_branch_taken"])
    )
    stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            neighboring_capture.capsule_json,
            list(neighboring_capture.payloads),
            binary.read_bytes(),
        )
    )
    result = HARNESS.stack_write_semantic_result(
        stack_report,
        sample=sample.id,
        scenario="bad",
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, "bad")]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert any(
        relation.get("field", {}).get("value", {}).get("name") == "canary"
        for relation in stack_report["relations"]
    )


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_counterfactual_neighbor_reaches_real_command_metacharacter(
    tmp_path: Path,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import (
        capture_instruction_trace_child,
        validate_instruction_trace_counterfactual_child,
    )

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_command_argument"
    )
    counterfactual_sample = replace(
        sample,
        cflags=sample.cflags + ("-DGLAURUNG_RUNTIME_COUNTERFACTUAL_SINK_FIXTURE",),
    )
    binary = HARNESS.compile_sample(counterfactual_sample, "gcc", "O0", "pie", tmp_path)
    supplied = b"cad"
    capture = capture_instruction_trace_child(
        binary,
        [supplied.decode()],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
        public_input=supplied,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    candidates = report["solver_query_candidates"]
    assert len(candidates) == 1, candidates
    counterfactual = candidates[0]["counterfactual"]
    if counterfactual["status"] == "unknown":
        assert counterfactual["reason_kind"] == "no_solver", counterfactual
        pytest.skip("native counterfactual solver is not compiled into this extension")
    assert counterfactual["status"] == "satisfiable", counterfactual
    neighboring = bytearray(supplied)
    for mutation in counterfactual["mutations"]:
        neighboring[mutation["source_offset"]] = int(mutation["replacement_hex"], 16)
    assert bytes(neighboring) == b"bad"
    validation_result = validate_instruction_trace_counterfactual_child(
        binary,
        capture.capsule_json,
        capture.payloads,
        [supplied.decode()],
        source_id=candidates[0]["source_id"],
        candidate_sequence=candidates[0]["sequence"],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
    )
    assert validation_result.materialized_input == bytes(neighboring)
    validation_relation = json.loads(validation_result.validation_json)
    assert validation_relation["status"] == "validated", validation_relation
    assert validation_relation["original_capture_id"] == report["capture_id"]
    assert validation_relation["static_operation"] == candidates[0]["static_operation"]
    assert (
        validation_relation["observed_edge"]["branch_taken"]
        == counterfactual["predicted_branch_taken"]
    )
    with pytest.raises(ValueError, match="original argv bytes disagree"):
        validate_instruction_trace_counterfactual_child(
            binary,
            capture.capsule_json,
            capture.payloads,
            ["bad"],
            source_id=candidates[0]["source_id"],
            candidate_sequence=candidates[0]["sequence"],
            environment=HARNESS.fixture_environment(sample),
            cwd=tmp_path,
            timeout=10,
        )
    validation_environment = os.environ.copy()
    validation_environment.pop("GLAURUNG_RUNTIME_TRACE_BEGIN", None)
    validation_environment.pop("GLAURUNG_RUNTIME_TRACE_END", None)
    validation = subprocess.run(
        [binary, neighboring.decode()],
        check=True,
        capture_output=True,
        env=validation_environment,
        timeout=10,
    )
    assert b"SINK command ;" in validation.stdout
    assert b"RESULT metachar 1" in validation.stdout


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_counterfactual_neighbor_reaches_real_null_write_crash(tmp_path: Path) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import (
        capture_instruction_trace_child,
        validate_instruction_trace_counterfactual_child,
    )

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "crash_null_write"
    )
    counterfactual_sample = replace(
        sample,
        cflags=sample.cflags + ("-DGLAURUNG_RUNTIME_COUNTERFACTUAL_CRASH_FIXTURE",),
    )
    binary = HARNESS.compile_sample(counterfactual_sample, "gcc", "O0", "pie", tmp_path)
    supplied = b"cad"
    capture = capture_instruction_trace_child(
        binary,
        [supplied.decode()],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
        public_input=supplied,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    candidates = report["solver_query_candidates"]
    assert len(candidates) == 1, candidates
    counterfactual = candidates[0]["counterfactual"]
    if counterfactual["status"] == "unknown":
        assert counterfactual["reason_kind"] == "no_solver", counterfactual
        pytest.skip("native counterfactual solver is not compiled into this extension")
    assert counterfactual["status"] == "satisfiable", counterfactual
    neighboring = bytearray(supplied)
    for mutation in counterfactual["mutations"]:
        neighboring[mutation["source_offset"]] = int(mutation["replacement_hex"], 16)
    assert bytes(neighboring) == b"bad"

    validation_result = validate_instruction_trace_counterfactual_child(
        binary,
        capture.capsule_json,
        capture.payloads,
        [supplied.decode()],
        source_id=candidates[0]["source_id"],
        candidate_sequence=candidates[0]["sequence"],
        environment=HARNESS.fixture_environment(sample),
        timeout=10,
        expected_crash_class="null_write",
    )
    assert validation_result.materialized_input == b"bad"
    validation_relation = json.loads(validation_result.validation_json)
    assert validation_relation["status"] == "validated", validation_relation
    assert validation_relation["validation_kind"] == "crash_class"
    assert validation_relation["expected_crash_class"] == "null_write"
    assert validation_relation["observed_crash_class"]["value"] == "null_write"
    static_location = validation_relation["crash_static_location"]
    assert static_location["status"] == "inferred", static_location
    assert any(
        operation["kind"] == "store"
        for operation in static_location["value"]["address"]["code"]["operations"][
            "operations"
        ]
    )


@pytest.mark.slow
@pytest.mark.parametrize("compiler", ["gcc", "clang"])
@pytest.mark.parametrize("optimization", ["O0", "O2"])
@pytest.mark.parametrize("link", ["pie", "no-pie"])
def test_trace_relates_observed_indirect_call_without_mutating_static_cfg(
    tmp_path: Path,
    compiler: str,
    optimization: str,
    link: str,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.llm.kb.persistent import PersistentKnowledgeBase
    from glaurung.llm.kb.runtime_relations import (
        analyze_and_persist_instruction_trace,
        list_runtime_operation_occurrences,
        persist_process_capsule,
    )
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_command_argument"
    )
    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    instrumented = replace(
        sample,
        cflags=sample.cflags + ("-DGLAURUNG_RUNTIME_INDIRECT_TARGET_FIXTURE",),
    )
    binary = HARNESS.compile_sample(
        instrumented, compiler, optimization, link, tmp_path
    )
    capture = capture_instruction_trace_child(
        binary,
        ["cad"],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
        public_input=b"cad",
    )

    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )

    coverage = report["main_image_address_coverage"]
    assert coverage["status"] == "inferred", coverage
    assert coverage["value"]["observed_step_count"] > 0
    assert (
        coverage["value"]["exact_step_count"]
        == coverage["value"]["observed_step_count"]
    )
    assert coverage["value"]["failures"] == []
    assert report["observed_indirect_targets"]
    targets = [
        item
        for item in report["observed_indirect_targets"]
        if item["target"].get("status") == "inferred"
        and item["static_operation"].get("status") == "inferred"
        and item["static_operation"]["value"]["kind"] == "call"
        and item["static_operation"]["value"]["call_target"]["kind"] == "indirect"
    ]
    assert len(targets) == 1, report["observed_indirect_targets"]
    target = targets[0]
    assert target["static_operation"]["status"] == "inferred"
    assert target["static_operation"]["value"]["kind"] == "call"
    assert target["static_operation"]["value"]["call_target"]["kind"] == "indirect"
    static_call = target["static_operation"]["value"]
    assert static_call["call_target_expression_id"].startswith("static-expression-")
    assert static_call["call_target_value_id"].startswith("static-value-")
    target_values = [
        value
        for value in static_call["semantic_values"]
        if value["role"] == "call_target"
    ]
    assert len(target_values) == 1
    assert target_values[0]["id"] == static_call["call_target_value_id"]
    assert (
        target_values[0]["expression_root_id"]
        == static_call["call_target_expression_id"]
    )
    assert (
        target["target"]["value"]["source_static_va"]
        != target["target"]["value"]["target_static_va"]
    )
    assert target["target"]["value"]["transfer_kind"] == "indirect_call"
    assert target["operation_occurrence"]["status"] == "inferred"

    capsule = json.loads(capture.capsule_json)
    matching_event = next(
        event for event in capsule["events"] if event["sequence"] == target["sequence"]
    )
    matching_event["fields"]["after_address"] = str(0xDEADBEEF)
    wrong_target_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            json.dumps(capsule), list(capture.payloads), binary.read_bytes()
        )
    )
    wrong_target = next(
        item
        for item in wrong_target_report["observed_indirect_targets"]
        if item["sequence"] == target["sequence"]
    )
    assert wrong_target["target"]["status"] == "unknown"
    assert wrong_target["operation_occurrence"]["status"] == "unknown"

    wrong_image = bytearray(binary.read_bytes())
    wrong_image[-1] ^= 1
    wrong_image_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), bytes(wrong_image)
        )
    )
    assert wrong_image_report["main_image_address_coverage"]["status"] == "unknown"

    project = tmp_path / f"indirect-target-{compiler}-{optimization}-{link}.glaurung"
    with PersistentKnowledgeBase.open(project, binary_path=binary) as kb:
        persisted = persist_process_capsule(
            kb, capture.capsule_json, list(capture.payloads)
        )
        analyze_and_persist_instruction_trace(
            kb, persisted.capture_id, binary.read_bytes()
        )
        occurrences = list_runtime_operation_occurrences(
            kb, capture_id=persisted.capture_id
        )
    matching_occurrences = [
        occurrence
        for occurrence in occurrences
        if occurrence.event_sequence == target["sequence"]
        and occurrence.static_operation["kind"] == "call"
    ]
    assert len(matching_occurrences) == 1


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_counterfactual_unsat_retains_the_observed_prefix(tmp_path: Path) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_command_argument"
    )
    unsat_sample = replace(
        sample,
        cflags=sample.cflags + ("-DGLAURUNG_RUNTIME_COUNTERFACTUAL_UNSAT_FIXTURE",),
    )
    binary = HARNESS.compile_sample(unsat_sample, "gcc", "O0", "pie", tmp_path)
    supplied = b"cad"
    capture = capture_instruction_trace_child(
        binary,
        [supplied.decode()],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
        public_input=supplied,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    candidates = report["solver_query_candidates"]
    assert len(candidates) == 2, candidates
    if all(
        candidate["counterfactual"]["status"] == "unknown"
        and candidate["counterfactual"]["reason_kind"] == "no_solver"
        for candidate in candidates
    ):
        pytest.skip("native counterfactual solver is not compiled into this extension")
    unsatisfiable = [
        candidate
        for candidate in candidates
        if candidate["counterfactual"]["status"] == "unsatisfiable"
    ]
    assert len(unsatisfiable) == 1, candidates
    unsatisfiable_candidate = unsatisfiable[0]
    unsatisfiable_query = unsatisfiable_candidate["counterfactual"]
    assert unsatisfiable_query["backend"] == "axeyum-native"
    assert unsatisfiable_query["asserted_path_conditions"] == 2
    bounds = unsatisfiable_query["bounds"]
    assert bounds["first_event_sequence"] <= bounds["last_event_sequence"]
    assert bounds["observed_instruction_count"] > 0
    assert bounds["symbolic_input_byte_count"] == 1
    assert bounds["memory_snapshot_sequence"] < bounds["first_event_sequence"]
    assert bounds["captured_memory_byte_count"] > 0
    assert bounds["solver_timeout_ms"] > 0
    conditions = unsatisfiable_query["path_conditions"]
    assert [condition["role"] for condition in conditions] == [
        "observed_prefix",
        "negated_target",
    ]
    assert [condition["sequence"] for condition in conditions] == sorted(
        condition["sequence"] for condition in conditions
    )
    assert all(
        condition["static_operation"]["kind"] == "cond_jump" for condition in conditions
    )
    assert (
        conditions[-1]["static_operation"]
        == unsatisfiable_candidate["static_operation"]
    )
    assert (
        conditions[-1]["required_branch_taken"]
        is not unsatisfiable_candidate["observed_edge"]["branch_taken"]
    )
    satisfiable = [
        candidate
        for candidate in candidates
        if candidate["counterfactual"]["status"] == "satisfiable"
    ]
    assert len(satisfiable) == 1, candidates
    satisfiable_query = satisfiable[0]["counterfactual"]
    assert satisfiable_query["asserted_path_conditions"] == 1
    assert [
        condition["role"] for condition in satisfiable_query["path_conditions"]
    ] == ["negated_target"]


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.parametrize(
    ("fixture", "extra_flags", "error"),
    [
        (
            "heap_snapshot_no_object",
            [],
            "combined heap trace requires one main-module object at trace begin",
        ),
        (
            "heap_snapshot_multiple_objects",
            [],
            "combined heap trace requires one main-module object at trace begin",
        ),
        (
            "heap_snapshot_worker_object",
            ["-pthread"],
            "combined heap-provider event belongs to another thread",
        ),
        (
            "heap_snapshot_wrong_phase",
            [],
            "combined heap-provider events do not match checkpoint phases",
        ),
    ],
)
def test_combined_heap_trace_rejects_invalid_main_module_object_population(
    tmp_path: Path, fixture: str, extra_flags: list[str], error: str
) -> None:
    from glaurung.runtime_capture import capture_instruction_trace_child

    provider = tmp_path / "heap_snapshot_interposer.so"
    binary = tmp_path / fixture
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            str(ROOT / "tests/runtime_samples/support/heap_snapshot_interposer.c"),
            "-o",
            str(provider),
        ],
        check=True,
    )
    subprocess.run(
        [
            "gcc",
            "-std=c11",
            "-O0",
            "-fno-builtin",
            "-I",
            str(ROOT / "tests/runtime_samples/include"),
            str(ROOT / f"tests/runtime_samples/support/{fixture}.c"),
            *extra_flags,
            "-o",
            str(binary),
        ],
        check=True,
    )

    with pytest.raises(
        RuntimeError,
        match=error,
    ):
        capture_instruction_trace_child(binary, heap_interposer=provider, timeout=10)


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize(("scenario", "before_hex"), [("good", "00"), ("bad", "44")])
def test_instruction_trace_observes_direct_stack_store(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    compiler: str,
    link: str,
    scenario: str,
    before_hex: str,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item
        for item in HARNESS.load_samples()
        if item.id == "memory_struct_field_overwrite"
    )
    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        timeout=10,
    )
    capsule = json.loads(capture.capsule_json)
    assert capsule["identity"]["acquisition"] == "trace"
    assert capsule["processes"][0]["terminal"] == {"kind": "exited", "code": 0}
    assert '"before_hex"' not in capture.capsule_json
    assert '"after_hex"' not in capture.capsule_json
    steps = [
        event for event in capsule["events"] if event["kind"] == "instruction_step"
    ]
    assert 0 < len(steps) < 4096
    direct_changes = []
    payloads = dict(capture.payloads)
    for event in steps:
        payload_id = event["fields"].get("stack_changes_payload_id")
        if payload_id is None:
            continue
        assert "stack_changed_intervals" not in event["fields"]
        encoded = payloads[payload_id]
        assert (
            hashlib.sha256(encoded).hexdigest()
            == event["fields"]["stack_changes_sha256"]
        )
        assert len(encoded) == int(event["fields"]["stack_changes_byte_len"])
        step_evidence = json.loads(encoded)
        assert step_evidence["schema"] == "glaurung-instruction-step-evidence-v1"
        assert set(step_evidence["registers"]) >= {"rip", "rbp", "rsp", "rax"}
        for interval in step_evidence["changes"]:
            if interval["before_hex"] == before_hex and interval["after_hex"] == "aa":
                direct_changes.append((event, interval))
    assert len(direct_changes) == 1, direct_changes
    event, interval = direct_changes[0]
    assert interval["end"] == interval["start"] + 1
    assert event["address"] > 0
    assert int(event["fields"]["after_address"]) > 0
    snapshots = sorted(
        (
            item
            for item in capsule["object_snapshots"]
            if item["object_id"] == "object-instruction-trace-stack-mapping"
        ),
        key=lambda item: item["point"]["sequence"],
    )
    assert len(snapshots) == 2
    for snapshot in snapshots:
        payload = snapshot["content"]["payload"]
        assert hashlib.sha256(payloads[payload["id"]]).hexdigest() == payload["sha256"]

    from glaurung.llm.kb.persistent import PersistentKnowledgeBase
    from glaurung.llm.kb.runtime_relations import (
        analyze_and_persist_instruction_trace,
        list_runtime_analysis_reports,
        list_runtime_operation_occurrences,
        persist_process_capsule,
        runtime_capture_summary_json,
    )

    project = tmp_path / f"trace-{compiler}-{link}-{scenario}.glaurung"
    with PersistentKnowledgeBase.open(project, binary_path=binary) as kb:
        persisted_capture = persist_process_capsule(
            kb, capture.capsule_json, list(capture.payloads)
        )
        persisted_report = analyze_and_persist_instruction_trace(
            kb, persisted_capture.capture_id, binary.read_bytes()
        )
        persisted_occurrences = list_runtime_operation_occurrences(
            kb, capture_id=persisted_capture.capture_id
        )
        persisted_trace_summary = runtime_capture_summary_json(
            kb, persisted_capture.capture_id
        )
    report = json.loads(persisted_report.report_json)
    trace_summary = json.loads(persisted_trace_summary)
    assert trace_summary["counts"]["operation_occurrences"] == len(
        persisted_occurrences
    )
    assert len(trace_summary["observed_operations"]) == len(persisted_occurrences)
    assert all(
        "inputs" not in item and "effects" not in item
        for item in trace_summary["observed_operations"]
    )
    from glaurung.cli.main import main as cli_main

    assert (
        cli_main(
            [
                "runtime",
                "--json",
                "observed-xrefs",
                str(project),
                persisted_capture.capture_id,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == trace_summary["observed_operations"]
    assert report["schema"] == "glaurung-runtime-instruction-trace-report-v1"
    assert report["coverage"] == {
        "observed_steps": len(steps),
        "steps_with_stack_changes": sum(
            "stack_changes_payload_id" in step["fields"] for step in steps
        ),
        "compared_region": "fixed_bounded_stack_window",
        "broader_runtime_state": "partial",
    }
    matching = [
        relation
        for relation in report["relations"]
        if relation["changes"].get("status") == "observed"
        and relation["changes"]["value"]
        == [
            {
                "start": interval["start"],
                "end": interval["end"],
                "before_hex": before_hex,
                "after_hex": "aa",
            }
        ]
    ]
    assert len(matching) == 1, matching
    relation = matching[0]
    assert relation["runtime_instruction_va"] == event["address"]
    assert relation["address_resolution"]["verdict"] == "exact"
    assert relation["registers"]["status"] == "observed"
    effective_address = relation["effective_address"]
    assert effective_address["status"] == "inferred"
    assert effective_address["value"]["effective_address"] == interval["start"]
    assert effective_address["value"]["byte_len"] == 1
    if compiler == "gcc":
        assert effective_address["value"] == {
            "base_register": "rax",
            "base_value": interval["start"],
            "index_register": None,
            "index_value": None,
            "scale": 1,
            "displacement": 0,
            "effective_address": interval["start"],
            "byte_len": 1,
        }
    else:
        assert effective_address["value"]["base_register"] == "rbp"
        assert effective_address["value"]["index_register"] == "rax"
        assert effective_address["value"]["index_value"] == (
            7 if scenario == "good" else 8
        )
        assert effective_address["value"]["displacement"] == -28
    occurrence = relation["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    assert occurrence["value"]["static_operation"]["id"].startswith("static-operation-")
    assert occurrence["value"]["static_operation"]["function_id"].startswith(
        "static-function-"
    )
    assert occurrence["value"]["static_operation"]["block_id"].startswith(
        "static-block-"
    )
    assert occurrence["value"]["static_operation"]["kind"] == "store"
    address_expression = occurrence["value"]["static_operation"]["address_expression"]
    assert occurrence["value"]["static_operation"]["address_expression_id"].startswith(
        "static-expression-"
    )
    assert occurrence["value"]["static_operation"][
        "stored_value_expression_id"
    ].startswith("static-expression-")
    assert (
        occurrence["value"]["static_operation"]["address_expression_id"]
        != occurrence["value"]["static_operation"]["stored_value_expression_id"]
    )
    expression_nodes = occurrence["value"]["static_operation"]["expression_nodes"]
    expression_node_ids = {node["id"] for node in expression_nodes}
    expression_root_ids = {
        occurrence["value"]["static_operation"]["address_expression_id"],
        occurrence["value"]["static_operation"]["stored_value_expression_id"],
    }
    roots = [node for node in expression_nodes if node["path"] == ""]
    assert {node["id"] for node in roots} == expression_root_ids
    assert all(node["parent_id"] is None for node in roots)
    assert all(node["root_id"] in expression_root_ids for node in expression_nodes)
    assert all(
        node["parent_id"] is None or node["parent_id"] in expression_node_ids
        for node in expression_nodes
    )
    assert all(
        node["id"].startswith("static-expression-node-")
        for node in expression_nodes
        if node["path"]
    )
    semantic_values = occurrence["value"]["static_operation"]["semantic_values"]
    assert {value["role"] for value in semantic_values} == {
        "memory_address",
        "stored_value",
    }
    assert all(value["id"].startswith("static-value-") for value in semantic_values)
    assert all(
        value["operation_id"] == occurrence["value"]["static_operation"]["id"]
        for value in semantic_values
    )
    assert {value["expression_root_id"] for value in semantic_values} == (
        expression_root_ids
    )
    encoded_expression = json.dumps(address_expression, sort_keys=True)
    assert '"kind": "load"' in encoded_expression
    if compiler == "gcc":
        assert '"name": "rbp"' in encoded_expression
        assert '"value": -20' in encoded_expression
        assert '"value": -32' in encoded_expression
    assert occurrence["value"]["effects"] == [
        {
            "kind": "memory_write",
            "runtime_object_id": "object-instruction-trace-stack-mapping",
            "errno": None,
            "address": interval["start"],
            "byte_len": 1,
        }
    ]

    persisted_occurrence = next(
        item
        for item in persisted_occurrences
        if item.occurrence_id == occurrence["value"]["id"]
    )
    assert (
        persisted_occurrence.static_operation == occurrence["value"]["static_operation"]
    )
    assert occurrence["value"] in persisted_occurrence.evidence_records
    assert (
        persisted_occurrence.static_operation["id"]
        == occurrence["value"]["static_operation"]["id"]
    )
    assert (
        persisted_occurrence.static_operation["function_id"]
        == occurrence["value"]["static_operation"]["function_id"]
    )
    assert (
        persisted_occurrence.static_operation["block_id"]
        == occurrence["value"]["static_operation"]["block_id"]
    )
    assert len(persisted_occurrence.evidence_records) >= 2
    assert (
        len(
            {
                HARNESS.canonical_json(item["inputs"])
                for item in persisted_occurrence.evidence_records
            }
        )
        >= 2
    )

    with PersistentKnowledgeBase.open(project, binary_path=binary) as reopened:
        assert list_runtime_analysis_reports(
            reopened, capture_id=persisted_capture.capture_id
        ) == [persisted_report]
        assert (
            list_runtime_operation_occurrences(
                reopened, capture_id=persisted_capture.capture_id
            )
            == persisted_occurrences
        )
        assert (
            runtime_capture_summary_json(reopened, persisted_capture.capture_id)
            == persisted_trace_summary
        )

    stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    stack_matches = [
        item
        for item in stack_report["relations"]
        if item["sequence"] == event["sequence"]
        and item["operation_occurrence"].get("status") == "inferred"
    ]
    assert len(stack_matches) == 1, stack_matches
    stack_relation = stack_matches[0]
    assert (
        stack_relation["operation_occurrence"]["value"]["static_operation"]["kind"]
        == "store"
    )
    assert stack_relation["frame"]["status"] == "inferred", stack_relation
    assert stack_relation["frame"]["value"]["function_name"] == "main"
    assert stack_relation["object"]["status"] == "inferred", stack_relation
    assert stack_relation["object"]["value"]["source_name"] == "b"
    assert stack_relation["object"]["value"]["c_type"] == "struct box"
    assert stack_relation["field"]["status"] == "inferred", stack_relation
    assert stack_relation["field"]["value"]["name"] == (
        "data" if scenario == "good" else "canary"
    )
    assert stack_relation["bounds"]["value"]["classification"] == "within_field"
    derivation = stack_relation["address_derivation"]
    assert derivation["status"] == "inferred", stack_relation
    assert derivation["value"]["base_field"]["name"] == "data"
    assert derivation["value"]["element_index"] == (7 if scenario == "good" else 8)
    assert derivation["value"]["element_byte_len"] == 1
    assert derivation["value"]["effective_address"] == interval["start"]
    assert derivation["value"]["field_bytes_exceeded"] == (
        0 if scenario == "good" else 1
    )
    assert derivation["value"]["classification"] == (
        "within_field" if scenario == "good" else "crosses_field_boundary"
    )
    assert stack_relation["field_changes"]["status"] == "inferred", stack_relation
    changed_fields = {
        change["field"]["name"]: change
        for change in stack_relation["field_changes"]["value"]
    }
    assert set(changed_fields) == {"data", "canary"}
    target_change = changed_fields["data" if scenario == "good" else "canary"]
    assert target_change["changed_intervals"] == [
        {
            "field_offset_start": 7 if scenario == "good" else 0,
            "field_offset_end": 8 if scenario == "good" else 1,
            "before_hex": before_hex,
            "after_hex": "aa",
        }
    ]
    semantic_result = HARNESS.stack_write_semantic_result(
        stack_report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(semantic_result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert evaluation["matched"] == 2

    if scenario == "bad":
        change_payload_id = event["fields"]["stack_changes_payload_id"]
        without_change_payload = [
            item for item in capture.payloads if item[0] != change_payload_id
        ]
        incomplete = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                capture.capsule_json, without_change_payload, binary.read_bytes()
            )
        )
        incomplete_relation = next(
            item
            for item in incomplete["relations"]
            if item["runtime_instruction_va"] == event["address"]
        )
        assert incomplete_relation["changes"] == {
            "status": "unknown",
            "reason": (
                f"instruction-step change payload {change_payload_id} is unavailable"
            ),
        }
        assert incomplete_relation["operation_occurrence"]["status"] == "unknown"

        changed_step_payload = json.loads(payloads[change_payload_id])
        changed_step_payload["registers"]["rax"] = (
            f"{int(changed_step_payload['registers']['rax'], 16) + 1:016x}"
        )
        changed_step_bytes = json.dumps(
            changed_step_payload, sort_keys=True, separators=(",", ":")
        ).encode()
        event["fields"]["stack_changes_sha256"] = hashlib.sha256(
            changed_step_bytes
        ).hexdigest()
        event["fields"]["stack_changes_byte_len"] = str(len(changed_step_bytes))
        changed_capsule = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(capsule, separators=(",", ":"))
        )
        changed_payloads = [
            (
                payload_id,
                changed_step_bytes if payload_id == change_payload_id else data,
            )
            for payload_id, data in capture.payloads
        ]
        inconsistent = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                changed_capsule, changed_payloads, binary.read_bytes()
            )
        )
        inconsistent_relation = next(
            item
            for item in inconsistent["relations"]
            if item["runtime_instruction_va"] == event["address"]
        )
        assert inconsistent_relation["changes"]["status"] == "observed"
        assert inconsistent_relation["registers"]["status"] == "observed"
        assert inconsistent_relation["effective_address"] == {
            "status": "unknown",
            "reason": ("LLIR effective address disagrees with observed changed bytes"),
        }

        wrong_image = bytearray(binary.read_bytes())
        wrong_image[-1] ^= 1
        wrong = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                capture.capsule_json, list(capture.payloads), bytes(wrong_image)
            )
        )
        wrong_relation = next(
            item
            for item in wrong["relations"]
            if item["runtime_instruction_va"] == event["address"]
        )
        assert wrong_relation["address_resolution"]["verdict"] == "wrong_image"
        assert wrong_relation["operation_occurrence"]["status"] == "unknown"

        with pytest.raises(
            RuntimeError, match="instruction trace exhausted its step or time budget"
        ):
            capture_instruction_trace_child(
                binary,
                [HARNESS.scenario_arg(sample, scenario)],
                environment=HARNESS.fixture_environment(sample),
                cwd=tmp_path,
                max_steps=1,
                timeout=10,
            )


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang is unavailable")
@pytest.mark.parametrize(("scenario", "before_hex"), [("good", "00"), ("bad", "44")])
def test_optimized_direct_store_absence_is_scoped_to_trace_window(
    tmp_path: Path, scenario: str, before_hex: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item
        for item in HARNESS.load_samples()
        if item.id == "memory_struct_field_overwrite"
    )
    binary = HARNESS.compile_sample(sample, "clang", "O2", "pie", tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    assert report["coverage"]["observed_steps"] > 0
    assert report["coverage"]["compared_region"] == "fixed_bounded_stack_window"
    assert report["coverage"]["broader_runtime_state"] == "partial"
    assert not any(
        change["before_hex"] == before_hex and change["after_hex"] == "aa"
        for relation in report["relations"]
        if relation["changes"].get("status") == "observed"
        for change in relation["changes"]["value"]
    )


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize(
    ("scenario", "destination_field", "element_index"),
    [("good", "a", 3), ("bad", "canary", 4)],
)
def test_instruction_trace_recovers_multibyte_array_index(
    tmp_path: Path,
    compiler: str,
    link: str,
    scenario: str,
    destination_field: str,
    element_index: int,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_index_write"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    matches = [
        relation
        for relation in report["relations"]
        if relation["event_kind"] == "instruction_step"
        and relation["field"].get("value", {}).get("name") == destination_field
        and relation["address_derivation"]
        .get("value", {})
        .get("base_field", {})
        .get("name")
        == "a"
    ]
    assert len(matches) == 1, matches
    relation = matches[0]
    derivation = relation["address_derivation"]["value"]
    assert derivation["element_index"] == element_index
    assert derivation["element_byte_len"] == 4
    assert derivation["field_bytes_exceeded"] == (0 if scenario == "good" else 4)
    assert derivation["classification"] == (
        "within_field" if scenario == "good" else "crosses_field_boundary"
    )
    result = HARNESS.stack_write_semantic_result(
        report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert evaluation["matched"] == 2


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize("scenario", ["good", "bad"])
def test_instruction_trace_recovers_off_by_one_terminator(
    tmp_path: Path, compiler: str, link: str, scenario: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_off_by_one"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    result = HARNESS.stack_write_semantic_result(
        report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert evaluation["matched"] == 2
    if scenario == "bad":
        relations = [
            relation
            for relation in report["relations"]
            if relation["field"].get("value", {}).get("name") == "tag"
            and relation["address_derivation"].get("value", {}).get("element_index")
            == 8
        ]
        assert len(relations) == 1, relations
        operation = relations[0]["operation_occurrence"]["value"]["static_operation"]
        assert operation["stored_value"] == {"kind": "constant", "value": 0}
        assert (
            relations[0]["address_derivation"]["value"]["base_field"]["name"] == "text"
        )


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("ltrace") is None, reason="ltrace is unavailable")
def test_environment_trace_records_actual_getenv_with_redacted_byte_identity(
    tmp_path: Path,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_environment_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_environment_path"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    environment = HARNESS.fixture_environment(sample)
    environment["PATH"] = "/controlled/search/path"
    capture = capture_environment_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=environment,
        selected_environment=["PATH"],
        cwd=tmp_path,
        public_input=b"bad",
    )
    capsule = json.loads(capture.capsule_json)
    events = [
        event for event in capsule["events"] if event["kind"] == "environment_read"
    ]
    assert len(events) == 1
    event = events[0]
    assert event["fields"]["name"] == "PATH"
    assert event["fields"]["result"] == "present"
    assert event["fields"]["content_redacted"] == "true"
    assert "content_hex" not in event["fields"]
    source_name = event["fields"]["input_source_name"]
    provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(capture.capsule_json)
    )
    source = next(
        source for source in provenance["sources"] if source["name"] == source_name
    )
    assert source["sensitivity"] == "sensitive"
    assert source["byte_len"] == len(environment["PATH"].encode())
    assert source["sha256"] == hashlib.sha256(environment["PATH"].encode()).hexdigest()
    byte = json.loads(
        runtime_analysis.resolve_process_capsule_input_byte(
            capture.capsule_json, source_name, 0
        )
    )
    assert byte["source_id"] == source["id"]
    completeness = {item["evidence"]: item for item in capsule["completeness"]}
    assert completeness["environment_events"]["status"] == "complete"

    public_capture = capture_environment_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=environment,
        selected_environment=["PATH"],
        public_environment=["PATH"],
        cwd=tmp_path,
        public_input=b"bad",
    )
    public_capsule = json.loads(public_capture.capsule_json)
    public_event = next(
        event
        for event in public_capsule["events"]
        if event["kind"] == "environment_read"
    )
    assert (
        bytes.fromhex(public_event["fields"]["content_hex"]).decode()
        == environment["PATH"]
    )
    assert public_capsule["identity"]["capture_id"] != capsule["identity"]["capture_id"]

    with pytest.raises(ValueError, match="were not read: HOME"):
        capture_environment_trace_child(
            binary,
            [HARNESS.scenario_arg(sample, "bad")],
            environment={**environment, "HOME": "/controlled/home"},
            selected_environment=["HOME"],
            cwd=tmp_path,
        )


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize("scenario", ["good", "bad"])
def test_file_trace_preserves_resource_identity_across_duplication(
    tmp_path: Path, scenario: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(item for item in HARNESS.load_samples() if item.id == "normal_dup_fd")
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_paths=["/dev/null"],
        public_content_paths=["/dev/null"],
    )
    capsule = json.loads(capture.capsule_json)
    opened = next(
        event
        for event in capsule["events"]
        if event["kind"] == "file_open" and event["fields"].get("path") == "/dev/null"
    )
    resource_id = opened["fields"]["resource_id"]
    linked = [
        event
        for event in capsule["events"]
        if event["fields"].get("resource_id") == resource_id
    ]
    assert [event["kind"] for event in linked] == [
        "file_open",
        "file_dup",
        "file_write",
        "file_close",
        "file_close",
    ]
    source_descriptor = opened["fields"]["descriptor"]
    duplicate_descriptor = linked[1]["fields"]["duplicate_descriptor"]
    assert linked[1]["fields"]["source_descriptor"] == source_descriptor
    assert linked[2]["fields"]["descriptor"] == duplicate_descriptor
    assert {linked[3]["fields"]["descriptor"], linked[4]["fields"]["descriptor"]} == {
        source_descriptor,
        duplicate_descriptor,
    }

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(capture.capsule_json)
    )
    duplication = next(
        item for item in behavior["duplications"] if item["resource_id"] == resource_id
    )
    assert duplication["source_descriptor"] == int(source_descriptor)
    assert duplication["outcome"]["value"] == int(duplicate_descriptor)

    result = HARNESS.file_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"]
    assert evaluation["matched"] == 2
    duplication_fact = next(
        fact for fact in result["facts"] if fact["predicate"] == "duplication"
    )
    assert duplication_fact["value"] == "open->dup->write:length=1->close_both"

    incomplete = json.loads(capture.capsule_json)
    incomplete["events"].remove(
        next(
            event
            for event in incomplete["events"]
            if event["kind"] == "file_close"
            and event["fields"].get("resource_id") == resource_id
        )
    )
    incomplete_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(incomplete)
    )
    incomplete_result = HARNESS.file_semantic_result(
        incomplete_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    incomplete_evaluation = HARNESS.evaluate_semantic_result(incomplete_result, oracle)
    assert not incomplete_evaluation["passed"]
    assert incomplete_evaluation["matched"] == 0
    assert incomplete_evaluation["failures"] == [
        {
            "fact": ("os_event", "descriptor:/dev/null", "duplication"),
            "error": "missing",
        }
    ]
    assert len(incomplete_evaluation["incomplete"]) == 1


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize("scenario", ["good", "bad"])
def test_descriptor_trace_normalizes_pipe_roundtrip_with_policy_identity(
    tmp_path: Path, scenario: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "normal_pipe_roundtrip"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_ipc_content=True,
    )
    capsule = json.loads(capture.capsule_json)
    descriptor_events = [
        event for event in capsule["events"] if event["kind"].startswith("descriptor_")
    ]
    assert [event["kind"] for event in descriptor_events] == [
        "descriptor_pipe_create",
        "descriptor_write",
        "descriptor_read",
        "descriptor_close",
        "descriptor_close",
    ]
    resource_id = descriptor_events[0]["fields"]["resource_id"]
    assert resource_id.startswith("pipe-")
    assert all(
        event["fields"]["resource_id"] == resource_id for event in descriptor_events
    )
    assert descriptor_events[1]["fields"]["content_hex"] == "51"
    assert descriptor_events[2]["fields"]["content_hex"] == "51"
    read_input_name = descriptor_events[2]["fields"]["input_source_name"]
    assert "input_source_name" not in descriptor_events[1]["fields"]
    provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(capture.capsule_json)
    )
    read_source = next(
        source for source in provenance["sources"] if source["name"] == read_input_name
    )
    assert read_source["byte_len"] == 1
    assert read_source["sensitivity"] == "public"
    assert (
        json.loads(
            runtime_analysis.resolve_process_capsule_input_byte(
                capture.capsule_json, read_input_name, 0
            )
        )["source_id"]
        == read_source["id"]
    )

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_descriptor_behavior(
            capture.capsule_json
        )
    )
    assert behavior["schema"] == "glaurung-runtime-descriptor-behavior-report-v1"
    assert behavior["event_scope"]["status"] == "observed"
    assert len(behavior["resources"]) == 1
    assert [item["operation"] for item in behavior["transfers"]] == [
        "write",
        "read",
    ]
    assert all(item["content"].get("value") == "51" for item in behavior["transfers"])
    assert (
        next(item for item in behavior["transfers"] if item["operation"] == "read")[
            "input_source_name"
        ]
        == read_input_name
    )
    assert len(behavior["closes"]) == 2

    relations = json.loads(
        runtime_analysis.correlate_process_capsule_input_events(
            capture.capsule_json, binary.read_bytes()
        )
    )
    assert len(relations["relations"]) == 1
    relation = relations["relations"][0]
    assert relation["event_kind"] == "descriptor_read"
    assert relation["input_source"]["value"] == read_source
    assert relation["operation_occurrence"]["status"] == "inferred"
    assert relation["operation_occurrence"]["value"]["introduced_input_sources"] == [
        read_source
    ]

    result = HARNESS.descriptor_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"]
    assert evaluation["matched"] == 2
    roundtrip = next(
        fact for fact in result["facts"] if fact["predicate"] == "roundtrip"
    )
    assert roundtrip["value"] == "write:51:length=1->read:51:length=1"
    roundtrip["value"] += ":mutated"
    assert not HARNESS.evaluate_semantic_result(result, oracle)["passed"]

    tampered = json.loads(capture.capsule_json)
    tampered_transfer = next(
        event for event in tampered["events"] if event["kind"] == "descriptor_write"
    )
    tampered_transfer["fields"]["content_hex"] = "52"
    tampered_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(tampered)
    )
    tampered_behavior = json.loads(
        runtime_analysis.analyze_process_capsule_descriptor_behavior(tampered_json)
    )
    assert tampered_behavior["transfers"][0]["content"]["status"] == "unknown"
    tampered_result = HARNESS.descriptor_semantic_result(
        tampered_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    tampered_evaluation = HARNESS.evaluate_semantic_result(tampered_result, oracle)
    assert not tampered_evaluation["passed"]
    assert tampered_evaluation["matched"] == 1

    private_capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_ipc_content=False,
    )
    private_capsule = json.loads(private_capture.capsule_json)
    assert (
        private_capsule["identity"]["capture_id"] != capsule["identity"]["capture_id"]
    )
    private_transfers = [
        event
        for event in private_capsule["events"]
        if event["kind"] in {"descriptor_read", "descriptor_write"}
    ]
    assert private_transfers
    assert all(
        event["fields"]["content_redacted"] == "true"
        and "content_hex" not in event["fields"]
        for event in private_transfers
    )
    private_behavior = json.loads(
        runtime_analysis.analyze_process_capsule_descriptor_behavior(
            private_capture.capsule_json
        )
    )
    assert all(
        item["content"]["status"] == "unknown" for item in private_behavior["transfers"]
    )
    private_read = next(
        event for event in private_transfers if event["kind"] == "descriptor_read"
    )
    private_provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(private_capture.capsule_json)
    )
    private_source = next(
        source
        for source in private_provenance["sources"]
        if source["name"] == private_read["fields"]["input_source_name"]
    )
    assert private_source["sensitivity"] == "sensitive"
    assert "content_hex" not in private_read["fields"]


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize("scenario", ["good", "bad"])
def test_descriptor_trace_normalizes_bidirectional_socketpair(
    tmp_path: Path, scenario: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "normal_socketpair"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_ipc_content=True,
    )
    capsule = json.loads(capture.capsule_json)
    descriptor_events = [
        event for event in capsule["events"] if event["kind"].startswith("descriptor_")
    ]
    assert [event["kind"] for event in descriptor_events] == [
        "descriptor_socketpair_create",
        "descriptor_send",
        "descriptor_recv",
        "descriptor_close",
        "descriptor_close",
    ]
    resource_id = descriptor_events[0]["fields"]["resource_id"]
    assert resource_id.startswith("socketpair-")
    assert all(
        event["fields"]["resource_id"] == resource_id for event in descriptor_events
    )
    assert descriptor_events[0]["fields"]["domain"] == "AF_UNIX"
    assert descriptor_events[0]["fields"]["socket_type"] == "SOCK_STREAM"

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_descriptor_behavior(
            capture.capsule_json
        )
    )
    resource = behavior["resources"][0]
    assert resource["kind"] == "socketpair"
    assert resource["domain"] == "AF_UNIX"
    assert resource["socket_type"] == "SOCK_STREAM"
    assert {endpoint["role"] for endpoint in resource["endpoints"]} == {
        "peer0",
        "peer1",
    }
    assert [item["operation"] for item in behavior["transfers"]] == [
        "send",
        "recv",
    ]
    assert all(item["content"].get("value") == "53" for item in behavior["transfers"])

    result = HARNESS.descriptor_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"]
    assert evaluation["matched"] == 2
    roundtrip = next(
        fact for fact in result["facts"] if fact["predicate"] == "roundtrip"
    )
    assert roundtrip["value"] == "send:53:length=1->recv:53:length=1"

    wrong_role = json.loads(capture.capsule_json)
    send_event = next(
        event for event in wrong_role["events"] if event["kind"] == "descriptor_send"
    )
    send_event["fields"]["endpoint"] = "read"
    wrong_role_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(wrong_role)
    )
    wrong_role_behavior = json.loads(
        runtime_analysis.analyze_process_capsule_descriptor_behavior(wrong_role_json)
    )
    assert wrong_role_behavior["ignored_events"] == 1
    assert [item["operation"] for item in wrong_role_behavior["transfers"]] == ["recv"]
    wrong_role_result = HARNESS.descriptor_semantic_result(
        wrong_role_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    assert not HARNESS.evaluate_semantic_result(wrong_role_result, oracle)["passed"]


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize(
    ("scenario", "expected_address", "finding_count"),
    [("good", "127.0.0.1", 0), ("bad", "0.0.0.0", 1)],
)
def test_descriptor_trace_contextualizes_inet_bind_without_inventing_listener(
    tmp_path: Path,
    scenario: str,
    expected_address: str,
    finding_count: int,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_bind_listener"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
    )
    capsule = json.loads(capture.capsule_json)
    descriptor_events = [
        event for event in capsule["events"] if event["kind"].startswith("descriptor_")
    ]
    assert [event["kind"] for event in descriptor_events] == [
        "descriptor_socket_create",
        "descriptor_bind",
        "descriptor_close",
    ]
    resource_id = descriptor_events[0]["fields"]["resource_id"]
    assert descriptor_events[1]["fields"]["resource_id"] == resource_id
    assert descriptor_events[1]["fields"]["address"] == expected_address
    assert descriptor_events[1]["fields"]["port"] == "0"

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_descriptor_behavior(
            capture.capsule_json
        )
    )
    assert behavior["resources"][0]["kind"] == "socket"
    assert behavior["binds"][0]["address"] == expected_address
    assert behavior["binds"][0]["port"] == 0
    assert behavior["listens"] == []
    assert len(behavior["dangerous_findings"]) == finding_count
    if finding_count:
        assert behavior["dangerous_findings"][0]["kind"] == "wildcard_bind"

    result = HARNESS.descriptor_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"]
    assert evaluation["matched"] == 2
    bind_fact = next(
        fact for fact in result["facts"] if fact["predicate"] == "bind_endpoint"
    )
    assert bind_fact["value"] == f"{expected_address}:ephemeral"

    wrong_resource = json.loads(capture.capsule_json)
    bind_event = next(
        event
        for event in wrong_resource["events"]
        if event["kind"] == "descriptor_bind"
    )
    bind_event["fields"]["resource_id"] = "socket-unrelated"
    wrong_resource_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(wrong_resource)
    )
    wrong_result = HARNESS.descriptor_semantic_result(
        wrong_resource_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    wrong_evaluation = HARNESS.evaluate_semantic_result(wrong_result, oracle)
    assert not wrong_evaluation["passed"]
    assert wrong_evaluation["matched"] == 1


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize(
    ("scenario", "path", "expected_result"),
    [
        ("good", "/dev/null", "success:file_type=character_device"),
        ("bad", "missing", "failure:ENOENT"),
    ],
)
def test_file_trace_normalizes_authorized_stat_result(
    tmp_path: Path, scenario: str, path: str, expected_result: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "normal_stat_file"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_paths=[path],
    )
    capsule = json.loads(capture.capsule_json)
    stat_events = [event for event in capsule["events"] if event["kind"] == "file_stat"]
    public_events = [
        event for event in stat_events if event["fields"].get("path") == path
    ]
    assert len(public_events) == 1
    assert public_events[0]["fields"]["resource_id"].startswith("file-stat-")
    assert all(
        "path" not in event["fields"]
        for event in stat_events
        if event["fields"]["path_redacted"] == "true"
    )

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(capture.capsule_json)
    )
    public_stats = [
        stated for stated in behavior["stats"] if stated["path"].get("value") == path
    ]
    assert len(public_stats) == 1
    assert public_stats[0]["outcome"]["status"] == "observed"

    result = HARNESS.file_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"]
    assert evaluation["matched"] == 2
    stat_fact = next(
        fact for fact in result["facts"] if fact["predicate"] == "stat_result"
    )
    assert stat_fact["value"] == expected_result
    stat_fact["value"] += ":mutated"
    assert not HARNESS.evaluate_semantic_result(result, oracle)["passed"]

    tampered = json.loads(capture.capsule_json)
    tampered_event = next(
        event
        for event in tampered["events"]
        if event["kind"] == "file_stat" and event["fields"].get("path") == path
    )
    tampered_event["fields"]["path"] += "-tampered"
    tampered_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(tampered)
    )
    tampered_behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(tampered_json)
    )
    tampered_stat = next(
        stated
        for stated in tampered_behavior["stats"]
        if stated["resource_id"] == tampered_event["fields"]["resource_id"]
    )
    assert tampered_stat["path"]["status"] == "unknown"


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize(
    ("scenario", "expected_mode", "world_writable"),
    [("good", "0600", False), ("bad", "0666", True)],
)
def test_file_trace_normalizes_world_writable_chmod(
    tmp_path: Path,
    scenario: str,
    expected_mode: str,
    world_writable: bool,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_world_writable"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_paths=["permissions.out"],
    )
    capsule = json.loads(capture.capsule_json)
    chmod_events = [
        event
        for event in capsule["events"]
        if event["kind"] == "file_chmod"
        and event["fields"].get("path") == "permissions.out"
    ]
    assert len(chmod_events) == 1
    chmod_event = chmod_events[0]
    assert chmod_event["fields"]["mode"] == expected_mode
    assert chmod_event["fields"]["result"] == "success"
    assert chmod_event["fields"]["resource_id"].startswith("file-chmod-")
    assert f"{tmp_path.joinpath('permissions.out').stat().st_mode & 0o7777:04o}" == (
        expected_mode
    )

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(capture.capsule_json)
    )
    chmods = [
        chmod
        for chmod in behavior["chmods"]
        if chmod["path"].get("value") == "permissions.out"
    ]
    assert len(chmods) == 1
    assert chmods[0]["mode"] == expected_mode
    assert chmods[0]["outcome"]["value"] == "success"
    findings = [
        finding
        for finding in behavior["dangerous_findings"]
        if finding["kind"] == "world_writable"
    ]
    assert bool(findings) is world_writable

    result = HARNESS.file_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"]
    assert evaluation["matched"] == 2

    mutated = json.loads(json.dumps(result))
    mode_fact = next(
        fact for fact in mutated["facts"] if fact["predicate"] == "mode_after_chmod"
    )
    mode_fact["value"] = "0777"
    mutation_evaluation = HARNESS.evaluate_semantic_result(mutated, oracle)
    assert mutation_evaluation["passed"] is False
    assert mutation_evaluation["failures"][0]["error"] == "value_mismatch"

    malformed = json.loads(capture.capsule_json)
    malformed_event = next(
        event
        for event in malformed["events"]
        if event["kind"] == "file_chmod"
        and event["fields"].get("path") == "permissions.out"
    )
    malformed_event["fields"]["mode"] = "not-octal"
    malformed_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(malformed)
    )
    malformed_result = HARNESS.file_semantic_result(
        malformed_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    malformed_evaluation = HARNESS.evaluate_semantic_result(malformed_result, oracle)
    assert malformed_evaluation["passed"] is False
    assert malformed_evaluation["matched"] == 0


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize(("scenario", "expected_children"), [("good", 1), ("bad", 3)])
def test_process_trace_normalizes_created_and_reaped_children(
    tmp_path: Path,
    scenario: str,
    expected_children: int,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_fork_tree"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
    )
    capsule = json.loads(capture.capsule_json)
    creates = [
        event
        for event in capsule["events"]
        if event["kind"] == "process_create"
        and event["fields"].get("result") == "success"
    ]
    waits = [
        event
        for event in capsule["events"]
        if event["kind"] == "process_wait"
        and event["fields"].get("result") == "success"
    ]
    assert len(creates) == expected_children
    assert len(waits) == expected_children
    created_pids = {event["fields"]["child_os_pid"] for event in creates}
    reaped_pids = {event["fields"]["reaped_os_pid"] for event in waits}
    assert created_pids == reaped_pids
    process_scope = next(
        item for item in capsule["completeness"] if item["evidence"] == "process_events"
    )
    assert process_scope["status"] == "complete"
    assert process_scope["obtained"] == process_scope["expected"]

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_process_behavior(capture.capsule_json)
    )
    assert behavior["schema"] == "glaurung-runtime-process-behavior-report-v1"
    assert behavior["event_scope"]["status"] == "observed"
    assert behavior["ignored_events"] == 0
    successful_creations = [
        creation
        for creation in behavior["creations"]
        if creation["outcome"].get("value", {}).get("kind") == "success"
    ]
    successful_waits = [
        wait
        for wait in behavior["waits"]
        if wait["outcome"].get("value", {}).get("kind") == "success"
    ]
    assert len(successful_creations) == expected_children
    assert len(successful_waits) == expected_children

    result = HARNESS.process_tree_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"], evaluation
    assert evaluation["matched"] == 2

    mutated = json.loads(json.dumps(result))
    created_fact = next(
        fact for fact in mutated["facts"] if fact["predicate"] == "children_created"
    )
    created_fact["value"] = str(expected_children + 1)
    mutation_evaluation = HARNESS.evaluate_semantic_result(mutated, oracle)
    assert mutation_evaluation["passed"] is False
    assert any(
        failure["error"] == "value_mismatch"
        for failure in mutation_evaluation["failures"]
    )

    malformed = json.loads(capture.capsule_json)
    malformed_wait = next(
        event
        for event in malformed["events"]
        if event["kind"] == "process_wait"
        and event["fields"].get("result") == "success"
    )
    malformed_wait["fields"]["reaped_os_pid"] = "999999999"
    malformed_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(malformed)
    )
    malformed_result = HARNESS.process_tree_semantic_result(
        malformed_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    malformed_evaluation = HARNESS.evaluate_semantic_result(malformed_result, oracle)
    assert malformed_evaluation["passed"] is False
    assert malformed_evaluation["matched"] == 0

    dropped = json.loads(capture.capsule_json)
    dropped["events"].remove(
        next(event for event in dropped["events"] if event["kind"] == "process_wait")
    )
    dropped_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(dropped)
    )
    dropped_behavior = json.loads(
        runtime_analysis.analyze_process_capsule_process_behavior(dropped_json)
    )
    assert dropped_behavior["event_scope"]["status"] == "unknown"
    dropped_result = HARNESS.process_tree_semantic_result(
        dropped_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    dropped_evaluation = HARNESS.evaluate_semantic_result(dropped_result, oracle)
    assert dropped_evaluation["passed"] is False
    assert dropped_evaluation["matched"] == 0


def test_process_trace_does_not_misclassify_clone_thread_as_child() -> None:
    from glaurung.runtime_capture import _parse_os_trace

    capsule = {
        "processes": [{"id": "process-main", "os_pid": 10}],
        "threads": [],
    }
    trace = (
        "10 clone(child_stack=0x1000, "
        "flags=CLONE_VM|CLONE_THREAD|CLONE_SIGHAND, "
        "child_tidptr=0x2000) = 11\n"
    )
    assert _parse_os_trace(trace, capsule) == []


def test_strace_ioctl_request_decoder_recovers_linux_request_identity() -> None:
    from glaurung.runtime_capture import _trace_ioctl_request

    assert _trace_ioctl_request("_IOC(_IOC_NONE, 0, 0, 0)") == 0
    assert (
        _trace_ioctl_request("_IOC(_IOC_READ|_IOC_WRITE, 0xbe, 0xef, 0x1ead)")
        == 0xDEADBEEF
    )
    assert _trace_ioctl_request("UNSUPPORTED_IOCTL") is None


def test_raw_stdin_read_requires_complete_returned_byte_dump() -> None:
    from glaurung.runtime_capture import _normalize_stdin_raw_reads

    trace = "123 read(0, 0x7000, 0x8) = 0x3\n | 00000  41 42"
    with pytest.raises(ValueError, match="read byte dump is missing"):
        _normalize_stdin_raw_reads(trace)


def test_tracked_ioctl_with_unsupported_provider_spelling_fails_closed() -> None:
    from glaurung.runtime_capture import _parse_os_trace

    capsule = {"processes": [{"id": "process-main"}], "threads": []}
    trace = (
        '1 openat(AT_FDCWD, "/dev/null", O_RDONLY) = 3\n'
        "1 ioctl(3, UNSUPPORTED_IOCTL, 0) = -1 ENOTTY (unsupported)\n"
    )
    with pytest.raises(
        ValueError,
        match="in-scope operation on a tracked file resource could not be normalized",
    ):
        _parse_os_trace(trace, capsule, public_paths=["/dev/null"])


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize(
    ("scenario", "expected_request", "expected_matched", "expected_passed"),
    [
        ("good", 0, 2, True),
        ("bad", 0xDEADBEEF, 1, False),
    ],
)
def test_ioctl_trace_retains_request_without_inventing_input_taint(
    tmp_path: Path,
    scenario: str,
    expected_request: int,
    expected_matched: int,
    expected_passed: bool,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_ioctl_input"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        public_paths=["/dev/null"],
    )
    capsule = json.loads(capture.capsule_json)
    provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(capture.capsule_json)
    )
    assert provenance["schema"] == "glaurung-runtime-input-provenance-v1"
    assert provenance["capture_id"] == capsule["identity"]["capture_id"]
    assert len(provenance["sources"]) == 1
    input_source = provenance["sources"][0]
    assert input_source["name"] == "argv[1]"
    assert input_source["byte_len"] == len(scenario)
    assert input_source["byte_identity"] == "(source_id,offset)"
    input_bytes = [
        json.loads(
            runtime_analysis.resolve_process_capsule_input_byte(
                capture.capsule_json, "argv[1]", offset
            )
        )
        for offset in range(len(scenario))
    ]
    assert {item["source_id"] for item in input_bytes} == {input_source["id"]}
    assert [item["offset"] for item in input_bytes] == list(range(len(scenario)))
    assert len({item["id"] for item in input_bytes}) == len(scenario)
    assert input_bytes[0] == json.loads(
        runtime_analysis.resolve_process_capsule_input_byte(
            capture.capsule_json, "argv[1]", 0
        )
    )
    with pytest.raises(ValueError, match="outside argv\\[1\\] length"):
        runtime_analysis.resolve_process_capsule_input_byte(
            capture.capsule_json, "argv[1]", len(scenario)
        )
    event = next(event for event in capsule["events"] if event["kind"] == "file_ioctl")
    assert event["fields"]["request"] == f"0x{expected_request:08x}"
    assert event["fields"]["result"] == "-1"
    assert event["fields"]["errno"] == "ENOTTY"
    assert event["fields"]["user_frame_artifact_sha256"] == HARNESS.sha256(binary)
    assert int(event["fields"]["user_return_module_offset"]) > 0
    assert event["fields"]["provider_user_frame_symbol"].startswith("main+")
    assert capsule["provider.strace"]["user_stack_frames"] is True

    behavior = json.loads(
        runtime_analysis.analyze_process_capsule_file_behavior(capture.capsule_json)
    )
    assert behavior["ignored_events"] == 0
    assert behavior["ioctls"] == [
        {
            "process_id": event["process_id"],
            "thread_id": event.get("thread_id"),
            "sequence": event["sequence"],
            "resource_id": event["fields"]["resource_id"],
            "descriptor": int(event["fields"]["descriptor"]),
            "request": expected_request,
            "scalar_argument": "0",
            "result": {
                "status": "observed",
                "value": -1,
                "source": "normalized ioctl kernel result",
            },
            "errno": "ENOTTY",
            "user_return_module_offset": int(
                event["fields"]["user_return_module_offset"]
            ),
            "user_frame_artifact_sha256": HARNESS.sha256(binary),
        }
    ]
    relations = json.loads(
        runtime_analysis.correlate_process_capsule_ioctl_events(
            capture.capsule_json, binary.read_bytes()
        )
    )
    assert relations["schema"] == "glaurung-runtime-ioctl-event-relation-v1"
    assert len(relations["relations"]) == 1
    relation = relations["relations"][0]
    assert relation["request"] == expected_request
    assert relation["static_callsite"]["status"] == "inferred", relation[
        "static_callsite"
    ]
    callsite = relation["static_callsite"]["value"]
    assert callsite["static_instruction_va"] < callsite["observed_return_module_offset"]
    assert callsite["code"]["verdict"] == "resolved"
    assert callsite["code"]["instruction_end"] == callsite["static_return_va"]
    assert any(
        operation["kind"] == "call"
        for operation in callsite["code"]["operations"]["operations"]
    )
    occurrence = relation["operation_occurrence"]
    assert occurrence["status"] == "inferred"
    occurrence_value = occurrence["value"]
    assert occurrence_value["id"].startswith("operation-occurrence-")
    assert occurrence_value["capture_id"] == capsule["identity"]["capture_id"]
    assert occurrence_value["event_sequence"] == event["sequence"]
    assert occurrence_value["static_operation"]["kind"] == "call"
    assert occurrence_value["inputs"]["request"]["value"] == (
        f"0x{expected_request:08x}"
    )
    assert occurrence_value["inputs"]["scalar_argument"]["value"] == "0"
    assert occurrence_value["output"]["value"] == -1
    assert occurrence_value["effects"] == [
        {
            "kind": "file_ioctl",
            "resource_id": event["fields"]["resource_id"],
            "errno": "ENOTTY",
        }
    ]

    tampered = json.loads(capture.capsule_json)
    tampered_ioctl = next(
        item for item in tampered["events"] if item["kind"] == "file_ioctl"
    )
    tampered_ioctl["fields"]["user_frame_artifact_sha256"] = "0" * 64
    tampered_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(tampered)
    )
    tampered_relations = json.loads(
        runtime_analysis.correlate_process_capsule_ioctl_events(
            tampered_json, binary.read_bytes()
        )
    )
    assert tampered_relations["relations"][0]["static_callsite"] == {
        "status": "unknown",
        "reason": "IOCTL user frame is not bound to the exact static image",
    }
    assert tampered_relations["relations"][0]["operation_occurrence"]["status"] == (
        "unknown"
    )
    wrong_return = json.loads(capture.capsule_json)
    wrong_return_ioctl = next(
        item for item in wrong_return["events"] if item["kind"] == "file_ioctl"
    )
    wrong_return_ioctl["fields"]["user_return_module_offset"] = str(
        int(wrong_return_ioctl["fields"]["user_return_module_offset"]) + 1
    )
    wrong_return_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(wrong_return)
    )
    wrong_return_relations = json.loads(
        runtime_analysis.correlate_process_capsule_ioctl_events(
            wrong_return_json, binary.read_bytes()
        )
    )
    assert wrong_return_relations["relations"][0]["static_callsite"] == {
        "status": "unknown",
        "reason": (
            "IOCTL return offset is not immediately after an exact LLIR call operation"
        ),
    }

    result = HARNESS.file_semantic_result(
        capture.capsule_json,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link="pie",
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["matched"] == expected_matched
    assert evaluation["passed"] is expected_passed
    ioctl_fact = next(
        fact for fact in result["facts"] if fact["predicate"] == "ioctl_request"
    )
    assert ioctl_fact["value"] == f"0x{expected_request:08x}:result=-1"
    ioctl_fact["value"] += ":mutated"
    assert not HARNESS.evaluate_semantic_result(result, oracle)["passed"]

    if scenario == "bad":
        assert not any(fact["kind"] == "dataflow" for fact in result["facts"])


@pytest.mark.slow
@pytest.mark.parametrize("compiler", ["gcc", "clang"])
@pytest.mark.parametrize("opt", ["O0", "O2"])
@pytest.mark.parametrize("link", ["pie", "no-pie"])
def test_instruction_trace_carries_argv_byte_to_command_memory(
    tmp_path: Path, compiler: str, opt: str, link: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_command_argument"
    )
    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    binary = HARNESS.compile_sample(sample, compiler, opt, link, tmp_path)
    supplied = b"bad"
    capture = capture_instruction_trace_child(
        binary,
        [supplied.decode()],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=10,
        public_input=supplied,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    assert report["solver_query_candidates"] == []
    block_relations = report["observed_blocks"]
    blocks = [
        item["relation"]["value"]
        for item in block_relations
        if item["relation"]["status"] == "inferred"
    ]
    assert blocks, block_relations
    assert len({block["id"] for block in blocks}) == len(blocks)
    for block in blocks:
        assert block["capture_id"] == report["capture_id"]
        assert block["thread_id"] is not None
        assert block["first_sequence"] <= block["last_sequence"]
        assert block["native_block_start"] <= block["native_block_end"]
        assert block["lift_profile"] == "glaurung-raw-llir-v1"
        assert block["lifted_block_start"] == block["native_block_start"]
        assert [step["sequence"] for step in block["steps"]] == sorted(
            step["sequence"] for step in block["steps"]
        )
        assert block["first_sequence"] == block["steps"][0]["sequence"]
        assert block["last_sequence"] == block["steps"][-1]["sequence"]
        assert all(
            step["static_instruction_va"] == step["static_va"]
            and block["native_block_start"]
            <= step["static_instruction_va"]
            < step["static_instruction_end"]
            <= block["native_block_end"]
            for step in block["steps"]
        )
    assert report["replay_seeds"]
    seed_relation = report["replay_seeds"][0]
    assert seed_relation["seed"]["status"] == "inferred", seed_relation
    seed = seed_relation["seed"]["value"]
    assert seed["first_divergence"] is None
    assert seed["id"].startswith("replay-seed-")
    assert seed["capture_id"] == report["capture_id"]
    assert seed["observed_block_id"] == blocks[0]["id"]
    assert seed["sequence"] == blocks[0]["first_sequence"]
    assert seed["pc"] == blocks[0]["steps"][0]["runtime_instruction_va"]
    assert seed["registers"]["rip"] == seed["pc"]
    assert seed["verified_register_count"] == len(seed["registers"])
    assert seed["memory_ranges"]
    assert seed["verified_memory_byte_count"] == sum(
        item["byte_len"] for item in seed["memory_ranges"]
    )
    assert seed["memory_reconstruction_from_sequence"] < seed["sequence"]
    assert seed["memory_reconstruction_through_sequence"] == seed["sequence"] - 1
    assert seed["unseeded_memory"].startswith("unknown;")
    replay = seed["bounded_replay"]
    assert replay["status"] == "inferred", replay
    replay_value = replay["value"]
    assert replay_value["observed_block_id"] == seed["observed_block_id"]
    assert replay_value["first_sequence"] == seed["sequence"]
    assert replay_value["last_sequence"] == blocks[0]["last_sequence"]
    assert replay_value["executed_operation_count"] > 0
    assert replay_value["observed_successor_sequence"] == (
        replay_value["last_sequence"] + 1
    )
    assert set(replay_value["compared_registers"]).isdisjoint(
        replay_value["uncompared_registers"]
    )
    assert set(replay_value["address_normalized_registers"]).issubset(
        replay_value["compared_registers"]
    )
    assert all(
        item["replay_static_va"] != item["observed_runtime_va"] and item["mapping_id"]
        for item in replay_value["address_normalized_registers"].values()
    )
    assert all(
        item["replay_static_va"] != item["observed_runtime_va"] and item["mapping_id"]
        for item in replay_value["address_normalized_memory"]
    )
    assert all(replay_value["uncompared_registers"].values())
    assert (
        replay_value["compared_memory_byte_count"] == seed["verified_memory_byte_count"]
    )
    assert replay_value["terminal_state"] == "matches_observation"
    provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(capture.capsule_json)
    )
    source = next(item for item in provenance["sources"] if item["name"] == "argv[1]")
    location = next(
        item["location"]["value"]
        for item in report["input_locations"]
        if item["source_id"] == source["id"]
        and item["location"]["status"] == "inferred"
    )
    assert any(
        item["start"] <= location["runtime_address"]
        and location["runtime_address"] + 1 <= item["start"] + item["byte_len"]
        for item in seed["memory_ranges"]
    )
    flows = [
        flow
        for flow in report["input_value_flows"]
        if flow["source_id"] == source["id"]
    ]
    assert len(flows) == 1, flows
    relation = flows[0]["relation"]
    assert relation["status"] == "inferred", relation
    flow = relation["value"]
    assert flow["source_name"] == "argv[1]"
    assert flow["source_byte_len"] == len(supplied)
    writes = [
        step for step in flow["steps"] if step["transfer"]["kind"] == "memory_write"
    ]
    assert len(writes) == 2, flow
    expected_span = {
        "source_id": source["id"],
        "source_offset": 0,
        "byte_len": 1,
    }
    for write in writes:
        assert write["provenance"] == [expected_span]
        assert write["static_operation"]["kind"] == "store"
        assert write["transfer"]["byte_len"] == 1
        assert write["transfer"]["address"] > 0
        load = write["source_load_occurrence"]
        assert load["status"] == "inferred", write
        assert load["value"]["static_operation"]["kind"] == "load"
        assert load["value"]["event_sequence"] < write["sequence"]
        assert load["value"] in [
            item["operation_occurrence"]["value"]
            for item in report["executed_loads"]
            if item["operation_occurrence"]["status"] == "inferred"
        ]
    assert writes[0]["transfer"]["address"] != writes[1]["transfer"]["address"]
    assert [write["source_memory_address"] for write in writes] == [
        location["runtime_address"],
        writes[0]["transfer"]["address"],
    ]
    assert (
        writes[1]["source_load_occurrence"]["value"]["event_sequence"]
        > writes[0]["sequence"]
    )

    if (compiler, opt, link) == ("gcc", "O0", "pie"):
        damaged_step = next(
            step
            for block in blocks
            for step in block["steps"]
            if step["static_instruction_end"] - step["static_instruction_va"] > 1
        )
        damaged_sequence = damaged_step["sequence"]
        damaged_blocks_capsule = json.loads(capture.capsule_json)
        damaged_event = next(
            event
            for event in damaged_blocks_capsule["events"]
            if event["kind"] == "instruction_step"
            and event["sequence"] == damaged_sequence
        )
        damaged_event["address"] += 1
        damaged_blocks_json = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(damaged_blocks_capsule, separators=(",", ":"))
        )
        damaged_blocks_report = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                damaged_blocks_json, list(capture.payloads), binary.read_bytes()
            )
        )
        damaged_relation = next(
            item
            for item in damaged_blocks_report["observed_blocks"]
            if item["first_sequence"] == damaged_sequence
        )
        assert damaged_relation["last_sequence"] == damaged_sequence
        assert damaged_relation["relation"] == {
            "status": "unknown",
            "reason": "observed block correlation requires an exact instruction start",
        }
        assert damaged_sequence not in {
            step["sequence"]
            for item in damaged_blocks_report["observed_blocks"]
            if item["relation"]["status"] == "inferred"
            for step in item["relation"]["value"]["steps"]
        }

        missing_seed_payloads = [
            item
            for item in capture.payloads
            if item[0] != "instruction-trace-stack-before"
        ]
        missing_seed = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                capture.capsule_json, missing_seed_payloads, binary.read_bytes()
            )
        )
        assert [
            item["relation"]["value"]["id"]
            for item in missing_seed["observed_blocks"]
            if item["relation"]["status"] == "inferred"
        ] == [block["id"] for block in blocks]
        assert missing_seed["replay_seeds"][0]["seed"] == {
            "status": "unknown",
            "reason": (
                "replay snapshot payload instruction-trace-stack-before is unavailable"
            ),
        }

        divergent_capsule = json.loads(capture.capsule_json)
        divergent_trace_ref = divergent_capsule["provider.ptrace_single_step"][
            "register_trace"
        ]
        divergent_trace_id = divergent_trace_ref["payload_id"]
        divergent_trace = json.loads(dict(capture.payloads)[divergent_trace_id])
        successor_registers = next(
            step["registers"]
            for step in divergent_trace["steps"]
            if step["sequence"] == replay_value["observed_successor_sequence"]
        )
        successor_registers["rsp"] = f"{int(successor_registers['rsp'], 16) + 16:016x}"
        divergent_trace_bytes = json.dumps(
            divergent_trace, sort_keys=True, separators=(",", ":")
        ).encode()
        divergent_trace_ref["sha256"] = hashlib.sha256(
            divergent_trace_bytes
        ).hexdigest()
        divergent_trace_ref["byte_len"] = len(divergent_trace_bytes)
        divergent_capsule_json = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(divergent_capsule, separators=(",", ":"))
        )
        divergent_payloads = [
            (
                payload_id,
                divergent_trace_bytes if payload_id == divergent_trace_id else payload,
            )
            for payload_id, payload in capture.payloads
        ]
        divergent_report = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                divergent_capsule_json,
                divergent_payloads,
                binary.read_bytes(),
            )
        )
        divergent_seed = divergent_report["replay_seeds"][0]["seed"]["value"]
        assert divergent_seed["bounded_replay"]["status"] == "unknown"
        assert divergent_seed["first_divergence"] == {
            "kind": "register_mismatch",
            "reason": "replayed register rsp disagrees with observation",
            "operation": {
                "event_sequence": replay_value["last_sequence"],
                "static_instruction_va": blocks[0]["steps"][-1][
                    "static_instruction_va"
                ],
                "llir_block_start": blocks[0]["lifted_block_start"],
                "operation_index": blocks[0]["steps"][-1]["operation_indices"][-1],
                "operation_kind": blocks[0]["steps"][-1]["operation_kinds"][-1],
            },
            "state_component": "register:rsp",
            "replayed_value": f"{replay_value['compared_registers']['rsp']:#x}",
            "observed_value": f"{int(successor_registers['rsp'], 16):#x}",
        }

        changed_load_capsule = json.loads(capture.capsule_json)
        register_trace_ref = changed_load_capsule["provider.ptrace_single_step"][
            "register_trace"
        ]
        register_trace_id = register_trace_ref["payload_id"]
        changed_register_trace = json.loads(dict(capture.payloads)[register_trace_id])
        second_load = writes[1]["source_load_occurrence"]["value"]
        base_register = second_load["static_operation"]["memory_access"][
            "base_register"
        ]
        second_load_registers = next(
            step["registers"]
            for step in changed_register_trace["steps"]
            if step["sequence"] == second_load["event_sequence"]
        )
        second_load_registers[base_register] = (
            f"{int(second_load_registers[base_register], 16) + 1:016x}"
        )
        changed_register_bytes = json.dumps(
            changed_register_trace, sort_keys=True, separators=(",", ":")
        ).encode()
        register_trace_ref["sha256"] = hashlib.sha256(
            changed_register_bytes
        ).hexdigest()
        register_trace_ref["byte_len"] = len(changed_register_bytes)
        changed_load_capsule_json = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(changed_load_capsule, separators=(",", ":"))
        )
        changed_load_payloads = [
            (
                payload_id,
                changed_register_bytes if payload_id == register_trace_id else payload,
            )
            for payload_id, payload in capture.payloads
        ]
        changed_load = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                changed_load_capsule_json,
                changed_load_payloads,
                binary.read_bytes(),
            )
        )
        changed_load_flow = next(
            item["relation"]["value"]
            for item in changed_load["input_value_flows"]
            if item["source_id"] == source["id"]
            and item["relation"]["status"] == "inferred"
        )
        assert len(changed_load_flow["steps"]) == 1
        assert (
            changed_load_flow["steps"][0]["transfer"]["address"]
            == writes[0]["transfer"]["address"]
        )

        changed_memory_capsule = json.loads(capture.capsule_json)
        first_write_event = next(
            event
            for event in changed_memory_capsule["events"]
            if event["sequence"] == writes[0]["sequence"]
        )
        first_write_payload_id = first_write_event["fields"]["stack_changes_payload_id"]
        changed_memory_payload = json.loads(
            dict(capture.payloads)[first_write_payload_id]
        )
        changed_memory_payload["changes"][0]["after_hex"] = "63"
        changed_memory_bytes = json.dumps(
            changed_memory_payload, sort_keys=True, separators=(",", ":")
        ).encode()
        first_write_event["fields"]["stack_changes_sha256"] = hashlib.sha256(
            changed_memory_bytes
        ).hexdigest()
        first_write_event["fields"]["stack_changes_byte_len"] = str(
            len(changed_memory_bytes)
        )
        changed_memory_capsule_json = (
            runtime_analysis.canonicalize_process_capsule_json(
                json.dumps(changed_memory_capsule, separators=(",", ":"))
            )
        )
        changed_memory_payloads = [
            (
                payload_id,
                changed_memory_bytes
                if payload_id == first_write_payload_id
                else payload,
            )
            for payload_id, payload in capture.payloads
        ]
        changed_memory = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                changed_memory_capsule_json,
                changed_memory_payloads,
                binary.read_bytes(),
            )
        )
        changed_memory_flow = next(
            item
            for item in changed_memory["input_value_flows"]
            if item["source_id"] == source["id"]
        )
        assert changed_memory_flow["relation"] == {
            "status": "unknown",
            "reason": "no observed LLIR store carries exact bytes from this input",
        }

        capsule = json.loads(capture.capsule_json)
        checkpoint = next(
            event
            for event in capsule["events"]
            if event["kind"] == "capture_checkpoint"
            and event["fields"].get("phase") == "trace_begin"
        )
        checkpoint["fields"]["input_runtime_address"] = str(
            int(checkpoint["fields"]["input_runtime_address"]) + 1
        )
        changed_capsule = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(capsule, separators=(",", ":"))
        )
        changed = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                changed_capsule, list(capture.payloads), binary.read_bytes()
            )
        )
        changed_flow = next(
            item
            for item in changed["input_value_flows"]
            if item["source_id"] == source["id"]
        )
        assert changed_flow["relation"] == {
            "status": "unknown",
            "reason": "input byte flow requires one exact runtime input location",
        }


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.parametrize(
    ("scenario", "expected_request"),
    [("good", 0), ("bad", 0xDEADBEEF)],
)
def test_ioctl_instruction_trace_covers_request_selection_and_sink(
    tmp_path: Path, scenario: str, expected_request: int
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_ioctl_input"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
        public_input=scenario.encode(),
        public_paths=["/dev/null"],
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    provenance = json.loads(
        runtime_analysis.process_capsule_input_provenance(capture.capsule_json)
    )
    source = next(item for item in provenance["sources"] if item["name"] == "argv[1]")
    input_location = next(
        item for item in report["input_locations"] if item["source_id"] == source["id"]
    )
    assert input_location["location"]["status"] == "inferred", input_location
    location = input_location["location"]["value"]
    assert location["source_name"] == "argv[1]"
    assert location["byte_len"] == len(scenario)
    capsule = json.loads(capture.capsule_json)
    containing_page = next(
        page
        for page in capsule["pages"]
        if page["start"] <= location["runtime_address"]
        and location["runtime_address"] + len(scenario)
        <= page["start"] + page["byte_len"]
    )
    assert location["mapping_id"] == containing_page["mapping_id"]
    strcmp_calls = [
        relation
        for relation in report["call_relations"]
        if relation["callee"].get("value") == "strcmp"
    ]
    assert len(strcmp_calls) == 1
    strcmp_occurrence = strcmp_calls[0]["operation_occurrence"]
    assert strcmp_occurrence["status"] == "inferred", strcmp_occurrence
    strcmp_return = strcmp_calls[0]["return_occurrence"]
    assert strcmp_return["status"] == "inferred", strcmp_return
    assert strcmp_return["value"]["return_register"] == "rax"
    strcmp_value = strcmp_occurrence["value"]
    assert [item["id"] for item in strcmp_value["introduced_input_sources"]] == [
        source["id"]
    ]
    assert strcmp_value["effects"] == [
        {
            "kind": "input_compare_call",
            "errno": None,
            "address": location["runtime_address"],
            "byte_len": len(scenario),
            "input_source_id": source["id"],
        }
    ]
    assert location["runtime_address"] in {
        int(strcmp_value["inputs"]["left_address"]["value"]),
        int(strcmp_value["inputs"]["right_address"]["value"]),
    }
    assert (strcmp_value["output"]["value"] == 0) is (scenario == "bad")
    ioctl_calls = [
        relation
        for relation in report["call_relations"]
        if relation["callee"].get("value") == "ioctl"
    ]
    assert len(ioctl_calls) == 1, [
        relation["callee"] for relation in report["call_relations"]
    ]
    control_transfers = [
        relation
        for relation in report["control_transfers"]
        if strcmp_return["value"]["sequence"]
        <= relation["sequence"]
        < ioctl_calls[0]["sequence"]
    ]
    strcmp_dependent_branches = [
        relation
        for relation in control_transfers
        if relation["static_operation"].get("value", {}).get("kind") == "cond_jump"
        and relation["static_operation"]["value"].get("condition_call_results")
        == [
            {
                "machine_va": strcmp_value["static_operation"]["machine_va"],
                "register": "rax",
            }
        ]
    ]
    assert strcmp_dependent_branches, control_transfers
    assert all(
        relation["observed_successor"]["status"] == "observed"
        and relation["edge"]["status"] == "inferred"
        for relation in strcmp_dependent_branches
    )
    predicate_calls = [
        relation
        for relation in report["call_relations"]
        if relation["static_target_va"].get("value")
        == strcmp_value["static_operation"]["function_entry"]
    ]
    assert len(predicate_calls) == 1
    predicate_return = predicate_calls[0]["return_occurrence"]
    assert predicate_return["status"] == "inferred", predicate_return
    request_branches = [
        relation
        for relation in control_transfers
        if relation["sequence"] >= predicate_return["value"]["sequence"]
        and relation["static_operation"]["value"].get("condition_call_results")
        == [
            {
                "machine_va": predicate_calls[0]["address_resolution"]["address"][
                    "code"
                ]["instruction_va"],
                "register": "rax",
            }
        ]
    ]
    assert len(request_branches) == 1, control_transfers
    request_branch = request_branches[0]
    assert request_branch["edge"]["status"] == "inferred"
    selected_writes = [
        relation
        for relation in report["executed_stores"]
        if request_branch["sequence"]
        < relation["sequence"]
        < ioctl_calls[0]["sequence"]
        and relation["operation_occurrence"]
        .get("value", {})
        .get("static_operation", {})
        .get("kind")
        == "store"
    ]
    assert len(selected_writes) == 1, selected_writes
    selected_write = selected_writes[0]
    selected_operation = selected_write["operation_occurrence"]["value"][
        "static_operation"
    ]
    request_input = next(
        item
        for item in ioctl_calls[0]["address_resolution"]["address"]["code"][
            "operations"
        ]["operations"][0]["call_register_inputs"]
        if item["position"] == 1
    )
    assert request_input["expression"]["kind"] == "load"
    assert (
        request_input["expression"]["address"]
        == selected_operation["address_expression"]
    )
    stored_value = selected_operation["stored_value"]
    observed_stored_value = (
        selected_write["registers"]["value"][stored_value["name"]]
        if stored_value["kind"] == "register"
        else stored_value["value"]
    )
    assert observed_stored_value == expected_request
    occurrence = ioctl_calls[0]["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    assert occurrence["value"]["inputs"]["request"]["value"] == str(expected_request)
    source_to_sink = report["input_to_call_arguments"]
    assert len(source_to_sink) == 1, source_to_sink
    assert source_to_sink[0]["source_id"] == source["id"]
    assert source_to_sink[0]["sink_sequence"] == ioctl_calls[0]["sequence"]
    assert source_to_sink[0]["relation"]["status"] == "inferred", source_to_sink
    source_to_sink_value = source_to_sink[0]["relation"]["value"]
    assert source_to_sink_value["argument_name"] == "request"
    assert source_to_sink_value["argument_value"] == str(expected_request)
    assert source_to_sink_value["comparison_occurrence"]["id"] == strcmp_value["id"]
    assert source_to_sink_value["propagation"]["kind"] == "branch_selected_memory"
    assert (
        source_to_sink_value["propagation"]["selected_write"]["id"]
        == (selected_write["operation_occurrence"]["value"]["id"])
    )
    assert source_to_sink_value["sink_occurrence"]["id"] == occurrence["value"]["id"]

    wrong_edge_capsule = json.loads(json.dumps(capsule))
    wrong_edge_event = next(
        event
        for event in wrong_edge_capsule["events"]
        if event["kind"] == "instruction_step"
        and event["sequence"] == request_branch["sequence"]
    )
    wrong_edge_event["fields"]["after_address"] = str(
        ioctl_calls[0]["runtime_instruction_va"]
    )
    wrong_edge_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            json.dumps(wrong_edge_capsule),
            list(capture.payloads),
            binary.read_bytes(),
        )
    )
    wrong_edge = next(
        relation
        for relation in wrong_edge_report["control_transfers"]
        if relation["sequence"] == request_branch["sequence"]
    )
    assert wrong_edge["edge"]["status"] == "unknown"
    assert wrong_edge_report["input_to_call_arguments"][0]["relation"]["status"] == (
        "unknown"
    )

    wrong_input_capsule = json.loads(json.dumps(capsule))
    begin_checkpoint = next(
        event
        for event in wrong_input_capsule["events"]
        if event["kind"] == "capture_checkpoint"
        and event["fields"].get("phase") == "trace_begin"
    )
    begin_checkpoint["fields"]["input_runtime_address"] = str(
        int(begin_checkpoint["fields"]["input_runtime_address"]) + 1
    )
    wrong_input_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            json.dumps(wrong_input_capsule),
            list(capture.payloads),
            binary.read_bytes(),
        )
    )
    assert wrong_input_report["input_locations"][0]["location"]["status"] == ("unknown")
    assert wrong_input_report["input_to_call_arguments"][0]["relation"]["status"] == (
        "unknown"
    )

    missing_payload_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json,
            [
                payload
                for payload in capture.payloads
                if payload[0] != containing_page["content"]["payload"]["id"]
            ],
            binary.read_bytes(),
        )
    )
    missing_location = next(
        item
        for item in missing_payload_report["input_locations"]
        if item["source_id"] == source["id"]
    )
    assert missing_location["location"]["status"] == "unknown"
    assert (
        missing_payload_report["input_to_call_arguments"][0]["relation"]["status"]
        == "unknown"
    )


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.parametrize(
    ("scenario", "expected_request"),
    [("good", 0), ("bad", 0xDEADBEEF)],
)
def test_optimized_ioctl_trace_uses_conditional_value_propagation(
    tmp_path: Path, scenario: str, expected_request: int
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_ioctl_input"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O2", "pie", tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
        public_input=scenario.encode(),
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    assert len(report["input_to_call_arguments"]) == 1
    relation = report["input_to_call_arguments"][0]["relation"]
    assert relation["status"] == "inferred", relation
    value = relation["value"]
    assert value["argument_value"] == str(expected_request)
    propagation = value["propagation"]
    assert propagation["kind"] == "conditional_value"
    selection = propagation["selection"]
    assert selection["output"]["status"] == "observed"
    assert selection["output"]["value"] == expected_request
    selection_operation = selection["static_operation"]["value"]
    assert selection_operation["kind"] == "ite"
    assert "condition_expression_id" not in selection_operation
    assert "defined_value_expression_id" not in selection_operation
    assert "semantic_values" not in selection_operation
    assert selection_operation["condition_call_results"] == [
        {
            "machine_va": value["comparison_occurrence"]["static_operation"][
                "machine_va"
            ],
            "register": "rax",
        }
    ]
    if scenario == "bad":
        capsule = json.loads(capture.capsule_json)
        trace_ref = capsule["provider.ptrace_single_step"]["register_trace"]
        register_bytes = dict(capture.payloads)[trace_ref["payload_id"]]
        register_trace = json.loads(register_bytes)
        post_selection_step = min(
            (
                step
                for step in register_trace["steps"]
                if step["sequence"] > selection["sequence"]
            ),
            key=lambda step: step["sequence"],
        )
        post_selection_step["registers"]["rsi"] = "0000000000000000"
        changed_bytes = json.dumps(
            register_trace, sort_keys=True, separators=(",", ":")
        ).encode()
        trace_ref["sha256"] = hashlib.sha256(changed_bytes).hexdigest()
        trace_ref["byte_len"] = len(changed_bytes)
        changed_capsule = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(capsule, separators=(",", ":"))
        )
        changed_payloads = [
            (
                payload_id,
                changed_bytes if payload_id == trace_ref["payload_id"] else data,
            )
            for payload_id, data in capture.payloads
        ]
        changed_report = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                changed_capsule, changed_payloads, binary.read_bytes()
            )
        )
        assert (
            changed_report["input_to_call_arguments"][0]["relation"]["status"]
            == "unknown"
        )


@pytest.mark.slow
@pytest.mark.parametrize(
    ("compiler", "opt", "expected_path"),
    [
        ("gcc", "O0", "branch_selected_memory"),
        ("gcc", "O2", "conditional_value"),
        ("clang", "O0", "spilled_predicate_return_conditional_memory"),
        ("clang", "O2", "branch_selected_register"),
    ],
)
@pytest.mark.parametrize("link", ["pie", "no-pie"])
@pytest.mark.parametrize(
    ("scenario", "expected_request"),
    [("good", 0), ("bad", 0xDEADBEEF)],
)
def test_ioctl_input_to_call_relation_supported_build_matrix(
    tmp_path: Path,
    compiler: str,
    opt: str,
    expected_path: str,
    link: str,
    scenario: str,
    expected_request: int,
) -> None:
    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_ioctl_input"
    )
    binary = HARNESS.compile_sample(sample, compiler, opt, link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
        public_input=scenario.encode(),
        public_paths=["/dev/null"],
    )
    captured_capsule = json.loads(capture.capsule_json)
    assert {
        descriptor["target"]
        for descriptor in captured_capsule["descriptors"]
        if not descriptor["redacted"]
    } == {"/dev/null"}
    assert all(
        descriptor.get("target") == "/dev/null" or descriptor["redacted"]
        for descriptor in captured_capsule["descriptors"]
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    assert len(report["input_to_call_arguments"]) == 1
    relation = report["input_to_call_arguments"][0]["relation"]
    assert relation["status"] == "inferred", relation
    assert relation["value"]["argument_value"] == str(expected_request)
    propagation = relation["value"]["propagation"]
    assert propagation["kind"] == expected_path
    semantic = HARNESS.instruction_trace_semantic_result(
        capture.capsule_json,
        list(capture.payloads),
        binary.read_bytes(),
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt=opt,
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(semantic, oracle)
    assert evaluation["passed"], json.dumps(evaluation, indent=2)
    dataflow_facts = [fact for fact in semantic["facts"] if fact["kind"] == "dataflow"]
    assert dataflow_facts == [
        {
            "kind": "dataflow",
            "subject": "ioctl_request",
            "predicate": "source_to_sink",
            "status": "inferred",
            "value": "scenario_selected->ioctl",
            "source": (
                "one inferred glaurung-runtime-instruction-trace-report-v1 "
                "input-to-call-argument relation"
            ),
        }
    ]
    if expected_path == "branch_selected_register":
        definition = propagation["selected_definition"]
        assert definition["output"] == {
            "status": "observed",
            "value": expected_request,
            "source": (
                "hash-bound post-step register agrees with immutable LLIR definition"
            ),
        }
        assert definition["static_operation"]["defined_register"] == "esi"
        assert definition["static_operation"]["defined_value"]["kind"] == (
            "constant" if scenario == "bad" else "bitwise_xor"
        )
        assert definition["static_operation"]["defined_value_expression_id"].startswith(
            "static-expression-"
        )
        assert [
            value["role"] for value in definition["static_operation"]["semantic_values"]
        ] == ["defined_value"]
        assert (
            definition["static_operation"]["semantic_values"][0]["expression_root_id"]
            == definition["static_operation"]["defined_value_expression_id"]
        )
        if scenario != "bad" or link != "pie":
            return
        capsule = json.loads(capture.capsule_json)
        trace_ref = capsule["provider.ptrace_single_step"]["register_trace"]
        register_trace = json.loads(dict(capture.payloads)[trace_ref["payload_id"]])
        post_definition = min(
            (
                step
                for step in register_trace["steps"]
                if step["sequence"] > definition["sequence"]
            ),
            key=lambda step: step["sequence"],
        )
        post_definition["registers"]["rsi"] = "0000000000000000"
        changed_bytes = json.dumps(
            register_trace, sort_keys=True, separators=(",", ":")
        ).encode()
        trace_ref["sha256"] = hashlib.sha256(changed_bytes).hexdigest()
        trace_ref["byte_len"] = len(changed_bytes)
        changed_capsule = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(capsule, separators=(",", ":"))
        )
        changed_payloads = [
            (
                payload_id,
                changed_bytes if payload_id == trace_ref["payload_id"] else data,
            )
            for payload_id, data in capture.payloads
        ]
        changed_report = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                changed_capsule, changed_payloads, binary.read_bytes()
            )
        )
        assert changed_report["input_to_call_arguments"][0]["relation"]["status"] == (
            "unknown"
        )
        changed_semantic = HARNESS.instruction_trace_semantic_result(
            changed_capsule,
            changed_payloads,
            binary.read_bytes(),
            sample=sample.id,
            scenario=scenario,
            compiler=compiler,
            opt=opt,
            link=link,
        )
        assert not any(fact["kind"] == "dataflow" for fact in changed_semantic["facts"])
        assert not HARNESS.evaluate_semantic_result(changed_semantic, oracle)["passed"]
        return
    if expected_path != "spilled_predicate_return_conditional_memory":
        return
    flow = propagation["comparison_to_predicate_return"]
    assert (
        flow["source_call_machine_va"]
        == relation["value"]["comparison_occurrence"]["static_operation"]["machine_va"]
    )
    assert flow["destination_value"] == (1 if scenario == "bad" else 0)
    transfer_kinds = {step["transfer"]["kind"] for step in flow["steps"]}
    assert transfer_kinds == {"register", "memory_write", "memory_read"}
    predicate_writes = [
        step for step in flow["steps"] if step["transfer"]["kind"] == "memory_write"
    ]
    predicate_reads = [
        step for step in flow["steps"] if step["transfer"]["kind"] == "memory_read"
    ]
    assert len(predicate_writes) == len(predicate_reads) == 1
    assert predicate_writes[0]["transfer"] == predicate_reads[0]["transfer"] | {
        "kind": "memory_write"
    }
    assert (
        propagation["selected_write"]["static_operation"]["stored_value_register"]
        == propagation["selection"]["static_operation"]["value"]["value_selection"][
            "output_register"
        ]
    )

    if scenario != "bad" or link != "pie":
        return
    capsule = json.loads(capture.capsule_json)
    trace_ref = capsule["provider.ptrace_single_step"]["register_trace"]
    register_trace = json.loads(dict(capture.payloads)[trace_ref["payload_id"]])
    spill_step = next(
        step
        for step in register_trace["steps"]
        if step["sequence"] == predicate_writes[0]["sequence"]
    )
    spill_step["registers"]["rbp"] = (
        f"{int(spill_step['registers']['rbp'], 16) + 1:016x}"
    )
    changed_bytes = json.dumps(
        register_trace, sort_keys=True, separators=(",", ":")
    ).encode()
    trace_ref["sha256"] = hashlib.sha256(changed_bytes).hexdigest()
    trace_ref["byte_len"] = len(changed_bytes)
    changed_capsule = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(capsule, separators=(",", ":"))
    )
    changed_payloads = [
        (
            payload_id,
            changed_bytes if payload_id == trace_ref["payload_id"] else data,
        )
        for payload_id, data in capture.payloads
    ]
    changed_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            changed_capsule, changed_payloads, binary.read_bytes()
        )
    )
    assert changed_report["input_to_call_arguments"][0]["relation"]["status"] == (
        "unknown"
    )
    changed_semantic = HARNESS.instruction_trace_semantic_result(
        changed_capsule,
        changed_payloads,
        binary.read_bytes(),
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt=opt,
        link=link,
    )
    assert not any(fact["kind"] == "dataflow" for fact in changed_semantic["facts"])
    assert not HARNESS.evaluate_semantic_result(changed_semantic, oracle)["passed"]


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
@pytest.mark.parametrize("compiler", ["gcc", "clang"])
@pytest.mark.parametrize("opt", ["O0", "O2"])
@pytest.mark.parametrize("link", ["pie", "no-pie"])
def test_ioctl_event_correlates_to_llir_call_across_default_matrix(
    tmp_path: Path, compiler: str, opt: str, link: str
) -> None:
    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_mapping_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "danger_ioctl_input"
    )
    binary = HARNESS.compile_sample(sample, compiler, opt, link, tmp_path)
    capture = capture_mapping_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=b"bad",
        public_paths=["/dev/null"],
    )
    report = json.loads(
        runtime_analysis.correlate_process_capsule_ioctl_events(
            capture.capsule_json, binary.read_bytes()
        )
    )
    assert len(report["relations"]) == 1
    relation = report["relations"][0]
    assert relation["request"] == 0xDEADBEEF
    assert relation["static_callsite"]["status"] == "inferred", relation[
        "static_callsite"
    ]
    code = relation["static_callsite"]["value"]["code"]
    assert code["verdict"] == "resolved"
    assert any(
        operation["kind"] == "call" for operation in code["operations"]["operations"]
    )
    assert relation["operation_occurrence"]["status"] == "inferred"
    assert relation["operation_occurrence"]["value"]["static_operation"]["kind"] == (
        "call"
    )


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.parametrize(
    ("scenario", "changed_offset", "final_canary"),
    [
        ("good", 7, bytes.fromhex("78563412")),
        ("bad", 8, bytes.fromhex("ff563412")),
    ],
)
def test_heap_snapshot_provider_captures_real_object_lifetime(
    tmp_path: Path,
    scenario: str,
    changed_offset: int,
    final_canary: bytes,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_heap_snapshots_child

    provider = tmp_path / "heap_snapshot_interposer.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            str(ROOT / "tests/runtime_samples/support/heap_snapshot_interposer.c"),
            "-o",
            str(provider),
        ],
        check=True,
    )
    sample = next(
        item
        for item in HARNESS.load_samples()
        if item.id == "memory_heap_canary_overwrite"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_heap_snapshots_child(
        binary,
        provider,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        public_input=scenario.encode(),
    )
    capsule = json.loads(capture.capsule_json)
    assert capsule["identity"]["acquisition"] == "trace"
    assert capsule["processes"][0]["terminal"] == {"kind": "exited", "code": 0}
    payloads = dict(capture.payloads)
    candidates = []
    for runtime_object in capsule["runtime_objects"]:
        if runtime_object["byte_len"] != 16:
            continue
        snapshots = sorted(
            (
                snapshot
                for snapshot in capsule["object_snapshots"]
                if snapshot["object_id"] == runtime_object["id"]
            ),
            key=lambda snapshot: snapshot["point"]["sequence"],
        )
        if len(snapshots) != 2:
            continue
        before = payloads[snapshots[0]["content"]["payload"]["id"]]
        after = payloads[snapshots[1]["content"]["payload"]["id"]]
        if before == bytes(16) and after[8:12] == final_canary:
            candidates.append((before, after))
    assert len(candidates) == 1
    before, after = candidates[0]
    assert before[changed_offset] == 0
    assert after[changed_offset] == 0xFF

    report = json.loads(
        runtime_analysis.analyze_process_capsule_object_changes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    assert report["schema"] == "glaurung-runtime-object-change-report-v1"
    changed = next(
        item
        for item in report["objects"]
        if item["object_byte_len"] == 16
        and item["changed_intervals"]["status"] == "observed"
        and item["changed_intervals"]["value"]
        == [
            {
                "object_offset_start": changed_offset,
                "object_offset_end": 12,
                "before_hex": "00" * (12 - changed_offset),
                "after_hex": after[changed_offset:12].hex(),
            }
        ]
    )
    assert changed["responsible_write"] == {
        "status": "unknown",
        "reason": "expected one bounded write event covering every changed byte, found 0",
    }
    changed_object_id = changed["object_id"]
    after_snapshot = max(
        (
            snapshot
            for snapshot in capsule["object_snapshots"]
            if snapshot["object_id"] == changed_object_id
        ),
        key=lambda snapshot: snapshot["point"]["sequence"],
    )
    after_payload_id = after_snapshot["content"]["payload"]["id"]
    tampered_payloads = [
        (payload_id, b"tampered" if payload_id == after_payload_id else data)
        for payload_id, data in capture.payloads
    ]
    weakened = json.loads(
        runtime_analysis.analyze_process_capsule_object_changes(
            capture.capsule_json, tampered_payloads, binary.read_bytes()
        )
    )
    weakened_object = next(
        item for item in weakened["objects"] if item["object_id"] == changed_object_id
    )
    assert weakened_object["changed_intervals"]["status"] == "unknown"
    assert (
        "payload identity disagrees" in weakened_object["changed_intervals"]["reason"]
    )


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.parametrize(
    ("scenario", "object_size", "link"),
    [("good", 24, "no-pie"), ("bad", 16, "no-pie"), ("bad", 16, "pie")],
)
def test_heap_snapshot_provider_attributes_bounded_memset_event(
    tmp_path: Path, scenario: str, object_size: int, link: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_heap_snapshots_child

    provider = tmp_path / "heap_snapshot_interposer.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            str(ROOT / "tests/runtime_samples/support/heap_snapshot_interposer.c"),
            "-o",
            str(provider),
        ],
        check=True,
    )
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_underallocation"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", link, tmp_path)
    capture = capture_heap_snapshots_child(
        binary,
        provider,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        public_input=scenario.encode(),
    )
    capsule = json.loads(capture.capsule_json)
    allocation = next(
        event
        for event in capsule["events"]
        if event["kind"] == "allocation"
        and event["fields"]["byte_len"] == str(object_size)
    )
    assert allocation["fields"]["calloc_count"] == "1"
    assert allocation["fields"]["calloc_element_size"] == str(object_size)
    assert allocation["fields"]["caller_main_module"] == "true"
    assert int(allocation["fields"]["caller_return_va"]) > 0
    assert allocation["fields"]["provider_sequence"] == "1"
    assert allocation["fields"]["provider_os_tid"] == str(
        capsule["processes"][0]["os_pid"]
    )
    assert allocation["thread_id"] == capsule["threads"][0]["id"]
    assert capsule["threads"][0]["os_tid"] == capsule["processes"][0]["os_pid"]
    write = next(
        event for event in capsule["events"] if event["kind"] == "memory_write"
    )
    assert write["fields"]["fill_byte"] == "170"
    assert write["fields"]["requested_byte_len"] == "16"
    assert int(write["fields"]["provider_sequence"]) > int(
        allocation["fields"]["provider_sequence"]
    )
    assert write["fields"]["provider_os_tid"] == allocation["fields"]["provider_os_tid"]
    assert write["thread_id"] == allocation["thread_id"]
    report = json.loads(
        runtime_analysis.analyze_process_capsule_object_changes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    changed = next(
        item
        for item in report["objects"]
        if item["object_byte_len"] == object_size
        and item["changed_intervals"]["status"] == "observed"
        and item["changed_intervals"]["value"][0]["object_offset_start"] == 0
    )
    creation_callsite = changed["creation_callsite"]
    assert creation_callsite["status"] == "inferred", creation_callsite
    creation = changed["creation_occurrence"]
    assert creation["status"] == "inferred", creation
    assert creation["value"]["static_operation"]["call_target"]["symbol"] == "calloc"
    assert creation["value"]["inputs"]["count"]["value"] == "1"
    assert creation["value"]["inputs"]["element_size"]["value"] == str(object_size)
    assert creation["value"]["effects"] == [
        {
            "kind": "memory_allocate",
            "runtime_object_id": changed["object_id"],
            "errno": None,
            "address": changed["runtime_start"],
            "byte_len": object_size,
        }
    ]
    prefix = changed["allocation_prefix_write"]
    assert prefix["status"] == "inferred", prefix
    prefix_value = prefix["value"]
    assert prefix_value["source_name"] == "n"
    assert prefix_value["logical_prefix_byte_len"] == (16 if scenario == "good" else 8)
    assert prefix_value["reserved_tail_byte_len"] == 8
    assert prefix_value["allocation_byte_len"] == object_size
    assert prefix_value["write_byte_len"] == 16
    assert prefix_value["prefix_bytes_exceeded"] == (0 if scenario == "good" else 8)
    assert prefix_value["source_pointer"]["source_name"] == "p"
    assert prefix_value["classification"] == (
        "within_allocation_prefix"
        if scenario == "good"
        else "crosses_allocation_prefix_within_object"
    )
    semantic = HARNESS.heap_object_semantic_result(
        capture.capsule_json,
        report,
        sample=sample.id,
        scenario=scenario,
        compiler="gcc",
        opt="O0",
        link=link,
    )
    prefix_bounds = [
        fact for fact in semantic["facts"] if fact["predicate"] == "bounds_violation"
    ]
    if scenario == "good":
        assert prefix_bounds == []
    else:
        assert prefix_bounds == [
            {
                "kind": "memory",
                "subject": "heap_object:p",
                "predicate": "bounds_violation",
                "status": "inferred",
                "value": "logical_allocation=8:write_length=16",
                "source": (
                    "glaurung-runtime-object-change-report-v1 "
                    "allocation-prefix relation"
                ),
            }
        ]
    if scenario == "bad":
        assert changed["changed_intervals"]["value"] == [
            {
                "object_offset_start": 0,
                "object_offset_end": 16,
                "before_hex": "00" * 16,
                "after_hex": "aa" * 16,
            }
        ]
        attribution = changed["responsible_write"]
        assert attribution["status"] == "observed"
        assert attribution["source"] == ("provider-neutral bounded memory_write event")
        assert attribution["value"]["kind"] == "event"
        assert attribution["value"]["byte_len"] == 16
        assert attribution["value"]["address"] == changed["runtime_start"]
        static_callsite = changed["static_callsite"]
        assert static_callsite["status"] == "inferred"
        assert static_callsite["value"]["runtime_return_va"] > 0
        assert static_callsite["value"]["code"]["verdict"] == "resolved"
        assert static_callsite["value"]["code"]["mnemonic"].startswith("call")
        assert static_callsite["value"]["code"]["operations"]["verdict"] == ("resolved")
        assert any(
            operation["kind"] == "call"
            for operation in static_callsite["value"]["code"]["operations"][
                "operations"
            ]
        )
        occurrence = changed["operation_occurrence"]
        assert occurrence["status"] == "inferred", occurrence
        assert occurrence["value"]["static_operation"]["kind"] == "call"
        assert occurrence["value"]["inputs"]["destination_address"]["value"] == str(
            changed["runtime_start"]
        )
        assert occurrence["value"]["inputs"]["write_byte_len"]["value"] == "16"
        assert occurrence["value"]["effects"] == [
            {
                "kind": "memory_write",
                "runtime_object_id": changed["object_id"],
                "errno": None,
                "address": changed["runtime_start"],
                "byte_len": 16,
            }
        ]
        assert (
            static_callsite["value"]["code"]["instruction_end"]
            == static_callsite["value"]["static_instruction_va"] + 5
        )
        wrong_binary = HARNESS.compile_sample(sample, "gcc", "O2", link, tmp_path)
        wrong_report = json.loads(
            runtime_analysis.analyze_process_capsule_object_changes(
                capture.capsule_json,
                list(capture.payloads),
                wrong_binary.read_bytes(),
            )
        )
        wrong_object = next(
            item
            for item in wrong_report["objects"]
            if item["object_id"] == changed["object_id"]
        )
        assert wrong_object["responsible_write"]["status"] == "observed"
        assert wrong_object["creation_callsite"]["status"] == "unknown"
        assert wrong_object["creation_occurrence"]["status"] == "unknown"
        assert wrong_object["static_callsite"] == {
            "status": "unknown",
            "reason": "capsule executable identity disagrees with static image",
        }
        assert wrong_object["operation_occurrence"] == {
            "status": "unknown",
            "reason": "memory-write occurrence requires an exact static callsite",
        }
        assert wrong_object["allocation_prefix_write"]["status"] == "unknown"
        tampered_capsule = json.loads(capture.capsule_json)
        write_event = next(
            event
            for event in tampered_capsule["events"]
            if event["process_id"] == attribution["value"]["process_id"]
            and event["sequence"] == attribution["value"]["sequence"]
        )
        write_event["fields"]["caller_module_base"] = str(
            int(write_event["fields"]["caller_module_base"]) + 1
        )
        tampered_json = runtime_analysis.canonicalize_process_capsule_json(
            json.dumps(tampered_capsule)
        )
        tampered_report = json.loads(
            runtime_analysis.analyze_process_capsule_object_changes(
                tampered_json, list(capture.payloads), binary.read_bytes()
            )
        )
        tampered_object = next(
            item
            for item in tampered_report["objects"]
            if item["object_id"] == changed["object_id"]
        )
        assert tampered_object["responsible_write"]["status"] == "observed"
        assert tampered_object["creation_occurrence"]["status"] == "inferred"
        assert tampered_object["static_callsite"]["status"] == "unknown"
        assert tampered_object["operation_occurrence"]["status"] == "unknown"
        assert tampered_object["allocation_prefix_write"]["status"] == "unknown"
    else:
        assert changed["responsible_write"]["status"] == "unknown"
        assert changed["operation_occurrence"]["status"] == "unknown"


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize(
    ("scenario", "logical_size", "object_size", "classification"),
    [
        ("good", 16, 24, "within_allocation_prefix"),
        ("bad", 8, 16, "crosses_allocation_prefix_within_object"),
    ],
)
def test_underallocation_prefix_relation_across_build_matrix(
    tmp_path: Path,
    compiler: str,
    link: str,
    scenario: str,
    logical_size: int,
    object_size: int,
    classification: str,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_heap_snapshots_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    provider = tmp_path / "heap_snapshot_interposer.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            str(ROOT / "tests/runtime_samples/support/heap_snapshot_interposer.c"),
            "-o",
            str(provider),
        ],
        check=True,
    )
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_underallocation"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_heap_snapshots_child(
        binary,
        provider,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        public_input=scenario.encode(),
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_object_changes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    changed = next(
        item for item in report["objects"] if item["object_byte_len"] == object_size
    )
    relation = changed["allocation_prefix_write"]
    assert relation["status"] == "inferred", relation
    value = relation["value"]
    assert value["source_name"] == "n"
    assert value["logical_prefix_byte_len"] == logical_size
    assert value["reserved_tail_byte_len"] == 8
    assert value["allocation_byte_len"] == object_size
    assert value["write_byte_len"] == 16
    assert value["prefix_bytes_exceeded"] == max(16 - logical_size, 0)
    assert value["classification"] == classification
    assert value["source_pointer"]["source_name"] == "p"
    transition = changed["allocation_prefix_transition"]
    assert transition["status"] == "inferred", transition
    transition_value = transition["value"]
    assert (
        transition_value["write_sequence"]
        == value["write_occurrence"]["event_sequence"]
    )
    assert transition_value["logical_prefix_byte_len"] == logical_size
    assert transition_value["reserved_tail_byte_len"] == 8
    assert transition_value["prefix_changed_intervals"] == [
        {
            "object_offset_start": 0,
            "object_offset_end": logical_size,
            "before_hex": "00" * logical_size,
            "after_hex": "aa" * logical_size,
        }
    ]
    assert transition_value["tail_before_hex"] == "57136824" + "00" * 4
    assert transition_value["tail_after_hex"] == (
        "57136824" + "00" * 4 if scenario == "good" else "aa" * 8
    )
    assert transition_value["tail_changed_intervals"] == (
        []
        if scenario == "good"
        else [
            {
                "object_offset_start": 8,
                "object_offset_end": 16,
                "before_hex": "57136824" + "00" * 4,
                "after_hex": "aa" * 8,
            }
        ]
    )
    semantic = HARNESS.heap_object_semantic_result(
        capture.capsule_json,
        report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    bounds = [
        fact for fact in semantic["facts"] if fact["predicate"] == "bounds_violation"
    ]
    assert bounds == (
        []
        if scenario == "good"
        else [
            {
                "kind": "memory",
                "subject": "heap_object:p",
                "predicate": "bounds_violation",
                "status": "inferred",
                "value": "logical_allocation=8:write_length=16",
                "source": (
                    "glaurung-runtime-object-change-report-v1 "
                    "allocation-prefix relation"
                ),
            }
        ]
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(semantic, oracle)
    assert evaluation["matched"] == 1
    if scenario == "good":
        assert evaluation["failures"] == [
            {
                "fact": ("negative", "heap_object:canary", "changed"),
                "error": "missing",
            }
        ]
    else:
        assert evaluation["failures"] == [
            {
                "fact": ("memory", "heap_object:canary", "changed_interval"),
                "error": "missing",
            }
        ]


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize("scenario", ["good", "bad"])
def test_underallocation_direct_canary_store_occurs_across_build_matrix(
    tmp_path: Path,
    compiler: str,
    link: str,
    scenario: str,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_underallocation"
    )
    provider = tmp_path / "heap_snapshot_interposer.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            str(ROOT / "tests/runtime_samples/support/heap_snapshot_interposer.c"),
            "-o",
            str(provider),
        ],
        check=True,
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        timeout=15,
        heap_interposer=provider,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    stores = [
        relation
        for relation in report["executed_stores"]
        if relation.get("operation_occurrence", {}).get("status") == "inferred"
        and relation["operation_occurrence"]["value"]["static_operation"].get(
            "stored_value"
        )
        == {"kind": "constant", "value": 0x24681357}
    ]
    assert len(stores) == 1, stores
    relation = stores[0]
    address = relation["effective_address"]
    assert address["status"] == "inferred", relation
    assert address["value"]["byte_len"] == 4
    occurrence = relation["operation_occurrence"]["value"]
    operation = occurrence["static_operation"]
    assert operation["kind"] == "store"
    assert operation["memory_access"]["byte_len"] == 4
    assert operation["address_expression"]["kind"] == "load"
    assert operation["address_expression"]["byte_len"] == 8
    source_pointer = relation["source_pointer"]
    assert source_pointer["status"] == "inferred", relation
    assert source_pointer["value"]["source_name"] == "canary"
    assert source_pointer["value"]["c_type"] == "uint32_t *"
    assert source_pointer["value"]["static_variable"]["id"].startswith(
        "static-variable-"
    )
    assert source_pointer["value"]["static_type"]["id"].startswith("static-type-")
    assert (
        source_pointer["value"]["static_variable"]["type_id"]
        == source_pointer["value"]["static_type"]["id"]
    )
    address_value = next(
        value
        for value in operation["semantic_values"]
        if value["role"] == "memory_address"
    )
    assert (
        source_pointer["value"]["semantic_binding"]["semantic_value_id"]
        == (address_value["id"])
    )
    assert (
        source_pointer["value"]["semantic_binding"]["variable_id"]
        == (source_pointer["value"]["static_variable"]["id"])
    )
    assert source_pointer["value"]["pointer_byte_len"] == 8
    assert (
        source_pointer["value"]["effective_address"]
        == address["value"]["effective_address"]
    )
    assert source_pointer["value"]["runtime_object_id"] == (
        "heap-object-0000000000000001"
    )
    assert (
        source_pointer["value"]["pointer_value"]
        == address["value"]["effective_address"]
    )
    assert source_pointer["value"]["store_offset_from_pointer"] == 0
    assert relation["allocation_prefix"] == {
        "status": "unknown",
        "reason": (
            "allocation prefix source pointer does not equal the runtime object start"
        ),
    }
    assert relation["allocation_tail"] == {
        "status": "unknown",
        "reason": "allocation tail requires a resolved allocation prefix",
    }
    assert occurrence["event_sequence"] == relation["sequence"]
    assert occurrence["inputs"]["effective_address"]["value"] == str(
        address["value"]["effective_address"]
    )
    assert occurrence["effects"] == [
        {
            "kind": "memory_write",
            "runtime_object_id": "heap-object-0000000000000001",
            "errno": None,
            "address": address["value"]["effective_address"],
            "byte_len": 4,
        }
    ]
    capsule = json.loads(capture.capsule_json)
    event = next(
        event
        for event in capsule["events"]
        if event["kind"] == "instruction_step"
        and event["sequence"] == relation["sequence"]
    )
    assert "stack_changes_payload_id" not in event["fields"]
    heap_object = next(
        item
        for item in capsule["runtime_objects"]
        if item["id"] == "heap-object-0000000000000001"
    )
    heap_snapshots = sorted(
        (
            item
            for item in capsule["object_snapshots"]
            if item["object_id"] == heap_object["id"]
        ),
        key=lambda item: item["point"]["sequence"],
    )
    assert len(heap_snapshots) == 3
    payloads = dict(capture.payloads)
    heap_bytes = [
        payloads[snapshot["content"]["payload"]["id"]] for snapshot in heap_snapshots
    ]
    canary_offset = address["value"]["effective_address"] - heap_object["start"]
    assert heap_bytes[0][canary_offset : canary_offset + 4] == bytes(4)
    assert heap_bytes[1][canary_offset : canary_offset + 4] == bytes.fromhex("57136824")
    assert heap_bytes[2][canary_offset : canary_offset + 4] == (
        bytes.fromhex("57136824") if scenario == "good" else bytes.fromhex("aaaaaaaa")
    )
    transition = relation["object_transition"]
    assert transition["status"] == "inferred", relation
    assert transition["value"] == {
        "runtime_object_id": heap_object["id"],
        "object_offset": canary_offset,
        "byte_len": 4,
        "before_snapshot_id": heap_snapshots[0]["id"],
        "stored_snapshot_id": heap_snapshots[1]["id"],
        "final_snapshot_id": heap_snapshots[2]["id"],
        "before_hex": "00000000",
        "stored_hex": "57136824",
        "final_hex": "57136824" if scenario == "good" else "aaaaaaaa",
        "changed_after_store": scenario == "bad",
    }
    semantic = HARNESS.memory_interval_semantic_result(
        report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    expected_fact = (
        {
            "kind": "negative",
            "subject": "heap_object:canary",
            "predicate": "changed",
            "status": "inferred",
            "value": "false:value=0x24681357",
            "source": (
                "executed LLIR store, DWARF source pointer, and ordered "
                "runtime-object snapshots"
            ),
        }
        if scenario == "good"
        else {
            "kind": "memory",
            "subject": "heap_object:canary",
            "predicate": "changed_interval",
            "status": "inferred",
            "value": "offset=0..4:old=57136824:new=aaaaaaaa:final=0xaaaaaaaa",
            "source": (
                "executed LLIR store, DWARF source pointer, and ordered "
                "runtime-object snapshots"
            ),
        }
    )
    assert semantic["facts"] == [expected_fact]
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(semantic, oracle)
    assert evaluation["matched"] == 1
    object_report = json.loads(
        runtime_analysis.analyze_process_capsule_object_changes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    object_change = next(
        item
        for item in object_report["objects"]
        if item["object_id"] == heap_object["id"]
    )
    assert object_change["creation_occurrence"]["status"] == "inferred", object_change
    assert len(object_change["write_observations"]) == 1
    memset_occurrence = object_change["write_observations"][0]["operation_occurrence"]
    assert memset_occurrence["status"] == "inferred", object_change
    assert (
        memset_occurrence["value"]["static_operation"]["call_target"]["symbol"]
        == "memset"
    )
    if scenario == "good":
        assert object_change["responsible_write"] == {
            "status": "unknown",
            "reason": "expected one bounded write event covering every changed byte, found 0",
        }
        assert object_change["operation_occurrence"] == {
            "status": "unknown",
            "reason": "memory-write occurrence requires one observed write event",
        }
    else:
        assert object_change["responsible_write"]["status"] == "observed"
        assert object_change["operation_occurrence"] == memset_occurrence
    assert object_change["allocation_prefix_write"]["status"] == "inferred", (
        object_change
    )
    assert object_change["allocation_prefix_transition"]["status"] == "inferred", (
        object_change
    )
    occurrence_capture_ids = {
        occurrence["capture_id"],
        object_change["creation_occurrence"]["value"]["capture_id"],
        memset_occurrence["value"]["capture_id"],
    }
    assert occurrence_capture_ids == {capsule["identity"]["capture_id"]}
    heap_semantic = HARNESS.heap_object_semantic_result(
        capture.capsule_json,
        object_report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    combined_semantic = dict(heap_semantic)
    combined_semantic["facts"] = [
        *heap_semantic["facts"],
        *semantic["facts"],
    ]
    combined_evaluation = HARNESS.evaluate_semantic_result(combined_semantic, oracle)
    assert combined_evaluation["passed"], combined_evaluation
    assert combined_evaluation["matched"] == 2
    if scenario == "bad":
        stored_payload_id = heap_snapshots[1]["content"]["payload"]["id"]
        without_stored_snapshot = [
            payload for payload in capture.payloads if payload[0] != stored_payload_id
        ]
        incomplete = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                capture.capsule_json, without_stored_snapshot, binary.read_bytes()
            )
        )
        incomplete_store = next(
            item
            for item in incomplete["executed_stores"]
            if item["sequence"] == relation["sequence"]
        )
        assert incomplete_store["operation_occurrence"]["status"] == "inferred"
        assert incomplete_store["source_pointer"]["status"] == "inferred"
        assert incomplete_store["object_transition"] == {
            "status": "unknown",
            "reason": (f"object snapshot {heap_snapshots[1]['id']} payload is missing"),
        }


@pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("strip") is None,
    reason="gcc or strip is unavailable",
)
def test_underallocation_direct_store_source_requires_dwarf(
    tmp_path: Path,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_underallocation"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    subprocess.run(["strip", "--strip-debug", str(binary)], check=True)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=15,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    stores = [
        relation
        for relation in report["executed_stores"]
        if relation.get("operation_occurrence", {}).get("status") == "inferred"
        and relation["operation_occurrence"]["value"]["static_operation"].get(
            "stored_value"
        )
        == {"kind": "constant", "value": 0x24681357}
    ]
    assert len(stores) == 1, stores
    assert stores[0]["effective_address"]["status"] == "inferred"
    assert stores[0]["source_pointer"] == {
        "status": "unknown",
        "reason": "store function has no DWARF local-variable contract",
    }


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize(
    ("scenario", "object_offset", "before_hex", "final_canary"),
    [("good", 7, "00", "78563412"), ("bad", 8, "78", "ff563412")],
)
def test_heap_index_store_uses_allocator_object_across_build_matrix(
    tmp_path: Path,
    compiler: str,
    link: str,
    scenario: str,
    object_offset: int,
    before_hex: str,
    final_canary: str,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    provider = tmp_path / "heap_snapshot_interposer.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            str(ROOT / "tests/runtime_samples/support/heap_snapshot_interposer.c"),
            "-o",
            str(provider),
        ],
        check=True,
    )
    sample = next(
        item
        for item in HARNESS.load_samples()
        if item.id == "memory_heap_canary_overwrite"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        public_input=scenario.encode(),
        timeout=15,
        heap_interposer=provider,
    )
    capsule = json.loads(capture.capsule_json)
    heap_object = next(
        item
        for item in capsule["runtime_objects"]
        if item["kind"] == "heap" and item["byte_len"] == 16
    )
    assert not any(event["kind"] == "memory_write" for event in capsule["events"])
    snapshots = sorted(
        (
            snapshot
            for snapshot in capsule["object_snapshots"]
            if snapshot["object_id"] == heap_object["id"]
        ),
        key=lambda snapshot: snapshot["point"]["sequence"],
    )
    assert len(snapshots) == 3
    payloads = dict(capture.payloads)
    snapshot_bytes = [
        payloads[snapshot["content"]["payload"]["id"]] for snapshot in snapshots
    ]
    assert snapshot_bytes[0][8:12].hex() == "78563412"
    assert snapshot_bytes[1][8:12].hex() == final_canary
    assert snapshot_bytes[2] == snapshot_bytes[1]

    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    stores = [
        relation
        for relation in report["executed_stores"]
        if relation.get("operation_occurrence", {}).get("status") == "inferred"
        and relation.get("effective_address", {}).get("status") == "inferred"
        and relation["effective_address"]["value"]["effective_address"]
        == heap_object["start"] + object_offset
    ]
    assert len(stores) == 1, stores
    relation = stores[0]
    assert relation["operation_occurrence"]["value"]["static_operation"][
        "stored_value"
    ] == {"kind": "constant", "value": -1}
    assert relation["source_pointer"]["status"] == "inferred", relation
    pointer = relation["source_pointer"]["value"]
    assert pointer["source_name"] == "p"
    assert pointer["runtime_object_id"] == heap_object["id"]
    assert pointer["pointer_value"] == heap_object["start"]
    assert pointer["pointer_object_offset"] == 0
    assert pointer["store_offset_from_pointer"] == object_offset
    prefix = relation["allocation_prefix"]
    assert prefix["status"] == "inferred", prefix
    prefix_value = prefix["value"]
    assert prefix_value["runtime_object_id"] == heap_object["id"]
    assert prefix_value["extent_source_name"] == "n"
    assert prefix_value["logical_prefix_byte_len"] == 8
    assert prefix_value["reserved_tail_byte_len"] == 8
    assert prefix_value["allocation_byte_len"] == 16
    assert prefix_value["store_object_offset"] == object_offset
    assert prefix_value["store_byte_len"] == 1
    assert prefix_value["prefix_bytes_exceeded"] == (0 if scenario == "good" else 1)
    assert prefix_value["classification"] == (
        "within_allocation_prefix"
        if scenario == "good"
        else "crosses_allocation_prefix_within_object"
    )
    assert prefix_value["source_pointer"] == pointer
    assert prefix_value["store_occurrence"] == relation["operation_occurrence"]["value"]
    assert (
        prefix_value["allocation_occurrence"]["capture_id"]
        == capsule["identity"]["capture_id"]
    )
    assert (
        prefix_value["store_occurrence"]["capture_id"]
        == capsule["identity"]["capture_id"]
    )
    tail = relation["allocation_tail"]
    assert tail["status"] == "inferred", tail
    tail_value = tail["value"]
    assert tail_value["runtime_object_id"] == heap_object["id"]
    assert tail_value["source_name"] == "canary"
    assert tail_value["c_type"] == "uint32_t *"
    assert tail_value["pointer_byte_len"] == 8
    assert tail_value["pointer_value"] == heap_object["start"] + 8
    assert tail_value["pointer_object_offset"] == 8
    assert tail_value["pointee_byte_len"] == 4
    assert tail_value["reserved_tail_byte_len"] == 8
    assert tail_value["store_overlap_byte_len"] == (0 if scenario == "good" else 1)
    assert tail_value["before_snapshot_id"] == snapshots[0]["id"]
    assert tail_value["stored_snapshot_id"] == snapshots[1]["id"]
    assert tail_value["final_snapshot_id"] == snapshots[2]["id"]
    assert tail_value["before_hex"] == "78563412"
    assert tail_value["stored_hex"] == final_canary
    assert tail_value["final_hex"] == final_canary
    assert (
        relation["operation_occurrence"]["value"]["effects"][0]["runtime_object_id"]
        == heap_object["id"]
    )
    assert relation["object_transition"]["status"] == "inferred", relation
    transition = relation["object_transition"]["value"]
    assert transition["object_offset"] == object_offset
    assert transition["before_hex"] == before_hex
    assert transition["stored_hex"] == "ff"
    assert transition["final_hex"] == "ff"
    assert transition["changed_after_store"] is False

    semantic = HARNESS.memory_interval_semantic_result(
        report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    assert semantic["facts"] == (
        [
            {
                "kind": "memory",
                "subject": "heap_object:p",
                "predicate": "changed_interval",
                "status": "inferred",
                "value": "offset=7..8:old=00:new=ff",
                "source": (
                    "executed LLIR store within allocation prefix and ordered "
                    "runtime-object snapshots"
                ),
            },
            {
                "kind": "negative",
                "subject": "heap_object:canary",
                "predicate": "changed",
                "status": "inferred",
                "value": "false:value=0x12345678",
                "source": (
                    "occurrence-time allocation-tail pointer and three ordered "
                    "runtime-object snapshots"
                ),
            },
        ]
        if scenario == "good"
        else [
            {
                "kind": "memory",
                "subject": "heap_object:p",
                "predicate": "bounds_violation",
                "status": "inferred",
                "value": "write:index=8:declared_data_length=8",
                "source": (
                    "executed LLIR store, allocation occurrence, DWARF extent, "
                    "and runtime object"
                ),
            },
            {
                "kind": "memory",
                "subject": "heap_object:canary",
                "predicate": "changed_interval",
                "status": "inferred",
                "value": "offset=0..1:old=78:new=ff:final=0x123456ff",
                "source": (
                    "executed LLIR store overlapping an occurrence-time "
                    "allocation-tail pointer and three ordered runtime-object "
                    "snapshots"
                ),
            },
        ]
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(semantic, oracle)
    assert evaluation["matched"] == 2
    assert evaluation["failures"] == []
    if scenario == "bad" and compiler == "gcc" and link == "pie":
        mutated = json.loads(json.dumps(semantic))
        bounds_fact = next(
            fact for fact in mutated["facts"] if fact["predicate"] == "bounds_violation"
        )
        bounds_fact["value"] = "write:index=7:declared_data_length=8"
        mutation_evaluation = HARNESS.evaluate_semantic_result(mutated, oracle)
        assert mutation_evaluation["passed"] is False
        assert mutation_evaluation["failures"] == [
            {
                "fact": ("memory", "heap_object:p", "bounds_violation"),
                "error": "value_mismatch",
                "expected": "write:index=8:declared_data_length=8",
                "observed": "write:index=7:declared_data_length=8",
            }
        ]

    object_report = json.loads(
        runtime_analysis.analyze_process_capsule_object_changes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    object_change = next(
        item
        for item in object_report["objects"]
        if item["object_id"] == heap_object["id"]
    )
    assert object_change["changed_intervals"] == {
        "status": "observed",
        "value": [
            {
                "object_offset_start": object_offset,
                "object_offset_end": object_offset + 1,
                "before_hex": before_hex,
                "after_hex": "ff",
            }
        ],
        "source": "hash-verified object snapshot payloads",
    }
    assert object_change["responsible_write"]["status"] == "unknown"
    if scenario == "bad":
        stored_payload_id = snapshots[1]["content"]["payload"]["id"]
        incomplete = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                capture.capsule_json,
                [item for item in capture.payloads if item[0] != stored_payload_id],
                binary.read_bytes(),
            )
        )
        incomplete_store = next(
            item
            for item in incomplete["executed_stores"]
            if item["sequence"] == relation["sequence"]
        )
        assert incomplete_store["operation_occurrence"]["status"] == "inferred"
        assert incomplete_store["source_pointer"]["status"] == "inferred"
        assert incomplete_store["allocation_prefix"]["status"] == "inferred"
        assert incomplete_store["allocation_tail"] == {
            "status": "unknown",
            "reason": "allocation tail requires a resolved object transition",
        }
        assert incomplete_store["object_transition"] == {
            "status": "unknown",
            "reason": f"object snapshot {snapshots[1]['id']} payload is missing",
        }
        stack_object = next(
            item
            for item in capsule["runtime_objects"]
            if item["id"] == "object-instruction-trace-stack-mapping"
        )
        stack_snapshot = next(
            item
            for item in capsule["object_snapshots"]
            if item["object_id"] == stack_object["id"]
            and item["point"]["sequence"] == 0
        )
        stack_payload_id = stack_snapshot["content"]["payload"]["id"]
        missing_stack = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                capture.capsule_json,
                [item for item in capture.payloads if item[0] != stack_payload_id],
                binary.read_bytes(),
            )
        )
        missing_stack_store = next(
            item
            for item in missing_stack["executed_stores"]
            if item["sequence"] == relation["sequence"]
        )
        assert missing_stack_store["operation_occurrence"]["status"] == "inferred"
        assert missing_stack_store["object_transition"]["status"] == "inferred"
        assert missing_stack_store["source_pointer"] == {
            "status": "unknown",
            "reason": (f"object snapshot {stack_snapshot['id']} payload is missing"),
        }
        assert missing_stack_store["allocation_prefix"] == {
            "status": "unknown",
            "reason": "allocation prefix requires a resolved source pointer",
        }
        assert missing_stack_store["allocation_tail"] == {
            "status": "unknown",
            "reason": "allocation tail requires a resolved allocation prefix",
        }


@pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("strip") is None,
    reason="gcc or strip is unavailable",
)
def test_heap_index_store_source_requires_dwarf(tmp_path: Path) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    provider = tmp_path / "heap_snapshot_interposer.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            str(ROOT / "tests/runtime_samples/support/heap_snapshot_interposer.c"),
            "-o",
            str(provider),
        ],
        check=True,
    )
    sample = next(
        item
        for item in HARNESS.load_samples()
        if item.id == "memory_heap_canary_overwrite"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    subprocess.run(["strip", "--strip-debug", str(binary)], check=True)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=15,
        heap_interposer=provider,
    )
    capsule = json.loads(capture.capsule_json)
    heap_object = next(
        item for item in capsule["runtime_objects"] if item["kind"] == "heap"
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    relation = next(
        item
        for item in report["executed_stores"]
        if item.get("effective_address", {}).get("status") == "inferred"
        and item["effective_address"]["value"]["effective_address"]
        == heap_object["start"] + 8
    )
    assert relation["operation_occurrence"]["status"] == "inferred"
    assert relation["object_transition"]["status"] == "inferred"
    assert relation["source_pointer"] == {
        "status": "unknown",
        "reason": "store function has no DWARF local-variable contract",
    }
    assert relation["allocation_prefix"] == {
        "status": "unknown",
        "reason": "allocation prefix requires a resolved source pointer",
    }
    assert relation["allocation_tail"] == {
        "status": "unknown",
        "reason": "allocation tail requires a resolved allocation prefix",
    }


@pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("strip") is None,
    reason="gcc or strip is unavailable",
)
def test_underallocation_prefix_relation_requires_dwarf_scalar(
    tmp_path: Path,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_heap_snapshots_child

    provider = tmp_path / "heap_snapshot_interposer.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            str(ROOT / "tests/runtime_samples/support/heap_snapshot_interposer.c"),
            "-o",
            str(provider),
        ],
        check=True,
    )
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_underallocation"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    subprocess.run(["strip", "--strip-debug", str(binary)], check=True)
    capture = capture_heap_snapshots_child(
        binary,
        provider,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=HARNESS.fixture_environment(sample),
        public_input=b"bad",
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_object_changes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    changed = next(item for item in report["objects"] if item["object_byte_len"] == 16)
    assert changed["creation_occurrence"]["status"] == "inferred"
    assert changed["operation_occurrence"]["status"] == "inferred"
    assert changed["write_observations"][0]["source_pointer"]["status"] == "unknown"
    assert changed["allocation_prefix_write"] == {
        "status": "unknown",
        "reason": "calloc function has no DWARF local-variable contract",
    }
    assert changed["allocation_prefix_transition"]["status"] == "unknown"


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize("scenario", ["good", "bad"])
def test_heap_provider_preserves_post_free_write_against_ended_object(
    tmp_path: Path, compiler: str, link: str, scenario: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_heap_snapshots_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    provider = tmp_path / "heap_snapshot_interposer.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            str(ROOT / "tests/runtime_samples/support/heap_snapshot_interposer.c"),
            "-o",
            str(provider),
        ],
        check=True,
    )
    sample = next(
        item
        for item in HARNESS.load_samples()
        if item.id == "memory_stale_pointer_write"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_heap_snapshots_child(
        binary,
        provider,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        public_input=scenario.encode(),
    )
    capsule = json.loads(capture.capsule_json)
    runtime_object = next(
        item for item in capsule["runtime_objects"] if item["byte_len"] == 16
    )
    assert "ended_at" in runtime_object
    write_completeness = next(
        item
        for item in capsule["completeness"]
        if item["evidence"] == "heap_object_writes"
    )
    expected_writes = 1 if scenario == "good" else 2
    assert write_completeness == {
        "evidence": "heap_object_writes",
        "status": "complete",
        "requested": True,
        "obtained": expected_writes,
        "expected": expected_writes,
    }

    report = json.loads(
        runtime_analysis.analyze_process_capsule_object_changes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    changed = next(
        item for item in report["objects"] if item["object_id"] == runtime_object["id"]
    )
    writes = changed["write_observations"]
    assert [write["lifetime"] for write in writes] == (
        ["live"] if scenario == "good" else ["live", "ended"]
    )
    assert writes[0]["object_offset"]["value"] == 0
    assert writes[0]["after_hex"]["value"] == "01"
    for write in writes:
        assert write["static_callsite"]["status"] == "inferred", write
        assert write["operation_occurrence"]["status"] == "inferred", write
        assert (
            write["operation_occurrence"]["value"]["static_operation"]["call_target"][
                "symbol"
            ]
            == "memset"
        )
        source_pointer = write["source_pointer"]
        assert source_pointer["status"] == "inferred", (
            source_pointer,
            write["operation_occurrence"]["value"]["static_operation"][
                "call_register_inputs"
            ][0],
        )
        assert source_pointer["value"]["runtime_object_id"] == runtime_object["id"]
        assert source_pointer["value"]["source_name"] == "p"
        assert "unsigned char" in source_pointer["value"]["c_type"]
        assert "*" in source_pointer["value"]["c_type"]
        assert source_pointer["value"]["static_variable"]["id"].startswith(
            "static-variable-"
        )
        assert source_pointer["value"]["static_type"]["id"].startswith("static-type-")
        assert (
            source_pointer["value"]["static_variable"]["type_id"]
            == source_pointer["value"]["static_type"]["id"]
        )
        assert source_pointer["value"]["argument_position"] == 0
        assert source_pointer["value"]["abi_register"] == "rdi"
        call_input = next(
            call_input
            for call_input in write["operation_occurrence"]["value"][
                "static_operation"
            ]["call_register_inputs"]
            if call_input["position"] == 0
        )
        assert (
            source_pointer["value"]["semantic_binding"]["semantic_value_id"]
            == (call_input["value_id"])
        )
        assert (
            source_pointer["value"]["semantic_binding"]["variable_id"]
            == (source_pointer["value"]["static_variable"]["id"])
        )
        assert source_pointer["value"]["relation"] == "points_to_runtime_object_start"
    if scenario == "bad":
        ended = writes[1]
        assert ended["object_offset"]["value"] == 0
        assert ended["after_hex"]["value"] == "09"
        ended_event = next(
            event
            for event in capsule["events"]
            if event["sequence"] == ended["sequence"]
        )
        payload_id = ended_event["fields"]["write_bytes_payload_id"]
        incomplete = json.loads(
            runtime_analysis.analyze_process_capsule_object_changes(
                capture.capsule_json,
                [item for item in capture.payloads if item[0] != payload_id],
                binary.read_bytes(),
            )
        )
        incomplete_object = next(
            item
            for item in incomplete["objects"]
            if item["object_id"] == runtime_object["id"]
        )
        incomplete_ended = incomplete_object["write_observations"][1]
        assert incomplete_ended["lifetime"] == "ended"
        assert incomplete_ended["after_hex"] == {
            "status": "unknown",
            "reason": f"write-byte payload {payload_id} is unavailable",
        }
        assert incomplete_ended["operation_occurrence"]["status"] == "inferred"
        assert incomplete_ended["source_pointer"]["status"] == "inferred"

    result = HARNESS.heap_object_semantic_result(
        capture.capsule_json,
        report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    if scenario == "bad":
        assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
        assert evaluation["matched"] == 2
    else:
        assert not evaluation["passed"]
        assert evaluation["matched"] == 1
        assert evaluation["failures"] == []
        assert evaluation["incomplete"] == [
            {
                "fact": ("negative", "heap_object:p", "changed"),
                "status": "unknown",
                "reason": "write stream is complete only for provider scope ['memset']",
            }
        ]


@pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("strip") is None,
    reason="gcc or strip is unavailable",
)
def test_stale_pointer_source_relation_requires_matching_dwarf(tmp_path: Path) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_heap_snapshots_child

    provider = tmp_path / "heap_snapshot_interposer.so"
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            str(ROOT / "tests/runtime_samples/support/heap_snapshot_interposer.c"),
            "-o",
            str(provider),
        ],
        check=True,
    )
    sample = next(
        item
        for item in HARNESS.load_samples()
        if item.id == "memory_stale_pointer_write"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    subprocess.run(["strip", "--strip-debug", str(binary)], check=True)
    capture = capture_heap_snapshots_child(
        binary,
        provider,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=HARNESS.fixture_environment(sample),
        public_input=b"bad",
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_object_changes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    ended = next(
        write
        for changed in report["objects"]
        for write in changed["write_observations"]
        if write["lifetime"] == "ended"
    )
    assert ended["after_hex"]["value"] == "09"
    assert ended["static_callsite"]["status"] == "inferred"
    assert ended["operation_occurrence"]["status"] == "inferred"
    assert ended["source_pointer"] == {
        "status": "unknown",
        "reason": "call function has no DWARF local-variable contract",
    }


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize(("scenario", "byte_len"), [("good", 8), ("bad", 12)])
def test_integer_truncation_trace_preserves_memset_fill_and_object_effects(
    tmp_path: Path, compiler: str, link: str, scenario: str, byte_len: int
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    sample = next(
        item
        for item in HARNESS.load_samples()
        if item.id == "memory_integer_truncation"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
    )
    instruction_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    call = next(
        relation
        for relation in instruction_report["call_relations"]
        if relation["callee"].get("value") == "memset"
    )
    occurrence = call["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    inputs = occurrence["value"]["inputs"]
    assert inputs["byte_len"]["value"] == str(byte_len)
    assert inputs["fill_byte"]["value"] == "238"
    assert "source_address" not in inputs

    stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    conversions = stack_report["integer_conversion_writes"]
    assert len(conversions) == 1
    conversion = conversions[0]
    assert conversion["source_object"]["source_name"] == "requested"
    assert conversion["converted_object"]["source_name"] == "narrowed"
    assert conversion["source_bits"] == 64
    assert conversion["converted_bits"] == 8
    assert conversion["source_value"] == (8 if scenario == "good" else 265)
    assert conversion["converted_value"] == (8 if scenario == "good" else 9)
    assert conversion["write_field"]["name"] == "dst"
    assert conversion["write_field"]["byte_len"] == 8
    assert conversion["write_bounds"]["write_byte_len"] == byte_len
    assert conversion["classification"] == (
        "narrowing_precedes_bounded_write"
        if scenario == "good"
        else "narrowing_precedes_field_overflow"
    )
    result = HARNESS.stack_write_semantic_result(
        stack_report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    if scenario == "good":
        assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
        assert evaluation["matched"] == 2
    else:
        assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
        assert evaluation["matched"] == 2
        assert evaluation["incomplete"] == []
        assert evaluation["failures"] == []


@pytest.mark.skipif(
    shutil.which("gcc") is None or shutil.which("strip") is None,
    reason="gcc or strip is unavailable",
)
def test_integer_conversion_relation_requires_dwarf_scalars(tmp_path: Path) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item
        for item in HARNESS.load_samples()
        if item.id == "memory_integer_truncation"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    subprocess.run(["strip", "--strip-debug", str(binary)], check=True)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
    )
    report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    assert report["integer_conversion_writes"] == []
    call = next(
        relation
        for relation in report["relations"]
        if relation["event_kind"] == "semantic_call"
    )
    assert call["operation_occurrence"]["status"] == "inferred"
    assert call["operation_occurrence"]["value"]["inputs"]["byte_len"]["value"] == (
        "12"
    )
    assert call["object"]["status"] == "unknown"


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize(("scenario", "length"), [("good", 8), ("bad", 12)])
def test_memcpy_trace_recovers_call_arguments(
    tmp_path: Path, compiler: str, link: str, scenario: str, length: int
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_memcpy_overflow"
    )
    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
    )
    capsule = json.loads(capture.capsule_json)
    trace_ref = capsule["provider.ptrace_single_step"]["register_trace"]
    register_bytes = dict(capture.payloads)[trace_ref["payload_id"]]
    assert hashlib.sha256(register_bytes).hexdigest() == trace_ref["sha256"]
    assert len(register_bytes) == trace_ref["byte_len"]
    register_trace = json.loads(register_bytes)
    assert register_trace["schema"] == "glaurung-instruction-register-trace-v1"
    assert len(register_trace["steps"]) == trace_ref["step_count"]
    assert len(register_trace["steps"]) == sum(
        event["kind"] == "instruction_step" for event in capsule["events"]
    )

    report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    calls = [
        relation
        for relation in report["call_relations"]
        if relation["callee"].get("value") == "memcpy"
    ]
    assert len(calls) == 1, json.dumps(report["call_relations"], sort_keys=True)
    call = calls[0]
    assert call["registers"]["status"] == "observed"
    assert call["operation_occurrence"]["status"] == "inferred", call
    occurrence = call["operation_occurrence"]["value"]
    assert occurrence["static_operation"]["kind"] == "call"
    assert occurrence["static_operation"]["call_target"] == {
        "kind": "direct",
        "address": call["static_target_va"]["value"],
        "symbol": "memcpy",
    }
    static_call = occurrence["static_operation"]
    assert "call_target_expression_id" not in static_call
    assert static_call["call_target_value_id"].startswith("static-value-")
    target_value = next(
        value
        for value in static_call["semantic_values"]
        if value["role"] == "call_target"
    )
    assert target_value["id"] == static_call["call_target_value_id"]
    assert "expression_root_id" not in target_value
    assert static_call["call_register_inputs"]
    for call_input in static_call["call_register_inputs"]:
        assert call_input["expression_id"].startswith("static-expression-")
        assert call_input["value_id"].startswith("static-value-")
        semantic_value = next(
            value
            for value in static_call["semantic_values"]
            if value["role"] == f"call_input_{call_input['position']}"
        )
        assert semantic_value["id"] == call_input["value_id"]
        assert semantic_value["expression_root_id"] == call_input["expression_id"]
    assert occurrence["inputs"]["destination_address"]["value"] == str(
        call["registers"]["value"]["rdi"]
    )
    assert occurrence["inputs"]["source_address"]["value"] == str(
        call["registers"]["value"]["rsi"]
    )
    assert occurrence["inputs"]["byte_len"]["value"] == str(length)
    assert occurrence["effects"] == [
        {
            "kind": "memory_write",
            "runtime_object_id": "object-instruction-trace-stack-mapping",
            "errno": None,
            "address": call["registers"]["value"]["rdi"],
            "byte_len": length,
        }
    ]
    stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    semantic_result = HARNESS.stack_write_semantic_result(
        stack_report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(semantic_result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert evaluation["matched"] == 2


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is unavailable")
def test_memcpy_register_trace_tampering_fails_closed(tmp_path: Path) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_memcpy_overflow"
    )
    binary = HARNESS.compile_sample(sample, "gcc", "O0", "pie", tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, "bad")],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
    )
    capsule = json.loads(capture.capsule_json)
    trace_ref = capsule["provider.ptrace_single_step"]["register_trace"]
    register_bytes = dict(capture.payloads)[trace_ref["payload_id"]]

    incomplete = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json,
            [item for item in capture.payloads if item[0] != trace_ref["payload_id"]],
            binary.read_bytes(),
        )
    )
    incomplete_memcpy = next(
        item
        for item in incomplete["call_relations"]
        if item["callee"].get("value") == "memcpy"
    )
    assert incomplete_memcpy["registers"]["status"] == "unknown"
    assert incomplete_memcpy["operation_occurrence"]["status"] == "unknown"

    baseline = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    call = next(
        item
        for item in baseline["call_relations"]
        if item["callee"].get("value") == "memcpy"
    )
    tampered_trace = json.loads(register_bytes)
    tampered_step = next(
        step for step in tampered_trace["steps"] if step["sequence"] == call["sequence"]
    )
    tampered_step["address"] += 1
    tampered_bytes = json.dumps(
        tampered_trace, sort_keys=True, separators=(",", ":")
    ).encode()
    trace_ref["sha256"] = hashlib.sha256(tampered_bytes).hexdigest()
    trace_ref["byte_len"] = len(tampered_bytes)
    tampered_json = runtime_analysis.canonicalize_process_capsule_json(
        json.dumps(capsule, separators=(",", ":"))
    )
    tampered_payloads = [
        (payload_id, tampered_bytes if payload_id == trace_ref["payload_id"] else data)
        for payload_id, data in capture.payloads
    ]
    inconsistent = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            tampered_json, tampered_payloads, binary.read_bytes()
        )
    )
    inconsistent_memcpy = next(
        item
        for item in inconsistent["call_relations"]
        if item["callee"].get("value") == "memcpy"
    )
    assert inconsistent_memcpy["registers"] == {
        "status": "unknown",
        "reason": "instruction register-trace address disagrees with public event",
    }
    assert inconsistent_memcpy["operation_occurrence"]["status"] == "unknown"


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize("scenario", ["good", "bad"])
def test_memmove_trace_uses_the_shared_copy_call_model(
    tmp_path: Path, compiler: str, link: str, scenario: str
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_memmove_overflow"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
    )
    instruction_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    calls = [
        relation
        for relation in instruction_report["call_relations"]
        if relation["callee"].get("value") == "memmove"
    ]
    assert len(calls) == 1, json.dumps(
        instruction_report["call_relations"], sort_keys=True
    )
    occurrence = calls[0]["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    assert occurrence["value"]["inputs"]["byte_len"]["value"] == (
        "12" if scenario == "bad" else "8"
    )

    stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    result = HARNESS.stack_write_semantic_result(
        stack_report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert evaluation["matched"] == 2


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize(("scenario", "source_bytes"), [("good", 4), ("bad", 12)])
def test_strcpy_trace_derives_length_from_captured_source(
    tmp_path: Path,
    compiler: str,
    link: str,
    scenario: str,
    source_bytes: int,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_strcpy_overflow"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
    )
    instruction_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    call = next(
        relation
        for relation in instruction_report["call_relations"]
        if relation["callee"].get("value") == "strcpy"
    )
    occurrence = call["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    assert occurrence["value"]["inputs"]["source_bytes"]["value"] == str(source_bytes)
    assert occurrence["value"]["effects"][0]["byte_len"] == source_bytes

    stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    result = HARNESS.stack_write_semantic_result(
        stack_report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert evaluation["matched"] == 2

    if scenario == "bad" and compiler == "gcc" and link == "pie":
        capsule = json.loads(capture.capsule_json)
        before_snapshot = min(
            capsule["object_snapshots"],
            key=lambda snapshot: snapshot["point"]["sequence"],
        )
        before_payload_id = before_snapshot["content"]["payload"]["id"]
        incomplete = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                capture.capsule_json,
                [item for item in capture.payloads if item[0] != before_payload_id],
                binary.read_bytes(),
            )
        )
        incomplete_call = next(
            relation
            for relation in incomplete["call_relations"]
            if relation["callee"].get("value") == "strcpy"
        )
        assert incomplete_call["registers"]["status"] == "observed"
        assert incomplete_call["operation_occurrence"] == {
            "status": "unknown",
            "reason": f"strcpy source payload {before_payload_id} is unavailable",
        }


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize(
    ("scenario", "append_bytes", "final_bytes"),
    [("good", 2, 5), ("bad", 9, 12)],
)
def test_strcat_trace_separates_write_start_and_final_extent(
    tmp_path: Path,
    compiler: str,
    link: str,
    scenario: str,
    append_bytes: int,
    final_bytes: int,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_strcat_overflow"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
    )
    instruction_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    call = next(
        relation
        for relation in instruction_report["call_relations"]
        if relation["callee"].get("value") == "strcat"
    )
    occurrence = call["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    inputs = occurrence["value"]["inputs"]
    assert inputs["append_bytes"]["value"] == str(append_bytes)
    assert inputs["final_bytes"]["value"] == str(final_bytes)
    effect = occurrence["value"]["effects"][0]
    assert effect["address"] == int(inputs["write_address"]["value"])
    assert effect["byte_len"] == append_bytes

    stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    result = HARNESS.stack_write_semantic_result(
        stack_report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert evaluation["matched"] == 2

    if scenario == "bad" and compiler == "gcc" and link == "pie":
        capsule = json.loads(capture.capsule_json)
        before_snapshot = min(
            capsule["object_snapshots"],
            key=lambda snapshot: snapshot["point"]["sequence"],
        )
        before_payload_id = before_snapshot["content"]["payload"]["id"]
        incomplete = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                capture.capsule_json,
                [item for item in capture.payloads if item[0] != before_payload_id],
                binary.read_bytes(),
            )
        )
        incomplete_call = next(
            relation
            for relation in incomplete["call_relations"]
            if relation["callee"].get("value") == "strcat"
        )
        assert incomplete_call["registers"]["status"] == "observed"
        assert incomplete_call["operation_occurrence"] == {
            "status": "unknown",
            "reason": f"strcat source payload {before_payload_id} is unavailable",
        }


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize(
    ("scenario", "output_bytes"),
    [("good", 3), ("bad", 13)],
)
def test_sprintf_trace_requires_captured_percent_s_semantics(
    tmp_path: Path,
    compiler: str,
    link: str,
    scenario: str,
    output_bytes: int,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_sprintf_overflow"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
    )
    instruction_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    call = next(
        relation
        for relation in instruction_report["call_relations"]
        if relation["callee"].get("value") == "sprintf"
    )
    occurrence = call["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    inputs = occurrence["value"]["inputs"]
    assert inputs["output_bytes"]["value"] == str(output_bytes)
    assert inputs["source_address"]["value"] != inputs["format_address"]["value"]
    effect = occurrence["value"]["effects"][0]
    assert effect["address"] == int(inputs["destination_address"]["value"])
    assert effect["byte_len"] == output_bytes

    stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    result = HARNESS.stack_write_semantic_result(
        stack_report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert evaluation["matched"] == 2

    if scenario == "bad" and compiler == "gcc" and link == "pie":
        capsule = json.loads(capture.capsule_json)
        before_snapshot = min(
            capsule["object_snapshots"],
            key=lambda snapshot: snapshot["point"]["sequence"],
        )
        before_payload_id = before_snapshot["content"]["payload"]["id"]
        incomplete = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                capture.capsule_json,
                [item for item in capture.payloads if item[0] != before_payload_id],
                binary.read_bytes(),
            )
        )
        incomplete_call = next(
            relation
            for relation in incomplete["call_relations"]
            if relation["callee"].get("value") == "sprintf"
        )
        assert incomplete_call["registers"]["status"] == "observed"
        assert incomplete_call["operation_occurrence"] == {
            "status": "unknown",
            "reason": f"sprintf format payload {before_payload_id} is unavailable",
        }

        format_address = int(inputs["format_address"]["value"])
        object_record = next(
            runtime_object
            for runtime_object in capsule["runtime_objects"]
            if runtime_object["id"] == before_snapshot["object_id"]
        )
        snapshot_start = object_record["start"] + before_snapshot["object_offset"]
        format_offset = format_address - snapshot_start
        mutated_payload = bytearray(dict(capture.payloads)[before_payload_id])
        assert mutated_payload[format_offset : format_offset + 3] == b"%s\0"
        mutated_payload[format_offset : format_offset + 3] = b"%d\0"
        before_snapshot["content"]["payload"]["sha256"] = hashlib.sha256(
            mutated_payload
        ).hexdigest()
        unsupported = json.loads(
            runtime_analysis.analyze_process_capsule_instruction_trace(
                json.dumps(capsule),
                [
                    (payload_id, bytes(mutated_payload))
                    if payload_id == before_payload_id
                    else (payload_id, payload)
                    for payload_id, payload in capture.payloads
                ],
                binary.read_bytes(),
            )
        )
        unsupported_call = next(
            relation
            for relation in unsupported["call_relations"]
            if relation["callee"].get("value") == "sprintf"
        )
        assert unsupported_call["operation_occurrence"] == {
            "status": "unknown",
            "reason": (
                "sprintf format semantics are only implemented for an exact "
                "captured %s format"
            ),
        }


@pytest.mark.parametrize(
    ("compiler", "link"),
    [("gcc", "pie"), ("gcc", "no-pie"), ("clang", "pie"), ("clang", "no-pie")],
)
@pytest.mark.parametrize(
    ("scenario", "callee"),
    [("good", "memmove"), ("bad", "memcpy")],
)
def test_overlapping_copy_uses_call_contract_to_classify_precondition(
    tmp_path: Path,
    compiler: str,
    link: str,
    scenario: str,
    callee: str,
) -> None:
    from glaurung import runtime_analysis
    from glaurung.runtime_capture import capture_instruction_trace_child

    if shutil.which(compiler) is None:
        pytest.skip(f"{compiler} is unavailable")
    sample = next(
        item for item in HARNESS.load_samples() if item.id == "memory_overlapping_copy"
    )
    binary = HARNESS.compile_sample(sample, compiler, "O0", link, tmp_path)
    capture = capture_instruction_trace_child(
        binary,
        [HARNESS.scenario_arg(sample, scenario)],
        environment=HARNESS.fixture_environment(sample),
        cwd=tmp_path,
        timeout=30,
    )
    instruction_report = json.loads(
        runtime_analysis.analyze_process_capsule_instruction_trace(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    call = next(
        relation
        for relation in instruction_report["call_relations"]
        if relation["callee"].get("value") == callee
    )
    occurrence = call["operation_occurrence"]
    assert occurrence["status"] == "inferred", occurrence
    inputs = occurrence["value"]["inputs"]
    source = int(inputs["source_address"]["value"])
    destination = int(inputs["destination_address"]["value"])
    byte_len = int(inputs["byte_len"]["value"])
    assert byte_len == 8
    assert source < destination + byte_len
    assert destination < source + byte_len

    stack_report = json.loads(
        runtime_analysis.analyze_process_capsule_stack_writes(
            capture.capsule_json, list(capture.payloads), binary.read_bytes()
        )
    )
    result = HARNESS.stack_write_semantic_result(
        stack_report,
        sample=sample.id,
        scenario=scenario,
        compiler=compiler,
        opt="O0",
        link=link,
    )
    oracle = HARNESS.load_semantic_oracles(samples=[sample])[(sample.id, scenario)]
    evaluation = HARNESS.evaluate_semantic_result(result, oracle)
    assert evaluation["passed"], json.dumps(evaluation, sort_keys=True)
    assert evaluation["matched"] == 2
