#!/usr/bin/env python3
"""Fail-closed structural validator for a Glaurung ordered trace v1 directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from dataclasses import dataclass, field


def fail(message: str) -> None:
    raise ValueError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def framed_digest(scopes: list[tuple[str, str]]) -> str:
    digest = hashlib.sha256()
    digest.update(b"glaurung-scope-digest-v1\0")
    for scope_id, constraint_id in scopes:
        for value in (scope_id, constraint_id):
            encoded = value.encode()
            digest.update(len(encoded).to_bytes(8, "little"))
            digest.update(encoded)
    return digest.hexdigest()


@dataclass
class PathState:
    scopes: list[tuple[str, str | None]] = field(default_factory=list)
    next_seq: int = 0
    ended: bool = False
    last_event: str | None = None
    last_check: str | None = None
    last_model_read: str | None = None


def assertion_hashes(script: bytes) -> list[str]:
    # Glaurung's sharing-preserving writer emits every assertion on one line.
    # Retain the newline because the producer hashes the exact assertion bytes.
    lines = script.splitlines(keepends=True)
    return [sha256(line) for line in lines if line.startswith(b"(assert ")]


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read JSON {path}: {error}")


def validate(root: pathlib.Path) -> dict[str, int]:
    manifest_path = root / "trace-manifest-v1.json"
    events_path = root / "events-v1.ndjson"
    index_path = root / "query-index-v1.json"
    manifest = load_json(manifest_path)
    index = load_json(index_path)
    if not isinstance(manifest, dict) or manifest.get("schema") != "glaurung-ordered-trace-v1":
        fail("manifest schema is not glaurung-ordered-trace-v1")
    if manifest.get("version") != 1:
        fail("manifest version is not 1")
    events_bytes = events_path.read_bytes()
    index_bytes = index_path.read_bytes()
    if sha256(events_bytes) != manifest.get("events_sha256"):
        fail("events SHA-256 does not match manifest")
    if sha256(index_bytes) != manifest.get("query_index_sha256"):
        fail("query-index SHA-256 does not match manifest")

    query_rows = index.get("queries") if isinstance(index, dict) else None
    if not isinstance(query_rows, list):
        fail("query-index queries is not an array")
    indexed: dict[str, dict] = {}
    for row in query_rows:
        if not isinstance(row, dict):
            fail("query-index row is not an object")
        content_hash = row.get("content_hash")
        relative = row.get("path")
        if not isinstance(content_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", content_hash):
            fail(f"invalid query content hash: {content_hash!r}")
        if content_hash in indexed:
            fail(f"duplicate query-index row: {content_hash}")
        if relative != f"queries/{content_hash}.smt2":
            fail(f"non-canonical query path for {content_hash}: {relative!r}")
        query_bytes = (root / relative).read_bytes()
        if sha256(query_bytes) != content_hash:
            fail(f"query bytes do not match content hash: {content_hash}")
        outcomes = row.get("outcomes")
        if not isinstance(outcomes, list) or not outcomes:
            fail(f"query {content_hash} has no outcomes")
        if "sat" in outcomes and "unsat" in outcomes:
            fail(f"query {content_hash} has conflicting decided outcomes")
        indexed[content_hash] = row
    stored = {path.stem for path in (root / "queries").glob("*.smt2")}
    if stored != set(indexed):
        fail(
            "query-store membership differs from query index: "
            f"unindexed={sorted(stored - set(indexed))[:5]} "
            f"missing={sorted(set(indexed) - stored)[:5]}"
        )

    paths: dict[str, PathState] = {"analysis": PathState()}
    checks: dict[str, tuple[str, str]] = {}
    model_reads: dict[str, str] = {}
    observed_occurrences: dict[str, list[tuple[str, str, int]]] = {}
    next_event = next_process = next_worker = 0
    analysis_id = process_id = worker_id = None
    event_count = 0
    kinds: list[str] = []
    for line_number, raw in enumerate(events_bytes.splitlines(), 1):
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as error:
            fail(f"invalid event JSON on line {line_number}: {error}")
        if not isinstance(event, dict) or event.get("version") != 1:
            fail(f"invalid event envelope on line {line_number}")
        for field_name, expected in (
            ("event_seq", next_event),
            ("process_seq", next_process),
            ("worker_seq", next_worker),
        ):
            if event.get(field_name) != expected:
                fail(f"non-contiguous {field_name} on line {line_number}: {event.get(field_name)!r} != {expected}")
        next_event += 1
        next_process += 1
        next_worker += 1
        event_count += 1
        for field_name, prior in (
            ("analysis_id", analysis_id),
            ("process_id", process_id),
            ("worker_id", worker_id),
        ):
            current = event.get(field_name)
            if not isinstance(current, str) or not current:
                fail(f"missing {field_name} on line {line_number}")
            if prior is not None and current != prior:
                fail(f"{field_name} changed on line {line_number}")
            if field_name == "analysis_id":
                analysis_id = current
            elif field_name == "process_id":
                process_id = current
            else:
                worker_id = current

        path_id = event.get("path_id")
        kind = event.get("event")
        if not isinstance(kind, str):
            fail(f"missing event kind on line {line_number}")
        kinds.append(kind)
        if kind == "path_start":
            if path_id in paths:
                fail(f"duplicate path start: {path_id}")
            parent = event.get("parent_path_id")
            if parent is None:
                inherited: list[tuple[str, str | None]] = []
            else:
                if parent not in paths or paths[parent].ended:
                    fail(f"path {path_id} references missing/ended parent {parent}")
                inherited = list(paths[parent].scopes)
            state = PathState(scopes=inherited)
            paths[path_id] = state
            complete = [(scope, constraint) for scope, constraint in inherited if constraint is not None]
            if len(complete) != len(inherited) or framed_digest(complete) != event.get("scope_digest"):
                fail(f"bad inherited scope digest for {path_id}")
        elif not isinstance(path_id, str) or path_id not in paths:
            fail(f"event {kind!r} references unknown path {path_id!r}")
        state = paths[path_id]
        if event.get("path_seq") != state.next_seq:
            fail(f"non-contiguous path_seq on {path_id}: {event.get('path_seq')!r} != {state.next_seq}")
        state.next_seq += 1
        if state.ended and kind != "path_start":
            fail(f"event after terminal event on {path_id}: {kind}")

        if kind == "push":
            if event.get("prior_depth") != len(state.scopes):
                fail(f"bad push prior depth on {path_id}")
            scope_id = event.get("scope_id")
            if not isinstance(scope_id, str) or any(scope_id == scope for scope, _ in state.scopes):
                fail(f"invalid/reused active scope ID on {path_id}: {scope_id!r}")
            state.scopes.append((scope_id, None))
            if event.get("resulting_depth") != len(state.scopes):
                fail(f"bad push resulting depth on {path_id}")
        elif kind == "assert":
            if not state.scopes or state.scopes[-1][0] != event.get("scope_id") or state.scopes[-1][1] is not None:
                fail(f"assert does not fill the top scope on {path_id}")
            constraint = event.get("constraint_id")
            if not isinstance(constraint, str) or not re.fullmatch(r"[0-9a-f]{64}", constraint):
                fail(f"invalid constraint ID on {path_id}")
            if event.get("assertion_sha256") != constraint or event.get("sort_validated") is not True:
                fail(f"unvalidated assertion on {path_id}")
            state.scopes[-1] = (state.scopes[-1][0], constraint)
            complete = [(scope, value) for scope, value in state.scopes if value is not None]
            if len(complete) != len(state.scopes) or framed_digest(complete) != event.get("scope_digest"):
                fail(f"bad assertion scope digest on {path_id}")
        elif kind == "check":
            check_id = event.get("check_id")
            query_hash = event.get("query_sha256")
            outcome = event.get("outcome")
            if not isinstance(check_id, str) or check_id in checks:
                fail(f"duplicate/invalid check ID: {check_id!r}")
            if query_hash not in indexed or outcome not in {"sat", "unsat", "unknown", "error"}:
                fail(f"invalid query/outcome for {check_id}")
            complete = [(scope, value) for scope, value in state.scopes if value is not None]
            if len(complete) != len(state.scopes):
                fail(f"check with unasserted scope on {path_id}")
            if event.get("scope_depth") != len(complete) or event.get("active_constraint_count") != len(complete):
                fail(f"check scope/count mismatch for {check_id}")
            if framed_digest(complete) != event.get("scope_digest"):
                fail(f"check scope digest mismatch for {check_id}")
            query_bytes = (root / f"queries/{query_hash}.smt2").read_bytes()
            if assertion_hashes(query_bytes) != [value for _, value in complete]:
                fail(f"query assertions do not reconstruct active scopes for {check_id}")
            if outcome not in indexed[query_hash]["outcomes"]:
                fail(f"check outcome absent from query index for {check_id}")
            checks[check_id] = (outcome, path_id)
            observed_occurrences.setdefault(query_hash, []).append((check_id, path_id, event["event_seq"]))
            state.last_check = check_id
            state.last_model_read = None
            if outcome in {"unknown", "error"} and not event.get("outcome_detail"):
                fail(f"unclassified {outcome} outcome for {check_id}")
        elif kind == "model_read":
            read_id = event.get("model_read_id")
            check_id = event.get("check_id")
            if not isinstance(read_id, str) or read_id in model_reads:
                fail(f"duplicate/invalid model-read ID: {read_id!r}")
            if checks.get(check_id) != ("sat", path_id):
                fail(f"model read {read_id} does not follow a SAT check on the same path")
            if state.last_event != "check" or state.last_check != check_id:
                fail(f"model read {read_id} is not immediately after its SAT check on the path")
            width = event.get("width")
            if not isinstance(width, int) or width <= 0 or event.get("sort") != f"(_ BitVec {width})":
                fail(f"bad model-read sort for {read_id}")
            model_reads[read_id] = check_id
            state.last_model_read = read_id
        elif kind == "model_choice":
            check_id = event.get("check_id")
            read_ids = event.get("model_read_ids")
            if checks.get(check_id) != ("sat", path_id) or not isinstance(read_ids, list) or not read_ids:
                fail(f"invalid model choice on {path_id}")
            if any(model_reads.get(read_id) != check_id for read_id in read_ids):
                fail(f"model choice references foreign/missing reads on {path_id}")
            if state.last_event != "model_read" or state.last_model_read not in read_ids:
                fail(f"model choice is not immediately after its model read on {path_id}")
        elif kind == "pop":
            if not state.scopes or event.get("scope_id") != state.scopes[-1][0]:
                fail(f"scope underflow/mismatch on {path_id}")
            if event.get("prior_depth") != len(state.scopes):
                fail(f"bad pop prior depth on {path_id}")
            state.scopes.pop()
            if event.get("resulting_depth") != len(state.scopes):
                fail(f"bad pop resulting depth on {path_id}")
            complete = [(scope, value) for scope, value in state.scopes if value is not None]
            if len(complete) != len(state.scopes) or framed_digest(complete) != event.get("scope_digest"):
                fail(f"bad pop scope digest on {path_id}")
        elif kind == "path_end":
            complete = [(scope, value) for scope, value in state.scopes if value is not None]
            if len(complete) != len(state.scopes) or framed_digest(complete) != event.get("scope_digest"):
                fail(f"bad terminal scope digest on {path_id}")
            if event.get("terminal_scope_depth") != len(state.scopes):
                fail(f"bad terminal scope depth on {path_id}")
            state.ended = True
        state.last_event = kind

    for path_id, state in paths.items():
        if path_id != "analysis" and not state.ended:
            fail(f"unterminated path: {path_id}")
    if event_count != manifest.get("event_count"):
        fail("manifest event count mismatch")
    if not kinds or kinds[0] != "analysis_start" or kinds[-1] != "analysis_end":
        fail("analysis_start/analysis_end do not bound the event stream")
    if kinds.count("analysis_start") != 1 or kinds.count("analysis_end") != 1:
        fail("analysis boundary events are not unique")
    if len(paths) - 1 != manifest.get("path_count"):
        fail("manifest path count mismatch")
    if len(indexed) != manifest.get("query_count"):
        fail("manifest query count mismatch")
    for query_hash, row in indexed.items():
        expected = [
            (entry.get("check_id"), entry.get("path_id"), entry.get("event_seq"))
            for entry in row.get("occurrences", [])
        ]
        if expected != observed_occurrences.get(query_hash, []):
            fail(f"query-index occurrences disagree with events for {query_hash}")
        observed_outcomes = {
            checks[check_id][0]
            for check_id, _, _ in observed_occurrences.get(query_hash, [])
        }
        if observed_outcomes != set(row["outcomes"]):
            fail(f"query-index outcomes disagree with events for {query_hash}")
    return {
        "events": event_count,
        "paths": len(paths) - 1,
        "queries": len(indexed),
        "checks": len(checks),
        "model_reads": len(model_reads),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=pathlib.Path)
    args = parser.parse_args()
    try:
        summary = validate(args.trace)
    except (OSError, ValueError) as error:
        print(f"ordered trace INVALID: {error}", file=sys.stderr)
        return 1
    print("ordered trace valid: " + " ".join(f"{key}={value}" for key, value in summary.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
