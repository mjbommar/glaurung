"""The reachability ratchet from `docs/history/development/test-estate/01-reachability.md`.

    Everything else in the plan lands into the estate this phase repairs. The
    failure mode being closed: a test that exists, is tracked, reads as
    coverage -- and is run by nothing.

`docs/test-inventory/findings.md` counted 89 such entries. Every invariant
below would have caught one of them *at the moment it was introduced*:

* Ten files in `tests/triage/` are named by no `mod` declaration anywhere, so
  they have never compiled -- 28 tests including the adversarial suite whose
  whole premise is that a truncated ELF/PE/gzip must error rather than panic.
* `tests/register_view_semantics.rs` is `#![cfg(feature = "exec")]`, so a
  plain `cargo test` builds it to an EMPTY target and reports it **passing**.
  24 tests, the only lifter<->emulator differential in the tree.
* All 63 `samples/binaries/metadata/*.json` files fail `json.load` -- they
  contain literal `\n` two-character sequences instead of newlines.
* `tests/decompiler_fixtures/src/` numbering runs 175 -> 181 and 199 -> 201,
  because five Go fixtures were written and never wired and fixture 200 does
  not exist at all. A numbering gap is the visible symptom of a corpus entry
  that reads as present in a report and is measured by nothing.

These are static checks -- no compilation, no binary execution, no network --
so this file costs milliseconds and runs on every `uv run pytest`. Invariants
that cannot be decided statically (does CI *really* run the suite?) are out of
scope here; `01-reachability.md` 1.5 covers those.

Each assertion names the offending file and says what to do about it. When one
fails, the fix is to make the estate reachable -- never to widen a constant
here so the failure goes away.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TESTS = ROOT / "tests"
TRIAGE_TESTS = TESTS / "triage"
FUZZ = ROOT / "fuzz"
BENCHES = ROOT / "benches"
CARGO_TOML = ROOT / "Cargo.toml"
SAMPLE_METADATA = ROOT / "samples" / "binaries" / "metadata"
FIXTURE_SRC = TESTS / "decompiler_fixtures" / "src"


# --- a) every tests/triage/*.rs is declared by tests/triage/mod.rs -----------

_MOD_DECL_RE = re.compile(r"^\s*(?:pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", re.M)


def declared_triage_modules() -> set[str]:
    """The module names `tests/triage/mod.rs` actually declares.

    Only bare `mod name;` declarations count -- an inline `mod name { .. }`
    body is not a file reference, so it must not be able to launder a
    same-named orphan file into looking reachable.
    """
    text = (TRIAGE_TESTS / "mod.rs").read_text(encoding="utf-8")
    return set(_MOD_DECL_RE.findall(text))


def triage_test_files() -> set[str]:
    """Every `tests/triage/*.rs` stem except `mod.rs` itself."""
    return {p.stem for p in TRIAGE_TESTS.glob("*.rs") if p.name != "mod.rs"}


def test_the_triage_module_discovery_is_not_vacuous():
    """A layout move that emptied either side would make the two checks below
    pass while proving nothing. Catch that first."""
    assert (TRIAGE_TESTS / "mod.rs").is_file(), (
        f"{TRIAGE_TESTS / 'mod.rs'} is missing; if the triage integration "
        "tests moved, point this module at the new location rather than "
        "deleting the check"
    )
    assert triage_test_files(), f"no *.rs files found beside {TRIAGE_TESTS / 'mod.rs'}"
    assert declared_triage_modules(), (
        f"{TRIAGE_TESTS / 'mod.rs'} declares no modules at all"
    )


def test_every_triage_test_file_is_declared_in_mod_rs():
    """`tests/triage/` is a non-`mod.rs` directory module: a sibling `.rs`
    file that no `mod` names is never compiled, never run, and reported by
    nothing. Ten files sat in exactly that state for their whole lives."""
    undeclared = sorted(triage_test_files() - declared_triage_modules())
    assert undeclared == [], (
        "tests/triage/*.rs file(s) that no `mod` declaration names -- these "
        "are NEVER COMPILED and never run, and nothing else in the tree will "
        "report that. Add `mod <name>;` to tests/triage/mod.rs (one at a "
        "time -- never-compiled code rots), fix what breaks, and delete any "
        "test whose premise is no longer true rather than `#[ignore]`-ing it "
        "into a new kind of unreachable:\n"
        + "\n".join(
            f"  tests/triage/{stem}.rs  (add `mod {stem};`)" for stem in undeclared
        )
    )


def test_no_mod_declaration_names_a_missing_triage_file():
    """The other direction: a `mod` left behind by a deleted file does not
    compile, so this can only fail transiently -- but it fails here with a
    file name instead of a rustc error a Python-side run never sees."""
    missing = sorted(declared_triage_modules() - triage_test_files())
    assert missing == [], (
        "tests/triage/mod.rs declares module(s) with no matching file; "
        "delete the stale declaration or restore the file:\n"
        + "\n".join(
            f"  mod {stem};  -> tests/triage/{stem}.rs not found" for stem in missing
        )
    )


# --- b) feature-gated top-level integration tests must name their runner ----
#
# A top-level `tests/*.rs` that opens with `#![cfg(feature = "X")]` compiles
# to an EMPTY target under a plain `cargo test` -- and cargo reports that
# empty target as passing, by name, with `0 passed; 0 failed`. Nothing in the
# output distinguishes "ran nothing" from "ran and was fine".
#
# So every such file must appear here with the exact command that actually
# runs it. The registry is the answer to "what types this file into a
# terminal, and does anything call that?".
#
# `docs/history/development/test-estate/01-reachability.md` 1.3 adds the command
# below to `scripts/decbench-local-gate.sh` lane 1; until it lands, the entry
# records that the only runner is a human typing it.
FEATURE_GATED_TEST_RUNNERS: dict[str, tuple[str, str]] = {
    # file stem -> (feature, command that runs it)
    "register_view_semantics": (
        "exec",
        "cargo test --features exec --test register_view_semantics",
    ),
}

_INNER_CFG_RE = re.compile(r"^#!\[cfg\((.*)\)\]", re.M)
_FEATURE_RE = re.compile(r'feature\s*=\s*"([^"]+)"')


def feature_gated_top_level_tests() -> dict[str, set[str]]:
    """`{stem: {feature, ...}}` for every top-level `tests/*.rs` carrying a
    crate-level `#![cfg(...)]` that mentions a feature.

    Matched at column 0 with `re.M` because a crate-level inner attribute can
    only appear in the file header, after the `//!` doc comment -- which is
    exactly where `register_view_semantics.rs` puts it (line 24). `all(...)`
    and `any(...)` forms are handled by collecting every `feature = "..."` in
    the attribute rather than assuming a single one.
    """
    found: dict[str, set[str]] = {}
    for path in sorted(TESTS.glob("*.rs")):
        text = path.read_text(encoding="utf-8")
        features: set[str] = set()
        for attr in _INNER_CFG_RE.findall(text):
            features.update(_FEATURE_RE.findall(attr))
        if features:
            found[path.stem] = features
    return found


def test_every_feature_gated_top_level_test_is_registered():
    gated = feature_gated_top_level_tests()

    unregistered = sorted(set(gated) - set(FEATURE_GATED_TEST_RUNNERS))
    assert unregistered == [], (
        "top-level tests/*.rs file(s) gated behind a cargo feature with no "
        "entry in FEATURE_GATED_TEST_RUNNERS. A plain `cargo test` builds "
        "these to an EMPTY target and reports them PASSING, so an unregistered "
        "one is indistinguishable from working coverage. Add each with the "
        "feature and the exact command that runs it, and make sure something "
        "actually types that command:\n"
        + "\n".join(
            f"  tests/{stem}.rs  (features: {', '.join(sorted(gated[stem]))})"
            for stem in unregistered
        )
    )

    stale = sorted(set(FEATURE_GATED_TEST_RUNNERS) - set(gated))
    assert stale == [], (
        "FEATURE_GATED_TEST_RUNNERS entries for file(s) that are no longer "
        "feature-gated (or no longer exist). The registry must track reality "
        "exactly -- remove the stale entry:\n"
        + "\n".join(f"  tests/{stem}.rs" for stem in stale)
    )


def test_each_registered_feature_matches_the_gate_in_the_file():
    gated = feature_gated_top_level_tests()
    for stem, (feature, _command) in sorted(FEATURE_GATED_TEST_RUNNERS.items()):
        if stem not in gated:
            continue  # reported by the test above
        assert feature in gated[stem], (
            f"FEATURE_GATED_TEST_RUNNERS records feature {feature!r} for "
            f"tests/{stem}.rs, but its `#![cfg(...)]` names "
            f"{sorted(gated[stem])!r}. Update the registry -- the recorded "
            "command runs the wrong feature, which means it runs nothing."
        )


def test_each_registered_command_actually_names_the_test_and_the_feature():
    """A registry of commands is only worth anything if the commands are real.
    `cargo test --features exec` alone would build the whole exec-gated suite
    and is a fine thing to run, but it is not evidence that *this* target was
    selected -- so the entry has to name the target too."""
    for stem, (feature, command) in sorted(FEATURE_GATED_TEST_RUNNERS.items()):
        assert "cargo test" in command, (
            f"FEATURE_GATED_TEST_RUNNERS[{stem!r}] command {command!r} is not "
            "a `cargo test` invocation; a feature-gated integration test is "
            "run by nothing else"
        )
        assert f"--features {feature}" in command, (
            f"FEATURE_GATED_TEST_RUNNERS[{stem!r}] command {command!r} does "
            f"not pass `--features {feature}`, so it builds the target EMPTY "
            "and reports it passing -- the exact failure this registry exists "
            "to prevent"
        )
        assert f"--test {stem}" in command, (
            f"FEATURE_GATED_TEST_RUNNERS[{stem!r}] command {command!r} does "
            f"not select `--test {stem}`; name the target so the command is "
            "evidence this file ran rather than evidence the feature built"
        )


# --- c) fuzz targets: declaration and file must agree -----------------------
#
# `fuzz/` is a separate crate and not a workspace member, so `cargo check
# --all-targets` never sees it in any gate lane (findings.md 5). Nothing
# builds it, which means a `[[bin]]` pointing at a deleted file and an
# orphaned `fuzz_targets/*.rs` are equally invisible.


def fuzz_bin_declarations() -> dict[str, str]:
    """`{bin name: declared path}` from `fuzz/Cargo.toml`."""
    with (FUZZ / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    return {
        entry["name"]: entry.get("path", f"fuzz_targets/{entry['name']}.rs")
        for entry in manifest.get("bin", [])
    }


def test_the_fuzz_crate_still_declares_targets():
    """Guards the two checks below against an emptied manifest."""
    assert (FUZZ / "Cargo.toml").is_file(), f"{FUZZ / 'Cargo.toml'} is missing"
    assert fuzz_bin_declarations(), (
        "fuzz/Cargo.toml declares no [[bin]] targets; if the fuzzing crate "
        "was retired, delete it and this check together"
    )


def test_every_fuzz_bin_declaration_has_a_target_file():
    declared = fuzz_bin_declarations()
    missing = sorted(
        (name, path) for name, path in declared.items() if not (FUZZ / path).is_file()
    )
    assert missing == [], (
        "fuzz/Cargo.toml [[bin]] target(s) whose source file does not exist. "
        "Nothing in any gate lane builds the fuzz crate, so this is silent "
        "until someone runs `cargo fuzz`. Restore the file or delete the "
        "[[bin]] block:\n"
        + "\n".join(
            f"  [[bin]] {name} -> fuzz/{path} not found" for name, path in missing
        )
    )


def test_every_fuzz_target_is_actually_run_by_the_nightly_workflow():
    """Declared and built is not the same as run.

    The two checks above make a target buildable; they say nothing about
    whether anything executes it. All eight were compile-verified by the
    twelfth feature-gate lane and executed by NOTHING until
    `.github/workflows/fuzz-nightly.yml` existed -- and a target that is built
    and never run is the same defect this whole file exists to catch, one
    layer up.

    So the workflow's matrix must name every declared target. A new [[bin]]
    that nobody adds here is a fuzzer that quietly never runs.
    """
    workflow = ROOT / ".github" / "workflows" / "fuzz-nightly.yml"
    assert workflow.is_file(), (
        f"{workflow.relative_to(ROOT)} is missing. If nightly fuzzing was "
        "retired deliberately, delete this test with it and say why -- do not "
        "leave eight targets that nothing runs."
    )
    import yaml

    matrix = yaml.safe_load(workflow.read_text())["jobs"]["fuzz"]["strategy"]["matrix"][
        "target"
    ]
    declared = set(fuzz_bin_declarations())
    listed = set(matrix)
    assert declared == listed, (
        "the nightly fuzz matrix and fuzz/Cargo.toml disagree about which "
        f"targets exist.\n  declared but never run: {sorted(declared - listed)}"
        f"\n  run but not declared:    {sorted(listed - declared)}"
    )


def test_every_fuzz_target_file_is_declared_as_a_bin():
    declared_paths = {
        (FUZZ / path).resolve() for path in fuzz_bin_declarations().values()
    }
    orphans = sorted(
        p
        for p in (FUZZ / "fuzz_targets").glob("*.rs")
        if p.resolve() not in declared_paths
    )
    assert orphans == [], (
        "fuzz/fuzz_targets/*.rs file(s) that no [[bin]] in fuzz/Cargo.toml "
        "declares -- they are never built and `cargo fuzz list` will not show "
        "them. Add a [[bin]] block (name, path, `test = false`, `doc = false`, "
        "`bench = false`) or delete the file:\n"
        + "\n".join(f"  {p.relative_to(ROOT)}" for p in orphans)
    )


# --- d) every [[bench]] in the root manifest has a source file --------------


def bench_declarations() -> dict[str, str]:
    """`{bench name: declared path}` from the root `Cargo.toml`.

    Cargo's default for a `[[bench]]` without an explicit `path` is
    `benches/<name>.rs`, which is what every entry relies on today.
    """
    with CARGO_TOML.open("rb") as handle:
        manifest = tomllib.load(handle)
    return {
        entry["name"]: entry.get("path", f"benches/{entry['name']}.rs")
        for entry in manifest.get("bench", [])
    }


def test_the_root_manifest_still_declares_benches():
    assert bench_declarations(), (
        "Cargo.toml declares no [[bench]] targets; the criterion suite is "
        "documented in CLAUDE.md, so an empty list is a manifest accident"
    )


def test_every_declared_bench_has_a_source_file():
    """Nothing anywhere invokes `cargo bench` (findings.md 5), so a
    `[[bench]]` pointing at a file that was never written -- or was deleted --
    produces no error from any command the project runs."""
    missing = sorted(
        (name, path)
        for name, path in bench_declarations().items()
        if not (ROOT / path).is_file()
    )
    assert missing == [], (
        "Cargo.toml [[bench]] target(s) with no source file. Nothing in the "
        "repository runs `cargo bench`, so this only surfaces when a human "
        "tries. Write the bench or delete the [[bench]] block:\n"
        + "\n".join(f"  [[bench]] {name} -> {path} not found" for name, path in missing)
    )


# --- e) every committed sample metadata sidecar is real JSON ----------------


def test_every_sample_metadata_json_parses():
    """`samples/binaries/metadata/` is committed, reads as corpus
    documentation, and nothing loads it -- which is how all 63 files came to
    contain literal `\\n` two-character sequences where newlines belong,
    making every one of them fail `json.load`. A sidecar that cannot be parsed
    is not metadata; it is a file."""
    if not SAMPLE_METADATA.is_dir():
        return  # the whole directory was retired; nothing to assert
    broken: list[tuple[str, str]] = []
    for path in sorted(SAMPLE_METADATA.glob("*.json")):
        try:
            with path.open("rb") as handle:
                json.load(handle)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            broken.append((path.name, str(exc)))
    assert broken == [], (
        f"{len(broken)} file(s) under samples/binaries/metadata/ do not parse "
        "as JSON. Nothing reads them, so they have looked like corpus "
        "documentation while being unloadable. Fix the content or delete the "
        "file -- an unparseable sidecar must not stay committed:\n"
        + "\n".join(
            f"  samples/binaries/metadata/{name}: {msg}" for name, msg in broken
        )
    )


# --- f) the fixture corpus has no undocumented numbering holes --------------
#
# `tools/fixture_harness.py` globs `*.c`, `*.cpp` and `*.rs` (and nothing
# else), so those are the extensions that actually reach a lane and a
# baseline verdict. A numbered fixture in any other language is written,
# committed, reported on by nobody, and shows up only as a hole in the
# numbering of every report.
HARNESS_SOURCE_SUFFIXES = (".c", ".cpp", ".rs")

# The numbering holes that are known, understood, and accepted. Every entry
# is a promise that someone looked; an unexplained hole is a fixture that
# silently is not measured.
#
# Do not add a number here to make a failure go away -- add the fixture, or
# write down why the number is dead.
ALLOWED_FIXTURE_NUMBER_GAPS: dict[int, str] = {
    # 176-180: the five Go fixtures (itab dispatch, slices/strings,
    # defer/panic/recover, struct methods, overflow/bits). The .go sources ARE
    # committed and readable in tests/decompiler_fixtures/src/, but
    # tools/fixture_harness.py globs only .c/.cpp/.rs and carries no Go
    # toolchain, so they build nothing and hold no verdict in any of the six
    # baselines. They come off this list -- and stop being a gap -- when
    # Phase 7 wires Go. See docs/development/decompiler-curriculum-corpus.md.
    176: "Go fixture 176_go_itab_dispatch.go written, harness has no Go lane",
    177: "Go fixture 177_go_slices_strings.go written, harness has no Go lane",
    178: "Go fixture 178_go_defer_panic_recover.go written, harness has no Go lane",
    179: "Go fixture 179_go_struct_methods.go written, harness has no Go lane",
    180: "Go fixture 180_go_overflow_bits.go written, harness has no Go lane",
    # 200: no source file of any extension has ever carried this number. The
    # numbering simply jumps 199 -> 201, undocumented, discovered by the test
    # estate inventory. Recorded here so the hole is accounted for rather
    # than mistaken for a fixture that went missing; the next fixture to need
    # a number may take 200 and delete this entry.
    200: "never existed: the corpus numbering jumps 199 -> 201",
}


def wired_fixture_numbers() -> set[int]:
    """Every fixture number with a source the harness will actually compile."""
    numbers: set[int] = set()
    for path in FIXTURE_SRC.iterdir():
        if path.suffix not in HARNESS_SOURCE_SUFFIXES:
            continue
        match = re.match(r"^(\d+)_", path.name)
        if match:
            numbers.add(int(match.group(1)))
    return numbers


def test_the_fixture_corpus_is_discoverable():
    assert FIXTURE_SRC.is_dir(), f"{FIXTURE_SRC} is missing"
    assert len(wired_fixture_numbers()) > 100, (
        "fewer than 100 numbered fixture sources found; the corpus is ~218 "
        "entries, so this discovery is broken rather than the corpus"
    )


def test_fixture_numbering_gaps_match_the_documented_allowlist():
    numbers = wired_fixture_numbers()
    gaps = set(range(min(numbers), max(numbers) + 1)) - numbers

    undocumented = sorted(gaps - set(ALLOWED_FIXTURE_NUMBER_GAPS))
    assert undocumented == [], (
        "undocumented hole(s) in the tests/decompiler_fixtures/src/ "
        "numbering. Every report over the corpus will skip these numbers with "
        "no explanation, which is what a fixture that is committed but wired "
        "to no lane looks like. Either wire the fixture (source in an "
        "extension tools/fixture_harness.py globs: "
        f"{', '.join(HARNESS_SOURCE_SUFFIXES)}) or add the number to "
        "ALLOWED_FIXTURE_NUMBER_GAPS with a sentence saying why it is dead:\n"
        + "\n".join(f"  fixture {n:03d} is missing" for n in undocumented)
    )

    filled = sorted(set(ALLOWED_FIXTURE_NUMBER_GAPS) - gaps)
    assert filled == [], (
        "ALLOWED_FIXTURE_NUMBER_GAPS documents number(s) that are no longer "
        "gaps -- the fixture now exists and is wired. Delete the entry so the "
        "allowlist keeps meaning exactly 'the holes that are accounted for':\n"
        + "\n".join(f"  {n:03d}: {ALLOWED_FIXTURE_NUMBER_GAPS[n]}" for n in filled)
    )


def test_every_allowlisted_gap_carries_a_reason():
    """A bare number in the allowlist is a hole with the explanation removed."""
    for number, reason in sorted(ALLOWED_FIXTURE_NUMBER_GAPS.items()):
        assert len(reason.split()) >= 4, (
            f"ALLOWED_FIXTURE_NUMBER_GAPS[{number}] = {reason!r} is not an "
            "explanation; say why the number is dead and what would fill it"
        )
