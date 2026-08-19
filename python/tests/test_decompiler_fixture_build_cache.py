"""`tests/decompiler_fixtures/build/` is a CACHE, and its key must cover the bytes.

THE DEFECT. The directory is keyed by `{fixture}-{cc}-{opt}.so` and nothing else.
When `-ffile-prefix-map=$ROOT=.` / `--remap-path-prefix` was added, every object
already on disk kept its old bytes — including the absolute checkout path the
flag exists to erase — and every consumer that READS an object without compiling
it went on measuring the old ones. Measured on the main checkout, 2026-08-19:

    find tests/decompiler_fixtures/build -name '*.so' -printf '%TY-%Tm-%Td\\n' | sort | uniq -c
        479 2026-08-18      283 2026-08-18      17 2026-08-12   <- pre-remap
    strings -a 132_cpp_vtable_layout-rustc-O0.so | grep -c "$PWD"   ->  4

It cost two wrong findings in one day: two def-use censuses of the same commit
disagreeing, and four `144_inline_asm` cross-architecture cells credited to a
commit that does not produce them on a cold cache.

WHAT THESE TESTS DO. The whole defect is "a stale artefact is silently reused",
so every test here CONSTRUCTS a stale artefact — a flag that changed, a compiler
that changed, a source that changed, an object someone overwrote, a sidecar from
an older schema — and asserts it is rebuilt rather than trusted. Most run
without touching a compiler at all; the five that do compile use one small C
fixture and one Rust fixture, which is a couple of seconds under the pinned
toolchain.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import fixture_harness as H  # ty: ignore[unresolved-import]  # added to sys.path above
import fixture_toolchain as TC  # ty: ignore[unresolved-import]

#: A small, fast C fixture. Any lane would do; this one compiles in milliseconds.
C_FIXTURE = "13_loop_early_exit"
#: The Rust lanes are the ones the `__toolchain__` fingerprint does not pin at
#: all (it probes gcc/g++/clang/clang++/ld/libc and no rustc), so they are the
#: ones a per-object fingerprint has to carry on its own.
RUST_FIXTURE = "166_rust_generics"


def _c_src() -> Path:
    return H.SRC / f"{C_FIXTURE}.c"


def _rust_src() -> Path:
    return H.SRC / f"{RUST_FIXTURE}.rs"


def _stamp(path: Path) -> tuple[int, int]:
    st = path.stat()
    return st.st_mtime_ns, st.st_size


# ---------------------------------------------------------------------------
# the key itself — pure, no compiler
# ---------------------------------------------------------------------------


def test_the_key_covers_the_flags_that_were_added_to_erase_the_build_path():
    """The exact change that produced the defect must change the key.

    `path_remap_flags` is what was added; an object built before it and an
    object built after it differ in `.rodata` (see that function), so a key that
    does not move when the flag moves is a key that hands back the wrong bytes.
    """
    compiler, out, argv = H.compile_plan(_c_src(), "gcc", "O0")
    with_flag = H.object_fingerprint(_c_src(), compiler, argv)
    without = H.object_fingerprint(
        _c_src(), compiler, [a for a in argv if not a.startswith("-ffile-prefix-map")]
    )
    assert with_flag != without
    assert with_flag["argv"] != without["argv"]

    _rc, _rout, rargv = H.compile_plan(_rust_src(), "rustc", "O0")
    assert any(a.startswith("--remap-path-prefix=") for a in rargv), rargv


def test_the_key_records_the_compiler_version_the_target_and_the_toolchain():
    """Everything the brief names, present and non-empty, for both front ends."""
    for src, cc in ((_c_src(), "gcc"), (_rust_src(), "rustc")):
        compiler, _out, argv = H.compile_plan(src, cc, "O0")
        fp = H.object_fingerprint(src, compiler, argv)
        assert fp["compiler_version"], fp
        assert fp["target"], fp
        assert fp["toolchain_mode"] in ("docker", "host"), fp
        assert fp["toolchain_image"], fp
        assert fp["source_sha256"], fp
        assert fp["schema"] == H.CACHE_SCHEMA


def test_the_rust_lane_key_pins_rustc_which_the_baseline_toolchain_does_not():
    """The blind spot one level up, closed at the object level.

    `fixture_toolchain._VERSION_PROBES` records gcc, g++, clang, clang++, ld and
    libc — no rustc — so `__toolchain__` in baseline.json and
    defuse_baseline.json pins every compiler EXCEPT the one that builds ~95% of
    the def-use census. Adding rustc there is a one-line change that invalidates
    all four committed baselines, so it is a baseline-refresh operation rather
    than a code change. The per-object key can pin it today, and does.
    """
    assert "rustc" not in dict(TC._VERSION_PROBES), (
        "rustc is in the toolchain fingerprint now — delete this test and the "
        "carve-out it documents"
    )
    compiler, _out, argv = H.compile_plan(_rust_src(), "rustc", "O0")
    fp = H.object_fingerprint(_rust_src(), compiler, argv)
    assert fp["compiler_version"].startswith("rustc "), fp["compiler_version"]


def test_the_key_is_stable_across_checkouts_at_different_paths():
    """A worktree must not rebuild the whole corpus.

    The remap flags make the produced object byte-identical across checkouts at
    different paths — proven by construction in `path_remap_flags` — so keying on
    the literal absolute path would force ~768 needless rebuilds in every agent
    worktree while proving nothing.
    """
    _c, _o, argv = H.compile_plan(_c_src(), "gcc", "O0")
    assert str(H.ROOT) not in " ".join(H._normalized_argv(argv))
    assert "$ROOT" in " ".join(H._normalized_argv(argv))


def test_the_strict_lane_and_the_execution_lane_do_not_share_a_key():
    """They share an OUTPUT PATH: `-Wall -Wextra -Werror` and `-w` both write
    `{fixture}-{cc}-{opt}.so`. That is the same hole in miniature, and the key
    has to see the difference even though these particular flags do not move the
    codegen."""
    _c, _o, lenient = H.compile_plan(_c_src(), "gcc", "O0", strict=False)
    _c2, _o2, strict = H.compile_plan(_c_src(), "gcc", "O0", strict=True)
    assert lenient != strict
    assert H._normalized_argv(lenient) != H._normalized_argv(strict)


def test_a_missing_sidecar_reads_as_stale():
    """The state every object in an existing checkout is in on the day this
    lands: bytes present, provenance unknown. Unknown must mean rebuild."""
    fake = H.BUILD / "definitely-not-a-real-lane.so"
    assert H.stale_reason(fake, {"schema": H.CACHE_SCHEMA}) == "not built"


def test_a_sidecar_from_an_older_schema_reads_as_stale(tmp_path):
    """An old sidecar cannot record a field it never knew about, so comparing
    only the fields it does have would re-open the hole. The schema number is
    the whole check."""
    obj = tmp_path / "x.so"
    obj.write_bytes(b"\x7fELF-not-really")
    H.write_sidecar(obj, {"schema": H.CACHE_SCHEMA - 1, "compiler": "gcc"})
    reason = H.stale_reason(obj, {"schema": H.CACHE_SCHEMA, "compiler": "gcc"})
    assert reason is not None and "schema" in reason, reason


def test_an_object_replaced_under_its_own_sidecar_reads_as_stale(tmp_path):
    obj = tmp_path / "x.so"
    obj.write_bytes(b"original")
    H.write_sidecar(obj, {"schema": H.CACHE_SCHEMA})
    assert H.stale_reason(obj, {"schema": H.CACHE_SCHEMA}) is None
    obj.write_bytes(b"original, plus a byte someone appended")
    reason = H.stale_reason(obj, {"schema": H.CACHE_SCHEMA})
    assert reason is not None and "hash" in reason, reason


def test_an_unreadable_sidecar_reads_as_stale(tmp_path):
    obj = tmp_path / "x.so"
    obj.write_bytes(b"bytes")
    H.sidecar_for(obj).write_text("{ this is not json")
    assert H.stale_reason(obj, {"schema": H.CACHE_SCHEMA}) is not None


def test_the_stale_reason_names_the_field_that_moved(tmp_path):
    """A rebuild nobody can explain is a rebuild people work around. The reason
    is the deliverable, not the boolean."""
    obj = tmp_path / "x.so"
    obj.write_bytes(b"bytes")
    H.write_sidecar(obj, {"schema": H.CACHE_SCHEMA, "compiler_version": "gcc 11.4.0"})
    reason = H.stale_reason(
        obj, {"schema": H.CACHE_SCHEMA, "compiler_version": "gcc 15.2.0"}
    )
    assert reason is not None
    assert "compiler_version" in reason and "15.2.0" in reason, reason


# ---------------------------------------------------------------------------
# the reuse decision — these compile
# ---------------------------------------------------------------------------


def test_a_stale_object_is_rebuilt_and_a_matching_one_is_not():
    """The defect, constructed and then watched not to happen.

    Step 2 is the assertion that matters: the object on disk is byte-for-byte
    what the current flags produce, and no compiler runs. Step 3 tampers with
    exactly one recorded field — the remap flag, the real one — and the object
    must come back rebuilt.
    """
    src = _c_src()
    so, err = H.ensure_fixture(src, "gcc", "O0")
    assert so is not None, err
    fresh = _stamp(so)

    # 2. a matching object is reused, not recompiled
    again, err = H.ensure_fixture(src, "gcc", "O0")
    assert again is not None, err
    assert _stamp(again) == fresh, "a provably-current object was needlessly rebuilt"

    # 3. make it stale the way the real defect did: the recorded flag list loses
    #    the path-remap flag, exactly as an object built before that flag has.
    side = H.sidecar_for(so)
    recorded = json.loads(side.read_text())
    recorded["argv"] = [
        a for a in recorded["argv"] if not a.startswith("-ffile-prefix-map")
    ]
    side.write_text(json.dumps(recorded, indent=2, sort_keys=True) + "\n")
    compiler, _out, argv = H.compile_plan(src, "gcc", "O0")
    assert H.stale_reason(so, H.object_fingerprint(src, compiler, argv)), (
        "a pre-remap object still looks current"
    )
    # The check every consumer used to make, still passing on the stale object.
    # That is the whole defect in one line: `exists()` cannot tell these apart.
    assert so.exists()

    rebuilt, err = H.ensure_fixture(src, "gcc", "O0")
    assert rebuilt is not None, err
    assert _stamp(rebuilt) != fresh, "the stale object was silently reused"
    assert json.loads(H.sidecar_for(rebuilt).read_text())["argv"] == H._normalized_argv(
        H.compile_plan(src, "gcc", "O0")[2]
    )


def test_a_host_built_object_is_not_reused_under_the_pinned_toolchain(monkeypatch):
    """The realistic version of the defect, end to end, with two real compilers.

    `GLAURUNG_FIXTURE_TOOLCHAIN=host` and the default `docker` mode write the
    SAME path. On this host that is gcc 15.2 versus the image's gcc 11.4 — a
    different program producing a different binary — and until the fingerprint
    existed, one `host` run left objects that every later pinned reader consumed
    as pinned. The toolchain guard cannot catch it either: `__toolchain__` is
    recorded per BASELINE, not per object, so it says what the run declared, not
    what the bytes on disk were built by.
    """
    src = _c_src()
    pinned, err = H.ensure_fixture(src, "gcc", "O0")
    assert pinned is not None, err
    pinned_version = json.loads(H.sidecar_for(pinned).read_text())["compiler_version"]

    try:
        monkeypatch.setenv("GLAURUNG_FIXTURE_TOOLCHAIN", "host")
        TC.image_id.cache_clear()
        H.compiler_identity.cache_clear()
        host, err = H.compile_fixture(src, "gcc", "O0")
        assert host is not None, err
        host_version = json.loads(H.sidecar_for(host).read_text())["compiler_version"]
        if host_version == pinned_version:
            pytest.skip(
                f"this host's gcc IS the pinned one ({host_version}); the two "
                f"modes are indistinguishable here by construction"
            )

        monkeypatch.delenv("GLAURUNG_FIXTURE_TOOLCHAIN")
        TC.image_id.cache_clear()
        H.compiler_identity.cache_clear()
        compiler, out, argv = H.compile_plan(src, "gcc", "O0")
        reason = H.stale_reason(out, H.object_fingerprint(src, compiler, argv))
        assert reason is not None, (
            f"an object built by the HOST {host_version} looks current to the "
            f"pinned {pinned_version} gate"
        )
        assert "compiler_version" in reason or "toolchain_mode" in reason, reason
    finally:
        monkeypatch.delenv("GLAURUNG_FIXTURE_TOOLCHAIN", raising=False)
        TC.image_id.cache_clear()
        H.compiler_identity.cache_clear()
        restored, err = H.ensure_fixture(src, "gcc", "O0")
        assert restored is not None, err
    assert (
        json.loads(H.sidecar_for(restored).read_text())["compiler_version"]
        == pinned_version
    )


def test_deleting_the_sidecar_forces_a_rebuild():
    """Every object in every existing checkout is in this state today."""
    src = _c_src()
    so, err = H.ensure_fixture(src, "gcc", "O0")
    assert so is not None, err
    before = _stamp(so)
    H.sidecar_for(so).unlink()
    after, err = H.ensure_fixture(src, "gcc", "O0")
    assert after is not None, err
    assert _stamp(after) != before
    assert H.sidecar_for(after).is_file()


def test_a_rust_object_built_by_a_different_rustc_is_rebuilt():
    """The lane the `__toolchain__` fingerprint does not cover at all.

    A Rust cdylib embeds its panic-location strings and its std monomorphisations,
    so a different rustc is a different binary and a different census. With no
    rustc in `__toolchain__`, the per-object key is the ONLY thing that notices.
    """
    src = _rust_src()
    so, err = H.ensure_fixture(src, "rustc", "O0")
    assert so is not None, err
    before = _stamp(so)

    side = H.sidecar_for(so)
    recorded = json.loads(side.read_text())
    assert recorded["compiler_version"].startswith("rustc ")
    recorded["compiler_version"] = "rustc 1.0.0 (from a parallel universe)"
    side.write_text(json.dumps(recorded, indent=2, sort_keys=True) + "\n")

    after, err = H.ensure_fixture(src, "rustc", "O0")
    assert after is not None, err
    assert _stamp(after) != before, "a Rust object from another rustc was reused"


def test_a_failed_rebuild_does_not_leave_the_old_object_looking_fresh(tmp_path):
    """The compiler drivers write `-o` only on success, so a failed rebuild
    leaves the PREVIOUS object at that path. If its sidecar survived, the next
    reader would be handed a binary built from source that no longer compiles."""
    src = _c_src()
    so, err = H.ensure_fixture(src, "gcc", "O0")
    assert so is not None, err
    assert H.sidecar_for(so).is_file()

    # A source with the SAME STEM that does not compile. `compile_plan` derives
    # the output path from the stem, so this targets the real lane's object.
    broken = tmp_path / f"{C_FIXTURE}.c"
    broken.write_text("this is not C;\n")
    plan_out = H.compile_plan(src, "gcc", "O0")[1]
    assert H.compile_plan(broken, "gcc", "O0")[1] == plan_out

    failed, msg = H.compile_fixture(broken, "gcc", "O0")
    assert failed is None, "a syntactically invalid source compiled"
    assert msg
    assert not H.sidecar_for(plan_out).is_file(), (
        "a failed rebuild left the previous object's fingerprint in place"
    )
    # put it back so the rest of the suite (and the gate) sees a current object
    restored, err = H.ensure_fixture(src, "gcc", "O0")
    assert restored is not None, err


# ---------------------------------------------------------------------------
# orphans — the objects nothing will ever overwrite
# ---------------------------------------------------------------------------


def test_an_orphan_object_is_reported_and_prunable():
    """`132_cpp_vtable_layout-rustc-O0.so` is the worked example: a C++ fixture
    recorded under a Rust lane by the old cross-product in `lanes_for`, left
    behind when that was fixed, and still carrying pre-remap bytes six days
    later. No lane produces that name, so nothing will ever rebuild it — only a
    scan over the directory can find it."""
    H.BUILD.mkdir(parents=True, exist_ok=True)
    orphan = H.BUILD / "132_cpp_vtable_layout-rustc-O0.so"
    created = not orphan.exists()
    if created:
        orphan.write_bytes(b"\x7fELF stale bytes from a lane that no longer exists")
    try:
        assert orphan.name not in H.expected_objects()
        problems = H.cache_problems()
        assert any(p.startswith(orphan.name) and "orphan" in p for p in problems), (
            problems[:5]
        )
    finally:
        if created:
            orphan.unlink(missing_ok=True)
            H.sidecar_for(orphan).unlink(missing_ok=True)


def test_a_strict_lane_object_is_not_reported_stale():
    """The strict compile gate (`-Wall -Wextra -Werror`) and the execution matrix
    (`-w`) write to the same path, and an ordinary `pytest python/tests/` run
    leaves the strict one there. Both are current products of the current source
    and toolchain; reporting 768 problems the suite just legitimately created
    would train people to ignore the report."""
    src = _c_src()
    so, err = H.compile_fixture(src, "gcc", "O0", strict=True)
    assert so is not None, err
    try:
        assert [p for p in H.cache_problems() if p.startswith(so.name)] == []
    finally:
        restored, err = H.ensure_fixture(src, "gcc", "O0")
        assert restored is not None, err


def test_every_declared_lane_has_a_predictable_object_name():
    """`expected_objects` is what tells an orphan from a current object, so it
    has to agree with the names `compile_plan` actually writes."""
    expected = H.expected_objects()
    assert len(expected) >= 700, len(expected)
    for name, (src, cc, opt) in expected.items():
        assert H.compile_plan(src, cc, opt)[1].name == name


@pytest.mark.slow
def test_the_built_corpus_has_no_stale_or_orphan_objects():
    """The gate for the directory as a whole.

    `slow` because it fingerprints every object present. It reports nothing on a
    checkout that has never built the corpus — a fresh checkout has no cache to
    be wrong about — which is why the constructed-staleness tests above carry
    the actual proof.
    """
    problems = H.cache_problems()
    assert not problems, (
        f"{len(problems)} object(s) in {H.BUILD} cannot be trusted; "
        f"`python tools/fixture_harness.py --prune-cache` removes them:\n  "
        + "\n  ".join(problems[:20])
    )
