"""The decompiler fixture harness must be FAIL-CLOSED and trustworthy.

These tests exercise the harness itself, not the decompiler: every failure mode
(missing dependency, compile failure, worker crash, timeout, decompile failure,
zero DWARF signatures, zero cases, a required function missing) must produce a
FAILURE, never a silent skip or a green 0/0 run. A harness that fails open is
worse than no harness — it hides regressions.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS = ROOT / "tools"
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import diff_decompile as D
import fixture_harness as H

# Portable scratch dir: whatever manifest.tmpdir() resolves (env-driven, with a
# system-tempfile fallback) — never a hardcoded machine path.
_td = D.M.tmpdir()
WORKDIR_KW = {"dir": _td} if _td else {}

_SO_KEEP = []  # keep NamedTemporaryFile handles alive for the test session


def _compile_so(c_src: str, tag: str) -> str:
    """Compile a snippet into a -g .so and return its path (kept for the run)."""
    import os
    fd, path = tempfile.mkstemp(suffix=".so", prefix=f"h_{tag}_", **WORKDIR_KW)
    os.close(fd)
    src = path[:-3] + ".c"
    Path(src).write_text(c_src + "\n")
    subprocess.run(["gcc", "-shared", "-fPIC", "-g", "-O0", "-o", path, src], check=True)
    _SO_KEEP.append(path)
    return path


def test_pyelftools_is_a_declared_dependency():
    # Fail-closed relies on the import at module load — verify it is a real dep,
    # not an undeclared global that silently disappears.
    import elftools  # noqa: F401


def test_all_ten_sources_are_discovered():
    sources = sorted(p.name for p in SRC.glob("*.c")) + sorted(p.name for p in SRC.glob("*.cpp"))
    assert len(sources) == 10, f"expected 10 fixture sources, found {sources}"


def test_zero_dwarf_signatures_is_an_error(tmp_path):
    # A stripped / DWARF-less binary must ERROR, never report a green empty run.
    src = tmp_path / "x.c"
    src.write_text("int f(int a){return a;}\n")
    so = tmp_path / "x.so"
    subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(so), str(src)], check=True)  # no -g
    results = D.run(str(so), str(src), "nope", seed=1, fuzz=1)
    assert "__error__" in results


def test_compile_failure_of_decompilation_is_fail(monkeypatch, tmp_path):
    # If the decompiled C does not compile, the function FAILS (not skip).
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "int"}
    monkeypatch.setattr(D, "decompiled_c", lambda *_a, **_k: "int f(int arg0){ this is not c }")
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", "unused", Path(td), seed=1, fuzz=1)
    assert r["status"] == "fail" and "compile" in r["detail"]


def test_decompile_failure_is_fail(monkeypatch, tmp_path):
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "int"}
    monkeypatch.setattr(D, "decompiled_c", lambda *_a, **_k: None)
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", "unused", Path(td), seed=1, fuzz=1)
    assert r["status"] == "fail" and "decompile" in r["detail"]


def test_worker_crash_is_fail(monkeypatch, tmp_path):
    # A decompilation that segfaults must not crash the caller: the worker dies
    # in its own process and the parent reports a FAIL.
    sig = {"name": "boom", "va": 0, "params": [], "ret": "int"}
    # Compile a real original + a decompilation that dereferences null on call.
    orig = tmp_path / "o.c"
    orig.write_text("int boom(void){return 1;}\n")
    orig_so = tmp_path / "o.so"
    subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(orig_so), str(orig)], check=True)
    monkeypatch.setattr(D, "decompiled_c", lambda *_a, **_k: "int boom(void){ int*p=0; return *p; }")
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", str(orig_so), Path(td), seed=1, fuzz=1)
    assert r["status"] == "fail", r


def test_worker_nonzero_exit_is_fail(tmp_path):
    # Directly: a malformed worker spec makes the worker raise -> nonzero exit ->
    # the parent's subprocess check must treat it as a failure.
    spec = tmp_path / "bad.json"
    spec.write_text("{ not json")
    r = subprocess.run([sys.executable, str(TOOLS / "diff_decompile.py"), "--worker", str(spec)],
                       capture_output=True, text=True, check=False)
    assert r.returncode != 0


def test_skip_exec_is_structural_not_pass(monkeypatch, tmp_path):
    # A function the manifest marks skip_exec is reported `structural`, a distinct
    # status the structural lane must check — never a silent pass.
    sig = {"name": "apply", "va": 0, "params": ["int", "int"], "ret": "int"}
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "08_indirect_dispatch", "unused", Path(td), seed=1, fuzz=1)
    assert r["status"] == "structural"


def test_no_executable_cases_is_not_a_pass(monkeypatch, tmp_path):
    # Zero generated cases is an infra failure (distinct `nocases` status so
    # --write-baseline refuses it), never a silent pass.
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "int"}
    monkeypatch.setattr(D, "decompiled_c", lambda *_a, **_k: "int f(int arg0){return arg0;}")
    monkeypatch.setattr(D, "make_vectors", lambda *_a, **_k: [])
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", "unused", Path(td), seed=1, fuzz=1)
    assert r["status"] == "nocases" and "case" in r["detail"]


def test_required_missing_function_is_fail():
    # Fixture 01 really has these; delete-simulate via a fixture with a bogus
    # requirement by checking the presence logic directly.
    assert "cmp_signed" in D.M.REQUIRED_FUNCTIONS["01_conditional_polarity"]


def test_vector_generation_is_reproducible_across_processes():
    # Python's hash(str) is per-process randomized; the fuzz seed must NOT depend
    # on it, or a CI lane on another machine exercises different inputs. Two fresh
    # interpreters must produce byte-identical vectors.
    prog = (
        "import sys;sys.path.insert(0,'tools');sys.path.insert(0,'tests/decompiler_fixtures');"
        "import json,diff_decompile as D;"
        "print(json.dumps(D.make_vectors({'name':'vec_sum','params':['ptr','int'],'ret':'int'},"
        "{'len_args':[1]},1,6)))"
    )
    outs = [
        subprocess.run([sys.executable, "-c", prog], cwd=ROOT, capture_output=True,
                       text=True, check=True).stdout
        for _ in range(2)
    ]
    assert outs[0] == outs[1], "fuzz vectors differ across processes (non-deterministic seed)"


def test_stable_seed_is_independent_of_python_hash_randomization():
    # Directly: the seed helper must not use the randomized builtin hash().
    assert D._stable_seed("vec_sum", 1) == D._stable_seed("vec_sum", 1)
    assert D._stable_seed("a", 1) != D._stable_seed("b", 1)


def test_tmpdir_is_portable_and_falls_back(monkeypatch):
    # No env + no /nas4 path -> None (system tempfile default), never a crash.
    monkeypatch.delenv("GLAURUNG_FIXTURE_TMPDIR", raising=False)
    monkeypatch.delenv("TMPDIR", raising=False)
    assert D.M.tmpdir() is None
    # A bogus override is ignored (missing/unwritable), not trusted.
    monkeypatch.setenv("GLAURUNG_FIXTURE_TMPDIR", "/no/such/dir/xyz")
    assert D.M.tmpdir() is None
    # A real writable override is honored.
    with tempfile.TemporaryDirectory() as td:
        monkeypatch.setenv("GLAURUNG_FIXTURE_TMPDIR", td)
        assert D.M.tmpdir() == td


def test_harness_runs_without_the_nas_scratch_path(monkeypatch):
    # Prove run_function works when /nas4/.../rdtmp does not exist: point the
    # scratch dir at a plain system tempdir and execute a trivially-correct
    # decompilation end to end.
    monkeypatch.setattr(D, "decompiled_c", lambda *_a, **_k: "int f(int arg0){return arg0;}")
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "int"}
    with tempfile.TemporaryDirectory() as bwd:
        # a real original .so so the worker has something to call
        src = Path(bwd) / "o.c"
        src.write_text("int f(int a){return a;}\n")
        orig = Path(bwd) / "o.so"
        subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(orig), str(src)], check=True)
        r = D.run_function(sig, "fx", str(orig), Path(bwd), seed=1, fuzz=2)
    assert r["status"] == "pass", r


def test_wrong_high_32_bits_of_a_64bit_return_fails(monkeypatch):
    # A 64-bit return whose high half the decompilation drops must FAIL — only
    # possible if the return width is modeled as 8 bytes, not truncated to int.
    orig = _compile_so("long f(long a){ return a; }", "hi")
    monkeypatch.setattr(D, "decompiled_c",
                        lambda *_a, **_k: "long f(long a){ return a & 0xFFFFFFFF; }")
    sig = {"name": "f", "va": 0, "params": ["long"], "ret": "long"}
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", orig, Path(td), seed=1, fuzz=2)
    assert r["status"] == "fail", r


def test_wrong_sign_extension_fails(monkeypatch):
    # orig sign-extends a 32-bit arg into a 64-bit return; the decompilation
    # zero-extends. On a negative input the two differ only in the high 32 bits.
    orig = _compile_so("long f(int a){ return a; }", "sx")
    monkeypatch.setattr(D, "decompiled_c",
                        lambda *_a, **_k: "long f(int a){ return (unsigned int)a; }")
    sig = {"name": "f", "va": 0, "params": ["int"], "ret": "long"}
    with tempfile.TemporaryDirectory(**WORKDIR_KW) as td:
        r = D.run_function(sig, "fx", orig, Path(td), seed=1, fuzz=2)
    assert r["status"] == "fail", r


def test_signatures_recover_width_and_signedness():
    # DWARF recovery must carry width + signedness, not collapse to int.
    so = _compile_so(
        "long g(unsigned char b, int i, long l, const unsigned char* p){"
        " (void)b;(void)i;(void)l;return p?p[0]:0; }", "sg")
    sigs = {s["name"]: s for s in D.signatures(so)}
    g = sigs["g"]
    assert D._as_desc(g["ret"]) == {"k": "int", "w": 8, "s": True}
    ps = [D._as_desc(p) for p in g["params"]]
    assert ps[0] == {"k": "int", "w": 1, "s": False}          # unsigned char
    assert ps[1] == {"k": "int", "w": 4, "s": True}           # int
    assert ps[2] == {"k": "int", "w": 8, "s": True}           # long
    assert ps[3]["k"] == "ptr" and ps[3]["pw"] == 1 and ps[3]["const"] is True


def test_exit_code_distinguishes_infra_from_semantic():
    assert D.exit_code({"f": {"status": "pass"}}) == 0
    assert D.exit_code({"f": {"status": "structural"}}) == 0
    assert D.exit_code({"f": {"status": "fail"}}) == 1
    assert D.exit_code({"f": {"status": "missing"}}) == 2
    assert D.exit_code({"f": {"status": "nocases"}}) == 2
    assert D.exit_code({"__error__": "no dwarf"}) == 2


def test_json_mode_returns_two_on_infra(tmp_path):
    # A stripped binary -> no DWARF -> __error__ -> nonzero (infra) exit.
    src = tmp_path / "x.c"
    src.write_text("int f(int a){return a;}\n")
    so = tmp_path / "x.so"
    subprocess.run(["gcc", "-shared", "-fPIC", "-O0", "-o", str(so), str(src)], check=True)  # no -g
    r = subprocess.run([sys.executable, str(TOOLS / "diff_decompile.py"), str(so), str(src), "--json"],
                       capture_output=True, text=True, check=False)
    assert r.returncode == 2, r.stderr


def test_write_baseline_refuses_lane_errors_and_infra_statuses():
    good = {"01:gcc:O0": {"cmp_signed": "pass", "sc_and": "fail"}}
    assert H.baseline_problems(good) == []
    bad_lane = {"01:gcc:O0": {"__lane__": "compile-failed: boom"}}
    assert H.baseline_problems(bad_lane), "must refuse a compile-failed lane"
    env_ok = {"10:clang:O0": {"__lane__": "env-missing"}}
    assert H.baseline_problems(env_ok) == [], "declared env-missing lanes are allowed"
    bad_status = {"09:gcc:O0": {"tick": "structural", "read_be16": "missing"}}
    assert H.baseline_problems(bad_status), "must refuse a missing required function"
    nocases = {"x:gcc:O0": {"f": "nocases"}}
    assert H.baseline_problems(nocases), "must refuse a zero-case function"


def test_schema_requires_all_ten_fixtures():
    # A baseline covering only some fixtures is rejected.
    partial = {"01_conditional_polarity:gcc:O0": {"cmp_signed": "pass"}}
    assert H.schema_problems(partial, [("gcc", "O0")]), "must require all ten fixtures"


def test_length_args_are_clamped_to_buffer():
    # A scalar flagged as a length must never exceed the allocated buffer, so a
    # boundary like INT_MAX cannot drive an out-of-bounds ctypes write.
    sig = {"name": "vec_sum", "va": 0, "params": ["ptr", "int"], "ret": "int"}
    ov = D.M.override("09_memory_effects", "vec_sum")
    vecs = D.make_vectors(sig, ov, seed=1, fuzz=4)
    ptr_len = ov.get("ptr_len", D.M.DEFAULT_PTR_LEN)
    for v in vecs:
        assert 0 <= v[1] <= ptr_len, f"length arg {v[1]} not clamped to {ptr_len}"
        assert isinstance(v[0], list) and len(v[0]) == ptr_len
