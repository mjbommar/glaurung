#!/usr/bin/env python3
"""Compile the fixture corpus across a toolchain matrix and run the fail-closed
execution-differential gate, producing a per-function result map.

Required PR matrix (x86-64): {gcc, clang} x {O0, O2}. A compiler that is missing,
or a required-lane source that fails to compile, is a FAILURE — not a skip
(fail-closed). Environment-only gaps (e.g. a missing clang C++ runtime) must be
declared in ALLOWED_MISSING, which is itself asserted, so nothing is skipped
silently.

  python tools/fixture_harness.py                 # run required matrix, print
  python tools/fixture_harness.py --write-baseline # regenerate baseline.json
  python tools/fixture_harness.py --json           # machine-readable result map
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
DIFF = ROOT / "tools" / "diff_decompile.py"
BASELINE = ROOT / "tests" / "decompiler_fixtures" / "baseline.json"

sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
import manifest as M  # ty: ignore[unresolved-import]

REQUIRED_MATRIX = [("gcc", "O0"), ("gcc", "O2"), ("clang", "O0"), ("clang", "O2")]


def _cpp_compiler(cc: str) -> str:
    return "g++" if cc == "gcc" else "clang++"


def _cxx_runtime_ok(cc: str) -> bool:
    """Can this toolchain actually build+link a C++ program that throws? A
    machine may have clang but no libstdc++/libc++ for it. Probed, not assumed,
    so ALLOWED_MISSING reflects a REAL gap on this host (and disappears on a CI
    runner where the runtime IS provisioned)."""
    import tempfile
    with tempfile.TemporaryDirectory(dir=M.tmpdir()) as td:
        src = Path(td) / "p.cpp"
        src.write_text("int f(int x){ if(x<0) throw x; return x; }\n"
                       "extern \"C\" int probe(int x){ try{ return f(x); }catch(int e){ return e; } }\n")
        out = Path(td) / "p.so"
        r = subprocess.run([_cpp_compiler(cc), "-shared", "-fPIC", f"-{DEFAULT_OPT}",
                            "-o", str(out), str(src)], capture_output=True, text=True, check=False)
        return r.returncode == 0


DEFAULT_OPT = "O0"


def detect_allowed_missing() -> set[tuple[str, str, str]]:
    """Environment gaps to permit as declared (never silent) skips: a clang C++
    lane on a host whose clang cannot link C++. Each entry is a probed real gap."""
    missing: set[tuple[str, str, str]] = set()
    cpp_stems = [p.stem for p in SRC.glob("*.cpp")]
    if cpp_stems and not _cxx_runtime_ok("clang"):
        for stem in cpp_stems:
            for opt in ("O0", "O2"):
                missing.add(("clang", opt, stem))
    return missing


def compile_fixture(src: Path, cc: str, opt: str, strict: bool = False) -> tuple[Path | None, str]:
    is_cpp = src.suffix == ".cpp"
    compiler = _cpp_compiler(cc) if is_cpp else cc
    BUILD.mkdir(parents=True, exist_ok=True)
    out = BUILD / f"{src.stem}-{cc}-{opt}.so"
    # Fixtures are warning-clean C; the strict lane proves it (-Werror + explicit
    # fallthrough annotations). Execution builds stay lenient only re: -g/-fPIC.
    warn = ["-Wall", "-Wextra", "-Werror"] if strict else ["-w"]
    cmd = [compiler, "-shared", "-fPIC", "-g", f"-{opt}", *warn, "-o", str(out), str(src)]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if r.returncode != 0:
        return None, (r.stderr.strip().splitlines() or ["?"])[-1]
    return out, ""


def strict_compile_problems(matrix=None, allowed_missing=None) -> list[str]:
    """Every fixture must compile -Wall -Wextra -Werror in every required lane.
    A clang C++ lane on a host without the C++ runtime is a probed, declared gap
    (env-missing) — asserted real, never a silent skip. Returns a list of lanes
    that failed (empty == all good)."""
    if matrix is None:
        matrix = REQUIRED_MATRIX
    if allowed_missing is None:
        allowed_missing = detect_allowed_missing()
    problems = []
    srcs = sorted(list(SRC.glob("*.c")) + list(SRC.glob("*.cpp")))
    assert len(srcs) == 10, f"expected 10 fixtures, found {len(srcs)}"
    for src in srcs:
        for cc, opt in matrix:
            so, err = compile_fixture(src, cc, opt, strict=True)
            if (cc, opt, src.stem) in allowed_missing:
                # declared gap: must genuinely fail (env runtime absent)
                if so is not None:
                    problems.append(f"{src.stem}:{cc}:{opt}: declared env-missing but compiled")
                continue
            if so is None:
                problems.append(f"{src.stem}:{cc}:{opt}: {err}")
    return problems


def run_matrix(matrix, fuzz: int, allowed_missing=None) -> dict:
    """Return {f"{stem}:{cc}:{opt}": {func: status}} plus lane-level errors."""
    if allowed_missing is None:
        allowed_missing = detect_allowed_missing()
    result: dict = {}
    srcs = sorted(list(SRC.glob("*.c")) + list(SRC.glob("*.cpp")))
    for src in srcs:
        for cc, opt in matrix:
            key = f"{src.stem}:{cc}:{opt}"
            # A declared env gap must be a REAL gap: assert the compile truly
            # fails before recording it as env-missing (never a silent skip).
            if (cc, opt, src.stem) in allowed_missing:
                so, err = compile_fixture(src, cc, opt)
                assert so is None, f"declared env-missing lane {key} unexpectedly compiled"
                result[key] = {"__lane__": "env-missing"}
                continue
            so, err = compile_fixture(src, cc, opt)
            if so is None:
                result[key] = {"__lane__": f"compile-failed: {err}"}
                continue
            r = subprocess.run(
                [sys.executable, str(DIFF), str(so), str(src),
                 "--fixture", src.stem, "--fuzz", str(fuzz), "--json"],
                capture_output=True, text=True, timeout=900, check=False,
            )
            try:
                fns = json.loads(r.stdout)
            except json.JSONDecodeError:
                result[key] = {"__lane__": f"gate-crashed: {r.stderr.strip()[-160:]}"}
                continue
            if "__error__" in fns:
                result[key] = {"__lane__": fns["__error__"]}
                continue
            result[key] = {name: v["status"] for name, v in fns.items()}
    return result


STATUS_KINDS = ("pass", "fail", "structural", "missing", "nocases")


def summarize(result: dict) -> dict:
    c = {k: 0 for k in STATUS_KINDS}
    c["lane"] = c["env_missing"] = 0
    for fns in result.values():
        if "__lane__" in fns:
            c["env_missing" if fns["__lane__"] == "env-missing" else "lane"] += 1
            continue
        for st in fns.values():
            c[st] = c.get(st, 0) + 1
    return c


def baseline_problems(result: dict) -> list[str]:
    """Reasons a result must NOT be written as a baseline: a non-env lane error
    (compile/gate/infra) or any infra status (a missing required function or a
    zero-case function). Known decompiler fails/structurals are fine to record."""
    problems = []
    for key, fns in sorted(result.items()):
        if "__lane__" in fns:
            if fns["__lane__"] != "env-missing":
                problems.append(f"{key}: lane error ({fns['__lane__']})")
            continue
        for func, st in sorted(fns.items()):
            if st in ("missing", "nocases"):
                problems.append(f"{key}:{func}: {st}")
    return problems


def schema_problems(result: dict, matrix) -> list[str]:
    """All ten fixtures must be present across every matrix lane; every status a
    recognized kind. Guards against a truncated/renamed baseline."""
    problems = []
    stems = sorted(p.stem for p in list(SRC.glob("*.c")) + list(SRC.glob("*.cpp")))
    if len(stems) != 10:
        problems.append(f"expected 10 fixtures, found {len(stems)}")
    for stem in stems:
        for cc, opt in matrix:
            key = f"{stem}:{cc}:{opt}"
            if key not in result:
                problems.append(f"missing lane {key}")
                continue
            fns = result[key]
            if "__lane__" in fns:
                continue
            for func, st in fns.items():
                if st not in STATUS_KINDS:
                    problems.append(f"{key}:{func}: bad status {st!r}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fuzz", type=int, default=M.FIXTURE_FUZZ)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--gcc-o0-only", action="store_true", help="fast local subset")
    args = ap.parse_args()

    matrix = [("gcc", "O0")] if args.gcc_o0_only else REQUIRED_MATRIX
    result = run_matrix(matrix, args.fuzz)

    if args.write_baseline:
        problems = baseline_problems(result) + schema_problems(result, matrix)
        if problems:
            print("REFUSING to write baseline — infrastructure problems:", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            return 1
        BASELINE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"wrote {BASELINE}")
        return 0
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if not baseline_problems(result) else 2

    for key, fns in sorted(result.items()):
        if "__lane__" in fns:
            print(f"{key:44s}  LANE: {fns['__lane__']}")
            continue
        pf = sum(1 for st in fns.values() if st == "pass")
        ff = sum(1 for st in fns.values() if st == "fail")
        sf = sum(1 for st in fns.values() if st == "structural")
        flag = "" if ff == 0 else "  <-- FAILURES"
        print(f"{key:44s}  {pf:3d} pass {ff:3d} fail {sf:3d} struct{flag}")
    c = summarize(result)
    print(f"\n=== TOTAL: {c['pass']} pass, {c['fail']} fail, {c['structural']} structural, "
          f"{c['missing']} missing, {c['nocases']} no-cases; "
          f"{c['lane']} lane error(s), {c['env_missing']} env-missing ===")
    # Fail-closed: any real lane error or infra status fails the run (env-missing
    # is a declared, probed gap and does not).
    return 1 if (c["fail"] or c["lane"] or c["missing"] or c["nocases"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
