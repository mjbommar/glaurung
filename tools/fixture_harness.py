#!/usr/bin/env python3
"""Compile the fixture corpus across a toolchain matrix and run the fail-closed
execution-differential gate, producing a per-function result map.

Required PR matrix (x86-64): {gcc, clang} x {O0, O2}. A compiler that is missing,
or a required-lane source that fails to compile, is a FAILURE — not a skip
(fail-closed). Environment-only gaps (e.g. a missing clang C++ runtime) must be
declared in ALLOWED_MISSING, which is itself asserted, so nothing is skipped
silently.

Every compile runs under the fingerprinted toolchain (`tools/fixture_toolchain.py`)
and the resulting result map carries that toolchain's fingerprint, because a
per-function verdict recorded against one host's compiler releases cannot be
compared against another's.

  python tools/fixture_harness.py                 # run required matrix, print
  python tools/fixture_harness.py --write-baseline # regenerate baseline.json
  python tools/fixture_harness.py --json           # machine-readable result map
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "tests" / "decompiler_fixtures" / "src"
BUILD = ROOT / "tests" / "decompiler_fixtures" / "build"
DIFF = ROOT / "tools" / "diff_decompile.py"
BASELINE = ROOT / "tests" / "decompiler_fixtures" / "baseline.json"

sys.path.insert(0, str(ROOT / "tests" / "decompiler_fixtures"))
sys.path.insert(0, str(ROOT / "tools"))
import build_guard as BG  # ty: ignore[unresolved-import]
import fixture_toolchain as TC
import manifest as M  # ty: ignore[unresolved-import]

REQUIRED_MATRIX = [("gcc", "O0"), ("gcc", "O2"), ("clang", "O0"), ("clang", "O2")]
#: Rust has exactly one compiler, so its lanes are named `rustc` rather than
#: cross-producted with a C compiler that never builds it.
RUST_MATRIX = [("rustc", "O0"), ("rustc", "O2")]


def matrix_for(src) -> list[tuple[str, str]]:
    """The compiler/optimization lanes that apply to one fixture source."""
    return RUST_MATRIX if str(src).endswith(".rs") else REQUIRED_MATRIX


def rust_lanes_enabled() -> bool:
    """Whether Rust fixtures participate in the matrix.

    ON: the pinned toolchain image now provisions rustc (see
    `toolchain/Dockerfile`) and `_VERSION_PROBES` records its version, so a Rust
    verdict is attributable to a fingerprinted toolchain exactly as a gcc or
    clang verdict is. That is the guarantee this gate exists to make, and it is
    why the lanes were held back until rustc was in the image rather than run
    against whatever happened to be on the host.

    Set GLAURUNG_FIXTURE_RUST=0 to drop the Rust lanes — useful on a host whose
    image predates them, where every Rust lane would otherwise report
    `compile-failed: rustc: executable file not found`.
    """
    return os.environ.get("GLAURUNG_FIXTURE_RUST", "1") != "0"


def _fixture_sources() -> list:
    """Every fixture source the matrix should cover."""
    srcs = list(SRC.glob("*.c")) + list(SRC.glob("*.cpp"))
    if rust_lanes_enabled():
        srcs += list(SRC.glob("*.rs"))
    return sorted(srcs)


#: Reserved key in a result map / baseline holding the compile toolchain identity
#: (see fixture_toolchain.fingerprint). Not a lane — every consumer filters it.
TOOLCHAIN_KEY = "__toolchain__"


def lanes(mapping: dict) -> dict:
    """The `{fixture}:{cc}:{opt}` entries of a result map or baseline, without the
    reserved metadata keys."""
    return {k: v for k, v in mapping.items() if k != TOOLCHAIN_KEY}


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
        src.write_text(
            "int f(int x){ if(x<0) throw x; return x; }\n"
            'extern "C" int probe(int x){ try{ return f(x); }catch(int e){ return e; } }\n'
        )
        out = Path(td) / "p.so"
        r = TC.run(
            [
                _cpp_compiler(cc),
                "-shared",
                "-fPIC",
                f"-{DEFAULT_OPT}",
                "-o",
                str(out),
                str(src),
            ]
        )
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


def _compile_rust_fixture(
    src: Path, cc: str, opt: str, strict: bool = False
) -> tuple[Path | None, str]:
    """Build a Rust fixture as a cdylib.

    rustc is its own front end and back end, so the `{gcc, clang}` axis has no
    meaning here — a Rust fixture has exactly one compiler and the lane is named
    `rustc`. `-shared`/`-fPIC` are rejected by rustc (a cdylib is already
    both), `-O` is `-C opt-level=2`, and `-D warnings` is the analogue of
    `-Wall -Wextra -Werror`.

    DWARF v4 is emitted with `-g`, which is what the execution differential
    recovers signatures from; a cdylib exports exactly its `#[no_mangle]`
    symbols and does not re-export std.
    """
    BUILD.mkdir(parents=True, exist_ok=True)
    out = BUILD / f"{src.stem}-rustc-{opt}.so"
    level = "0" if opt == "O0" else "2"
    cmd = [
        "rustc",
        "--edition",
        "2021",
        "-g",
        "-C",
        f"opt-level={level}",
        "--crate-type",
        "cdylib",
        *(["-D", "warnings"] if strict else []),
        "-o",
        str(out),
        str(src),
    ]
    completed = TC.run(cmd)
    if completed.returncode != 0:
        return None, completed.stderr
    return out, ""


def compile_fixture(
    src: Path, cc: str, opt: str, strict: bool = False
) -> tuple[Path | None, str]:
    if src.suffix == ".rs":
        return _compile_rust_fixture(src, cc, opt, strict)
    is_cpp = src.suffix == ".cpp"
    compiler = _cpp_compiler(cc) if is_cpp else cc
    BUILD.mkdir(parents=True, exist_ok=True)
    out = BUILD / f"{src.stem}-{cc}-{opt}.so"
    # Fixtures are warning-clean C; the strict lane proves it (-Werror + explicit
    # fallthrough annotations). Execution builds stay lenient only re: -g/-fPIC.
    warn = ["-Wall", "-Wextra", "-Werror"] if strict else ["-w"]
    cmd = [
        compiler,
        "-shared",
        "-fPIC",
        "-g",
        f"-{opt}",
        *warn,
        "-o",
        str(out),
        str(src),
    ]
    r = TC.run(cmd)
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
    srcs = _fixture_sources()
    # Shared with gen_structural_baseline.py — see M.assert_fixtures_declared for why
    # this must not live in only one of the two writers.
    M.assert_fixtures_declared()
    for src in srcs:
        # A Rust fixture has rustc lanes only; cross-producting it with the C
        # matrix would demand `166_rust_generics:gcc:O0`, which never exists.
        for cc, opt in matrix if src.suffix != ".rs" else matrix_for(src):
            so, err = compile_fixture(src, cc, opt, strict=True)
            if (cc, opt, src.stem) in allowed_missing:
                # declared gap: must genuinely fail (env runtime absent)
                if so is not None:
                    problems.append(
                        f"{src.stem}:{cc}:{opt}: declared env-missing but compiled"
                    )
                continue
            if so is None:
                problems.append(f"{src.stem}:{cc}:{opt}: {err}")
    return problems


def _run_lane(
    src: Path,
    cc: str,
    opt: str,
    fuzz: int,
    env_missing: bool,
    funcs: tuple[str, ...] | None = None,
) -> dict:
    """One (fixture, compiler, opt) lane: {func: status} or a `__lane__` error.

    `funcs` restricts which functions in the lane are executed — the whole point
    of `tools/dectest.py`. It changes WHAT IS REPORTED, never how a reported
    function is judged: the same binary is compiled, and each function's fuzz
    seed is derived from its own name (`_stable_seed`), so a verdict from a
    one-function run is identical to that function's verdict in a full run.
    Anything else would make the fast loop lie.
    """
    # A declared env gap must be a REAL gap: assert the compile truly fails before
    # recording it as env-missing (never a silent skip).
    if env_missing:
        so, _ = compile_fixture(src, cc, opt)
        assert so is None, (
            f"declared env-missing lane {src.stem}:{cc}:{opt} unexpectedly compiled"
        )
        return {"__lane__": "env-missing"}
    so, err = compile_fixture(src, cc, opt)
    if so is None:
        return {"__lane__": f"compile-failed: {err}"}
    cmd = [
        BG.python_bin(),
        str(DIFF),
        str(so),
        str(src),
        "--fixture",
        src.stem,
        "--fuzz",
        str(fuzz),
        "--json",
    ]
    for f in funcs or ():
        cmd += ["--function", f]
    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
        env=BG.export_bin_to_path(),
    )
    try:
        fns = json.loads(r.stdout)
    except json.JSONDecodeError:
        return {"__lane__": f"gate-crashed: {r.stderr.strip()[-160:]}"}
    if "__error__" in fns:
        return {"__lane__": fns["__error__"]}
    return {name: v["status"] for name, v in fns.items()}


def default_jobs() -> int:
    """Lanes to run concurrently.

    Lanes are independent (distinct binaries, per-function subprocess workers,
    per-function stable fuzz seeds), so concurrency changes wall-clock, not
    verdicts — and a gate that takes hours serially is a gate nobody runs, and one
    CI cannot afford. Deliberately not `cpu_count()`: a decompilation that loops
    forever is bounded by the worker's wall-clock timeout, and oversubscribing the
    machine could push a slow-but-correct function past it."""
    env = os.environ.get("GLAURUNG_FIXTURE_JOBS")
    if env:
        return max(1, int(env))
    return max(1, min(8, (os.cpu_count() or 2) - 1))


def run_matrix(
    matrix, fuzz: int, allowed_missing=None, jobs: int | None = None
) -> dict:
    """Return {f"{stem}:{cc}:{opt}": {func: status}} plus lane-level errors, and a
    `__toolchain__` entry identifying the compilers that produced it."""
    if allowed_missing is None:
        allowed_missing = detect_allowed_missing()
    if jobs is None:
        jobs = default_jobs()
    result: dict = {TOOLCHAIN_KEY: TC.fingerprint()}
    srcs = _fixture_sources()
    lanes_to_run = [
        (f"{src.stem}:{cc}:{opt}", src, cc, opt, (cc, opt, src.stem) in allowed_missing)
        for src in srcs
        for cc, opt in (matrix if src.suffix != ".rs" else matrix_for(src))
    ]
    if jobs == 1:
        for key, src, cc, opt, env_missing in lanes_to_run:
            result[key] = _run_lane(src, cc, opt, fuzz, env_missing)
        return result
    # subprocess.run releases the GIL, so threads are enough (and avoid pickling
    # the module state a process pool would need).
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(_run_lane, src, cc, opt, fuzz, env_missing): key
            for key, src, cc, opt, env_missing in lanes_to_run
        }
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                result[key] = fut.result()
            except Exception as e:  # noqa: BLE001 — a lane crash is a lane error, not a skip
                result[key] = {"__lane__": f"harness-crashed: {type(e).__name__}: {e}"}
    return result


def run_lanes(
    lane_specs, fuzz: int, allowed_missing=None, jobs: int | None = None
) -> dict:
    """`run_matrix` for an explicit list of `(fixture, cc, opt, funcs)`.

    The scoped entry point used by `tools/dectest.py`. It shares `_run_lane` with
    the full matrix so a scoped verdict and a gate verdict come from the same
    code — a separate fast path would eventually disagree with the gate, which is
    worse than having no fast path.

    The returned map deliberately carries no `__toolchain__` fingerprint: that
    key is what makes a result map writable as a baseline, and a partial run must
    never be. See `tools/dectest.py` on why there is no `--write-baseline`.
    """
    if allowed_missing is None:
        allowed_missing = detect_allowed_missing()
    if jobs is None:
        jobs = default_jobs()
    work = []
    for fixture, cc, opt, funcs in lane_specs:
        matches = [
            p
            for p in (
                SRC / f"{fixture}.c",
                SRC / f"{fixture}.cpp",
                SRC / f"{fixture}.rs",
            )
            if p.is_file()
        ]
        if not matches:
            raise FileNotFoundError(f"no fixture source for {fixture!r} in {SRC}")
        work.append(
            (
                f"{fixture}:{cc}:{opt}",
                matches[0],
                cc,
                opt,
                (cc, opt, fixture) in allowed_missing,
                tuple(funcs),
            )
        )
    result: dict = {}
    if jobs == 1:
        for key, src, cc, opt, env_missing, funcs in work:
            result[key] = _run_lane(src, cc, opt, fuzz, env_missing, funcs)
        return result
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(_run_lane, src, cc, opt, fuzz, env_missing, funcs): key
            for key, src, cc, opt, env_missing, funcs in work
        }
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                result[key] = fut.result()
            except Exception as e:  # noqa: BLE001 — a lane crash is a lane error, not a skip
                result[key] = {"__lane__": f"harness-crashed: {type(e).__name__}: {e}"}
    return result


#: Every verdict `diff_decompile` can return. `incomparable` and `nonportable`
#: are produced only for cross-architecture lanes (`tools/arch_roundtrip.py`) and
#: never appear in this gate's own x86-64 matrix, but they are declared here
#: because both gates share this vocabulary and `schema_problems` rejects
#: anything outside it.
STATUS_KINDS = (
    "pass",
    "fail",
    "structural",
    "missing",
    "nocases",
    "timeout",
    "incomparable",
    "nonportable",
)


def summarize(result: dict) -> dict:
    c = {k: 0 for k in STATUS_KINDS}
    c["lane"] = c["env_missing"] = 0
    for fns in lanes(result).values():
        if "__lane__" in fns:
            c["env_missing" if fns["__lane__"] == "env-missing" else "lane"] += 1
            continue
        for st in fns.values():
            c[st] = c.get(st, 0) + 1
    return c


def baseline_problems(result: dict) -> list[str]:
    """Reasons a result must NOT be written as a baseline: a non-env lane error
    (compile/gate/infra) or any infra status — a missing required function, a
    zero-case function, or a worker TIMEOUT (which says the machine was too slow,
    not that the decompilation is wrong). Known decompiler fails/structurals are
    fine to record."""
    problems = []
    for key, fns in sorted(lanes(result).items()):
        if "__lane__" in fns:
            if fns["__lane__"] != "env-missing":
                problems.append(f"{key}: lane error ({fns['__lane__']})")
            continue
        for func, st in sorted(fns.items()):
            if st in ("missing", "nocases", "timeout"):
                problems.append(f"{key}:{func}: {st}")
    return problems


def env_lane_problems(current: dict, baseline: dict) -> list[str]:
    """Lanes whose environment availability changed, in either direction.

    A lane recorded `env-missing` is excluded from the per-function comparison —
    there is nothing to compare. That exclusion is only sound while the gap is
    real: on a host (or CI runner) where the runtime IS provisioned, the lane runs,
    produces real verdicts, and would silently drop out of the gate. So an
    `env-missing` lane that becomes runnable is a hard failure demanding a baseline
    refresh, and a runnable lane that becomes `env-missing` is a hard failure
    demanding a provisioned environment. Pure so the fast lane can test the rule
    without compiling anything.
    """
    problems = []
    for lane, base in sorted(lanes(baseline).items()):
        cur = lanes(current).get(lane)
        if cur is None:
            continue  # absence is the matrix test's fail-closed concern
        base_env = base.get("__lane__") == "env-missing"
        cur_env = cur.get("__lane__") == "env-missing"
        if base_env and not cur_env:
            n = len([k for k in cur if k != "__lane__"])
            problems.append(
                f"{lane}: baseline records env-missing but this environment ran it "
                f"({n} function result(s) would be silently excluded) — verify the "
                f"results, then refresh baseline.json"
            )
        elif cur_env and not base_env:
            problems.append(
                f"{lane}: baseline recorded real results but this environment "
                f"reports env-missing — provision the missing runtime instead of "
                f"dropping the lane"
            )
    return problems


def schema_problems(result: dict, matrix) -> list[str]:
    """Every declared fixture must be present across every matrix lane; every
    status a recognized kind. Guards against a truncated/renamed baseline.

    The corpus size comes from the manifest rather than a literal: a hardcoded
    count catches a fixture that silently disappeared, but it also fails whenever
    one is legitimately added, which trains people to edit the guard. Comparing
    the sources on disk against `REQUIRED_FUNCTIONS` catches both a vanished
    fixture and one added without being declared."""
    problems = []
    stems = sorted(p.stem for p in _fixture_sources())
    declared = set(M.REQUIRED_FUNCTIONS)
    if set(stems) != declared:
        problems.append(
            f"fixture sources and the manifest disagree: "
            f"only on disk {sorted(set(stems) - declared)}, "
            f"only declared {sorted(declared - set(stems))}"
        )
    if TOOLCHAIN_KEY not in result:
        problems.append(
            f"no {TOOLCHAIN_KEY} fingerprint — the verdicts are not attributable to "
            f"a toolchain; regenerate with `--write-baseline`"
        )
    sources = {src.stem: src for src in _fixture_sources()}
    for stem in stems:
        # Per-language lanes: a Rust fixture has rustc:O0/rustc:O2 and no gcc or
        # clang lane at all, so cross-producting every stem with the global
        # matrix would demand `171_rust_overflow:gcc:O2` and report it missing.
        src = sources.get(stem)
        lanes = matrix if src is None or src.suffix != ".rs" else matrix_for(src)
        for cc, opt in lanes:
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
    ap.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="lanes to run concurrently (default: GLAURUNG_FIXTURE_JOBS or cores-1, max 8)",
    )
    args = ap.parse_args()

    matrix = [("gcc", "O0")] if args.gcc_o0_only else REQUIRED_MATRIX
    result = run_matrix(matrix, args.fuzz, jobs=args.jobs)

    if args.write_baseline:
        problems = baseline_problems(result) + schema_problems(result, matrix)
        if problems:
            print(
                "REFUSING to write baseline — infrastructure problems:", file=sys.stderr
            )
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            return 1
        BASELINE.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"wrote {BASELINE}")
        return 0
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if not baseline_problems(result) else 2

    fp = result[TOOLCHAIN_KEY]
    print(f"toolchain[{fp['mode']}]: {fp['gcc']} | {fp['clang']} | {fp['libc']}\n")
    for key, fns in sorted(lanes(result).items()):
        if "__lane__" in fns:
            print(f"{key:44s}  LANE: {fns['__lane__']}")
            continue
        pf = sum(1 for st in fns.values() if st == "pass")
        ff = sum(1 for st in fns.values() if st == "fail")
        sf = sum(1 for st in fns.values() if st == "structural")
        flag = "" if ff == 0 else "  <-- FAILURES"
        print(f"{key:44s}  {pf:3d} pass {ff:3d} fail {sf:3d} struct{flag}")
    c = summarize(result)
    print(
        f"\n=== TOTAL: {c['pass']} pass, {c['fail']} fail, {c['structural']} structural, "
        f"{c['missing']} missing, {c['nocases']} no-cases; "
        f"{c['lane']} lane error(s), {c['env_missing']} env-missing ==="
    )
    # Fail-closed: any real lane error or infra status fails the run (env-missing
    # is a declared, probed gap and does not).
    return (
        1
        if (c["fail"] or c["nonportable"] or c["lane"] or c["missing"] or c["nocases"])
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
