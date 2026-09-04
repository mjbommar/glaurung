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

import scratch  # noqa: F401  -- points TMPDIR off the shared /tmp tmpfs on import
import argparse
import functools
import hashlib
import json
import os
import shutil
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

#: Go, like Rust, has exactly one compiler, so its lanes are named `go`.
#:
#: Go has no `-O` levels. The two lanes are the honest analogues: an ordinary
#: `go build` (optimised, the O2 analogue) and `-gcflags=all=-N -l` (no
#: optimisation, no inlining, the O0 analogue). They keep the `O0`/`O2` spelling
#: so every downstream key format, selector and baseline reader works unchanged.
GO_MATRIX = [("go", "O0"), ("go", "O2")]

#: Suffix marking an optimisation level whose object is STRIPPED before it is
#: decompiled: `O2strip` is `-O2 -g`, then `strip`.
#:
#: Why the optimisation slot and not a new axis. A lane is identified everywhere
#: in this corpus by the three-part key `fixture:cc:opt` -- in all four committed
#: baselines, in `tools/dectest.py`'s selector grammar, and in the manifest's
#: `skip_exec_lanes`. A fourth colon component is not available: `dectest` already
#: spends it on the FUNCTION (`13_loop_early_exit:gcc:O0:bisect`), so a lane key
#: with four parts could not be told from a function selector. The compiler slot
#: is the other candidate and it is already overloaded --
#: `tools/arch_roundtrip.py` puts `i386`, `aarch64`, `armv7` and `x86_64_gcc15`
#: there -- and putting the strip variant in it would multiply rather than
#: compose. The optimisation slot is in practice the BUILD-RECIPE slot: it
#: already names the flags handed to the compiler. `-O2` then `strip` is one more
#: recipe, it composes with every compiler for free, and its control lane is a
#: mechanical string operation on the key (`O2strip` -> `O2`).
STRIP_SUFFIX = "strip"


def split_opt(opt: str) -> tuple[str, bool]:
    """`("O2", True)` for `"O2strip"`, `("O2", False)` for `"O2"`."""
    if opt.endswith(STRIP_SUFFIX) and len(opt) > len(STRIP_SUFFIX):
        return opt[: -len(STRIP_SUFFIX)], True
    return opt, False


def stripped_opt(opt: str) -> str:
    """The stripped counterpart of a base optimisation level."""
    base, already = split_opt(opt)
    return opt if already else base + STRIP_SUFFIX


#: Base optimisation levels that get a stripped counterpart.
#:
#: `-O2` only, and that is a scope decision made against a measurement rather
#: than taste -- see `docs/development/decompiler-testing.md`. At `-O0` a function
#: begins at a `push rbp` after a `ret`, every local is a frame-pointer offset and
#: nothing is inlined or outlined, so removing the debug info costs the analysis
#: almost nothing; `-O2` is where extents, prototypes and types genuinely have to
#: be inferred, and it is the configuration real targets ship in.
STRIPPED_BASE_OPTS = ("O2",)


def stripped_lanes_for(src) -> list[tuple[str, str]]:
    """The stripped lanes for one fixture source.

    Derived from `matrix_for` rather than restated, so a Rust fixture gets
    `rustc:O2strip` and never `gcc:O2strip` -- the same per-language rule
    `lanes_for` exists to enforce, and the same trap
    (`10_cpp_runtime_shapes:rustc:O0`) it was written to close.

    Deliberately NOT folded into `REQUIRED_MATRIX`: this lane is a DIFFERENTIAL
    against the `-g` build of the same source, not a standalone pass/fail, so its
    control is the `fixture:cc:O2` cell already committed in `baseline.json` and
    it has no baseline of its own. See `tools/stripped_differential.py`.
    """
    return [
        (cc, stripped_opt(opt))
        for cc, opt in matrix_for(src)
        if opt in STRIPPED_BASE_OPTS
    ]


def path_remap_flags(compiler: str) -> list[str]:
    """Flags that erase this checkout's absolute path from the produced object.

    WHY THIS IS NOT COSMETIC. Without it a fixture binary embeds `ROOT` twice
    over -- in `DW_AT_comp_dir`, in every DWARF file name, in `__FILE__`
    expansions, and (for rustc) in the panic-location string literal of every
    `unwrap`/bounds check. Those are STRINGS, so a checkout at a different path
    depth produces different string lengths, a different `.rodata` layout, and
    different section addresses; function discovery then finds a different set
    of functions and every downstream census moves.

    Measured, 2026-08-18: the def-use census in an agent worktree
    (`<root>/.claude/worktrees/agent-XXXX`) read `rustc:O0 7522 violations in
    3034 emitted functions` where the same commit in the main checkout read
    `7525 / 3035`. Two agents on one day reported the committed baseline stale
    on that evidence. Both were right about their own tree and wrong about
    master, and either report, if trusted, would have written a bad baseline.

    The map target is `.` rather than a sentinel like `/glaurung` so the
    recorded paths stay resolvable relative to the compile's working directory,
    which `compile_fixture` pins to `ROOT` for exactly that reason: the remap
    only removes the prefix it is given, so a build whose cwd is elsewhere would
    still bake that cwd into `DW_AT_comp_dir`.

    Proven sufficient by construction, not assumed: building one fixture under
    two roots whose path lengths differ by 60 characters gives byte-identical
    objects for gcc, clang, g++ and rustc (`cmp` clean) with these flags, and
    four different sizes without them.
    """
    if compiler == "rustc":
        return [f"--remap-path-prefix={ROOT}=."]
    if compiler == "go":
        # Go spells this `-trimpath`, which takes no argument: it strips the
        # module root unconditionally rather than remapping a given prefix. The
        # effect is the same one the C and Rust flags buy -- no absolute build
        # path baked into the object, so two checkouts at different depths
        # produce identical bytes.
        return ["-trimpath"]
    return [f"-ffile-prefix-map={ROOT}=."]


def matrix_for(src) -> list[tuple[str, str]]:
    """The compiler/optimization lanes that apply to one fixture source."""
    name = str(src)
    if name.endswith(".rs"):
        return RUST_MATRIX
    if name.endswith(".go"):
        return GO_MATRIX
    return REQUIRED_MATRIX


def lanes_for(src, matrix) -> list[tuple[str, str]]:
    """The lanes to run for one fixture, narrowed by a caller-supplied matrix.

    The fixture's LANGUAGE decides which compilers can build it; `matrix` may
    then narrow that set. Callers routinely pass the UNION of every lane in the
    baseline (`sorted({tuple(k.split(":")[1:]) for k in lanes(baseline)})`), and
    once the corpus contained a single Rust fixture that union grew `rustc`
    lanes -- which the old `matrix if src.suffix != ".rs" else matrix_for(src)`
    then handed to every C and C++ source. That is how
    `10_cpp_runtime_shapes:rustc:O0` came to exist: a C++ fixture built by g++
    and recorded, with its Itanium-mangled symbols, under a Rust lane label.

    Narrowing to the intersection fixes that. An EMPTY intersection means the
    caller's matrix names no compiler this language has -- a C matrix against a
    Rust source -- which is an omission rather than a request for nothing, so
    fall back to the language's own compilers at whichever optimisation levels
    were asked for. `--gcc-o0-only` therefore still means O0-only for a Rust
    fixture instead of silently running both levels.
    """
    language = matrix_for(src)
    if matrix is None:
        return list(language)
    narrowed = [lane for lane in language if lane in matrix]
    if narrowed:
        return narrowed
    opts = {opt for _cc, opt in matrix}
    return [lane for lane in language if lane[1] in opts]


def rust_lanes_enabled() -> bool:
    """Whether Rust fixtures participate in the matrix.

    ON — but read the next paragraph before trusting it.

    This docstring used to say "the pinned toolchain image now provisions rustc
    (see `toolchain/Dockerfile`) and `_VERSION_PROBES` records its version".
    Neither half is true, measured 2026-08-18:

      * `tests/decompiler_fixtures/toolchain/Dockerfile` installs
        `gcc g++ clang libstdc++-11-dev libc6-dev` and nothing else. The image
        that exists on the machines where the Rust lanes work has a FOURTH layer
        (`docker history glaurung-fixture-toolchain:1` shows
        `apt-get install ... rustc`) that no committed Dockerfile ever contained,
        and `ensure_image` never rebuilds a tag that already exists. A fresh
        checkout therefore builds an image with no rustc and loses all 12 Rust
        lanes to `compile-failed: rustc: executable file not found`.
      * `fixture_toolchain._VERSION_PROBES` probes gcc, g++, clang, clang++, ld
        and libc. There is no rustc in `__toolchain__`, in baseline.json or in
        defuse_baseline.json — even though the Rust lanes are ~95% of the def-use
        census. `object_fingerprint` pins it per object; the recorded baselines
        still do not.

    Set GLAURUNG_FIXTURE_RUST=0 to drop the Rust lanes — which is what a fresh
    checkout needs until the Dockerfile grows the missing line.
    """
    return os.environ.get("GLAURUNG_FIXTURE_RUST", "1") != "0"


def go_lanes_enabled() -> bool:
    """Whether the five Go fixtures (176-180) participate.

    OFF by default, and that is a statement about the BASELINES rather than
    about the toolchain. The sources have been in the tree since they were
    written, already `-buildmode=c-shared` with `//export`ed drivers over C
    scalars -- exactly the dlopen shape the execution differential consumes --
    and the pinned image builds all five clean once `golang-go` is installed.
    What is missing is a recorded verdict: turning them on adds ~10 host lanes
    that appear in none of `baseline.json`, `structural_baseline.json`,
    `arch_baseline.json` or `defuse_baseline.json`, so every one of those gates
    reads the new lanes as unrecorded.

    So the switch exists to make enabling them ONE deliberate act -- set this,
    regenerate all four baselines on a quiet machine, and read every diff --
    rather than a surprise the next person to run the gate discovers.

    Set GLAURUNG_FIXTURE_GO=1 to opt in.
    """
    return os.environ.get("GLAURUNG_FIXTURE_GO", "0") != "0"


def fixture_sources() -> list:
    """Every fixture source the matrix should cover."""
    srcs = list(SRC.glob("*.c")) + list(SRC.glob("*.cpp"))
    if rust_lanes_enabled():
        srcs += list(SRC.glob("*.rs"))
    if go_lanes_enabled():
        srcs += list(SRC.glob("*.go"))
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
            for opt in ("O0", "O2", "O0" + STRIP_SUFFIX, "O2" + STRIP_SUFFIX):
                missing.add(("clang", opt, stem))
    return missing


def _rust_argv(src: Path, opt: str, out: Path, strict: bool) -> list[str]:
    """The command line that builds a Rust fixture as a cdylib.

    rustc is its own front end and back end, so the `{gcc, clang}` axis has no
    meaning here — a Rust fixture has exactly one compiler and the lane is named
    `rustc`. `-shared`/`-fPIC` are rejected by rustc (a cdylib is already
    both), `-O` is `-C opt-level=2`, and `-D warnings` is the analogue of
    `-Wall -Wextra -Werror`.

    DWARF v4 is emitted with `-g`, which is what the execution differential
    recovers signatures from; a cdylib exports exactly its `#[no_mangle]`
    symbols and does not re-export std.
    """
    return [
        "rustc",
        "--edition",
        "2021",
        "-g",
        "-C",
        f"opt-level={'0' if split_opt(opt)[0] == 'O0' else '2'}",
        "--crate-type",
        "cdylib",
        *path_remap_flags("rustc"),
        *(["-D", "warnings"] if strict else []),
        "-o",
        str(out),
        str(src),
    ]


def _go_argv(src: Path, opt: str, out: Path, strict: bool) -> list[str]:
    """The command line that builds a Go fixture as a C shared library.

    `-buildmode=c-shared` is what the fixtures were written for: each exports
    its `//export`ed entry points over plain C scalars and a caller-owned
    buffer, which is precisely the dlopen shape the execution differential
    drives. No adaptation was needed on the fixture side.

    Go has no `-O`, so the two lanes are the honest analogues rather than an
    invented axis: an ordinary build is the optimised one, and
    `-gcflags=all=-N -l` (disable optimisation, disable inlining) is the O0 one.
    `all=` matters -- without it the flags apply to the named package only and
    the runtime is still built optimised, which is not the shape a debug build
    of a Go program actually has.

    Expect these lanes to record badly at first. Go's calling convention, its
    goroutine-stack prologue and the enormous `.gopclntab` are exactly the
    shapes fixtures 176-180 were written to expose, so a red-but-RECORDED
    baseline is the deliverable here, not a green one.
    """
    return [
        "go",
        "build",
        "-buildmode=c-shared",
        *path_remap_flags("go"),
        *(["-gcflags=all=-N -l"] if split_opt(opt)[0] == "O0" else []),
        # Go has no `-Werror` analogue at build time; `strict` has nothing to
        # bind to here, and pretending otherwise would be a silent no-op.
        "-o",
        str(out),
        str(src),
    ]


def _c_argv(
    compiler: str, cc: str, src: Path, opt: str, out: Path, strict: bool
) -> list[str]:
    """The command line that builds a C or C++ fixture as a shared object."""
    # Fixtures are warning-clean C; the strict lane proves it (-Werror + explicit
    # fallthrough annotations). Execution builds stay lenient only re: -g/-fPIC.
    warn = ["-Wall", "-Wextra", "-Werror"] if strict else ["-w"]
    return [
        compiler,
        "-shared",
        "-fPIC",
        "-g",
        f"-{split_opt(opt)[0]}",
        *warn,
        *path_remap_flags(cc),
        "-o",
        str(out),
        str(src),
    ]


def _canonical_source(src: Path) -> Path:
    """`src` as a ROOT-RELATIVE path, whatever spelling the caller used.

    Canonicalising matters because `_normalized_argv` rewrites the literal ROOT
    prefix, which a relative path does not carry -- so the same build
    fingerprinted two ways depending on whether the caller passed
    `tests/.../x.c` or the absolute path, and every lane read as stale on the
    next check.

    It canonicalises DOWNWARD, to the relative form, and that direction is not a
    style choice. `rustc`'s `--remap-path-prefix` rewrites only what matches the
    prefix, so an absolute source becomes `./tests/...` while a relative one
    stays `tests/...` -- a one-character difference that rustc embeds, changing
    the object bytes and therefore the decompiler's output. Measured on
    `166_rust_generics.rs`:

        relative  sha=966f5ab828ca98f0   embeds `tests/decompiler_fixtures/...`
        absolute  sha=8214c0a6f3727f0d   embeds `./tests/decompiler_fixtures/...`

    Canonicalising upward silently rebuilt every Rust object and moved the
    def-use census by 20 violations in `rustc:O0` and 12 in `rustc:O2`, which
    the ratchet then reported as a regression in whatever change happened to be
    in flight. Relative is also the form the committed baselines were measured
    with. `compile_fixture` runs with `cwd=ROOT`, so the compiler resolves it
    identically either way.
    """
    if not src.is_absolute():
        return src
    try:
        return src.resolve().relative_to(ROOT)
    except ValueError:
        # Outside the checkout: nothing to make relative to, and the remap flag
        # will not touch it either. Leave it exactly as given.
        return src


def compile_plan(
    src: Path, cc: str, opt: str, strict: bool = False
) -> tuple[str, Path, list[str]]:
    """`(compiler, output path, argv)` for one fixture lane, without running it.

    Split out of `compile_fixture` so the cache key is computed from THE SAME
    argv that is executed. The alternative — a fingerprint built from a second,
    hand-maintained list of "the flags we use" — reproduces the defect this whole
    mechanism exists for one level up: the day the two lists disagree, the key
    silently stops covering a flag that moves the bytes, and nothing says so.
    """
    # Canonicalise the source BEFORE the argv is built. `compile_fixture` runs
    # with `cwd=ROOT`, so a caller may legitimately pass either
    # `tests/decompiler_fixtures/src/x.c` or the absolute path, and both compile
    # to the same bytes. They did NOT fingerprint the same: `_normalized_argv`
    # rewrites the literal ROOT prefix, which a relative path does not carry, so
    # the same object recorded `.../src/x.c` one way and `$ROOT/.../src/x.c` the
    # other and every lane read as stale on the next check. Resolving here makes
    # the key a function of the build rather than of the caller's spelling.
    src = _canonical_source(src)
    if src.suffix == ".rs":
        out = BUILD / f"{src.stem}-rustc-{opt}.so"
        return "rustc", out, _rust_argv(src, opt, out, strict)
    if src.suffix == ".go":
        out = BUILD / f"{src.stem}-go-{opt}.so"
        return "go", out, _go_argv(src, opt, out, strict)
    compiler = _cpp_compiler(cc) if src.suffix == ".cpp" else cc
    out = BUILD / f"{src.stem}-{cc}-{opt}.so"
    return compiler, out, _c_argv(compiler, cc, src, opt, out, strict)


# ---------------------------------------------------------------------------
# per-object build fingerprints  (tests/decompiler_fixtures/build/ is a CACHE)
# ---------------------------------------------------------------------------

#: Suffix of the sidecar recording what produced one object.
#:
#: A sidecar rather than an encoding in the object's filename: the filename is
#: the lane identity that ~20 call sites already construct by hand
#: (`f"{fixture}-{cc}-{opt}.so"`), and every one of them would have to learn to
#: hash. A sidecar also stays readable — `cat build/foo-gcc-O0.so.build.json`
#: says why a rebuild happened, where a hash in a filename says only that two
#: names differ.
SIDECAR_SUFFIX = ".build.json"

#: Schema version of the sidecar. BUMP THIS when a field is added, so every
#: object written by an older harness is treated as stale rather than trusted:
#: an old sidecar cannot record a key it did not know about, and comparing only
#: the keys it does have would re-open the hole this whole mechanism closes.
CACHE_SCHEMA = 1


def sidecar_for(out: Path) -> Path:
    """The fingerprint file that belongs to one built object."""
    return out.with_name(out.name + SIDECAR_SUFFIX)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _normalized_argv(argv: list[str]) -> list[str]:
    """`argv` with this checkout's absolute path replaced by `$ROOT`.

    The remap flags are PROVEN to make the produced object byte-identical across
    checkouts at different paths (see `path_remap_flags`), so keying on the
    literal `-ffile-prefix-map=/home/.../glaurung=.` would force a full rebuild
    in every worktree for objects that are known to be identical. Normalising
    keeps the key stable across checkouts while still changing the moment the
    flag is added, removed, renamed, or given a different target — which is the
    change that actually moved the bytes.
    """
    root = str(ROOT)
    return [tok.replace(root, "$ROOT") for tok in argv]


@functools.lru_cache(maxsize=None)
def compiler_identity(compiler: str) -> dict[str, str]:
    """`{version, target}` of one compiler, probed THROUGH the pinned toolchain.

    Probed through `TC.run` and not `subprocess.run`: under the default docker
    mode the compiler that builds the fixtures is the image's (gcc 11.4,
    rustc 1.75 here), and the host's (gcc 15.2, rustc 1.97 here) is a different
    program that would produce a different object. A key recording the host's
    version would call an image-built object stale on a machine whose host
    compiler moved, and — far worse — call a host-built object fresh under
    docker mode.

    The target triple is recorded separately from the version because it can
    move without the version moving: the same gcc build invoked as a multilib or
    cross driver emits for a different target, and nothing in `--version` says
    so.
    """
    if compiler == "rustc":
        r = TC.run(["rustc", "-vV"], cwd=ROOT)
        if r.returncode != 0:
            raise TC.ToolchainError(f"cannot probe rustc: {r.stderr.strip()[-400:]}")
        lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        host = next(
            (ln.split(":", 1)[1].strip() for ln in lines if ln.startswith("host:")), ""
        )
        return {"version": lines[0] if lines else "", "target": host}
    ver = TC.run([compiler, "--version"], cwd=ROOT)
    tgt = TC.run([compiler, "-dumpmachine"], cwd=ROOT)
    if ver.returncode != 0 or tgt.returncode != 0:
        raise TC.ToolchainError(
            f"cannot probe {compiler}: {(ver.stderr + tgt.stderr).strip()[-400:]}"
        )
    first = (ver.stdout.strip().splitlines() or [""])[0].strip()
    return {"version": first, "target": tgt.stdout.strip()}


def object_fingerprint(src: Path, compiler: str, argv: list[str]) -> dict:
    """Everything that can change the bytes of one built fixture object.

    THE DEFECT THIS EXISTS FOR. `tests/decompiler_fixtures/build/` is a cache
    keyed by `{fixture}-{cc}-{opt}.so` and nothing else. When
    `-ffile-prefix-map=$ROOT=.` / `--remap-path-prefix` was added, every object
    already on disk kept its old bytes — including the absolute checkout path
    the flag exists to erase — and every consumer that READS an object without
    rebuilding it (`tools/dectest.py --show`,
    `python/tests/test_decompile_determinism.py`,
    `python/tests/test_loop_hoist_traps.py`) went on measuring the old ones.
    Measured on the main checkout, 2026-08-19: 17 objects six days older than
    the flag change survived it, and `132_cpp_vtable_layout-rustc-O0.so` — a
    label no lane has produced since `lanes_for` stopped cross-producting C++
    sources with Rust lanes — still contained the checkout path four times.

    Two wrong findings came out of that in one day: two def-use censuses of the
    same commit disagreeing, and four `144_inline_asm` cross-arch cells credited
    to a commit that does not produce them on a cold cache.

    The fields, and what each one catches:

    ``argv``               every flag, including whatever `path_remap_flags`
                           returns and the `-Wall -Wextra -Werror` / `-w` split
                           between the strict lane and the execution lane, which
                           share an output path.
    ``compiler_version``   a compiler upgrade under a stable image tag.
    ``target``             the same driver retargeted (multilib, cross).
    ``toolchain_mode``     `docker` vs `host`. These write to the SAME paths with
                           different compilers (gcc 11.4 vs 15.2 here); one
                           `GLAURUNG_FIXTURE_TOOLCHAIN=host` run used to leave
                           host objects that a later pinned run read as pinned.
    ``toolchain_image``    the image CONTENT digest, because `ensure_image` only
                           checks that the tag exists — see `TC.image_id`.
    ``source_sha256``      an edited fixture.

    Not covered, deliberately and with the reason: the system headers and libc
    the compile pulls in. They live inside the pinned image, so `toolchain_image`
    moves whenever they do; under `GLAURUNG_FIXTURE_TOOLCHAIN=host` they are
    unpinned, which is already what that mode means.
    """
    ident = compiler_identity(compiler)
    return {
        "schema": CACHE_SCHEMA,
        "argv": _normalized_argv(argv),
        "compiler": compiler,
        "compiler_version": ident["version"],
        "target": ident["target"],
        "toolchain_mode": TC.mode(),
        "toolchain_image": TC.image_id(),
        "source_sha256": _sha256(src),
    }


def read_sidecar(out: Path) -> dict | None:
    """The recorded fingerprint of one object, or `None` if there is not a
    readable one."""
    side = sidecar_for(out)
    try:
        recorded = json.loads(side.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return recorded if isinstance(recorded, dict) else None


def write_sidecar(out: Path, fingerprint: dict) -> None:
    """Record what produced `out`, atomically.

    Atomic because lanes compile concurrently and a half-written sidecar is
    indistinguishable from a fingerprint that genuinely disagrees — it would
    force a rebuild rather than allow a stale reuse, so it fails safe, but it
    would also make the cache look permanently broken.
    """
    side = sidecar_for(out)
    payload = dict(fingerprint, object_sha256=_sha256(out))
    tmp = side.with_name(side.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, side)


def stale_reason(out: Path, expected: dict) -> str | None:
    """Why `out` cannot be reused, or `None` if it is exactly what `expected`
    describes.

    Returns a REASON rather than a bool because "the cache missed" is the
    question a person debugging a surprise rebuild actually has, and a bool
    makes them re-derive the answer by hand.
    """
    if not out.is_file():
        return "not built"
    recorded = read_sidecar(out)
    if recorded is None:
        return (
            "no build fingerprint — produced by a harness that predates "
            "the fingerprint, or written by hand"
        )
    if recorded.get("schema") != CACHE_SCHEMA:
        return f"fingerprint schema {recorded.get('schema')!r} != {CACHE_SCHEMA}"
    if recorded.get("object_sha256") != _sha256(out):
        return (
            "object does not hash to its recorded fingerprint (replaced or truncated)"
        )
    for key, want in sorted(expected.items()):
        got = recorded.get(key)
        if got != want:
            return f"{key}: recorded {got!r} != current {want!r}"
    return None


def ensure_fixture(
    src: Path, cc: str, opt: str, strict: bool = False
) -> tuple[Path | None, str]:
    """`compile_fixture`, but reuse the object on disk when it is PROVABLY the
    one these flags, this compiler and this source produce.

    This is the entry point for every consumer that READS a built object without
    having compiled it itself. `compile_fixture` deliberately keeps rebuilding
    unconditionally, and the measurement says that is the right call: a full cold
    build of the corpus is 29-34s wall for all 768 objects at
    `default_jobs()==8` (26.4s before this change added the fingerprints;
    2026-08-18, docker mode, 24-core host) against a ~50 minute gate. Skipping
    compiles would buy ~1% and would stake the gate's correctness on this key
    being complete. The readers, which today do no compile at all, buy
    correctness for nothing.
    """
    compiler, out, argv = compile_plan(src, cc, opt, strict)
    try:
        expected = object_fingerprint(src, compiler, argv)
    except (TC.ToolchainError, OSError) as exc:
        return None, f"cannot fingerprint the build: {exc}"
    # A stripped lane is TWO files. A fresh sidecar proves the compile is
    # current; it says nothing about the `-g` oracle beside it, which a
    # `prune_cache` or a hand `rm` can remove on its own. Rebuild when the pair
    # is incomplete rather than hand a differential a missing control.
    pair_ok = not split_opt(opt)[1] or dwarf_sibling(out).exists()
    if pair_ok and stale_reason(out, expected) is None:
        return out, ""
    return compile_fixture(src, cc, opt, strict)


def dwarf_sibling(so: Path) -> Path:
    """The `-g` object a stripped lane's oracle signatures are read from.

    Kept beside the stripped object under its own name rather than shared with
    the `fixture:cc:O2` lane's file: the two lanes run CONCURRENTLY out of one
    build directory (`run_matrix` submits them to a single thread pool), and a
    shared path would let one lane's `strip` land on the other lane's object
    mid-run. A separate name costs a second compile and buys a lane that cannot
    corrupt its own control.
    """
    return so.with_name(so.name[: -len(".so")] + ".dwarf.so")


def _strip_if_requested(out: Path, opt: str) -> tuple[Path | None, str]:
    """Turn a freshly built `-g` object into a stripped lane's pair of objects.

    Returns the object to DECOMPILE. For a base lane that is the `-g` build
    unchanged. For a stripped lane the `-g` build is preserved as
    `dwarf_sibling(out)` -- the oracle -- and `out` becomes a `strip`ped copy of
    it, which is what the decompiler is handed.

    `strip` removes `.symtab` and every `.debug_*` section and leaves `.dynsym`
    alone, so a shared object's exported functions survive and the result is
    still `dlopen`able and callable through ctypes. That is what makes this lane
    cheap: the existing execution differential runs unmodified on the stripped
    object. Measured on this corpus -- `201_float_bit_stores` at gcc -O2 keeps all
    8 exported `T` symbols at all 8 unchanged addresses across the strip while
    losing all 8 `.debug_*` sections and its entire 27-entry `.symtab`.
    """
    _base, stripped = split_opt(opt)
    if not stripped:
        return out, ""
    oracle = dwarf_sibling(out)
    shutil.copy2(out, oracle)
    r = TC.run(["strip", str(out)])
    if r.returncode != 0:
        return None, f"strip failed: {(r.stderr.strip().splitlines() or ['?'])[-1]}"
    return out, ""


def compile_fixture(
    src: Path, cc: str, opt: str, strict: bool = False
) -> tuple[Path | None, str]:
    """Build one fixture lane, unconditionally, and record what produced it.

    Always recompiles: see `ensure_fixture` for why the gate is not made
    cache-aware. What changed is that success now leaves a fingerprint sidecar,
    and failure REMOVES any sidecar left over from a previous success — an
    object whose rebuild failed must never look fresh, and the old object is
    still sitting at that path (the compiler drivers write `-o` only on success).

    NOT fixed here, and worth knowing: `build/` is shared by every process, and
    two of them running at once (a `pytest -m slow` beside a `dectest`, or two
    `dectest` invocations) write the SAME path for the same lane. The sidecar
    lets `ensure_fixture` reject an object whose write FINISHED with the wrong
    flags, but nothing serialises the write itself, so a reader can still be
    handed a half-written object by a concurrent builder. Fixing that needs a
    per-object lock or a per-process build directory, neither of which this
    change makes.
    """
    compiler, out, argv = compile_plan(src, cc, opt, strict)
    BUILD.mkdir(parents=True, exist_ok=True)
    r = TC.run(argv, cwd=ROOT)
    if r.returncode != 0:
        sidecar_for(out).unlink(missing_ok=True)
        stderr = r.stderr.strip()
        if src.suffix == ".rs":
            return None, r.stderr
        return None, (stderr.splitlines() or ["?"])[-1]
    # Strip BEFORE the sidecar. The fingerprint describes the compile -- source,
    # compiler, argv -- none of which `strip` touches, so the ordering looks
    # free. It is not: `write_sidecar` also records `object_sha256`, and `strip`
    # rewrites exactly those bytes. Fingerprinting first made every stripped
    # object read back as "does not hash to its recorded fingerprint (replaced
    # or truncated)" -- 390 of them -- which is the one verdict that must mean
    # someone tampered with the file.
    stripped_out, strip_err = _strip_if_requested(out, opt)
    if stripped_out is None:
        sidecar_for(out).unlink(missing_ok=True)
        return None, strip_err
    try:
        write_sidecar(out, object_fingerprint(src, compiler, argv))
    except (TC.ToolchainError, OSError):
        # A compile that succeeded but could not be fingerprinted must not be
        # left looking fresh; the object is still usable for THIS run.
        sidecar_for(out).unlink(missing_ok=True)
    return stripped_out, strip_err


def expected_objects() -> dict[str, tuple[Path, str, str]]:
    """`{object name: (source, cc, opt)}` for every lane the corpus declares.

    Deliberately NOT `fixture_sources()`: that one drops the Rust sources under
    `GLAURUNG_FIXTURE_RUST=0`, and the question here is which names a lane COULD
    produce, not which this run will. Using the narrower set would make every
    `*-rustc-*.so` an orphan the moment someone set that variable, and
    `prune_cache` would then delete objects that are perfectly fresh.
    """
    srcs = sorted(
        list(SRC.glob("*.c")) + list(SRC.glob("*.cpp")) + list(SRC.glob("*.rs"))
    )
    out: dict[str, tuple[Path, str, str]] = {}
    for src in srcs:
        # `stripped_lanes_for` is included even though it is not in
        # `REQUIRED_MATRIX`: this map answers "which names could a lane produce",
        # and `prune_cache` deletes everything it does not answer for. Leaving
        # the stripped objects out would make an opt-in `--stripped` run's
        # products orphans that the next ordinary `pytest` run deletes.
        for cc, opt in lanes_for(src, None) + stripped_lanes_for(src):
            _compiler, path, _argv = compile_plan(src, cc, opt)
            out[path.name] = (src, cc, opt)
    return out


def cache_problems() -> list[str]:
    """Everything in `build/` that a consumer must not trust.

    Two kinds, and the second is the one that produced a wrong finding:

    * STALE — the object exists but its fingerprint disagrees with what this
      source, compiler and flag list would produce now.
    * ORPHAN — the object's name is not a lane any current source declares, so
      NOTHING will ever overwrite it. `132_cpp_vtable_layout-rustc-O0.so` is the
      worked example: a C++ fixture recorded under a Rust lane by the old
      cross-product in `lanes_for`, left behind when that was fixed, and still
      carrying pre-remap bytes six days later.

    EITHER of the two current builds counts as fresh. The strict lane
    (`-Wall -Wextra -Werror`, `strict_compile_problems`) and the execution lane
    (`-w`, `run_matrix`) write to the SAME path, and whichever ran last is what
    is on disk. Both are products of the current source, flags and toolchain, so
    neither is stale — calling the strict one stale would make an ordinary
    `pytest python/tests/` run report 768 problems it just legitimately created.
    What is NOT accepted is a third argv nobody produces any more, which is the
    actual defect.

    An empty `build/` reports nothing — a fresh checkout has no cache to be
    wrong about.
    """
    if not BUILD.is_dir():
        return []
    expected = expected_objects()
    problems = []
    for obj in sorted(BUILD.glob("*.so")):
        # The `-g` oracle beside a stripped object is a byte copy of that
        # object's own pre-strip build (`_strip_if_requested`), not a lane
        # product: it has no sidecar of its own and its freshness IS the stripped
        # lane's freshness, which is checked on the next line. `ensure_fixture`
        # rebuilds the pair when the oracle is missing.
        if obj.name.endswith(".dwarf.so"):
            continue
        lane = expected.get(obj.name)
        if lane is None:
            problems.append(
                f"{obj.name}: orphan — no current fixture lane produces this "
                f"name, so nothing will ever rebuild it"
            )
            continue
        src, cc, opt = lane
        reasons = []
        for strict in (False, True):
            compiler, path, argv = compile_plan(src, cc, opt, strict)
            reason = stale_reason(path, object_fingerprint(src, compiler, argv))
            if reason is None:
                break
            reasons.append(reason)
        else:
            problems.append(f"{obj.name}: stale — {reasons[0]}")
    return problems


def prune_cache() -> list[str]:
    """Delete every stale or orphan object (and its sidecar). Returns what went.

    Deleting rather than rebuilding: an orphan has no lane to rebuild it from,
    and a stale object is rebuilt by the next run that needs it anyway.
    """
    removed = []
    for problem in cache_problems():
        name = problem.split(":", 1)[0]
        obj = BUILD / name
        obj.unlink(missing_ok=True)
        sidecar_for(obj).unlink(missing_ok=True)
        removed.append(problem)
    return removed


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
    srcs = fixture_sources()
    # Shared with gen_structural_baseline.py — see M.assert_fixtures_declared for why
    # this must not live in only one of the two writers.
    M.assert_fixtures_declared()
    for src in srcs:
        # A Rust fixture has rustc lanes only; cross-producting it with the C
        # matrix would demand `166_rust_generics:gcc:O0`, which never exists.
        for cc, opt in lanes_for(src, matrix):
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
    shadow_v2: bool = False,
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
    if split_opt(opt)[1]:
        # The decompiler is handed the stripped object; the ORACLE's prototypes
        # come from the `-g` build of the same compile. See `_strip_if_requested`
        # and `diff_decompile.run`'s `dwarf_so`.
        cmd += ["--dwarf-so", str(dwarf_sibling(so))]
    if shadow_v2:
        cmd.append("--shadow-v2")
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
    srcs = fixture_sources()
    lanes_to_run = [
        (f"{src.stem}:{cc}:{opt}", src, cc, opt, (cc, opt, src.stem) in allowed_missing)
        for src in srcs
        for cc, opt in lanes_for(src, matrix)
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
    lane_specs,
    fuzz: int,
    allowed_missing=None,
    jobs: int | None = None,
    shadow_v2: bool = False,
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
            result[key] = _run_lane(
                src, cc, opt, fuzz, env_missing, funcs, shadow_v2=shadow_v2
            )
        return result
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(
                _run_lane,
                src,
                cc,
                opt,
                fuzz,
                env_missing,
                funcs,
                shadow_v2,
            ): key
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
    stems = sorted(p.stem for p in fixture_sources())
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
    sources = {src.stem: src for src in fixture_sources()}
    for stem in stems:
        # Per-language lanes: a Rust fixture has rustc:O0/rustc:O2 and no gcc or
        # clang lane at all, so cross-producting every stem with the global
        # matrix would demand `171_rust_overflow:gcc:O2` and report it missing.
        src = sources.get(stem)
        lanes = matrix if src is None else lanes_for(src, matrix)
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
        "--check-cache",
        action="store_true",
        help="report stale/orphan objects in build/ and exit (compiles nothing)",
    )
    ap.add_argument(
        "--prune-cache",
        action="store_true",
        help="delete stale/orphan objects in build/ and exit",
    )
    ap.add_argument(
        "--jobs",
        type=int,
        default=None,
        help="lanes to run concurrently (default: GLAURUNG_FIXTURE_JOBS or cores-1, max 8)",
    )
    args = ap.parse_args()

    if args.prune_cache:
        removed = prune_cache()
        for r in removed:
            print(f"pruned {r}")
        print(f"pruned {len(removed)} object(s) from {BUILD}")
        return 0
    if args.check_cache:
        problems = cache_problems()
        for p in problems:
            print(p)
        n = len(list(BUILD.glob("*.so"))) if BUILD.is_dir() else 0
        print(f"{len(problems)} problem(s) over {n} object(s) in {BUILD}")
        return 1 if problems else 0

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
