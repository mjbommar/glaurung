"""Layering and environment-variable-dependence checks from
`docs/development/testing-gates.md`'s "Code quality, composition, and
file-size program":

    Add dependency checks: renderers cannot import lifters, HIR cannot parse
    images, targets cannot import renderers, and correctness cannot depend on
    environment variables.

The archived roadmap's ownership map
(`docs/history/design/decompiler-roadmap-2026-08-13.md`) describes a target
layout with dedicated `src/render/`, `src/lift/`, and `src/target/`
directories; only `src/target/` exists as a separate directory today. The
renderer and HIR live together in `src/ir/ast.rs` (documented in the
ownership map as "HIR model, projection, visitors, verifier, declaration
planning, cleanup, and renderers"), and the lifters are `src/ir/lift_*.rs`.
These tests check the boundaries against *today's* module layout; they will
need their file lists updated, not deleted, once the physical split lands.

All of these are pure source-text checks (regex over the checked-out
`src/`), matching this repo's existing convention for cheap layering tests
(see `test_local_gate_fails_closed.py`). They do not require building the
crate.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SRC = ROOT / "src"
FITNESS_TOOL = ROOT / "tools" / "fitness_report.py"


def _load_fitness_report():
    spec = importlib.util.spec_from_file_location("fitness_report", FITNESS_TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fr = _load_fitness_report()


_COMMENT_LINE_RE = re.compile(r"^\s*//")


def _product_text(relative: str, *, drop_comment_lines: bool = False) -> str:
    """Test-stripped product source for one file, addressed by `src/`-relative
    path, so a fixture living only inside a `#[cfg(test)]` block can never
    trip a layering check meant for real dependencies.

    `drop_comment_lines` additionally removes whole-line `//`/`///`/`//!`
    comments, so a rustdoc link such as `[crate::ir::abi]` in a doc comment
    does not read as a real dependency -- only code does.
    """
    path = SRC / relative
    assert path.is_file(), f"expected file missing (module layout changed?): {path}"
    text = fr.strip_test_items(path.read_text(encoding="utf-8"))
    if not drop_comment_lines:
        return text
    return "\n".join(
        line for line in text.splitlines() if not _COMMENT_LINE_RE.match(line)
    )


# --- renderers cannot import lifters -----------------------------------------

# The renderer functions (`render`, `render_c`, `render_with_types`) live in
# `src/ir/ast.rs` today, alongside the HIR model itself.
RENDERER_HIR_FILE = "ir/ast.rs"


def renderer_hir_files() -> list[str]:
    """Every product file in the renderer/HIR owner, discovered rather than
    listed: `src/ir/ast.rs` plus everything under `src/ir/ast/`.

    Discovery matters because Phase 7 splits this owner. A hard-coded single
    filename would keep passing while each new submodule carved out of
    `ast.rs` escaped the boundary unchecked.
    """
    found = [RENDERER_HIR_FILE]
    for path in sorted((SRC / "ir" / "ast").rglob("*.rs")):
        relative = path.relative_to(SRC)
        if not fr.is_test_path(relative):
            found.append(str(relative))
    return found


def test_the_renderer_owner_is_more_than_one_file_or_still_the_one_we_know():
    """Guards the discovery above against a layout move that would empty it."""
    files = renderer_hir_files()
    assert RENDERER_HIR_FILE in files
    assert all((SRC / relative).is_file() for relative in files)


# `src/ir/lift_*` are the per-architecture lifters (machine bytes -> LLIR).
LIFTER_REFERENCE_RE = re.compile(
    r"crate::ir::lift_(x86|arm32|arm64|function)\b|"
    r"\buse\s+crate::ir::\{[^}]*\blift_(x86|arm32|arm64|function)\b"
)


def test_renderer_hir_does_not_reference_the_lifters():
    for relative in renderer_hir_files():
        text = _product_text(relative, drop_comment_lines=True)
        hit = LIFTER_REFERENCE_RE.search(text)
        assert hit is None, (
            f"{relative} (renderer/HIR) references a lifter module "
            f"({hit.group(0) if hit else ''!r}); the renderer must consume the "
            "already-lifted IR, not lift bytes itself"
        )


# --- HIR cannot parse images --------------------------------------------------

# Image parsing lives behind `crate::formats::*` (ELF/PE/Mach-O) and the
# `object`/`goblin`-style parsing entry points. The HIR receives an already
# lifted, already parsed function -- it must never reach back to raw bytes.
IMAGE_PARSING_RE = re.compile(r"crate::formats::|\bProgramImage\b|\bobject::File\b")


def test_hir_does_not_parse_images():
    for relative in renderer_hir_files():
        text = _product_text(relative, drop_comment_lines=True)
        hit = IMAGE_PARSING_RE.search(text)
        assert hit is None, (
            f"{relative} (HIR) references image parsing "
            f"({hit.group(0) if hit else ''!r}); HIR construction must receive "
            "already-lifted evidence, never parse a binary image itself"
        )


# --- targets cannot import renderers -----------------------------------------

TARGET_FILES = (
    "target/abi.rs",
    "target/registers.rs",
    "target/spec.rs",
    "target/mod.rs",
)

# Anything in `crate::ir` at all is suspicious for `src/target`: TargetSpec
# is meant to sit below the IR layer (lifters and analysis consume it), so an
# `ir` import here would mean the dependency arrow had reversed. The specific
# renderer symbols get their own message so a failure is diagnosable at a
# glance rather than just "found crate::ir".
RENDERER_SYMBOL_RE = re.compile(r"\bir::ast::(render|render_c|render_with_types)\b")
ANY_IR_IMPORT_RE = re.compile(r"crate::ir\b")


def test_targets_do_not_import_renderers():
    for relative in TARGET_FILES:
        path = SRC / relative
        if not path.is_file():
            continue  # module layout changed; other files in the tuple still check
        text = _product_text(relative, drop_comment_lines=True)
        renderer_hit = RENDERER_SYMBOL_RE.search(text)
        assert renderer_hit is None, (
            f"{relative} references a renderer symbol ({renderer_hit.group(0)!r}); "
            "target/ must not depend on the render layer"
        )
        ir_hit = ANY_IR_IMPORT_RE.search(text)
        assert ir_hit is None, (
            f"{relative} imports from crate::ir; target/ is meant to sit below "
            "the IR layer (lifters and analysis consume TargetSpec, not the "
            "other way around) -- if this is deliberate, narrow this check "
            "rather than deleting it"
        )


def test_at_least_one_target_file_exists():
    """A layout change that silently emptied `TARGET_FILES` would make the
    check above vacuously pass. Catch that."""
    assert any((SRC / relative).is_file() for relative in TARGET_FILES)


# --- the parsing substrate stays language-neutral -----------------------------

# `src/syntax/` is the language-neutral parsing substrate; `src/csource/` is the
# C front end built on it. Three rules from
# `docs/design/source-front-ends/substrate.md` section 1, checked here because
# they are cheap to enforce now and expensive to restore after something has
# crossed them:
#
#   1. `syntax` must not import any language module.
#   2. `csource::cfg` must not import `csource::joern` -- the Joern-parity layer
#      reproduces another tool's artifacts, and if those leak into the general
#      CFG then the lowering to LLIR inherits a graph shaped by a JVM program's
#      expression granularity.
#   3. `syntax::cfg` must not know what a C statement is; it consumes events.
#
# Rules 2 and 3 guard modules that do not exist yet. That is deliberate: a
# boundary written before the first crossing costs one regex, and after it costs
# a refactor. Each check skips cleanly while its files are absent, and
# `test_the_substrate_boundary_checks_are_not_vacuous` fails if *every* one of
# them is skipping, so the whole block cannot quietly become a no-op.

SYNTAX_DIR = SRC / "syntax"
CSOURCE_DIR = SRC / "csource"

#: Any language front end the substrate must not reach into.
LANGUAGE_MODULE_RE = re.compile(r"\bcrate::(csource|ir|disasm|analysis|formats)\b")


def _rust_files(directory: Path) -> list[str]:
    """Product `.rs` files under `directory`, `src/`-relative, tests excluded."""
    if not directory.is_dir():
        return []
    found = []
    for path in sorted(directory.rglob("*.rs")):
        relative = path.relative_to(SRC)
        if not fr.is_test_path(relative):
            found.append(str(relative))
    return found


def test_the_substrate_does_not_import_a_language_front_end():
    """`REQ-SYN-1`: nothing in `src/syntax/` names a specific language.

    The substrate supplies mechanics -- spans, interning, a token buffer, an
    event stream, a CFG builder over control-flow events. Token kinds and node
    tags are opaque `u16` values a language supplies. The moment the substrate
    imports a language module it stops being reusable and the second front end
    pays for it.
    """
    for relative in _rust_files(SYNTAX_DIR):
        text = _product_text(relative, drop_comment_lines=True)
        hit = LANGUAGE_MODULE_RE.search(text)
        assert hit is None, (
            f"{relative} imports {hit.group(0)!r}; src/syntax/ is the "
            "language-neutral substrate and must not depend on a language front "
            "end (REQ-SYN-1). If this is deliberate, move the code into the "
            "language module rather than widening this check"
        )


def test_the_general_c_cfg_does_not_import_the_joern_parity_layer():
    """The parity layer reproduces another tool's quirks; it must stay above.

    `csource/cfg/` builds the graph a person would draw. `csource/joern/`
    reproduces expression-granular nodes, a method-return node deleted only when
    it stayed a singleton, and entry/exit as derived flags. Those are metric
    artifacts. If they leak downward, `lower/` lowers a distorted graph to LLIR
    and every consumer of the general CFG inherits the distortion.
    """
    for relative in _rust_files(CSOURCE_DIR / "cfg"):
        text = _product_text(relative, drop_comment_lines=True)
        hit = re.search(r"\bcrate::csource::joern\b|\bsuper::joern\b", text)
        assert hit is None, (
            f"{relative} references {hit.group(0)!r}; the general CFG must not "
            "depend on the Joern-parity layer (docs/design/static-c-analysis/"
            "architecture.md section 1)"
        )


def test_the_substrate_cfg_builder_is_language_blind():
    """`REQ-SYN-8`: the CFG builder consumes control-flow events, not syntax.

    It never sees a token, a node tag or a keyword -- which is what makes it the
    one component a second language front end reuses unchanged.
    """
    for relative in _rust_files(SYNTAX_DIR / "cfg") + (
        ["syntax/cfg.rs"] if (SYNTAX_DIR / "cfg.rs").is_file() else []
    ):
        text = _product_text(relative, drop_comment_lines=True)
        hit = LANGUAGE_MODULE_RE.search(text)
        assert hit is None, (
            f"{relative} imports {hit.group(0)!r}; the CFG builder consumes "
            "control-flow events and must stay language-blind (REQ-SYN-8)"
        )


def test_the_substrate_boundary_checks_are_not_vacuous():
    """At least the substrate itself must exist, or the block above proves
    nothing. This is the same guard `test_at_least_one_target_file_exists`
    provides for the target-layer checks."""
    assert _rust_files(SYNTAX_DIR), (
        "src/syntax/ has no product .rs files; the substrate boundary checks "
        "above would pass vacuously"
    )


# --- correctness cannot depend on environment variables ----------------------
#
# Every `std::env::var`/`var_os`/`vars()` read in production code (test files
# and `#[cfg(test)]` items are stripped first) must be a reviewed, allowed
# entry below. The categories:
#
#   diagnostic   stderr dump / telemetry / trace metadata only; the decision
#                or computed result does not change based on the variable.
#   instrumentation
#                adds review-only comments to rendered output when requested;
#                the underlying analysis runs unconditionally either way.
#   resource     selects which external resource (signature file, solver
#                binary, checkout path, trace directory) to consult; has a
#                defined default and absence never silently changes what a
#                completed analysis means.
#   budget       process-wide timeout/step budget for the solver backends;
#                changes how much work is attempted, never what a completed
#                answer means.
#   policy       principled, versioned policy selecting among several
#                equally sound witnesses in the symbolic explorer; the
#                chosen policy id is written into the trace for audit.
#   pinned-confirmation
#                refuses to run unless a fixed, named set of tuning
#                variables already carries specific pinned values -- the
#                opposite of a silent semantic gate.
#
# What must NOT appear here: a variable that silently changes which analysis
# runs, what a lifted/verified/rendered artifact contains, or what counts as
# correct/complete -- gating a semantic decision behind an environment
# variable, the way verified MIR used to be built only when
# `GLAURUNG_DUMP_PASSES` was set (fixed this session; see
# `PreparedLlir::mir` in `src/python_bindings/ir.rs`).
ENV_VAR_ALLOWLIST: dict[tuple[str, str], str] = {
    # -- decompiler-scope: diagnostics, all gate an eprintln/dump only --
    ("analysis/exception.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    ("analysis/cfg/repair.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    ("analysis/ioctl_surface.rs", '"GLAURUNG_IOCTL_DEBUG"'): "diagnostic",
    ("decompile/profile.rs", '"GLAURUNG_PIPELINE_PROFILE"'): "diagnostic",
    ("ir/exception_recover.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    ("ir/health.rs", '"GLAURUNG_PASS_HEALTH"'): "diagnostic",
    # The float-gate diagnostic, added in `7d834ed7` alongside the fix for an ISA
    # proxy that misread a spilled float as ARM. Same category and same shape as
    # `ir/health.rs`: it gates only `eprintln!` of a JSON line and changes no
    # decompiler output. Registered here after the fact — the commit that added
    # it did not run this suite, and `cargo test`, `dectest`, `cargo fmt` and the
    # fitness ratchet were all green over the gap.
    ("ir/ast/float_gate.rs", '"GLAURUNG_PASS_HEALTH"'): "diagnostic",
    # The lowering stack reservation, added in `aea49ddc`. Not a diagnostic: it
    # sizes the thread `ast::lower` runs on. It cannot disable the guard -- values
    # below a 16 MB floor clamp and warn -- so it tunes a resource reservation and
    # changes no decompiler output. Registered late; the commit that added it did
    # not run this suite, exactly as `ir/ast/float_gate.rs` above records for its
    # own gap.
    ("ir/ast/lower_region.rs", '"GLAURUNG_LOWERING_STACK_MB"'): "resource",
    ("ir/high_variables.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    ("ir/pass_stats.rs", '"GLAURUNG_PASS_STATS"'): "diagnostic",
    ("ir/structure.rs", '"GLAURUNG_ACCOUNT_STRUCTURE"'): "diagnostic",
    # R8.1. `src/testing.rs` is `#[cfg(test)]`-gated, so this never reaches a
    # shipped build -- but the allowlist is keyed by file path and does not
    # know that, and being asked to justify it is the right outcome. It gates
    # nothing semantic: it only decides whether a test that CANNOT run reports
    # a skip or a failure. Set in CI so a missing compiler is loud there;
    # unset locally so a machine without cross-compilers still works.
    ("testing.rs", "REQUIRE_ENV"): "diagnostic",
    # Its fixture twin, added in `5c4778b1`. Same file, same `#[cfg(test)]`
    # gating, same shape: it decides only whether a test whose prebuilt binary
    # is absent reports a skip or a failure. Set by the Decompiler Fixture
    # Gate, the one lane that builds `tests/decompiler_fixtures/build`.
    ("testing.rs", "REQUIRE_FIXTURES_ENV"): "diagnostic",
    ("ir/value_number/coalesce.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    ("program/environment.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    ("program/format_environment.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    ("python_bindings/ir.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    ("python_bindings/ir/callee_contracts.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    # The AST pass-list dump and the two LLIR-stage dumps, moved verbatim out of
    # `python_bindings/ir.rs` when the shared pipeline was split out. Same reads,
    # same `eprintln!`-only effect.
    ("python_bindings/ir/pipeline.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    # The prepared-AST and rendered-C dumps, moved verbatim out of
    # `python_bindings/ir.rs` with the DecBench renderer.
    ("python_bindings/ir/decbench_render.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    ("python_bindings/ir/dwarf_contracts.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    # `diagnostics_are_disabled()` iterates this exact reviewed list to decide
    # whether the *render cache* may be reused; it never changes what a fresh
    # render would have produced, only whether an in-process cache is trusted.
    ("python_bindings/ir/session.rs", "name"): "diagnostic",
    # The `===== recovered declaration types =====` dump at the end of
    # `decbench_type_maps`. It moved here verbatim from `python_bindings/ir.rs`
    # when the DecBench type maps were split out; the read is unchanged and
    # still gates only `eprintln!`.
    ("python_bindings/ir/type_maps.rs", '"GLAURUNG_DUMP_PASSES"'): "diagnostic",
    # -- decompiler-scope: instrumentation (opt-in output comments) --
    # Splices def-before-use violation comments into rendered C. The
    # verification itself (`violations`) is always computed; this only gates
    # whether it is echoed as comments in the artifact. See the docstring at
    # `splice_verify_comments`'s call site for the documented reasoning.
    (
        "python_bindings/ir/decbench_render.rs",
        '"GLAURUNG_VERIFY_DEFS"',
    ): "instrumentation",
    # -- decompiler-scope: resource selection --
    # Which FLIRT signature library to consult; has a documented cwd-relative
    # default and a `None` (no-op) fallback if nothing is reachable.
    ("flirt/mod.rs", '"GLAURUNG_FLIRT_LIB"'): "resource",
    # The directory rung below it: every `*.flirt.json` in one directory,
    # merged. Same fallback chain, same no-op when nothing is reachable.
    ("flirt/mod.rs", '"GLAURUNG_SIG_DIR"'): "resource",
    # `~/.cache/glaurung/sigs/`, the client download cache, is one rung further
    # down that chain; `HOME` is read only to spell it.
    ("flirt/mod.rs", '"HOME"'): "resource",
    # -- symbolic-execution engine (out of decompiler scope, still in src/) --
    ("symbolic/solver/mod.rs", '"GLAURUNG_FAIR_SHADOW"'): "diagnostic",
    ("symbolic/solver/mod.rs", '"GLAURUNG_DUMP_QUERIES"'): "diagnostic",
    ("symbolic/solver/mod.rs", '"GLAURUNG_DUMP_SHADOW_SPLITS"'): "diagnostic",
    ("symbolic/solver/mod.rs", '"GLAURUNG_SHADOW_DIFF"'): "diagnostic",
    ("symbolic/solver/mod.rs", "Z3_RLIMIT_ENV"): "budget",
    ("symbolic/solver/mod.rs", "AXEYUM_PROGRESS_CHECK_LIMIT_ENV"): "budget",
    ("symbolic/solver/mod.rs", "BITWUZLA_TERMINATION_POLL_LIMIT_ENV"): "budget",
    ("symbolic/solver/mod.rs", "CHECK_TIMEOUT_ENV"): "budget",
    ("symbolic/solver/pipe.rs", '"GLAURUNG_SMT_SOLVER"'): "resource",
    ("symbolic/solver/constraint_cache.rs", "ENGINE_CONSTRAINT_CACHE_ENV"): "budget",
    ("symbolic/solver/axeyum_backend/config.rs", "WARM_MAX_LIVE_PATHS_ENV"): "budget",
    (
        "symbolic/solver/axeyum_backend/config.rs",
        "WARM_MAX_ASSERTIONS_PER_PATH_ENV",
    ): "budget",
    ("symbolic/solver/axeyum_backend/config.rs", "WARM_REUSE_ENV"): "budget",
    ("symbolic/solver/axeyum_backend/config.rs", "DIRECT_DELTA_ENV"): "budget",
    (
        "symbolic/solver/axeyum_backend/config.rs",
        "WARM_TIMEOUT_COLD_RETRY_ENV",
    ): "budget",
    ("symbolic/solver/axeyum_backend/config.rs", "WARM_TIMEOUT_CONTINUE_ENV"): "budget",
    ("symbolic/solver/axeyum_backend/config.rs", "WARM_OWNER_TRANSFER_ENV"): "budget",
    (
        "symbolic/solver/axeyum_backend/config.rs",
        "WARM_SERIAL_SIBLING_REUSE_ENV",
    ): "budget",
    ("symbolic/solver/axeyum_backend/config.rs", "REPLAY_SAT_CACHE_ENV"): "budget",
    (
        "symbolic/solver/axeyum_backend/config.rs",
        "INTERNAL_AND_FLATTENING_ENV",
    ): "budget",
    ("symbolic/solver/axeyum_backend.rs", "PROFILE_DIR_ENV"): "diagnostic",
    ("symbolic/solver/axeyum_backend.rs", "CNF_SNAPSHOT_DIR_ENV"): "diagnostic",
    ("symbolic/concretization.rs", "CONCRETIZATION_POLICY_ENV"): "policy",
    ("symbolic/concretization.rs", "LEGACY_CANONICAL_MODEL_CHOICE_ENV"): "policy",
    ("symbolic/ordered_replay.rs", "AXEYUM_SOURCE_REPO_ENV"): "resource",
    ("symbolic/ordered_replay.rs", "FACTORIAL_MODE_ENV"): "pinned-confirmation",
    # Dynamic lookup over the fixed, named tuning-variable list defined a few
    # lines above each call site in `validate_runtime_configuration` /
    # `runtime_configuration` -- every name in that literal list already has
    # its own entry above (WARM_REUSE_ENV et al.).
    ("symbolic/ordered_replay.rs", "name"): "pinned-confirmation",
    ("symbolic/ordered_trace.rs", '"GLAURUNG_ORDERED_TRACE_DIR"'): "resource",
    ("symbolic/ordered_trace.rs", '"GLAURUNG_TRACE_ORACLE_VERSION"'): "diagnostic",
    # `std::env::vars()`: snapshots every GLAURUNG_/IOCTLANCE_/BITWUZLA_
    # variable into the trace's recorded configuration metadata. Recording
    # ambient configuration for audit is not the same as branching on it.
    ("symbolic/ordered_trace.rs", ""): "diagnostic",
}

_ENV_CALL_RE = re.compile(r"std::env::(?:var_os|var|vars)\(([^()]*)\)")


def discover_env_var_reads(root: Path) -> set[tuple[str, str]]:
    """Return every `(relative_file, argument_token)` pair for a production
    `std::env::var`/`var_os`/`vars()` call under `root`.

    `argument_token` is the literal source text of the call argument: a
    quoted string for `std::env::var("X")`, or the bare identifier for
    `std::env::var(SOME_CONST)` / a loop variable. This intentionally does
    NOT resolve identifiers to their string value -- the allowlist is keyed
    on what a reviewer actually reads at the call site, which is enough to
    prove every call site has been looked at.
    """
    found: set[tuple[str, str]] = set()
    for path in fr.iter_source_files(root):
        relative = path.relative_to(root)
        if fr.is_test_path(relative):
            continue
        text = fr.strip_test_items(path.read_text(encoding="utf-8"))
        for line in text.splitlines():
            for match in _ENV_CALL_RE.finditer(line):
                found.add((str(relative), match.group(1).strip()))
    return found


def test_every_env_var_read_in_src_is_a_reviewed_allowlist_entry():
    found = discover_env_var_reads(SRC)
    allowed = set(ENV_VAR_ALLOWLIST)

    unreviewed = sorted(found - allowed)
    assert unreviewed == [], (
        "unreviewed std::env::var read(s) in production code -- add each to "
        "ENV_VAR_ALLOWLIST with a category after confirming it cannot gate a "
        "semantic decision:\n"
        + "\n".join(f"  {path}: {token}" for path, token in unreviewed)
    )

    stale = sorted(allowed - found)
    assert stale == [], (
        "ENV_VAR_ALLOWLIST entries no longer found in src/ -- the allowlist "
        "must track reality exactly, remove the stale entry(ies):\n"
        + "\n".join(f"  {path}: {token}" for path, token in stale)
    )


def test_no_allowlist_entry_is_categorized_as_a_semantic_gate():
    """A tripwire for the next person editing the allowlist: if a new
    category ever gets introduced to describe "changes which analysis runs
    or what counts as correct", this must fail loudly rather than let the
    category quietly join the allowed set."""
    allowed_categories = {
        "diagnostic",
        "instrumentation",
        "resource",
        "budget",
        "policy",
        "pinned-confirmation",
    }
    used_categories = set(ENV_VAR_ALLOWLIST.values())
    assert used_categories <= allowed_categories, (
        f"unrecognized category(ies) in ENV_VAR_ALLOWLIST: "
        f"{used_categories - allowed_categories}"
    )
