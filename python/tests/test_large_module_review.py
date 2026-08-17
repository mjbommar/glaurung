"""The roadmap's "reject new production modules over 1,000 LOC without a
documented review" gate.

    docs/design/decompiler-roadmap.md, "Code quality, composition, and
    file-size program" -> ownership map:

        - [ ] Reject new production modules over 1,000 LOC without a
              documented review.

`tools/fitness_baseline.json` already ratchets the *count* of product files
above 1,000 LOC, but a count cannot see a swap: if one owner is split below
the line in the same change that pushes a new owner above it, the count is
unchanged and the ratchet stays silent. This module ratchets the *set*.

`REVIEWED_LARGE_MODULES` is the inventory of every product file currently
over 1,000 physical lines of non-test code, each with the review that
admitted it. Adding a file to the set fails the suite until an entry --
which is the documented review -- is written for it. Removing a file from
the set also fails, so a split that lands must delete its entry rather than
leave a stale licence behind for the file to re-cross under.

`ir/x87.rs` (2026-08-15, `dcc62aa`) is the worked example of the flow this
gate formalises: it crossed 1,000 LOC, the count ratchet fired, and the
author refreshed the baseline with the reasoning in the commit message. That
reasoning now has a place to live next to the file it is about.

LOC is measured exactly as `tools/fitness_report.py` measures it: physical
lines, whole test files and whole generated files excluded, inline
`#[cfg(test)]` items stripped. This is a source-text check and does not
require building the crate.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SRC = ROOT / "src"
FITNESS_TOOL = ROOT / "tools" / "fitness_report.py"

LARGE_MODULE_LOC = 1000


def _load_fitness_report():
    spec = importlib.util.spec_from_file_location("fitness_report", FITNESS_TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fr = _load_fitness_report()


# Every product file over 1,000 LOC, with the review that admits it.
#
# A "scheduled split" entry names a split the roadmap's ownership map has
# already committed to under "Priority splits, performed only as ownership
# migrates" -- the file is over the line *and* has a named destination.
#
# An "accepted" entry is a file with no scheduled split: the review found one
# reason to change and a single owner, so the size is a property of the
# problem rather than of mixed responsibility. Accepted is not permanent; it
# is a recorded judgement that the next person may overturn.
#
# Do not add a row to make a failure go away. The failure is the review
# request.
REVIEWED_LARGE_MODULES: dict[str, str] = {
    # -- scheduled splits, named in the roadmap's ownership map --
    "ir/ast.rs": (
        "scheduled split: HIR model, projection, visitors, verifier, "
        "declaration planning, cleanup, and renderers. The roadmap's single "
        "largest owner and the target of Phase 7."
    ),
    "ir/ast/dec_render.rs": (
        "extracted 2026-08-16 from ir/ast.rs's Phase 7 split (see that "
        'entry above): the typed C ("dec") expression and statement '
        "printer -- write_stmt_dec, write_expr_dec, write_call_dec, and the "
        "~50 other *_dec functions and private helpers that exist only to "
        "serve them, moved as one call-graph-validated unit. One entry "
        "point (write_stmt_dec, the module's only pub(super) item, called "
        "once from the DecBench render front door in the parent module); "
        "everything else is either called solely from inside this module or "
        "recurses within it. It has no state of its own -- it reads the "
        "parent's installed DeclarationPlan and render-scoped thread-locals "
        "through the parent's private accessors, which is why the module is "
        "a child of ir/ast rather than a standalone sibling. It crossed "
        "1,000 LOC on the move itself (2,170 LOC, almost none of it test "
        "code, unlike the file it came from); the recommended next cut is a "
        "further split along the expression-printer / statement-printer "
        "seam inside this module once that is worth the added pub(super) "
        "surface between the two halves."
    ),
    "ir/lift_x86.rs": "scheduled split: shared lift builder plus x86 instruction families.",
    "ir/lift_arm32.rs": "scheduled split: shared lift builder plus ARM32 instruction families.",
    "ir/lift_arm64.rs": "scheduled split: shared lift builder plus ARM64 instruction families.",
    "ir/call_args.rs": (
        "scheduled split: ABI classification, evidence, solver, and HIR projection."
    ),
    "ir/types_recover.rs": (
        "scheduled split: constraints, collection, solving, prototypes, and "
        "language spelling."
    ),
    "ir/stack_locals.rs": (
        "under review, measured 2026-08-17. Four of the five concerns the "
        "earlier note listed are real; one is not. Of 3,241 product LOC: "
        "promotion 1,076 (the driver, `rewrite_body`, `rewrite_expr`, the "
        "address-escape recovery and the late reconcile), frame analysis 752, "
        "access recovery 720, object construction 362, the data model 97 -- "
        "and NAMING is 141, one 121-line `alloc_name` plus a nine-line "
        "reservation helper. That is a function, not a module, exactly like "
        "`types_recover`'s 43-line 'language spelling'. The note also called "
        "the file untouched when it was already three files: `address_aliases` "
        "(697) and `bounded_overlap` (62) predate this entry. Three layers "
        "have now been lifted to descendant modules -- `address_recovery` "
        "(707), `coordinate_flow` (526), `indexed_objects` (378) -- leaving "
        "the promotion pass itself: entry points, driver, rewriter, naming."
    ),
    "ir/structure.rs": (
        "scheduled split: graph algorithms, regions, selection, verification, and HIR."
    ),
    "python_bindings/ir.rs": (
        "scheduled split: thin adapters over session, engine, and typed results."
    ),
    # -- accepted: one owner, one reason to change --
    "analysis/cfg.rs": (
        "accepted, under review: the entry-rooted walk that turns bytes into "
        "blocks, edges, and functions. Two clusters have been lifted out to "
        "descendant modules -- `cfg/scan.rs` (speculative image scans, "
        "3c61879) and `cfg/repair.rs` (post-discovery repairs: split-chunk "
        "merge, DWARF overrides, landing-pad attachment). What remains is one "
        "walk with one reason to change. The earlier note here claimed the "
        "jump-table and budget responsibilities were separable; measurement "
        "says otherwise. The jump-table DECODERS already live in "
        "analysis/jump_table.rs, and what is left under that name is dispatch "
        "edge replay inside `discover_function` -- 22 call sites, all "
        "internal, 7 widenings to buy 258 lines. `Budgets` is separable and "
        "worth 165 lines against 19 importers across four subsystems."
    ),
    "ir/value_number.rs": "accepted: one global value-numbering pass and its lattice.",
    "ir/copy_prop.rs": "accepted: one copy/constant propagation pass and its safety proofs.",
    "ir/call_contracts.rs": (
        "accepted (2026-08-16, c2fb19d): one pass with one reason to change — "
        "an authoritative prototype overriding what ABI liveness merely "
        "suggested. It crossed 1,000 lines when SysV return classes landed, "
        "because a return CLASS is exactly the kind of authoritative fact this "
        "pass exists to apply. Splitting the classifier out would separate a "
        "fact from its only consumer, which is the coupling the ownership map "
        "warns against rather than the one it asks to break."
    ),
    "ir/const_fold.rs": "accepted: one constant-folding pass over the full operator set.",
    "ir/loop_form.rs": "accepted: loop normalisation, one pass with one reason to change.",
    "ir/x87.rs": (
        "accepted (2026-08-15, dcc62aa): the x87 register stack must be "
        "resolved to a proven depth per function before ST(i) means anything, "
        "so the depth fixed point, the eight-slot lowering, and the "
        "control-word window matcher are one analysis, not three."
    ),
    "ir/dwarf_fields.rs": "accepted: DWARF field/member decoding for one producer surface.",
    "debug/dwarf.rs": "accepted: DWARF section parsing; one input format, one owner.",
    "symbols/pdb.rs": "accepted: PDB ingestion; one input format, one owner.",
    "analysis/java_class.rs": "accepted: the Java class-file format in one owner.",
    "analysis/ioctl_taint.rs": "accepted: the Windows ioctl taint analysis, one pass.",
    "python_bindings/analysis.rs": (
        "accepted: thin PyO3 adapters; large by row count, not by depth. "
        "Shrinks with the analysis surface, not on its own."
    ),
    "triage/api.rs": "accepted: the triage entry surface; adapters over one pipeline.",
    "triage/config.rs": "accepted: triage configuration and its defaults/validation.",
    # -- symbolic-execution engine (out of decompiler scope, still in src/) --
    "symbolic/solver/axeyum_backend.rs": "accepted: one solver backend and its warm-reuse protocol.",
    "symbolic/solver/mod.rs": "accepted: the solver facade and its shared query plumbing.",
    "symbolic/explore.rs": "accepted: the symbolic path explorer, one search loop.",
    "symbolic/ordered_trace.rs": "accepted: the ordered trace format and its writer.",
    "symbolic/ordered_replay.rs": "accepted: ordered replay against a pinned configuration.",
}


def large_product_modules(root: Path) -> dict[str, int]:
    """Return `{src-relative path: product LOC}` for files over the line."""
    return {
        str(relative): loc
        for relative, loc in fr.measured_files(root)
        if loc > LARGE_MODULE_LOC
    }


def test_every_large_product_module_has_a_documented_review():
    measured = large_product_modules(SRC)
    unreviewed = sorted(set(measured) - set(REVIEWED_LARGE_MODULES))
    assert unreviewed == [], (
        "production module(s) over 1,000 LOC with no documented review.\n"
        "Prefer splitting the file. If the size is genuinely one owner with "
        "one reason to change, add an entry to REVIEWED_LARGE_MODULES saying "
        "so -- that entry IS the review:\n"
        + "\n".join(f"  {path}: {measured[path]} LOC" for path in unreviewed)
    )


def test_no_review_entry_outlives_the_file_it_reviewed():
    """A split that lands must take its licence with it, or the file can
    re-cross 1,000 LOC later without anyone looking."""
    measured = large_product_modules(SRC)
    stale = sorted(set(REVIEWED_LARGE_MODULES) - set(measured))
    assert stale == [], (
        "REVIEWED_LARGE_MODULES entries for files that are no longer over "
        "1,000 LOC (or no longer exist). Delete them:\n"
        + "\n".join(f"  {path}" for path in stale)
    )


def test_the_set_ratchet_sees_a_swap_the_count_ratchet_cannot():
    """The reason this module exists at all: `product_files_above_1000` is a
    count, so splitting one owner below the line while a new owner crosses it
    leaves the count unchanged. Prove the set check catches that."""
    reviewed = {"ir/ast.rs": "scheduled split", "ir/lift_x86.rs": "scheduled split"}
    after_a_swap = {"ir/ast.rs": 11628, "ir/brand_new_owner.rs": 1400}

    assert len(after_a_swap) == len(reviewed)  # the count ratchet sees nothing
    assert sorted(set(after_a_swap) - set(reviewed)) == ["ir/brand_new_owner.rs"]
    assert sorted(set(reviewed) - set(after_a_swap)) == ["ir/lift_x86.rs"]


def test_a_new_oversized_module_is_detected_on_disk(tmp_path):
    """Prove the detector fires on a real file, not just on the synthetic
    sets above: a fresh 1,400-line product module in a scanned tree shows up,
    and the same module made test-only or generated does not."""
    (tmp_path / "ir").mkdir()
    body = "\n".join(f"const K{i}: u32 = {i};" for i in range(1400))
    (tmp_path / "ir" / "brand_new_owner.rs").write_text(body, encoding="utf-8")
    (tmp_path / "ir" / "brand_new_owner_tests.rs").write_text(body, encoding="utf-8")
    (tmp_path / "ir" / "brand_new_table.rs").write_text(
        "// @generated\n" + body, encoding="utf-8"
    )

    assert sorted(large_product_modules(tmp_path)) == ["ir/brand_new_owner.rs"]


def test_the_inventory_is_not_vacuous():
    """A measurement bug that returned no files would make both checks above
    pass trivially."""
    measured = large_product_modules(SRC)
    assert len(measured) > 10, (
        f"only {len(measured)} product file(s) measured over 1,000 LOC; the "
        "measurement is more likely broken than the tree that clean"
    )


def test_the_review_count_agrees_with_the_fitness_report():
    """The set check and the committed count ratchet must be measuring the
    same population, or one of them is silently scoped wrong."""
    report = fr.build_report(SRC)
    assert report["measures"]["product_files_above_1000"] == len(
        large_product_modules(SRC)
    )
