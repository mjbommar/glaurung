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
    "ir/lift_x86.rs": "scheduled split: shared lift builder plus x86 instruction families.",
    "ir/lift_arm32.rs": "scheduled split: shared lift builder plus ARM32 instruction families.",
    "ir/lift_arm64.rs": "scheduled split: shared lift builder plus ARM64 instruction families.",
    "ir/call_args.rs": (
        "accepted (2026-08-17): the argument-folding driver, 3,920 -> 1,327 LOC "
        "across seven cuts. The previous note here promised a split into 'ABI "
        "classification, evidence, solver, and HIR projection'; none of those "
        "four destinations ever existed, and the entry had been describing an "
        "imaginary file since the first real cut. What actually happened: "
        "cdecl32, aapcs and tail_calls (per-convention folding), slot_marking "
        "and captured_defs (argument-slot evidence), return_attribution (246 "
        "lines, where a callee's result goes), enclosing_slots (187 lines, the "
        "loop-carried argument context) and fold_one_call (663 lines, 31% of "
        "the file at the time, ONE pub(super) marker because it was fully "
        "private and 22 parent items were free to it as a descendant). What "
        "remains is one driver with one reason to change."
    ),
    "ir/types_recover.rs": (
        "scheduled split: constraints, collection, solving, prototypes, and "
        "language spelling."
    ),
    "ir/structure.rs": (
        "scheduled split: graph algorithms, regions, selection, verification, and HIR."
    ),
    "python_bindings/ir.rs": (
        "scheduled split, three cuts taken 2026-08-18 (2,738 -> 1,422): "
        "ir/lift.rs (396) took the LLIR dict encoder and the two lift "
        "entry points the module header is about; ir/pipeline.rs (504) took "
        "the shared LLIR/AST stage pipeline -- run_ast_passes, "
        "prepare_llir_for_lowering, PreparedLlir and the four stage helpers; "
        "ir/decbench_render.rs (461) took prepare/verify/render of the "
        "DecBench C artifact. Textually pure moves, MISSING: 0 on both the "
        "code-token and comment-word multisets, costing 19 pub(super) on "
        "moved privates (seven of them the PreparedLlir type and its six "
        "destructured fields) and zero pub(crate)/pub. The previous note here "
        "read 'thin adapters over session, engine, and typed results' and was "
        "false in both halves: 'engine' and 'typed results' named no "
        "destination that ever existed, and the file's four largest items "
        "were not adapters -- decbench_text_with_installed_environment (349), "
        "encode_op (212), run_ast_passes (188) and prepare_llir_for_lowering "
        "(123) were the engine itself. What is left IS the adapter layer: "
        "seven #[pyfunction] entry points, decompile_at_session, the "
        "registration function, and the decbench prototype contract the "
        "pipeline locks against."
    ),
    # -- accepted: one owner, one reason to change --
    "ir/ast/dec_render.rs": (
        "accepted (2026-08-18) at 1,788 LOC: one recursive-descent printer "
        "for one grammar -- an Expr tree in, C text out. Extracted 2026-08-16 "
        "from ir/ast.rs's Phase 7 split; it has no state of its own, reading "
        "the parent's installed DeclarationPlan and render-scoped "
        "thread-locals through the parent's private accessors, which is why "
        "it is a child of ir/ast rather than a sibling. The statement half "
        "left on 2026-08-17 (2,195 -> 1,727 LOC) into the dec_render::stmt "
        "child, where the call graph made the seam exact: write_stmt_dec and "
        "its seven helpers had no caller outside that set, the expression "
        "side never called a statement printer, so the dependency ran one "
        "way (twelve names, stmt -> expr) and a child module widened nothing. "
        "THAT WAS THE LAST ACYCLIC SEAM. What is left, measured on 282a0055: "
        "46 functions, of which 11 spanning 903 lines -- 54% of the file's "
        "item lines -- form a SINGLE strongly-connected component "
        "(write_expr_dec, write_representation_value_dec, write_call_dec, "
        "write_typed_call_arg_dec, write_call_arg_dec, write_float_expr_dec, "
        "write_array_access_dec, write_machine_arithmetic_operand_dec, "
        "write_select_arm_dec, write_wide_arithmetic_dec, "
        "write_expr_for_destination_dec). Every candidate cut proposed so far "
        "slices through it. The float hypothesis (a dec_render/float.rs) was "
        "tested and failed on its own evidence: exactly ONE function renders "
        "floats (write_float_expr_dec, 103 lines, 5.8% of the file); only 5 "
        "of the 46 functions mention a floating-point type at all and 4 of "
        "those are one- or two-line dispatch sites; the scalar-float "
        "intrinsic tables are ALREADY a separate owner (ir/ast/float_gate.rs); "
        "and the union type-punning predates this file -- it landed in "
        "ir/ast.rs (c5944387, 039c7d61) and arrived here by pure move. "
        "Extracting it would trade 103 lines for a bidirectional module edge: "
        "it calls write_expr_dec at six sites and write_expr_dec calls it "
        "back. The call-argument family (11 functions, 287 LOC: write_call_dec, "
        "write_typed_call_arg_dec, write_call_arg_dec, "
        "call_argument_pointer_ctype, pointer_parameter_needs_cast, "
        "integer_call_arg_cast_is_redundant, signed_integer_type_represents, "
        "call_prototype_for_render, effective_call_site_spec, "
        "write_call_pointer_declarator, selected_named_call_prototype) has the "
        "best boundary metrics of any candidate -- six outbound references, "
        "and it is the sole user of all three types on the file's "
        "ir::call_contracts import line -- and is still rejected, on the test "
        "that decides this: CO-CHANGE. Across the 197 commits that have "
        "touched this code, the share of commits to a candidate that touch "
        "nothing else in the file is: stmt, the cut that WAS accepted, 36% "
        "(12/33); call 24% (5/21); the destination/representation cluster 25% "
        "(3/12); float 25% (1/4); and the six pure pattern-recognisers "
        "(try_array_index, scaled_index, index_with_addend, "
        "normalize_wrapped_array_index, "
        "strip_implicit_pointer_index_extension, scaled_pointer_offset) 11% "
        "(1/9) -- that last being the ONLY structurally closed candidate, "
        "with ZERO outbound references, and the worst-changing of all five. "
        "Structural closure without change locality is a boundary and no "
        "narrowing, which is the whole lesson. Nothing left reaches the bar "
        "the accepted cut set. The growth is not accretion: 1,727 -> 1,789 -> "
        "1,788 is +62 from a single commit (4d3353c0, the _Bool return "
        "narrowing) and -1 from 69e55746's shift-operand fix; a third cited "
        "fix (fdbcf58a, the all-SSE return class) landed in write_stmt_dec and "
        "contributes nothing to this file. FALSIFY THIS BY MEASURING, not by "
        "reading it. Split this file when any of: (a) the strongly-connected "
        "component falls below 8 functions or 600 lines; (b) any candidate's "
        "self-contained-commit share reaches the 36% the stmt cut scored; "
        "(c) the file re-crosses 2,000 LOC. Until one of those holds, a cut "
        "here buys a module boundary and no narrowing."
    ),
    "analysis/cfg.rs": (
        "accepted, under review: the entry-rooted walk that turns bytes into "
        "blocks, edges, and functions. Three clusters have been lifted out to "
        "descendant modules -- `cfg/scan.rs` (speculative image scans, "
        "3c61879), `cfg/repair.rs` (post-discovery repairs: split-chunk "
        "merge, DWARF overrides, landing-pad attachment, 5b60729) and "
        "`cfg/pe_tables.rs` (the authoritative PE `.pdata` and export tables "
        "read as seeds, 426 LOC, 2 pub(super), 0 widenings). What remains is "
        "one walk with one reason to change. The earlier note here claimed the "
        "jump-table and budget responsibilities were separable; measurement "
        "says otherwise. The jump-table DECODERS already live in "
        "analysis/jump_table.rs, and what is left under that name is dispatch "
        "edge replay inside `discover_function` -- 22 call sites, all "
        "internal, 7 widenings to buy 258 lines. `Budgets` is separable and "
        "worth 165 lines against 19 importers across four subsystems."
    ),
    "ir/value_number.rs": "accepted: one global value-numbering pass and its lattice.",
    "ir/copy_prop.rs": (
        "under review (2026-08-17): NOT one pass. The previous note said "
        "'accepted: one copy/constant propagation pass and its safety proofs' "
        "and the first half is false -- the file exports EIGHT pub entry "
        "points, scheduled independently at seven call sites in "
        "ir/ast/prepare.rs plus two in python_bindings/ir.rs. A module whose "
        "callers interleave seven of its passes at different pipeline "
        "positions has seven reasons to change, which is the exact question "
        "this list asks. The 'safety proofs' half is accurate and the "
        "2026-08-17 cuts are the evidence: copy_prop/alias.rs took the "
        "memory-disjointness proof out at 284 lines with only 7 names crossing "
        "the boundary, and four of its items turned out to have no reference "
        "anywhere outside it. copy_prop/reads.rs took the read-counting "
        "analysis at 207. Both at token ratio 1.000000. Remaining work is to "
        "decide whether the eight entry points are one owner -- and note that "
        "prune_unobservable_scratch_dataflow is pub with ZERO callers outside "
        "this module, which pub visibility hides from both dead-code counts."
    ),
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
    "analysis/ioctl_taint.rs": "accepted: the Windows ioctl taint analysis, one pass.",
    "python_bindings/analysis.rs": (
        "accepted: thin PyO3 adapters; large by row count, not by depth. "
        "Shrinks with the analysis surface, not on its own."
    ),
    "triage/api.rs": "accepted: the triage entry surface; adapters over one pipeline.",
    "triage/config.rs": "accepted: triage configuration and its defaults/validation.",
    # -- symbolic-execution engine (out of decompiler scope, still in src/) --
    "symbolic/solver/mod.rs": "accepted: the solver facade and its shared query plumbing.",
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
