"""The "reject new production modules over 1,000 LOC without a documented
review" gate.

    docs/development/testing-gates.md, "Code quality, composition, and
    file-size program":

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
import json
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
        "scheduled split, re-reviewed 2026-09-24 at 2,101 LOC (blessed 1,711 at "
        "3e82c79a; 85 commits, 38 origin and 18 identity-authority). The +390 is the "
        "origin carrier landing on the HIR model -- Expr::Origin/Stmt::Origin plus "
        "seven accessors (with_origins, merge_origins, semantic, semantic_mut, "
        "origins, into_semantic_with_origins, with_optional_origins) duplicated across "
        "impl Expr and impl Stmt, ~140 lines -- and more render state: the DEC_* "
        "thread-local cells here went 10 -> 13, against the roadmap's 'rendering is "
        "not a pure projection' item. One cut landed: ast/origin.rs (96 LOC, 7bea3314) "
        "took OriginSet. The 'Phase 7' destination this entry used to cite no longer "
        "exists (real-binary-decompiler.md records that the decomposition never "
        "happened), so the next cut is named instead: the Expr/Stmt origin-carrier "
        "impls into ast/origin.rs beside OriginSet (~140 lines, no call-graph cost). "
        "HIR model, projection, visitors, verifier, declaration planning, cleanup and "
        "renderers remain the eventual owners."
    ),
    "ir/ast/lower_ops.rs": (
        "accepted (2026-08-31): one LLIR `Op` becomes one `Stmt`. A 26-arm "
        "dispatch over `Op` plus fourteen small helpers it dispatches into "
        "(`lower_value`, `widen_cast`, the memory-fill and memory-copy "
        "intrinsic recognisers). The arms do not share state and are not "
        "separately callable, so splitting by arm produces files that exist "
        "only to be re-imported by the same match; splitting helpers out leaves "
        "a match that cannot be read without them. It crossed 1,000 LOC by "
        "three lines in `5547b56c`, which turned `lower_op` from returning a "
        "`Vec<Stmt>` into returning one `Stmt` -- the change that made the "
        "one-op-one-statement property explicit rather than incidental. "
        "Reviewed as the delta, not as a fresh read of the whole file."
    ),
    "ir/lift_x86.rs": "scheduled split: shared lift builder plus x86 instruction families.",
    "ir/lift_arm32.rs": "scheduled split: shared lift builder plus ARM32 instruction families.",
    "ir/lift_arm64.rs": "scheduled split: shared lift builder plus ARM64 instruction families.",
    "ir/call_args.rs": (
        "accepted, re-reviewed 2026-09-24 at 2,107 LOC (blessed 1,327 at 3e82c79a; 58 "
        "commits). No new responsibility arrived: 23 commits re-keyed existing "
        "slot/storage/call-result tests to exact SSA identities (register_is_*storage, "
        "register_argument_slot, the *_with_identities outgoing-stack helpers the "
        "cdecl32 and fold_one_call children use), 22 made folding origin-transparent, "
        "and the rest are per-convention recovery (6c18440b vtable tail calls, "
        "ede20fb0 SysV aggregate buffers, fe50a360 SSE-pair tail args, a9001bd1 "
        "table-call args, 67b6a8a0 hard-float frame args). The one cluster that looked "
        "new -- recovered-layout call folding, 12 fns, ~500 lines -- was measured and "
        "is not a seam: 1/19 (5%) self-contained co-change and 10 outbound names back "
        "into the driver, fold_body among them. Noted accretion: the public "
        "reconstruct_args_* forwarders grew 4 -> 7 (153 lines); fold them into one "
        "options struct before the next re-review. History: 3,920 -> 1,327 across "
        "seven cuts by 2026-08-17 (cdecl32, aapcs, tail_calls, slot_marking, "
        "captured_defs, return_attribution, enclosing_slots, fold_one_call)."
    ),
    "ir/types_recover.rs": (
        "scheduled split, re-reviewed 2026-09-24 at 2,140 LOC (blessed 1,906 at "
        "3e82c79a; 20 commits). The +234 is identity authority threaded through the "
        "driver (recover_types -> recover_types_with_authority plus the "
        "for_ssa/ensure_value_id/value_id helpers; fda323fb, 630595f9, 1e43c1b9, "
        "90c9ff42) and parameter work (apply_locked_parameters 125 -> 181, "
        "fcd9bd2d/62a4ab72). Progress: types_recover/constraints.rs (76 LOC, 8bf704f4, "
        "per-use signedness) is the first named destination to exist, after "
        "types_recover/copies.rs (2026-08-21). Next cut, from the call graph: "
        "prototypes -- recover_prototype_with_arm_vfp_args (416), "
        "apply_locked_parameters (181), locked_{aapcs,sysv_amd64}_parameter_storage, "
        "parameter_refinement* -- roughly 900-1,000 lines whose only in-file callers "
        "are recover_types_with_authority and direct_return_storage."
    ),
    "python_bindings/identity.rs": (
        "accepted (2026-09-03): the PyO3 surface for the identity ladder, six "
        "lanes in one file BY DESIGN and not by accretion. The module's own "
        "header states the convention: each lane (`structural`, `warp`, `cfr`, "
        "`gate`, `values`, `rerank`) keeps its items inside a delimited "
        "section and gets its own `register_*` block, so two lanes landing at "
        "once is a trivial merge instead of a conflict inside a function body. "
        "That held: four lanes were merged onto one line and the only "
        "conflicts in this file were the header's lane roster and the "
        "registration list -- three lines. Splitting by lane would replace one "
        "reviewed convention with six files whose only shared contract is a "
        "`register_identity_bindings` that has to import all of them anyway, "
        "and it would break the property that makes concurrent lanes cheap. It "
        "crossed 1,000 LOC by merging, not by growth: no single lane's section "
        "exceeds ~300 lines. Reviewed as the union of six section deltas, each "
        "already reviewed on its own lane."
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
        "RE-REVIEWED 2026-09-24 at 2,746 LOC (blessed 2,033 at 3e82c79a): trigger (c) "
        "fired 446 lines past 2,300 and is NOT renewed -- SPLIT OWED. The +713 is 38 "
        "commits, 25 of them expression-origin work (9b10f06e onward); largest single "
        "additions 38f3f6cc (O0 source-shaped C), 81ffe9ab (width-proved range "
        "idioms), 2be036eb (signed-comparison cast elision), db2e7735 (line mappings). "
        "Method: a name-reference call graph over top-level fns, coarser than the "
        "2026-08-19 method (it reads 15 SCC functions at 16e6b764, not 12). Top-level "
        "fns 49 -> 69; SCC 15 fns/1,058 lines -> 18/1,336, so trigger (a) moved the "
        "wrong way again, and +278 of +621 fn lines landed inside the SCC. Co-change "
        "over the 46 commits since 3e82c79a touching dec_render.rs or "
        "dec_render/stmt.rs, by the -U0 hunk-in-span rule: the call-argument family "
        "(write_call_dec, write_typed_call_arg_dec, write_call_arg_dec, "
        "call_argument_pointer_ctype, pointer_parameter_needs_cast, "
        "call_prototype_for_render, printf_variadic_parameter_types, "
        "declared_integer_call_arg_through_views, "
        "declared_global_integer_call_arg_through_views, "
        "integer_call_arg_cast_is_redundant; 10 fns, ~388 lines) reads 6/10 = 60% "
        "self-contained. It is cyclic (write_expr_dec <-> write_call_dec), so trigger "
        "(b) as worded does not fire, but the stmt child already shows a child module "
        "absorbs a two-way edge at no visibility cost. Two new acyclic seams also "
        "closed: the render-scoped side channel (LineMappingCollector, "
        "DEC_LINE_MAPPINGS, DEC_PARAMETER_NAMES and five accessors, ~80 lines, zero "
        "in-file edges) and the signed-comparison spelling cluster (5 fns, 114 lines, "
        "one outbound edge, 2/6 = 33%, exactly the bar). Owed cut: the call-argument "
        "family into dec_render/call.rs and the side channel out of the printer "
        "(~2,290), plus the signed-comparison cluster (~2,170). The co-change window "
        "here is only the commits since 3e82c79a, not the full history the entry below "
        "used. -- "
        "accepted (2026-08-19) at 2,013 LOC, RENEWING the 2026-08-18 verdict "
        "at 1,788 LOC after its own trigger (c) fired. One recursive-descent "
        "printer for one grammar -- an Expr tree in, C text out. The re-review "
        "asked the right question -- the +225 lines arrived as COHERENT chunks "
        "(float bit-reinterpretation, shift-width widening, return C types), "
        "and coherent new functionality is exactly what creates a seam where "
        "none existed -- and the answer, measured on 16e6b764, is that it did "
        "not. The SCC did not shrink, it GREW IN STEP: 46 functions -> 49, of "
        "which 11 spanning 903 lines (53.7% of item lines) -> 12 spanning "
        "1,029 lines (54.1%). Trigger (a) wanted it below 8 functions or 600 "
        "lines; it moved the wrong way. 57% of the growth (+126 of +222 fn "
        "lines) landed INSIDE the SCC: write_wide_arithmetic_dec +42, "
        "write_expr_dec +36, write_float_bits_expr_dec +27 (new, and it joined "
        "the SCC on arrival), write_representation_value_dec +21. Only "
        "float_rendered_width (+57) and wide_left_shift_operand_ctypes (+39) "
        "landed outside it. THE FLOAT HYPOTHESIS WAS RE-TESTED ON ITS NEW "
        "EVIDENCE AND FAILED HARDER. It is no longer one function: "
        "write_float_expr_dec (103L, bits -> float) now has "
        "float_rendered_width (57L, the predicate that gates it) and "
        "write_float_bits_expr_dec (27L, float -> bits, the same C99 union "
        "read from the other member) beside it -- a genuinely coherent trio of "
        "187 lines. It is still not separable. Under STRICT floating-point "
        "tokens only 4 of the 49 functions touch an FP type (was 5 of 46), so "
        "the concentration did not change; the trio's module edge is "
        "BIDIRECTIONAL in both directions at once (child -> parent: "
        "write_expr_dec, write_reg_lvalue_dec; parent -> child: 7 call sites "
        "across write_expr_dec, write_typed_call_arg_dec and "
        "write_representation_value_dec); and dec_render::stmt ALREADY "
        "consumes two of the three, so the cut would widen a name the sibling "
        "reaches through a second hop. Decisively, its CO-CHANGE got WORSE, "
        "not better: 25% (1/4) for the old one-function scope, 20% (1/5) for "
        "the new three-function scope -- the two new float functions did not "
        "arrive in float-only commits. Two seams ARE structurally closed at "
        "2,013 that were not enumerated before -- shift_operand_ctype + "
        "wide_left_shift_operand_ctypes + double_width_ctype (3 fns, 99L, ZERO "
        "outbound references) and its union with the six pure "
        "pattern-recognisers (9 fns, 285L, also zero) -- and both score far "
        "below the bar: 25% (2/8) and 15% (2/13). Structural closure without "
        "change locality is a boundary and no narrowing; that lesson now has a "
        "second, independent instance. METHOD, stated so the next re-review "
        "does not have to guess (the 2026-08-18 entry did not, and its "
        "absolute counts could not be reproduced -- see the caveat below): "
        "tracked universe = every top-level fn now in dec_render.rs and "
        "dec_render/stmt.rs; history = all commits touching src/ir/ast.rs or "
        "src/ir/ast/** (207), because this code lived in ir/ast.rs until "
        "a792b9ab and moved here by pure move; a commit touches a function "
        "when a -U0 diff hunk falls inside that function's span in the "
        "pre- or post-image blob; a candidate's share = commits whose whole "
        "touched set lies inside the candidate, over commits touching any of "
        "it. That method reproduces the 2026-08-18 SCC EXACTLY at 282a0055 -- "
        "46 functions, 11 in the component, 903 lines, the same eleven names "
        "-- and reproduces two of its five co-change figures exactly (stmt, "
        "the accepted cut, 36%; float 1/4 = 25%). CAVEAT, recorded rather than "
        "hidden: it does NOT reproduce the call family's published 24% (5/21), "
        "reading it instead at 42% (8/19), which is ABOVE the bar trigger (b) "
        "names. A wider variant of the same method (counting every ast-tree "
        "function as 'else', not just the tracked set) reads call at 21% "
        "(4/19), close to the published figure, but then zeroes the accepted "
        "stmt cut -- so neither reconstruction is the original, and the "
        "original's absolute denominators (33, 21, 12, 4, 9) were not "
        "recovered. What BOTH reconstructions agree on is the thing this "
        "review was called to decide: the call family scored IDENTICALLY "
        "before and after the growth (42.1% -> 42.1% narrow, 21.1% -> 21.1% "
        "wide), so the new code created no locality there, and it fails the "
        "structural test independently -- 3 of its 11 members "
        "(write_call_dec, write_typed_call_arg_dec, write_call_arg_dec) are "
        "SCC members, so the cut slices the component and costs 6 outbound "
        "references to 4 parent items. NO CANDIDATE IMPROVED BECAUSE OF THE "
        "NEW CODE; the one that got a new scope got worse. Split this file "
        "when any of: (a) the strongly-connected component falls below 8 "
        "functions or 600 lines; (b) a candidate that is also ACYCLIC reaches "
        "the 33% the stmt cut scores under the method above -- the acyclicity "
        "clause is new, because the only candidate ever to clear the "
        "co-change bar is the one whose edge runs both ways; (c) the file "
        "reaches 2,300 LOC. FALSIFY THIS BY MEASURING, not by reading it. "
        "The 2026-08-18 review, whose structural findings all still hold, "
        "follows. Extracted 2026-08-16 "
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
        "contributes nothing to this file. [Its triggers were: (a) SCC below 8 "
        "functions or 600 lines; (b) any candidate's self-contained-commit "
        "share reaching 36%; (c) the file re-crossing 2,000 LOC. Trigger (c) "
        "fired on 11634706 and produced the 2026-08-19 re-review above, which "
        "supersedes these three.] A cut here buys a module boundary and no "
        "narrowing."
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
    "ir/const_fold.rs": (
        "SPLIT OWED (re-review 2026-09-24 at 1,938 LOC, blessed 1,421 at 3e82c79a; 42 "
        "commits, 29 origin preservation, 9 identity such as 99843238, 49a78f31, "
        "05a524e8). The old 'one constant-folding pass' entry was already wrong: the "
        "file holds the syntactic fold_constants AND two TypeMap-driven passes, "
        "fold_typed_comparison_extensions_with_identities and "
        "fold_typed_declared_views_with_identities (~420 lines), which the module "
        "header's 'purely syntactic, no dataflow info' does not describe. The typed "
        "pair is acyclic -- one outbound edge (common_extended_operand), no inbound "
        "from the rest of the file, external callers only widen.rs and "
        "python_bindings/ir/decbench_render.rs -- and scores 3/9 = 33% self-contained "
        "co-change since 3e82c79a. Seam: const_fold/typed.rs (parent ~1,520). The "
        "syntactic pass's own growth (fold_expr_at +~220) is origin-carrier unwrapping "
        "over the same operator set."
    ),
    "ir/loop_form.rs": (
        "accepted, re-reviewed 2026-09-24 at 1,455 LOC (blessed 1,259 at 3e82c79a): "
        "loop normalisation, one pass. 18 commits, 15 of them origin composition "
        "through the existing recognisers (e.g. fca387da, a4326607, eb414739), plus "
        "50cc926d (identity-proved for-loop stores) and 85a61693 (typed "
        "continuations). The growth is spread over existing recognisers "
        "(guarded_do_while_candidate +39, recover_guarded_do_while_body +32, "
        "sentinel_search_candidate +26, for_candidate +25) with two new small fns; no "
        "new loop shape, so no new reason to change."
    ),
    "ir/x87.rs": (
        "accepted (2026-08-15, dcc62aa): the x87 register stack must be "
        "resolved to a proven depth per function before ST(i) means anything, "
        "so the depth fixed point, the eight-slot lowering, and the "
        "control-word window matcher are one analysis, not three."
    ),
    "ir/dwarf_fields.rs": "accepted: DWARF field/member decoding for one producer surface.",
    "debug/dwarf.rs": (
        "accepted, re-reviewed 2026-09-24 at 1,563 (blessed at 1,362): DWARF "
        "section parsing; one input format, one owner. The +201 came from "
        "4b2a1ef8, 153852de and 0c6f1d5e -- function-local statics and "
        "breg-relative locals, variadic declaration preservation, inherited "
        "authoritative-declaration provenance -- all decoded through the same "
        "`extract_dwarf_functions` walk, so more attributes of one parse, not a "
        "second responsibility."
    ),
    "symbols/pdb.rs": (
        "accepted, re-reviewed 2026-09-24 at 1,379 (blessed at 1,180): PDB "
        "ingestion; one input format, one owner. The +199 is one commit, "
        "e4256781, the PDB-side twin of dwarf.rs's authoritative declaration "
        "provenance (`PdbFunctionPrototype`, `PePdbSource`, `PdbIngestor` and "
        "the `describe_declaration_type_name(s)` helpers)."
    ),
    "analysis/ioctl_taint.rs": "accepted: the Windows ioctl taint analysis, one pass.",
    "python_bindings/analysis.rs": (
        "accepted: thin PyO3 adapters; large by row count, not by depth. "
        "Shrinks with the analysis surface, not on its own."
    ),
    "triage/api.rs": "accepted: the triage entry surface; adapters over one pipeline.",
    "triage/config.rs": "accepted: triage configuration and its defaults/validation.",
    # -- symbolic-execution engine (out of decompiler scope, still in src/) --
    "symbolic/solver/bitwuzla_backend.rs": (
        "accepted: one FFI surface for one library. The bulk is the pinned "
        "libbitwuzla 0.9.1 C ABI -- extern declarations, the kind-constant "
        "block, and the term builders that use them -- and those cannot be "
        "separated without exporting raw enum values across a module boundary, "
        "which is the one thing the file argues against: it warns that a wrong "
        "kind value builds fine and silently constructs a different operator. "
        "It crossed 1,000 LOC when the shift-distance and divide-by-zero "
        "reduction was added so the solver denotes what src/exec/concrete.rs "
        "computes. Splitting was rejected on evidence rather than taste: "
        "libbitwuzla is not installed here, so this backend compiles but has "
        "never executed, and restructuring code no test on this machine can run "
        "trades a documented size for an undetectable regression."
    ),
    "symbolic/solver/mod.rs": (
        "SPLIT OWED (re-review 2026-09-24 at 2,264, blessed at 1,710; the "
        "earlier 'accepted: the solver facade and its shared query plumbing' "
        "no longer describes the file). The +554 across 165ff4ed, e207fed8, "
        "17ff0387, b1f420ab and 0d07b09d is dominated by the shadow-split "
        "disagreement corpus -- `maybe_dump_query` through "
        "`append_capture_index` plus the three `shadow_*_stats` readers, ~550 "
        "lines -- which writes an on-disk capture/index format for the "
        "differential comparison lane. That changes for a different reason "
        "(capture format, directory layout) than `solve`'s backend dispatch, "
        "budgets and engine cache. Seam: `symbolic/solver/shadow_capture.rs`."
    ),
    "symbolic/solver/axeyum_backend.rs": (
        "accepted (2026-09-24) at 1,004: the core Axeyum `Solver` "
        "implementations (native `AxeyumSolver`/`IncrementalAxeyumSolver` and "
        "the `AxeyumTextSolver` SMT-LIB2 path) plus the infeasible-path "
        "certificate types. Config, profiling, snapshot reuse, translation, "
        "warm paths and warm stats were already carved into six submodules at "
        "a4b2494e (3,357 -> 925); this residual is one backend, one owner. Four "
        "lines over the threshold: watch, do not split yet."
    ),
    "symbolic/solver/axeyum_backend/warm_paths.rs": (
        "accepted (2026-09-24) at 1,153: the retained per-path solver lineages "
        "(`LineageIncrementalAxeyumSolver`, `DirectDeltaLineageAxeyumSolver`) "
        "and the thread-local admission/closure that drives them, split out of "
        "axeyum_backend.rs at a4b2494e and grown by the runtime-foundation and "
        "canonical-cache work. Its module doc argues against a further cut: "
        "admission and closure reach eight private methods and a field that "
        "would have to widen to `pub(super)`."
    ),
    "symbolic/ordered_trace.rs": "accepted: the ordered trace format and its writer.",
    "symbolic/ordered_replay.rs": "accepted: ordered replay against a pinned configuration.",
    # -- 2026-09-24 catch-up review. tools/fitness_baseline.json was last
    # written at 3e82c79a (2026-09-02); 35 files crossed 1,000 LOC after it
    # with no entry, and this gate was red for them. Each was reviewed at its
    # current size. "SPLIT OWED" admits the file ONLY as a record that the
    # review found a separable seam, named in the entry; it is a work item,
    # not a licence, and the next re-review should find the cut made. --
    "runtime_analysis/instruction_trace.rs": (
        "SPLIT OWED (2026-09-24) at 7,396 LOC, the largest product file in the tree "
        "and more than three times the next. Introduced whole in 0c6f1d5e ('build "
        "hybrid runtime analysis foundation', 2026-09-17) with no review. It holds at "
        "least four relation engines, each with its own struct family and pub "
        "relate_*/analyze_* entry point and no shared state beyond "
        "ProcessCapsule/ProgramImage: block-level replay (ObservedBlock*, ReplaySeed*, "
        "BoundedBlockReplay, ReplayDivergence; ~2.2k), input taint/dataflow with "
        "branch counterfactuals (InputValueFlow*, InputDependentBranch, "
        "BranchCounterfactual; ~2.6k), store/load provenance (ExecutedStore*, "
        "locate_invocation_inputs; ~1.4k) and call/control-transfer semantics "
        "(InstructionCallRelation, SemanticCallContract, resolve_call_semantics; "
        "~2.2k). Seams: block_replay.rs, input_dataflow.rs, store_load_semantics.rs, "
        "call_control_semantics.rs."
    ),
    "runtime_analysis/correlation.rs": (
        "accepted (2026-09-24) at 1,985, introduced whole in 0c6f1d5e: one problem -- "
        "resolving a runtime address back into the static image -- at three layers "
        "(identity/mapping resolution ~170, page-provenance classification ~300, and "
        "the resolve_runtime_address/resolve_static_operations semantic-value engine "
        "~1.3k that instruction_trace, stack_objects and crash all call). The bulk "
        "enumerates IR Op variants to reconstruct operand semantics, the same reason a "
        "lifter is large; one owner, no independent report type."
    ),
    "runtime_analysis/behavior.rs": (
        "SPLIT OWED (2026-09-24) at 1,759, introduced whole in 0c6f1d5e: four "
        "independent OS-behaviour analyzers, each with its own report type, event "
        "vocabulary and normalize_* helpers and nothing shared beyond capsule "
        "iteration -- process (analyze_process_behavior, ~120), mapping/mprotect "
        "(~180), descriptor/socket (~480) and file (~590). A new fd operation does not "
        "touch file or process logic, so these are four reasons to change. Seams: "
        "process_behavior.rs, mapping_behavior.rs, descriptor_behavior.rs, "
        "file_behavior.rs."
    ),
    "runtime_analysis/stack_objects.rs": (
        "accepted (2026-09-24) at 1,539, introduced whole in 0c6f1d5e: one algorithm "
        "-- relate observed runtime writes to DWARF-declared stack objects -- behind "
        "one public entry point (analyze_stack_writes); derive_stack_address, "
        "evaluate_static_expression, the snapshot comparisons and "
        "relate_input_field_effects are private stages of that one pipeline. The size "
        "is the number of expression and snapshot cases, not bundled responsibilities."
    ),
    "runtime_analysis/corruption.rs": (
        "accepted (2026-09-24) at 1,294, introduced whole in 0c6f1d5e: one report type "
        "(ObjectChangeReport) from one entry point (analyze_object_changes); "
        "allocation prefix/tail transition detection, source-pointer attribution and "
        "snapshot comparison are private helpers classifying one object's byte changes "
        "over time. No second analyzer."
    ),
    "runtime_analysis/crash.rs": (
        "accepted (2026-09-24) at 1,131, introduced whole in 0c6f1d5e: one "
        "crash-report pipeline (analyze_crash, native-stack unwinding, "
        "classify_access/classify_crash) plus its two consumers compare_crashes and "
        "render_crash_analysis, all over the same CrashReport/CrashAnalysis types. "
        "render_crash_analysis (~120 lines of text formatting) is the first thing to "
        "move if it grows."
    ),
    "runtime_analysis/capsule.rs": (
        "accepted (2026-09-24) at 1,024, introduced whole in 0c6f1d5e: the versioned "
        "glaurung-process-capsule-v1 schema -- ProcessCapsule, ~30 nested record/enum "
        "types that exist only as its fields, JSON/CBOR (de)serialisation and one "
        "exhaustive validate(). One reason to change: schema evolution. A data model, "
        "not separable behaviour."
    ),
    "disasm/native_aarch64.rs": (
        "SPLIT OWED (2026-09-24) at 4,165, added whole in ac8f3fb2 (2026-09-08, "
        "'native AArch64 decoder foundation', the first slice of the Capstone "
        "replacement) with no review. One impl NativeAarch64Disassembler dispatching "
        "through ~176 private decode_*/word_is_* fns. The ~47 Advanced-SIMD-and-FP "
        "decoders (decode_advanced_simd_*, decode_scalar_fp_*, "
        "decode_simd_load_store_*, vector_*/scalar_fp_* helpers, ~1,700-1,900 lines) "
        "are the encoding class the ARM manual itself separates, and meet the "
        "general-purpose half at one dispatch site. Seam: a second impl block in "
        "disasm/native_aarch64/simd.rs, zero behaviour change."
    ),
    "flirt/mod.rs": (
        "SPLIT OWED (2026-09-24) at 1,701: grew 275 -> 1,701 in one day (2026-09-03: "
        "masking, CRC, gsig container, referenced-name matching, process-wide caching, "
        "VA mapping). archive.rs, crc16.rs and gsig/ are already out; mod.rs still "
        "mixes three owners -- the matcher core (FlirtSignature*, "
        "FlirtLibrary::match_at*, ~430), library loading and the process-wide cache "
        "(LIBRARY_CACHE, library_for, default_library_paths, packaged_sig_dir, ~340) "
        "and applying matches to a Function (apply_flirt_overrides*, "
        "FlirtReferenceSites, build_va_map, discover_flirt_seeds, ~470). Seams: "
        "flirt/library_cache.rs and flirt/apply.rs."
    ),
    "metrics/tree_distance.rs": (
        "accepted (2026-09-24) at 1,153, added whole in eaa62fda (2026-09-04): one "
        "Skeleton type, one extraction Builder (~400 lines of recursive descent over a "
        "Tree) and one Zhang-Shasha tree-edit distance over it -- one structural "
        "metric with one reason to exist. Touched since only by the cindergraph import "
        "rewrite (b4311b7c)."
    ),
    "metrics/byte_match.rs": (
        "accepted (2026-09-24) at 1,042, added whole in afb0d404 (2026-09-04): a "
        "deliberate line-for-line transcription of DecBench's "
        "decbench/metrics/byte_match.py, whose parity (quirks included) is the "
        "module's whole point. Disassembly/normalisation and the Myers diff both track "
        "that one upstream file, and nothing else in the crate would share the diff "
        "half."
    ),
    "python_bindings/ir/pipeline.rs": (
        "accepted (2026-09-24) at 1,968 (504 when cut out of python_bindings/ir.rs on "
        "2026-08-18): the one copy of the shared LLIR/AST stage order, so the four "
        "Python entry points cannot drift into different value models; "
        "PipelineStageTracker/AstPassOrder exist to enforce that order. Grown by ~35 "
        "'recover/preserve/identify by identity' commits (2026-09-08..24) that each "
        "added a sequential stage, not a second concern. Watch it: every new stage "
        "lands here."
    ),
    "python_bindings/ir/callee_contracts.rs": (
        "accepted (2026-09-24) at 1,475 (903 at 3e82c79a): the bounded "
        "callee/grandcallee analysis every Python decompilation entry point uses. The "
        "growth, most recently four 2026-09-12 commits adding indirect/table-call "
        "recovery, is layered on it: recover_table_entry_layouts calls "
        "recover_direct_callee_definition directly, so splitting table calls out would "
        "cut through that dependency."
    ),
    "python_bindings/source_metrics.rs": (
        "accepted (2026-09-24) at 1,139: a uniform PyO3 adapter over "
        "cindergraph::csource's analysis surface (metrics, CFG, feature vectors, data "
        "flow, control dependence, slicing, call summaries, reachability, path "
        "feasibility, findings), one #[pyfunction] per analysis under one rule -- "
        "plain dicts/lists out, never Python-shaped input. Same precedent as "
        "python_bindings/analysis.rs: it shrinks with the analysis surface, not on its "
        "own."
    ),
    "analysis/cfg/repair.rs": (
        "SPLIT OWED (2026-09-24) at 1,507. Its module doc says the parent calls "
        "'exactly those three' repairs (merge-split-chunks, DWARF overrides, landing "
        "pads); that is stale -- worklist.rs calls six, including "
        "apply_symbol_and_export_names and two CRT-startup main recognisers. Those "
        "came in ac4668c0 and efb45024 (2026-09-03), ~690 lines of per-architecture "
        "(i386/x86-64/Thumb/AArch64, ELF/PE) pattern matchers recovering main from "
        "_start/CRTStartup, with no calls into the block-surgery/landing-pad cluster. "
        "Seam: analysis/cfg/crt_main.rs, the same move dispatch.rs -> arm_tables.rs "
        "already made; fix the module doc with it."
    ),
    "analysis/dispatch.rs": (
        "SPLIT OWED (2026-09-24) at 1,425. It was cut to 997 on 2026-08-28 (ARM "
        "recognisers into dispatch/arm_tables.rs); the core DispatchTracker "
        "(get/set/bound_value/observe_instruction) is still one coupled "
        "abstract-interpretation state machine and one owner. What re-crossed is "
        "observe_aarch64_compact_table plus two private helpers (~290 lines, 310b949e, "
        "2026-09-05): AArch64-only, called from one site in observe_instruction -- the "
        "same shape already moved to arm_tables.rs. Seam: move it there."
    ),
    "ir/high_variables.rs": (
        "accepted (2026-09-24) at 1,450 (953 at 3e82c79a): one pub(crate) entry, "
        "refine_pointer_high_variables_with_identities, drives every refine_* rule "
        "(unsigned-constant, pointer-fact, object-cursor, authoritative-pointer) to "
        "one bounded fixed point over prepared AST values; no second caller. The "
        "growth is the 2026-09-08..13 identity migration making each existing rule "
        "fail closed against SSA identity instead of name matching; no rule was added."
    ),
    "ir/function_tables.rs": (
        "SPLIT OWED (2026-09-24) at 1,357 (881 at 3e82c79a): two lifecycles with "
        "different callers. collect_function_pointer_tables/tables_referenced_by (~350 "
        "lines, the relocation walk) run once per binary from pipeline.rs and are also "
        "read by callee_contracts.rs; resolve_function_table_entries[_with_identities] "
        "and its ~900-line AST dataflow run per function, and took all the growth "
        "('recover ARM table call arguments', 'resolve tables through promoted stack "
        "slots', 'recover affine table addresses'). Seam: function_tables/collect.rs "
        "for the per-binary half."
    ),
    "ir/guard_chain.rs": (
        "SPLIT OWED (2026-09-24) at 1,294: eight public recognisers -- ladder "
        "collapse, shared-assignment recovery, break-guard fusion, two return-guard "
        "families, contradiction pruning, redundant-copy pruning -- each with private "
        "helpers, invoked from eight separate points in ir/ast/prepare.rs rather than "
        "one driver, sharing only merge_statement_origin and negate_exact_condition. "
        "It accreted independent shapes (five 2026-07-31 commits) and then the 2026-09 "
        "identity/origin migration touched each separately. Seams by family: "
        "ladder+assignment (~450), return guards (~420), break/contradiction/copy "
        "pruning (~400)."
    ),
    "ir/x86_prologue.rs": (
        "accepted (2026-09-24) at 1,290 (886 at 3e82c79a): recognise_x86_prologue, "
        "recognise_cdecl32_call_alignment and drop_implicit_main_runtime_call are "
        "called together from one site, pipeline.rs's recognise_machine_frame, as the "
        "x86 branch of the per-architecture dispatch beside "
        "arm32_prologue/arm64_prologue. Growth is the 2026-09-07..13 identity "
        "hardening of the existing recognisers; no new shape."
    ),
    "ir/dead_stores.rs": (
        "SPLIT OWED (2026-09-24) at 1,275 (701 at 3e82c79a, +82%): public passes with "
        "no shared driver -- eliminate_dead_stores (pipeline.rs identity-space "
        "cleanup), drop_globally_unused_call_results (ast/prepare.rs), "
        "prune_callee_saved_spills_nested (recognise_machine_frame) and "
        "prune_unobserved_promoted_object_stores (decbench_render.rs only) -- sharing "
        "a ~150-line read-detection kernel (expr_reads, contains_nested_read/exit, "
        "stmt_reads_direct). Grown by the 2026-09-08..13 identity migration applied to "
        "each pass separately. Seams: a shared reads kernel, plus elimination / "
        "callee-saved-spill pruning / promoted-object pruning."
    ),
    "ir/direct_output.rs": (
        "SPLIT OWED (2026-09-24) at 1,058, crossed by the float-result repair "
        "(8251b6f3: a float-typed prototype no longer takes its result from the "
        "integer bank). The return-materialisation core (materialize_*, "
        "find_written_*_reg, apply_default_return) is one owner. Two cleanup passes "
        "that only share its return-register predicates also live here: "
        "prune_unread_promoted_locals* (~270 lines) and "
        "prune_void_entry_result_restores* (~190). Seam: move those two into their "
        "own module beside dead_stores.rs."
    ),
    "ir/verify_defs.rs": (
        "accepted (2026-09-24) at 1,273 (839 at 3e82c79a): one verifier with two rules "
        "(NeverDefined, flow-sensitive UsedBeforeDefinition) run from one driver, "
        "check_where, over one AST. Grown by extending the same two rules to exception "
        "regions, nested frame addresses, stack stores, renderer-owned locals and "
        "goto-aware CFG (2026-09-04..13), not by a third rule."
    ),
    "ir/switch_ladder.rs": (
        "accepted (2026-09-24) at 1,252 (929 at 3e82c79a): one algorithm -- match a "
        "binary-search comparison tree over one discriminant and rewrite it to "
        "Stmt::Switch -- applied idempotently twice in ast/prepare.rs and once from "
        "decbench_render.rs. Growth is more of the same shape (nested GCC state "
        "switches, final join breaks, origin preservation, 2026-09-04..07)."
    ),
    "ir/lift_x86/packed.rs": (
        "accepted (2026-09-24) at 1,212 (846 when cut out of lift_x86.rs on "
        "2026-08-17): the landed x86 packed/SSE family destination -- one pub(super) "
        "fn per mnemonic, dispatched from lift_x86.rs, no cross-function state. Grown "
        "only by adding mnemonics to the same flat family (SSE string ops, VEX 256-bit "
        "AND and byte-broadcast, SysV homogeneous float returns). If it keeps growing, "
        "split by SSE vs VEX encoding, not by accident of arrival."
    ),
    "ir/ssa.rs": (
        "accepted (2026-09-24) at 1,057 (860 at 3e82c79a): Cooper-Harvey-Kennedy "
        "dominators, frontiers, phi placement and renaming over one LlirFunction into "
        "one SsaInfo side-car -- one algorithm, one entry "
        "(compute_ssa/compute_ssa_for_target). The growth is SSA owning its opaque "
        "value identities (2026-09-08..12)."
    ),
    "ir/call_result_split.rs": (
        "accepted (2026-09-24) at 1,041 (852 at 3e82c79a): one Splitter state machine "
        "with one public entry (split_call_result_lifetimes[_with_identities]) walking "
        "a body once to version ABI call-result banks; its ~30 methods are private "
        "steps of that walk. Growth is re-keying the same splitter on storage identity "
        "(2026-09-08..12)."
    ),
    "ir/stack_locals/rewrite.rs": (
        "accepted (2026-09-24) at 1,024 (920 at 3e82c79a): the mutating half of the "
        "stack_locals split (7410e00d, 2026-08-17) -- rewrite_body/rewrite_expr fold a "
        "frame access into Reg(local), and reconcile_late_address_taken_objects "
        "repairs slots proven address-taken later. The sibling decides what a slot IS; "
        "this file decides what a statement BECOMES."
    ),
    "ir/call_args/fold_one_call.rs": (
        "accepted (2026-09-24) at 1,126 (700 at 3e82c79a): the landed cut the "
        "ir/call_args.rs entry describes -- one pub(super) fn fold_one_call, a single "
        "backward scan over the statements before one call that dispatches into the "
        "per-convention siblings; the seven fns after it are its leaves. Growth is "
        "identity-hardening proof obligations added to that one scan (2026-09-08..13)."
    ),
    "ir/ast/lower_region.rs": (
        "accepted (2026-09-24) at 1,261 (926 at 3e82c79a; 17 commits): the LLIR->AST "
        "region walk; lower_region and lower_region_inner are mutually recursive (499 "
        "of 1,113 fn lines). Growth is raw-shape fallbacks (lower_raw_loop_block 43 -> "
        "154, the 2026-09-05 raw switch/loop series c9483542..1ce1a80b), which "
        "co-changed with lower_region_inner in 7 of 7 commits, and multi-exit transfer "
        "materialisation (0da8744d, c3bbe2a6, 9c848ac9). The only acyclic candidate, "
        "materialize_multi_exit_transfers(_inner) (142 lines), scores 1/5 = 20% "
        "self-contained co-change, below the 33% bar. Re-review at 33% or 1,400 LOC."
    ),
    "ir/ast/lower_conds.rs": (
        "accepted (2026-09-24) at 1,035 (982 at 3e82c79a): condition code motion and "
        "the conservative safety predicates that gate it, as the module header states. "
        "The fn set is unchanged (14 -> 14); +53 lines of origin preservation through "
        "negation and hoisting (1b915c0d, a50e583f, d8e6c351) and 003e4fc1's "
        "stack-identity hoist proofs. No call-graph cycle; separating the predicates "
        "from their two consumers would recreate the 2026-08-18 shadow-copy hazard the "
        "header records."
    ),
    "ir/ast/decbench_render.rs": (
        "SPLIT OWED (2026-09-24) at 1,093 (697 at 3e82c79a; 16 commits incl. 38f3f6cc, "
        "5cbb36bd/973d1931, fea34010, e4b370c2, c27bb0a2, c4c56e51). 776 lines -- 71% "
        "of the file -- are one function, render_decbench_..._and_identities, which "
        "installs the render-scoped DEC_* cells, decides the signature (arity, "
        "conventional main, prototype acceptance, parameter names) and emits. The "
        "module header is stale (says six entry points; there are eight). Seams: "
        "inline_scalar_declarations + statement_writes_register (128 lines, "
        "declaration planning) into declaration_plan.rs (~965), then the ~95-line "
        "signature step out of the 776-line function."
    ),
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


#: How far a reviewed file may drift past the size it was last blessed at
#: before its review must be redone. Absolute, not proportional: the question
#: "does this review still describe this file?" does not get easier because the
#: file was already large, and a percentage would hand the biggest files the
#: most headroom -- exactly backwards.
REVIEW_DRIFT_LOC = 150


def test_no_review_licence_outlives_the_file_it_was_written_for():
    """A "no further split" verdict is a licence, and licences must expire.

    `test_no_review_entry_outlives_the_file_it_reviewed` already deletes an
    entry when its file drops BELOW 1,000 LOC. Nothing checked the other
    direction, so an entry written about a 1,788-line file kept authorising a
    2,013-line one -- 225 lines it had never examined, added by four commits in
    a single day, while `check_ratchet` printed "no regressions" because
    `product_loc_above_1000` is a SUM with thousands of lines of slack.

    The baseline's `oversized_files` map is the record of the last size anyone
    deliberately blessed: regenerating it is an explicit act, so a file that has
    grown well past its recorded size has grown since the last time a human
    looked. That is precisely when a "no further split" argument -- built on a
    specific call graph, a specific strongly-connected component, specific
    co-change numbers -- stops being evidence about the file in front of you.

    Fixing this means EITHER splitting the file OR re-reviewing it and
    refreshing the baseline. Both are real work; neither is editing a number.
    """
    baseline = json.loads((ROOT / "tools" / "fitness_baseline.json").read_text())
    blessed = fr._owner_sizes(baseline)
    measured = large_product_modules(SRC)
    overgrown = {
        path: (blessed[path], loc)
        for path, loc in sorted(measured.items())
        if path in REVIEWED_LARGE_MODULES
        and path in blessed
        and loc - blessed[path] > REVIEW_DRIFT_LOC
    }
    assert not overgrown, (
        "review entries now authorising files they never examined "
        f"(grown more than {REVIEW_DRIFT_LOC} LOC past their last blessed "
        "size):\n"
        + "\n".join(
            f"  {path}: reviewed at {was} LOC, now {now} (+{now - was})"
            for path, (was, now) in overgrown.items()
        )
        + "\n\nSplit the file, or redo the review and regenerate "
        "tools/fitness_baseline.json so the new size is on the record."
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
