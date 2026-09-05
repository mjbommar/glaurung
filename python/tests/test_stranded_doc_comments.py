"""A doc comment stranded on the wrong item.

The refactor program has produced this defect five known times, every one of
them found by hand, every one of them the same mechanism: a cut (or an insert)
put a new item between an existing `///` block and the item that block
described, so rustdoc now renders one item's summary as another's -- and the
item that lost its doc is usually the important one.

    * `analysis/cfg.rs`      -- `merge_dispatch_addresses` opened with
      "Discover a single function starting at `entry`...", so `discover_function`,
      the entry point of the whole CFG walk, had no doc for months (43b0dd23).
    * `ir/lift_x86.rs:603`   -- a `/// Lift a single iced instruction...` line
      left on `synchronise_xmm_views`.
    * `ir/lift_arm32/flags.rs` -- `flags_for_arith` carried `cmp_flag_ops`'
      summary, which was ALSO stale (43b0dd23).
    * `ir/structure.rs`      -- two paragraphs fused into one `///` run on
      `invert_for`, so `detect_if_shape` -- 353 lines -- had no doc (b5da6e7a).
    * `ir/copy_prop.rs`      -- `is_deferable_promoted_value` opened with a note
      about how a promoted stack slot is *represented* (43b0dd23).

THE RULE, in two parts, both cheap and both text-only:

1. A *fused boundary*: inside one `///` run attached to an item, a line whose
   sentence ends exactly at the line break is immediately followed by a line
   starting a new sentence, with no blank `///` between them. That is the
   mechanical signature of "a line was inserted above an existing doc" and of
   "two docs were glued when the separator was lost". It fires on all five
   instances above.
2. The doc's *first sentence shares no word with the item's own name* (loose
   prefix matching, so `flag`/`flags` and `address`/`addressing` count as
   shared). A summary that is about its item almost always says the item's
   name; a stranded summary is about something else.

MEASURED, over the whole of `src/` at 467649f7 (3,469 doc blocks on items):

    part 1 alone                 174 hits  -- unusable, ~1% precision
    part 1 AND part 2             33 hits  -- 10 genuine, 23 benign (30%)

So the rule DOES NOT gate on its raw verdict: a 70% false-positive rate would
fail the build on ordinary two-sentence summaries. It gates on *new* suspects,
against the reviewed allowlist below -- the same shape as
`REVIEWED_LARGE_MODULES` in `test_large_module_review.py`. Adding an entry is
cheap and explicit; letting a strand land silently is what actually happened
five times.

Part 2 is what makes the list reviewable, and it is also why recall is not 5/5:
`flags_for_arith` (the word "flag" appears in the stranded summary) and
`is_deferable_promoted_value` ("promoted", "value") are missed. The brief's
originally proposed rule -- compare the first sentence's *backticked
identifier* against the item name -- was measured too: it catches none of the
five, because the backticked tokens in those summaries are parameter names
(`entry`, `cond`) and assembly fragments (`cmp a, b`), not item names.

Pure source-text checks over the checked-out `src/`, matching the convention of
`test_src_dependency_boundaries.py` and `test_large_module_review.py`. No build
required.
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


# --- source scanning ---------------------------------------------------------

_CFG_TEST_ATTR_RE = re.compile(r"^\s*#\[cfg\((?P<pred>.*)\)\]\s*$")
_DOC_RE = re.compile(r"^\s*///(?!/)(.*)$")
_ATTR_RE = re.compile(r"^\s*#\[")
_ITEM_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r'(?:extern\s+"[^"]*"\s+)?'
    r"(fn|struct|enum|trait|type|const|static|mod|union|impl|macro_rules!)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)


def _product_lines(text: str) -> list[str]:
    """`text` with every `#[cfg(test)]` item removed, mirroring
    `fitness_report.strip_test_items` -- a doc inside a test module is not
    product documentation and cannot mislead a reader of the rendered docs."""
    lines = text.splitlines()
    kept: list[str] = []
    index = 0
    count = len(lines)
    while index < count:
        attribute = _CFG_TEST_ATTR_RE.match(lines[index])
        if not attribute or not fr._is_test_predicate(attribute.group("pred")):
            kept.append(lines[index])
            index += 1
            continue
        index += 1
        depth = 0
        seen_brace = False
        while index < count:
            line = lines[index]
            depth += line.count("{") - line.count("}")
            if "{" in line:
                seen_brace = True
            index += 1
            if seen_brace and depth <= 0:
                break
            if not seen_brace and line.rstrip().endswith(";"):
                break
    return kept


def doc_blocks(text: str):
    """Yield `(doc_lines, item_kind, item_name)` for every `///` run that sits
    directly on a named item (attributes in between are allowed, blank lines
    are not -- a blank line detaches the doc, which rustdoc rejects anyway)."""
    lines = _product_lines(text)
    index = 0
    count = len(lines)
    while index < count:
        if not _DOC_RE.match(lines[index]):
            index += 1
            continue
        docs: list[str] = []
        while index < count:
            match = _DOC_RE.match(lines[index])
            if not match:
                break
            docs.append(match.group(1).strip())
            index += 1
        after = index
        while after < count and _ATTR_RE.match(lines[after]):
            depth = lines[after].count("(") - lines[after].count(")")
            after += 1
            while after < count and depth > 0:
                depth += lines[after].count("(") - lines[after].count(")")
                after += 1
        if after < count:
            item = _ITEM_RE.match(lines[after])
            if item:
                yield docs, item.group(1), item.group(2)


# --- part 1: the fused boundary ----------------------------------------------

_LIST_RE = re.compile(r"^\s*(?:[-*+>]\s|\d+[.)]\s|\|)")
_SENTENCE_END_RE = re.compile(r"[.!?][\"'`)\]]*$")
_NEW_SENTENCE_RE = re.compile(r"^[A-Z]")
# `e.g.`/`i.e.`/`Fig.`/`2.` end a line without ending a sentence.
_ABBREVIATION_RE = re.compile(
    r"(?:\b(?:e\.g|i\.e|etc|vs|cf|approx|resp|Fig|no|No|al|st|nd|rd|th)\.|"
    r"\b[A-Za-z0-9]\.)$"
)


def has_fused_boundary(docs: list[str]) -> bool:
    """Whether two sentences meet at a line break with no blank `///` between.

    Code fences, list items and headings are skipped: a bulleted list is
    supposed to break at every line, and a fenced block is not prose.
    """
    in_fence = False
    for first, second in zip(docs, docs[1:]):
        if first.startswith("```"):
            in_fence = not in_fence
        if in_fence or not first or not second:
            continue
        if _LIST_RE.match(first) or _LIST_RE.match(second):
            continue
        if first.startswith("#") or second.startswith("#"):
            continue
        if not _SENTENCE_END_RE.search(first) or _ABBREVIATION_RE.search(first):
            continue
        if _NEW_SENTENCE_RE.match(second):
            return True
    return False


# --- part 2: does the summary name its own item? -----------------------------

_STOPWORDS = frozenset(
    """is to for in of on the and or by from with as an a py fn new get set into
    one all any not no self this that it its we our be are was were when then
    than so if else do does can may must will which what has have had but out up
    down over under per run use used uses each every only also here""".split()
)
_WORD_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")


def _identifier_words(name: str) -> list[str]:
    words: list[str] = []
    for chunk in name.split("_"):
        words.extend(re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", chunk))
    return [word.lower() for word in words if _is_content(word)]


def _is_content(word: str) -> bool:
    return len(word) > 2 and word.lower() not in _STOPWORDS


def _related(one: str, other: str) -> bool:
    """Loose morphological relation: equal, or one a prefix of the other with at
    least four shared leading characters (`flag`/`flags`, `address`/`addressing`,
    `decompile`/`decompiler`). Deliberately generous -- every extra match
    REMOVES a suspect, so the loose end costs recall, never a false failure."""
    if one == other:
        return True
    shorter, longer = sorted((one, other), key=len)
    return len(shorter) >= 4 and longer.startswith(shorter)


def first_sentence(docs: list[str]) -> str:
    paragraph: list[str] = []
    for line in docs:
        if not line:
            break
        paragraph.append(line)
    joined = " ".join(paragraph)
    return _SENTENCE_SPLIT_RE.split(joined)[0] if joined else ""


def summary_names_its_item(name: str, summary: str) -> bool:
    words = [word.lower() for word in _WORD_RE.findall(summary) if _is_content(word)]
    return any(
        _related(part, word) for part in _identifier_words(name) for word in words
    )


# --- the check ----------------------------------------------------------------


def suspects() -> dict[str, str]:
    """`"path::item"` -> the first sentence, for every doc block whose summary
    both breaks mid-run and says nothing about the item it sits on."""
    found: dict[str, str] = {}
    for path in sorted(SRC.rglob("*.rs")):
        relative = path.relative_to(SRC)
        if fr.is_test_path(relative):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for docs, _kind, name in doc_blocks(text):
            if not has_fused_boundary(docs):
                continue
            summary = first_sentence(docs)
            if summary_names_its_item(name, summary):
                continue
            found[f"{relative.as_posix()}::{name}"] = summary
    return found


# Reviewed and found benign: in each of these the summary really is about the
# item, it just runs into a second sentence without a blank `///` between --
# ordinary prose, not a strand. Keyed by item rather than line so a nearby edit
# does not silently invalidate the review.
REVIEWED_DOC_SUMMARIES: dict[str, str] = {
    "analysis/cfg/must_dataflow.rs::bound_fixed_point": "the fixed point IS the loop-carried range proof",
    "analysis/dispatch/memory_guard.rs::MemKey": "'the effective-address expression that identifies a location' IS the key (MemKey tokenises as mem+key, and the summary says 'memory')",
    "analysis/linux_symbolic_frontend.rs::is_unmodeled_control_flow": "'unknown branch or trap' is the unmodeled control flow",
    "csource/joern/nodes.rs::Work": "'the S2 graph in a form the rewrite phases can edit in place' is the Work graph -- an editable mirror of Cfg, named for the phase that owns it",
    "ir/dwarf_type_env.rs::render_named_declaration": "'attach an identifier to a plain C type using conventional pointer spacing' is the named declaration it renders",
    "python_bindings/ir/dwarf_contracts.rs::debug_output_contracts": "'merge compiler declarations with deterministic authority ordering' is what producing the debug-output contracts means",
    "ir/const_fold.rs::rewrite": "'overwrite `slot` and record that this pass changed the AST' is the rewrite",
    "ir/copy_prop/reads.rs::bump": "'add one read of `r` to the histogram' is the bump",
    "ir/ast.rs::is_high_variable": "'source-value identity from an SSA-versioned register' is what a varN is",
    "ir/ast.rs::DEC_GLOBAL_ADDRS": "'original-image VAs that denote writable static storage' is the table",
    "ir/call_args/aapcs.rs::known_arm_hard_float_layout": "'AAPCS-VFP storage selected by a locked prototype' is the layout",
    "program/format_environment.rs::FormatIndex": "'the views of `address_names` this module actually consults, built once' is the index",
    "ir/high_variables.rs::collect_unsafe_pointer_uses": "'mark names below incompatible operations' is the collection",
    "ir/indirect_targets.rs::resolve_indirect_jumps": "'destination of every computed transfer' is the indirect jump",
    "ir/lift_arm32.rs::resolve_pc": "'substitute a read of pc' is the resolution",
    "ir/lift_x86/packed_string.rs::packed_insert_ops": "PINSRW/PINSRD/PINSRQ are the packed inserts",
    "ir/lift_x86/scalar_float.rs::scalar_float_compare_ops": "the ZF/CF/PF effect of ucomiss IS the compare lowering",
    "ir/memory_objects/mir.rs::address_memop": "'one memory operand and its role' is the memop",
    "ir/soft_helpers.rs::DIVMOD_TEMP": "'scratch lane for the quotient' is the temp",
    "ir/ssa.rs::ARM32_AMBIGUOUS": "'names AArch64 and ARM32 spell alike' is the ambiguity (ARM32 tokenises as arm+32)",
    "ir/structure/switch_shape.rs::find_switch_join": "'block reached from the greatest number of arms' is the join",
    "ir/value_number/tagging.rs::tag_op": "'apply the def and use versions to one op' is the tagging",
    "ir/value_number/coalesce.rs::coalescing_definition_claims": "'width constraints that must survive coalescing' is the claim",
    "ir/value_number/coalesce.rs::MAX_COALESCE_CANDIDATES": "'past this many phi-copy operands' is the maximum",
    "program/references.rs::admits": "'whether evidence may promote a value' is what admits decides",
    "program/session.rs::ProgramSession": "'one immutable image plus analysis artifacts' is the session",
    "program/session.rs::clear_caches": "'drop budget-dependent artifacts' is the clearing",
    "symbolic/explore/query.rs::arg_reg": "'the MS x64 integer argument register' is the arg reg",
    "symbolic/solver/z3_backend.rs::CTX": "'one z3 context per thread' is the CTX",
}


def test_no_doc_summary_is_stranded_on_the_wrong_item():
    unexpected = {
        key: summary
        for key, summary in suspects().items()
        if key not in REVIEWED_DOC_SUMMARIES
    }
    assert not unexpected, (
        "doc summary may belong to a different item than the one it sits on "
        "(a `///` run that breaks mid-sentence-run and never names its item):\n"
        + "\n".join(f"  {key}\n      {summary}" for key, summary in unexpected.items())
        + "\n\nMove the stranded paragraph down to the item it describes, or -- if "
        "the summary really is about this item -- add it to "
        "REVIEWED_DOC_SUMMARIES with a one-line reason."
    )


def test_no_review_entry_outlives_the_doc_it_reviewed():
    """A reviewed entry whose doc was since fixed (or whose item was renamed)
    must be deleted, or the allowlist silently grows into a place where a real
    strand can hide."""
    live = suspects()
    stale = sorted(key for key in REVIEWED_DOC_SUMMARIES if key not in live)
    assert not stale, (
        "REVIEWED_DOC_SUMMARIES entries no longer match any doc block; delete "
        f"them: {stale}"
    )


# --- the rule, checked against the instances that motivated it ----------------

# Verbatim from 43b0dd23^ and b5da6e7a^ -- the real defects, not invented ones.
HISTORICAL_STRANDS = {
    "analysis/cfg.rs::merge_dispatch_addresses": (
        [
            "Discover a single function starting at `entry` within executable regions.",
            "Merge one predecessor's concrete address facts into a block input.",
            "",
            "The first predecessor establishes the candidate map; later predecessors can",
            "only narrow it.",
        ],
        "merge_dispatch_addresses",
    ),
    "ir/structure.rs::invert_for": (
        [
            "Recognise an if-then / if-then-else diamond rooted at `cond`.",
            "",
            "Returns `Some((region, after))` when we can structurally absorb the whole",
            "conditional and continue at `after` (the join block, or None if one of",
            "the arms exits outright).",
            "Whether the lowered condition at block `cond` must be negated when",
            "`then_entry` is used as the `then` arm.",
        ],
        "invert_for",
    ),
    "ir/lift_x86.rs::synchronise_xmm_views": (
        [
            "Lift a single iced instruction into zero or more LLIR ops.",
            "Keep an XMM register's two representations in step.",
            "",
            "This LLIR gives an XMM register two names.",
        ],
        "synchronise_xmm_views",
    ),
}


def test_the_rule_fires_on_the_historical_instances():
    for key, (docs, name) in HISTORICAL_STRANDS.items():
        assert has_fused_boundary(docs), f"{key}: no fused boundary found"
        assert not summary_names_its_item(name, first_sentence(docs)), (
            f"{key}: first sentence unexpectedly names `{name}`"
        )


def test_the_rule_does_not_fire_on_an_ordinary_summary():
    docs = [
        "Merge one predecessor's concrete address facts into a block input.",
        "",
        "The first predecessor establishes the candidate map; later predecessors",
        "can only narrow it.",
    ]
    assert not has_fused_boundary(docs)
    assert summary_names_its_item("merge_dispatch_addresses", first_sentence(docs))


def test_a_two_sentence_summary_still_needs_the_name_check():
    """Part 1 on its own is not a defect signal: an ordinary hand-wrapped
    paragraph whose sentence happens to end at the line break trips it, which is
    why part 2 exists and why 174 fused boundaries reduce to 33 suspects."""
    docs = [
        "Build a best-effort map of GOT entry addresses (r_offset) to symbol names.",
        "Supports ELF64 RELA and ELF32 REL formats. Returns empty on failure.",
    ]
    assert has_fused_boundary(docs)
    assert summary_names_its_item("elf_got_map", first_sentence(docs))
