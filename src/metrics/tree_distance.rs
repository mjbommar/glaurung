//! Control-skeleton tree edit distance --- the one structural metric
//! `docs/design/metrics-research/structural-metrics.md` section 2.6
//! recommends.
//!
//! # Why a tree, when a graph is already here
//!
//! [`crate::syntax::ged`] reimplements the distance DecBench scores, and
//! `docs/design/metrics-research/what-ged-measures.md` measures what it can
//! see. Two of those measurements are the whole reason this module exists:
//!
//! * **24,243 of 89,014 scorable functions have a one-node CFG** --- one node,
//!   no edges, flagged entry *and* exit. Inside that single class live 7,393
//!   distinct statement bodies whose statement counts run from 3 to 618. Every
//!   CFG-derived metric assigns all of them the same value *by construction*,
//!   which is why a "decompiler" emitting `int f(void) { return 0; }` for
//!   every function scores 27.24% GED-perfect.
//! * **A `while` loop and its goto-ified equivalent have the same CFG.** The
//!   same nodes, the same edges, the same degree multiset. Structuring --- the
//!   thing decompiler work is actually judged on --- is invisible to every
//!   metric computed from the control-flow graph alone.
//!
//! A tree over the *recovered control structure* is the only structural
//! candidate that is not saturated by the dominant class and the only one that
//! can see structuring at all. The alternatives were rejected on measured
//! grounds and are not reopened here: 1-WL colour refinement produces 8,034
//! classes on this corpus and VF2 inside every bucket produces the same 8,034,
//! so a graph kernel adds exactly nothing over the isomorphism check that
//! already exists (`structural-metrics.md` section 2.2).
//!
//! # The projection, and why each choice is defensible rather than convenient
//!
//! The failure mode of a tree metric is to run it over the full AST, where it
//! becomes a measure of expression shape and moves when a decompiler renames a
//! variable. So the tree here is a *projection* onto a fixed, small alphabet
//! ([`SkeletonKind`], 17 members), and every rule below is a decision about
//! what counts as the same program. The set of rules is versioned as
//! [`SKELETON_VERSION`], because changing one changes every number the metric
//! has ever produced.
//!
//! ## Kept
//!
//! * **Every control construct, by kind.** `if`/`then`/`else`, `while`,
//!   `do`-`while`, `switch`, `case`, `default`, `break`, `continue`, `goto`, a
//!   label, `return`. These are what a decompiler *decides*: two outputs that
//!   differ here differ in the recovered structure, which is the measurand.
//! * **Statement count, and a three-way statement kind** --- `Call`, `Assign`,
//!   `Expr`, and nothing else. This is what splits the single-node class:
//!   zlib `adler32` (one statement) and cleanflight `pgResetFn_osdConfig` (618)
//!   are the *same* CFG and different trees. The kind distinction is one level
//!   deep --- the outermost form of the statement's expression --- so it costs
//!   no expression traversal and cannot see an operator, a name or a literal.
//!
//! ## Dropped
//!
//! * **Every expression's interior.** No identifiers, no literals, no types,
//!   no operators. That is what makes the metric insensitive to renaming, and
//!   --- honestly --- it is also what makes it unable to *detect* a flipped
//!   comparison or a bumped constant. `what-ged-measures.md` section 5 measured
//!   that ceiling: of 795 applied mutations, the six semantics-only classes
//!   (relational-flip, equality-flip, logic-flip, arith-flip, constant-bump,
//!   negate-condition) change no control-flow graph and, by construction,
//!   change no control skeleton either. This metric does not close that gap and
//!   will not close it by getting better.
//! * **Loop and branch conditions**, for the same reason: a condition is an
//!   expression. See "the false positive we take" below.
//! * **Declarations with no initializer.** `REQ-CFG-3` already decided a
//!   declaration is a node only when it initializes something, and the reason
//!   here is stronger than consistency: decompilers hoist every local to the
//!   top of the function while C99 source declares inline, so counting bare
//!   declarations would charge every decompiler a systematic penalty that has
//!   nothing to do with structuring. Measured over the published `source_code`
//!   samples and every decompiler column beside them, source functions carry
//!   0.024 bare declarations per skeleton node and decompiled functions carry
//!   0.098 --- a 4.1x asymmetry that is pure declaration style. See
//!   `the_published_samples_are_the_corpus_this_metric_was_argued_from`, which
//!   prints the ratio it was measured from.
//!
//! ## Canonicalized
//!
//! * `for (a; b; c) S` becomes `a; while { S; c; }`. A decompiler choosing
//!   `while` over `for` is not wrong, and every real one does.
//! * **`else if` flattens.** An `n`-armed chain is one [`SkeletonKind::If`]
//!   with `n` [`SkeletonKind::Then`] children and at most one
//!   [`SkeletonKind::Else`], not `n-1` nested `If`s. Nested, an extra arm costs
//!   three nodes; flat it costs one, and scoring chain length quadratically is
//!   scoring it twice.
//! * **A bare block splices.** `{ a; b; }` in statement position contributes
//!   its statements and no node of its own. A redundant scope is punctuation,
//!   and a decompiler that adds or drops one has changed nothing.
//! * `Error` and `asm` become [`SkeletonKind::Expr`], matching `REQ-CFG-11`:
//!   an unparsed region keeps its node, so a parse gap costs fidelity but not
//!   a statement count.
//!
//! ## Explicitly *not* canonicalized, and the false positives we take
//!
//! * `if (!c) A else B` versus `if (c) B else A`. They are the same program.
//!   Treating them as the same requires reading the condition, which
//!   reintroduces exactly the expression sensitivity the projection exists to
//!   remove. Take the false positive.
//! * `if (a && b) X` versus `if (a) if (b) X`. Because conditions are dropped,
//!   the second is one `If` larger. This one cuts the other way from the first:
//!   the unfolded form *is* worse decompiler output, so charging for it is
//!   arguably the metric working. It is listed here rather than defended
//!   because the honest position is that the choice was made to avoid walking
//!   expressions, and the scoring consequence is a side effect of that.
//! * `while` versus `do`-`while`. Kept apart deliberately: a pre-tested loop
//!   turned post-tested runs the body when it should not, and
//!   `tests/decompiler_fixtures/src/03_loop_shapes.c` exists to catch exactly
//!   that.
//!
//! # The distance
//!
//! [`tree_edit_distance`] is Zhang--Shasha over ordered trees with unit
//! insert, delete and relabel costs. Order comes from source order, which is
//! canonical, so there is no tie-break and no order to choose. Complexity is
//! the classical `O(n1 * n2 * min(d1, l1) * min(d2, l2))`, where `d` is depth
//! and `l` is leaf count. Note that the *keyroot count* is the leaf count, not
//! the depth --- on the 285 published sample sources the keyroot count runs to
//! 2,355 for a 2,367-node skeleton --- and it is the collapsed factor
//! `min(depth, leaves)` that is small: measured depth is 4 at the median, 8 at
//! p90 and 14 at the maximum. So the real cost is roughly `n1 * n2 * 16` to
//! `n1 * n2 * 200`, and it is the `n1 * n2` that bounds a big pair.
//!
//! APTED would improve the worst case and was not built. Its advantage is on
//! trees whose optimal decomposition strategy is neither left-heavy nor
//! right-heavy, and the price is a substantially larger implementation with a
//! strategy-computation phase of its own. For trees four deep at the median
//! that is the wrong trade for a metric whose whole value is that a reviewer
//! can check it.
//!
//! **Determinism is total.** Every quantity is a `u32`, every loop is over a
//! `Vec` in index order, and there is no map, no float and no tie-break
//! anywhere in the distance. Two runs over the same two skeletons produce the
//! same integer on any machine. The only `f64` in the module is
//! [`skeleton_score`], which exists because a score is reported as a ratio.
//!
//! # What it buys, measured
//!
//! Everything here was computed from the materialized DecBench tree at
//! `~/.cache/glaurung/decbench-full` --- the 300 `samples` records, each
//! carrying one benchmark function's real source and every decompiler's output
//! for it. **No DecBench pipeline and no Joern process was run**; the numbers
//! come from a published JSON file and Glaurung's own C front end.
//! `the_published_samples_are_the_corpus_this_metric_was_argued_from` is the
//! test that prints them, and the command is in its docs.
//!
//! * **The single-node class is split.** 80 of the 285 resolvable sample
//!   sources (28.07%) are branchless --- which reproduces the corpus-wide
//!   27.24% from a different population --- and every pair of them is one and
//!   the same CFG, scored `0.0` by GED. They hold **34 distinct skeletons**,
//!   and 92.28% of the 3,160 pairs are at non-zero tree distance, median 3,
//!   maximum 98 (`base-passwd` `usage`, 2 nodes, against `chibios`
//!   `rt_test_001_003_execute`, 99).
//! * **The null decompiler stops being a good decompiler.** `int f(void) {
//!   return 0; }` is GED-perfect on 27.24% of the corpus. Against the same
//!   sample sources it scores a mean of **0.2178** here and is exactly right on
//!   **6.09%** --- a 4.5x drop in the false-perfect rate, and the number to
//!   publish beside any aggregate of this metric.
//! * **Goto-ification is visible, and the CFG's blindness is not an
//!   exaggeration.** `tests/decbench_corpus/src/loops.c` `factorial` and two
//!   goto rewrites of it produce *byte-identical* parity CFGs --- the same node
//!   ids, the same edge list --- and GED scores both `0.0`. The tree distance
//!   is 4 for the latched rewrite and 7 for full goto soup, on a 6-node source.
//!
//! * **The decompiled side is only as good as the parse, and that is not a
//!   uniform tax.** Of the 1,998 decompiler outputs offered beside those
//!   sources, 175 (8.76%) hold no definition this front end can resolve for the
//!   named function --- and 144 of the 175 are `dewolf`, which is 85% of
//!   `dewolf`'s own offers. Its mean of 0.31 is therefore over the 26 outputs
//!   that parsed, not over what it produced. A per-column mean from this metric
//!   must be published with its unresolved count beside it, and the
//!   `structural-metrics.md` section 4 caveat --- that the parse coverage which
//!   makes this metric look free was measured on C Glaurung itself emitted ---
//!   stands unchanged.
//!
//! And the weakness, which is real and is not tuned away: **the normalized
//! score saturates.** At 7 edits against a 6-node source the soup rewrite
//! scores `0.0`, and so does a completely unrelated function 999 edits away.
//! Past 2x expansion `1 - TED/|source|` has no resolution, so the raw distance
//! has to be reported beside the score.
//!
//! # No native recursion, no panics
//!
//! Both hold, as everywhere in this front end (`REQ-SYN-2`, `REQ-SYN-3`). The
//! skeleton builder is one loop over an explicit `Vec<Step>`, the post-order
//! numbering is one loop over an explicit stack, and the distance is three
//! nested `for`s. `deeply_nested_input_does_not_touch_the_native_stack` drives
//! 20,000 levels of nesting through both, which is the shape decompiler output
//! actually produces and the shape a recursive walker dies on.
//!
//! # A non-answer is a value
//!
//! Above [`MAX_SKELETON_NODES`] the distance abstains --- [`tree_edit_distance`]
//! returns `None` --- rather than degrading to something cheaper.
//! [`crate::metrics`] states the rule: an abstention leaves the denominator
//! uniformly for every decompiler, while a fallback value that is not the
//! metric is a silent wrong answer. The cap is a *memory* bound and not a knob
//! that changes an answer: Zhang--Shasha holds two `(n1+1) x (n2+1)` `u32`
//! tables, so a pair at the cap costs 33 MB and a pair above it would cost
//! more than the measurement is worth. Section "corpus" of the tests reports
//! how much of the corpus it excludes.

use std::collections::BTreeMap;

use crate::csource::parse::tag::NodeTag;
use crate::csource::parse::{parse, FunctionDef, Tree};
use crate::syntax::ids::NodeId;
use crate::syntax::tree::Arena;

/// The version of the projection rules, bumped whenever a canonicalization
/// changes.
///
/// Every number this metric has ever produced is relative to one value of this
/// constant, so a stored score without it is not comparable to a fresh one.
/// The rules it versions are the "Canonicalized" list in the module docs.
pub const SKELETON_VERSION: u32 = 1;

/// The largest skeleton either side may have before the distance abstains.
///
/// A memory bound, not a quality knob. Zhang--Shasha keeps a permanent
/// `(n1+1) x (n2+1)` tree-distance table and a same-sized forest-distance
/// scratch table, both `u32`, so a pair of skeletons at this size costs
/// `2 * 2049^2 * 4` bytes = 33.6 MB. Doubling the cap quadruples that.
///
/// The rate it costs is measured rather than assumed. Over the 285 published
/// sample sources --- a slice deliberately weighted towards hard functions,
/// with `bash` `yyparse` and four `coreutils` `main`s in it --- 6 exceed the
/// cap, and 77 of 1,823 source-to-decompiled pairs (4.2%) abstain. The corpus
/// as a whole is far smaller than the sample slice: its median function has 12
/// CFG nodes.
pub const MAX_SKELETON_NODES: usize = 2048;

/// How many builder steps one function may take, per AST node in the file.
///
/// `REQ-SYN-4` wants a work budget on every entry point. The builder spends a
/// small constant number of steps per statement node, so eight per *arena*
/// node is generous by more than an order of magnitude; exceeding it truncates
/// the skeleton rather than looping, which matters only for an arena whose
/// child links were built by hand into a cycle.
const STEPS_PER_NODE: usize = 8;

/// How many wrapper layers the `else if` and bare-block unwrappers will peel.
///
/// `{ { { if (c) ... } } }` is legal C and a decompiler could in principle emit
/// it; a thousand layers is not, and bounding the peel keeps the helper a loop
/// with a proof of termination that does not depend on the arena being acyclic.
const MAX_UNWRAP: usize = 64;

/// One node of the control skeleton: the whole alphabet, and nothing else.
///
/// Seventeen members, fixed. The count is the point --- a larger alphabet is a
/// metric that sees more of the expression detail the projection exists to
/// discard, and a smaller one stops separating the single-node class.
///
/// `#[repr(u8)]` and `Ord` so a skeleton is cheap to store and a census of
/// kinds can be a sorted table rather than a hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SkeletonKind {
    /// The function body: the root, and the only sequence node. A bare block
    /// inside the body splices rather than nesting.
    Seq,
    /// A conditional. Its children are one or more [`SkeletonKind::Then`] arms
    /// --- more than one means an `else if` chain --- and at most one trailing
    /// [`SkeletonKind::Else`].
    If,
    /// One taken arm of an [`SkeletonKind::If`].
    Then,
    /// The final untaken arm of an [`SkeletonKind::If`].
    Else,
    /// A pre-tested loop. `for` normalizes to this; `while` is this.
    While,
    /// A post-tested loop, kept distinct from [`SkeletonKind::While`] because
    /// the body runs a different number of times.
    DoWhile,
    /// A multi-way dispatch.
    Switch,
    /// A `case` label. A sibling of the statements it guards, not their
    /// parent, matching the parser and `REQ-CFG-4`.
    Case,
    /// A `default` label.
    Default,
    /// `break`.
    Break,
    /// `continue`.
    Continue,
    /// `goto`, computed or not: the difference is the target expression, which
    /// the projection drops.
    Goto,
    /// A named label --- the target half of a `goto`.
    Label,
    /// `return`, with or without a value.
    Return,
    /// A statement whose outermost expression is a call.
    Call,
    /// A statement whose outermost expression is an assignment, including an
    /// initialized declaration, which *is* an assignment.
    Assign,
    /// Any other statement expression, an `asm`, or an unparsed region.
    Expr,
}

impl SkeletonKind {
    /// Every kind, in discriminant order --- for a census table.
    pub const ALL: &'static [SkeletonKind] = &[
        SkeletonKind::Seq,
        SkeletonKind::If,
        SkeletonKind::Then,
        SkeletonKind::Else,
        SkeletonKind::While,
        SkeletonKind::DoWhile,
        SkeletonKind::Switch,
        SkeletonKind::Case,
        SkeletonKind::Default,
        SkeletonKind::Break,
        SkeletonKind::Continue,
        SkeletonKind::Goto,
        SkeletonKind::Label,
        SkeletonKind::Return,
        SkeletonKind::Call,
        SkeletonKind::Assign,
        SkeletonKind::Expr,
    ];

    /// This kind's name, for a rendered skeleton and for a census dump.
    pub const fn name(self) -> &'static str {
        match self {
            SkeletonKind::Seq => "seq",
            SkeletonKind::If => "if",
            SkeletonKind::Then => "then",
            SkeletonKind::Else => "else",
            SkeletonKind::While => "while",
            SkeletonKind::DoWhile => "do_while",
            SkeletonKind::Switch => "switch",
            SkeletonKind::Case => "case",
            SkeletonKind::Default => "default",
            SkeletonKind::Break => "break",
            SkeletonKind::Continue => "continue",
            SkeletonKind::Goto => "goto",
            SkeletonKind::Label => "label",
            SkeletonKind::Return => "return",
            SkeletonKind::Call => "call",
            SkeletonKind::Assign => "assign",
            SkeletonKind::Expr => "expr",
        }
    }

    /// Whether this kind is a control construct rather than a straight-line
    /// statement.
    ///
    /// The predicate that answers "does this function have any control flow at
    /// all", which is the same question as "is it in the single-node CFG
    /// class". A skeleton whose kinds are all *false* here is branchless, and
    /// every branchless function is one graph to
    /// [`crate::syntax::ged`] --- which is the gap this module exists to fill.
    pub const fn is_control(self) -> bool {
        !matches!(
            self,
            SkeletonKind::Seq
                | SkeletonKind::Call
                | SkeletonKind::Assign
                | SkeletonKind::Expr
                | SkeletonKind::Return
        )
    }
}

/// One function's control skeleton, stored in the shape Zhang--Shasha reads.
///
/// Nodes are held in **post-order**, which is not a detail: the distance
/// indexes `l(i)`, the keyroots and the tree-distance table by post-order
/// position, so storing any other order would mean renumbering on every call.
/// Post-order is derived from source order, so it is canonical and two parses
/// of the same text produce the same vectors byte for byte (`REQ-SYN-5`).
///
/// The tree's shape is recoverable from `kinds` and `left` alone --- see
/// [`Skeleton::children`] --- so no parent or child vectors are stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skeleton {
    /// Node kinds in post-order.
    kinds: Vec<SkeletonKind>,
    /// `left[i]` is the post-order index of the leftmost leaf descendant of
    /// node `i`, which for a leaf is `i` itself.
    left: Vec<u32>,
    /// The Zhang--Shasha keyroots, ascending: every node that is not the
    /// leftmost child of its parent, plus the root.
    keyroots: Vec<u32>,
    /// The deepest nesting reached, in nodes. Reported rather than used: it is
    /// the factor that bounds the keyroot count and therefore the runtime.
    depth: u32,
    /// Whether the builder hit its step budget and stopped early.
    truncated: bool,
}

impl Skeleton {
    /// How many nodes the skeleton has.
    ///
    /// This is the denominator of [`skeleton_score`] when the skeleton is the
    /// ground truth, which is why it is a property of the source side and
    /// cannot be inflated by a decompiler.
    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    /// Whether the skeleton has no nodes at all.
    ///
    /// Only true for a function with no body: every real body yields at least
    /// the root [`SkeletonKind::Seq`].
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// The node kinds, in post-order.
    pub fn kinds(&self) -> &[SkeletonKind] {
        &self.kinds
    }

    /// The deepest nesting reached, in nodes.
    pub fn depth(&self) -> u32 {
        self.depth
    }

    /// How many keyroots the tree has --- the factor that multiplies the
    /// `n1 * n2` in the distance's cost.
    pub fn keyroot_count(&self) -> usize {
        self.keyroots.len()
    }

    /// Whether the builder stopped on its step budget rather than at the end of
    /// the function.
    ///
    /// A truncated skeleton is still a value and still comparable; it is simply
    /// not the whole function, and a caller reporting a score for one should
    /// say so.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Whether this function has no control flow --- the single-node CFG class.
    ///
    /// Every member of this class is one and the same graph to
    /// [`crate::syntax::ged`]: one node, no edges, entry and exit. 27.24% of
    /// the scored corpus lives here.
    pub fn is_branchless(&self) -> bool {
        !self.kinds.iter().any(|kind| kind.is_control())
    }

    /// How many nodes of each kind, as a sorted table.
    ///
    /// `BTreeMap` so a census printed from it is diffable; nothing in this
    /// module may iterate a `HashMap` into output.
    pub fn census(&self) -> BTreeMap<SkeletonKind, usize> {
        let mut counts = BTreeMap::new();
        for kind in &self.kinds {
            *counts.entry(*kind).or_insert(0) += 1;
        }
        counts
    }

    /// The children of post-order node `node`, left to right.
    ///
    /// Recovered from `left` rather than stored: in post-order the children of
    /// `node` are the maximal subtrees inside `[left[node], node - 1]`, so
    /// walking backwards from `node - 1` and jumping to `left[c] - 1` each time
    /// enumerates them right to left. Reversing that is cheaper than four bytes
    /// a node of child pointers.
    pub fn children(&self, node: u32) -> Vec<u32> {
        let mut found = Vec::new();
        let Some(&lo) = self.left.get(node as usize) else {
            return found;
        };
        let mut cursor = node;
        while cursor > lo {
            let child = cursor - 1;
            found.push(child);
            let Some(&child_lo) = self.left.get(child as usize) else {
                break;
            };
            cursor = child_lo;
        }
        found.reverse();
        found
    }

    /// The skeleton as a parenthesised expression, root first.
    ///
    /// The form every test expectation in this file is written in, because a
    /// vector of 40 post-order kinds is not reviewable and `(if (then ...))`
    /// is. Built over an explicit stack, like everything else here.
    pub fn render(&self) -> String {
        if self.kinds.is_empty() {
            return String::new();
        }
        let root = (self.kinds.len() - 1) as u32;
        let mut out = String::new();
        // `Some(node)` opens a node; `None` closes the one on top.
        let mut stack: Vec<Option<u32>> = vec![Some(root)];
        while let Some(step) = stack.pop() {
            match step {
                Some(node) => {
                    let kind = self.kinds[node as usize];
                    let children = self.children(node);
                    if children.is_empty() {
                        if !out.is_empty() && !out.ends_with('(') {
                            out.push(' ');
                        }
                        out.push_str(kind.name());
                        continue;
                    }
                    if !out.is_empty() && !out.ends_with('(') {
                        out.push(' ');
                    }
                    out.push('(');
                    out.push_str(kind.name());
                    stack.push(None);
                    for child in children.into_iter().rev() {
                        stack.push(Some(child));
                    }
                }
                None => out.push(')'),
            }
        }
        out
    }
}

/// Project one function definition onto its control skeleton.
///
/// Total on every input, like every other entry point in this front end: a
/// function with no body, a body the parser only recovered part of, a node
/// whose children are missing --- each yields a skeleton rather than a failure.
/// A function with no body yields the empty skeleton, which is the honest
/// answer and is distinguishable from a function with an empty body (one
/// [`SkeletonKind::Seq`] node).
pub fn skeleton(tree: &Tree, func: &FunctionDef) -> Skeleton {
    let Some(body) = func.body else {
        return Skeleton {
            kinds: Vec::new(),
            left: Vec::new(),
            keyroots: Vec::new(),
            depth: 0,
            truncated: false,
        };
    };
    let mut builder = Builder::new(tree.arena());
    builder.open(SkeletonKind::Seq);
    builder.push(&[Step::Block(body), Step::Close]);
    builder.run();
    builder.finish()
}

/// Project every function definition in a C translation unit, by name.
///
/// The whole-file entry point, and the one the corpus gates use. A file with
/// two definitions of the same name keeps the last, which is the same rule
/// [`crate::csource::joern::parity_cfgs`] applies, so the two maps have the
/// same keys for the same input.
pub fn skeletons(text: &str) -> BTreeMap<String, Skeleton> {
    let tree = parse(text).into_parts().0;
    let mut found = BTreeMap::new();
    for func in tree.functions(text) {
        if func.name.is_empty() {
            continue;
        }
        found.insert(func.name.clone(), skeleton(&tree, &func));
    }
    found
}

/// The ordered tree edit distance between two control skeletons, or `None`
/// when either is larger than [`MAX_SKELETON_NODES`].
///
/// Zhang--Shasha with unit costs: inserting a node costs 1, deleting one costs
/// 1, and relabelling one costs 1 unless the kinds already agree, in which case
/// it costs 0. Unit costs rather than a kind-dependent table because a table is
/// a knob --- every entry in it moves the score, and there is no ground truth
/// against which to fit one (`what-ged-measures.md` section 6: the corpus
/// carries no human labels).
///
/// The distance is a metric in the mathematical sense on skeletons: zero
/// exactly on identical trees, symmetric, and triangle-obeying, all of which
/// follow from unit edit costs and all three of which are asserted on real
/// skeletons ---
/// `the_distance_is_zero_only_on_identical_skeletons_and_is_symmetric` and
/// `the_triangle_inequality_holds_on_real_skeletons`. The DP itself is
/// cross-checked against an independent Levenshtein implementation on every
/// flat skeleton in the fixture corpus, which is exactly the branchless class
/// this module exists to separate.
///
/// `None` is an abstention and not a zero: see the module docs.
pub fn tree_edit_distance(a: &Skeleton, b: &Skeleton) -> Option<u32> {
    if a.len() > MAX_SKELETON_NODES || b.len() > MAX_SKELETON_NODES {
        return None;
    }
    let n1 = a.kinds.len();
    let n2 = b.kinds.len();
    // The empty skeleton is a real value --- a function with no body --- and
    // its distance to anything is that thing's size.
    if n1 == 0 {
        return Some(n2 as u32);
    }
    if n2 == 0 {
        return Some(n1 as u32);
    }

    // `tree_dist[i * (n2 + 1) + j]` is the distance between the subtree rooted
    // at post-order `i` of `a` and the one rooted at `j` of `b`. It is
    // permanent: the keyroot loop reads entries an earlier iteration wrote.
    let mut tree_dist = vec![0u32; (n1 + 1) * (n2 + 1)];
    // Forest distance, reused across keyroot pairs. Only the window
    // `[0..=i-l(i)] x [0..=j-l(j)]` is live in any one pass, and every live
    // cell is written before it is read, so no clear is needed between passes.
    let mut forest = vec![0u32; (n1 + 1) * (n2 + 1)];

    for &key1 in &a.keyroots {
        let lo1 = a.left[key1 as usize];
        let rows = (key1 - lo1 + 1) as usize;
        for &key2 in &b.keyroots {
            let lo2 = b.left[key2 as usize];
            let cols = (key2 - lo2 + 1) as usize;

            forest[0] = 0;
            for x in 1..=rows {
                forest[x * (n2 + 1)] = forest[(x - 1) * (n2 + 1)] + 1;
            }
            for y in 1..=cols {
                forest[y] = forest[y - 1] + 1;
            }

            for x in 1..=rows {
                let node1 = lo1 as usize + x - 1;
                let same_root1 = a.left[node1] == lo1;
                for y in 1..=cols {
                    let node2 = lo2 as usize + y - 1;
                    let delete = forest[(x - 1) * (n2 + 1) + y] + 1;
                    let insert = forest[x * (n2 + 1) + y - 1] + 1;
                    if same_root1 && b.left[node2] == lo2 {
                        // Both windows are whole subtrees, so the third option
                        // is a relabel and the answer is also this subtree
                        // pair's permanent distance.
                        let relabel = forest[(x - 1) * (n2 + 1) + y - 1]
                            + u32::from(a.kinds[node1] != b.kinds[node2]);
                        let best = delete.min(insert).min(relabel);
                        forest[x * (n2 + 1) + y] = best;
                        tree_dist[node1 * (n2 + 1) + node2] = best;
                    } else {
                        // At least one window is a proper forest: the third
                        // option is "match the two rightmost subtrees, then
                        // whatever is left of both forests".
                        let px = (a.left[node1] - lo1) as usize;
                        let py = (b.left[node2] - lo2) as usize;
                        let joint =
                            forest[px * (n2 + 1) + py] + tree_dist[node1 * (n2 + 1) + node2];
                        forest[x * (n2 + 1) + y] = delete.min(insert).min(joint);
                    }
                }
            }
        }
    }
    Some(tree_dist[(n1 - 1) * (n2 + 1) + (n2 - 1)])
}

/// `1 - TED / |source|`, clamped to `[0, 1]`, or `None` when the distance
/// abstained.
///
/// The aggregation `structural-metrics.md` section 3 specifies. The denominator
/// is the **source** skeleton's node count, deliberately: a denominator that
/// included the decompiled side could be inflated by emitting more code, and a
/// metric a decompiler can move without improving is not a metric.
///
/// The clamp is where the honesty is. A decompiled skeleton more than twice the
/// size of the source saturates at `0.0` and the metric stops distinguishing
/// "somewhat worse" from "completely wrong" --- which is exactly what happens
/// to goto-ified output, and is reported rather than tuned away. See
/// `goto_ification_saturates_the_normalized_score`.
pub fn skeleton_score(source: &Skeleton, decompiled: &Skeleton) -> Option<f64> {
    let distance = tree_edit_distance(source, decompiled)?;
    let denominator = source.len();
    if denominator == 0 {
        // No ground truth to be right or wrong about. An exact match with the
        // other empty skeleton is 1.0; anything else is 0.0.
        return Some(if decompiled.is_empty() { 1.0 } else { 0.0 });
    }
    let raw = 1.0 - f64::from(distance) / denominator as f64;
    Some(raw.clamp(0.0, 1.0))
}

// --- the builder ------------------------------------------------------------

/// One suspended step of the projection.
///
/// A `Step` *is* the call stack a recursive walker would have used, made data
/// so that nesting costs heap rather than the native stack (`REQ-SYN-3`).
#[derive(Debug, Clone, Copy)]
enum Step {
    /// Project one statement node.
    Stmt(NodeId),
    /// Splice one block's children into the current node, adding no node of its
    /// own.
    Block(NodeId),
    /// Continue an `if`/`else if` chain under the already-open `If` node.
    IfArms(NodeId),
    /// Emit one `Assign` per initialized declarator of a declaration.
    Decl(NodeId),
    /// Project a `for` clause: each expression child becomes one leaf, and a
    /// declaration becomes its initializers.
    ForClause(NodeId),
    /// Open a node; a matching `Close` must follow.
    Open(SkeletonKind),
    /// Emit a childless node.
    Leaf(SkeletonKind),
    /// Close the innermost open node.
    Close,
}

/// The projection's state: an arena of skeleton nodes in *open* order, plus the
/// stack of nodes that are still open.
///
/// Nodes are numbered in open order here and renumbered to post-order in
/// [`Builder::finish`]. Two orders are needed because the builder can only
/// append (it does not know a node's children when it opens the node) while the
/// distance can only read post-order.
struct Builder<'a> {
    arena: &'a Arena,
    kinds: Vec<SkeletonKind>,
    parent: Vec<u32>,
    open_nodes: Vec<u32>,
    steps: Vec<Step>,
    budget: usize,
    depth: u32,
    truncated: bool,
}

/// The parent of a root, in [`Builder::parent`].
const NO_PARENT: u32 = u32::MAX;

impl<'a> Builder<'a> {
    /// A builder over one parse's arena, with a budget scaled to its size.
    fn new(arena: &'a Arena) -> Self {
        Self {
            arena,
            kinds: Vec::new(),
            parent: Vec::new(),
            open_nodes: Vec::new(),
            steps: Vec::new(),
            budget: arena
                .len()
                .saturating_mul(STEPS_PER_NODE)
                .saturating_add(16),
            depth: 0,
            truncated: false,
        }
    }

    /// Push steps so they run in the order written --- the stack is LIFO, so
    /// they go on reversed.
    fn push(&mut self, steps: &[Step]) {
        for step in steps.iter().rev() {
            self.steps.push(*step);
        }
    }

    /// Append a node under the innermost open one and make it the innermost
    /// open one.
    fn open(&mut self, kind: SkeletonKind) {
        let id = self.kinds.len() as u32;
        self.kinds.push(kind);
        self.parent
            .push(self.open_nodes.last().copied().unwrap_or(NO_PARENT));
        self.open_nodes.push(id);
        self.depth = self.depth.max(self.open_nodes.len() as u32);
    }

    /// Append a node that has no children.
    fn leaf(&mut self, kind: SkeletonKind) {
        self.open(kind);
        self.open_nodes.pop();
    }

    /// Run the machine until the steps run out or the budget does.
    fn run(&mut self) {
        while let Some(step) = self.steps.pop() {
            if self.budget == 0 {
                self.truncated = true;
                return;
            }
            self.budget -= 1;
            match step {
                Step::Open(kind) => self.open(kind),
                Step::Leaf(kind) => self.leaf(kind),
                // The root is never closed: a `Close` with nothing but the
                // root open would orphan every later node, and a skeleton with
                // two roots is not a tree. Unreachable while the steps are
                // balanced, which is what `every_close_has_an_open` asserts.
                Step::Close => {
                    if self.open_nodes.len() > 1 {
                        self.open_nodes.pop();
                    }
                }
                Step::Block(node) => {
                    let children: Vec<Step> =
                        self.arena.children_iter(node).map(Step::Stmt).collect();
                    self.push(&children);
                }
                Step::Stmt(node) => self.statement(node),
                Step::IfArms(node) => self.if_arms(node),
                Step::Decl(node) => self.declaration(node),
                Step::ForClause(node) => self.for_clause(node),
            }
        }
    }

    /// Project one statement node.
    ///
    /// The dispatch mirrors [`crate::csource::cfg`]'s, deliberately: a
    /// construct that contributes no control-flow event contributes no skeleton
    /// node either, so the two views of "what is a statement here" cannot
    /// drift.
    fn statement(&mut self, node: NodeId) {
        let Some(tag) = self.tag(node) else {
            return;
        };
        match tag {
            // A bare block is a scope, not control flow: splice it.
            NodeTag::CompoundStmt | NodeTag::StmtExpr => self.push(&[Step::Block(node)]),
            NodeTag::ExprStmt => {
                let kind = self.expr_kind(self.arena.children_iter(node).next());
                self.leaf(kind);
            }
            NodeTag::Decl => self.push(&[Step::Decl(node)]),
            NodeTag::IfStmt => self.push(&[
                Step::Open(SkeletonKind::If),
                Step::IfArms(node),
                Step::Close,
            ]),
            NodeTag::WhileStmt => self.wrap_body(node, SkeletonKind::While),
            NodeTag::DoWhileStmt => self.wrap_body(node, SkeletonKind::DoWhile),
            // `for (a; b; c) S` becomes `a; while { S; c; }`.
            NodeTag::ForStmt => self.for_stmt(node),
            NodeTag::SwitchStmt => self.wrap_body(node, SkeletonKind::Switch),
            NodeTag::CaseLabel => self.leaf(SkeletonKind::Case),
            NodeTag::DefaultLabel => self.leaf(SkeletonKind::Default),
            NodeTag::LabelStmt => self.leaf(SkeletonKind::Label),
            NodeTag::GotoStmt => self.leaf(SkeletonKind::Goto),
            NodeTag::BreakStmt => self.leaf(SkeletonKind::Break),
            NodeTag::ContinueStmt => self.leaf(SkeletonKind::Continue),
            NodeTag::ReturnStmt => self.leaf(SkeletonKind::Return),
            // `REQ-CFG-11`: an unparsed region keeps its node, and an `asm` is
            // one opaque straight-line item.
            NodeTag::Error | NodeTag::Asm => self.leaf(SkeletonKind::Expr),
            // No control flow and no statement: `;`, a directive line, a
            // `_Static_assert`, a `__label__`.
            NodeTag::NullStmt
            | NodeTag::PpDirective
            | NodeTag::StaticAssert
            | NodeTag::LocalLabel => {}
            other => {
                if other.is_expression() {
                    let kind = self.expr_kind(Some(node));
                    self.leaf(kind);
                }
            }
        }
    }

    /// Emit the arms of an `if`, flattening an `else if` chain into the
    /// already-open [`SkeletonKind::If`].
    fn if_arms(&mut self, node: NodeId) {
        let mut arms = self.body_of(node).into_iter();
        let then = arms.next();
        let otherwise = arms.next();
        let mut steps = vec![Step::Open(SkeletonKind::Then)];
        if let Some(then) = then {
            steps.push(Step::Stmt(then));
        }
        steps.push(Step::Close);
        if let Some(otherwise) = otherwise {
            // The chain continues only when the whole else arm is one `if`. An
            // else arm holding anything else --- `else { x = 1; if (c) ... }`
            // --- is a real nesting and stays nested.
            match self.lone_if(otherwise) {
                Some(inner) => steps.push(Step::IfArms(inner)),
                None => steps.extend([
                    Step::Open(SkeletonKind::Else),
                    Step::Stmt(otherwise),
                    Step::Close,
                ]),
            }
        }
        self.push(&steps);
    }

    /// Open `kind`, project the construct's body under it, close it.
    ///
    /// The shape every single-body construct shares. Written once because the
    /// order the steps go on the stack in is the part that is easy to get
    /// wrong, and getting it wrong silently produces a differently-shaped tree
    /// rather than an error.
    fn wrap_body(&mut self, node: NodeId, kind: SkeletonKind) {
        let body = self.body_of(node).into_iter().next();
        let mut steps = vec![Step::Open(kind)];
        if let Some(body) = body {
            steps.push(Step::Stmt(body));
        }
        steps.push(Step::Close);
        self.push(&steps);
    }

    /// `for (init; cond; step) body` as `init; while { body; step; }`.
    fn for_stmt(&mut self, node: NodeId) {
        let mut init = None;
        let mut step = None;
        for child in self.arena.children_iter(node) {
            match self.tag(child) {
                Some(NodeTag::ForInit) => init = Some(child),
                Some(NodeTag::ForStep) => step = Some(child),
                // `ForCond` is the loop condition: an expression, dropped like
                // every other condition.
                _ => {}
            }
        }
        let body = self.body_of(node).into_iter().next();
        let mut steps = Vec::new();
        if let Some(init) = init {
            steps.push(Step::ForClause(init));
        }
        steps.push(Step::Open(SkeletonKind::While));
        if let Some(body) = body {
            steps.push(Step::Stmt(body));
        }
        if let Some(step) = step {
            steps.push(Step::ForClause(step));
        }
        steps.push(Step::Close);
        self.push(&steps);
    }

    /// One `for` clause: a declaration becomes its initializers, an expression
    /// becomes one leaf of its own kind.
    fn for_clause(&mut self, node: NodeId) {
        let children: Vec<NodeId> = self.arena.children_iter(node).collect();
        let mut steps = Vec::new();
        for child in children {
            match self.tag(child) {
                Some(NodeTag::Decl) => steps.push(Step::Decl(child)),
                Some(tag) if tag.is_expression() => {
                    steps.push(Step::Leaf(self.expr_kind(Some(child))))
                }
                _ => {}
            }
        }
        self.push(&steps);
    }

    /// One `Assign` per initialized declarator.
    ///
    /// `REQ-CFG-3`'s rule, and the module docs' argument: an uninitialized
    /// declaration is style, an initialized one is an assignment. `int a = 1,
    /// b = 2;` is two.
    fn declaration(&mut self, node: NodeId) {
        let initializers = self
            .arena
            .children_iter(node)
            .filter(|child| self.tag(*child) == Some(NodeTag::Initializer))
            .count();
        for _ in 0..initializers {
            self.leaf(SkeletonKind::Assign);
        }
    }

    /// The statement children of a construct --- its arms and bodies, never its
    /// condition or its `for` clauses.
    fn body_of(&self, node: NodeId) -> Vec<NodeId> {
        self.arena
            .children_iter(node)
            .filter(|child| self.tag(*child).is_some_and(is_body))
            .collect()
    }

    /// The single `if` an else arm consists of, peeling redundant braces, or
    /// `None` when the arm is anything else.
    fn lone_if(&self, node: NodeId) -> Option<NodeId> {
        let mut cursor = node;
        for _ in 0..MAX_UNWRAP {
            match self.tag(cursor)? {
                NodeTag::IfStmt => return Some(cursor),
                NodeTag::CompoundStmt => {
                    let mut significant = self
                        .arena
                        .children_iter(cursor)
                        .filter(|child| self.tag(*child).is_some_and(is_significant));
                    let only = significant.next()?;
                    if significant.next().is_some() {
                        return None;
                    }
                    cursor = only;
                }
                _ => return None,
            }
        }
        None
    }

    /// Which of the three statement kinds an expression is, from its outermost
    /// form and nothing deeper.
    ///
    /// One `ParenExpr` layer is peeled because `(f());` and `f();` are the same
    /// statement and a decompiler's parenthesisation is not a structural
    /// choice. A `CommaExpr` is **not** descended into: it stays one
    /// [`SkeletonKind::Expr`], because splitting it would mean deciding how
    /// many statements a comma expression is, and nothing downstream needs the
    /// answer.
    fn expr_kind(&self, node: Option<NodeId>) -> SkeletonKind {
        let Some(node) = node else {
            return SkeletonKind::Expr;
        };
        let mut cursor = node;
        for _ in 0..MAX_UNWRAP {
            if self.tag(cursor) == Some(NodeTag::ParenExpr) {
                match self.arena.children_iter(cursor).next() {
                    Some(inner) => cursor = inner,
                    None => break,
                }
            } else {
                break;
            }
        }
        match self.tag(cursor) {
            Some(NodeTag::AssignExpr) => SkeletonKind::Assign,
            // A postfix chain is flat, one suffix node per link, so the
            // outermost operation is the *last* child: `f()` is a call and
            // `f()->x` is a member access that happens to contain one.
            Some(NodeTag::PostfixExpr) => {
                let last = self.arena.children_iter(cursor).last();
                if last.and_then(|child| self.tag(child)) == Some(NodeTag::CallArgs) {
                    SkeletonKind::Call
                } else {
                    SkeletonKind::Expr
                }
            }
            _ => SkeletonKind::Expr,
        }
    }

    /// The C tag of an arena node, or `None` for a handle this arena does not
    /// address and for a tag some other front end wrote.
    fn tag(&self, node: NodeId) -> Option<NodeTag> {
        self.arena.tag(node).and_then(NodeTag::from_u16)
    }

    /// Renumber into post-order and compute what the distance reads.
    fn finish(self) -> Skeleton {
        let n = self.kinds.len();
        if n == 0 {
            return Skeleton {
                kinds: Vec::new(),
                left: Vec::new(),
                keyroots: Vec::new(),
                depth: 0,
                truncated: self.truncated,
            };
        }
        // Children in source order, from the parent links: open order is a
        // pre-order walk, so a node's children have ascending ids in the order
        // they were opened.
        let mut children: Vec<Vec<u32>> = vec![Vec::new(); n];
        for (id, &parent) in self.parent.iter().enumerate() {
            if parent != NO_PARENT && (parent as usize) < n {
                children[parent as usize].push(id as u32);
            }
        }
        // Post-order over an explicit stack of (node, next child to visit).
        let mut order: Vec<u32> = Vec::with_capacity(n);
        let mut stack: Vec<(u32, usize)> = vec![(0, 0)];
        while let Some((node, index)) = stack.pop() {
            match children[node as usize].get(index) {
                Some(&child) => {
                    stack.push((node, index + 1));
                    stack.push((child, 0));
                }
                None => order.push(node),
            }
        }
        let mut position = vec![0u32; n];
        for (post, &node) in order.iter().enumerate() {
            position[node as usize] = post as u32;
        }
        // `order` holds every node reachable from the root, which is every node
        // the builder made: the root is never closed, so nothing is ever opened
        // without a parent. Sizing the vectors by `order` rather than by `n`
        // keeps that an invariant rather than an assumption --- a shorter
        // `order` yields a smaller, still well-formed skeleton instead of an
        // index panic (`REQ-SYN-2`).
        let reached = order.len();
        let mut kinds = Vec::with_capacity(reached);
        let mut left = vec![0u32; reached];
        for (post, &node) in order.iter().enumerate() {
            kinds.push(self.kinds[node as usize]);
            left[post] = match children[node as usize].first() {
                // Children precede their parent in post-order, so this entry is
                // already final.
                Some(&first) => left[position[first as usize] as usize],
                None => post as u32,
            };
        }
        // A keyroot is the last node, in post-order, carrying each distinct
        // leftmost-leaf value --- equivalently every node that is not its
        // parent's leftmost child, plus the root.
        let mut last_with_left = vec![u32::MAX; reached];
        for (post, &lo) in left.iter().enumerate() {
            last_with_left[lo as usize] = post as u32;
        }
        let mut keyroots: Vec<u32> = last_with_left
            .into_iter()
            .filter(|post| *post != u32::MAX)
            .collect();
        keyroots.sort_unstable();
        Skeleton {
            kinds,
            left,
            keyroots,
            depth: self.depth,
            truncated: self.truncated,
        }
    }
}

/// Whether a tag names a construct's *body* rather than one of its clauses.
///
/// The same rule `crate::csource::cfg::reach::is_body` applies, restated
/// because it is `pub(super)` there: a `for`'s three clause nodes are not
/// bodies, an unparsed region is, and everything else follows
/// [`NodeTag::is_statement`].
fn is_body(tag: NodeTag) -> bool {
    match tag {
        NodeTag::ForInit | NodeTag::ForCond | NodeTag::ForStep => false,
        NodeTag::Error => true,
        other => other.is_statement(),
    }
}

/// Whether a statement contributes anything at all --- used only to decide
/// whether an else arm is a lone `if`.
///
/// `else { ; if (c) ... }` is an `else if` chain with a stray semicolon in it,
/// and calling it a nesting because of the semicolon would be scoring
/// punctuation.
fn is_significant(tag: NodeTag) -> bool {
    !matches!(
        tag,
        NodeTag::NullStmt | NodeTag::PpDirective | NodeTag::StaticAssert | NodeTag::LocalLabel
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csource::joern::parity_cfgs;
    use crate::syntax::ged::{ged, GedGraph, GedNode};
    use std::path::{Path, PathBuf};

    // --- helpers -------------------------------------------------------------

    /// One in-repo fixture's text, by path relative to the crate root.
    ///
    /// Fixtures are read rather than pasted into the test on purpose: a quoted
    /// copy of a real function drifts silently from the file it was copied
    /// from, and a test whose fixture has drifted asserts about code that no
    /// longer exists.
    fn fixture(relative: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} is a corpus file: {error}", path.display()))
    }

    /// The skeleton of one named function in `text`, which must exist.
    fn projected(text: &str, name: &str) -> Skeleton {
        skeletons(text)
            .remove(name)
            .unwrap_or_else(|| panic!("{name} is not a function definition in this text"))
    }

    /// One named function's Joern-parity CFG in the degree-and-flag view that
    /// is all [`crate::syntax::ged`] can see.
    ///
    /// This is what makes the "GED says these are the same" half of the
    /// separation tests real rather than asserted: the graph comes from the
    /// same parity layer DecBench's `ged` column is computed over.
    fn parity_ged(text: &str, name: &str) -> GedGraph {
        let cfgs = parity_cfgs(text);
        let cfg = cfgs
            .get(name)
            .unwrap_or_else(|| panic!("{name} has no parity CFG"));
        let mut incoming: BTreeMap<u32, u32> = BTreeMap::new();
        let mut outgoing: BTreeMap<u32, u32> = BTreeMap::new();
        for (from, to) in &cfg.edges {
            *outgoing.entry(*from).or_insert(0) += 1;
            *incoming.entry(*to).or_insert(0) += 1;
        }
        let nodes = cfg
            .nodes
            .iter()
            .map(|node| {
                GedNode::new(
                    incoming.get(node).copied().unwrap_or(0),
                    outgoing.get(node).copied().unwrap_or(0),
                    cfg.entry.contains(node),
                    cfg.exit.contains(node),
                )
            })
            .collect();
        GedGraph::new(nodes, cfg.edges.len() as u64)
    }

    /// Every `.c` file directly under `dir`, sorted, or nothing when the
    /// directory is absent.
    fn c_files(dir: &Path) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut found: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "c"))
            .collect();
        found.sort();
        found
    }

    /// The value at quantile `q` of an already-sorted slice.
    fn quantile(sorted: &[usize], q: f64) -> usize {
        if sorted.is_empty() {
            return 0;
        }
        sorted[(((sorted.len() - 1) as f64) * q) as usize]
    }

    // --- the projection ------------------------------------------------------

    #[test]
    fn the_alphabet_is_the_seventeen_kinds_the_design_names() {
        // `structural-metrics.md` section 2.6 fixes the alphabet, and its size
        // is the metric's whole insensitivity story: growing it is how a tree
        // metric turns back into an AST diff.
        assert_eq!(SkeletonKind::ALL.len(), 17);
        let mut names: Vec<&str> = SkeletonKind::ALL.iter().map(|kind| kind.name()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "two kinds share a name");
    }

    #[test]
    fn a_real_counted_for_projects_to_the_shape_the_design_specifies() {
        // tests/decompiler_fixtures/src/03_loop_shapes.c :: for_sum
        //     int s = 0;
        //     for (int i = 0; i < N; i++)
        //         s += p[i];
        //     return s;
        // The `int i = 0` becomes the second `assign`, hoisted out of the loop
        // by the `for` canonicalization, and the `i++` becomes the `expr`
        // *inside* the loop, after the body.
        let text = fixture("tests/decompiler_fixtures/src/03_loop_shapes.c");
        let sum = projected(&text, "for_sum");
        assert_eq!(
            sum.render(),
            "(seq assign assign (while assign expr) return)"
        );
        assert!(!sum.is_branchless());
    }

    #[test]
    fn a_for_and_the_while_a_decompiler_emits_for_it_are_the_same_skeleton() {
        // The canonicalization `structural-metrics.md` section 2.6 requires:
        // `for (a; b; c) S` normalizes to `a; while (b) { S; c; }`, because a
        // decompiler choosing `while` over `for` is not wrong --- and every
        // real one does choose `while`.
        //
        // Source: tests/decompiler_fixtures/src/03_loop_shapes.c :: for_sum.
        // The rewrite below is that function's body with the `for` spelled out
        // by hand, which is the transformation a decompiler performs.
        let text = fixture("tests/decompiler_fixtures/src/03_loop_shapes.c");
        let as_for = projected(&text, "for_sum");
        let as_while = projected(
            "int for_sum(const int *p) { int s = 0; int i = 0;\n\
             while (i < 8) { s += p[i]; i++; } return s; }",
            "for_sum",
        );
        assert_eq!(as_for.render(), as_while.render());
        assert_eq!(tree_edit_distance(&as_for, &as_while), Some(0));
        assert_eq!(skeleton_score(&as_for, &as_while), Some(1.0));
    }

    #[test]
    fn an_else_if_ladder_is_one_if_node_with_one_then_per_arm() {
        // tests/decompiler_fixtures/src/151_wide_branch_ladder.c ::
        // big151_branch_ladder is a real 211-arm descending threshold ladder,
        // which is the largest `else if` chain in the repository and the reason
        // the flattening rule is worth having: nested, each extra arm would
        // cost three nodes (If + Then + Else) instead of one.
        let text = fixture("tests/decompiler_fixtures/src/151_wide_branch_ladder.c");
        let ladder = projected(&text, "big151_branch_ladder");
        // The ladder's own `If` is the outermost one; find it as the `If`
        // carrying the most `Then` children.
        let widest = (0..ladder.len() as u32)
            .filter(|node| ladder.kinds()[*node as usize] == SkeletonKind::If)
            .map(|node| {
                ladder
                    .children(node)
                    .into_iter()
                    .filter(|child| ladder.kinds()[*child as usize] == SkeletonKind::Then)
                    .count()
            })
            .max()
            .expect("the ladder has an `if`");
        // 210 thresholds (`tag >= 210` down to `tag >= 1`) plus a final bare
        // `else` for arm 0 --- 211 arms, 210 of which are tested.
        assert_eq!(
            widest, 210,
            "the ladder must be one `if` with one `then` per tested arm"
        );
        let ladder_if = (0..ladder.len() as u32)
            .find(|node| {
                ladder.kinds()[*node as usize] == SkeletonKind::If
                    && ladder
                        .children(*node)
                        .iter()
                        .filter(|child| ladder.kinds()[**child as usize] == SkeletonKind::Then)
                        .count()
                        == 210
            })
            .expect("the ladder's own `if`");
        assert_eq!(
            ladder
                .children(ladder_if)
                .iter()
                .filter(|child| ladder.kinds()[**child as usize] == SkeletonKind::Else)
                .count(),
            1,
            "the ladder ends in one `else`, not a 211th `if`"
        );
        // Nested rather than flattened, the same ladder would carry 211 `If`
        // nodes for the chain alone; flattened, the only remaining `If`s are
        // the per-arm inner branches.
        let census = ladder.census();
        println!(
            "151 big151_branch_ladder: {} nodes, census {census:?}",
            ladder.len()
        );
    }

    #[test]
    fn a_redundant_scope_is_punctuation_and_contributes_no_node() {
        // tests/decompiler_fixtures/src/118_bit_tricks.c :: clear_lowest_set,
        // wrapped in braces a decompiler is free to add or drop.
        let text = fixture("tests/decompiler_fixtures/src/118_bit_tricks.c");
        let plain = projected(&text, "clear_lowest_set");
        let braced = projected(
            "uint32_t clear_lowest_set(uint32_t value) { { { return value & (value - 1u); } } }",
            "clear_lowest_set",
        );
        assert_eq!(plain.render(), "(seq return)");
        assert_eq!(tree_edit_distance(&plain, &braced), Some(0));
    }

    // --- validation 1: the single-node CFG class is separated -----------------

    #[test]
    fn the_single_node_cfg_class_is_separated() {
        // The class that holds 24,243 of 89,014 scorable functions and that
        // every CFG-derived metric assigns one value to. Three real in-repo
        // functions, all branchless, all one node / no edges / entry+exit:
        //
        //   118_bit_tricks.c       :: isolate_lowest_set        (1 statement)
        //   117_modular_arithmetic :: absolute_without_branch   (3 statements)
        //   100_struct_layout.c    :: struct_assignment_copies  (6 statements)
        //
        // GED scores every pair of them 0.0 --- a perfect decompilation, by the
        // metric DecBench publishes. The tree distance does not.
        let cases = [
            (
                "tests/decompiler_fixtures/src/118_bit_tricks.c",
                "isolate_lowest_set",
            ),
            (
                "tests/decompiler_fixtures/src/117_modular_arithmetic.c",
                "absolute_without_branch",
            ),
            (
                "tests/decompiler_fixtures/src/100_struct_layout.c",
                "struct_assignment_copies",
            ),
        ];
        let mut projections = Vec::new();
        for (path, name) in cases {
            let text = fixture(path);
            let cfgs = parity_cfgs(&text);
            let cfg = cfgs.get(name).expect("a parity CFG");
            assert_eq!(
                (
                    cfg.nodes.len(),
                    cfg.edges.len(),
                    cfg.entry.len(),
                    cfg.exit.len()
                ),
                (1, 0, 1, 1),
                "{name} must be in the one-node entry+exit class"
            );
            let projection = projected(&text, name);
            assert!(projection.is_branchless(), "{name} has no control flow");
            projections.push((name, parity_ged(&text, name), projection));
        }
        // Every pair is GED-perfect and tree-distinct.
        let mut separated = 0;
        for left in 0..projections.len() {
            for right in (left + 1)..projections.len() {
                let (a, b) = (&projections[left], &projections[right]);
                let graph = ged(&a.1, &b.1);
                assert_eq!(
                    (graph.value, graph.approximated),
                    (0.0, false),
                    "{} and {} must be GED-perfect against each other",
                    a.0,
                    b.0
                );
                let distance = tree_edit_distance(&a.2, &b.2).expect("both are small");
                assert!(
                    distance > 0,
                    "{} and {} are the same tree, so nothing was separated",
                    a.0,
                    b.0
                );
                println!(
                    "GED({}, {}) = 0.0   TED = {distance}   [{} vs {} nodes]",
                    a.0,
                    b.0,
                    a.2.len(),
                    b.2.len()
                );
                separated += 1;
            }
        }
        assert_eq!(separated, 3);
        // The exact distances, so a change to the projection has to be looked
        // at rather than absorbed.
        assert_eq!(projections[0].2.render(), "(seq return)");
        assert_eq!(projections[1].2.render(), "(seq assign assign return)");
        assert_eq!(
            projections[2].2.render(),
            "(seq assign assign assign assign assign return)"
        );
    }

    #[test]
    fn the_null_decompiler_no_longer_scores_the_class_perfect() {
        // `what-ged-measures.md` section 2.2: a decompiler emitting
        // `int f(void) { return 0; }` for every function is GED-perfect on
        // 27.24% of the corpus. Against the same three real functions the tree
        // metric awards it a perfect score on exactly the one whose body really
        // is a single `return`.
        let null = projected("int f(void) { return 0; }", "f");
        assert_eq!(null.render(), "(seq return)");
        let cases = [
            (
                "tests/decompiler_fixtures/src/118_bit_tricks.c",
                "isolate_lowest_set",
                1.0_f64,
            ),
            (
                "tests/decompiler_fixtures/src/117_modular_arithmetic.c",
                "absolute_without_branch",
                0.5,
            ),
            (
                "tests/decompiler_fixtures/src/100_struct_layout.c",
                "struct_assignment_copies",
                2.0 / 7.0,
            ),
        ];
        for (path, name, expected) in cases {
            let text = fixture(path);
            let source = projected(&text, name);
            let graph = ged(
                &parity_ged(&text, name),
                &parity_ged("int f(void){return 0;}", "f"),
            );
            assert_eq!(
                graph.value, 0.0,
                "{name} is GED-perfect against the null body"
            );
            let score = skeleton_score(&source, &null).expect("small skeletons");
            assert!(
                (score - expected).abs() < 1e-9,
                "{name}: null score {score} != {expected}"
            );
            println!("null decompiler vs {name}: GED perfect, tree score {score:.4}");
        }
    }

    // --- validation 2: goto-ification ----------------------------------------

    /// The three goto rewrites of `loops.c :: factorial` the tests below use.
    ///
    /// All three are semantics-preserving source transformations of one real
    /// in-repo function, which is what `mutate.py` does to build the
    /// calibration corpus. `latched` keeps the loop's condition and turns only
    /// the latch into a jump; `soup` is the full ladder a bad structurer emits;
    /// `rotated` is the bottom-tested form a compiler produces, which is the
    /// one whose CFG is *not* identical and which GED still cannot see.
    const GOTO_LATCHED: &str =
        "long factorial(int n){ long f=1; loop: if (n>1) { f*=n; n--; goto loop; } return f; }";
    const GOTO_SOUP: &str = "long factorial(int n){ long f=1;\n\
         loop: if (!(n>1)) goto done;\n\
         f*=n; n--; goto loop;\n\
         done: return f; }";
    const GOTO_ROTATED: &str = "long factorial(int n){ long f=1;\n\
         goto test;\n\
         body: f*=n; n--;\n\
         test: if (n>1) goto body;\n\
         return f; }";

    #[test]
    fn goto_ification_leaves_the_cfg_identical_and_moves_the_tree() {
        // The claim `structural-metrics.md` section 2.6 makes, on a real
        // function: tests/decbench_corpus/src/loops.c :: factorial,
        //
        //     long factorial(int n){ long f=1; while(n>1){ f*=n; n--; } return f; }
        //
        // and two goto rewrites of it. Both rewrites produce a control-flow
        // graph that is *identical* to the loop's --- the same node ids and the
        // same edge list, not merely isomorphic --- so GED scores both 0.0,
        // which is a perfect decompilation. The project records the same
        // blindness from the other direction: "Execution differential is blind
        // to structure --- goto soup passes every fixture".
        let text = fixture("tests/decbench_corpus/src/loops.c");
        let structured = projected(&text, "factorial");
        assert_eq!(
            structured.render(),
            "(seq assign (while assign expr) return)"
        );
        let structured_cfg = parity_cfgs(&text).remove("factorial").expect("a CFG");

        for (name, rewrite, expected_render, expected_distance) in [
            (
                "latched",
                GOTO_LATCHED,
                "(seq assign label (if (then assign expr goto)) return)",
                4u32,
            ),
            (
                "soup",
                GOTO_SOUP,
                "(seq assign label (if (then goto)) assign expr goto label return)",
                7,
            ),
        ] {
            let rewritten_cfg = parity_cfgs(rewrite).remove("factorial").expect("a CFG");
            assert_eq!(
                (&structured_cfg.nodes, &structured_cfg.edges),
                (&rewritten_cfg.nodes, &rewritten_cfg.edges),
                "the {name} rewrite must not change the CFG, or this proves nothing"
            );
            let graph = ged(
                &parity_ged(&text, "factorial"),
                &parity_ged(rewrite, "factorial"),
            );
            assert_eq!(
                (graph.value, graph.approximated),
                (0.0, false),
                "{name}: GED must call this a perfect decompilation"
            );

            let rewritten = projected(rewrite, "factorial");
            assert_eq!(rewritten.render(), expected_render, "{name}");
            let distance = tree_edit_distance(&structured, &rewritten).expect("both are small");
            assert_eq!(distance, expected_distance, "{name}");
            println!(
                "factorial/{name}: CFG identical, GED 0.0; skeleton {} -> {} nodes, TED {distance}, score {:?}",
                structured.len(),
                rewritten.len(),
                skeleton_score(&structured, &rewritten)
            );
        }

        // The bottom-tested rotation a compiler emits does *not* produce an
        // identical CFG --- and GED still scores it 0.0, because it preserves
        // the degree multiset. That is the `vj_ged` blindness measured in
        // `what-ged-measures.md` section 1, reproduced on real code.
        let rotated_cfg = parity_cfgs(GOTO_ROTATED)
            .remove("factorial")
            .expect("a CFG");
        assert_ne!(structured_cfg.edges, rotated_cfg.edges);
        let graph = ged(
            &parity_ged(&text, "factorial"),
            &parity_ged(GOTO_ROTATED, "factorial"),
        );
        assert_eq!(graph.value, 0.0);
        let rotated = projected(GOTO_ROTATED, "factorial");
        assert_eq!(
            tree_edit_distance(&structured, &rotated),
            Some(7),
            "the rotated form is as far from the loop as the soup is"
        );
    }

    #[test]
    fn goto_ification_saturates_the_normalized_score() {
        // The honest half, and a real weakness rather than a success. The score
        // is `1 - TED / |source|`, so a decompiled skeleton more than twice the
        // source's size lands at 0.0 whatever it did.
        //
        // `factorial` is 6 skeleton nodes. The latched rewrite costs 4 edits
        // and scores 0.33, which is informative. The soup costs 7, which is
        // past the source's own size, so it scores 0.0 --- and so does a
        // completely unrelated 200-diamond cascade 998 edits away. Above 2x
        // expansion this metric has no resolution left, and the raw distance
        // must be reported beside the score for that reason.
        let text = fixture("tests/decbench_corpus/src/loops.c");
        let structured = projected(&text, "factorial");
        let latched = projected(GOTO_LATCHED, "factorial");
        let soup = projected(GOTO_SOUP, "factorial");
        let unrelated = projected(
            &fixture("tests/decompiler_fixtures/src/151_wide_branch_ladder.c"),
            "big151_flat_cascade",
        );

        let latched_score = skeleton_score(&structured, &latched).expect("small");
        assert!((latched_score - 1.0 / 3.0).abs() < 1e-9);
        assert_eq!(skeleton_score(&structured, &soup), Some(0.0));
        assert_eq!(skeleton_score(&structured, &unrelated), Some(0.0));
        println!(
            "saturation: TED(factorial, latched) = {:?} -> {latched_score:.4}; \
             TED(factorial, soup) = {:?} -> 0.0; \
             TED(factorial, big151_flat_cascade) = {:?} -> 0.0",
            tree_edit_distance(&structured, &latched),
            tree_edit_distance(&structured, &soup),
            tree_edit_distance(&structured, &unrelated),
        );
    }

    #[test]
    fn a_pre_tested_and_a_post_tested_loop_are_different_skeletons() {
        // tests/decompiler_fixtures/src/03_loop_shapes.c ::
        // dowhile_atleastonce exists because a `do`-`while` lowered as a
        // `while` skips the first element. The two loop kinds are one relabel
        // apart, which is the smallest non-zero distance the metric has, and it
        // is a distance the CFG *can* also see --- this is a guard that the
        // canonicalization did not quietly merge them.
        let text = fixture("tests/decompiler_fixtures/src/03_loop_shapes.c");
        let post = projected(&text, "dowhile_atleastonce");
        let pre = projected(
            "int dowhile_atleastonce(const int *p) { int i = 0; int s = 0;\n\
             while (i < 8 && p[i - 1] > 0) { s += p[i]; i++; } return s * 10 + i; }",
            "dowhile_atleastonce",
        );
        assert_eq!(
            post.render(),
            "(seq assign assign (do_while assign expr) return)"
        );
        assert_eq!(
            pre.render(),
            "(seq assign assign (while assign expr) return)"
        );
        assert_eq!(tree_edit_distance(&post, &pre), Some(1));
    }

    // --- the measured ceiling ------------------------------------------------

    #[test]
    fn the_six_semantics_only_defect_classes_are_invisible_and_that_is_the_ceiling() {
        // `what-ged-measures.md` section 5: 795 mutations were applied and the
        // CFG metric detected 7. The six semantics-only classes change no
        // control-flow graph, and --- by construction, since the projection
        // drops every expression --- they change no control skeleton either.
        // Asserted rather than merely documented so that nobody can claim this
        // metric detects them.
        //
        // Base: tests/decompiler_fixtures/src/118_bit_tricks.c :: xor_swap.
        let text = fixture("tests/decompiler_fixtures/src/118_bit_tricks.c");
        let base = projected(&text, "xor_swap");
        let mutants = [
            // negate-condition
            ("negate-condition", "int32_t xor_swap(int32_t *left, int32_t *right) { if (!(left != 0 && right != 0 && left != right)) { return -1; } *left ^= *right; *right ^= *left; *left ^= *right; return *left - *right; }"),
            // relational-flip / equality-flip
            ("equality-flip", "int32_t xor_swap(int32_t *left, int32_t *right) { if (left != 0 || right != 0 || left != right) { return -1; } *left ^= *right; *right ^= *left; *left ^= *right; return *left - *right; }"),
            // constant-bump
            ("constant-bump", "int32_t xor_swap(int32_t *left, int32_t *right) { if (left == 0 || right == 0 || left == right) { return -2; } *left ^= *right; *right ^= *left; *left ^= *right; return *left - *right; }"),
            // arith-flip
            ("arith-flip", "int32_t xor_swap(int32_t *left, int32_t *right) { if (left == 0 || right == 0 || left == right) { return -1; } *left ^= *right; *right ^= *left; *left ^= *right; return *left + *right; }"),
        ];
        for (name, source) in mutants {
            let mutant = projected(source, "xor_swap");
            assert_eq!(
                tree_edit_distance(&base, &mutant),
                Some(0),
                "{name} must be invisible: it is, and that is the ceiling"
            );
        }
        // And a renaming, which is the property the projection exists for.
        let renamed = projected(
            "int32_t xor_swap(int32_t *a, int32_t *b) { if (a == 0 || b == 0 || a == b) { return -1; } *a ^= *b; *b ^= *a; *a ^= *b; return *a - *b; }",
            "xor_swap",
        );
        assert_eq!(tree_edit_distance(&base, &renamed), Some(0));
    }

    // --- the distance itself -------------------------------------------------

    #[test]
    fn the_distance_is_zero_only_on_identical_skeletons_and_is_symmetric() {
        // Over every function in the in-repo DecBench corpus: a metric that is
        // not symmetric, or that awards 0 to two different trees, is not a
        // distance and every number computed from it is meaningless.
        let mut projections: Vec<(String, Skeleton)> = Vec::new();
        for path in
            c_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decbench_corpus/src"))
        {
            let text = std::fs::read_to_string(&path).expect("a corpus file");
            for (name, projection) in skeletons(&text) {
                projections.push((format!("{}::{name}", path.display()), projection));
            }
        }
        assert!(
            projections.len() >= 30,
            "the in-repo corpus should hold at least 30 functions, found {}",
            projections.len()
        );
        let mut zero_pairs = 0;
        for left in 0..projections.len() {
            for right in 0..projections.len() {
                let forward = tree_edit_distance(&projections[left].1, &projections[right].1);
                let backward = tree_edit_distance(&projections[right].1, &projections[left].1);
                assert_eq!(forward, backward, "asymmetric on {left}/{right}");
                let Some(distance) = forward else { continue };
                if left == right {
                    assert_eq!(distance, 0, "a skeleton must be zero from itself");
                } else if distance == 0 {
                    assert_eq!(
                        projections[left].1.render(),
                        projections[right].1.render(),
                        "zero distance between different trees"
                    );
                    zero_pairs += 1;
                }
            }
        }
        println!(
            "in-repo corpus: {} functions, {} ordered pairs at distance 0",
            projections.len(),
            zero_pairs
        );
    }

    /// Levenshtein distance over two kind sequences, written the obvious way.
    ///
    /// An *independent* implementation, and the reason it is here: on a flat
    /// tree --- a root whose children are all leaves --- ordered tree edit
    /// distance reduces exactly to string edit distance over the children,
    /// because no subtree can be deleted without deleting its single node. So
    /// this is a check of the Zhang--Shasha DP against something that shares
    /// none of its code, on real skeletons rather than on a fixture.
    fn levenshtein(left: &[SkeletonKind], right: &[SkeletonKind]) -> u32 {
        let mut row: Vec<u32> = (0..=right.len() as u32).collect();
        for (i, a) in left.iter().enumerate() {
            let mut previous = row[0];
            row[0] = i as u32 + 1;
            for (j, b) in right.iter().enumerate() {
                let candidate = previous + u32::from(a != b);
                previous = row[j + 1];
                row[j + 1] = candidate.min(row[j] + 1).min(row[j + 1] + 1);
            }
        }
        row[right.len()]
    }

    #[test]
    fn the_distance_matches_string_edit_distance_on_every_flat_skeleton() {
        // The branchless class is exactly the flat skeletons --- a `Seq` root
        // over leaves --- so this validates the DP on the population the metric
        // exists to separate, against an implementation that shares no code
        // with it.
        let mut flat: Vec<Skeleton> = Vec::new();
        for path in
            c_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/src"))
        {
            let text = std::fs::read_to_string(&path).expect("a corpus file");
            for projection in skeletons(&text).into_values() {
                if projection.depth() == 2 && projection.len() <= 64 {
                    flat.push(projection);
                }
            }
        }
        assert!(
            flat.len() > 100,
            "expected a large flat population, found {}",
            flat.len()
        );
        let mut checked = 0usize;
        for left in 0..flat.len() {
            for right in 0..flat.len() {
                // The children of a flat tree are its kinds minus the root,
                // which post-order puts last.
                let a = &flat[left].kinds()[..flat[left].len() - 1];
                let b = &flat[right].kinds()[..flat[right].len() - 1];
                assert_eq!(
                    tree_edit_distance(&flat[left], &flat[right]),
                    Some(levenshtein(a, b)),
                    "Zhang-Shasha disagrees with string edit distance on a flat pair"
                );
                checked += 1;
            }
        }
        println!("flat skeletons cross-checked against Levenshtein: {checked} pairs");
    }

    #[test]
    fn the_distance_agrees_with_edits_counted_by_hand() {
        // Four cases small enough to count by eye, so a DP that is subtly wrong
        // in the nested case cannot hide behind a corpus statistic.
        let cases = [
            // one leaf inserted
            (
                "int f(void){ return 0; }",
                "int f(void){ x = 1; return 0; }",
                1u32,
            ),
            // two leaves inserted
            ("int f(void){ ; }", "int f(void){ x = 1; y = 2; }", 2),
            // one relabel: `while` becomes `do`-`while`
            (
                "int f(int c){ while (c) return 0; }",
                "int f(int c){ do return 0; while (c); }",
                1,
            ),
            // the `if` and its `then` deleted, the body kept
            (
                "int f(int c){ if (c) return 0; }",
                "int f(int c){ return 0; }",
                2,
            ),
            // a whole three-node subtree deleted
            (
                "int f(int c){ x = 1; while (c) { y = 2; } return 0; }",
                "int f(int c){ x = 1; return 0; }",
                2,
            ),
        ];
        for (left, right, expected) in cases {
            let a = projected(left, "f");
            let b = projected(right, "f");
            assert_eq!(
                tree_edit_distance(&a, &b),
                Some(expected),
                "{} vs {}",
                a.render(),
                b.render()
            );
        }
    }

    #[test]
    fn the_distance_stays_inside_its_arithmetic_bounds_on_the_corpus() {
        // `abs(|a| - |b|) <= d <= |a| + |b|` for unit costs. A DP that reads an
        // uninitialized cell or indexes the wrong window breaks one of these
        // long before it breaks symmetry.
        let mut projections: Vec<Skeleton> = Vec::new();
        for path in
            c_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decbench_corpus/src"))
        {
            let text = std::fs::read_to_string(&path).expect("a corpus file");
            projections.extend(skeletons(&text).into_values());
        }
        for a in &projections {
            for b in &projections {
                let distance = tree_edit_distance(a, b).expect("small skeletons");
                let lower = a.len().abs_diff(b.len()) as u32;
                let upper = (a.len() + b.len()) as u32;
                assert!(
                    (lower..=upper).contains(&distance),
                    "{distance} outside [{lower}, {upper}] for {} vs {}",
                    a.render(),
                    b.render()
                );
            }
        }
    }

    #[test]
    fn the_triangle_inequality_holds_on_real_skeletons() {
        // Unit edit costs make the distance a metric; if a change to the cost
        // model ever breaks that, every aggregate over it becomes unsound.
        let text = fixture("tests/decbench_corpus/src/loops.c");
        let all: Vec<Skeleton> = skeletons(&text).into_values().collect();
        assert!(all.len() >= 3);
        for a in 0..all.len() {
            for b in 0..all.len() {
                for c in 0..all.len() {
                    let (ab, bc, ac) = (
                        tree_edit_distance(&all[a], &all[b]).unwrap(),
                        tree_edit_distance(&all[b], &all[c]).unwrap(),
                        tree_edit_distance(&all[a], &all[c]).unwrap(),
                    );
                    assert!(ac <= ab + bc, "triangle broken at {a},{b},{c}");
                }
            }
        }
    }

    #[test]
    fn an_oversized_skeleton_abstains_rather_than_answering_wrong() {
        // `crate::metrics`: a non-answer is a value. The alternative --- a
        // cheaper fallback distance --- is what put a size-delta number into
        // DecBench's own `ged` column above its node cap, where it is not the
        // metric and reads as if it were.
        let huge = Skeleton {
            kinds: vec![SkeletonKind::Expr; MAX_SKELETON_NODES + 1],
            left: vec![0; MAX_SKELETON_NODES + 1],
            keyroots: vec![0],
            depth: 1,
            truncated: false,
        };
        let small = projected("int f(void) { return 0; }", "f");
        assert_eq!(tree_edit_distance(&huge, &small), None);
        assert_eq!(tree_edit_distance(&small, &huge), None);
        assert_eq!(skeleton_score(&small, &huge), None);
    }

    #[test]
    fn a_function_with_no_body_is_the_empty_skeleton_and_still_has_a_distance() {
        // A declaration yields no `FunctionDef`, but a recovered parse can hand
        // back a definition whose body never closed. That is a value, not a
        // failure.
        let empty = Skeleton {
            kinds: Vec::new(),
            left: Vec::new(),
            keyroots: Vec::new(),
            depth: 0,
            truncated: false,
        };
        let small = projected("int f(void) { return 0; }", "f");
        assert!(empty.is_empty());
        assert_eq!(tree_edit_distance(&empty, &small), Some(2));
        assert_eq!(tree_edit_distance(&small, &empty), Some(2));
        assert_eq!(skeleton_score(&empty, &small), Some(0.0));
        assert_eq!(skeleton_score(&empty, &empty), Some(1.0));
        assert_eq!(skeleton_score(&small, &empty), Some(0.0));
    }

    // --- robustness ----------------------------------------------------------

    #[test]
    fn deeply_nested_input_does_not_touch_the_native_stack() {
        // `REQ-GEN-4` / `REQ-SYN-3`, and the adversarial case this repository
        // has precedent for: decompiler output has attacker-controlled nesting
        // depth. A recursive projection or a recursive post-order aborts the
        // process here, and a process that aborts reports nothing.
        const DEPTH: usize = 20_000;
        for (name, text) in [
            (
                "blocks",
                format!(
                    "int f(void) {{ {}x = 1;{} }}",
                    "{".repeat(DEPTH),
                    "}".repeat(DEPTH)
                ),
            ),
            (
                "ifs",
                format!(
                    "int f(int c) {{ {}x = 1;{} return 0; }}",
                    "if (c) {".repeat(DEPTH),
                    "}".repeat(DEPTH)
                ),
            ),
            (
                "else-if chain",
                format!(
                    "int f(int c) {{ if (c) return 0; {} return 1; }}",
                    "else if (c) return 0;".repeat(DEPTH)
                ),
            ),
            (
                "parens",
                format!(
                    "int f(void) {{ return {}1{}; }}",
                    "(".repeat(DEPTH),
                    ")".repeat(DEPTH)
                ),
            ),
            (
                "statements",
                format!("int f(void) {{ {} }}", "x = 1;".repeat(DEPTH)),
            ),
        ] {
            let projection = projected(&text, "f");
            println!(
                "{name}: {} nodes, depth {}, {} keyroots, truncated {}",
                projection.len(),
                projection.depth(),
                projection.keyroot_count(),
                projection.truncated()
            );
            // `render` and `children` walk the same tree and must not recurse
            // either.
            let _ = projection.render().len();
            // The distance is deliberately NOT called on these: at 40,000
            // nodes the two `u32` tables would be 12.8 GB, and the point of
            // [`MAX_SKELETON_NODES`] is that nothing ever asks for them.
            // `an_oversized_skeleton_abstains_rather_than_answering_wrong` is
            // where the abstention is asserted, on a skeleton one node over
            // the cap rather than twenty times it.
            assert!(
                projection.len() <= 2 || projection.len() > MAX_SKELETON_NODES,
                "{name}: {} nodes, which is neither trivial nor over the cap",
                projection.len()
            );
        }
    }

    #[test]
    fn no_input_panics_and_every_input_terminates() {
        // `REQ-SYN-2`. The same hostile list the parser holds itself to, plus
        // the shapes that are specific to this module: an `else` with no `if`,
        // a `case` outside a switch, a `for` with empty clauses.
        for text in [
            "",
            " ",
            "\0",
            "int",
            "int f(",
            "{",
            "}",
            ")",
            ";;;;",
            "int f(void){",
            "int f(void){ else {} }",
            "int f(void){ case 1: }",
            "int f(void){ for(;;); }",
            "int f(void){ for(;;){} }",
            "int f(void){ do ; while(0); }",
            "int f(void){ switch(x); }",
            "int f(void){ if (x) ; else ; }",
            "int f(void){ goto; }",
            "int f(void){ L: }",
            "int f(void){ int a, b = 1, c = 2; }",
            "int f(void){ @@@ }",
            "int f(void){ asm(\"nop\"); }",
            "int \u{4e2d}(void){}",
            "\u{80}\u{81}",
        ] {
            let projections = skeletons(text);
            for projection in projections.values() {
                let _ = projection.render();
                let _ = projection.census();
                let _ = tree_edit_distance(projection, projection);
            }
        }
    }

    #[test]
    fn the_projection_is_deterministic_across_repeated_parses() {
        // `REQ-SYN-5`. Every gate in this programme is a diff.
        let text = fixture("tests/decbench_corpus/src/statemachine.c");
        let first = skeletons(&text);
        for _ in 0..4 {
            assert_eq!(skeletons(&text), first);
        }
    }

    // --- validation 3: the distribution over a real corpus slice ---------------

    #[test]
    fn the_in_repo_corpus_projects_and_reports_its_distribution() {
        // The always-available slice: every `.c` file under
        // tests/decompiler_fixtures/src and tests/decbench_corpus/src. Real
        // hand-written C rather than decompiler output, so it is the *source*
        // side of the metric and the branchless share here is not the corpus
        // figure --- see the published-samples test for that.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for relative in ["tests/decompiler_fixtures/src", "tests/decbench_corpus/src"] {
            files.extend(c_files(&root.join(relative)));
        }
        if files.is_empty() {
            println!("SKIP: no in-repo C corpus under {}", root.display());
            return;
        }
        let started = std::time::Instant::now();
        let mut sizes = Vec::new();
        let mut depths = Vec::new();
        let mut keyroots = Vec::new();
        let mut branchless = 0usize;
        let mut over_cap = 0usize;
        let mut kinds: BTreeMap<SkeletonKind, usize> = BTreeMap::new();
        let mut biggest = (0usize, String::new());
        for path in &files {
            let text = std::fs::read_to_string(path).expect("a corpus file");
            for (name, projection) in skeletons(&text) {
                sizes.push(projection.len());
                depths.push(projection.depth() as usize);
                keyroots.push(projection.keyroot_count());
                if projection.is_branchless() {
                    branchless += 1;
                }
                if projection.len() > MAX_SKELETON_NODES {
                    over_cap += 1;
                }
                for (kind, count) in projection.census() {
                    *kinds.entry(kind).or_insert(0) += count;
                }
                if projection.len() > biggest.0 {
                    biggest = (projection.len(), format!("{}::{name}", path.display()));
                }
                assert!(!projection.truncated(), "{name} exhausted the step budget");
            }
        }
        let elapsed = started.elapsed();
        sizes.sort_unstable();
        depths.sort_unstable();
        keyroots.sort_unstable();
        println!(
            "in-repo corpus: {} files, {} functions, projected in {elapsed:?}",
            files.len(),
            sizes.len()
        );
        println!(
            "  skeleton nodes  min={} p50={} p90={} p99={} max={}",
            sizes[0],
            quantile(&sizes, 0.5),
            quantile(&sizes, 0.9),
            quantile(&sizes, 0.99),
            sizes[sizes.len() - 1]
        );
        println!(
            "  depth           p50={} p90={} max={}",
            quantile(&depths, 0.5),
            quantile(&depths, 0.9),
            depths[depths.len() - 1]
        );
        println!(
            "  keyroots        p50={} p90={} max={}",
            quantile(&keyroots, 0.5),
            quantile(&keyroots, 0.9),
            keyroots[keyroots.len() - 1]
        );
        println!(
            "  branchless      {branchless} / {} ({:.2}%)",
            sizes.len(),
            100.0 * branchless as f64 / sizes.len() as f64
        );
        println!("  over the cap    {over_cap}  (cap = {MAX_SKELETON_NODES})");
        println!("  largest         {} ({} nodes)", biggest.1, biggest.0);
        for (kind, count) in &kinds {
            println!("  {:<10} {count}", kind.name());
        }
        // Every construct in the alphabet must appear somewhere in a corpus
        // this size, or the projection has a branch nothing exercises.
        for kind in SkeletonKind::ALL {
            assert!(
                kinds.contains_key(kind),
                "no in-repo function projects a `{}` node",
                kind.name()
            );
        }
    }

    #[test]
    fn the_published_samples_are_the_corpus_this_metric_was_argued_from() {
        // The real source-to-decompiled measurement, over the 300 `samples`
        // records of the materialized DecBench tree --- each carrying one
        // benchmark function's real `source_code` and every decompiler's output
        // for it. **No DecBench pipeline and no Joern process runs here**: this
        // reads a published JSON file and Glaurung's own C front end.
        //
        // Opt-in: it is minutes of work in a debug build, so it is gated rather
        // than merely slow. Run it with
        //
        //     GLAURUNG_METRICS_FULL_CORPUS=1 cargo test --features python-ext \
        //         --lib metrics::tree_distance -- --nocapture
        if std::env::var("GLAURUNG_METRICS_FULL_CORPUS").is_err() {
            println!("SKIP: set GLAURUNG_METRICS_FULL_CORPUS=1 to run the published-samples lane");
            return;
        }
        let Ok(home) = std::env::var("HOME") else {
            println!("SKIP: no HOME");
            return;
        };
        let path = PathBuf::from(home)
            .join(".cache/glaurung/decbench-full/published_function_results.json");
        if !path.exists() {
            println!("SKIP: no published results at {}", path.display());
            return;
        }
        let bytes = std::fs::read(&path).expect("a readable published-results file");
        let Some(slice) = samples_slice(&bytes) else {
            println!("SKIP: no `samples` array in {}", path.display());
            return;
        };
        let samples: Vec<Sample> = serde_json::from_slice(slice).expect("a well-formed array");
        println!("published samples: {}", samples.len());

        let null = projected("int f(void) { return 0; }", "f");
        let mut sizes = Vec::new();
        let mut depths = Vec::new();
        let mut branchless: Vec<Skeleton> = Vec::new();
        let mut distances = Vec::new();
        let mut abstentions = 0usize;
        let mut null_scores = Vec::new();
        let mut per_column: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        let (mut source_bare, mut source_nodes) = (0usize, 0usize);
        let (mut decompiled_bare, mut decompiled_nodes) = (0usize, 0usize);
        let mut offered = 0usize;
        let mut unresolved: BTreeMap<String, usize> = BTreeMap::new();
        let started = std::time::Instant::now();
        for sample in &samples {
            let Some(source) = one(&sample.source_code, &sample.function) else {
                continue;
            };
            sizes.push(source.len());
            depths.push(source.depth() as usize);
            if source.is_branchless() {
                branchless.push(source.clone());
            }
            if let Some(score) = skeleton_score(&source, &null) {
                null_scores.push(score);
            }
            if let Some((bare, nodes)) = bare_declarations(&sample.source_code, &sample.function) {
                source_bare += bare;
                source_nodes += nodes;
            }
            for (column, code) in &sample.decompiled {
                offered += 1;
                let Some(decompiled) = one(code, &sample.function) else {
                    // The caveat `structural-metrics.md` section 4 carries: the
                    // decompiled side of the distance is only as good as the
                    // parse, and a column this front end cannot resolve a
                    // definition in is scored by nobody.
                    *unresolved.entry(column.clone()).or_insert(0usize) += 1;
                    continue;
                };
                if let Some((bare, nodes)) = bare_declarations(code, &sample.function) {
                    decompiled_bare += bare;
                    decompiled_nodes += nodes;
                }
                match tree_edit_distance(&source, &decompiled) {
                    Some(distance) => {
                        distances.push(distance as usize);
                        per_column
                            .entry(column.clone())
                            .or_default()
                            .push(skeleton_score(&source, &decompiled).expect("not abstained"));
                    }
                    None => abstentions += 1,
                }
            }
        }
        let elapsed = started.elapsed();
        sizes.sort_unstable();
        depths.sort_unstable();
        distances.sort_unstable();

        println!("resolved source functions: {}", sizes.len());
        println!(
            "  skeleton nodes p50={} p90={} p99={} max={}",
            quantile(&sizes, 0.5),
            quantile(&sizes, 0.9),
            quantile(&sizes, 0.99),
            sizes[sizes.len() - 1]
        );
        println!(
            "  depth p50={} p90={} max={}",
            quantile(&depths, 0.5),
            quantile(&depths, 0.9),
            depths[depths.len() - 1]
        );
        println!(
            "  branchless (the single-node CFG class): {} / {} ({:.2}%)",
            branchless.len(),
            sizes.len(),
            100.0 * branchless.len() as f64 / sizes.len() as f64
        );
        println!(
            "  over the cap: {} of {}   abstentions: {} of {} pairs ({:.2}%)",
            sizes.iter().filter(|n| **n > MAX_SKELETON_NODES).count(),
            sizes.len(),
            abstentions,
            abstentions + distances.len(),
            100.0 * abstentions as f64 / (abstentions + distances.len()) as f64
        );
        println!(
            "  source-to-decompiled distances: n={} p10={} p50={} p90={} max={}, zero {} ({:.2}%)  [{elapsed:?}]",
            distances.len(),
            quantile(&distances, 0.10),
            quantile(&distances, 0.50),
            quantile(&distances, 0.90),
            distances[distances.len() - 1],
            distances.iter().filter(|d| **d == 0).count(),
            100.0 * distances.iter().filter(|d| **d == 0).count() as f64 / distances.len() as f64
        );
        println!(
            "  bare declarations per skeleton node: source {:.3} ({source_bare}/{source_nodes}), decompiled {:.3} ({decompiled_bare}/{decompiled_nodes})",
            source_bare as f64 / source_nodes.max(1) as f64,
            decompiled_bare as f64 / decompiled_nodes.max(1) as f64
        );
        println!(
            "  NULL DECOMPILER baseline: n={} mean={:.4} exact={:.2}%",
            null_scores.len(),
            null_scores.iter().sum::<f64>() / null_scores.len() as f64,
            100.0 * null_scores.iter().filter(|s| **s >= 1.0).count() as f64
                / null_scores.len() as f64
        );

        // The separation claim, on the real class rather than on three
        // hand-picked functions: every member of this set is one and the same
        // CFG to GED.
        let mut renders: std::collections::BTreeSet<String> = Default::default();
        for projection in &branchless {
            renders.insert(projection.render());
        }
        let mut pairs = Vec::new();
        for left in 0..branchless.len() {
            for right in (left + 1)..branchless.len() {
                if let Some(distance) = tree_edit_distance(&branchless[left], &branchless[right]) {
                    pairs.push(distance as usize);
                }
            }
        }
        pairs.sort_unstable();
        println!(
            "  branchless class: {} functions, {} distinct skeletons; pairwise TED n={} zero={} ({:.2}%) p50={} p90={} max={}",
            branchless.len(),
            renders.len(),
            pairs.len(),
            pairs.iter().filter(|d| **d == 0).count(),
            100.0 * pairs.iter().filter(|d| **d == 0).count() as f64 / pairs.len() as f64,
            quantile(&pairs, 0.5),
            quantile(&pairs, 0.9),
            pairs[pairs.len() - 1]
        );

        println!(
            "  decompiled columns offered: {offered}; unresolved by this front end: {} ({:.2}%)",
            unresolved.values().sum::<usize>(),
            100.0 * unresolved.values().sum::<usize>() as f64 / offered.max(1) as f64
        );
        println!(
            "  {:<14} {:>6} {:>8} {:>9} {:>11}",
            "column", "n", "mean", "exact%", "unresolved"
        );
        for (column, scores) in &per_column {
            println!(
                "  {:<14} {:>6} {:>8.4} {:>8.2}% {:>11}",
                column,
                scores.len(),
                scores.iter().sum::<f64>() / scores.len() as f64,
                100.0 * scores.iter().filter(|s| **s >= 1.0).count() as f64 / scores.len() as f64,
                unresolved.get(column).copied().unwrap_or(0)
            );
        }
        assert!(
            renders.len() > 1,
            "the single-node class must be separated, not merely measured"
        );
    }

    // --- the published-samples reader ----------------------------------------

    /// One `samples` record: the fields this measurement reads and no others.
    #[derive(serde::Deserialize)]
    struct Sample {
        function: String,
        source_code: String,
        /// Each decompiler column's output for the same function.
        #[serde(default)]
        decompiled: BTreeMap<String, String>,
    }

    /// The `samples` array, sliced out of the published results by a bracket
    /// scan.
    ///
    /// The file's `groups` section contains bare `Infinity` literals, which are
    /// not JSON and which `serde_json` rightly refuses, so the whole document
    /// cannot be deserialized. The `samples` array is well-formed; this finds
    /// its extent without interpreting anything else, and returns `None` rather
    /// than panicking on a file that does not have one.
    fn samples_slice(bytes: &[u8]) -> Option<&[u8]> {
        let key = b"\"samples\"";
        let at = bytes.windows(key.len()).position(|window| window == key)?;
        let start = at + bytes[at..].iter().position(|byte| *byte == b'[')?;
        let (mut depth, mut in_string, mut escaped) = (0i32, false, false);
        for (offset, byte) in bytes[start..].iter().enumerate() {
            if in_string {
                match byte {
                    _ if escaped => escaped = false,
                    b'\\' => escaped = true,
                    b'"' => in_string = false,
                    _ => {}
                }
                continue;
            }
            match byte {
                b'"' => in_string = true,
                b'[' => depth += 1,
                b']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&bytes[start..=start + offset]);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// The skeleton of one named function in `text`, or `None` when the parse
    /// did not recover a definition of that name.
    fn one(text: &str, name: &str) -> Option<Skeleton> {
        skeletons(text).remove(name)
    }

    /// How many declarators of one function declare without initializing, and
    /// how many skeleton nodes the function has.
    ///
    /// The measurement behind the "declarations with no initializer are
    /// dropped" rule in the module docs.
    fn bare_declarations(text: &str, name: &str) -> Option<(usize, usize)> {
        let tree = parse(text).into_parts().0;
        let function = tree.functions(text).into_iter().find(|f| f.name == name)?;
        let body = function.body?;
        let arena = tree.arena();
        let mut bare = 0usize;
        for node in arena.preorder(body) {
            if arena.tag(node) != Some(NodeTag::Decl.as_u16()) {
                continue;
            }
            let initializers = arena
                .children_iter(node)
                .filter(|child| arena.tag(*child) == Some(NodeTag::Initializer.as_u16()))
                .count();
            let declarators = arena
                .children_iter(node)
                .filter(|child| arena.tag(*child) == Some(NodeTag::Declarator.as_u16()))
                .count();
            bare += declarators.saturating_sub(initializers);
        }
        Some((bare, skeleton(&tree, &function).len()))
    }
}
