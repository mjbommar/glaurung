//! The per-function pre-pass: which statements control can reach, which
//! subtrees contain a jump target, and which contain a short-circuit operator.
//!
//! Spec: `docs/design/static-c-analysis/requirements.md` `REQ-GEN-1` (every
//! node is reachable from the entry), `REQ-CFG-6` (the short-circuit operators
//! are control flow) and `REQ-CFG-7` (a computed `goto`'s target set).
//!
//! # Why the emitter needs an answer before it emits
//!
//! Two of the emitter's decisions cannot be made from the statement in front
//! of it:
//!
//! * **Is this statement reachable?** `REQ-GEN-1`'s first invariant --- every
//!   node is reachable from the entry --- is false of any graph that gives a
//!   node to the `foo();` in `return 0; foo();`. C source really does contain
//!   such text, and decompiler output contains a great deal of it, so the
//!   emitter has to know that control cannot arrive before it places the node.
//!   That means knowing whether the *previous* statement falls through, which
//!   for an `if` or a `switch` is a property of its whole subtree.
//! * **Does this subtree still need emitting even though control cannot fall
//!   into it?** A `goto` target or a `case` label is reached without falling
//!   through, so a statement list that is dead becomes live again at one.
//!
//! Both are whole-subtree questions, so both are answered once here rather than
//! rediscovered per statement --- which would make the emitter quadratic in
//! nesting depth. [`Reach::sc_in`] is the third question, asked for the same
//! reason: `REQ-CFG-6` makes the emitter walk into an expression only where a
//! short-circuit operator actually lives, and a per-node scan for one would be
//! quadratic in expression depth.
//!
//! # Why the label set is a fixpoint and not a scan
//!
//! "Which labels are jump targets" and "which statements are reachable" define
//! each other: a label is a target only if some *reachable* `goto` names it,
//! and a `goto` is reachable only if the statements before it are. Taking every
//! `goto` in the text at face value keeps whole regions of decompiler output
//! alive through a jump that itself can never run --- measured, on one 14-file
//! lane of stored `zlib` output, as 4,028 unreachable nodes descending from a
//! single dead `goto` in `inflate`.
//!
//! So the set is computed by iterating from *nothing* upwards: with no label a
//! target, find the reachable `goto`s; make their labels targets; repeat. The
//! set only grows, so the iteration terminates, and it terminates at the
//! smallest set consistent with itself. A pathological goto chain that has not
//! settled within [`MAX_LIVE_ROUNDS`] falls back to treating every label as a
//! target, which is the answer that suppresses nothing.
//!
//! # No native recursion
//!
//! Node ids are dense in *preorder* (`crate::syntax::tree`'s sink assigns one
//! on `open`), so a subtree occupies a contiguous ascending id range and a
//! parent's id is always below its children's. Visiting the function's nodes in
//! descending id order therefore visits every child before its parent, which is
//! a post-order fold without a stack of frames and without recursion
//! (`REQ-GEN-4`, `REQ-SYN-3`). The ordering is re-derived by sorting rather
//! than assumed, so a tree that violated the invariant would produce
//! conservative answers rather than wrong ones. The top-down half is an
//! ordinary explicit-stack walk.
//!
//! # The one caller that wants the opposite answer
//!
//! [`Coverage`] is the switch. `REQ-GEN-1` is the right rule for every consumer
//! of the *general* graph, and it stays the default. It is the wrong rule for
//! exactly one caller: [`crate::csource::joern`], whose whole job is to
//! reproduce a tool whose CFG construction is syntax-directed and therefore
//! keeps what control cannot reach. Measured on the published DecBench source
//! CFGs, 105 of 91,548 functions carry a component with no path from the entry,
//! so the difference is Joern's, not a defect in its export; on decompiler
//! output it is very large indeed, because a decompiler that loses a jump-table
//! dispatch strands every arm. `O0 openssh-portable sshd`
//! `process_server_config_line_depth` parses clean into 1,133 statements, of
//! which the fixpoint proves 194 reachable through 13 of its 129 labels ---
//! a graph of 48 blocks where Joern's is around 435.
//!
//! [`Coverage::Syntactic`] is therefore not "turn the analysis off". It is
//! "answer the emitter's second question with *yes* everywhere": every
//! statement is a place control can arrive, so the emitter walks into all of
//! them and their fall-through wiring composes exactly the way a
//! syntax-directed builder's does. Everything else this pass answers ---
//! short-circuits, initializers, `case`/`break`/`continue` binding, the
//! computed-`goto` target set --- is unchanged, because none of it is a
//! reachability question.

use std::collections::BTreeSet;

use crate::csource::lex::TokenKind;
use crate::csource::parse::tag::NodeTag;
use crate::csource::parse::Tree;
use crate::syntax::ids::{NodeId, Span, TokenId};

use super::expr::{is_unevaluated, logical_kind};
use super::{bodies, goto_label, tag_of};

/// How many times the reachable-label fixpoint may iterate.
///
/// Each round makes every label named by a reachable `goto` a target, so the
/// number of rounds a function needs is the depth of its `goto` chain --- one
/// or two for source C, a handful for the goto webs a decompiler emits. Sixteen
/// is far above what either corpus reaches, and exceeding it costs
/// conservatism, not correctness: the fallback is to treat every label as a
/// target, which is exactly the behaviour of not doing the analysis at all.
const MAX_LIVE_ROUNDS: usize = 64;

/// Which statements the emitter is asked to place a node for.
///
/// This is a property of the *consumer*, not of the C: the same function has
/// both graphs, and which one is wanted depends on what the caller is going to
/// do with it. Making it an argument rather than two emitters is what keeps
/// `docs/design/static-c-analysis/architecture.md` section 1's rule --- the
/// parity layer's quirks must not leak into the general graph --- true by
/// construction: the default is the only behaviour any general consumer can
/// obtain, and the variant is named after what it does rather than after the
/// tool that wants it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Coverage {
    /// Only statements control can reach (`REQ-GEN-1`), which is what makes
    /// [`crate::syntax::cfg::Cfg::validate`] pass and what every consumer of
    /// the general graph --- the C-to-LLIR lowering, the structural gates ---
    /// is entitled to assume.
    #[default]
    Reachable,
    /// Every statement in the text, whether control can arrive or not, wired
    /// the way a syntax-directed builder wires it: an unreachable region
    /// becomes a component with no path from the entry rather than nothing.
    ///
    /// A graph built this way deliberately fails `REQ-GEN-1`, so it is for
    /// callers that do not validate --- today, only
    /// [`crate::csource::joern`].
    Syntactic,
}

/// Whether `tag` names something the emitter treats as a statement body.
///
/// The three `for` clause tags are statements by [`NodeTag::is_statement`] ---
/// they sit inside the statement range of the tag table --- but they are parts
/// of a `for` header, not its body, so every "which child is the body" question
/// has to exclude them. [`NodeTag::Error`] is included because `REQ-CFG-11`
/// makes an unparsed region keep its node, and a recovered `if` whose arm is an
/// error node still has an arm.
pub(super) fn is_body(tag: NodeTag) -> bool {
    match tag {
        NodeTag::ForInit | NodeTag::ForCond | NodeTag::ForStep => false,
        NodeTag::Error => true,
        other => other.is_statement(),
    }
}

/// Whether `tag` opens a construct a `break` binds to.
fn binds_break(tag: NodeTag) -> bool {
    matches!(
        tag,
        NodeTag::WhileStmt | NodeTag::DoWhileStmt | NodeTag::ForStmt | NodeTag::SwitchStmt
    )
}

/// Whether `tag` opens a construct a `continue` binds to.
fn binds_continue(tag: NodeTag) -> bool {
    matches!(
        tag,
        NodeTag::WhileStmt | NodeTag::DoWhileStmt | NodeTag::ForStmt
    )
}

/// The answers the emitter needs about every node of one function body.
///
/// Parallel bit vectors indexed by node id minus the body's id. They are
/// separate vectors rather than one struct-of-flags per node because each is
/// read in a different place and a `Vec<bool>` costs one byte per node per
/// question --- a few tens of kilobytes for the largest function in either
/// corpus.
pub(super) struct Reach {
    /// Which statements the emitter was asked to place.
    coverage: Coverage,
    /// The lowest node id these vectors describe: the function body's own id.
    base: u32,
    /// Whether control can continue past this statement.
    falls: Vec<bool>,
    /// Whether this subtree defines a label some reachable `goto` names.
    label_in: Vec<bool>,
    /// Whether this subtree carries a `case` or `default` label bound to an
    /// enclosing switch.
    case_in: Vec<bool>,
    /// Whether this subtree carries a `break` bound to an enclosing construct.
    break_in: Vec<bool>,
    /// Whether this subtree carries a `continue` bound to an enclosing loop.
    continue_in: Vec<bool>,
    /// Whether this subtree carries a `default` label bound to an enclosing
    /// switch.
    default_in: Vec<bool>,
    /// Whether this subtree carries an evaluated `&&`, `||` or `?:`.
    sc_in: Vec<bool>,
    /// Whether this declaration subtree carries an initializer, which is what
    /// `REQ-CFG-3` makes the difference between a node and nothing.
    init_in: Vec<bool>,
    /// Every label whose address is taken with GNU `&&label`, in source order:
    /// the target set of a computed `goto` (`REQ-CFG-7`).
    address_taken: Vec<String>,
}

/// One `goto` and what it names: `None` is the computed form.
struct Jump {
    node: NodeId,
    label: Option<String>,
}

impl Reach {
    /// Fold every question over the subtree rooted at `body`.
    ///
    /// `spans` is the tree's token span table, hoisted by the caller: label
    /// names are read out of the source text, and re-lexing the file per
    /// function to get one identifier back would make the whole pass quadratic
    /// in the number of functions.
    pub(super) fn new(tree: &Tree, text: &str, spans: &[Span], body: NodeId) -> Self {
        Self::with_coverage(tree, text, spans, body, Coverage::Reachable)
    }

    /// Fold every question over `body`, answering the reachability one the way
    /// `coverage` asks.
    ///
    /// Under [`Coverage::Syntactic`] the fixpoint is skipped outright rather
    /// than run and discarded: with every statement an entry point there is no
    /// dead `goto` for it to prove dead, so its answer could only ever be the
    /// full label set it is handed here. Skipping it also removes the one place
    /// this pass is superlinear in a goto web's depth, which is why the mode is
    /// cheaper than the default rather than more expensive.
    pub(super) fn with_coverage(
        tree: &Tree,
        text: &str,
        spans: &[Span],
        body: NodeId,
        coverage: Coverage,
    ) -> Self {
        let arena = tree.arena();
        let mut order: Vec<NodeId> = arena.preorder(body).collect();
        // Descending id order is post-order; see the module docs. Sorted rather
        // than assumed so a tree that broke the invariant degrades to
        // conservative answers.
        order.sort_unstable_by_key(|node| std::cmp::Reverse(node.raw()));
        let base = body.raw();
        let hi = order.iter().map(|n| n.raw()).max().unwrap_or(base);
        let len = hi.saturating_sub(base).saturating_add(1) as usize;

        let mut jumps: Vec<Jump> = Vec::new();
        let mut labels: BTreeSet<String> = BTreeSet::new();
        let mut address_taken: Vec<String> = Vec::new();
        // Ascending, so `address_taken` is in source order (`REQ-SYN-5`).
        for &node in order.iter().rev() {
            match tag_of(tree, node) {
                Some(NodeTag::GotoStmt) => jumps.push(Jump {
                    node,
                    label: goto_label(tree, text, spans, node),
                }),
                Some(NodeTag::LabelStmt) => {
                    labels.insert(name_after(tree, text, spans, node, 0));
                }
                Some(NodeTag::LabelAddr) => {
                    let name = name_after(tree, text, spans, node, 1);
                    if !address_taken.contains(&name) {
                        address_taken.push(name);
                    }
                }
                _ => {}
            }
        }

        let mut reach = Self {
            coverage,
            base,
            falls: vec![true; len],
            label_in: vec![false; len],
            case_in: vec![false; len],
            break_in: vec![false; len],
            continue_in: vec![false; len],
            default_in: vec![false; len],
            sc_in: vec![false; len],
            init_in: vec![false; len],
            address_taken,
        };

        if coverage == Coverage::Syntactic {
            reach.fold(tree, text, spans, &order, &labels);
            return reach;
        }

        let mut targeted: BTreeSet<String> = BTreeSet::new();
        for _ in 0..MAX_LIVE_ROUNDS {
            reach.fold(tree, text, spans, &order, &targeted);
            let live = reach.simulate(tree, body);
            let next = reach.targets_of_live_jumps(&jumps, &live);
            if next == targeted {
                return reach;
            }
            targeted = next;
        }
        // A goto chain deeper than the round limit: keep every label, which
        // suppresses nothing and leaves every `goto` resolvable.
        reach.fold(tree, text, spans, &order, &labels);
        reach
    }

    /// Recompute every vector for one candidate set of jump targets.
    fn fold(
        &mut self,
        tree: &Tree,
        text: &str,
        spans: &[Span],
        order: &[NodeId],
        targeted: &BTreeSet<String>,
    ) {
        let arena = tree.arena();
        for &node in order {
            let Some(tag) = tag_of(tree, node) else {
                continue;
            };
            let Some(slot) = self.slot(node) else {
                continue;
            };
            let mut label = matches!(tag, NodeTag::LabelStmt)
                && targeted.contains(&name_after(tree, text, spans, node, 0));
            let mut case = matches!(tag, NodeTag::CaseLabel | NodeTag::DefaultLabel);
            let mut default = matches!(tag, NodeTag::DefaultLabel);
            let mut brk = matches!(tag, NodeTag::BreakStmt);
            let mut cont = matches!(tag, NodeTag::ContinueStmt);
            let mut sc = logical_kind(tree, node, tag).is_some();
            let mut init = matches!(tag, NodeTag::Initializer);
            let descend = !is_unevaluated(tree, node, tag);
            for child in arena.children_iter(node) {
                // The raw vector, not [`Reach::label_in`]: this is the fold that
                // *builds* the honest answer, and reading the mode-applied
                // accessor here would write `Coverage::Syntactic`'s blanket
                // `true` back into the data.
                label |= self.at(&self.label_in, child);
                init |= self.init_in(child);
                if descend {
                    sc |= self.sc_in(child);
                }
                if tag != NodeTag::SwitchStmt {
                    case |= self.case_in(child);
                    default |= self.default_in(child);
                }
                if !binds_break(tag) {
                    brk |= self.break_in(child);
                }
                if !binds_continue(tag) {
                    cont |= self.continue_in(child);
                }
            }
            self.label_in[slot] = label;
            self.case_in[slot] = case;
            self.default_in[slot] = default;
            self.break_in[slot] = brk;
            self.continue_in[slot] = cont;
            self.sc_in[slot] = sc;
            self.init_in[slot] = init;
            self.falls[slot] = self.compute_falls(tree, node, tag);
        }
    }

    /// Whether control can continue past the statement `node`.
    ///
    /// The rules are the ones the builder's own wiring makes true, not C's
    /// semantics: every loop falls through because
    /// [`crate::syntax::cfg::CfgBuilder`] always gives a loop header a second
    /// edge out of the construct, so `while (1) {}` followed by code leaves
    /// that code reachable even though no execution reaches it. Reporting it
    /// unreachable here would suppress a node the graph does connect.
    ///
    /// Under [`Coverage::Syntactic`] the statement-list rule reads through
    /// [`Reach::label_in`]'s blanket `true`, so a list falls through iff its
    /// *last* statement does --- `{ return 1; foo(); }` falls through, because
    /// `foo()` is emitted and its own successor edge is real. That is the
    /// sequential composition a syntax-directed builder performs, and it is why
    /// the mode needs no second rule here.
    fn compute_falls(&self, tree: &Tree, node: NodeId, tag: NodeTag) -> bool {
        match tag {
            NodeTag::ReturnStmt
            | NodeTag::GotoStmt
            | NodeTag::BreakStmt
            | NodeTag::ContinueStmt => false,
            NodeTag::CompoundStmt | NodeTag::StmtExpr => {
                let mut live = true;
                for child in tree.arena().children_iter(node) {
                    if !live && (self.label_in(child) || self.case_in(child)) {
                        live = true;
                    }
                    if live {
                        live = self.falls(child);
                    }
                }
                live
            }
            NodeTag::IfStmt => {
                let mut arms = bodies(tree, node);
                let then = arms.next();
                match arms.next() {
                    // Both arms present: the join is reachable only if one of
                    // them reaches it.
                    Some(otherwise) => then.is_none_or(|t| self.falls(t)) || self.falls(otherwise),
                    // No `else`, so the false edge of the test reaches the join
                    // whatever the then-arm does.
                    None => true,
                }
            }
            NodeTag::SwitchStmt => match bodies(tree, node).next() {
                // With no `default` the dispatch itself leaves the construct
                // (`REQ-CFG-4`); otherwise the only ways out are a `break` and
                // the last arm running off the end.
                Some(body) => !self.default_in(body) || self.falls(body) || self.break_in(body),
                None => true,
            },
            _ => true,
        }
    }

    /// Which statements the emitter will reach, propagated top-down.
    ///
    /// A mirror of the emitter's own liveness rules: a region entered from a
    /// construct's head is live whatever preceded the construct, the region
    /// between a `switch` dispatch and its first arm is not, and a statement
    /// list becomes live again at a jump target. Its only consumer is the
    /// fixpoint above, which needs to know which `goto`s actually run.
    fn simulate(&self, tree: &Tree, body: NodeId) -> Vec<bool> {
        let mut live = vec![false; self.falls.len()];
        if let Some(slot) = self.slot(body) {
            live[slot] = true;
        }
        let mut stack = vec![body];
        while let Some(node) = stack.pop() {
            let Some(tag) = tag_of(tree, node) else {
                continue;
            };
            let here = self.at(&live, node);
            // The emitter walks into a statement control cannot fall into only
            // when it carries a jump target; otherwise it skips the subtree.
            let emitted = here || self.label_in(node) || self.case_in(node);
            if !emitted {
                continue;
            }
            let arena = tree.arena();
            match tag {
                NodeTag::CompoundStmt | NodeTag::StmtExpr => {
                    let mut cur = here;
                    for child in arena.children_iter(node) {
                        if !cur && (self.label_in(child) || self.case_in(child)) {
                            cur = true;
                        }
                        self.set(&mut live, child, cur);
                        stack.push(child);
                        cur = cur && self.falls(child);
                    }
                }
                NodeTag::SwitchStmt => {
                    for child in arena.children_iter(node) {
                        let inside = tag_of(tree, child).is_some_and(is_body);
                        self.set(&mut live, child, !inside && here);
                        stack.push(child);
                    }
                }
                _ => {
                    for child in arena.children_iter(node) {
                        self.set(&mut live, child, emitted);
                        stack.push(child);
                    }
                }
            }
        }
        live
    }

    /// Every label a reachable `goto` can transfer to.
    fn targets_of_live_jumps(&self, jumps: &[Jump], live: &[bool]) -> BTreeSet<String> {
        let mut targets = BTreeSet::new();
        for jump in jumps {
            if !self.at(live, jump.node) {
                continue;
            }
            match &jump.label {
                Some(name) => {
                    targets.insert(name.clone());
                }
                // `REQ-CFG-7`: a computed `goto`'s target set is the labels
                // whose address was taken, which is the only way C lets a
                // program name one.
                None => targets.extend(self.address_taken.iter().cloned()),
            }
        }
        targets
    }

    /// Where `id`'s answers live, or `None` when it is outside this body.
    fn slot(&self, id: NodeId) -> Option<usize> {
        let offset = id.raw().checked_sub(self.base)? as usize;
        (offset < self.falls.len()).then_some(offset)
    }

    /// Read one bit vector at `id`, defaulting to `false` off the end.
    fn at(&self, vector: &[bool], id: NodeId) -> bool {
        self.slot(id).is_some_and(|slot| vector[slot])
    }

    /// Write one bit vector at `id`, ignoring an id off the end.
    fn set(&self, vector: &mut [bool], id: NodeId, value: bool) {
        if let Some(slot) = self.slot(id) {
            vector[slot] = value;
        }
    }

    /// Whether control can continue past `node`. Unknown nodes fall through,
    /// which is the answer that suppresses nothing.
    pub(super) fn falls(&self, node: NodeId) -> bool {
        self.slot(node).is_none_or(|slot| self.falls[slot])
    }

    /// Whether the emitter must walk into `node` even though control cannot
    /// fall into it.
    ///
    /// Under [`Coverage::Reachable`] that is "the subtree defines a label some
    /// reachable `goto` names", the only way a statement list control has left
    /// becomes live again. Under [`Coverage::Syntactic`] it is unconditionally
    /// true, which is the whole of what that mode changes: the emitter's one
    /// pruning test is `label_in || case_in`, so answering yes here is what
    /// makes an unreachable region emit as its own component instead of
    /// vanishing.
    ///
    /// The mode is applied on the way out, not folded into the data. That is
    /// not cosmetic: [`Reach::fold`] propagates a child's bit into its parent,
    /// so reading this accessor there would write [`Coverage::Syntactic`]'s
    /// blanket `true` into every node of the tree and destroy the vector. What
    /// the vector holds under that mode is the honest "this subtree defines a
    /// label" --- the fold runs once against the complete label set, since with
    /// no dead statements there is no dead `goto` to exclude.
    pub(super) fn label_in(&self, node: NodeId) -> bool {
        match self.coverage {
            Coverage::Syntactic => true,
            Coverage::Reachable => self.at(&self.label_in, node),
        }
    }

    /// Whether `node`'s subtree carries a `case` or `default` label bound to a
    /// switch outside it.
    pub(super) fn case_in(&self, node: NodeId) -> bool {
        self.at(&self.case_in, node)
    }

    /// Whether `node`'s subtree carries a `continue` bound to a loop outside it.
    pub(super) fn continue_in(&self, node: NodeId) -> bool {
        self.at(&self.continue_in, node)
    }

    /// Whether `node`'s subtree carries an evaluated `&&`, `||` or `?:`.
    pub(super) fn sc_in(&self, node: NodeId) -> bool {
        self.at(&self.sc_in, node)
    }

    /// Whether `node`'s subtree carries a declarator initializer.
    pub(super) fn init_in(&self, node: NodeId) -> bool {
        self.at(&self.init_in, node)
    }

    /// The labels a computed `goto` in this function may transfer to, in source
    /// order.
    pub(super) fn address_taken(&self) -> &[String] {
        &self.address_taken
    }

    /// Whether `node`'s subtree carries a `default` label bound to a switch
    /// outside it.
    fn default_in(&self, node: NodeId) -> bool {
        self.at(&self.default_in, node)
    }

    /// Whether `node`'s subtree carries a `break` bound to a construct outside
    /// it.
    fn break_in(&self, node: NodeId) -> bool {
        self.at(&self.break_in, node)
    }
}

/// The identifier `offset` tokens after `node`'s first token, or the empty
/// string when there is none.
///
/// Both callers want a name the parser consumed into the node itself rather
/// than into a child: a `LabelStmt` is `ident :` and a `LabelAddr` is
/// `&& ident`, so the name sits at offset 0 and 1 respectively.
fn name_after(tree: &Tree, text: &str, spans: &[Span], node: NodeId, offset: u32) -> String {
    let Some((first, end)) = tree.arena().token_extent(node) else {
        return String::new();
    };
    let Some(raw) = first.checked_add(offset) else {
        return String::new();
    };
    if raw >= end {
        return String::new();
    }
    let id = TokenId::new(raw);
    if TokenKind::from_u16(tree.tokens().kind(id)) != Some(TokenKind::Identifier) {
        return String::new();
    }
    spans
        .get(id.index())
        .and_then(|span| text.get(span.range()))
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csource::parse::parse;

    /// Parse `text` and hand back the pieces the pass needs.
    fn analyse(text: &str) -> (Tree, Vec<Span>, NodeId) {
        let tree = parse(text).into_parts().0;
        let spans = tree.token_spans(text);
        let body = tree.functions(text)[0].body.expect("a body");
        (tree, spans, body)
    }

    /// `text`'s one function under `coverage`, as the graph the emitter built.
    fn cfg_of(text: &str, coverage: Coverage) -> crate::syntax::cfg::Cfg {
        let tree = parse(text).into_parts().0;
        let mut built = super::super::function_cfgs_with(&tree, text, coverage)
            .into_parts()
            .0;
        assert_eq!(built.len(), 1, "expected exactly one function");
        built.remove(0).cfg
    }

    /// Every node span of `cfg`, rendered back to source text.
    fn node_texts<'a>(cfg: &crate::syntax::cfg::Cfg, text: &'a str) -> Vec<&'a str> {
        cfg.nodes()
            .iter()
            .filter_map(|node| text.get(node.span().range()))
            .collect()
    }

    /// A reduction of `O0 openssh-portable sshd` `process_server_config_line_depth`
    /// lines 3307-3323 of `glaurung-229fbb1-clean_sshd.c`: three `goto`s to the
    /// same forward label, then a block that no label heads.
    ///
    /// The shape is what a decompiler emits when it loses a jump-table
    /// dispatch, and it is why that function reaches 48 of the 663 nodes the
    /// published CFG has. Joern keeps the stranded block; `REQ-GEN-1` says we
    /// must not, unless the caller asked for [`Coverage::Syntactic`].
    const STRANDED_ARM: &str = "int f(int a, int b, char *s) {\
        if (a) { goto L_20a88; }\
        if (b) { goto L_20a88; }\
        a = b;\
        goto L_20a88;\
        s = strchr(s, 91);\
        if (s) { b = 1; }\
        L_20a88: ;\
        return b; }";

    fn falls_of_body(text: &str) -> bool {
        let (tree, spans, body) = analyse(text);
        Reach::new(&tree, text, &spans, body).falls(body)
    }

    /// The first node of `tag` in the first function's body.
    fn first(tree: &Tree, body: NodeId, tag: NodeTag) -> NodeId {
        tree.arena()
            .preorder(body)
            .find(|n| tag_of(tree, *n) == Some(tag))
            .unwrap_or_else(|| panic!("no {tag:?} node"))
    }

    #[test]
    fn the_block_after_an_unconditional_goto_is_pruned_by_default_and_kept_syntactically() {
        let pruned = cfg_of(STRANDED_ARM, Coverage::Reachable);
        let kept = cfg_of(STRANDED_ARM, Coverage::Syntactic);
        assert!(
            !node_texts(&pruned, STRANDED_ARM)
                .iter()
                .any(|t| t.contains("strchr")),
            "REQ-GEN-1: control cannot arrive at the stranded arm, so it has no \
             node: {:?}",
            node_texts(&pruned, STRANDED_ARM)
        );
        assert!(
            node_texts(&kept, STRANDED_ARM)
                .iter()
                .any(|t| t.contains("strchr")),
            "Joern's construction is syntax-directed and keeps it: {:?}",
            node_texts(&kept, STRANDED_ARM)
        );
        assert!(
            kept.node_count() > pruned.node_count(),
            "{} kept vs {} pruned",
            kept.node_count(),
            pruned.node_count()
        );
    }

    #[test]
    fn what_syntactic_coverage_adds_is_a_component_with_no_path_from_the_entry() {
        let kept = cfg_of(STRANDED_ARM, Coverage::Syntactic);
        let reachable = kept.reachable();
        let stranded: Vec<&str> = kept
            .nodes()
            .iter()
            .enumerate()
            .filter(|(index, _)| !reachable[*index])
            .filter_map(|(_, node)| STRANDED_ARM.get(node.span().range()))
            .collect();
        assert!(
            stranded.iter().any(|t| t.contains("strchr")),
            "the stranded arm is exactly a node the entry cannot reach: {stranded:?}"
        );
        // It is a component, not a dangling node: the arm's own `if` still
        // wires to the label that follows it, which is what makes the node
        // count grow by more than one.
        assert!(
            stranded.len() > 1,
            "a whole region, not one statement: {stranded:?}"
        );
    }

    #[test]
    fn only_the_syntactic_graph_gives_up_req_gen_1() {
        assert!(
            cfg_of(STRANDED_ARM, Coverage::Reachable)
                .validate()
                .iter()
                .next()
                .is_none(),
            "the default graph is the one REQ-GEN-1 is stated of"
        );
        assert!(
            cfg_of(STRANDED_ARM, Coverage::Syntactic)
                .validate()
                .iter()
                .next()
                .is_some(),
            "the parity graph deliberately fails it, which is why it is opt-in \
             and why nothing that validates may ask for it"
        );
    }

    #[test]
    fn the_default_is_what_it_was_before_the_option_existed() {
        // The layering claim in `syntax::cfg`'s module docs is only true if
        // asking for the parity graph cannot change the general one. Shapes,
        // not just counts: a silent edge change would pass a count check.
        for text in [
            STRANDED_ARM,
            "int f(int a) { if (a) return 1; else return 2; }",
            "int g(int a) { while (a) { a--; if (a == 3) continue; } return a; }",
            "int h(int a) { switch (a) { case 1: return 1; default: break; } return 0; }",
        ] {
            let tree = parse(text).into_parts().0;
            let plain = super::super::function_cfgs(&tree, text).into_parts().0;
            let asked = super::super::function_cfgs_with(&tree, text, Coverage::Reachable)
                .into_parts()
                .0;
            assert_eq!(plain.len(), asked.len());
            for (a, b) in plain.iter().zip(asked.iter()) {
                let kinds = |c: &crate::syntax::cfg::Cfg| {
                    c.nodes().iter().map(|n| n.kind()).collect::<Vec<_>>()
                };
                let wires = |c: &crate::syntax::cfg::Cfg| {
                    c.edges()
                        .iter()
                        .map(|e| (e.src.raw(), e.dst.raw(), e.kind))
                        .collect::<Vec<_>>()
                };
                assert_eq!(kinds(&a.cfg), kinds(&b.cfg), "{text}");
                assert_eq!(wires(&a.cfg), wires(&b.cfg), "{text}");
            }
        }
    }

    #[test]
    fn a_statement_list_falls_through_to_its_last_statement_under_syntactic_coverage() {
        // `{ return 1; foo(); }` is the shape the module docs use, and the
        // rule matters: under `Syntactic` the call is emitted, so the list's
        // own successor edge leaves *it*, which is the sequential composition
        // Joern performs.
        let text = "int f(void) { return 1; g(); }";
        let (tree, spans, body) = analyse(text);
        assert!(!Reach::new(&tree, text, &spans, body).falls(body));
        assert!(
            Reach::with_coverage(&tree, text, &spans, body, Coverage::Syntactic).falls(body),
            "the emitted `g()` falls through, so the list does"
        );
    }

    #[test]
    fn a_label_only_a_dead_goto_names_still_emits_under_syntactic_coverage() {
        // The counterpart of `a_label_only_a_dead_goto_names_is_not_a_jump_target`.
        // `O0 openssh-portable sshd process_server_config_line_depth` has 129
        // labels of which the fixpoint proves 13 live; `L_1c19d` (line 3346) is
        // one of the 116 whose only `goto`s are themselves dead, and it heads a
        // region Joern keeps.
        let text = "int f(void) { return 0; goto spare; spare: return 1; }";
        let (tree, spans, body) = analyse(text);
        let strict = Reach::new(&tree, text, &spans, body);
        assert!(!strict.label_in(first(&tree, body, NodeTag::LabelStmt)));
        let loose = Reach::with_coverage(&tree, text, &spans, body, Coverage::Syntactic);
        assert!(loose.label_in(first(&tree, body, NodeTag::LabelStmt)));
        assert!(
            node_texts(&cfg_of(text, Coverage::Syntactic), text)
                .iter()
                .any(|t| t.contains("return 1")),
            "the dead label's own arm is a node too"
        );
    }

    #[test]
    fn syntactic_coverage_is_applied_on_the_way_out_not_folded_into_the_data() {
        // `Reach::fold` propagates a child's bit into its parent, so it must
        // read the raw vector: through the accessor, `Coverage::Syntactic`'s
        // blanket `true` would climb into every node in the function and the
        // vector would say nothing at all. A statement with no label anywhere
        // beneath it is the witness.
        let text = "int f(int a) { if (a) goto here; return 0; here: return 1; }";
        let (tree, spans, body) = analyse(text);
        let loose = Reach::with_coverage(&tree, text, &spans, body, Coverage::Syntactic);
        let plain = tree
            .arena()
            .preorder(body)
            .filter(|n| tag_of(&tree, *n) == Some(NodeTag::ReturnStmt))
            .collect::<Vec<_>>();
        assert_eq!(plain.len(), 2, "two returns to look at");
        for node in plain {
            assert!(
                !loose.at(&loose.label_in, node),
                "a `return` defines no label, whatever the mode answers callers"
            );
            assert!(loose.label_in(node), "...but the mode still says `emit it`");
        }
        // And the vector is still populated, not merely all-false: the label
        // statement's own bit is set, because the fold ran against the
        // complete label set.
        assert!(loose.at(&loose.label_in, first(&tree, body, NodeTag::LabelStmt)));
    }

    #[test]
    fn the_parity_layer_actually_asks_for_syntactic_coverage() {
        // The option is worth nothing unless its one caller passes it, and the
        // call site is a single argument that a refactor can quietly drop. The
        // guard lives here, next to the mode it protects, because
        // `csource::joern` has no other reason to know this module exists.
        //
        // `O0 openssh-portable sshd process_server_config_line_depth`: 663
        // published nodes against the 48 the pruned build reached.
        let parity = crate::csource::joern::parity_cfgs(STRANDED_ARM);
        let f = parity.get("f").expect("f is recovered");
        let mut seen: BTreeSet<u32> = f.entry.iter().copied().collect();
        let mut stack: Vec<u32> = f.entry.clone();
        while let Some(node) = stack.pop() {
            for (src, dst) in &f.edges {
                if *src == node && seen.insert(*dst) {
                    stack.push(*dst);
                }
            }
        }
        assert!(
            !f.entry.is_empty(),
            "the parity graph has an entry to walk from: {f:?}"
        );
        assert!(
            seen.len() < f.nodes.len(),
            "the stranded arm has to survive into the scored graph as a \
             component the entry cannot reach: {} of {} nodes reachable",
            seen.len(),
            f.nodes.len()
        );
    }

    #[test]
    fn the_two_modes_agree_wherever_nothing_is_dead() {
        // `Coverage::Syntactic` must *add* the unreachable and change nothing
        // else. The goto chain is the interesting case: it is deeper than
        // `MAX_LIVE_ROUNDS`, so the default mode reaches its all-labels
        // fallback, and the two answers have to meet there exactly.
        let mut chain = String::from("int f(int a) { goto l0;");
        let depth = MAX_LIVE_ROUNDS + 8;
        for index in 0..depth {
            chain.push_str(&format!(
                " l{index}: ; a = a + {index}; goto l{};",
                index + 1
            ));
        }
        chain.push_str(&format!(" l{depth}: ; return a; }}"));
        for text in [
            chain.as_str(),
            "int g(int a) { a = a + 1; return a; }",
            "int h(int a) { while (a) { a--; if (a == 3) break; } return a; }",
            "int i(int a) { switch (a) { case 1: return 1; default: return 0; } }",
        ] {
            let strict = cfg_of(text, Coverage::Reachable);
            let loose = cfg_of(text, Coverage::Syntactic);
            let shape = |c: &crate::syntax::cfg::Cfg| {
                (
                    c.nodes().iter().map(|n| n.kind()).collect::<Vec<_>>(),
                    c.edges()
                        .iter()
                        .map(|e| (e.src.raw(), e.dst.raw(), e.kind))
                        .collect::<Vec<_>>(),
                )
            };
            assert_eq!(
                shape(&strict),
                shape(&loose),
                "nothing here is dead, so the modes must produce one graph"
            );
        }
    }

    #[test]
    fn a_body_ending_in_a_return_does_not_fall_through() {
        assert!(!falls_of_body("int f(void) { return 1; }"));
        assert!(falls_of_body("void f(void) { g(); }"));
    }

    #[test]
    fn an_if_falls_through_unless_both_arms_leave() {
        assert!(!falls_of_body(
            "int f(int a) { if (a) return 1; else return 2; }"
        ));
        assert!(falls_of_body("int f(int a) { if (a) return 1; }"));
        assert!(falls_of_body(
            "int f(int a) { if (a) return 1; else a = 2; }"
        ));
    }

    #[test]
    fn a_switch_with_a_default_and_no_break_does_not_fall_through() {
        assert!(!falls_of_body(
            "int f(int a) { switch (a) { case 1: return 1; default: return 2; } }"
        ));
        assert!(falls_of_body(
            "int f(int a) { switch (a) { case 1: break; default: return 2; } }"
        ));
        assert!(
            falls_of_body("int f(int a) { switch (a) { case 1: return 1; } }"),
            "no default means the dispatch itself leaves the construct"
        );
    }

    #[test]
    fn a_loop_always_falls_through_because_the_builder_wires_it_that_way() {
        assert!(falls_of_body("void f(void) { while (1) { g(); } }"));
    }

    #[test]
    fn a_label_a_reachable_goto_names_is_a_jump_target() {
        let text = "int f(int a) { goto done; return 0; done: return 1; }";
        let (tree, spans, body) = analyse(text);
        let reach = Reach::new(&tree, text, &spans, body);
        assert!(reach.label_in(first(&tree, body, NodeTag::LabelStmt)));
    }

    #[test]
    fn an_unreferenced_label_is_not_a_jump_target() {
        let text = "int f(void) { return 0; spare: return 1; }";
        let (tree, spans, body) = analyse(text);
        let reach = Reach::new(&tree, text, &spans, body);
        assert!(!reach.label_in(first(&tree, body, NodeTag::LabelStmt)));
    }

    #[test]
    fn a_label_only_a_dead_goto_names_is_not_a_jump_target() {
        // The fixpoint's whole point: `spare` looks targeted until you notice
        // that the `goto` naming it can never run.
        let text = "int f(void) { return 0; goto spare; spare: return 1; }";
        let (tree, spans, body) = analyse(text);
        let reach = Reach::new(&tree, text, &spans, body);
        assert!(!reach.label_in(first(&tree, body, NodeTag::LabelStmt)));
    }

    #[test]
    fn a_chain_of_gotos_settles_at_the_labels_that_really_run() {
        let text = "int f(int a) { if (a) goto one; return 0;\
                    one: goto two; two: return 1;\
                    dead: goto four; four: return 2; }";
        let (tree, spans, body) = analyse(text);
        let reach = Reach::new(&tree, text, &spans, body);
        let labels: Vec<(String, bool)> = tree
            .arena()
            .preorder(body)
            .filter(|n| tag_of(&tree, *n) == Some(NodeTag::LabelStmt))
            .map(|n| (name_after(&tree, text, &spans, n, 0), reach.label_in(n)))
            .collect();
        assert_eq!(
            labels,
            vec![
                ("one".to_string(), true),
                ("two".to_string(), true),
                ("dead".to_string(), false),
                ("four".to_string(), false),
            ]
        );
    }

    #[test]
    fn a_computed_gotos_targets_are_the_labels_whose_address_is_taken() {
        let text = "int f(int a) { static void *t[2] = {&&one, &&two};\
                    goto *t[a]; one: return 1; two: return 2; }";
        let (tree, spans, body) = analyse(text);
        let reach = Reach::new(&tree, text, &spans, body);
        assert_eq!(
            reach.address_taken(),
            ["one".to_string(), "two".to_string()]
        );
        for node in tree.arena().preorder(body) {
            if tag_of(&tree, node) == Some(NodeTag::LabelStmt) {
                assert!(reach.label_in(node), "a computed goto reaches every one");
            }
        }
    }

    #[test]
    fn a_short_circuit_is_seen_through_a_call_argument_but_not_through_sizeof() {
        let text = "int f(int a, int b) { g(a && b); return sizeof(a || b); }";
        let (tree, spans, body) = analyse(text);
        let reach = Reach::new(&tree, text, &spans, body);
        assert!(reach.sc_in(first(&tree, body, NodeTag::CallArgs)));
        let sizeofs: Vec<NodeId> = tree
            .arena()
            .preorder(body)
            .filter(|n| {
                tag_of(&tree, *n) == Some(NodeTag::UnaryExpr)
                    && is_unevaluated(&tree, *n, NodeTag::UnaryExpr)
            })
            .collect();
        assert!(!sizeofs.is_empty());
        for node in sizeofs {
            assert!(!reach.sc_in(node), "sizeof does not evaluate its operand");
        }
    }

    #[test]
    fn a_declaration_records_whether_it_has_an_initializer() {
        let text = "void f(void) { int a; int b = 1; }";
        let (tree, spans, body) = analyse(text);
        let reach = Reach::new(&tree, text, &spans, body);
        let decls: Vec<NodeId> = tree
            .arena()
            .preorder(body)
            .filter(|n| tag_of(&tree, *n) == Some(NodeTag::Decl))
            .collect();
        assert_eq!(decls.len(), 2);
        assert!(!reach.init_in(decls[0]));
        assert!(reach.init_in(decls[1]));
    }
}
