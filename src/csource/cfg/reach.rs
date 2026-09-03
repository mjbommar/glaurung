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
                label |= self.label_in(child);
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

    /// Whether `node`'s subtree defines a label some reachable `goto` names.
    pub(super) fn label_in(&self, node: NodeId) -> bool {
        self.at(&self.label_in, node)
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
