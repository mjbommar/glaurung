//! [`CfgBuilder`]: the control-context stack, label backpatching, and the
//! [`Flow`] state machine.
//!
//! The irreducible half of this component --- the three things every language
//! front end would otherwise reimplement for itself: the control context
//! stack that resolves `break` and `continue` (including a labelled `break`
//! out of several levels at once), the label map and deferred-fixup list that
//! let a `goto` name a label defined later, and the bookkeeping that keeps
//! [`super::validate`]'s invariants true of whatever graph [`CfgBuilder`]
//! hands back. [`Dest`], [`RawEdge`], [`ScopeKind`] and [`Scope`] are private
//! to this file because nothing outside the builder's own state machine needs
//! them.

use std::collections::BTreeMap;

use crate::syntax::diag::{Diagnostic, Diagnostics, Parsed};
use crate::syntax::ids::{NodeId, Span, Symbol};

use super::{Cfg, CfgEdge, CfgNode, EdgeKind, Flow, LoopKind, NodeKind, MAX_NODES};

/// Where a pending edge is headed while the events are still arriving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dest {
    /// A node that already exists.
    Node(NodeId),
    /// A label that may not have been defined yet, resolved in the second pass.
    Label(Symbol, Span),
    /// A loop's `continue` target, which is only known once the loop closes.
    Continue(u32, Span),
}

/// An edge whose destination may still be a forward reference.
#[derive(Debug, Clone, Copy)]
struct RawEdge {
    src: NodeId,
    dst: Dest,
    kind: EdgeKind,
    is_back: bool,
}

/// Which construct a [`Scope`] is, for `break` and `continue` resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    /// A two-way branch. Never a `break` or `continue` target.
    Branch,
    /// A loop. A target for both.
    Loop(LoopKind),
    /// A switch. A `break` target but not a `continue` target.
    Switch,
}

/// One frame of the control context stack.
struct Scope {
    id: u32,
    kind: ScopeKind,
    label: Option<Symbol>,
    /// The branch test, loop test or switch dispatch node.
    head: NodeId,
    /// Every dangling exit that will become a predecessor of whatever follows
    /// the construct: the arms of a branch, the `break`s of a loop or switch,
    /// the fall-out of a switch.
    join: Vec<(NodeId, EdgeKind)>,
    /// The first node placed inside the construct, which a `do`-`while` needs
    /// in order to wire its bottom test back to the top of its body.
    body_head: Option<NodeId>,
    /// How many arms have been opened: `Then`/`Else` for a branch, `Case` for a
    /// switch.
    arms_seen: u32,
    declared_arms: u32,
    has_default: bool,
    continue_target: Option<NodeId>,
}

/// Consumes [`Flow`] events and produces a [`Cfg`].
///
/// The builder owns the three things every language would otherwise reimplement:
/// the control context stack that resolves `break` and `continue` (including a
/// labelled `break` out of several levels at once), the label map and
/// deferred-fixup list that let a `goto` name a label defined later, and the
/// invariants of `REQ-GEN-1`. It never inspects a token, a node tag or a
/// keyword (`REQ-SYN-8`).
pub struct CfgBuilder {
    nodes: Vec<CfgNode>,
    edges: Vec<RawEdge>,
    /// Dangling exits waiting for the next node to be placed.
    frontier: Vec<(NodeId, EdgeKind)>,
    scopes: Vec<Scope>,
    /// The label map of the second pass. A `BTreeMap` because duplicate-label
    /// diagnostics are emitted in iteration order and `REQ-SYN-5` makes that
    /// observable.
    labels: BTreeMap<Symbol, NodeId>,
    /// Each scope's resolved `continue` target, indexed by scope id.
    scope_continue: Vec<Option<NodeId>>,
    /// Each scope's test node, indexed by scope id. A `continue` counts as a
    /// loop back edge only when it lands here: a `for` loop's `continue` jumps
    /// *forwards* into the step region, and the edge that actually closes the
    /// cycle is the one from the step back to the test.
    scope_head: Vec<NodeId>,
    /// A label seen with no intervening event, waiting to name a construct.
    pending_scope_label: Option<Symbol>,
    /// The scope whose step region has begun and whose `continue` target is
    /// therefore the next node placed.
    awaiting_step: Option<usize>,
    diagnostics: Diagnostics,
    entry: NodeId,
    exit: NodeId,
    next_scope_id: u32,
    exhausted: bool,
}

impl CfgBuilder {
    /// A builder for a function spanning `function`, with its entry and
    /// function-end nodes already placed.
    ///
    /// Both are real nodes with real ids, not flags derived from degrees: that
    /// derivation is the parity layer's quirk, and
    /// `docs/design/static-c-analysis/architecture.md` section 1 is why it must
    /// not appear here. Their spans are the empty spans at the function's two
    /// ends, so `REQ-SYN-7` holds for them too.
    pub fn new(function: Span) -> Self {
        let nodes = vec![
            CfgNode::single(NodeKind::Entry, Span::empty_at(function.lo)),
            CfgNode::single(NodeKind::Exit, Span::empty_at(function.hi)),
        ];
        let entry = NodeId::new(0);
        Self {
            nodes,
            edges: Vec::new(),
            frontier: vec![(entry, EdgeKind::Fall)],
            scopes: Vec::new(),
            labels: BTreeMap::new(),
            scope_continue: Vec::new(),
            scope_head: Vec::new(),
            pending_scope_label: None,
            awaiting_step: None,
            diagnostics: Diagnostics::new(),
            entry,
            exit: NodeId::new(1),
            next_scope_id: 0,
            exhausted: false,
        }
    }

    /// Consume every event of `flows`, in order.
    pub fn extend(&mut self, flows: impl IntoIterator<Item = Flow>) {
        for flow in flows {
            self.push(flow);
        }
    }

    /// Consume one event.
    ///
    /// Never panics and never rejects: an event that makes no sense where it
    /// arrives --- an `Else` with no branch, a `break` outside every loop, a
    /// `Case` outside every switch --- records a diagnostic and the builder
    /// carries on with the best graph it can still produce (`REQ-SYN-2`).
    pub fn push(&mut self, flow: Flow) {
        if self.exhausted {
            return;
        }
        let defines_a_label = matches!(flow, Flow::Label { .. });
        match flow {
            Flow::Stmt(span) => {
                let node = self.place(NodeKind::Stmt, span);
                self.frontier = vec![(node, EdgeKind::Fall)];
            }
            Flow::Branch { cond } => {
                let head = self.place(NodeKind::Cond, cond);
                self.open(ScopeKind::Branch, head);
            }
            Flow::Then => self.begin_branch_arm(true),
            Flow::Else => self.begin_branch_arm(false),
            Flow::LoopHeader { kind, cond } => self.open_loop(kind, cond),
            Flow::LoopStep => self.begin_step(),
            Flow::Switch { arms, subject } => {
                let head = self.place(NodeKind::Switch, subject);
                let index = self.open(ScopeKind::Switch, head);
                if let Some(scope) = self.scopes.get_mut(index) {
                    scope.declared_arms = arms;
                }
            }
            Flow::Case { span, default } => self.begin_case(span, default),
            Flow::EndScope => self.close_scope(),
            Flow::Break { label, span } => self.transfer_break(label, span),
            Flow::Continue { label, span } => self.transfer_continue(label, span),
            Flow::Goto { label, span } => {
                let node = self.place(NodeKind::Goto, span);
                self.edges.push(RawEdge {
                    src: node,
                    dst: Dest::Label(label, span),
                    kind: EdgeKind::Jump,
                    is_back: false,
                });
                self.frontier.clear();
            }
            Flow::Label { name, span } => {
                let node = self.place(NodeKind::Label, span);
                if self.labels.insert(name, node).is_some() {
                    self.diagnostics.push(Diagnostic::error(
                        span,
                        format!("label {} is defined more than once", name.raw()),
                    ));
                }
                self.frontier = vec![(node, EdgeKind::Fall)];
                self.pending_scope_label = Some(name);
            }
            Flow::Return(span) => {
                let node = self.place(NodeKind::Return, span);
                let exit = self.exit;
                self.edges.push(RawEdge {
                    src: node,
                    dst: Dest::Node(exit),
                    kind: EdgeKind::Jump,
                    is_back: false,
                });
                self.frontier.clear();
            }
            Flow::Diverge(span) => {
                self.place(NodeKind::Diverge, span);
                self.frontier.clear();
            }
        }
        if !defines_a_label {
            self.pending_scope_label = None;
        }
    }

    /// Append a node without wiring anything to it.
    fn add(&mut self, kind: NodeKind, span: Span) -> NodeId {
        if self.nodes.len() >= MAX_NODES {
            if !self.exhausted {
                self.exhausted = true;
                self.diagnostics.push(Diagnostic::error(
                    span,
                    format!("control-flow graph exceeded the {MAX_NODES}-node budget"),
                ));
            }
            return self.exit;
        }
        let id = NodeId::new(self.nodes.len() as u32);
        self.nodes.push(CfgNode::single(kind, span));
        id
    }

    /// Append a node and make every dangling exit flow into it.
    fn place(&mut self, kind: NodeKind, span: Span) -> NodeId {
        let id = self.add(kind, span);
        if self.exhausted {
            return id;
        }
        for (src, edge_kind) in std::mem::take(&mut self.frontier) {
            self.edges.push(RawEdge {
                src,
                dst: Dest::Node(id),
                kind: edge_kind,
                is_back: false,
            });
        }
        // Amortised O(1): each scope's body head is set exactly once, and the
        // walk stops at the first scope that already has one.
        for scope in self.scopes.iter_mut().rev() {
            if scope.body_head.is_some() {
                break;
            }
            scope.body_head = Some(id);
        }
        if let Some(index) = self.awaiting_step.take() {
            if let Some(scope) = self.scopes.get_mut(index) {
                scope.continue_target = Some(id);
            }
        }
        id
    }

    /// Push a scope, returning its index on the stack.
    fn open(&mut self, kind: ScopeKind, head: NodeId) -> usize {
        let id = self.next_scope_id;
        self.next_scope_id = self.next_scope_id.saturating_add(1);
        self.scope_continue.push(None);
        self.scope_head.push(head);
        self.scopes.push(Scope {
            id,
            kind,
            label: self.pending_scope_label.take(),
            head,
            join: Vec::new(),
            body_head: None,
            arms_seen: 0,
            declared_arms: 0,
            has_default: false,
            continue_target: None,
        });
        self.frontier.clear();
        self.scopes.len() - 1
    }

    fn open_loop(&mut self, kind: LoopKind, cond: Span) {
        if kind == LoopKind::DoWhile {
            // The test is a latch below the body, so control entering the loop
            // must reach the body first: the header is added detached and the
            // frontier is handed back afterwards for the body's first node to
            // consume.
            let saved = std::mem::take(&mut self.frontier);
            let head = self.add(NodeKind::LoopHeader, cond);
            let index = self.open(ScopeKind::Loop(kind), head);
            if let Some(scope) = self.scopes.get_mut(index) {
                scope.continue_target = Some(head);
                scope.join.push((head, EdgeKind::False));
            }
            self.frontier = saved;
            return;
        }
        let head = self.place(NodeKind::LoopHeader, cond);
        let index = self.open(ScopeKind::Loop(kind), head);
        if let Some(scope) = self.scopes.get_mut(index) {
            scope.join.push((head, EdgeKind::False));
            if kind == LoopKind::While {
                scope.continue_target = Some(head);
            }
        }
        self.frontier = vec![(head, EdgeKind::True)];
    }

    fn begin_branch_arm(&mut self, first: bool) {
        let Some(index) = self.innermost(ScopeKind::Branch) else {
            self.diagnostics.push(Diagnostic::error(
                Span::default(),
                "branch arm outside any branch",
            ));
            return;
        };
        let head = self.scopes[index].head;
        let seen = self.scopes[index].arms_seen;
        if (first && seen != 0) || (!first && seen != 1) {
            self.diagnostics.push(Diagnostic::error(
                self.nodes[head.index()].span(),
                "branch arms arrived out of order",
            ));
            return;
        }
        if !first {
            let dangling = std::mem::take(&mut self.frontier);
            self.scopes[index].join.extend(dangling);
        }
        self.scopes[index].arms_seen = seen.saturating_add(1);
        self.frontier = vec![(
            head,
            if first {
                EdgeKind::True
            } else {
                EdgeKind::False
            },
        )];
    }

    fn begin_step(&mut self) {
        let Some(index) = self.innermost_loop() else {
            self.diagnostics.push(Diagnostic::error(
                Span::default(),
                "loop step region outside any loop",
            ));
            return;
        };
        self.awaiting_step = Some(index);
    }

    fn begin_case(&mut self, span: Span, default: bool) {
        let Some(index) = self.innermost(ScopeKind::Switch) else {
            self.diagnostics
                .push(Diagnostic::error(span, "switch arm outside any switch"));
            let node = self.place(NodeKind::Stmt, span);
            self.frontier = vec![(node, EdgeKind::Fall)];
            return;
        };
        // Whatever the previous arm left dangling runs into this one; that is
        // exactly `REQ-GEN-1`'s "a switch fall-through is an edge".
        for slot in self.frontier.iter_mut() {
            slot.1 = EdgeKind::FallThrough;
        }
        let node = self.place(NodeKind::Case, span);
        let head = self.scopes[index].head;
        self.edges.push(RawEdge {
            src: head,
            dst: Dest::Node(node),
            kind: if default {
                EdgeKind::Default
            } else {
                EdgeKind::Case
            },
            is_back: false,
        });
        let scope = &mut self.scopes[index];
        scope.arms_seen = scope.arms_seen.saturating_add(1);
        scope.has_default |= default;
        self.frontier = vec![(node, EdgeKind::Fall)];
    }

    fn transfer_break(&mut self, label: Option<Symbol>, span: Span) {
        let node = self.place(NodeKind::Break, span);
        self.frontier.clear();
        match self.target_scope(label, false) {
            Some(index) => self.scopes[index].join.push((node, EdgeKind::Jump)),
            None => {
                self.nodes[node.index()] = CfgNode::single(NodeKind::Diverge, span);
                self.diagnostics.push(Diagnostic::error(
                    span,
                    "break leaves no enclosing loop or switch",
                ));
            }
        }
    }

    fn transfer_continue(&mut self, label: Option<Symbol>, span: Span) {
        let node = self.place(NodeKind::Continue, span);
        self.frontier.clear();
        match self.target_scope(label, true) {
            Some(index) => {
                let scope_id = self.scopes[index].id;
                self.edges.push(RawEdge {
                    src: node,
                    dst: Dest::Continue(scope_id, span),
                    kind: EdgeKind::Jump,
                    is_back: true,
                });
            }
            None => {
                self.nodes[node.index()] = CfgNode::single(NodeKind::Diverge, span);
                self.diagnostics
                    .push(Diagnostic::error(span, "continue leaves no enclosing loop"));
            }
        }
    }

    /// The innermost scope a `break` or `continue` names, searching outwards so
    /// a labelled transfer can leave several levels at once.
    fn target_scope(&self, label: Option<Symbol>, loops_only: bool) -> Option<usize> {
        self.scopes.iter().rposition(|scope| {
            let eligible = match scope.kind {
                ScopeKind::Loop(_) => true,
                ScopeKind::Switch => !loops_only,
                ScopeKind::Branch => false,
            };
            match label {
                _ if !eligible => false,
                None => true,
                Some(name) => scope.label == Some(name),
            }
        })
    }

    fn innermost(&self, kind: ScopeKind) -> Option<usize> {
        self.scopes.iter().rposition(|scope| scope.kind == kind)
    }

    fn innermost_loop(&self) -> Option<usize> {
        self.scopes
            .iter()
            .rposition(|scope| matches!(scope.kind, ScopeKind::Loop(_)))
    }

    fn close_scope(&mut self) {
        let Some(scope) = self.scopes.pop() else {
            self.diagnostics.push(Diagnostic::error(
                Span::default(),
                "scope closed with no scope open",
            ));
            return;
        };
        if self.awaiting_step == Some(self.scopes.len()) {
            self.awaiting_step = None;
        }
        let mut join = scope.join;
        let dangling = std::mem::take(&mut self.frontier);
        match scope.kind {
            ScopeKind::Branch => {
                if scope.arms_seen == 0 {
                    self.diagnostics.push(Diagnostic::error(
                        self.nodes[scope.head.index()].span(),
                        "branch closed with neither arm emitted",
                    ));
                    join.push((scope.head, EdgeKind::True));
                    join.push((scope.head, EdgeKind::False));
                } else {
                    join.extend(dangling);
                    if scope.arms_seen == 1 {
                        join.push((scope.head, EdgeKind::False));
                    }
                }
            }
            ScopeKind::Loop(kind) => {
                let target = scope.continue_target.unwrap_or(scope.head);
                if let Some(slot) = self.scope_continue.get_mut(scope.id as usize) {
                    *slot = Some(target);
                }
                if kind == LoopKind::DoWhile {
                    for (src, edge_kind) in dangling {
                        self.edges.push(RawEdge {
                            src,
                            dst: Dest::Node(scope.head),
                            kind: edge_kind,
                            is_back: false,
                        });
                    }
                    let body = scope.body_head.unwrap_or(scope.head);
                    self.edges.push(RawEdge {
                        src: scope.head,
                        dst: Dest::Node(body),
                        kind: EdgeKind::True,
                        is_back: true,
                    });
                } else {
                    for (src, edge_kind) in dangling {
                        self.edges.push(RawEdge {
                            src,
                            dst: Dest::Node(scope.head),
                            kind: edge_kind,
                            is_back: true,
                        });
                    }
                }
            }
            ScopeKind::Switch => {
                if scope.declared_arms != scope.arms_seen {
                    self.diagnostics.push(Diagnostic::error(
                        self.nodes[scope.head.index()].span(),
                        format!(
                            "switch declared {} arms but {} arrived",
                            scope.declared_arms, scope.arms_seen
                        ),
                    ));
                }
                if !scope.has_default {
                    // No arm matches every value, so the dispatch itself is an
                    // exit from the construct.
                    join.push((scope.head, EdgeKind::Default));
                }
                join.extend(dangling);
            }
        }
        self.frontier = join;
    }

    /// Close every open scope, resolve every forward reference and return the
    /// graph alongside the diagnostics collected building it.
    ///
    /// The second pass is the assembler's: the label map is complete by now, so
    /// a `goto` to a label defined later resolves here, and so does a
    /// `continue` in a `for` loop whose step region had not been seen when the
    /// `continue` arrived. A reference that resolves to nothing turns its node
    /// into a [`NodeKind::Diverge`] --- the honest description of a transfer
    /// with no destination, and one that keeps the graph well-formed for
    /// [`Cfg::validate`] rather than producing a second report of the same
    /// defect.
    pub fn finish(mut self) -> Parsed<Cfg> {
        let mut guard = self.scopes.len();
        while !self.scopes.is_empty() && guard > 0 {
            self.diagnostics.push(Diagnostic::error(
                self.nodes[self.scopes[self.scopes.len() - 1].head.index()].span(),
                "construct was never closed",
            ));
            self.close_scope();
            guard -= 1;
        }
        let exit = self.exit;
        for (src, kind) in std::mem::take(&mut self.frontier) {
            self.edges.push(RawEdge {
                src,
                dst: Dest::Node(exit),
                kind,
                is_back: false,
            });
        }

        let mut edges = Vec::with_capacity(self.edges.len());
        for raw in std::mem::take(&mut self.edges) {
            let mut is_back = raw.is_back;
            let dst = match raw.dst {
                Dest::Node(id) => Some(id),
                Dest::Label(name, span) => match self.labels.get(&name) {
                    Some(&id) => Some(id),
                    None => {
                        self.diagnostics.push(Diagnostic::error(
                            span,
                            format!("goto names label {}, which is never defined", name.raw()),
                        ));
                        None
                    }
                },
                Dest::Continue(scope, span) => {
                    match self.scope_continue.get(scope as usize).copied().flatten() {
                        Some(id) => {
                            is_back = self.scope_head.get(scope as usize) == Some(&id);
                            Some(id)
                        }
                        None => {
                            self.diagnostics.push(Diagnostic::error(
                                span,
                                "continue names a loop with no resolved target",
                            ));
                            None
                        }
                    }
                }
            };
            match dst {
                Some(dst) => edges.push(CfgEdge {
                    src: raw.src,
                    dst,
                    kind: raw.kind,
                    is_back,
                }),
                None => {
                    if let Some(node) = self.nodes.get_mut(raw.src.index()) {
                        let node_span = node.span();
                        *node = CfgNode::single(NodeKind::Diverge, node_span);
                    }
                }
            }
        }

        let targets = self.scope_continue.iter().copied().flatten().collect();
        let cfg = Cfg::assemble(self.nodes, edges, self.entry, self.exit, targets);
        Parsed::new(cfg, self.diagnostics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(lo: u32) -> Span {
        Span::new(lo, lo + 1)
    }

    fn sym(raw: u32) -> Symbol {
        Symbol::new(raw)
    }

    fn build(flows: Vec<Flow>) -> (Cfg, Diagnostics) {
        let mut builder = CfgBuilder::new(Span::new(0, 1000));
        builder.extend(flows);
        builder.finish().into_parts()
    }

    fn node_of(cfg: &Cfg, span_lo: u32) -> NodeId {
        for (index, node) in cfg.nodes().iter().enumerate() {
            if node.spans().iter().any(|s| s.lo == span_lo) {
                return NodeId::new(index as u32);
            }
        }
        panic!("no node carries a span starting at {span_lo}");
    }

    fn successor_with(cfg: &Cfg, from: NodeId, kind: EdgeKind) -> NodeId {
        cfg.successor_edges(from)
            .iter()
            .find(|e| e.kind == kind)
            .map(|e| e.dst)
            .unwrap_or_else(|| panic!("{from} has no {kind:?} successor"))
    }

    #[test]
    fn an_empty_function_is_an_entry_wired_straight_to_the_function_end() {
        let (cfg, diagnostics) = build(vec![]);
        assert!(diagnostics.is_empty());
        assert_eq!(cfg.node_count(), 2);
        assert_eq!(cfg.edge_count(), 1);
        assert_eq!(cfg.successors(cfg.entry()).next(), Some(cfg.exit()));
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn node_ids_are_dense_in_construction_order() {
        let (cfg, _) = build(vec![
            Flow::Stmt(s(10)),
            Flow::Stmt(s(20)),
            Flow::Stmt(s(30)),
        ]);
        assert_eq!(cfg.node_count(), 5);
        assert_eq!(node_of(&cfg, 10), NodeId::new(2));
        assert_eq!(node_of(&cfg, 20), NodeId::new(3));
        assert_eq!(node_of(&cfg, 30), NodeId::new(4));
    }

    #[test]
    fn a_straight_line_of_statements_coalesces_into_one_block() {
        let (cfg, _) = build(vec![
            Flow::Stmt(s(10)),
            Flow::Stmt(s(20)),
            Flow::Stmt(s(30)),
        ]);
        let block = cfg.coalesced();
        // Entry, the three statements as one chain, and the function end.
        assert_eq!(block.node_count(), 3);
        let merged: Vec<usize> = block.nodes().iter().map(|n| n.spans().len()).collect();
        assert_eq!(merged.iter().copied().max(), Some(3));
        assert!(block.validate().is_empty());
    }

    #[test]
    fn a_branch_has_a_true_and_a_false_successor_that_join() {
        let (cfg, diagnostics) = build(vec![
            Flow::Branch { cond: s(10) },
            Flow::Then,
            Flow::Stmt(s(20)),
            Flow::Else,
            Flow::Stmt(s(30)),
            Flow::EndScope,
            Flow::Stmt(s(40)),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let cond = node_of(&cfg, 10);
        assert_eq!(cfg.out_degree(cond), 2);
        assert_eq!(
            successor_with(&cfg, cond, EdgeKind::True),
            node_of(&cfg, 20)
        );
        assert_eq!(
            successor_with(&cfg, cond, EdgeKind::False),
            node_of(&cfg, 30)
        );
        let join = node_of(&cfg, 40);
        assert_eq!(cfg.in_degree(join), 2);
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn a_branch_without_an_else_arm_lets_the_false_edge_reach_the_join() {
        let (cfg, diagnostics) = build(vec![
            Flow::Branch { cond: s(10) },
            Flow::Then,
            Flow::Stmt(s(20)),
            Flow::EndScope,
            Flow::Stmt(s(40)),
        ]);
        assert!(diagnostics.is_empty());
        let cond = node_of(&cfg, 10);
        assert_eq!(
            successor_with(&cfg, cond, EdgeKind::False),
            node_of(&cfg, 40)
        );
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn a_while_loop_closes_a_back_edge_to_its_header() {
        let (cfg, diagnostics) = build(vec![
            Flow::LoopHeader {
                kind: LoopKind::While,
                cond: s(10),
            },
            Flow::Stmt(s(20)),
            Flow::EndScope,
            Flow::Stmt(s(30)),
        ]);
        assert!(diagnostics.is_empty());
        let header = node_of(&cfg, 10);
        let body = node_of(&cfg, 20);
        assert_eq!(successor_with(&cfg, header, EdgeKind::True), body);
        assert_eq!(
            successor_with(&cfg, header, EdgeKind::False),
            node_of(&cfg, 30)
        );
        let back = cfg.successor_edges(body)[0];
        assert_eq!(back.dst, header);
        assert!(back.is_back, "the body must return to the header");
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn a_do_while_loop_runs_its_body_before_the_test() {
        let (cfg, diagnostics) = build(vec![
            Flow::LoopHeader {
                kind: LoopKind::DoWhile,
                cond: s(10),
            },
            Flow::Stmt(s(20)),
            Flow::EndScope,
            Flow::Stmt(s(30)),
        ]);
        assert!(diagnostics.is_empty());
        let header = node_of(&cfg, 10);
        let body = node_of(&cfg, 20);
        assert_eq!(cfg.successors(cfg.entry()).next(), Some(body));
        assert_eq!(cfg.successors(body).next(), Some(header));
        let back = cfg
            .successor_edges(header)
            .iter()
            .find(|e| e.is_back)
            .copied()
            .expect("the test must return to the body");
        assert_eq!(back.dst, body);
        assert_eq!(
            successor_with(&cfg, header, EdgeKind::False),
            node_of(&cfg, 30)
        );
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn a_for_loop_sends_continue_to_the_step_rather_than_the_test() {
        let (cfg, diagnostics) = build(vec![
            Flow::Stmt(s(5)),
            Flow::LoopHeader {
                kind: LoopKind::For,
                cond: s(10),
            },
            Flow::Continue {
                label: None,
                span: s(20),
            },
            Flow::LoopStep,
            Flow::Stmt(s(30)),
            Flow::EndScope,
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let step = node_of(&cfg, 30);
        let continue_node = node_of(&cfg, 20);
        assert_eq!(cfg.successors(continue_node).next(), Some(step));
        assert_eq!(cfg.continue_targets(), &[step]);
        assert_eq!(cfg.successors(step).next(), Some(node_of(&cfg, 10)));
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn a_for_loop_without_a_step_region_sends_continue_to_the_test() {
        let (cfg, diagnostics) = build(vec![
            Flow::LoopHeader {
                kind: LoopKind::For,
                cond: s(10),
            },
            Flow::Continue {
                label: None,
                span: s(20),
            },
            Flow::EndScope,
        ]);
        assert!(diagnostics.is_empty());
        assert_eq!(
            cfg.successors(node_of(&cfg, 20)).next(),
            Some(node_of(&cfg, 10))
        );
    }

    #[test]
    fn a_break_leaves_the_innermost_loop_and_lands_after_it() {
        let (cfg, diagnostics) = build(vec![
            Flow::LoopHeader {
                kind: LoopKind::While,
                cond: s(10),
            },
            Flow::Break {
                label: None,
                span: s(20),
            },
            Flow::EndScope,
            Flow::Stmt(s(30)),
        ]);
        assert!(diagnostics.is_empty());
        assert_eq!(
            cfg.successors(node_of(&cfg, 20)).next(),
            Some(node_of(&cfg, 30))
        );
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn nested_loops_send_break_and_continue_to_their_own_loop() {
        let (cfg, diagnostics) = build(vec![
            Flow::LoopHeader {
                kind: LoopKind::While,
                cond: s(10),
            },
            Flow::LoopHeader {
                kind: LoopKind::While,
                cond: s(20),
            },
            Flow::Branch { cond: s(25) },
            Flow::Then,
            Flow::Break {
                label: None,
                span: s(30),
            },
            Flow::Else,
            Flow::Continue {
                label: None,
                span: s(40),
            },
            Flow::EndScope,
            Flow::EndScope,
            Flow::Stmt(s(50)),
            Flow::EndScope,
            Flow::Stmt(s(60)),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        // The break leaves the inner loop only, landing on what follows it.
        assert_eq!(
            cfg.successors(node_of(&cfg, 30)).next(),
            Some(node_of(&cfg, 50))
        );
        assert_eq!(
            cfg.successors(node_of(&cfg, 40)).next(),
            Some(node_of(&cfg, 20))
        );
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn a_labelled_break_leaves_several_levels_at_once() {
        let outer = sym(7);
        let (cfg, diagnostics) = build(vec![
            Flow::Label {
                name: outer,
                span: s(5),
            },
            Flow::LoopHeader {
                kind: LoopKind::While,
                cond: s(10),
            },
            Flow::LoopHeader {
                kind: LoopKind::While,
                cond: s(20),
            },
            Flow::Switch {
                arms: 1,
                subject: s(25),
            },
            Flow::Case {
                span: s(26),
                default: false,
            },
            Flow::Break {
                label: Some(outer),
                span: s(30),
            },
            Flow::EndScope,
            Flow::EndScope,
            Flow::EndScope,
            Flow::Stmt(s(60)),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(
            cfg.successors(node_of(&cfg, 30)).next(),
            Some(node_of(&cfg, 60)),
            "the labelled break must leave the switch and both loops"
        );
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn a_break_inside_a_switch_inside_a_loop_leaves_the_switch_only() {
        let (cfg, diagnostics) = build(vec![
            Flow::LoopHeader {
                kind: LoopKind::While,
                cond: s(10),
            },
            Flow::Switch {
                arms: 1,
                subject: s(20),
            },
            Flow::Case {
                span: s(25),
                default: true,
            },
            Flow::Break {
                label: None,
                span: s(30),
            },
            Flow::EndScope,
            Flow::Stmt(s(40)),
            Flow::EndScope,
            Flow::Stmt(s(50)),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(
            cfg.successors(node_of(&cfg, 30)).next(),
            Some(node_of(&cfg, 40)),
            "the break belongs to the switch, not the loop"
        );
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn a_switch_arm_that_does_not_break_falls_through_to_the_next_arm() {
        let (cfg, diagnostics) = build(vec![
            Flow::Switch {
                arms: 2,
                subject: s(10),
            },
            Flow::Case {
                span: s(20),
                default: false,
            },
            Flow::Stmt(s(25)),
            Flow::Case {
                span: s(30),
                default: true,
            },
            Flow::Stmt(s(35)),
            Flow::EndScope,
            Flow::Stmt(s(40)),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let fall = cfg.successor_edges(node_of(&cfg, 25))[0];
        assert_eq!(fall.kind, EdgeKind::FallThrough);
        assert_eq!(fall.dst, node_of(&cfg, 30));
        let dispatch = node_of(&cfg, 10);
        assert_eq!(
            successor_with(&cfg, dispatch, EdgeKind::Default),
            node_of(&cfg, 30)
        );
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn a_switch_without_a_default_arm_can_fall_out_of_the_dispatch() {
        let (cfg, diagnostics) = build(vec![
            Flow::Switch {
                arms: 1,
                subject: s(10),
            },
            Flow::Case {
                span: s(20),
                default: false,
            },
            Flow::Break {
                label: None,
                span: s(25),
            },
            Flow::EndScope,
            Flow::Stmt(s(40)),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let dispatch = node_of(&cfg, 10);
        assert_eq!(cfg.out_degree(dispatch), 2);
        assert_eq!(
            successor_with(&cfg, dispatch, EdgeKind::Default),
            node_of(&cfg, 40),
            "an unmatched value must be able to leave the switch"
        );
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn a_switch_whose_declared_arm_count_disagrees_is_a_diagnostic() {
        let (_, diagnostics) = build(vec![
            Flow::Switch {
                arms: 3,
                subject: s(10),
            },
            Flow::Case {
                span: s(20),
                default: true,
            },
            Flow::EndScope,
        ]);
        assert_eq!(diagnostics.error_count(), 1);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("declared 3 arms but 1 arrived")));
    }

    #[test]
    fn a_goto_to_a_later_label_is_backpatched_in_the_second_pass() {
        let target = sym(3);
        let (cfg, diagnostics) = build(vec![
            Flow::Goto {
                label: target,
                span: s(10),
            },
            Flow::Stmt(s(20)),
            Flow::Label {
                name: target,
                span: s(30),
            },
            Flow::Stmt(s(40)),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(
            cfg.successors(node_of(&cfg, 10)).next(),
            Some(node_of(&cfg, 30))
        );
        // The statement between the goto and the label is unreachable, which is
        // exactly what the first invariant is for.
        let report = cfg.validate();
        assert!(report
            .iter()
            .any(|d| d.message.contains("not reachable from the entry")));
    }

    #[test]
    fn a_goto_to_an_earlier_label_closes_a_cycle() {
        let target = sym(3);
        let (cfg, diagnostics) = build(vec![
            Flow::Label {
                name: target,
                span: s(10),
            },
            Flow::Branch { cond: s(20) },
            Flow::Then,
            Flow::Goto {
                label: target,
                span: s(30),
            },
            Flow::EndScope,
            Flow::Stmt(s(40)),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(
            cfg.successors(node_of(&cfg, 30)).next(),
            Some(node_of(&cfg, 10))
        );
        let closes = cfg.cycle_closing_edges();
        assert!(closes.iter().any(|&b| b), "the goto must close a cycle");
        assert!(cfg.validate().is_empty(), "a jump may close a cycle");
    }

    #[test]
    fn a_goto_to_a_missing_label_is_a_diagnostic_rather_than_a_panic() {
        let (cfg, diagnostics) = build(vec![
            Flow::Goto {
                label: sym(9),
                span: s(10),
            },
            Flow::Stmt(s(20)),
        ]);
        assert_eq!(diagnostics.error_count(), 1);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("never defined")));
        let orphan = node_of(&cfg, 10);
        assert_eq!(cfg.out_degree(orphan), 0);
        assert_eq!(
            cfg.node(orphan).map(CfgNode::kind),
            Some(NodeKind::Diverge),
            "an unresolvable transfer diverges rather than dangling"
        );
    }

    #[test]
    fn a_label_defined_twice_is_a_diagnostic() {
        let name = sym(2);
        let (_, diagnostics) = build(vec![
            Flow::Label { name, span: s(10) },
            Flow::Label { name, span: s(20) },
        ]);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("defined more than once")));
    }

    #[test]
    fn a_return_flows_to_the_function_end() {
        let (cfg, diagnostics) = build(vec![Flow::Return(s(10)), Flow::Stmt(s(20))]);
        assert!(diagnostics.is_empty());
        assert_eq!(cfg.successors(node_of(&cfg, 10)).next(), Some(cfg.exit()));
        assert_eq!(
            cfg.node(node_of(&cfg, 10)).map(CfgNode::kind),
            Some(NodeKind::Return)
        );
    }

    #[test]
    fn a_diverging_construct_ends_a_path_without_reaching_the_function_end() {
        let (cfg, diagnostics) = build(vec![
            Flow::Branch { cond: s(10) },
            Flow::Then,
            Flow::Diverge(s(20)),
            Flow::EndScope,
            Flow::Stmt(s(30)),
        ]);
        assert!(diagnostics.is_empty());
        let diverge = node_of(&cfg, 20);
        assert_eq!(cfg.out_degree(diverge), 0);
        assert!(
            cfg.validate().is_empty(),
            "a diverging construct satisfies the second invariant"
        );
    }

    #[test]
    fn a_break_outside_any_loop_is_a_diagnostic_rather_than_a_panic() {
        let (cfg, diagnostics) = build(vec![Flow::Break {
            label: None,
            span: s(10),
        }]);
        assert_eq!(diagnostics.error_count(), 1);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("no enclosing loop or switch")));
        assert_eq!(
            cfg.node(node_of(&cfg, 10)).map(CfgNode::kind),
            Some(NodeKind::Diverge)
        );
    }

    #[test]
    fn a_continue_outside_any_loop_is_a_diagnostic_rather_than_a_panic() {
        let (_, diagnostics) = build(vec![Flow::Continue {
            label: None,
            span: s(10),
        }]);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("no enclosing loop")));
    }

    #[test]
    fn a_labelled_break_naming_nothing_is_a_diagnostic_rather_than_a_panic() {
        let (_, diagnostics) = build(vec![
            Flow::LoopHeader {
                kind: LoopKind::While,
                cond: s(10),
            },
            Flow::Break {
                label: Some(sym(99)),
                span: s(20),
            },
            Flow::EndScope,
        ]);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("no enclosing loop or switch")));
    }

    #[test]
    fn an_unbalanced_scope_is_closed_with_a_diagnostic() {
        let (cfg, diagnostics) = build(vec![
            Flow::LoopHeader {
                kind: LoopKind::While,
                cond: s(10),
            },
            Flow::Stmt(s(20)),
        ]);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("never closed")));
        assert!(cfg.validate().is_empty(), "the graph is still well formed");
    }

    #[test]
    fn an_end_scope_with_no_open_scope_is_a_diagnostic() {
        let (_, diagnostics) = build(vec![Flow::EndScope]);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("no scope open")));
    }

    #[test]
    fn a_branch_arm_outside_any_branch_is_a_diagnostic() {
        let (_, diagnostics) = build(vec![Flow::Then, Flow::Else]);
        assert_eq!(diagnostics.error_count(), 2);
    }

    #[test]
    fn a_branch_closed_with_no_arms_still_joins_both_edges() {
        let (cfg, diagnostics) = build(vec![
            Flow::Branch { cond: s(10) },
            Flow::EndScope,
            Flow::Stmt(s(20)),
        ]);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("neither arm emitted")));
        assert_eq!(cfg.out_degree(node_of(&cfg, 10)), 2);
    }

    #[test]
    fn a_case_outside_any_switch_is_a_diagnostic_rather_than_a_panic() {
        let (cfg, diagnostics) = build(vec![Flow::Case {
            span: s(10),
            default: false,
        }]);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("outside any switch")));
        assert_eq!(cfg.node_count(), 3);
    }

    #[test]
    fn a_loop_step_outside_any_loop_is_a_diagnostic_rather_than_a_panic() {
        let (_, diagnostics) = build(vec![Flow::LoopStep]);
        assert!(diagnostics
            .iter()
            .any(|d| d.message.contains("outside any loop")));
    }

    #[test]
    fn every_flow_variant_builds_a_graph_that_satisfies_the_invariants() {
        let name = sym(1);
        let (cfg, diagnostics) = build(vec![
            Flow::Stmt(s(10)),
            Flow::Label { name, span: s(11) },
            Flow::LoopHeader {
                kind: LoopKind::For,
                cond: s(12),
            },
            Flow::Branch { cond: s(13) },
            Flow::Then,
            Flow::Continue {
                label: None,
                span: s(14),
            },
            Flow::Else,
            Flow::Switch {
                arms: 2,
                subject: s(15),
            },
            Flow::Case {
                span: s(16),
                default: false,
            },
            Flow::Break {
                label: None,
                span: s(17),
            },
            Flow::Case {
                span: s(18),
                default: true,
            },
            Flow::Diverge(s(19)),
            Flow::EndScope,
            Flow::EndScope,
            Flow::LoopStep,
            Flow::Stmt(s(21)),
            Flow::EndScope,
            Flow::Branch { cond: s(22) },
            Flow::Then,
            Flow::Goto {
                label: name,
                span: s(24),
            },
            Flow::EndScope,
            Flow::Return(s(23)),
        ]);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let report = cfg.validate();
        assert!(report.is_empty(), "{report:?}");
        assert!(cfg.coalesced().validate().is_empty());
    }

    #[test]
    fn deeply_nested_branches_build_validate_and_print_without_native_recursion() {
        const DEPTH: usize = 5_000;
        let mut flows = Vec::with_capacity(DEPTH * 2 + 1);
        for level in 0..DEPTH {
            flows.push(Flow::Branch {
                cond: s(level as u32),
            });
            flows.push(Flow::Then);
        }
        flows.push(Flow::Stmt(s(900_000)));
        for _ in 0..DEPTH {
            flows.push(Flow::EndScope);
        }
        let (cfg, diagnostics) = build(flows);
        assert!(diagnostics.is_empty());
        assert_eq!(cfg.node_count(), DEPTH + 3);
        assert!(cfg.validate().is_empty());
        assert!(cfg.reachable().iter().all(|&b| b));
        assert_eq!(cfg.cycle_closing_edges().iter().filter(|&&b| b).count(), 0);
        let _ = cfg.coalesced();
        assert!(!format!("{cfg:?}").is_empty());
    }

    #[test]
    fn deeply_nested_loops_resolve_a_labelled_break_out_of_every_level() {
        const DEPTH: usize = 2_000;
        let outer = sym(1);
        let mut flows = vec![Flow::Label {
            name: outer,
            span: s(1),
        }];
        for level in 0..DEPTH {
            flows.push(Flow::LoopHeader {
                kind: LoopKind::While,
                cond: s(100 + level as u32),
            });
        }
        flows.push(Flow::Break {
            label: Some(outer),
            span: s(900_000),
        });
        for _ in 0..DEPTH {
            flows.push(Flow::EndScope);
        }
        flows.push(Flow::Stmt(s(900_001)));
        let (cfg, diagnostics) = build(flows);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(
            cfg.successors(node_of(&cfg, 900_000)).next(),
            Some(node_of(&cfg, 900_001))
        );
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn identical_event_streams_build_byte_identical_graphs() {
        let flows = vec![
            Flow::LoopHeader {
                kind: LoopKind::For,
                cond: s(10),
            },
            Flow::Branch { cond: s(20) },
            Flow::Then,
            Flow::Break {
                label: None,
                span: s(30),
            },
            Flow::Else,
            Flow::Continue {
                label: None,
                span: s(40),
            },
            Flow::EndScope,
            Flow::LoopStep,
            Flow::Stmt(s(50)),
            Flow::EndScope,
        ];
        let (first, _) = build(flows.clone());
        let (second, _) = build(flows);
        assert_eq!(format!("{first:?}"), format!("{second:?}"));
    }
}
