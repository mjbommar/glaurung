//! `REQ-CFG-3` through `REQ-CFG-5`, `REQ-CFG-7` and `REQ-CFG-11` --- one C
//! statement mapped to the events that describe it.
//!
//! Spec: `docs/design/static-c-analysis/requirements.md`, the CFG construction
//! section. The event vocabulary is
//! `docs/design/source-front-ends/substrate.md` section 5.
//!
//! # The one construct the vocabulary does not describe directly
//!
//! A loop header is two things at once: the node every back edge returns to,
//! and the two-way test whose second edge leaves the construct. For
//! `while (a && b)` those are different nodes --- control returns to the test of
//! `a`, but the construct is left when `b` fails too --- and no single
//! [`Flow::LoopHeader`] can be both.
//!
//! So a loop whose condition contains a short-circuit is emitted as a header
//! carrying the whole condition, the condition's own fork skeleton inside the
//! loop, and a [`Flow::Break`] on the path where the skeleton says the
//! condition is false. The header's own false edge remains, which makes the
//! loop's exit reachable by two paths where one would do. That is an
//! over-approximation --- an edge control never takes --- and it is the
//! deliberate direction to err in: the alternative shapes either lose the
//! `REQ-CFG-6` operator node or let the loop be *entered* without evaluating
//! its operands, and an under-approximation is a graph that lies about what can
//! happen. A condition with no short-circuit --- the overwhelming majority ---
//! takes none of this: its header is its test, and there is no extra node and
//! no extra edge.
//!
//! `do`-`while` needs none of it either, because its test already sits below
//! its body: the fork skeleton is emitted at the end of the body and the header
//! is the join the skeleton flows into.
//!
//! # Reachability
//!
//! `REQ-GEN-1`'s first invariant is that every node is reachable from the
//! entry, and C source contains statements that are not: the `foo();` after a
//! `return`, and the declaration between a `switch` dispatch and its first
//! `case`. A statement control cannot reach contributes no node --- unless its
//! subtree carries a jump target, which is reached without falling into it.
//! [`super::reach::Reach`] answers both questions before the walk starts.

use crate::syntax::cfg::{Flow, LoopKind};
use crate::syntax::ids::{NodeId, Span};

use super::reach::is_body;
use super::{bodies, goto_label, tag_of, Emitter, NodeTag, Task, Terminal};

/// How many nodes the arm census may visit before it gives up counting.
///
/// The count is compared against the number of [`Flow::Case`] events that
/// actually arrive, so a wrong answer costs a diagnostic rather than a wrong
/// graph. Bounding the walk keeps `REQ-ROB-3` true of a switch whose body a
/// recovered parse made enormous.
const MAX_ARM_SCAN: u32 = 1 << 20;

impl Emitter<'_> {
    /// Map one statement to events.
    ///
    /// Dispatch is on the node's tag alone. A tag this front end does not model
    /// contributes a straight-line node when it is an expression in statement
    /// position and nothing when it carries no control flow, so an unknown tag
    /// can never unbalance the scope stack.
    pub(super) fn statement(&mut self, node: NodeId) {
        let Some(tag) = tag_of(self.tree, node) else {
            return;
        };
        if !self.live && !self.is_entry_point(node) {
            return;
        }
        // Pushed first so it runs last: once the statement's own events are
        // done, whether the *next* one is reachable is a property of this
        // statement's whole subtree, which the pre-pass already folded.
        let falls = self.reach.falls(node);
        self.push_all(&[Task::Live(falls)]);
        let span = self.span(node);
        match tag {
            NodeTag::CompoundStmt | NodeTag::StmtExpr => {
                let tasks: Vec<Task> = self
                    .tree
                    .arena()
                    .children_iter(node)
                    .map(Task::Stmt)
                    .collect();
                self.push_all(&tasks);
            }
            NodeTag::ExprStmt => {
                self.push_all(&[Task::Expr {
                    node,
                    terminal: Terminal::Stmt(span),
                }]);
            }
            // `REQ-CFG-3`: a declaration is a node only when it initializes
            // something. The whole declaration is walked, not just the
            // initializer, so a `?:` in an array bound is still found.
            NodeTag::Decl => {
                if self.reach.init_in(node) {
                    self.push_all(&[Task::Expr {
                        node,
                        terminal: Terminal::Stmt(span),
                    }]);
                }
            }
            NodeTag::IfStmt => self.if_stmt(node, span),
            NodeTag::WhileStmt => self.loop_stmt(node, LoopKind::While, span),
            NodeTag::DoWhileStmt => self.loop_stmt(node, LoopKind::DoWhile, span),
            NodeTag::ForStmt => self.for_stmt(node, span),
            NodeTag::SwitchStmt => self.switch_stmt(node, span),
            NodeTag::CaseLabel => self.push_all(&[Task::Emit(Flow::Case {
                span,
                default: false,
            })]),
            NodeTag::DefaultLabel => self.push_all(&[Task::Emit(Flow::Case {
                span,
                default: true,
            })]),
            NodeTag::LabelStmt => {
                let name = self.intern_label(node);
                self.push_all(&[Task::Emit(Flow::Label { name, span })]);
            }
            NodeTag::GotoStmt => self.goto_stmt(node, span),
            NodeTag::BreakStmt => {
                self.push_all(&[Task::Emit(Flow::Break { label: None, span })]);
            }
            NodeTag::ContinueStmt => {
                self.push_all(&[Task::Emit(Flow::Continue { label: None, span })]);
            }
            NodeTag::ReturnStmt => {
                self.push_all(&[Task::Expr {
                    node,
                    terminal: Terminal::Return(span),
                }]);
            }
            // `REQ-CFG-11`: an unparsed region keeps its node, so a parse gap
            // costs fidelity but not a node count. An `asm` is the same shape
            // for the opposite reason --- it is fully parsed and deliberately
            // opaque.
            NodeTag::Error | NodeTag::Asm => {
                self.push_all(&[Task::Emit(Flow::Stmt(span))]);
            }
            // No control flow of its own: an empty statement, a directive line,
            // a `_Static_assert`, a `__label__` declaration.
            NodeTag::NullStmt
            | NodeTag::PpDirective
            | NodeTag::StaticAssert
            | NodeTag::LocalLabel => {}
            other => {
                if other.is_expression() {
                    self.push_all(&[Task::Expr {
                        node,
                        terminal: Terminal::Stmt(span),
                    }]);
                }
            }
        }
    }

    /// Whether an unreachable `node` still has to be emitted.
    ///
    /// A `goto` target and a `case` label are both reached without falling into
    /// them, so a statement list that is dead becomes live again at one; a
    /// `case` counts only inside a switch, since outside one it is a stray the
    /// builder reports rather than a jump target.
    fn is_entry_point(&self, node: NodeId) -> bool {
        self.reach.label_in(node) || (self.in_switch() && self.reach.case_in(node))
    }

    /// `if (cond) then [else otherwise]` --- `REQ-CFG-4`.
    fn if_stmt(&mut self, node: NodeId, span: Span) {
        let tree = self.tree;
        let cond = self.cond_child(node);
        let mut arms = bodies(tree, node);
        let then = arms.next();
        let otherwise = arms.next();
        let mut tasks = vec![self.cond_task(cond, Terminal::Branch(self.cond_span(cond, span)))];
        tasks.push(Task::Emit(Flow::Then));
        tasks.push(Task::Live(true));
        if let Some(then) = then {
            tasks.push(Task::Stmt(then));
        }
        if let Some(otherwise) = otherwise {
            tasks.push(Task::Emit(Flow::Else));
            tasks.push(Task::Live(true));
            tasks.push(Task::Stmt(otherwise));
        }
        tasks.push(Task::Emit(Flow::EndScope));
        self.push_all(&tasks);
    }

    /// `while (cond) body` and `do body while (cond);` --- `REQ-CFG-5`.
    fn loop_stmt(&mut self, node: NodeId, kind: LoopKind, span: Span) {
        let tree = self.tree;
        let cond = self.cond_child(node);
        let body = bodies(tree, node).next();
        let tasks = self.loop_tasks(kind, cond, span, body, None);
        self.push_all(&tasks);
    }

    /// `for (init; cond; step) body` --- `REQ-CFG-5`, including the step region
    /// that `continue` lands on rather than the test.
    fn for_stmt(&mut self, node: NodeId, span: Span) {
        let tree = self.tree;
        let clause = |tag: NodeTag| {
            tree.arena()
                .children_iter(node)
                .find(|child| tag_of(tree, *child) == Some(tag))
        };
        let init = clause(NodeTag::ForInit);
        let cond = clause(NodeTag::ForCond).and_then(|c| self.cond_child(c));
        let step = clause(NodeTag::ForStep).filter(|s| tree.arena().child_count(*s) > 0);
        let body = bodies(tree, node).next();
        let mut tasks = self.for_init_tasks(init);
        tasks.extend(self.loop_tasks(LoopKind::For, cond, span, body, step));
        self.push_all(&tasks);
    }

    /// The `for` initializer clause, which is a declaration or an expression.
    fn for_init_tasks(&self, init: Option<NodeId>) -> Vec<Task> {
        let Some(init) = init else {
            return Vec::new();
        };
        let tree = self.tree;
        let declarations: Vec<Task> = tree
            .arena()
            .children_iter(init)
            .filter(|child| tag_of(tree, *child) == Some(NodeTag::Decl))
            .map(Task::Stmt)
            .collect();
        if !declarations.is_empty() {
            return declarations;
        }
        if tree.arena().child_count(init) == 0 {
            return Vec::new();
        }
        vec![Task::Expr {
            node: init,
            terminal: Terminal::Stmt(self.span(init)),
        }]
    }

    /// The events of one loop, in the order they are emitted.
    ///
    /// The three shapes and the reason they differ are the module docs' subject.
    fn loop_tasks(
        &self,
        kind: LoopKind,
        cond: Option<NodeId>,
        span: Span,
        body: Option<NodeId>,
        step: Option<NodeId>,
    ) -> Vec<Task> {
        let cond_span = self.cond_span(cond, span);
        let forks = cond.is_some_and(|c| self.reach.sc_in(c));
        let mut tasks = vec![
            Task::Emit(Flow::LoopHeader {
                kind,
                cond: cond_span,
            }),
            Task::Live(true),
        ];
        if kind == LoopKind::DoWhile {
            if let Some(body) = body {
                tasks.push(Task::Stmt(body));
            }
            // The test is already below the body, so the skeleton simply flows
            // into it and no extra shape is needed.
            if forks {
                if let Some(cond) = cond {
                    tasks.push(Task::Expr {
                        node: cond,
                        terminal: Terminal::None,
                    });
                }
            }
            tasks.push(Task::Emit(Flow::EndScope));
            return tasks;
        }
        if forks {
            if let Some(cond) = cond {
                tasks.push(Task::Expr {
                    node: cond,
                    terminal: Terminal::Branch(cond_span),
                });
                tasks.push(Task::Emit(Flow::Then));
                tasks.push(Task::Live(true));
            }
        }
        if let Some(body) = body {
            tasks.push(Task::Stmt(body));
        }
        if forks {
            tasks.push(Task::Emit(Flow::Else));
            tasks.push(Task::Live(true));
            tasks.push(Task::Emit(Flow::Break {
                label: None,
                span: cond_span,
            }));
            tasks.push(Task::Emit(Flow::EndScope));
        }
        // The step region is the `continue` target, so it is emitted whenever
        // anything can reach it --- the body falling out of its end, or a
        // `continue` jumping forwards into it.
        if let Some(step) = step {
            let reachable = body.is_none_or(|b| self.reach.falls(b) || self.reach.continue_in(b));
            if reachable {
                tasks.push(Task::Emit(Flow::LoopStep));
                tasks.push(Task::Live(true));
                tasks.push(Task::Expr {
                    node: step,
                    terminal: Terminal::Stmt(self.span(step)),
                });
            }
        }
        tasks.push(Task::Emit(Flow::EndScope));
        tasks
    }

    /// `switch (subject) body` --- `REQ-CFG-4`.
    ///
    /// The region between the dispatch and the first arm is unreachable, which
    /// [`Emitter::emit`] records when it sees the dispatch; that is what makes
    /// `switch (x) { int y; case 1: ... }` --- legal C, and common --- produce
    /// no orphan node.
    fn switch_stmt(&mut self, node: NodeId, span: Span) {
        let tree = self.tree;
        let subject = self.cond_child(node);
        let body = bodies(tree, node).next();
        let arms = body.map_or(0, |b| self.count_arms(b));
        let mut tasks = vec![self.cond_task(
            subject,
            Terminal::Switch {
                arms,
                subject: self.cond_span(subject, span),
            },
        )];
        if let Some(body) = body {
            tasks.push(Task::Stmt(body));
        }
        tasks.push(Task::Emit(Flow::EndScope));
        self.push_all(&tasks);
    }

    /// How many `case` and `default` labels belong to the switch whose body is
    /// `body`.
    ///
    /// Walked with an explicit stack that stops at a nested `switch`, because
    /// that switch's arms are its own. It does *not* stop at a nested loop:
    /// Duff's device puts a `case` inside a `do`-`while` and the label still
    /// belongs to the outer switch.
    fn count_arms(&self, body: NodeId) -> u32 {
        let tree = self.tree;
        let mut stack = vec![body];
        let mut arms = 0u32;
        let mut visited = 0u32;
        while let Some(node) = stack.pop() {
            visited += 1;
            if visited > MAX_ARM_SCAN {
                break;
            }
            match tag_of(tree, node) {
                Some(NodeTag::CaseLabel) | Some(NodeTag::DefaultLabel) => {
                    arms = arms.saturating_add(1)
                }
                Some(NodeTag::SwitchStmt) if node != body => continue,
                _ => {}
            }
            for child in tree.arena().children_iter(node) {
                stack.push(child);
            }
        }
        arms
    }

    /// `goto label;` and the GNU computed form `goto *expr;` --- `REQ-CFG-7`.
    ///
    /// # The computed form
    ///
    /// `REQ-CFG-7` says a computed `goto` "must not silently produce an
    /// edge-free node, since that changes the degree sequence", and that the
    /// divergence must be recorded rather than guessed at. The target set is
    /// not actually a guess: C only lets a program name a label through GNU
    /// `&&label`, so the labels whose address this function takes are a sound
    /// over-approximation of where the jump can land, and
    /// [`super::reach::Reach::address_taken`] collects them.
    ///
    /// The event vocabulary has no n-way transfer, so the set is emitted as a
    /// chain of two-way tests each of whose true arm is one `goto` --- "the
    /// target is this one, or one of the rest". A function that takes no label
    /// address has nothing to over-approximate *to*, and there the abstention
    /// is all that is left: [`Flow::Diverge`] is a node with no successor,
    /// which is what "control leaves here and this layer cannot say where"
    /// means to [`crate::syntax::cfg::Cfg::validate`].
    fn goto_stmt(&mut self, node: NodeId, span: Span) {
        if let Some(name) = goto_label(self.tree, self.text, self.spans, node) {
            let label = self.labels.intern(&name);
            self.push_all(&[Task::Emit(Flow::Goto { label, span })]);
            return;
        }
        let targets: Vec<super::Symbol> = self
            .reach
            .address_taken()
            .to_vec()
            .iter()
            .map(|name| self.labels.intern(name))
            .collect();
        // The dispatch expression is evaluated first whichever shape follows,
        // so `goto *(a ? p : q)` still forks (`REQ-CFG-6`).
        let mut tasks = vec![Task::Expr {
            node,
            terminal: Terminal::None,
        }];
        if targets.is_empty() {
            tasks.push(Task::Emit(Flow::Diverge(span)));
            self.push_all(&tasks);
            return;
        }
        let last = targets.len() - 1;
        for (index, label) in targets.iter().enumerate() {
            if index < last {
                tasks.push(Task::Emit(Flow::Branch { cond: span }));
                tasks.push(Task::Emit(Flow::Then));
            }
            tasks.push(Task::Emit(Flow::Goto {
                label: *label,
                span,
            }));
            if index < last {
                tasks.push(Task::Emit(Flow::Else));
            }
        }
        for _ in 0..last {
            tasks.push(Task::Emit(Flow::EndScope));
        }
        self.push_all(&tasks);
    }

    /// The symbol for the label `node` defines.
    fn intern_label(&mut self, node: NodeId) -> super::Symbol {
        let name = self
            .tree
            .arena()
            .main_token(node)
            .and_then(|id| self.spans.get(id.index()))
            .and_then(|span| self.text.get(span.range()))
            .unwrap_or("")
            .to_string();
        self.labels.intern(&name)
    }

    /// The controlling expression of a construct, or `None` when a recovered
    /// parse left it out.
    fn cond_child(&self, node: NodeId) -> Option<NodeId> {
        let tree = self.tree;
        tree.arena().children_iter(node).find(|child| {
            tag_of(tree, *child).is_some_and(|tag| !is_body(tag) && tag.is_expression())
        })
    }

    /// The span to give a construct's test node: the condition's own, or the
    /// whole construct's when there is no condition to point at.
    fn cond_span(&self, cond: Option<NodeId>, fallback: Span) -> Span {
        cond.map_or(fallback, |node| self.span(node))
    }

    /// The task that places a construct's test node.
    ///
    /// With a condition it is the expression walk, so `REQ-CFG-6`'s forks land
    /// before the test; without one it is the bare event, so a recovered `if`
    /// still forks rather than silently becoming straight-line code.
    fn cond_task(&self, cond: Option<NodeId>, terminal: Terminal) -> Task {
        match cond {
            Some(node) => Task::Expr { node, terminal },
            None => match terminal.flow() {
                Some(flow) => Task::Emit(flow),
                None => Task::Live(self.live),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::csource::parse::parse;
    use crate::syntax::cfg::{Cfg, EdgeKind, NodeKind};

    /// The first function's graph, asserting it satisfies `REQ-GEN-1`.
    fn graph(text: &str) -> Cfg {
        let tree = parse(text).into_parts().0;
        let functions = tree.functions(text);
        let cfg = super::super::function_cfg(&tree, text, &functions[0])
            .into_parts()
            .0;
        let failures: Vec<String> = cfg.validate().iter().map(|d| d.render(text)).collect();
        assert!(failures.is_empty(), "{failures:#?}");
        cfg
    }

    fn kind_count(cfg: &Cfg, kind: NodeKind) -> usize {
        cfg.nodes().iter().filter(|n| n.kind() == kind).count()
    }

    #[test]
    fn a_plain_loop_condition_costs_one_header_and_nothing_else() {
        let cfg = graph("void f(int a) { while (a) g(); }");
        assert_eq!(kind_count(&cfg, NodeKind::LoopHeader), 1);
        assert_eq!(kind_count(&cfg, NodeKind::Break), 0);
        assert_eq!(kind_count(&cfg, NodeKind::Cond), 0);
    }

    #[test]
    fn a_short_circuit_loop_condition_forks_inside_the_loop() {
        let cfg = graph("void f(int a, int b) { while (a && b) g(); }");
        assert_eq!(kind_count(&cfg, NodeKind::LoopHeader), 1);
        assert_eq!(kind_count(&cfg, NodeKind::Cond), 2, "`a` and `a && b`");
        assert_eq!(
            kind_count(&cfg, NodeKind::Break),
            1,
            "the operator's false arm leaves the loop"
        );
        assert!(cfg.edges().iter().any(|e| e.is_back));
    }

    #[test]
    fn a_do_while_with_a_short_circuit_needs_no_break() {
        let cfg = graph("void f(int a, int b) { do g(); while (a && b); }");
        assert_eq!(kind_count(&cfg, NodeKind::Break), 0);
        assert_eq!(kind_count(&cfg, NodeKind::Cond), 1, "`a` forks");
        assert_eq!(kind_count(&cfg, NodeKind::LoopHeader), 1);
    }

    #[test]
    fn a_for_loop_emits_init_test_body_and_step_in_that_order() {
        let cfg = graph("void f(int n) { for (int i = 0; i < n; i++) g(); }");
        let spans: Vec<u32> = cfg.nodes().iter().map(|n| n.span().lo).collect();
        let header = cfg
            .nodes()
            .iter()
            .position(|n| n.kind() == NodeKind::LoopHeader)
            .expect("a header");
        assert!(
            spans[header - 1] < spans[header],
            "the init precedes the test"
        );
        assert_eq!(cfg.continue_targets().len(), 1);
    }

    #[test]
    fn a_for_loop_with_no_clauses_still_has_a_header() {
        let cfg = graph("void f(void) { for (;;) { g(); } }");
        assert_eq!(kind_count(&cfg, NodeKind::LoopHeader), 1);
    }

    #[test]
    fn a_break_leaves_the_loop_and_a_continue_returns_to_it() {
        let cfg = graph("void f(int a) { while (a) { if (a) break; else continue; } }");
        assert_eq!(kind_count(&cfg, NodeKind::Break), 1);
        assert_eq!(kind_count(&cfg, NodeKind::Continue), 1);
    }

    #[test]
    fn a_break_inside_a_switch_inside_a_loop_leaves_the_switch() {
        let cfg = graph("void f(int a) { while (a) { switch (a) { case 1: break; } g(); } }");
        let brk = cfg
            .nodes()
            .iter()
            .position(|n| n.kind() == NodeKind::Break)
            .map(|i| crate::syntax::ids::NodeId::new(i as u32))
            .expect("a break");
        let after = cfg.successors(brk).next().expect("a target");
        assert_eq!(
            cfg.node(after).map(|n| n.kind()),
            Some(NodeKind::Stmt),
            "the break reaches `g()`, not the loop header"
        );
    }

    #[test]
    fn a_nested_switchs_arms_belong_to_the_nested_switch() {
        let cfg = graph(
            "void f(int a) { switch (a) { case 1: switch (a) { case 2: g(); } break; default: h(); } }",
        );
        assert_eq!(kind_count(&cfg, NodeKind::Switch), 2);
        assert_eq!(kind_count(&cfg, NodeKind::Case), 3);
        let dispatch: Vec<usize> = cfg
            .nodes()
            .iter()
            .enumerate()
            .filter(|(_, n)| n.kind() == NodeKind::Switch)
            .map(|(i, _)| i)
            .collect();
        let outer = crate::syntax::ids::NodeId::new(dispatch[0] as u32);
        let dispatched = cfg
            .successor_edges(outer)
            .iter()
            .filter(|e| matches!(e.kind, EdgeKind::Case | EdgeKind::Default))
            .count();
        assert_eq!(dispatched, 2, "the outer switch has two arms of its own");
    }

    #[test]
    fn duffs_device_keeps_its_arms_on_the_outer_switch() {
        let cfg = graph(
            "void f(int n, char *p) { switch (n % 2) { case 0: do { *p++ = 0; case 1: *p++ = 1; } while (--n > 0); } }",
        );
        assert_eq!(kind_count(&cfg, NodeKind::Case), 2);
    }

    #[test]
    fn a_labelled_statement_is_a_node_a_later_goto_reaches() {
        let cfg = graph("void f(int a) { top: g(); if (a) goto top; }");
        assert_eq!(kind_count(&cfg, NodeKind::Label), 1);
        assert!(cfg.edges().iter().any(|e| e.kind == EdgeKind::Jump));
    }

    #[test]
    fn an_asm_statement_is_one_straight_line_node() {
        let cfg = graph("void f(void) { __asm__ volatile (\"nop\"); }");
        assert_eq!(kind_count(&cfg, NodeKind::Stmt), 1);
    }

    #[test]
    fn a_null_statement_contributes_nothing() {
        let cfg = graph("void f(void) { ; ; ; }");
        assert_eq!(cfg.node_count(), 2);
    }

    #[test]
    fn an_empty_loop_body_still_closes_its_cycle() {
        let cfg = graph("void f(int a) { while (a) ; }");
        assert_eq!(kind_count(&cfg, NodeKind::LoopHeader), 1);
        assert!(cfg.edges().iter().any(|e| e.is_back));
    }

    #[test]
    fn a_for_loop_whose_body_always_returns_emits_no_orphan_step() {
        // The body never falls out and never continues, so nothing can reach
        // the step; emitting it anyway would be a REQ-GEN-1 failure, which
        // `graph` asserts against.
        let cfg = graph("int f(int n) { for (int i = 0; i < n; i++) { return i; } return 0; }");
        assert_eq!(kind_count(&cfg, NodeKind::LoopHeader), 1);
    }

    #[test]
    fn a_for_loop_whose_body_only_continues_still_emits_its_step() {
        let cfg = graph("void f(int n) { for (int i = 0; i < n; i++) { continue; } }");
        assert_eq!(cfg.continue_targets().len(), 1);
    }
}
