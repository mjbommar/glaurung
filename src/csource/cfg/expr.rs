//! `REQ-CFG-6` --- `&&`, `||` and `?:` are control flow, not expressions.
//!
//! Spec: `docs/design/static-c-analysis/requirements.md` `REQ-CFG-6`, and
//! `src/csource/parse/expr.rs`, which deliberately parses all three as ordinary
//! expression nodes and says so: "their control-flow meaning is the CFG layer's
//! job, not the parser's". This file is that job.
//!
//! # The shape, and why it is exactly this shape
//!
//! `REQ-CFG-6` states the graph directly. For `a && b`: node `a` forks to node
//! `b` and to the `&&` operator node; node `b` flows to the `&&` node; the `&&`
//! node carries the branch. `||` is the mirror. `?:` forks on its condition to
//! the two arms, which join at the conditional node.
//!
//! Every one of those is a [`crate::syntax::cfg::Flow::Branch`] with a `Then`
//! arm, an `Else` arm and an `EndScope`, followed by one *terminal* node that
//! the two arms join at. The terminal is the operator's own node, and what kind
//! of node it is depends on where the operator sits: the condition of an `if`
//! makes it a second `Branch` (so `if (a && b)` forks twice, which is the whole
//! point), a `return` value makes it the `Return`, and an expression statement
//! makes it that statement's node --- which is why an expression statement
//! containing a `?:` forks even though the statement has one successor.
//!
//! # Flat operator nodes
//!
//! `src/csource/parse/tag.rs` records that a binary chain is one *flat* node
//! per precedence level, so `a && b && c` is a single [`NodeTag::BinaryExpr`]
//! with three children rather than two nested ones. The expansion below is
//! therefore a loop over `n` operands producing `n - 1` nested branches and one
//! terminal, which is the same graph the nested reading would give.
//!
//! # No native recursion
//!
//! Nothing here calls itself. An expansion pushes [`Task`]s describing what to
//! do next onto the emitter's stack, so an expression nested ten thousand deep
//! costs heap and nothing else (`REQ-GEN-4`, `REQ-SYN-3`).

use crate::csource::lex::TokenKind;
use crate::csource::parse::tag::NodeTag;
use crate::csource::parse::Tree;
use crate::syntax::cfg::Flow;
use crate::syntax::ids::{NodeId, TokenId};

use super::{Emitter, Task, Terminal};

/// Which of the three short-circuit operators a node is.
///
/// Three variants rather than a bool plus a flag because each expands to a
/// different arm order: `&&` puts its continuation in the then-arm, `||` in the
/// else-arm, and `?:` uses both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScKind {
    /// `&&`: the right operand runs only when the left is true.
    And,
    /// `||`: the right operand runs only when the left is false.
    Or,
    /// `?:`: exactly one of the two arms runs.
    Cond,
}

/// Which short-circuit operator `node` is, if it is one.
///
/// The operator is read from the tokens *between the first two children* rather
/// than from the node's main token. Both would work today --- a flat binary
/// node's first directly-owned token is its operator --- but the gap scan stays
/// right if a future recovery path ever gives the node a token of its own
/// first, and it costs one or two token reads.
pub(super) fn logical_kind(tree: &Tree, node: NodeId, tag: NodeTag) -> Option<ScKind> {
    if tag == NodeTag::CondExpr {
        return Some(ScKind::Cond);
    }
    if tag != NodeTag::BinaryExpr {
        return None;
    }
    let arena = tree.arena();
    let (_, left_end) = arena.token_extent(arena.child(node, 0)?)?;
    let (right_start, _) = arena.token_extent(arena.child(node, 1)?)?;
    let tokens = tree.tokens();
    for raw in left_end..right_start {
        match TokenKind::from_u16(tokens.kind(TokenId::new(raw))) {
            Some(TokenKind::AmpAmp) => return Some(ScKind::And),
            Some(TokenKind::PipePipe) => return Some(ScKind::Or),
            _ => {}
        }
    }
    None
}

/// Whether `node` is an operand C never evaluates, so its short-circuits are
/// not control flow.
///
/// `sizeof (a && b)` yields a constant and runs neither operand; forking on it
/// would invent a branch no execution takes. The type-name forms carry no
/// expression at all, and an `asm` operand list or an `__attribute__` argument
/// is a token run the parser never gave a grammar to (`tag.rs`), so descending
/// into either could only produce a fork from text that is not an expression.
pub(super) fn is_unevaluated(tree: &Tree, node: NodeId, tag: NodeTag) -> bool {
    match tag {
        NodeTag::SizeofType | NodeTag::AlignofType | NodeTag::TypeName => true,
        NodeTag::Attribute | NodeTag::Asm | NodeTag::StaticAssert => true,
        NodeTag::UnaryExpr => matches!(
            tree.arena()
                .main_token(node)
                .map(|id| tree.tokens().kind(id))
                .and_then(TokenKind::from_u16),
            Some(TokenKind::KwSizeof) | Some(TokenKind::KwAlignof)
        ),
        _ => false,
    }
}

impl Emitter<'_> {
    /// Emit everything the evaluation of `node` contributes, ending at
    /// `terminal`.
    ///
    /// Three cases, in the order they are cheapest to decide:
    ///
    /// * the subtree carries no short-circuit at all, so the whole expression
    ///   is one straight-line item and only the terminal node is placed ---
    ///   this is the overwhelmingly common path, and it is `O(1)` because
    ///   [`super::reach::Reach`] already answered the question;
    /// * `node` *is* a short-circuit, so it expands to branches (below);
    /// * `node` merely *contains* one, so the walk descends into the children
    ///   that carry it and nothing else, then places the terminal.
    pub(super) fn expression(&mut self, node: NodeId, terminal: Terminal) {
        let Some(tag) = super::tag_of(self.tree, node) else {
            self.push_terminal(terminal);
            return;
        };
        if let Some(kind) = logical_kind(self.tree, node, tag) {
            let terminal = terminal.or_stmt(self.span(node));
            self.expand_short_circuit(node, kind, terminal);
            return;
        }
        if !self.reach.sc_in(node) {
            self.push_terminal(terminal);
            return;
        }
        // A GNU statement expression is a *statement* list wearing an
        // expression's clothes, so its control flow is the statement walker's,
        // not this one's.
        if tag == NodeTag::StmtExpr {
            let mut tasks: Vec<Task> = self
                .tree
                .arena()
                .children_iter(node)
                .map(Task::Stmt)
                .collect();
            tasks.push(Task::Live(true));
            self.push_terminal_then(terminal, tasks);
            return;
        }
        let tasks: Vec<Task> = self
            .tree
            .arena()
            .children_iter(node)
            .filter(|child| self.reach.sc_in(*child))
            .map(|child| Task::Expr {
                node: child,
                terminal: Terminal::None,
            })
            .collect();
        self.push_terminal_then(terminal, tasks);
    }

    /// Expand one short-circuit operator into branches and a join.
    ///
    /// `&&` with operands `c0..cn` becomes `Branch(c0) Then Branch(c1) Then ...
    /// c_last Else EndScope Else EndScope ... terminal`, so every operand but
    /// the last is a test whose false edge reaches the terminal directly and
    /// whose true edge reaches the next operand. `||` swaps which arm carries
    /// the continuation. `?:` puts one arm in each.
    ///
    /// A malformed node --- fewer than two children, which a recovered parse
    /// can produce --- degrades to the terminal alone rather than to an
    /// unbalanced scope stack (`REQ-SYN-2`).
    fn expand_short_circuit(&mut self, node: NodeId, kind: ScKind, terminal: Terminal) {
        let operands: Vec<NodeId> = self.tree.arena().children_iter(node).collect();
        if operands.len() < 2 {
            self.push_terminal(terminal);
            return;
        }
        self.short_circuits = self.short_circuits.saturating_add(1);
        let mut tasks: Vec<Task> = Vec::with_capacity(operands.len() * 4);
        match kind {
            ScKind::Cond => {
                let last = operands.len() - 1;
                tasks.push(Task::Expr {
                    node: operands[0],
                    terminal: Terminal::Branch(self.span(operands[0])),
                });
                tasks.push(Task::Emit(Flow::Then));
                tasks.push(Task::Live(true));
                // `a ?: b` has no then-arm; the omitted arm is simply empty,
                // and the branch's true edge reaches the join directly.
                if last > 1 {
                    tasks.push(Task::Expr {
                        node: operands[1],
                        terminal: Terminal::Stmt(self.span(operands[1])),
                    });
                }
                tasks.push(Task::Emit(Flow::Else));
                tasks.push(Task::Live(true));
                tasks.push(Task::Expr {
                    node: operands[last],
                    terminal: Terminal::Stmt(self.span(operands[last])),
                });
                tasks.push(Task::Emit(Flow::EndScope));
            }
            ScKind::And | ScKind::Or => {
                let last = operands.len() - 1;
                for &operand in &operands[..last] {
                    tasks.push(Task::Expr {
                        node: operand,
                        terminal: Terminal::Branch(self.span(operand)),
                    });
                    tasks.push(Task::Emit(Flow::Then));
                    if kind == ScKind::Or {
                        tasks.push(Task::Emit(Flow::Else));
                    }
                    tasks.push(Task::Live(true));
                }
                tasks.push(Task::Expr {
                    node: operands[last],
                    terminal: Terminal::Stmt(self.span(operands[last])),
                });
                for _ in 0..last {
                    if kind == ScKind::And {
                        tasks.push(Task::Emit(Flow::Else));
                        tasks.push(Task::Live(true));
                    }
                    tasks.push(Task::Emit(Flow::EndScope));
                }
            }
        }
        if let Some(flow) = terminal.flow() {
            tasks.push(Task::Emit(flow));
        }
        self.push_all(&tasks);
    }

    /// Queue `terminal`'s node, if it has one.
    fn push_terminal(&mut self, terminal: Terminal) {
        if let Some(flow) = terminal.flow() {
            self.push_all(&[Task::Emit(flow)]);
        }
    }

    /// Queue `before`, then `terminal`'s node.
    fn push_terminal_then(&mut self, terminal: Terminal, mut before: Vec<Task>) {
        if let Some(flow) = terminal.flow() {
            before.push(Task::Emit(flow));
        }
        self.push_all(&before);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csource::parse::parse;
    use crate::syntax::cfg::{Cfg, NodeKind};

    /// The CFG of the first function in `text`, with no validation failure.
    fn graph(text: &str) -> Cfg {
        let parsed = parse(text).into_parts().0;
        let functions = parsed.functions(text);
        let built = super::super::function_cfg(&parsed, text, &functions[0]);
        let cfg = built.into_parts().0;
        let failures: Vec<String> = cfg.validate().iter().map(|d| d.message.clone()).collect();
        assert!(failures.is_empty(), "{failures:#?}");
        cfg
    }

    fn kinds(cfg: &Cfg) -> Vec<NodeKind> {
        cfg.nodes().iter().map(|n| n.kind()).collect()
    }

    #[test]
    fn a_logical_and_is_two_tests_and_a_join() {
        let cfg = graph("int f(int a, int b) { int c = a && b; return c; }");
        // Entry, exit, the `a` test, the `b` operand, the `&&` join that is the
        // declaration's node, the return.
        let conds = kinds(&cfg).iter().filter(|k| **k == NodeKind::Cond).count();
        assert_eq!(conds, 1, "`a` is a test");
        let test = cfg
            .nodes()
            .iter()
            .position(|n| n.kind() == NodeKind::Cond)
            .map(|i| crate::syntax::ids::NodeId::new(i as u32))
            .expect("a test");
        assert_eq!(cfg.out_degree(test), 2, "`a` forks");
        let join = cfg
            .successors(test)
            .filter(|dst| cfg.in_degree(*dst) == 2)
            .count();
        assert_eq!(join, 1, "one successor of `a` is the join both paths reach");
    }

    #[test]
    fn an_if_on_a_logical_and_forks_twice() {
        let cfg = graph("int f(int a, int b) { if (a && b) return 1; return 0; }");
        let forks = cfg
            .nodes()
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                cfg.out_degree(crate::syntax::ids::NodeId::new(*index as u32)) == 2
            })
            .count();
        assert_eq!(forks, 2, "`a` and `a && b` both fork");
    }

    #[test]
    fn a_logical_or_mirrors_a_logical_and() {
        let and = graph("int f(int a, int b) { return a && b; }");
        let or = graph("int f(int a, int b) { return a || b; }");
        assert_eq!(and.node_count(), or.node_count());
        assert_eq!(and.edge_count(), or.edge_count());
    }

    #[test]
    fn a_flat_chain_gives_every_operand_but_the_last_a_fork() {
        let cfg = graph("int f(int a, int b, int c) { return a && b && c; }");
        let forks = (0..cfg.node_count())
            .filter(|i| cfg.out_degree(crate::syntax::ids::NodeId::new(*i as u32)) == 2)
            .count();
        assert_eq!(forks, 2, "`a` and `b` fork; `c` does not");
    }

    #[test]
    fn a_conditional_operator_in_an_expression_statement_still_forks() {
        let cfg = graph("void f(int a, int b, int c) { a = b ? c : 0; }");
        let forks = (0..cfg.node_count())
            .filter(|i| cfg.out_degree(crate::syntax::ids::NodeId::new(*i as u32)) == 2)
            .count();
        assert_eq!(
            forks, 1,
            "a statement with one successor still forks inside"
        );
    }

    #[test]
    fn a_short_circuit_inside_a_call_argument_forks() {
        let cfg = graph("void f(int a, int b) { g(a && b, 3); }");
        let forks = (0..cfg.node_count())
            .filter(|i| cfg.out_degree(crate::syntax::ids::NodeId::new(*i as u32)) == 2)
            .count();
        assert_eq!(forks, 1);
    }

    #[test]
    fn sizeof_does_not_fork() {
        let cfg = graph("unsigned f(int a, int b) { return sizeof(a && b); }");
        let forks = (0..cfg.node_count())
            .filter(|i| cfg.out_degree(crate::syntax::ids::NodeId::new(*i as u32)) == 2)
            .count();
        assert_eq!(forks, 0, "sizeof evaluates nothing");
    }

    #[test]
    fn the_operator_is_read_from_the_gap_between_the_operands() {
        let text = "int f(int a, int b) { return a && b; }";
        let tree = parse(text).into_parts().0;
        let node = tree
            .arena()
            .preorder_roots()
            .find(|n| super::super::tag_of(&tree, *n) == Some(NodeTag::BinaryExpr))
            .expect("a binary node");
        assert_eq!(
            logical_kind(&tree, node, NodeTag::BinaryExpr),
            Some(ScKind::And)
        );
    }

    #[test]
    fn an_arithmetic_binary_node_is_not_a_short_circuit() {
        let text = "int f(int a, int b) { return a + b; }";
        let tree = parse(text).into_parts().0;
        let node = tree
            .arena()
            .preorder_roots()
            .find(|n| super::super::tag_of(&tree, *n) == Some(NodeTag::BinaryExpr))
            .expect("a binary node");
        assert_eq!(logical_kind(&tree, node, NodeTag::BinaryExpr), None);
    }
}
