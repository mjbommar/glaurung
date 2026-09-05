//! Syntax-shaped metrics: nesting, cognitive complexity, and the tag census.
//!
//! These read the AST rather than the graph, because the two answer different
//! questions. The CFG knows that a function has four branch points; only the
//! tree knows whether they are four flat `if`s or one nested four deep, and
//! that difference is most of what a reader means by "hard to follow".
//!
//! # Cognitive complexity, as implemented
//!
//! [`ShapeMetrics::cognitive`] follows G. Ann Campbell's *Cognitive
//! Complexity* specification (SonarSource, 2016--2021), restricted to the C
//! constructs that exist here. Written out, because an unstated variant of
//! this metric is not comparable with anyone else's:
//!
//! * **+1, plus the current nesting level**, for `if`, `switch`, `while`,
//!   `do`, `for`, and the `?:` conditional operator.
//! * **+1, with no nesting penalty**, for `else`, for an `else if`, and for
//!   `goto`. An `else if` is deliberately *not* charged the nesting its
//!   textual position would imply --- an `if`/`else if`/`else` ladder reads as
//!   one decision, and charging it as nesting is the single largest divergence
//!   between implementations of this metric.
//! * **+1 per run of like binary logical operators.** `a && b && c` is one
//!   run and scores 1; `a && b || c` is two runs and scores 2. A run is
//!   detected by comparing a node's operator with its parent's, so no
//!   flattening pass is needed.
//! * **Nesting increases** on entering the *body* of any structure in the
//!   first bullet, and nowhere else. A plain compound statement does not nest;
//!   a `case` arm does not nest inside its `switch`; and neither does a
//!   construct's header --- a `while`'s controlling expression, a `for`'s three
//!   clauses, a `switch`'s selector and a `?:`'s condition are all evaluated
//!   where the construct sits, not inside it. A ternary in a loop condition is
//!   therefore charged 1, not 2.
//!
//! Recursion is not charged (the specification's +1 for a recursive call): it
//! needs a call graph, and one function's text is not enough to know that a
//! name resolves back to the enclosing function rather than to a different
//! declaration with the same spelling.
//!
//! # No native recursion
//!
//! The walk is an explicit stack of [`Frame`]s (`REQ-SYN-3`) with a visit
//! budget, so a pathologically deep expression --- which decompiler output
//! produces routinely --- costs bounded work rather than a stack overflow that
//! takes the process down with no diagnostic.

use std::collections::{BTreeMap, BTreeSet};

use crate::csource::lex::kind::TokenKind;
use crate::csource::lex::lexeme;
use crate::csource::parse::tag::NodeTag;
use crate::csource::parse::Tree;
use crate::syntax::ids::NodeId;

/// A sentinel for "no enclosing logical operator" in [`Frame::parent_logical`].
const NO_OPERATOR: u16 = u16::MAX;

/// How a subtree is being entered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The ordinary case.
    Normal,
    /// An `if` reached as the `else` arm of another `if`, which the
    /// specification charges 1 with no nesting penalty.
    ElseIf,
}

/// One pending node in the walk.
#[derive(Debug, Clone, Copy)]
struct Frame {
    node: NodeId,
    /// The cognitive-complexity nesting level this node sits at.
    nesting: u32,
    /// How many loops enclose it, for [`ShapeMetrics::max_loop_depth`].
    loop_depth: u32,
    mode: Mode,
    /// The enclosing binary logical operator's token kind, or [`NO_OPERATOR`].
    parent_logical: u16,
}

/// Syntax-derived metrics for one function body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShapeMetrics {
    /// The deepest nesting of control structures reached, in levels.
    pub max_nesting: u32,
    /// The deepest nesting of loops specifically.
    pub max_loop_depth: u32,
    /// Cognitive complexity, per the module docs.
    pub cognitive: u32,
    /// Call expressions, counted once per argument list, so `f(g(x))` is two
    /// and a call through a function pointer counts like any other.
    pub calls: u32,
    /// Distinct directly-named callees, sorted. A call through a pointer or a
    /// member contributes to [`ShapeMetrics::calls`] and not to this list,
    /// because there is no name to record.
    pub callees: Vec<String>,
    /// How many nodes carry each tag, keyed by [`NodeTag::name`].
    pub tag_counts: BTreeMap<&'static str, u32>,
    /// Statement nodes of any kind.
    pub statements: u32,
    /// AST nodes in the body, whether the walk scored them or not.
    pub nodes: u32,
    /// Whether the visit budget stopped the walk, leaving every count here a
    /// lower bound rather than a measurement.
    pub truncated: bool,
}

/// The largest number of AST nodes one function's walk will visit.
///
/// A function body that exceeds this is not measured wrongly, it is measured
/// partially and says so via [`ShapeMetrics::truncated`] --- the same contract
/// [`crate::syntax::tree::Arena::preorder`] uses, and the same reason: a bound
/// that reports itself beats an unbounded walk over a tree built from hostile
/// input.
pub const MAX_VISITS: u32 = 2_000_000;

/// Whether a tag is a statement, for [`ShapeMetrics::statements`].
fn is_statement(tag: NodeTag) -> bool {
    matches!(
        tag,
        NodeTag::CompoundStmt
            | NodeTag::ExprStmt
            | NodeTag::NullStmt
            | NodeTag::IfStmt
            | NodeTag::WhileStmt
            | NodeTag::DoWhileStmt
            | NodeTag::ForStmt
            | NodeTag::SwitchStmt
            | NodeTag::CaseLabel
            | NodeTag::DefaultLabel
            | NodeTag::LabelStmt
            | NodeTag::GotoStmt
            | NodeTag::BreakStmt
            | NodeTag::ContinueStmt
            | NodeTag::ReturnStmt
    )
}

/// The token kind of `node`'s main token, if it has one.
fn main_kind(tree: &Tree, node: NodeId) -> Option<TokenKind> {
    tree.arena()
        .main_token(node)
        .map(|id| tree.tokens().kind(id))
        .and_then(TokenKind::from_u16)
}

/// The `&&` / `||` operator `node` applies, if it is one.
fn logical_operator(tree: &Tree, node: NodeId, tag: NodeTag) -> Option<TokenKind> {
    if tag != NodeTag::BinaryExpr {
        return None;
    }
    match main_kind(tree, node) {
        Some(kind @ (TokenKind::AmpAmp | TokenKind::PipePipe)) => Some(kind),
        _ => None,
    }
}

/// Measure the subtree rooted at `body`.
///
/// Total on any tree (`REQ-SYN-2`): a node whose tag the parser never resolved,
/// a child index that does not exist, a body that is a bare `Error` node ---
/// each contributes what it can and none of them fails the measurement.
pub fn measure(tree: &Tree, text: &str, body: NodeId) -> ShapeMetrics {
    let arena = tree.arena();
    let mut out = ShapeMetrics::default();
    let mut callees: BTreeSet<String> = BTreeSet::new();
    let mut budget = MAX_VISITS;

    let mut stack = vec![Frame {
        node: body,
        nesting: 0,
        loop_depth: 0,
        mode: Mode::Normal,
        parent_logical: NO_OPERATOR,
    }];

    while let Some(frame) = stack.pop() {
        if budget == 0 {
            out.truncated = true;
            break;
        }
        budget -= 1;
        out.nodes = out.nodes.saturating_add(1);

        let Some(tag) = arena.tag(frame.node).and_then(NodeTag::from_u16) else {
            // A node the parser left untagged still has children worth
            // counting, so descend rather than dropping the subtree.
            push_children(&mut stack, tree, &frame, frame.nesting, frame.loop_depth);
            continue;
        };
        *out.tag_counts.entry(tag.name()).or_insert(0) += 1;
        if is_statement(tag) {
            out.statements = out.statements.saturating_add(1);
        }
        out.max_nesting = out.max_nesting.max(frame.nesting);
        out.max_loop_depth = out.max_loop_depth.max(frame.loop_depth);

        match tag {
            NodeTag::IfStmt => {
                out.cognitive = out.cognitive.saturating_add(match frame.mode {
                    Mode::ElseIf => 1,
                    Mode::Normal => 1 + frame.nesting,
                });
                push_if_arms(&mut stack, tree, &frame, &mut out);
            }
            NodeTag::WhileStmt | NodeTag::DoWhileStmt | NodeTag::ForStmt => {
                out.cognitive = out.cognitive.saturating_add(1 + frame.nesting);
                push_body_nested(&mut stack, tree, &frame, frame.loop_depth + 1);
            }
            NodeTag::SwitchStmt => {
                out.cognitive = out.cognitive.saturating_add(1 + frame.nesting);
                push_body_nested(&mut stack, tree, &frame, frame.loop_depth);
            }
            NodeTag::CondExpr => {
                out.cognitive = out.cognitive.saturating_add(1 + frame.nesting);
                push_conditional_arms(&mut stack, tree, &frame);
            }
            NodeTag::GotoStmt => {
                out.cognitive = out.cognitive.saturating_add(1);
                push_children(&mut stack, tree, &frame, frame.nesting, frame.loop_depth);
            }
            NodeTag::PostfixExpr => {
                record_call(tree, text, frame.node, &mut out, &mut callees);
                push_children(&mut stack, tree, &frame, frame.nesting, frame.loop_depth);
            }
            _ => {
                if let Some(operator) = logical_operator(tree, frame.node, tag) {
                    // One increment per *run*: charge only where the run
                    // starts, which is where the parent applies a different
                    // operator (or is not a logical operator at all).
                    if frame.parent_logical != operator.as_u16() {
                        out.cognitive = out.cognitive.saturating_add(1);
                    }
                    push_children_with_operator(
                        &mut stack,
                        tree,
                        &frame,
                        frame.nesting,
                        frame.loop_depth,
                        operator.as_u16(),
                    );
                } else {
                    push_children(&mut stack, tree, &frame, frame.nesting, frame.loop_depth);
                }
            }
        }
    }

    out.callees = callees.into_iter().collect();
    out
}

/// Push a loop's or a `switch`'s children, nesting only the ones that are
/// statements.
///
/// The controlling expression of a `while`, the three clauses of a `for` and a
/// `switch`'s selector are *not* inside the construct's body, so the
/// specification's nesting increment does not apply to them --- only to the
/// body. Deciding that by tag rather than by child index is what makes one
/// arm cover all four constructs, whose child layouts differ: `do`'s body
/// precedes its condition, and `for` carries up to three clause children
/// before its body.
///
/// The `for` clause tags are deliberately outside [`is_statement`] for exactly
/// this reason --- they sit inside the tag table's statement range but are
/// parts of a header, not statements in a body.
fn push_body_nested(stack: &mut Vec<Frame>, tree: &Tree, frame: &Frame, loop_depth: u32) {
    let arena = tree.arena();
    let count = arena.child_count(frame.node);
    for index in (0..count).rev() {
        let Some(child) = arena.child(frame.node, index) else {
            continue;
        };
        let is_body = arena
            .tag(child)
            .and_then(NodeTag::from_u16)
            .is_some_and(is_statement);
        stack.push(Frame {
            node: child,
            nesting: if is_body {
                frame.nesting + 1
            } else {
                frame.nesting
            },
            loop_depth: if is_body { loop_depth } else { frame.loop_depth },
            mode: Mode::Normal,
            parent_logical: NO_OPERATOR,
        });
    }
}

/// Push a `?:`'s condition at the current level and its two arms one deeper.
///
/// The arms are the nested part; the condition is evaluated where the operator
/// sits. Unlike a loop this cannot be decided by tag, because all three
/// children are expressions --- but unlike a loop the layout is fixed, so the
/// index is reliable.
fn push_conditional_arms(stack: &mut Vec<Frame>, tree: &Tree, frame: &Frame) {
    let arena = tree.arena();
    let count = arena.child_count(frame.node);
    for index in (0..count).rev() {
        let Some(child) = arena.child(frame.node, index) else {
            continue;
        };
        stack.push(Frame {
            node: child,
            nesting: if index == 0 {
                frame.nesting
            } else {
                frame.nesting + 1
            },
            loop_depth: frame.loop_depth,
            mode: Mode::Normal,
            parent_logical: NO_OPERATOR,
        });
    }
}

/// Push `frame`'s children, inheriting its enclosing logical operator.
fn push_children(
    stack: &mut Vec<Frame>,
    tree: &Tree,
    frame: &Frame,
    nesting: u32,
    loop_depth: u32,
) {
    push_children_with_operator(stack, tree, frame, nesting, loop_depth, NO_OPERATOR);
}

/// Push `frame`'s children in reverse, so the walk visits them left to right.
fn push_children_with_operator(
    stack: &mut Vec<Frame>,
    tree: &Tree,
    frame: &Frame,
    nesting: u32,
    loop_depth: u32,
    parent_logical: u16,
) {
    let arena = tree.arena();
    let count = arena.child_count(frame.node);
    for index in (0..count).rev() {
        if let Some(child) = arena.child(frame.node, index) {
            stack.push(Frame {
                node: child,
                nesting,
                loop_depth,
                mode: Mode::Normal,
                parent_logical,
            });
        }
    }
}

/// Push an `if`'s condition, then-arm and else-arm with the levels the
/// specification gives each.
///
/// The children are `[cond, then]` or `[cond, then, else]`; anything else is a
/// recovered parse, and the fallback treats every child as a plain body rather
/// than guessing which slot is missing.
fn push_if_arms(stack: &mut Vec<Frame>, tree: &Tree, frame: &Frame, out: &mut ShapeMetrics) {
    let arena = tree.arena();
    let count = arena.child_count(frame.node);
    if count < 2 {
        push_children(stack, tree, frame, frame.nesting, frame.loop_depth);
        return;
    }
    // Pushed in reverse: else, then, condition.
    if let Some(else_arm) = arena.child(frame.node, 2) {
        let else_is_if = arena.tag(else_arm).and_then(NodeTag::from_u16) == Some(NodeTag::IfStmt);
        if else_is_if {
            stack.push(Frame {
                node: else_arm,
                nesting: frame.nesting,
                loop_depth: frame.loop_depth,
                mode: Mode::ElseIf,
                parent_logical: NO_OPERATOR,
            });
        } else {
            out.cognitive = out.cognitive.saturating_add(1);
            stack.push(Frame {
                node: else_arm,
                nesting: frame.nesting + 1,
                loop_depth: frame.loop_depth,
                mode: Mode::Normal,
                parent_logical: NO_OPERATOR,
            });
        }
    }
    if let Some(then_arm) = arena.child(frame.node, 1) {
        stack.push(Frame {
            node: then_arm,
            nesting: frame.nesting + 1,
            loop_depth: frame.loop_depth,
            mode: Mode::Normal,
            parent_logical: NO_OPERATOR,
        });
    }
    if let Some(condition) = arena.child(frame.node, 0) {
        stack.push(Frame {
            node: condition,
            nesting: frame.nesting,
            loop_depth: frame.loop_depth,
            mode: Mode::Normal,
            parent_logical: NO_OPERATOR,
        });
    }
}

/// Count a call and record its callee when the callee is a plain name.
///
/// A postfix expression is a call when it carries a [`NodeTag::CallArgs`]
/// suffix; `f(a)(b)` carries two and is two calls.
fn record_call(
    tree: &Tree,
    text: &str,
    node: NodeId,
    out: &mut ShapeMetrics,
    callees: &mut BTreeSet<String>,
) {
    let arena = tree.arena();
    let count = arena.child_count(node);
    let mut call_suffixes = 0u32;
    for index in 0..count {
        let Some(child) = arena.child(node, index) else {
            continue;
        };
        if arena.tag(child).and_then(NodeTag::from_u16) == Some(NodeTag::CallArgs) {
            call_suffixes += 1;
        }
    }
    if call_suffixes == 0 {
        return;
    }
    out.calls = out.calls.saturating_add(call_suffixes);

    // The callee is the primary expression only when the *first* suffix is the
    // argument list: in `p->fn(x)` the first suffix is the member access, and
    // the name `p` is not what is being called.
    let first_suffix_is_call =
        arena.child(node, 1).and_then(|c| arena.tag(c)).and_then(NodeTag::from_u16)
            == Some(NodeTag::CallArgs);
    if !first_suffix_is_call {
        return;
    }
    let Some(primary) = arena.child(node, 0) else {
        return;
    };
    if arena.tag(primary).and_then(NodeTag::from_u16) != Some(NodeTag::NameRef) {
        return;
    }
    if let Some(token) = arena.main_token(primary) {
        // `lexeme`, not `Tokens::text`: the latter carries trailing trivia,
        // so `g ()` would record a callee named "g ".
        let name = lexeme(tree.tokens(), token, text);
        if !name.is_empty() {
            callees.insert(name.to_string());
        }
    }
}
