//! `F-5`..`F-7` --- the C parser: expressions, statements and declarations.
//!
//! Spec: `docs/design/static-c-analysis/roadmap.md` stage S1, and
//! `docs/design/static-c-analysis/requirements.md` `REQ-IN-3` (the GNU
//! surface), `REQ-IN-4` (ill-formed input must not abort the file),
//! `REQ-GEN-4`/`REQ-SYN-3` (no native recursion), `REQ-GEN-5` (the AST is
//! lowerable) and `REQ-SYN-2` (parsing never fails).
//!
//! # The shape: one explicit task stack, no native recursion
//!
//! A recursive-descent C parser is the archetypal stack-overflow victim, and
//! decompiler output has attacker-controlled nesting depth: nested casts,
//! parenthesised spines, long `||` chains. An abort is the *worst* available
//! failure, because a process that dies cannot report a per-function result,
//! and per-function failure is exactly the whole-file voiding mode this
//! programme exists to remove (`REQ-ROB-2`).
//!
//! So there is no `parse_expr` calling `parse_unary` calling `parse_primary`.
//! There is one loop over a [`Vec<Task>`](Task): every step pops a task, may
//! consume tokens, and may push the tasks that must run next --- **in reverse
//! order**, since the stack is LIFO. Nesting costs heap, and the only bound is
//! [`MAX_TASKS`], which produces a diagnostic rather than a signal. The tests
//! drive it 20,000 parentheses deep.
//!
//! # The three grammars, and where each lives
//!
//! * [`expr`] --- precedence climbing over C's ladder, with the flat-node
//!   representation [`tag`] explains. `&&`, `||` and `?:` are parsed as
//!   ordinary expressions here; their control-flow meaning is the CFG layer's
//!   job (`REQ-CFG-6`), not the parser's.
//! * [`stmt`] --- every statement form plus GNU statement expressions.
//! * [`decl`] --- declarations, kept only as far as `REQ-GEN-5` needs: the
//!   specifier run, the declarator with its name, and the initializer, which is
//!   the part that contributes control flow.
//! * [`look`] --- the bounded lookahead the other three ask questions of.
//!
//! # What "error" means here, and why some recoveries are warnings
//!
//! `REQ-SYN-2` makes parsing total, so the interesting distinction is not
//! success versus failure but *how much was lost*:
//!
//! * a **warning** is a recovery that lost nothing --- a missing `;` between
//!   two statements, say, where the construct is complete and the tree is
//!   exactly the tree the `;` would have produced;
//! * an **error** is a construct the parser could not model, and it always
//!   comes with a [`NodeTag::Error`] node holding the tokens that were
//!   discarded (`REQ-CFG-11`: an unparsed region keeps its node).
//!
//! The distinction is load-bearing for the corpus gate: the in-repo `.c` files
//! are **not** preprocessed (`REQ-IN-2` assumes they are), so they contain
//! X-macro call statements such as `AS_CASE(NOP, 0, 1)` with no `;`. That is a
//! lossless recovery, not a modelling failure, and calling it an error would be
//! reporting the absent preprocessor as a parser defect.

pub mod decl;
pub mod expr;
pub mod look;
pub mod stmt;
pub mod tag;

use crate::csource::lex::{lexeme, tokenize, TokenKind};
use crate::syntax::diag::{Diagnostic, Diagnostics, Parsed};
use crate::syntax::event::{Events, Marker};
use crate::syntax::ids::{NodeId, Span, TokenId};
use crate::syntax::recover::{ProgressMark, WorkBudget};
use crate::syntax::token::{Cursor, Tokens};
use crate::syntax::tree::{self, Arena};
use tag::NodeTag;

/// How deep the task stack may grow before the parser gives up on a file.
///
/// This is not a native-stack guard --- there is no native recursion to guard
/// --- it is a *memory* guard, and it is set far above anything real C reaches:
/// the machine spends roughly two tasks per nesting level, so 262,144 admits
/// input more than a hundred thousand parentheses deep. Exceeding it is
/// reported and stops the file, which is still better than the alternative
/// `REQ-GEN-4` names.
///
/// **Why not [`crate::syntax::recover::DepthBudget`].** That type's whole
/// design is RAII: `enter` hands back a [`DepthGuard`](crate::syntax::recover::DepthGuard)
/// whose `Drop` releases the level, which is exactly right for a recursive
/// parser, where "the scope that holds the guard" and "one level of nesting"
/// are the same thing. This parser deliberately has no such scope --- a level
/// of nesting is a `Task` on a `Vec`, outliving the function call that pushed
/// it --- so a guard would have nowhere to live. The task stack's own length
/// *is* the live depth, and bounding it is the same measurement by a shorter
/// route. `SyncSet`, `WorkBudget` and `ProgressMark` from the same module are
/// used as designed.
pub const MAX_TASKS: usize = 262_144;

/// Work units granted per token of input, bounding total parsing effort
/// (`REQ-SYN-4`, `REQ-ROB-3`).
///
/// Every task step and every token of bounded lookahead charges one unit. The
/// multiplier is empirical headroom, not a measurement: the corpus gate runs at
/// well under 10 units per token, so a file that reaches 64 is pathological by
/// construction rather than merely large.
const WORK_PER_TOKEN: u32 = 64;

/// A suspended step of the parse: what to do next, and the state it needs.
///
/// This enum *is* the call stack a recursive parser would have used, made data
/// so that its depth is heap-bounded rather than stack-bounded. Every variant
/// that owns an open node carries its [`Marker`], which is why the enum is not
/// `Copy`: a marker is the unique right to close one node, and moving it into
/// and out of the stack is what keeps "closed exactly once" true.
#[derive(Debug)]
enum Task {
    /// Parse one external declaration at file scope.
    ExternalDecl,
    /// Parse one statement.
    Stmt,
    /// Parse the next item of a compound statement, or close it at `}`.
    ///
    /// `last` is the cursor position when this task last ran; equality means a
    /// step made no progress, which is the canonical recovery-loop bug and is
    /// forced forward rather than spun on.
    Block { marker: Marker, last: u32 },
    /// Parse one expression, entering the precedence ladder at `level` with the
    /// operator levels `mask` says the region can contain.
    ExprAt { level: u8, mask: u16 },
    /// Run one precedence level's operator loop over an already-parsed operand.
    BinLoop {
        level: u8,
        mask: u16,
        marker: Marker,
        ops: u32,
    },
    /// Parse prefix operators, casts and `sizeof`, then a primary and its
    /// postfix chain.
    Unary { mask: u16 },
    /// Close a postfix chain, or abandon its wrapper when there were no
    /// suffixes.
    Postfix { marker: Marker, suffixes: u32 },
    /// Parse the next argument of a call, if a `,` follows.
    ArgsMore,
    /// Close `marker` now.
    Close(Marker),
    /// Consume `kind` (reporting its absence), then close `marker`.
    EatClose {
        kind: TokenKind,
        hard: bool,
        marker: Marker,
    },
    /// Consume `kind`, reporting its absence with `severity_is_error`.
    Eat { kind: TokenKind, hard: bool },
    /// Continue a multi-phase construct; see [`stmt::Cont`].
    Cont {
        what: Cont,
        marker: Marker,
        phase: u8,
    },
    /// Parse the next declarator of a declaration.
    Declarators { marker: Marker, index: u32 },
    /// Decide what follows a declarator: another one, or the end.
    DeclTail { marker: Marker, index: u32 },
    /// Parse the next element of a braced initializer, or close it at `}`.
    InitList { marker: Marker, last: u32 },
    /// Consume the `,` between two initializer elements. `start` is where the
    /// element began, which is what the next round compares against to catch a
    /// stalled loop.
    InitMore { marker: Marker, start: u32 },
}

/// Which multi-phase construct a [`Task::Cont`] is resuming.
///
/// One enum rather than one `Task` variant per construct: the phases differ but
/// the state is always the same triple (which construct, which node, how far
/// in), so a shared variant keeps [`Task`] small and keeps the resumption
/// points in one readable match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cont {
    /// `if (cond) stmt [else stmt]`.
    If,
    /// `while (cond) stmt`.
    While,
    /// `do stmt while (cond);`.
    Do,
    /// `for (init; cond; step) stmt`.
    For,
    /// `switch (cond) stmt`.
    Switch,
    /// `case expr [... expr]:`.
    Case,
    /// The `:` and else-arm of a `?:`.
    Cond,
}

/// The parser's whole mutable state.
///
/// Deliberately one struct rather than a set of free functions taking eight
/// arguments: every step needs the cursor, the event stream, the diagnostics
/// and the budgets, and threading four `&mut` through a task machine is how
/// borrow errors get resolved by cloning.
struct Parser<'a> {
    /// The source text, needed for identifier spellings and for deciding
    /// whether two tokens sit on the same line (preprocessor directives).
    text: &'a str,
    /// The cursor over the token buffer.
    cursor: Cursor<'a>,
    /// The event stream being built.
    events: Events,
    /// Everything reported so far.
    diags: Diagnostics,
    /// The remaining work budget (`REQ-SYN-4`).
    work: WorkBudget,
    /// The explicit task stack that replaces native recursion.
    tasks: Vec<Task>,
    /// Set once a budget was exhausted, so the file stops rather than
    /// reporting the same exhaustion at every remaining position.
    stopped: bool,
    /// Scratch opener stack for [`Parser::eat_balanced_until`], kept here so
    /// the hottest recovery loop in the parser allocates once per file rather
    /// than once per bracket group. Empty between calls; the function that
    /// borrows it is iterative and never re-enters itself.
    brackets: Vec<TokenKind>,
}

impl<'a> Parser<'a> {
    /// A parser positioned at the first token of `tokens`.
    fn new(text: &'a str, tokens: &'a Tokens, diags: Diagnostics) -> Self {
        let budget = (tokens.len() as u32)
            .saturating_mul(WORK_PER_TOKEN)
            .max(1024);
        Self {
            text,
            cursor: tokens.cursor(),
            events: Events::with_capacity(tokens.len() * 2),
            diags,
            work: WorkBudget::new(budget),
            tasks: Vec::new(),
            stopped: false,
            brackets: Vec::new(),
        }
    }

    // --- token access -------------------------------------------------------

    /// Whether the cursor has run out of tokens.
    fn at_eof(&self) -> bool {
        self.cursor.is_eof()
    }

    /// The kind of the current token, or [`TokenKind::Unknown`] at end of
    /// input --- so every caller must check [`Parser::at_eof`] first when the
    /// difference matters.
    fn peek(&self) -> TokenKind {
        TokenKind::from_u16(self.cursor.peek()).unwrap_or(TokenKind::Unknown)
    }

    /// The kind `n` tokens ahead, with the same end-of-input convention.
    fn nth(&self, n: u32) -> TokenKind {
        TokenKind::from_u16(self.cursor.peek_at(n)).unwrap_or(TokenKind::Unknown)
    }

    /// Whether the current token is `kind`.
    fn at(&self, kind: TokenKind) -> bool {
        !self.at_eof() && self.peek() == kind
    }

    /// Consume the current token into the innermost open node.
    ///
    /// A no-op at end of input: emitting the sentinel token id would give the
    /// enclosing node an extent past the last real token.
    fn bump(&mut self) {
        if self.at_eof() {
            return;
        }
        let id = self.cursor.bump();
        self.events.token(id);
    }

    /// Consume the current token if it is `kind`; report whether it was.
    fn eat(&mut self, kind: TokenKind) -> bool {
        if self.at(kind) {
            self.bump();
            true
        } else {
            false
        }
    }

    /// Consume `kind`, or report its absence without discarding anything.
    ///
    /// `hard` picks the severity, and the choice is the module docs' rule: a
    /// missing separator between two complete constructs loses nothing and is a
    /// warning, while a missing bracket means the parser's idea of the nesting
    /// and the text's have diverged, which is an error.
    fn expect(&mut self, kind: TokenKind, hard: bool) -> bool {
        if self.eat(kind) {
            return true;
        }
        let span = self.cursor.span();
        let found = if self.at_eof() {
            "end of input".to_string()
        } else {
            format!("`{}`", self.peek().name())
        };
        let message = format!("expected `{}`, found {found}", kind.name());
        let diag = if hard {
            Diagnostic::error(span, message)
        } else {
            Diagnostic::warning(span, message)
        };
        let id = self.diags.push(diag.expecting(&[kind.name()]));
        self.events.error(id);
        false
    }

    /// The spelling of the current token, for a diagnostic or an identifier.
    fn current_text(&self) -> &'a str {
        lexeme(self.cursor.tokens(), self.cursor.current(), self.text)
    }

    // --- event helpers ------------------------------------------------------

    /// Open a node with `tag`.
    fn open(&mut self, tag: NodeTag) -> Marker {
        self.events.open(tag.as_u16())
    }

    /// Close the node `marker` opened.
    fn close(&mut self, marker: Marker) {
        let _ = self.events.close(marker);
    }

    /// Rewrite an open node's tag --- the forward patch that makes the
    /// declaration-versus-expression and operand-versus-operator decisions
    /// cheap, since neither is known until after the first tokens are consumed.
    fn patch(&mut self, marker: &Marker, tag: NodeTag) {
        self.events.patch(marker, tag.as_u16());
    }

    /// Drop a speculative node, keeping its children under its parent.
    fn abandon(&mut self, marker: Marker) {
        self.events.abandon(marker);
    }

    /// Record an error at the current position, tying it into the stream.
    fn error(&mut self, message: impl Into<String>) {
        let span = self.cursor.span();
        let id = self.diags.push(Diagnostic::error(span, message));
        self.events.error(id);
    }

    /// Push a task to run next.
    fn push(&mut self, task: Task) {
        self.tasks.push(task);
    }

    // --- the driver ---------------------------------------------------------

    /// Run until the task stack empties or a budget stops the file.
    fn run(&mut self) {
        while let Some(task) = self.tasks.pop() {
            if self.stopped {
                self.discard(task);
                continue;
            }
            if !self.work.charge(1) {
                self.give_up("parser work budget exhausted; the rest of the file is unparsed");
                self.discard(task);
                continue;
            }
            if self.tasks.len() >= MAX_TASKS {
                self.give_up("parser nesting budget exhausted; the rest of the file is unparsed");
                self.discard(task);
                continue;
            }
            self.step(task);
        }
    }

    /// Report a budget failure once and mark the file stopped.
    fn give_up(&mut self, message: &str) {
        if !self.stopped {
            self.error(message);
            self.stopped = true;
        }
    }

    /// Release a task's marker without closing its node.
    ///
    /// Only reachable after [`Parser::give_up`]. The nodes stay open on the
    /// event stream's own stack and [`Events::close_all`] balances them, which
    /// is what keeps a truncated parse a *tree* rather than an unusable stream.
    fn discard(&mut self, task: Task) {
        match task {
            Task::Block { marker, .. }
            | Task::BinLoop { marker, .. }
            | Task::Postfix { marker, .. }
            | Task::Close(marker)
            | Task::EatClose { marker, .. }
            | Task::Cont { marker, .. }
            | Task::Declarators { marker, .. }
            | Task::DeclTail { marker, .. }
            | Task::InitList { marker, .. }
            | Task::InitMore { marker, .. } => self.events.forget(marker),
            Task::ExternalDecl
            | Task::Stmt
            | Task::ExprAt { .. }
            | Task::Unary { .. }
            | Task::ArgsMore
            | Task::Eat { .. } => {}
        }
    }

    /// Perform one task.
    fn step(&mut self, task: Task) {
        match task {
            Task::ExternalDecl => self.external_decl(),
            Task::Stmt => self.statement(),
            Task::Block { marker, last } => self.block_item(marker, last),
            Task::ExprAt { level, mask } => self.expr_at(level, mask),
            Task::BinLoop {
                level,
                mask,
                marker,
                ops,
            } => self.bin_loop(level, mask, marker, ops),
            Task::Unary { mask } => self.unary(mask),
            Task::Postfix { marker, suffixes } => self.postfix(marker, suffixes),
            Task::ArgsMore => self.args_more(),
            Task::Close(marker) => self.close(marker),
            Task::EatClose { kind, hard, marker } => {
                self.expect(kind, hard);
                self.close(marker);
            }
            Task::Eat { kind, hard } => {
                self.expect(kind, hard);
            }
            Task::Cont {
                what,
                marker,
                phase,
            } => self.cont(what, marker, phase),
            Task::Declarators { marker, index } => self.declarators(marker, index),
            Task::DeclTail { marker, index } => self.decl_tail(marker, index),
            Task::InitList { marker, last } => self.init_list(marker, last),
            Task::InitMore { marker, start } => self.init_more(marker, start),
        }
    }
}

/// A parsed C translation unit: the tokens it was read from and the tree.
///
/// Both halves are needed together and neither is useful alone --- a node's
/// extent is a pair of token indices, so a span (`REQ-GEN-2`, `REQ-SYN-7`)
/// cannot be answered without the buffer. Keeping them in one value is what
/// stops a caller pairing an arena with the wrong file's tokens.
#[derive(Debug, Clone)]
pub struct Tree {
    /// The token buffer the tree indexes into.
    tokens: Tokens,
    /// The nodes.
    arena: Arena,
}

impl Tree {
    /// The arena of nodes.
    pub fn arena(&self) -> &Arena {
        &self.arena
    }

    /// The token buffer the nodes index into.
    pub fn tokens(&self) -> &Tokens {
        &self.tokens
    }

    /// Every token's exact span, with the trailing trivia the buffer's implicit
    /// extents carry removed.
    ///
    /// The trap `csource::lex` documents, closed once for the whole tree:
    /// [`Tokens::span`] measures the distance to the *next* token, so a node
    /// span built from it ends somewhere inside the whitespace after the node.
    /// Recomputing each lexeme's length costs one re-lex of the file and buys
    /// spans a caller can slice source out of.
    pub fn token_spans(&self, text: &str) -> Vec<Span> {
        (0..self.tokens.len() as u32)
            .map(|raw| {
                let start = self.tokens.start(TokenId::new(raw));
                let len = crate::csource::lex::lexeme_len(text, start as usize) as u32;
                Span::new(start, start.saturating_add(len))
            })
            .collect()
    }

    /// The byte span of `node`, or `None` if it consumed no token.
    ///
    /// Convenience for a single lookup; a caller asking about many nodes should
    /// hoist [`Tree::token_spans`] out of its loop rather than paying a re-lex
    /// per node.
    pub fn node_span(&self, node: NodeId, text: &str) -> Option<Span> {
        self.arena.span(node, &self.token_spans(text))
    }

    /// Every function *definition* in the file, in source order.
    ///
    /// This is what the next two consumers want and neither should have to
    /// rediscover: the CFG builder of stage S2 needs one graph per definition
    /// (`REQ-CFG-2`), and `L-6` source extraction needs a name and an exact
    /// span --- which is what replaces `tools/roundtrip_review.py`'s
    /// brace-matching regular expression, whose own docstring records that "a
    /// real parser would be more robust".
    ///
    /// A declaration without a body yields nothing, per `REQ-CFG-2`.
    pub fn functions(&self, text: &str) -> Vec<FunctionDef> {
        let spans = self.token_spans(text);
        let mut found = Vec::new();
        for node in self.arena.preorder_roots() {
            if self.arena.tag(node) != Some(NodeTag::FuncDef.as_u16()) {
                continue;
            }
            let Some(span) = self.arena.span(node, &spans) else {
                continue;
            };
            let (name, name_span) = self.name_of(node, &spans, text);
            let body = self
                .arena
                .children_iter(node)
                .find(|child| self.arena.tag(*child) == Some(NodeTag::CompoundStmt.as_u16()));
            found.push(FunctionDef {
                name,
                name_span,
                span,
                node,
                body,
            });
        }
        found
    }

    /// The declared name of a function definition, read from the `DeclName`
    /// inside its declarator.
    ///
    /// Scoped to the declarator on purpose: the body is full of `DeclName`
    /// nodes belonging to local variables, so a whole-subtree search would
    /// return the first local rather than the function.
    fn name_of(&self, func: NodeId, spans: &[Span], text: &str) -> (String, Span) {
        let empty = Span::empty_at(spans.get(0).map_or(0, |s| s.lo));
        let Some(declarator) = self
            .arena
            .children_iter(func)
            .find(|child| self.arena.tag(*child) == Some(NodeTag::Declarator.as_u16()))
        else {
            return (String::new(), empty);
        };
        for node in self.arena.preorder(declarator) {
            if self.arena.tag(node) != Some(NodeTag::DeclName.as_u16()) {
                continue;
            }
            let Some(span) = self.arena.span(node, spans) else {
                continue;
            };
            let name = text.get(span.range()).unwrap_or("").to_string();
            return (name, span);
        }
        (String::new(), empty)
    }
}

/// One function definition found by [`Tree::functions`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDef {
    /// The declared name, or the empty string when the declarator had none.
    pub name: String,
    /// The span of the name token.
    pub name_span: Span,
    /// The span of the whole definition, specifiers through closing brace.
    pub span: Span,
    /// The `FuncDef` node.
    pub node: NodeId,
    /// The `CompoundStmt` body, absent only in a recovered parse.
    pub body: Option<NodeId>,
}

/// Parse C source text into a tree, reporting problems alongside it.
///
/// Total on every input (`REQ-SYN-2`): every byte sequence yields a tree, no
/// input panics, no input loops, and an unparseable construct costs a
/// [`NodeTag::Error`] node rather than the enclosing function or the file
/// (`REQ-IN-4`). The diagnostics include the lexer's.
///
/// Byte offsets are offsets into `text` exactly as passed, so
/// [`crate::csource::normalize`] runs *before* this, never after.
pub fn parse(text: &str) -> Parsed<Tree> {
    let lexed = tokenize(text);
    let (tokens, mut diags) = lexed.into_parts();
    let events = {
        let mut parser = Parser::new(text, &tokens, std::mem::take(&mut diags));
        // One external declaration per outer iteration, so a construct that
        // defeats the machine costs one declaration and not the file
        // (`REQ-ROB-2`).
        while !parser.at_eof() && !parser.stopped {
            let mark = ProgressMark::here(&parser.cursor);
            parser.push(Task::ExternalDecl);
            parser.run();
            if parser.stopped {
                break;
            }
            mark.ensure(&mut parser.cursor, &mut parser.diags);
        }
        parser.events.close_all();
        diags = std::mem::take(&mut parser.diags);
        std::mem::take(&mut parser.events)
    };
    let file = Span::new(0, tokens.end_of_input());
    let arena = tree::build(events.as_slice(), file, &mut diags);
    Parsed::new(Tree { tokens, arena }, diags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// Assert `text` parses with no error diagnostic, returning the tree.
    fn clean(text: &str) -> Tree {
        let parsed = parse(text);
        let bad: Vec<String> = parsed
            .diagnostics()
            .iter()
            .filter(|d| d.severity == crate::syntax::diag::Severity::Error)
            .map(|d| d.render(text))
            .collect();
        assert!(bad.is_empty(), "unexpected errors: {bad:#?}");
        parsed.into_parts().0
    }

    /// The tags of every node in the tree, as names, in construction order.
    fn tags(tree: &Tree) -> Vec<&'static str> {
        tree.arena()
            .preorder_roots()
            .filter_map(|node| tree.arena().tag(node))
            .filter_map(NodeTag::from_u16)
            .map(NodeTag::name)
            .collect()
    }

    #[test]
    fn a_function_definition_is_found_with_its_name_and_span() {
        let text = "int main(void) { return 0; }\n";
        let tree = clean(text);
        let functions = tree.functions(text);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "main");
        assert_eq!(
            &text[functions[0].span.range()],
            "int main(void) { return 0; }"
        );
        assert_eq!(&text[functions[0].name_span.range()], "main");
        assert!(functions[0].body.is_some());
    }

    #[test]
    fn a_declaration_without_a_body_is_not_a_function_definition() {
        // `REQ-CFG-2`: one CFG per definition; a prototype yields nothing.
        let tree = clean("int f(int a);\nstruct s;\nextern int v;\n");
        assert!(tree
            .functions("int f(int a);\nstruct s;\nextern int v;\n")
            .is_empty());
    }

    #[test]
    fn several_definitions_come_back_in_source_order() {
        let text = "int a(void){return 1;}\nstatic void b(int x){ x++; }\nint c(void){return 2;}\n";
        let tree = clean(text);
        let names: Vec<String> = tree.functions(text).into_iter().map(|f| f.name).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn a_function_pointer_returning_declarator_still_names_the_function() {
        let text = "int (*resolve(int k))(void) { return 0; }\n";
        let tree = clean(text);
        let functions = tree.functions(text);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].name, "resolve");
    }

    #[test]
    fn identical_input_yields_a_byte_identical_tree() {
        // `REQ-SYN-5`: every gate in the programme is a diff.
        let text = "int f(int a){ if (a) return a * 2; else return a + 1; }\n";
        let one = parse(text).into_parts().0;
        let two = parse(text).into_parts().0;
        assert_eq!(tags(&one), tags(&two));
        assert_eq!(one.arena().len(), two.arena().len());
        assert_eq!(one.arena().extra(), two.arena().extra());
    }

    #[test]
    fn a_broken_function_does_not_void_the_file() {
        // `REQ-IN-4` / `REQ-ROB-2`: the failure is per-construct.
        let text =
            "int good1(void){return 1;}\nint bad(void){ ) ] ; }\nint good2(void){return 2;}\n";
        let tree = parse(text).into_parts().0;
        let names: Vec<String> = tree.functions(text).into_iter().map(|f| f.name).collect();
        assert_eq!(names, vec!["good1", "bad", "good2"]);
        assert!(tags(&tree).contains(&"error"), "the bad tokens keep a node");
    }

    #[test]
    fn garbage_between_functions_does_not_void_the_ones_after_it() {
        let text = "int a(void){return 1;}\n@@@ ??? \nint b(void){return 2;}\n";
        let tree = parse(text).into_parts().0;
        let names: Vec<String> = tree.functions(text).into_iter().map(|f| f.name).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn no_input_panics_and_every_input_terminates() {
        // `REQ-SYN-2`: no entry point may panic on any input.
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
            "/* unterminated",
            "\"unterminated",
            "int f(void){ return; } }",
            "a b c d e",
            "=====",
            "...",
            "case:",
            "if",
            "if(",
            "if()",
            "else {}",
            "for(;;)",
            "while",
            "do",
            "switch(x)",
            "goto",
            "return",
            "struct",
            "union {",
            "enum {,,,}",
            "typedef",
            "__attribute__",
            "__asm__",
            "sizeof",
            "sizeof(",
            "(int)",
            "x ? y",
            "x ?",
            "a[",
            "f(",
            "1 +",
            "int x = {",
            "#",
            "# 1 \"foo.c\"",
            "\u{80}\u{81}",
            "int \u{4e2d}(void){}",
        ] {
            let parsed = parse(text);
            // The product exists for every input; that is the whole contract.
            let _ = parsed.value().arena().len();
            let _ = parsed.value().functions(text);
        }
    }

    #[test]
    fn every_truncation_of_a_realistic_file_parses_without_a_panic() {
        let text = "#include <stdint.h>\nstatic int table[4] = {1,2,3,4};\n\
                    int walk(int *p, int n) {\n  int total = 0;\n\
                    for (int i = 0; i < n; ++i) { total += p[i] ? table[i & 3] : -1; }\n\
                    switch (total) { case 0: return 0; default: break; }\n  return total;\n}\n";
        for end in 0..text.len() {
            if !text.is_char_boundary(end) {
                continue;
            }
            let parsed = parse(&text[..end]);
            let _ = parsed.value().arena().len();
        }
    }

    #[test]
    fn deeply_nested_input_terminates_without_touching_the_native_stack() {
        // `REQ-GEN-4` / `REQ-SYN-3`. A recursive-descent parser aborts the
        // process here, and a process that aborts cannot report a per-function
        // failure. Three shapes, each thousands deep.
        const DEPTH: usize = 20_000;
        let parens = format!(
            "int f(void){{ return {}1{}; }}",
            "(".repeat(DEPTH),
            ")".repeat(DEPTH)
        );
        let braces = format!(
            "int f(void){{ {}{} }}",
            "{".repeat(DEPTH),
            "}".repeat(DEPTH)
        );
        let unary = format!("int f(void){{ return {}1; }}", "!".repeat(DEPTH));
        let chain = format!("int f(void){{ return 1{}; }}", " + 1".repeat(DEPTH));
        let casts = format!("int f(void){{ return {}1{}; }}", "(int)".repeat(DEPTH), "");
        for (name, text) in [
            ("parens", &parens),
            ("braces", &braces),
            ("unary", &unary),
            ("chain", &chain),
            ("casts", &casts),
        ] {
            let parsed = parse(text);
            println!(
                "{name}: {} nodes, {} errors, {} warnings",
                parsed.value().arena().len(),
                parsed.diagnostics().error_count(),
                parsed.diagnostics().warning_count()
            );
        }
        // The shallow shapes must still be *correct*, not merely survivable:
        // a few thousand levels is well inside the budget and must parse
        // clean, so the 20,000-deep run above is measuring the budget's edge
        // rather than hiding a failure that starts much earlier.
        const REAL: usize = 2_000;
        for text in [
            format!(
                "int f(void){{ return {}1{}; }}",
                "(".repeat(REAL),
                ")".repeat(REAL)
            ),
            format!("int f(void){{ {}{} }}", "{".repeat(REAL), "}".repeat(REAL)),
            format!("int f(void){{ return {}1; }}", "!".repeat(REAL)),
            format!("int f(void){{ return {}1{}; }}", "(int)".repeat(REAL), ""),
            format!("int f(void){{ int a{}; }}", "[1]".repeat(REAL)),
        ] {
            let parsed = parse(&text);
            assert_eq!(
                parsed.diagnostics().error_count(),
                0,
                "{} levels deep must parse clean",
                REAL
            );
        }
        assert_eq!(parse(&chain).diagnostics().error_count(), 0);
    }

    #[test]
    fn an_unbalanced_opener_repeated_does_not_hang() {
        let text = "(".repeat(50_000);
        let parsed = parse(&text);
        assert!(parsed.diagnostics().len() > 0);
    }

    // --- the coverage gate ---------------------------------------------------

    /// Every `.c` file directly under `dir`, sorted, or an empty list when the
    /// directory is absent --- which is how both gates below skip cleanly.
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

    /// Every `.c` file under a `decompiled/` directory anywhere in `root`.
    ///
    /// Walked with an explicit stack rather than recursion, matching the rule
    /// the parser itself holds to.
    fn every_decompiled_c(root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.filter_map(|entry| entry.ok()) {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|ext| ext == "c") {
                    found.push(path);
                }
            }
        }
        found.sort();
        found
    }

    /// What one corpus file cost: lines, functions, errors, warnings.
    struct Measured {
        lines: usize,
        functions: usize,
        errors: Vec<String>,
        warnings: Vec<String>,
    }

    /// Parse one file, reading it lossily the way `REQ-NORM-4` requires.
    fn measure(path: &Path) -> Measured {
        let raw = std::fs::read(path).expect("a readable corpus file");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let parsed = parse(&text);
        let errors = parsed
            .diagnostics()
            .iter()
            .filter(|d| d.severity == crate::syntax::diag::Severity::Error)
            .map(|d| d.render(&text))
            .collect();
        let warnings = parsed
            .diagnostics()
            .iter()
            .filter(|d| d.severity == crate::syntax::diag::Severity::Warning)
            .map(|d| d.render(&text))
            .collect();
        Measured {
            lines: text.lines().count(),
            functions: parsed.value().functions(&text).len(),
            errors,
            warnings,
        }
    }

    #[test]
    fn the_clean_in_repo_corpus_parses_with_zero_errors() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files: Vec<PathBuf> = Vec::new();
        for relative in ["tests/decompiler_fixtures/src", "tests/decbench_corpus/src"] {
            files.extend(c_files(&root.join(relative)));
        }
        if files.is_empty() {
            println!("SKIP: no in-repo C corpus under {}", root.display());
            return;
        }
        let (mut lines, mut functions, mut warnings) = (0usize, 0usize, 0usize);
        let (mut failures, mut empty) = (Vec::new(), Vec::new());
        let mut warned: Vec<String> = Vec::new();
        for path in &files {
            let measured = measure(path);
            lines += measured.lines;
            functions += measured.functions;
            warnings += measured.warnings.len();
            for warning in &measured.warnings {
                warned.push(format!("{}: {warning}", path.display()));
            }
            if measured.functions == 0 {
                empty.push(path.display().to_string());
            }
            if !measured.errors.is_empty() {
                failures.push(format!("{}: {:#?}", path.display(), measured.errors));
            }
        }
        println!("in-repo corpus: {} files", files.len());
        println!("  lines            = {lines}");
        println!("  functions        = {functions}");
        println!("  error diagnostics= {}", failures.len());
        println!("  warnings         = {warnings}");
        println!("  files with no fn = {}", empty.len());
        for warning in &warned {
            println!("  warning: {warning}");
        }
        assert!(
            failures.is_empty(),
            "C we own must parse clean; {} file(s) did not:\n{}",
            failures.len(),
            failures.join("\n")
        );
        assert!(
            empty.is_empty(),
            "these files yielded no function: {empty:#?}"
        );
    }

    #[test]
    fn real_decompiler_output_parses_without_a_panic_or_an_empty_file() {
        // Lives outside the repository, so absence is a skip rather than a
        // failure. Diagnostics here are expected and are the number to report;
        // a panic, a hang or a file with no functions is not.
        let Ok(home) = std::env::var("HOME") else {
            println!("SKIP: no HOME");
            return;
        };
        let root = PathBuf::from(home).join(".cache/glaurung/decbench-full/tree");
        // One project by default so the ordinary lane stays under a second;
        // the whole materialized tree on demand, because a defect that only
        // one of 1,606 files triggers is invisible to a 14-file slice.
        let files = if std::env::var("GLAURUNG_PARSE_FULL_CORPUS").is_ok() {
            every_decompiled_c(&root)
        } else {
            c_files(&root.join("O0/zlib/decompiled"))
        };
        if files.is_empty() {
            println!("SKIP: no decompiled corpus under {}", root.display());
            return;
        }
        let (mut lines, mut functions, mut errors, mut warnings) = (0usize, 0usize, 0usize, 0usize);
        let mut by_message: BTreeMap<String, usize> = BTreeMap::new();
        let mut empty = Vec::new();
        for path in &files {
            let measured = measure(path);
            lines += measured.lines;
            functions += measured.functions;
            errors += measured.errors.len();
            warnings += measured.warnings.len();
            if measured.functions == 0 {
                empty.push(path.display().to_string());
            }
            for message in measured.errors {
                let wording = message
                    .split_once("error: ")
                    .map_or(message.clone(), |(_, rest)| rest.to_string());
                let wording = wording.lines().next().unwrap_or("").to_string();
                *by_message.entry(wording).or_default() += 1;
            }
        }
        let per_kloc = errors as f64 * 1000.0 / lines.max(1) as f64;
        println!("decompiled corpus: {} files", files.len());
        println!("  lines             = {lines}");
        println!("  functions         = {functions}");
        println!("  error diagnostics = {errors}");
        println!("  errors per KLOC   = {per_kloc:.3}");
        println!("  warnings          = {warnings}");
        for (wording, count) in &by_message {
            println!("  {count:>6}  {wording}");
        }
        assert!(
            empty.is_empty(),
            "these files yielded no function: {empty:#?}"
        );
    }
}
