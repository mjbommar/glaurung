//! `F-5` --- the expression grammar: precedence climbing on an explicit stack.
//!
//! Spec: `docs/design/static-c-analysis/roadmap.md` stage S1 (`F-5`), and
//! `REQ-CFG-6`, which this module deliberately does **not** implement.
//!
//! # `&&`, `||` and `?:` are expressions here, and only here
//!
//! `REQ-CFG-6` says the short-circuit operators are control flow: `a && b`
//! costs three nodes and four edges in the graph. That is the CFG layer's job.
//! A parser that tried to express it would have to emit a control-flow shape
//! from inside an operand, and every consumer that wanted the *expression* ---
//! the lowering of stage S4, source extraction, a similarity feature --- would
//! have to reconstruct it. So [`NodeTag::BinaryExpr`] treats `&&` exactly like
//! `+`, and the graph builder reads the operator token to decide what to do
//! with it.
//!
//! # Why the precedence ladder is climbed with a bit mask
//!
//! The event stream has no `precede` (`substrate.md` section 2.2), so the
//! `Open` for a binary node must be emitted before its first operand --- before
//! the operator that says the node exists has been seen. The machine therefore
//! opens a *speculative* node per precedence level, and abandons the ones no
//! operator claimed; an abandoned `Open` becomes a tombstone the tree builder
//! skips, so the cost is an event, not a node.
//!
//! Opening all ten binary levels for every operand would pay that cost ten
//! times for `x`. [`Parser::scan_levels`] runs one bounded forward scan per
//! region and says which levels the region can contain, so the usual operand
//! opens one speculative node or none. The scan is allowed to over-approximate
//! and is not allowed to under-approximate; that asymmetry is its whole
//! contract.

use super::look::{
    is_assign_op, is_type_keyword, level_of, TypeNameLook, LEVEL_ASSIGN, LEVEL_COMMA, LEVEL_COND,
    LEVEL_MUL,
};
use super::tag::NodeTag;
use super::{Cont, Parser, Task};
use crate::csource::lex::TokenKind;
use crate::syntax::event::Marker;

/// The `last` sentinel for a loop task that has not run yet.
pub(super) const NO_POSITION: u32 = u32::MAX;

impl Parser<'_> {
    /// Queue one expression starting at `level`, scanning the region first.
    ///
    /// The entry point every other module uses. It rescans, so it is the right
    /// call at a genuine region boundary --- after `(`, `[`, `,` or `?` --- and
    /// the wrong one inside a level loop, which inherits its region's mask
    /// instead of paying for a scan per operand.
    pub(super) fn push_expr(&mut self, level: u8) {
        let mask = self.scan_levels(level);
        self.push(Task::ExprAt { level, mask });
    }

    /// Open one speculative node per reachable precedence level, then queue the
    /// operand that the innermost of them will be handed.
    ///
    /// Push order is the reverse of run order, so the levels are pushed
    /// outermost-first (which is also the order their `Open` events must be
    /// emitted in) and the operand is pushed last so it runs first.
    pub(super) fn expr_at(&mut self, level: u8, mask: u16) {
        let mut at = level;
        while at <= LEVEL_MUL {
            if mask & (1u16 << at) != 0 {
                let marker = self.open(NodeTag::Pending);
                self.push(Task::BinLoop {
                    level: at,
                    mask,
                    marker,
                    ops: 0,
                });
            }
            at += 1;
        }
        self.push(Task::Unary { mask });
    }

    /// One precedence level's operator loop, resumed after each operand.
    ///
    /// Three shapes share it. The conditional operator takes its own
    /// continuation because it has a `:` in the middle. Assignment is
    /// right-associative and flattens `a = b = c` into one node with two `=`
    /// tokens. Everything else is left-associative and flattens the same way.
    /// Flat is forced by the missing `precede`; nothing is lost, because the
    /// operator tokens are in the node and the associativity of a C level is a
    /// property of the level rather than of the text.
    pub(super) fn bin_loop(&mut self, level: u8, mask: u16, marker: Marker, ops: u32) {
        if level == LEVEL_COND {
            if self.at(TokenKind::Question) {
                self.patch(&marker, NodeTag::CondExpr);
                self.bump();
                self.push(Task::Cont {
                    what: Cont::Cond,
                    marker,
                    phase: 0,
                });
                self.push_expr(LEVEL_COMMA);
            } else {
                self.abandon(marker);
            }
            return;
        }

        let claimed = !self.at_eof()
            && if level == LEVEL_ASSIGN {
                is_assign_op(self.peek())
            } else {
                level_of(self.peek()) == Some(level)
            };
        if !claimed {
            if ops > 0 {
                self.close(marker);
            } else {
                self.abandon(marker);
            }
            return;
        }
        if ops == 0 {
            let tag = match level {
                LEVEL_COMMA => NodeTag::CommaExpr,
                LEVEL_ASSIGN => NodeTag::AssignExpr,
                _ => NodeTag::BinaryExpr,
            };
            self.patch(&marker, tag);
        }
        self.bump();
        // The right operand of an assignment is a conditional-expression, so
        // the level does not advance and the chain stays flat; every other
        // level hands the next operand to the level above it.
        let next = if level == LEVEL_ASSIGN {
            LEVEL_COND
        } else {
            level + 1
        };
        self.push(Task::BinLoop {
            level,
            mask,
            marker,
            ops: ops + 1,
        });
        self.push(Task::ExprAt { level: next, mask });
    }

    /// The `:` and else-arm of a `?:`, resumed after the then-arm.
    pub(super) fn cond_cont(&mut self, marker: Marker, _phase: u8) {
        self.expect(TokenKind::Colon, true);
        self.push(Task::Close(marker));
        // Right-associative: `a ? b : c ? d : e` nests in the else-arm, which
        // a fresh scan starting after the `:` gets right on its own.
        self.push_expr(LEVEL_COND);
    }

    /// Prefix operators, casts, `sizeof` and `_Alignof`, then a primary.
    ///
    /// The prefix run is a loop inside one task step rather than one task per
    /// operator, because each iteration consumes a token and pushes exactly one
    /// [`Task::Close`]; the nesting still lives on the heap.
    ///
    /// # `sizeof`, the classic ambiguity
    ///
    /// `sizeof(x)` is a type when `x` names one and an expression otherwise,
    /// and C's own grammar resolves it with the typedef table this parser does
    /// not have. The rule here: the parenthesised form is taken as a *type*
    /// whenever the parentheses contain something an expression could not be
    /// --- a type keyword, or an identifier followed by `*`, `[]` or a
    /// qualifier --- and also when they contain exactly one identifier, which
    /// is the unresolvable case. Everything else (`sizeof(a.b)`,
    /// `sizeof(a[0])`, `sizeof *p`, `sizeof x`) parses as an expression.
    ///
    /// Taking the tie as a type is safe *because of what the node keeps*: the
    /// tokens are in the node either way (`REQ-GEN-2`), a `sizeof` contributes
    /// no control flow under any reading (`REQ-CFG-3`), and a consumer that
    /// needs the distinction can re-decide it with information the parser does
    /// not have. The reverse choice would not be safe: parsing `sizeof(mytype
    /// *)` as an expression yields a dangling `*` and a spurious error.
    pub(super) fn unary(&mut self, mask: u16) {
        use TokenKind::*;
        loop {
            if self.at_eof() || !self.work.charge(1) {
                break;
            }
            match self.peek() {
                Amp | Star | Plus | Minus | Tilde | Bang | PlusPlus | MinusMinus | KwReal
                | KwImag => {
                    let marker = self.open(NodeTag::UnaryExpr);
                    self.bump();
                    self.push(Task::Close(marker));
                }
                // `__extension__` only silences a pedantic warning; it has no
                // grammar of its own and wraps whatever follows.
                KwExtension => self.bump(),
                // GNU `&&label`: the address of a label, for a computed goto.
                AmpAmp if self.nth(1) == Identifier => {
                    let marker = self.open(NodeTag::LabelAddr);
                    self.bump();
                    self.bump();
                    self.close(marker);
                    return;
                }
                KwSizeof => {
                    // Only the *conclusive* shapes take the type form; the
                    // ambiguous `(x)` and `(a[0])` fall through to the
                    // expression reading, which is the same tie-break the cast
                    // decision makes and for the same reason.
                    if self.nth(1) == LParen
                        && matches!(
                            self.type_name_in_parens(1),
                            TypeNameLook::Keyword | TypeNameLook::Pointerish
                        )
                    {
                        let marker = self.open(NodeTag::SizeofType);
                        self.bump();
                        let inner = self.open(NodeTag::TypeName);
                        self.eat_balanced();
                        self.close(inner);
                        self.close(marker);
                        return;
                    }
                    let marker = self.open(NodeTag::UnaryExpr);
                    self.bump();
                    self.push(Task::Close(marker));
                }
                KwAlignof => {
                    let marker = self.open(NodeTag::AlignofType);
                    self.bump();
                    if self.at(LParen) {
                        let inner = self.open(NodeTag::TypeName);
                        self.eat_balanced();
                        self.close(inner);
                    }
                    self.close(marker);
                    return;
                }
                LParen if self.is_cast_ahead() => {
                    if self.compound_literal_ahead() {
                        // `(T){ ... }` is a compound literal, not a cast of a
                        // block --- and it takes postfix suffixes, so its
                        // wrapper has to be opened before anything else.
                        let wrapper = self.open(NodeTag::Pending);
                        let marker = self.open(NodeTag::CompoundLiteral);
                        let inner = self.open(NodeTag::TypeName);
                        self.eat_balanced();
                        self.close(inner);
                        let list = self.open(NodeTag::InitList);
                        self.bump();
                        self.push(Task::Postfix {
                            marker: wrapper,
                            suffixes: 0,
                        });
                        self.push(Task::Close(marker));
                        self.push(Task::InitList {
                            marker: list,
                            last: NO_POSITION,
                        });
                        return;
                    }
                    let marker = self.open(NodeTag::CastExpr);
                    let inner = self.open(NodeTag::TypeName);
                    self.eat_balanced();
                    self.close(inner);
                    self.push(Task::Close(marker));
                }
                _ => break,
            }
        }
        self.primary_and_postfix(mask);
    }

    /// Open the postfix chain's wrapper, then queue the primary it applies to.
    ///
    /// The wrapper has to be opened first for the same reason a binary node
    /// does --- no `precede` --- and is abandoned when the chain turns out to
    /// be empty, which is the common case.
    fn primary_and_postfix(&mut self, mask: u16) {
        let marker = self.open(NodeTag::Pending);
        self.push(Task::Postfix {
            marker,
            suffixes: 0,
        });
        self.primary(mask);
    }

    /// One primary expression: a name, a literal, a parenthesised expression, a
    /// GNU statement expression, or a builtin whose arguments include a type.
    fn primary(&mut self, _mask: u16) {
        use TokenKind::*;
        if self.at_eof() {
            self.error("expected an expression, found end of input");
            return;
        }
        match self.peek() {
            Identifier => {
                let marker = self.open(NodeTag::NameRef);
                self.bump();
                self.close(marker);
            }
            IntLiteral | FloatLiteral | CharLiteral => {
                let marker = self.open(NodeTag::Literal);
                self.bump();
                self.close(marker);
            }
            StringLiteral => {
                // Adjacent string literals are one literal in C, and splitting
                // them would make a wide string two operands.
                let marker = self.open(NodeTag::Literal);
                while self.at(StringLiteral) {
                    self.bump();
                }
                self.close(marker);
            }
            // Each of these takes a *type* among its arguments, so its argument
            // list is not an expression list and is kept as a token run.
            KwGeneric
            | KwBuiltinVaArg
            | KwBuiltinOffsetof
            | KwBuiltinTypesCompatibleP
            | KwBuiltinChooseExpr => {
                let marker = self.open(NodeTag::BuiltinExpr);
                self.bump();
                if self.at(LParen) {
                    self.eat_balanced();
                }
                self.close(marker);
            }
            LParen if self.nth(1) == LBrace => {
                // GNU statement expression `({ ... })`: the one place a
                // statement is nested inside an expression.
                let marker = self.open(NodeTag::StmtExpr);
                self.bump();
                let body = self.open(NodeTag::CompoundStmt);
                self.bump();
                self.push(Task::EatClose {
                    kind: RParen,
                    hard: true,
                    marker,
                });
                self.push(Task::Block {
                    marker: body,
                    last: NO_POSITION,
                });
            }
            LParen => {
                let marker = self.open(NodeTag::ParenExpr);
                self.bump();
                self.push(Task::EatClose {
                    kind: RParen,
                    hard: true,
                    marker,
                });
                self.push_expr(LEVEL_COMMA);
            }
            other => {
                // `REQ-IN-4` and `REQ-CFG-11`: the construct is not modelled,
                // it keeps a node, and the enclosing function keeps parsing.
                let marker = self.open(NodeTag::Error);
                let message = format!("expected an expression, found `{}`", other.name());
                self.error(message);
                // A closer or a separator belongs to whoever is waiting for it;
                // consuming it here would desynchronise that caller instead.
                if !matches!(other, Semi | RParen | RBrace | RBracket | Comma | Colon) {
                    self.bump();
                }
                self.close(marker);
            }
        }
    }

    /// One link of a postfix chain, resumed after each suffix.
    pub(super) fn postfix(&mut self, marker: Marker, suffixes: u32) {
        use TokenKind::*;
        if self.at_eof() {
            self.finish_postfix(marker, suffixes);
            return;
        }
        match self.peek() {
            LParen => {
                let suffix = self.open(NodeTag::CallArgs);
                self.bump();
                self.push(Task::Postfix {
                    marker,
                    suffixes: suffixes + 1,
                });
                self.push(Task::EatClose {
                    kind: RParen,
                    hard: true,
                    marker: suffix,
                });
                if !self.at(RParen) {
                    self.push(Task::ArgsMore);
                    self.push_call_argument();
                }
            }
            LBracket => {
                let suffix = self.open(NodeTag::IndexSuffix);
                self.bump();
                self.push(Task::Postfix {
                    marker,
                    suffixes: suffixes + 1,
                });
                self.push(Task::EatClose {
                    kind: RBracket,
                    hard: true,
                    marker: suffix,
                });
                self.push_expr(LEVEL_COMMA);
            }
            Dot | Arrow => {
                let suffix = self.open(NodeTag::MemberSuffix);
                self.bump();
                if self.at(Identifier) {
                    self.bump();
                } else {
                    self.error("expected a member name after `.` or `->`");
                }
                self.close(suffix);
                self.push(Task::Postfix {
                    marker,
                    suffixes: suffixes + 1,
                });
            }
            PlusPlus | MinusMinus => {
                let suffix = self.open(NodeTag::IncDecSuffix);
                self.bump();
                self.close(suffix);
                self.push(Task::Postfix {
                    marker,
                    suffixes: suffixes + 1,
                });
            }
            _ => self.finish_postfix(marker, suffixes),
        }
    }

    /// Keep the postfix wrapper if the chain had links, drop it otherwise.
    fn finish_postfix(&mut self, marker: Marker, suffixes: u32) {
        if suffixes > 0 {
            self.patch(&marker, NodeTag::PostfixExpr);
            self.close(marker);
        } else {
            self.abandon(marker);
        }
    }

    /// The `,` between two call arguments, if there is one.
    pub(super) fn args_more(&mut self) {
        if self.at(TokenKind::Comma) {
            self.bump();
            self.push(Task::ArgsMore);
            self.push_call_argument();
        }
    }

    /// Queue one call argument, which is usually an assignment-expression and
    /// occasionally a type.
    ///
    /// `offsetof(struct Padded, payload)` and `container_of(p, struct s, m)`
    /// are macro invocations, and this parser does not preprocess (`REQ-IN-2`
    /// assumes someone else did). An argument beginning with a type keyword is
    /// therefore kept as a [`NodeTag::TypeName`] token run rather than parsed
    /// as an expression, which it cannot be: no C expression starts with
    /// `struct`, `unsigned` or `int`. The tolerance is free --- it can never
    /// fire on an expression --- and without it every unpreprocessed
    /// `offsetof` costs three diagnostics.
    fn push_call_argument(&mut self) {
        use TokenKind::*;
        if self.at_eof() || !is_type_keyword(self.peek()) {
            self.push_expr(LEVEL_ASSIGN);
            return;
        }
        let marker = self.open(NodeTag::TypeName);
        let mut depth = 0u32;
        while !self.at_eof() && self.work.charge(1) {
            match self.peek() {
                LParen | LBracket | LBrace => depth += 1,
                RParen | RBracket | RBrace => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                Comma if depth == 0 => break,
                _ => {}
            }
            self.bump();
        }
        self.close(marker);
    }
}

#[cfg(test)]
mod tests {
    use super::super::parse;
    use super::super::tag::NodeTag;
    use crate::syntax::diag::Severity;
    use crate::syntax::ids::NodeId;

    /// Every error diagnostic `text` produces.
    fn errors(text: &str) -> Vec<String> {
        parse(text)
            .diagnostics()
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.render(text))
            .collect()
    }

    /// A parenthesised dump of the tree, so a shape assertion is one string.
    fn shape(text: &str) -> String {
        let tree = parse(text).into_parts().0;
        let arena = tree.arena();
        let mut out = String::new();
        let mut stack: Vec<(NodeId, bool)> = arena
            .roots()
            .iter()
            .rev()
            .map(|node| (*node, false))
            .collect();
        while let Some((node, closing)) = stack.pop() {
            if closing {
                out.push(')');
                continue;
            }
            let name = arena
                .tag(node)
                .and_then(NodeTag::from_u16)
                .map_or("?", NodeTag::name);
            out.push_str(&format!("({name}"));
            stack.push((node, true));
            for child in arena
                .children_iter(node)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
            {
                stack.push((child, false));
            }
        }
        out
    }

    /// The expression of `int f(void){ <text>; }`, dumped.
    fn expr_shape(text: &str) -> String {
        shape(&format!("int f(void){{ {text}; }}"))
    }

    #[test]
    fn precedence_nests_the_levels_in_the_right_order() {
        // `a + b * c` must put the multiplication inside the addition.
        let dump = expr_shape("a + b * c");
        let add = dump.find("binary_expr").expect("an additive node");
        let mul = dump.rfind("binary_expr").expect("a multiplicative node");
        assert!(add < mul, "{dump}");
        // and `a * b + c` the other way round: one node per level, not one
        // flat node for both.
        assert_eq!(
            expr_shape("a * b + c").matches("binary_expr").count(),
            2,
            "{}",
            expr_shape("a * b + c")
        );
    }

    #[test]
    fn a_same_level_chain_is_one_flat_node() {
        // The documented consequence of the substrate having no `precede`.
        assert_eq!(
            expr_shape("a + b + c + d").matches("binary_expr").count(),
            1
        );
        assert_eq!(expr_shape("a && b && c").matches("binary_expr").count(), 1);
    }

    #[test]
    fn assignment_and_the_conditional_operator_are_right_associative() {
        assert_eq!(expr_shape("a = b = c").matches("assign_expr").count(), 1);
        // `a ? b : c ? d : e` nests in the else-arm.
        let dump = expr_shape("a ? b : c ? d : e");
        assert_eq!(dump.matches("cond_expr").count(), 2, "{dump}");
    }

    #[test]
    fn short_circuit_operators_are_ordinary_expressions_here() {
        // `REQ-CFG-6` is the graph layer's job; the parser must not pre-empt it.
        let dump = expr_shape("a && b || c");
        assert!(dump.contains("binary_expr"), "{dump}");
        assert!(!dump.contains("if_stmt"), "{dump}");
    }

    #[test]
    fn a_postfix_chain_is_flat_and_in_source_order() {
        let dump = expr_shape("f(a)[b].c->d++");
        assert_eq!(dump.matches("postfix_expr").count(), 1, "{dump}");
        let order: Vec<&str> = [
            "call_args",
            "index_suffix",
            "member_suffix",
            "inc_dec_suffix",
        ]
        .into_iter()
        .collect();
        let mut at = 0usize;
        for name in order {
            let found = dump[at..]
                .find(name)
                .unwrap_or_else(|| panic!("{name} missing from {dump}"));
            at += found + name.len();
        }
    }

    #[test]
    fn a_bare_operand_costs_no_node_beyond_itself() {
        // The reason `scan_levels` exists: `x` must not open ten speculative
        // nodes and abandon nine of them.
        assert_eq!(expr_shape("x").matches("binary_expr").count(), 0);
        assert_eq!(expr_shape("x").matches("postfix_expr").count(), 0);
        assert_eq!(expr_shape("x").matches("pending").count(), 0);
    }

    #[test]
    fn sizeof_takes_both_of_its_forms() {
        assert!(expr_shape("sizeof(int)").contains("sizeof_type"));
        assert!(expr_shape("sizeof(struct s)").contains("sizeof_type"));
        assert!(expr_shape("sizeof(mytype_t *)").contains("sizeof_type"));
        assert!(expr_shape("sizeof(char[4])").contains("sizeof_type"));
        // ...and every ambiguous or conclusive-expression form stays an
        // expression, so `sizeof(arr) / sizeof(arr[0])` keeps its subscript.
        assert!(expr_shape("sizeof x").contains("unary_expr"));
        assert!(expr_shape("sizeof *p").contains("unary_expr"));
        assert!(expr_shape("sizeof(a[0])").contains("index_suffix"));
        assert!(expr_shape("sizeof(a.b)").contains("member_suffix"));
        assert!(expr_shape("sizeof(x)").contains("paren_expr"));
        for text in [
            "sizeof(int)",
            "sizeof x",
            "sizeof *p",
            "sizeof(a[0])",
            "sizeof(int) / sizeof(int)",
            "sizeof(char[4])",
            "sizeof(a) / sizeof(a[0])",
            "sizeof(mytype_t)",
            "sizeof(struct s *)",
        ] {
            let full = format!("int f(void){{ {text}; }}");
            assert!(errors(&full).is_empty(), "{text}: {:?}", errors(&full));
        }
    }

    #[test]
    fn a_compound_literal_is_not_a_cast_of_a_block() {
        let dump = expr_shape("(struct point){ .x = 1, .y = 2 }");
        assert!(dump.contains("compound_literal"), "{dump}");
        assert!(dump.contains("init_list"), "{dump}");
    }

    #[test]
    fn a_statement_expression_nests_a_block_inside_an_expression() {
        let dump = expr_shape("({ int t = a; t * t; })");
        assert!(dump.contains("stmt_expr"), "{dump}");
        assert!(dump.contains("compound_stmt"), "{dump}");
        assert!(errors("int f(void){ int y = ({ int t = 1; t; }); }").is_empty());
    }

    #[test]
    fn the_gnu_expression_surface_parses() {
        for text in [
            "int f(void){ return __builtin_expect(!!(x), 1); }",
            "int f(va_list ap){ return __builtin_va_arg(ap, int); }",
            "int f(void){ return __builtin_offsetof(struct s, m); }",
            "int f(void){ return _Generic(x, int: 1, default: 0); }",
            "int f(void){ return __extension__ (1); }",
            "int f(void){ return __real__ z + __imag__ z; }",
            "void f(void){ static void *t[] = { &&a, &&b }; a: b: goto *t[0]; }",
        ] {
            assert!(errors(text).is_empty(), "{text}: {:?}", errors(text));
        }
    }

    #[test]
    fn a_comma_expression_is_kept_out_of_an_argument_list() {
        // `f(a, b)` is two arguments; `f((a, b))` is one comma expression.
        assert_eq!(expr_shape("f(a, b)").matches("comma_expr").count(), 0);
        assert_eq!(expr_shape("f((a, b))").matches("comma_expr").count(), 1);
        assert_eq!(expr_shape("x[a, b]").matches("comma_expr").count(), 1);
    }

    #[test]
    fn an_unparseable_operand_keeps_a_node_and_the_statement_continues() {
        let text = "int f(void){ int a = ) ; int b = 2; }";
        let dump = shape(text);
        assert!(dump.contains("error"), "{dump}");
        assert!(dump.matches("decl").count() >= 2, "{dump}");
    }
}
