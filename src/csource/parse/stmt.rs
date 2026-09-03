//! `F-6` --- the statement grammar, as continuations on the task stack.
//!
//! Spec: `docs/design/static-c-analysis/roadmap.md` stage S1 (`F-6`), and
//! `REQ-IN-4` / `REQ-ROB-2` (a bad statement costs a statement).
//!
//! # Why every compound construct is a continuation
//!
//! `if (c) s1 else s2` has three suspension points --- after the condition,
//! after the then-arm, after the else-arm --- and a recursive parser would keep
//! them in its own frames. Here they are [`Cont`] phases: the construct's node
//! marker and a phase number travel on the task stack, so nesting an `if`
//! inside an `if` inside a `for` costs heap and nothing else (`REQ-SYN-3`).
//!
//! # Labels are siblings, not parents
//!
//! C's grammar makes `case 1: return x;` a *labelled statement* containing the
//! `return`. This parser emits [`NodeTag::CaseLabel`] and the `return` as
//! siblings. The reason is the consumer: `REQ-CFG-4` makes each `case` label
//! group a jump target and `REQ-CFG-7` makes a label a node in its own right,
//! so a nesting the graph builder would immediately flatten is a nesting worth
//! not building. The cost is one construct --- `switch (x) case 1: f();`, a
//! labelled statement as the whole body of a switch --- where the `f();` ends
//! up outside the switch node. It does not occur in either corpus and it does
//! not change the statement's control flow, only which node owns it.

use super::expr::NO_POSITION;
use super::look::LEVEL_COMMA;
use super::look::LEVEL_COND;
use super::tag::NodeTag;
use super::{Cont, Parser, Task};
use crate::csource::lex::TokenKind;
use crate::syntax::event::Marker;

impl Parser<'_> {
    /// Parse one statement.
    ///
    /// The dispatch is on one token everywhere except two places: a label needs
    /// two (`ident :`), and the declaration-versus-expression decision needs
    /// [`Parser::starts_declaration`], whose rule and its justification are in
    /// [`super::look`].
    pub(super) fn statement(&mut self) {
        use TokenKind::*;
        if self.at_eof() {
            return;
        }
        match self.peek() {
            // `REQ-IN-2`: the input is meant to be preprocessed already, but
            // the in-repo corpus is raw `.c`. A directive line is skipped
            // whole rather than parsed as C.
            Hash => self.preprocessor_line(),
            LBrace => {
                let marker = self.open(NodeTag::CompoundStmt);
                self.bump();
                self.push(Task::Block {
                    marker,
                    last: NO_POSITION,
                });
            }
            Semi => {
                let marker = self.open(NodeTag::NullStmt);
                self.bump();
                self.close(marker);
            }
            KwIf => {
                let marker = self.open(NodeTag::IfStmt);
                self.bump();
                self.expect(LParen, true);
                self.push(Task::Cont {
                    what: Cont::If,
                    marker,
                    phase: 0,
                });
                self.push_expr(LEVEL_COMMA);
            }
            KwWhile => {
                let marker = self.open(NodeTag::WhileStmt);
                self.bump();
                self.expect(LParen, true);
                self.push(Task::Cont {
                    what: Cont::While,
                    marker,
                    phase: 0,
                });
                self.push_expr(LEVEL_COMMA);
            }
            KwDo => {
                let marker = self.open(NodeTag::DoWhileStmt);
                self.bump();
                self.push(Task::Cont {
                    what: Cont::Do,
                    marker,
                    phase: 0,
                });
                self.push(Task::Stmt);
            }
            KwFor => self.for_stmt(),
            KwSwitch => {
                let marker = self.open(NodeTag::SwitchStmt);
                self.bump();
                self.expect(LParen, true);
                self.push(Task::Cont {
                    what: Cont::Switch,
                    marker,
                    phase: 0,
                });
                self.push_expr(LEVEL_COMMA);
            }
            KwCase => {
                let marker = self.open(NodeTag::CaseLabel);
                self.bump();
                self.push(Task::Cont {
                    what: Cont::Case,
                    marker,
                    phase: 0,
                });
                // A case label's expression is a constant-expression, which is
                // a conditional-expression: no comma, or `case 1, 2:` would
                // swallow a second label.
                self.push_expr(LEVEL_COND);
            }
            KwDefault => {
                let marker = self.open(NodeTag::DefaultLabel);
                self.bump();
                self.expect(Colon, true);
                self.close(marker);
            }
            KwBreak | KwContinue => {
                let tag = if self.peek() == KwBreak {
                    NodeTag::BreakStmt
                } else {
                    NodeTag::ContinueStmt
                };
                let marker = self.open(tag);
                self.bump();
                self.expect(Semi, false);
                self.close(marker);
            }
            KwGoto => self.goto_stmt(),
            KwReturn => {
                let marker = self.open(NodeTag::ReturnStmt);
                self.bump();
                if self.at(Semi) {
                    self.bump();
                    self.close(marker);
                } else {
                    self.push(Task::EatClose {
                        kind: Semi,
                        hard: false,
                        marker,
                    });
                    self.push_expr(LEVEL_COMMA);
                }
            }
            // GNU `__label__ a, b;`: local label declarations, which name goto
            // targets and declare nothing else.
            KwLabel => {
                let marker = self.open(NodeTag::LocalLabel);
                self.bump();
                while !self.at_eof() && !self.at(Semi) && self.work.charge(1) {
                    self.bump();
                }
                self.eat(Semi);
                self.close(marker);
            }
            KwAsm => self.asm_construct(),
            KwStaticAssert => self.static_assert(),
            KwExtension if self.nth(1) != Identifier || self.starts_declaration() => {
                self.bump();
                self.push(Task::Stmt);
            }
            Identifier if self.nth(1) == Colon => {
                let marker = self.open(NodeTag::LabelStmt);
                self.bump();
                self.bump();
                self.close(marker);
            }
            _ => {
                if self.starts_declaration() {
                    self.declaration();
                } else {
                    let marker = self.open(NodeTag::ExprStmt);
                    // A missing `;` here is a lossless recovery, not a
                    // modelling failure: see the module docs on the unpreprocessed
                    // X-macro call statements in the in-repo corpus.
                    self.push(Task::EatClose {
                        kind: Semi,
                        hard: false,
                        marker,
                    });
                    self.push_expr(LEVEL_COMMA);
                }
            }
        }
    }

    /// Parse the next item of a compound statement, or close it at `}`.
    ///
    /// `last` is the cursor position this task last resumed at. Equality means
    /// the previous item consumed nothing, which is the recovery loop that
    /// spins forever; the answer is one forced token into an
    /// [`NodeTag::Error`] node, so the next round starts from new ground
    /// (`REQ-CFG-11`: the skipped text still has a node).
    pub(super) fn block_item(&mut self, marker: Marker, last: u32) {
        if self.at(TokenKind::RBrace) {
            self.bump();
            self.close(marker);
            return;
        }
        if self.at_eof() {
            self.error("unterminated block: expected `}`");
            self.close(marker);
            return;
        }
        if self.cursor.pos() == last {
            let skipped = self.open(NodeTag::Error);
            let message = format!(
                "no statement can start with `{}`; skipping it",
                self.peek().name()
            );
            self.error(message);
            self.bump();
            self.close(skipped);
        }
        let now = self.cursor.pos();
        self.push(Task::Block { marker, last: now });
        self.push(Task::Stmt);
    }

    /// Resume a multi-phase construct.
    pub(super) fn cont(&mut self, what: Cont, marker: Marker, phase: u8) {
        use TokenKind::*;
        match what {
            Cont::Cond => self.cond_cont(marker, phase),
            Cont::If => {
                if phase == 0 {
                    self.expect(RParen, true);
                    self.push(Task::Cont {
                        what: Cont::If,
                        marker,
                        phase: 1,
                    });
                    self.push(Task::Stmt);
                } else if self.at(KwElse) {
                    self.bump();
                    self.push(Task::Close(marker));
                    self.push(Task::Stmt);
                } else {
                    self.close(marker);
                }
            }
            Cont::While | Cont::Switch => {
                self.expect(RParen, true);
                self.push(Task::Close(marker));
                self.push(Task::Stmt);
            }
            Cont::Do => {
                if phase == 0 {
                    self.expect(KwWhile, true);
                    self.expect(LParen, true);
                    self.push(Task::Cont {
                        what: Cont::Do,
                        marker,
                        phase: 1,
                    });
                    self.push_expr(LEVEL_COMMA);
                } else {
                    self.expect(RParen, true);
                    self.expect(Semi, false);
                    self.close(marker);
                }
            }
            Cont::Case => {
                // GNU case ranges: `case 1 ... 5:` is one label with two bounds.
                if self.eat(Ellipsis) {
                    self.push(Task::Cont {
                        what: Cont::Case,
                        marker,
                        phase,
                    });
                    self.push_expr(LEVEL_COND);
                } else {
                    self.expect(Colon, true);
                    self.close(marker);
                }
            }
            Cont::For => self.for_cont(marker, phase),
        }
    }

    /// `for (init; cond; step) body`, both the C89 and the C99 forms.
    ///
    /// The C99 form declares in the init clause, which is why the init is
    /// dispatched through [`Parser::starts_declaration`] rather than assumed to
    /// be an expression --- and why the declaration path is allowed to consume
    /// the first `;` itself, since a declaration owns its terminator.
    fn for_stmt(&mut self) {
        use TokenKind::*;
        let marker = self.open(NodeTag::ForStmt);
        self.bump();
        self.expect(LParen, true);
        let init = self.open(NodeTag::ForInit);
        if self.eat(Semi) {
            self.close(init);
            self.push(Task::Cont {
                what: Cont::For,
                marker,
                phase: 1,
            });
            return;
        }
        self.push(Task::Cont {
            what: Cont::For,
            marker,
            phase: 1,
        });
        if self.starts_declaration() {
            self.push(Task::Close(init));
            self.declaration();
        } else {
            self.push(Task::Eat {
                kind: Semi,
                hard: false,
            });
            self.push(Task::Close(init));
            self.push_expr(LEVEL_COMMA);
        }
    }

    /// The condition, step and body clauses of a `for`, in that order.
    fn for_cont(&mut self, marker: Marker, phase: u8) {
        use TokenKind::*;
        match phase {
            1 => {
                let cond = self.open(NodeTag::ForCond);
                if self.eat(Semi) {
                    self.close(cond);
                    self.push(Task::Cont {
                        what: Cont::For,
                        marker,
                        phase: 2,
                    });
                    return;
                }
                self.push(Task::Cont {
                    what: Cont::For,
                    marker,
                    phase: 2,
                });
                self.push(Task::Eat {
                    kind: Semi,
                    hard: false,
                });
                self.push(Task::Close(cond));
                self.push_expr(LEVEL_COMMA);
            }
            2 => {
                let step = self.open(NodeTag::ForStep);
                if self.eat(RParen) {
                    self.close(step);
                    self.push(Task::Close(marker));
                    self.push(Task::Stmt);
                    return;
                }
                self.push(Task::Cont {
                    what: Cont::For,
                    marker,
                    phase: 3,
                });
                self.push(Task::Close(step));
                self.push_expr(LEVEL_COMMA);
            }
            _ => {
                self.expect(RParen, true);
                self.push(Task::Close(marker));
                self.push(Task::Stmt);
            }
        }
    }

    /// `goto label;` and the GNU computed form `goto *expr;`.
    ///
    /// The two are kept in one node kind on purpose: `REQ-CFG-7` needs a
    /// computed `goto` to be visibly a `goto` with an unknown target set, and
    /// the difference between the forms is whether the node has an expression
    /// child, which a consumer can see.
    fn goto_stmt(&mut self) {
        use TokenKind::*;
        let marker = self.open(NodeTag::GotoStmt);
        self.bump();
        if self.at(Identifier) {
            self.bump();
            self.expect(Semi, false);
            self.close(marker);
        } else if self.at(Star) {
            self.push(Task::EatClose {
                kind: Semi,
                hard: false,
                marker,
            });
            self.push_expr(LEVEL_COMMA);
        } else {
            self.error("expected a label or `*` after `goto`");
            self.expect(Semi, false);
            self.close(marker);
        }
    }

    /// `asm`, `__asm__` and their qualifiers, in both the basic and the
    /// extended forms.
    ///
    /// The operand list is kept as a token run: its constraint strings and
    /// clobber lists are not C expressions, and nothing downstream reads them.
    /// What matters is that the construct is one straight-line item, which is
    /// what the node makes it.
    pub(super) fn asm_construct(&mut self) {
        use TokenKind::*;
        let marker = self.open(NodeTag::Asm);
        self.bump();
        while matches!(self.peek(), KwVolatile | KwInline | KwGoto) && !self.at_eof() {
            self.bump();
        }
        if self.at(LParen) {
            self.eat_balanced();
        }
        self.eat(Semi);
        self.close(marker);
    }

    /// `_Static_assert(expr, "message");` --- a declaration with no declarator
    /// and no control flow, kept as one node.
    pub(super) fn static_assert(&mut self) {
        let marker = self.open(NodeTag::StaticAssert);
        self.bump();
        if self.at(TokenKind::LParen) {
            self.eat_balanced();
        }
        self.eat(TokenKind::Semi);
        self.close(marker);
    }

    /// Skip one preprocessor directive line.
    ///
    /// `REQ-IN-2` says the input is already preprocessed, so a `#` line is
    /// either a gcc line marker or is skipped. The in-repo gate corpus is raw
    /// `.c` rather than `.i`, so this is what keeps `#include` and `#define`
    /// out of the grammar --- and a `\`-continued `#define` body is one logical
    /// line, which is why [`Parser::line_break_between`] exists.
    pub(super) fn preprocessor_line(&mut self) {
        let marker = self.open(NodeTag::PpDirective);
        let mut previous = self.cursor.tokens().start(self.cursor.current());
        self.bump();
        while !self.at_eof() && self.work.charge(1) {
            let next = self.cursor.tokens().start(self.cursor.current());
            if self.line_break_between(previous, next) {
                break;
            }
            previous = next;
            self.bump();
        }
        self.close(marker);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{parse, tag::NodeTag};
    use crate::syntax::diag::Severity;

    /// Every error diagnostic `text` produces.
    fn errors(text: &str) -> Vec<String> {
        parse(text)
            .diagnostics()
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .map(|d| d.render(text))
            .collect()
    }

    /// The node tag names of `int f(void){ <body> }`, in construction order.
    fn body_tags(body: &str) -> Vec<&'static str> {
        let text = format!("int f(void){{ {body} }}");
        let tree = parse(&text).into_parts().0;
        let names: Vec<&'static str> = tree
            .arena()
            .preorder_roots()
            .filter_map(|node| tree.arena().tag(node))
            .filter_map(NodeTag::from_u16)
            .map(NodeTag::name)
            .collect();
        let bad = errors(&text);
        assert!(bad.is_empty(), "{body}: {bad:?}");
        names
    }

    #[test]
    fn every_statement_form_gets_its_own_node() {
        assert!(body_tags("{ }").contains(&"compound_stmt"));
        assert!(body_tags(";").contains(&"null_stmt"));
        assert!(body_tags("if (a) b();").contains(&"if_stmt"));
        assert!(body_tags("if (a) b(); else c();").contains(&"if_stmt"));
        assert!(body_tags("while (a) b();").contains(&"while_stmt"));
        assert!(body_tags("do b(); while (a);").contains(&"do_while_stmt"));
        assert!(body_tags("for (;;) b();").contains(&"for_stmt"));
        assert!(body_tags("switch (a) { case 1: break; default: break; }").contains(&"switch_stmt"));
        assert!(body_tags("switch (a) { case 1: break; }").contains(&"case_label"));
        assert!(body_tags("switch (a) { default: break; }").contains(&"default_label"));
        assert!(body_tags("while (1) continue;").contains(&"continue_stmt"));
        assert!(body_tags("l: goto l;").contains(&"label_stmt"));
        assert!(body_tags("l: goto l;").contains(&"goto_stmt"));
        assert!(body_tags("return 1;").contains(&"return_stmt"));
        assert!(body_tags("a();").contains(&"expr_stmt"));
    }

    #[test]
    fn an_else_binds_to_the_nearest_if() {
        // Two `if`s and one `else`: the else-arm must sit inside the inner one.
        let text = "int f(int a){ if (a) if (a) g(); else h(); }";
        assert!(errors(text).is_empty(), "{:?}", errors(text));
        let tree = parse(text).into_parts().0;
        let arena = tree.arena();
        let ifs: Vec<_> = arena
            .preorder_roots()
            .filter(|n| arena.tag(*n) == Some(NodeTag::IfStmt.as_u16()))
            .collect();
        assert_eq!(ifs.len(), 2);
        // The outer `if` has two children (condition, then-arm); the inner has
        // three (condition, then-arm, else-arm).
        assert_eq!(
            arena.child_count(ifs[0]),
            2,
            "the else attached to the outer if"
        );
        assert_eq!(arena.child_count(ifs[1]), 3);
    }

    #[test]
    fn a_for_loop_takes_both_its_c89_and_c99_forms() {
        let c89 = body_tags("int i; for (i = 0; i < 4; ++i) g(i);");
        assert!(c89.contains(&"for_init"), "{c89:?}");
        assert!(c89.contains(&"for_cond"));
        assert!(c89.contains(&"for_step"));
        let c99 = body_tags("for (int i = 0; i < 4; ++i) g(i);");
        assert!(c99.contains(&"decl"), "{c99:?}");
        assert!(c99.contains(&"for_cond"));
        // Every clause is optional, and the empty ones still get their node.
        assert!(body_tags("for (;;) break;").contains(&"for_stmt"));
        assert!(body_tags("for (int i = 0;;) break;").contains(&"for_stmt"));
        assert!(body_tags("for (; a;) break;").contains(&"for_stmt"));
        assert!(body_tags("for (;; ++a) break;").contains(&"for_stmt"));
    }

    #[test]
    fn a_case_range_and_a_fallthrough_group_parse() {
        assert!(body_tags("switch (a) { case 1 ... 4: case 5: break; }").contains(&"case_label"));
        let tags = body_tags("switch (a) { case 1: case 2: return 1; default: return 0; }");
        assert_eq!(tags.iter().filter(|t| **t == "case_label").count(), 2);
    }

    #[test]
    fn a_statement_expression_and_a_computed_goto_parse() {
        assert!(body_tags("int t = ({ int u = 1; u + 1; });").contains(&"stmt_expr"));
        assert!(body_tags("__label__ here; here: ;").contains(&"local_label"));
        let text = "void f(void){ static void *t[] = {&&a, &&b}; goto *t[0]; a: ; b: ; }";
        assert!(errors(text).is_empty(), "{:?}", errors(text));
    }

    #[test]
    fn a_preprocessor_directive_is_skipped_rather_than_parsed() {
        let text = "#include <stdint.h>\n#define N 8\nint f(void){\n#ifdef X\n  return N;\n#endif\n  return 0;\n}\n";
        assert!(errors(text).is_empty(), "{:?}", errors(text));
        let tree = parse(text).into_parts().0;
        assert_eq!(tree.functions(text).len(), 1);
    }

    #[test]
    fn a_missing_semicolon_is_a_warning_and_not_an_error() {
        // The unpreprocessed X-macro shape the in-repo corpus contains.
        let text = "int f(int a){ switch (a) { AS_CASE(NOP, 0, 1)\n return 1; } return 0; }";
        assert!(errors(text).is_empty(), "{:?}", errors(text));
        assert!(parse(text).diagnostics().warning_count() > 0);
    }

    #[test]
    fn a_bad_statement_costs_one_statement_and_not_the_block() {
        let text = "int f(void){ int a = 1; ) ; int b = 2; return a + b; }";
        let tree = parse(text).into_parts().0;
        let names: Vec<&'static str> = tree
            .arena()
            .preorder_roots()
            .filter_map(|n| tree.arena().tag(n))
            .filter_map(NodeTag::from_u16)
            .map(NodeTag::name)
            .collect();
        assert!(names.contains(&"error"), "{names:?}");
        assert!(names.contains(&"return_stmt"), "{names:?}");
        assert_eq!(tree.functions(text).len(), 1);
    }

    #[test]
    fn an_unterminated_block_still_yields_the_function_it_started() {
        let text = "int f(void){ int a = 1;";
        let tree = parse(text).into_parts().0;
        assert_eq!(tree.functions(text).len(), 1);
    }
}
