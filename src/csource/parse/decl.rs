//! `F-7` --- declarations: parsed far enough to be skipped correctly, and to
//! keep what contributes control flow.
//!
//! Spec: `docs/design/static-c-analysis/requirements.md` `REQ-GEN-5` (the AST
//! is lowerable), `REQ-CFG-3` (a declaration with an initializer is a node, one
//! without is not) and section 9 open question 1.
//!
//! # What is kept, and what is a token run
//!
//! Kept as structure: the specifier run, each declarator with the identifier it
//! declares, and each initializer --- because an initializer can contain a
//! call, a `?:` or a compound literal, and is therefore the part of a
//! declaration that has control flow. Everything else is a *token run* inside
//! one opaque node: a parameter list, a `struct` body, an `__attribute__`, an
//! `asm` operand list. The tokens are still addressable (`REQ-GEN-2`), so
//! nothing is destroyed; what is skipped is a grammar for text with no reader.
//!
//! A `struct` body being opaque is the one that looks lossy and is not. Its
//! members declare types, and section 8 says there is no type resolution here;
//! a member declaration contributes no statement, no edge and no node.
//!
//! # The declaration-versus-expression ambiguity, and why it is cheap here
//!
//! `A * b;` needs a typedef table to disambiguate in general. This parser does
//! not build one, and the requirements say why: both readings are one
//! straight-line item with the same degree contribution. The syntactic rule
//! lives in [`super::look`] with its falsification. This module's part of the
//! bargain is that the *declaration* reading still parses the initializer as an
//! expression, so nothing inside it is lost when the reading is the wrong one.

use super::expr::NO_POSITION;
use super::look::{is_type_keyword, LEVEL_ASSIGN};
use super::tag::NodeTag;
use super::{Parser, Task};
use crate::csource::lex::TokenKind;
use crate::syntax::event::Marker;
use crate::syntax::recover::SyncSet;

/// Where a declaration that could not be finished resumes.
///
/// `;` ends the declaration, `{` and `}` bound whatever body it belonged to.
/// The members must be written in discriminant order, which
/// `the_sync_set_is_sorted` checks rather than assumes --- [`SyncSet::new`]
/// binary-searches, so an unsorted set silently stops matching.
const DECL_SYNC: SyncSet = SyncSet::new(&[
    TokenKind::LBrace.as_u16(),
    TokenKind::RBrace.as_u16(),
    TokenKind::Semi.as_u16(),
]);

impl Parser<'_> {
    /// Parse one item at file scope.
    ///
    /// Everything at file scope is a declaration, which is why there is no
    /// ambiguity to resolve here and none is invented: the four special cases
    /// are a stray `;`, a preprocessor line, a file-scope `asm`, and
    /// `_Static_assert`.
    pub(super) fn external_decl(&mut self) {
        use TokenKind::*;
        if self.at_eof() {
            return;
        }
        match self.peek() {
            Hash => self.preprocessor_line(),
            Semi => {
                let marker = self.open(NodeTag::NullStmt);
                self.bump();
                self.close(marker);
            }
            KwStaticAssert => self.static_assert(),
            KwAsm => self.asm_construct(),
            KwExtension => {
                self.bump();
                self.push(Task::ExternalDecl);
            }
            // A closer or a separator at file scope belongs to no construct.
            // It keeps a node (`REQ-CFG-11`) and costs one token.
            RParen | RBrace | RBracket | Comma | Colon | Question => {
                let marker = self.open(NodeTag::Error);
                let message = format!("`{}` cannot start a declaration", self.peek().name());
                self.error(message);
                self.bump();
                self.close(marker);
            }
            _ => self.declaration(),
        }
    }

    /// Parse a declaration: specifiers, then one or more declarators.
    ///
    /// Queued rather than run to completion, because a declarator can carry an
    /// initializer and an initializer is an expression --- so the rest of the
    /// declaration is a continuation like any other (`REQ-SYN-3`).
    pub(super) fn declaration(&mut self) {
        let marker = self.open(NodeTag::Decl);
        let specifiers = self.open(NodeTag::DeclSpecifiers);
        self.eat_decl_specifiers();
        self.close(specifiers);
        // `struct s { int a; };` declares a type and nothing else.
        if self.eat(TokenKind::Semi) {
            self.close(marker);
            return;
        }
        self.push(Task::Declarators { marker, index: 0 });
    }

    /// The specifier run: storage classes, qualifiers, type specifiers and the
    /// GNU decorations that appear among them (`REQ-IN-3`).
    ///
    /// The one judgement call is when a bare identifier belongs to this run
    /// rather than starting the declarator. The rule --- no type specifier seen
    /// yet, and the next token continues a declaration head --- is the standard
    /// one, and it is what makes `undefined4 uVar1;` a declaration without
    /// anybody having declared `undefined4`.
    fn eat_decl_specifiers(&mut self) {
        use TokenKind::*;
        let mut saw_type = false;
        loop {
            if self.at_eof() || !self.work.charge(1) {
                return;
            }
            match self.peek() {
                KwTypedef | KwExtern | KwStatic | KwAuto | KwRegister | KwInline | KwNoreturn
                | KwThreadLocal | KwConst | KwVolatile | KwRestrict => self.bump(),
                KwVoid | KwChar | KwShort | KwInt | KwLong | KwFloat | KwDouble | KwSigned
                | KwUnsigned | KwBool | KwComplex | KwImaginary | KwInt128 | KwBuiltinVaList => {
                    saw_type = true;
                    self.bump();
                }
                KwStruct | KwUnion | KwEnum => {
                    saw_type = true;
                    self.bump();
                    self.eat_attribute_run();
                    if self.at(Identifier) {
                        self.bump();
                    }
                    if self.at(LBrace) {
                        let body = self.open(NodeTag::StructBody);
                        self.eat_balanced();
                        self.close(body);
                    }
                    self.eat_attribute_run();
                }
                KwAtomic => {
                    self.bump();
                    if self.at(LParen) {
                        saw_type = true;
                        self.eat_balanced();
                    }
                }
                KwTypeof => {
                    saw_type = true;
                    self.bump();
                    if self.at(LParen) {
                        self.eat_balanced();
                    }
                }
                KwAlignas => {
                    self.bump();
                    if self.at(LParen) {
                        self.eat_balanced();
                    }
                }
                KwAttribute => self.eat_attribute_run(),
                KwExtension => self.bump(),
                Identifier if !saw_type && self.identifier_is_a_specifier() => {
                    saw_type = true;
                    self.bump();
                }
                _ => return,
            }
        }
    }

    /// Whether the identifier under the cursor names a type in this specifier
    /// run, decided by what follows it and never by a typedef table.
    fn identifier_is_a_specifier(&self) -> bool {
        use TokenKind::*;
        let next = self.nth(1);
        matches!(
            next,
            Identifier | Star | LParen | KwConst | KwVolatile | KwRestrict
        ) || is_type_keyword(next)
    }

    /// Consume a run of `__attribute__((...))`, each as its own node.
    fn eat_attribute_run(&mut self) {
        while self.at(TokenKind::KwAttribute) && self.work.charge(1) {
            let marker = self.open(NodeTag::Attribute);
            self.bump();
            if self.at(TokenKind::LParen) {
                self.eat_balanced();
            }
            self.close(marker);
        }
    }

    /// Consume the attributes and `asm` name suffix a declarator may carry.
    ///
    /// Distinct from [`Parser::asm_construct`] in exactly one way: it must not
    /// eat the `;`, which belongs to the declaration rather than to the `asm`.
    fn eat_gnu_declarator_tail(&mut self) {
        loop {
            if self.at(TokenKind::KwAttribute) {
                self.eat_attribute_run();
                continue;
            }
            if self.at(TokenKind::KwAsm) {
                let marker = self.open(NodeTag::Asm);
                self.bump();
                if self.at(TokenKind::LParen) {
                    self.eat_balanced();
                }
                self.close(marker);
                continue;
            }
            return;
        }
    }

    /// One declarator, and then whichever of the four things can follow it.
    pub(super) fn declarators(&mut self, marker: Marker, index: u32) {
        use TokenKind::*;
        let before = self.cursor.pos();
        let declarator = self.open(NodeTag::Declarator);
        self.eat_declarator();
        if self.cursor.pos() == before {
            // `int;` and every recovery path: an empty node would carry no
            // span, which `REQ-SYN-7` would rather not have to explain.
            self.abandon(declarator);
        } else {
            self.close(declarator);
        }
        self.eat_gnu_declarator_tail();

        if self.at(LBrace) && index == 0 {
            self.begin_function_body(marker);
            return;
        }
        if self.at(Eq) {
            let initializer = self.open(NodeTag::Initializer);
            self.bump();
            self.push(Task::DeclTail { marker, index });
            self.push(Task::Close(initializer));
            self.push_initializer_value();
            return;
        }
        self.push(Task::DeclTail { marker, index });
    }

    /// Queue an initializer's value: a braced list, or an
    /// assignment-expression (never a comma expression --- the comma separates
    /// declarators).
    fn push_initializer_value(&mut self) {
        if self.at(TokenKind::LBrace) {
            let list = self.open(NodeTag::InitList);
            self.bump();
            self.push(Task::InitList {
                marker: list,
                last: NO_POSITION,
            });
        } else {
            self.push_expr(LEVEL_ASSIGN);
        }
    }

    /// Turn the declaration into a definition and queue its body.
    fn begin_function_body(&mut self, marker: Marker) {
        self.patch(&marker, NodeTag::FuncDef);
        let body = self.open(NodeTag::CompoundStmt);
        self.bump();
        self.push(Task::Close(marker));
        self.push(Task::Block {
            marker: body,
            last: NO_POSITION,
        });
    }

    /// Decide what ends a declarator: another declarator, the declaration's
    /// `;`, an old-style parameter list, or a recovery.
    pub(super) fn decl_tail(&mut self, marker: Marker, index: u32) {
        use TokenKind::*;
        if self.eat(Comma) {
            self.push(Task::Declarators {
                marker,
                index: index + 1,
            });
            return;
        }
        if self.eat(Semi) {
            self.close(marker);
            return;
        }
        if self.at_eof() {
            self.expect(Semi, false);
            self.close(marker);
            return;
        }
        // K&R: `int f(a, b) int a; int b; { ... }`. Only reachable when the
        // declarator ended in `)`, so an ordinary misparse cannot land here
        // and swallow the rest of the file looking for a brace.
        if index == 0 && self.previous_kind() == Some(RParen) && self.starts_declaration() {
            let params = self.open(NodeTag::ParamList);
            while !self.at_eof() && !self.at(LBrace) && self.work.charge(1) {
                self.bump();
            }
            self.close(params);
            if self.at(LBrace) {
                self.begin_function_body(marker);
            } else {
                self.close(marker);
            }
            return;
        }
        let skipped = self.open(NodeTag::Error);
        let message = format!(
            "expected `;` or `,` after a declarator, found `{}`",
            self.peek().name()
        );
        self.error(message);
        self.skip_into_error(&DECL_SYNC);
        self.close(skipped);
        self.eat(Semi);
        self.close(marker);
    }

    /// The kind of the token just consumed, or `None` at the start of input.
    fn previous_kind(&self) -> Option<TokenKind> {
        let at = self.cursor.pos().checked_sub(1)?;
        TokenKind::from_u16(
            self.cursor
                .tokens()
                .kind(crate::syntax::ids::TokenId::new(at)),
        )
    }

    /// Consume tokens into the open node until one the caller can resume on.
    ///
    /// **Why not [`crate::syntax::recover::skip_to_sync`]:** it advances the
    /// cursor directly, so the tokens it discards never reach the event stream
    /// and the recovered node ends up with no extent --- which `REQ-SYN-7`
    /// ("a construct recovered from an error still carries the span of the text
    /// it skipped") and `REQ-CFG-11` both forbid. The [`SyncSet`] itself, and
    /// its termination argument, are the parts worth reusing, so this bumps
    /// rather than skips and asks the set the same membership question.
    ///
    /// A declaration keyword also stops the skip. Without that, garbage between
    /// two functions would be skipped past the next function's header and eat
    /// it, turning one bad construct into a lost definition.
    fn skip_into_error(&mut self, set: &SyncSet) {
        while !self.at_eof() && self.work.charge(1) {
            let kind = self.peek();
            if set.contains(kind.as_u16()) || super::look::is_decl_start_keyword(kind) {
                return;
            }
            self.bump();
        }
    }

    /// One declarator: pointers, the name, and the array and parameter
    /// suffixes, including the parenthesised grouping form.
    ///
    /// A left-to-right loop with an explicit `depth` counter rather than the
    /// recursion the C grammar is written with. The name is the first
    /// identifier reached at declarator level: array suffixes and parameter
    /// lists are consumed whole, so nothing inside them can be mistaken for it,
    /// and `int (*resolve(int k))(void)` still names `resolve`.
    fn eat_declarator(&mut self) {
        use TokenKind::*;
        let mut found_name = false;
        let mut depth = 0u32;
        loop {
            if self.at_eof() || !self.work.charge(1) {
                return;
            }
            match self.peek() {
                Star | KwConst | KwVolatile | KwRestrict | KwAtomic => self.bump(),
                KwAttribute => self.eat_attribute_run(),
                Identifier if !found_name => {
                    let name = self.open(NodeTag::DeclName);
                    self.bump();
                    self.close(name);
                    found_name = true;
                }
                LParen if !found_name && !self.parameter_list_ahead() => {
                    self.bump();
                    depth += 1;
                }
                LParen => {
                    let params = self.open(NodeTag::ParamList);
                    self.eat_balanced();
                    self.close(params);
                }
                RParen if depth > 0 => {
                    self.bump();
                    depth -= 1;
                }
                LBracket => {
                    let suffix = self.open(NodeTag::ArraySuffix);
                    self.eat_balanced();
                    self.close(suffix);
                }
                _ => return,
            }
        }
    }

    /// Whether the `(` under the cursor opens a parameter list rather than
    /// grouping parentheses around an inner declarator.
    ///
    /// Only asked before the name has been found, where `int (foo)(void)` and
    /// `int (*)(void)` both start with `(`. A parameter list begins with `)`,
    /// `...`, an attribute or a type keyword; anything else --- an identifier,
    /// a `*` --- is the grouping form.
    fn parameter_list_ahead(&self) -> bool {
        use TokenKind::*;
        let next = self.nth(1);
        matches!(next, RParen | Ellipsis | KwAttribute) || is_type_keyword(next)
    }

    /// One element of a braced initializer, or the closing `}`.
    ///
    /// `last` carries the position the previous element started at, so an
    /// element that consumed nothing is detected and forced forward instead of
    /// spun on --- the same guard the compound-statement loop uses.
    pub(super) fn init_list(&mut self, marker: Marker, last: u32) {
        use TokenKind::*;
        if self.eat(RBrace) {
            self.close(marker);
            return;
        }
        if self.at_eof() {
            self.error("unterminated initializer: expected `}`");
            self.close(marker);
            return;
        }
        if self.cursor.pos() == last {
            let skipped = self.open(NodeTag::Error);
            let message = format!("unexpected `{}` in an initializer", self.peek().name());
            self.error(message);
            self.bump();
            self.close(skipped);
        }
        let start = self.cursor.pos();
        // Designators. `[3]` and `[0 ... 7]` are constant expressions with no
        // control flow, so the brackets are consumed whole.
        loop {
            if self.at(Dot) && self.nth(1) == Identifier {
                let designator = self.open(NodeTag::Designator);
                self.bump();
                self.bump();
                self.close(designator);
            } else if self.at(LBracket) {
                let designator = self.open(NodeTag::Designator);
                self.eat_balanced();
                self.close(designator);
            } else {
                break;
            }
            if !self.work.charge(1) {
                break;
            }
        }
        self.eat(Eq);
        self.push(Task::InitMore { marker, start });
        self.push_initializer_value();
    }

    /// The `,` between two initializer elements.
    pub(super) fn init_more(&mut self, marker: Marker, start: u32) {
        self.eat(TokenKind::Comma);
        self.push(Task::InitList {
            marker,
            last: start,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::{parse, tag::NodeTag};
    use super::DECL_SYNC;
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

    /// The node tag names of `text`'s tree, asserting it parsed clean.
    fn tags(text: &str) -> Vec<&'static str> {
        let bad = errors(text);
        assert!(bad.is_empty(), "{text}: {bad:?}");
        let tree = parse(text).into_parts().0;
        tree.arena()
            .preorder_roots()
            .filter_map(|node| tree.arena().tag(node))
            .filter_map(NodeTag::from_u16)
            .map(NodeTag::name)
            .collect()
    }

    #[test]
    fn the_sync_set_is_sorted() {
        // `SyncSet::new` binary-searches; an unsorted literal silently stops
        // matching one of its members, and the failure surfaces as a recovery
        // that runs to end of input.
        assert!(DECL_SYNC.contains(crate::csource::lex::TokenKind::Semi.as_u16()));
        assert!(DECL_SYNC.contains(crate::csource::lex::TokenKind::LBrace.as_u16()));
        assert!(DECL_SYNC.contains(crate::csource::lex::TokenKind::RBrace.as_u16()));
        assert!(!DECL_SYNC.contains(crate::csource::lex::TokenKind::Comma.as_u16()));
    }

    #[test]
    fn every_declarator_form_parses_and_names_what_it_declares() {
        for (text, name) in [
            ("int a;", "a"),
            ("int *p;", "p"),
            ("const char *const q;", "q"),
            ("int a[10];", "a"),
            ("int m[2][3];", "m"),
            ("int f(int x, int y);", "f"),
            ("int (*fp)(void);", "fp"),
            ("int (*table[4])(int);", "table"),
            ("static inline int g(void);", "g"),
            ("extern int (*volatile v)[8];", "v"),
            ("typedef unsigned long size_type;", "size_type"),
        ] {
            let bad = errors(text);
            assert!(bad.is_empty(), "{text}: {bad:?}");
            let tree = parse(text).into_parts().0;
            let arena = tree.arena();
            let spans = tree.token_spans(text);
            let found = arena
                .preorder_roots()
                .filter(|n| arena.tag(*n) == Some(NodeTag::DeclName.as_u16()))
                .filter_map(|n| arena.span(n, &spans))
                .map(|s| text[s.range()].to_string())
                .collect::<Vec<_>>();
            assert_eq!(found, vec![name.to_string()], "{text}");
        }
    }

    #[test]
    fn several_declarators_share_one_declaration() {
        let text = "int a, *b, c[4], (*d)(void);";
        assert!(errors(text).is_empty(), "{:?}", errors(text));
        let tree = parse(text).into_parts().0;
        let arena = tree.arena();
        let declarations = arena
            .preorder_roots()
            .filter(|n| arena.tag(*n) == Some(NodeTag::Decl.as_u16()))
            .count();
        let declarators = arena
            .preorder_roots()
            .filter(|n| arena.tag(*n) == Some(NodeTag::Declarator.as_u16()))
            .count();
        assert_eq!(declarations, 1);
        assert_eq!(declarators, 4);
    }

    #[test]
    fn an_initializer_is_kept_because_it_carries_control_flow() {
        // `REQ-CFG-3`: a declaration with an initializer is a node.
        let dump = tags("int x = f(a) ? g(b) : 0;");
        assert!(dump.contains(&"initializer"), "{dump:?}");
        assert!(dump.contains(&"cond_expr"), "{dump:?}");
        assert!(dump.contains(&"call_args"), "{dump:?}");
        // ...and one without contributes nothing but still parses.
        assert!(!tags("int x;").contains(&"initializer"));
    }

    #[test]
    fn a_nested_and_designated_initializer_parses() {
        for text in [
            "int a[3] = {1, 2, 3};",
            "int a[3] = {1, 2, 3,};",
            "struct p q = {.x = 1, .y = 2};",
            "int t[8] = {[3] = 1, [5] = 2};",
            "int t[2][2] = {{1, 2}, {3, 4}};",
            "struct s r = {.a.b = 1};",
            "char *n[] = {\"a\", \"b\", 0};",
            "int e[4] = {[0 ... 2] = 7};",
            "struct outer o = {.inner = {.deep = {1, 2}}, .tail = f(x)};",
        ] {
            let bad = errors(text);
            assert!(bad.is_empty(), "{text}: {bad:?}");
        }
    }

    #[test]
    fn the_gnu_declaration_surface_parses() {
        for text in [
            "__attribute__((noinline)) int f(void) { return 0; }",
            "int f(void) __attribute__((noreturn));",
            "int v __attribute__((aligned(16)));",
            "extern int e __asm__(\"real_name\");",
            "__extension__ typedef unsigned long long ull;",
            "typedef __typeof__(1 + 1) intish;",
            "_Static_assert(sizeof(int) == 4, \"width\");",
            "struct s { int a : 3; unsigned b : 5; };",
            "union u { int i; float f; };",
            "enum e { A = 1, B, C };",
            "struct { int anon; } named;",
            "static _Thread_local int tls;",
            "int f(int a, ...) { return a; }",
            "void f(void) { __label__ l; l: ; }",
            "typedef struct node { struct node *next; } node_t;",
            "static const char *const names[] __attribute__((used)) = {\"a\"};",
        ] {
            let bad = errors(text);
            assert!(bad.is_empty(), "{text}: {bad:?}");
        }
    }

    #[test]
    fn a_struct_body_is_one_opaque_node_and_declares_no_locals() {
        let text = "struct s { int a; int b; };";
        let dump = tags(text);
        assert!(dump.contains(&"struct_body"), "{dump:?}");
        // The members are inside the token run, so they are not `decl_name`s
        // competing with the thing being declared.
        assert!(!dump.contains(&"decl_name"), "{dump:?}");
    }

    #[test]
    fn an_old_style_definition_is_still_a_definition() {
        let text = "int add(a, b) int a; int b; { return a + b; }\n";
        let tree = parse(text).into_parts().0;
        let functions = tree.functions(text);
        assert_eq!(functions.len(), 1, "{:?}", errors(text));
        assert_eq!(functions[0].name, "add");
    }

    #[test]
    fn a_declaration_that_cannot_be_finished_stops_at_the_next_one() {
        let text = "int a = ;\nint good(void) { return 1; }\n";
        let tree = parse(text).into_parts().0;
        assert_eq!(
            tree.functions(text)
                .into_iter()
                .map(|f| f.name)
                .collect::<Vec<_>>(),
            vec!["good"]
        );
    }

    #[test]
    fn a_definition_after_an_unrecognised_declaration_is_not_swallowed() {
        // The reason `skip_into_error` also stops on a declaration keyword.
        let text = "int broken ??? \nint after(void) { return 2; }\n";
        let tree = parse(text).into_parts().0;
        let names: Vec<String> = tree.functions(text).into_iter().map(|f| f.name).collect();
        assert_eq!(names, vec!["after"]);
    }
}
