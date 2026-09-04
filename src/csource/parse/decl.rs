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
//! # Decorations that are consumed and produce nothing
//!
//! A calling convention ([`TokenKind::KwCallConv`]) and an IDA register
//! annotation ([`TokenKind::RegisterAnnotation`]) are legal in three places
//! each --- among the specifiers, inside the declarator, and trailing it ---
//! and in all three they are bumped and no node is opened. That is stronger
//! than "ignored": an opened-and-abandoned node would still carry a span, and
//! [`crate::csource::joern`] counts nodes. The invariant the tests state is the
//! one that matters, and it is an equality rather than a bound --- the tree for
//! `int __fastcall f(int a) { ... }` is the tree for `int f(int a) { ... }`,
//! tag for tag.
//!
//! `__declspec(...)` is the fourth, and it is *not* free: it takes a balanced
//! parenthesis group, so it shares [`Parser::eat_attribute_run`] with
//! `__attribute__((...))` and produces the same [`NodeTag::Attribute`] node
//! both already produced. Before it was recognised, `__declspec(noreturn) int
//! f(void) {...}` parsed as a function named **`noreturn`** --- a silently
//! wrong answer, which is worse than the dropped function a convention keyword
//! cost.
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

/// How many tokens an IDA `__spoils<...>` register list may hold before the
/// shape is not believed.
///
/// Sixteen registers plus their commas covers every architecture IDA
/// decompiles for; a longer run is far more likely to be arithmetic that
/// happens to contain a `<`.
const MAX_SPOILS_LIST: u32 = 32;

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

/// What ends a declarator-level bracket group even without its closer.
///
/// A parameter list, an array suffix and an attribute all sit at declarator
/// level, and neither a `{` nor a `;` can appear at one's own nesting level in
/// legal C. A `{` there belongs to the function body the declarator
/// introduces, a `;` ends the declaration; either one says the `)` or `]` is
/// missing rather than that the group continues. So
/// `int a(void { return 1; }` costs one function instead of the file, and
/// `int a[3; int b(void){...}` costs a bound instead of the file.
///
/// This is the grammar knowledge tree-sitter gets for free from
/// `function_definition -> declarator compound_statement` and delimiter
/// arithmetic cannot derive; `Parser::eat_balanced_until` explains why it is
/// checked only at depth one, and how the `struct`/`union`/`enum` body --- the
/// one construct that may legally open a brace inside a parameter list ---
/// stays exempt.
///
/// The members must be written in discriminant order, for the reason
/// [`DECL_SYNC`] gives; `the_declarator_follow_set_is_looked_up_not_assumed`
/// checks rather than trusts it.
pub(super) const DECLARATOR_FOLLOW: SyncSet =
    SyncSet::new(&[TokenKind::LBrace.as_u16(), TokenKind::Semi.as_u16()]);

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
            // Every arm below consumes at least one token, and the loop ends
            // the moment one does not. The guard is not decoration: an arm that
            // dispatches on a kind its consumer does not consume spins here
            // until the work budget --- four billion steps --- is gone, which
            // terminates on paper (`REQ-SYN-4`) and hangs in practice. Stopping
            // on no progress turns that class of mistake into one token the
            // caller reports instead.
            let before = self.cursor.pos();
            match self.peek() {
                KwTypedef | KwExtern | KwStatic | KwAuto | KwRegister | KwInline | KwNoreturn
                | KwThreadLocal | KwConst | KwVolatile | KwRestrict => self.bump(),
                // A calling convention is a specifier with no grammar and no
                // CFG contribution, so it is consumed and nothing is opened:
                // `int __fastcall f(int)` must build the same tree as
                // `int f(int)`, which
                // `a_calling_convention_changes_nothing_it_touches` asserts.
                KwCallConv => self.bump(),
                // Out of place here --- a register annotation belongs to a
                // declarator --- but `REQ-SYN-2` is about what happens when
                // input is not what it should be, and stopping the specifier
                // run on one would cost the whole declaration.
                RegisterAnnotation => self.bump(),
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
                KwAttribute | KwDeclspec => self.eat_attribute_run(),
                KwExtension => self.bump(),
                Identifier if self.spoils_list_ahead() => {
                    // Not a type, so `saw_type` is left alone: `__spoils<...>`
                    // decorates the declaration that already has one.
                    self.bump();
                    while !self.at_eof() && !self.at(Gt) && self.work.charge(1) {
                        self.bump();
                    }
                    self.eat(Gt);
                }
                Identifier if self.identifier_is_a_specifier(saw_type) => {
                    saw_type = true;
                    self.bump();
                }
                _ => return,
            }
            if self.cursor.pos() == before {
                return;
            }
        }
    }

    /// Whether the identifier under the cursor belongs to this specifier run
    /// rather than starting the declarator, decided by what follows it and
    /// never by a typedef table.
    ///
    /// # Why an identifier before another identifier is always a specifier
    ///
    /// `saw_type` is what normally stops the run: once a type has been seen,
    /// the next identifier is the name. That rule is wrong for exactly one
    /// shape, and it is the shape decompilers write constantly ---
    ///
    /// ```text
    /// undefined8 __rustcall FUN_00101169(void)
    /// __int64 __fastcall sub_401000(__int64 a1)
    /// long int64_t history_def_last(void *arg1)(void *arg1)
    /// void processEntry entry(void)
    /// ```
    ///
    /// --- where a *third* word sits between the type and the name. Under the
    /// `saw_type` rule the middle word becomes the function's name and the real
    /// name becomes an unexpected token, which costs the whole definition.
    ///
    /// The fix is structural, and deliberately not a keyword list. Measured
    /// over 4,287 captured Ghidra functions the middle position held
    /// `__rustcall` (436), `__cdecl` (320), `__thiscall` (59), `__stdcall` (10)
    /// and `processEntry` (6) --- the last being Ghidra's own name for the
    /// convention it gives every ELF `_start`, and evidence that the set is
    /// open. Any whitelist is a list that a decompiler release can invalidate.
    /// So: **an identifier directly followed by another identifier is a
    /// specifier**, however many have come before it. The name is the last
    /// identifier in the run, which is what C's own grammar says too.
    ///
    /// Nothing is given up. `int a b;` is not a legal declaration, so no
    /// correct program distinguishes the two readings, and the incorrect
    /// programs this front end exists to read all mean the same thing by it.
    ///
    /// # The array-return shape
    ///
    /// Ghidra writes a function returning an aggregate as `undefined1 [16]
    /// f(void)`. The `[16]` binds to the *return type*, and the giveaway is
    /// that an identifier follows the bracket group --- `undefined1 auVar1
    /// [16];`, a real array variable, has a `;` there instead. Recognising the
    /// specifier hands the `[16]` to [`Parser::eat_declarator`] as an ordinary
    /// array suffix, which is exactly how angr's already-working `unsigned long
    /// long [4] f(void)` reaches the same place.
    fn identifier_is_a_specifier(&self, saw_type: bool) -> bool {
        use TokenKind::*;
        let next = self.nth(1);
        if next == Identifier {
            return true;
        }
        if next == LBracket {
            return self.array_return_ahead();
        }
        // A calling convention sits *before* the declarator, never after the
        // name --- `int f __cdecl;` is not C, while `undefined8 __rustcall
        // __stdcall ns::f(void)` is what a decompiler writes when the middle
        // word is its own convention name and the next is a real one. Without
        // this the run ends at `__rustcall`, which then becomes the name and
        // costs the definition; `a_convention_after_a_middle_word_is_not_the_name`
        // is the case. It is the one member of the list below that stays true
        // after a type has been seen, because it is the one that cannot
        // legally follow a name.
        if next == KwCallConv {
            return true;
        }
        if saw_type {
            return false;
        }
        matches!(
            next,
            Star | LParen | KwConst | KwVolatile | KwRestrict | KwDeclspec
        ) || is_type_keyword(next)
    }

    /// Whether the identifier under the cursor carries an angle-bracketed
    /// register list --- IDA's `void __spoils<R1,R2,R3,R12,LR> f(char a)`.
    ///
    /// `<` and `>` are comparison operators in C, so this asks for the whole
    /// shape before believing any of it: a run of at most
    /// [`MAX_SPOILS_LIST`] identifiers and commas between the brackets, and an
    /// **identifier immediately after the `>`**. The last condition is what
    /// separates it from arithmetic --- `a < b > c` would have to appear where
    /// a declaration's specifiers go, which only file scope can produce and no
    /// correct program does. Nothing inside the brackets is kept: a spoiled
    /// register list says nothing about control flow.
    fn spoils_list_ahead(&self) -> bool {
        use TokenKind::*;
        if self.nth(1) != Lt {
            return false;
        }
        // A reserved-namespace spelling. Not a word list --- `__spoils` is the
        // only one IDA writes today and a later release may add another --- but
        // a leading `__` is reserved to the implementation at every scope, so
        // no correct program can lose a construct to this rule, and `a < b > c`
        // at file scope keeps its (nonsensical) reading instead of silently
        // becoming a declaration.
        if !self.current_text().starts_with("__") {
            return false;
        }
        for step in 2..(2 + MAX_SPOILS_LIST) {
            match self.nth(step) {
                Identifier | Comma => {}
                Gt => return self.nth(step + 1) == Identifier,
                _ => return false,
            }
        }
        false
    }

    /// Whether the identifier under the cursor is followed by `[` *integer* `]`
    /// and then another identifier --- Ghidra's array-return spelling.
    ///
    /// Tight on purpose. Requiring a literal bound rules out `a[i]`, and
    /// requiring an identifier after the bracket group rules out every real
    /// array declaration: `char buf[16];` has `;` there, `int a[3] = {...}` has
    /// `=`, and `int m[2][3];` has another `[`.
    fn array_return_ahead(&self) -> bool {
        use TokenKind::*;
        self.nth(1) == LBracket
            && self.nth(2) == IntLiteral
            && self.nth(3) == RBracket
            && self.nth(4) == Identifier
    }

    /// Consume a run of `__attribute__((...))` or `__declspec(...)`, each as
    /// its own node.
    ///
    /// The two share a loop because they are the same construct to a parser:
    /// a keyword, a balanced parenthesis group, no control flow inside either.
    /// [`Parser::eat_balanced`] does not care that GNU doubles the parentheses
    /// and MSVC does not, so nothing here has to.
    fn eat_attribute_run(&mut self) {
        use TokenKind::*;
        while (self.at(KwAttribute) || self.at(KwDeclspec)) && self.work.charge(1) {
            let marker = self.open(NodeTag::Attribute);
            self.bump();
            if self.at(LParen) {
                self.eat_balanced_until(&DECLARATOR_FOLLOW);
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
            // Unlike the two loops above, every branch here ends in `continue`,
            // so the only thing between this and a live-lock is that each one
            // consumed something. Asserting that rather than trusting it is
            // what a mutation of `eat_attribute_run` proved necessary: make it
            // stop consuming `__declspec` and this loop spins forever on the
            // token it keeps dispatching to a consumer that no longer takes it.
            let before = self.cursor.pos();
            if self.at(TokenKind::KwAttribute) || self.at(TokenKind::KwDeclspec) {
                self.eat_attribute_run();
                if self.cursor.pos() == before {
                    return;
                }
                continue;
            }
            // `int f(int a) @<eax>` --- the annotation trails the parameter
            // list rather than the name in some IDA output.
            if self.at(TokenKind::RegisterAnnotation) {
                self.bump();
                continue;
            }
            if self.at(TokenKind::KwAsm) {
                let marker = self.open(NodeTag::Asm);
                self.bump();
                if self.at(TokenKind::LParen) {
                    self.eat_balanced_until(&DECLARATOR_FOLLOW);
                }
                self.close(marker);
                continue;
            }
            if self.eat_trailing_attribute_run() && self.cursor.pos() != before {
                continue;
            }
            return;
        }
    }

    /// Consume the bare-identifier attributes that follow a parameter list,
    /// reporting whether any were there.
    ///
    /// # The construct
    ///
    /// Binary Ninja writes `void usage() __noreturn { ... }` and `uint64_t
    /// bi_reverse(uint32_t a) __pure { ... }`; dewolf writes the same word with
    /// an empty argument list, `void Default_Handler() __noreturn() { ... }`.
    /// It is not valid C --- these are macro names the decompiler prints
    /// unexpanded --- but Eclipse CDT tolerates it, DecBench does not sanitize
    /// it away, and it is the single largest measured gap against Joern in the
    /// sample corpus: 33 of binja's 34 lost functions are this and nothing else.
    ///
    /// # The one thing it must not eat
    ///
    /// A K&R definition puts *parameter declarations* in the same position:
    /// `int f(a) size_t a; { ... }`. `size_t` is an identifier followed by an
    /// identifier, so a naive "identifier after the declarator is an attribute"
    /// rule swallows the parameter list and loses the function --- trading one
    /// dialect for another.
    ///
    /// The discriminator already exists and is already tested:
    /// [`Parser::starts_declaration`], the same syntactic rule
    /// [`super::look`] uses to tell a declaration from an expression
    /// statement. `size_t a;` starts a declaration, `__noreturn {` does not.
    /// Reusing it means this construct cannot disagree with the K&R path in
    /// [`Parser::decl_tail`] about which of them owns the tokens.
    ///
    /// # And why it is anchored to a closing parenthesis
    ///
    /// Without that anchor the rule reaches past its construct. `int a` with a
    /// forgotten semicolon, followed by `foo(void) { ... }`, would read `foo`
    /// as an attribute of `a` and then attach the *body* to `a` --- a function
    /// silently recovered under the wrong name, which is worse than losing it,
    /// because a name is what the metric matches on. Requiring the previous
    /// token to be the `)` of the parameter list confines the rule to the
    /// position the construct actually occupies.
    ///
    /// Measured honestly: with today's [`Parser::starts_declaration`] follow set
    /// (`;` `,` `=` `[` `(` `__attribute__` `asm`) no input reaches this check
    /// and fails it --- deleting the anchor breaks no test. It is kept as the
    /// statement of the rule's scope, because the day that follow set grows is
    /// the day the anchor starts carrying weight, and the failure it prevents
    /// is a function recovered under the wrong name rather than a loud error.
    fn eat_trailing_attribute_run(&mut self) -> bool {
        use TokenKind::*;
        if self.previous_kind() != Some(RParen) {
            return false;
        }
        let mut ate = false;
        while self.at(Identifier) && !self.starts_declaration() && self.work.charge(1) {
            let marker = self.open(NodeTag::Attribute);
            self.bump();
            if self.at(LParen) {
                self.eat_balanced_until(&DECLARATOR_FOLLOW);
            }
            self.close(marker);
            ate = true;
        }
        ate
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
            // The same no-progress guard `eat_decl_specifiers` carries, for the
            // same reason.
            let before = self.cursor.pos();
            match self.peek() {
                Star | KwConst | KwVolatile | KwRestrict | KwAtomic => self.bump(),
                // `void (__stdcall *fp)(void)` puts the convention inside the
                // declarator, and `f@<eax>` puts the annotation directly after
                // the name. Both are dropped, and neither may set
                // `found_name`: consuming them is what leaves the *next*
                // identifier free to be the name.
                KwCallConv | RegisterAnnotation => self.bump(),
                KwAttribute | KwDeclspec => self.eat_attribute_run(),
                // The specifier run's structural rule, continued past the `*`
                // that ended it. dewolf writes `long * int64_t* f(long a)`, so
                // the declarator opens on a pointer and *then* meets a second
                // type word --- and an identifier followed by `*` or by another
                // identifier is a type word, never a name. No legal C
                // declarator has one there: `int *p` puts the star first,
                // `int a, *b` has a comma, and `int a * b;` is not a
                // declaration at all.
                Identifier if !found_name && matches!(self.nth(1), Star | Identifier) => {
                    self.bump()
                }
                Identifier if !found_name => {
                    let name = self.open(NodeTag::DeclName);
                    self.bump();
                    // `switchD_0010101c::caseD_0`, every C++ method Ghidra
                    // prints into a `.c` file, and angr's generic paths ---
                    // `core::slice::<impl [T]>::iter_mut`. `::` is not a C
                    // token, so it ended the declarator and cost the
                    // definition. `Parser::qualification_len` measures the
                    // whole run, including the `::<...>` segments the previous
                    // `Colon Colon Identifier` loop stopped at, and says why
                    // the spelling is kept whole.
                    let mut left = self.qualification_len(0);
                    while left > 0 && self.work.charge(1) {
                        self.bump();
                        left -= 1;
                    }
                    self.close(name);
                    found_name = true;
                }
                LParen if !found_name && !self.parameter_list_ahead() => {
                    self.bump();
                    depth += 1;
                }
                LParen => {
                    let params = self.open(NodeTag::ParamList);
                    self.eat_balanced_until(&DECLARATOR_FOLLOW);
                    self.close(params);
                }
                RParen if depth > 0 => {
                    self.bump();
                    depth -= 1;
                }
                LBracket => {
                    let suffix = self.open(NodeTag::ArraySuffix);
                    self.eat_balanced_until(&DECLARATOR_FOLLOW);
                    self.close(suffix);
                }
                _ => return,
            }
            if self.cursor.pos() == before {
                return;
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
    use super::{DECLARATOR_FOLLOW, DECL_SYNC};
    use crate::csource::lex::TokenKind;
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

    /// Every function definition name `text` yields, in source order.
    fn definition_names(text: &str) -> Vec<String> {
        let tree = parse(text).into_parts().0;
        tree.functions(text).into_iter().map(|f| f.name).collect()
    }

    #[test]
    fn the_declarator_follow_set_is_looked_up_not_assumed() {
        // `SyncSet::new` binary-searches; an unsorted or mis-typed literal
        // silently matches nothing, and the failure surfaces as a dropped
        // closer costing the whole file again.
        assert!(DECLARATOR_FOLLOW.contains(TokenKind::LBrace.as_u16()));
        assert!(DECLARATOR_FOLLOW.contains(TokenKind::Semi.as_u16()));
        assert!(!DECLARATOR_FOLLOW.contains(TokenKind::RBrace.as_u16()));
        assert!(!DECLARATOR_FOLLOW.contains(TokenKind::Comma.as_u16()));
    }

    #[test]
    fn a_qualified_definition_survives_a_dropped_brace() {
        // A dropped `}` puts the next definition at *block* scope, where
        // `starts_declaration` decides. `long long ns::f(...)` was already a
        // declaration because it starts with a type keyword; `u64 ns::g(...)`
        // was not, because the follow test landed on the first `:` of the
        // qualification. The two must behave the same, or a dropped brace
        // costs every later definition whose return type is a decompiler
        // typedef rather than a C keyword.
        let text = "int outer(void) {\n\
                    long long alloc::alloc::handle_alloc_error(unsigned long a0) { return 1; }\n\
                    u64 core::slice::sort::heapsort(unsigned long a1) { return 2; }\n";
        let names = definition_names(text);
        assert!(
            names.contains(&"core::slice::sort::heapsort".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"alloc::alloc::handle_alloc_error".to_string()),
            "{names:?}"
        );
    }

    #[test]
    fn a_convention_after_a_middle_word_is_not_the_name() {
        // Ghidra writes its own convention name and a real one side by side.
        // With the specifier run stopping at `__rustcall`, that word became the
        // function's name and the real one was lost. A calling convention
        // cannot follow a declarator's name in C, so an identifier before one
        // is always a specifier.
        for (text, name) in [
            (
                "u32 __rustcall __stdcall core::num::NonZeroU32::get(int self) { return self; }",
                "core::num::NonZeroU32::get",
            ),
            (
                "undefined8 __stdcall FUN_00101169(void) { return 0; }",
                "FUN_00101169",
            ),
            ("int __cdecl f(void) { return 0; }", "f"),
        ] {
            assert_eq!(definition_names(text), vec![name.to_string()], "{text}");
        }
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

    /// Every calling-convention and register-annotation decoration this front
    /// end accepts, written once so each test below sweeps the same set. Each
    /// entry is a `(prefix, suffix)` pair spliced into a fixed function header,
    /// which is what keeps "the decorated form" and "the plain form" the same
    /// text apart from the decoration.
    const DECORATIONS: &[(&str, &str)] = &[
        ("__cdecl ", ""),
        ("__stdcall ", ""),
        ("__fastcall ", ""),
        ("__thiscall ", ""),
        ("__vectorcall ", ""),
        ("__usercall ", ""),
        ("__userpurge ", ""),
        ("__regcall ", ""),
        ("_cdecl ", ""),
        ("_stdcall ", ""),
        ("_fastcall ", ""),
        ("__declspec(dllexport) ", ""),
        ("_declspec(noinline) ", ""),
        ("", "@<eax>"),
        ("", "@ <rax>"),
        ("", "@rax"),
        ("__usercall ", "@<eax>"),
        ("__userpurge ", "@<rax>"),
    ];

    /// The body used by the decoration sweeps: two returns behind a branch, so
    /// a CFG that lost the body would be a different shape rather than merely a
    /// smaller one.
    const BODY: &str = "(int a) { if (a) return 1; return 0; }";

    #[test]
    fn a_calling_convention_changes_nothing_it_touches() {
        // The requirement in one assertion: with the decoration and without it
        // the *whole* tree agrees, tag for tag, and so does the parity CFG the
        // metric reads. An arm that opened a node, or one that let a
        // convention keyword reach `found_name`, fails here.
        let plain = format!("int f{BODY}");
        let plain_tags = tags(&plain);
        let plain_cfg = crate::csource::joern::parity_cfgs(&plain);
        assert_eq!(plain_cfg["f"].nodes.len(), 3, "the fixture itself changed");
        for (prefix, suffix) in DECORATIONS {
            let decorated = format!("int {prefix}f{suffix}{BODY}");
            let bad = errors(&decorated);
            assert!(bad.is_empty(), "{decorated}: {bad:?}");
            // `__declspec(...)` is the one decoration that is *not* free: it
            // keeps the attribute node `__attribute__((...))` already kept.
            let expected: Vec<&str> = if prefix.contains("declspec") {
                let mut with_attribute = plain_tags.clone();
                let at = with_attribute
                    .iter()
                    .position(|tag| *tag == "declarator")
                    .expect("the plain tree has a declarator");
                with_attribute.insert(at, "attribute");
                with_attribute
            } else {
                plain_tags.clone()
            };
            assert_eq!(tags(&decorated), expected, "{decorated}");
            assert_eq!(
                crate::csource::joern::parity_cfgs(&decorated),
                plain_cfg,
                "{decorated} recovered a different CFG"
            );
        }
    }

    #[test]
    fn the_ida_function_header_recovers_its_body_and_its_name() {
        // The shape this work exists for: an undeclared return type, a calling
        // convention, and register annotations on the function and on every
        // parameter. Before, each of the last two lost the whole function.
        for text in [
            "__int64 __fastcall sub_401000(__int64 a1) { if (a1) return 1; return 0; }",
            "int __usercall sub_401000@<eax>(int a1@<ecx>) { if (a1) return 1; return 0; }",
            "_QWORD *__userpurge f@<rax>(int a@<edi>, int b@<esi>) { if (a) return 0; return 0; }",
            "void __stdcall f(unsigned __int8 a) { if (a) return; return; }",
            "__declspec(noreturn) void __cdecl f(int a) { if (a) return; return; }",
        ] {
            let cfgs = crate::csource::joern::parity_cfgs(text);
            let names: Vec<&String> = cfgs.keys().collect();
            assert_eq!(names.len(), 1, "{text}: recovered {names:?}");
            assert!(
                names[0] == "sub_401000" || names[0] == "f",
                "{text}: named {names:?}"
            );
            assert_eq!(
                cfgs[names[0]].nodes.len(),
                3,
                "{text}: {:?}",
                cfgs[names[0]]
            );
        }
    }

    #[test]
    fn a_convention_inside_a_declarator_names_the_pointer() {
        // `void (__stdcall *fp)(void)`: the convention sits where the parser
        // is looking for the name, so an arm that skipped it only in the
        // specifier run would take `fp` for a parameter list and lose it.
        for (text, name) in [
            ("int (__stdcall *fp)(int);", "fp"),
            ("int (__cdecl f)(int);", "f"),
            ("int (__declspec(dllimport) *g)(void);", "g"),
        ] {
            let bad = errors(text);
            assert!(bad.is_empty(), "{text}: {bad:?}");
            let tree = parse(text).into_parts().0;
            let arena = tree.arena();
            let spans = tree.token_spans(text);
            let found: Vec<String> = arena
                .preorder_roots()
                .filter(|n| arena.tag(*n) == Some(NodeTag::DeclName.as_u16()))
                .filter_map(|n| arena.span(n, &spans))
                .map(|s| text[s.range()].to_string())
                .collect();
            assert_eq!(found, vec![name.to_string()], "{text}");
        }
    }

    #[test]
    fn a_declspec_declares_the_function_and_not_its_argument() {
        // The regression this replaces was *silent*: `__declspec` lexed as an
        // identifier, `(noreturn)` as grouping parentheses, and the parser
        // reported a function named `noreturn`. A dropped function is visible
        // in a count; a renamed one corrupts the score it is matched by.
        let text = "__declspec(noreturn) int f(int a) { if (a) return 1; return 0; }";
        let cfgs = crate::csource::joern::parity_cfgs(text);
        assert_eq!(cfgs.keys().collect::<Vec<_>>(), vec!["f"], "{cfgs:?}");
    }

    #[test]
    fn a_malformed_annotation_costs_a_diagnostic_and_never_the_function() {
        // `REQ-SYN-2`: totality is about the inputs that are *not* well formed.
        // Truncated decompiler output is the reason this matters -- each of
        // these is a real annotation cut short somewhere different.
        for text in [
            "int __usercall f@<(int a) { if (a) return 1; return 0; }",
            "int __usercall f@<eax(int a) { if (a) return 1; return 0; }",
            "int __usercall f@(int a) { if (a) return 1; return 0; }",
            "int __usercall f@ (int a) { if (a) return 1; return 0; }",
            "int @<eax> f(int a) { if (a) return 1; return 0; }",
            "int f(int a) @<eax> { if (a) return 1; return 0; }",
        ] {
            let cfgs = crate::csource::joern::parity_cfgs(text);
            assert_eq!(
                cfgs.keys().collect::<Vec<_>>(),
                vec!["f"],
                "{text}: {cfgs:?}"
            );
            assert_eq!(cfgs["f"].nodes.len(), 3, "{text}: {:?}", cfgs["f"]);
        }
        // ...and the ones that are genuinely truncated say so, while a
        // well-formed annotation is accepted in silence.
        let warned = parse("int __usercall f@<(int a) { return 1; }")
            .diagnostics()
            .iter()
            .any(|d| d.severity == Severity::Warning);
        assert!(warned, "a truncated annotation must be reported");
        assert!(parse("int __usercall f@<eax>(int a) { return 1; }")
            .diagnostics()
            .is_empty());
    }

    /// One function, recovered from the header shape each row is named for.
    ///
    /// Every entry is copied from `samples.json`, the DecBench sample corpus,
    /// with the body cut down to a branch and two returns so the assertion can
    /// be an exact node count rather than "not empty" --- a recovered function
    /// with a lost body is a different failure wearing the same face.
    const CORPUS_HEADERS: &[(&str, &str, &str)] = &[
        (
            "ghidra: an open-set convention word",
            "undefined8 __rustcall FUN_00101169(int a) { if (a) return 1; return 0; }",
            "FUN_00101169",
        ),
        (
            "ghidra: the convention word is not even a convention",
            "void processEntry entry(int a) { if (a) return; return; }",
            "entry",
        ),
        (
            "ida: an undeclared return type and a convention",
            "__int64 __fastcall sub_401000(int a1) { if (a1) return 1; return 0; }",
            "sub_401000",
        ),
        (
            "ida: a spoiled-register list",
            "void __spoils<R1,R2,R3,R12,LR> dis_func1(char a1) { if (a1) return; return; }",
            "dis_func1",
        ),
        (
            "binja: a trailing attribute",
            "void usage() __noreturn { if (1) return; return; }",
            "usage",
        ),
        (
            "binja: a trailing attribute after real parameters",
            "unsigned long bi_reverse(unsigned a, int b) __pure { if (a) return 1; return b; }",
            "bi_reverse",
        ),
        (
            "dewolf: a trailing attribute with an argument list",
            "void void Default_Handler() __noreturn() { if (1) return; return; }",
            "Default_Handler",
        ),
        (
            "dewolf: the parameter list written twice",
            "long int64_t f(void* a)(void * a) { if (a) return 1; return 0; }",
            "f",
        ),
        (
            "dewolf: a pointer return written twice",
            "long * int64_t* g(long a)(long a) { if (a) return 0; return 0; }",
            "g",
        ),
        (
            "ghidra: an array return type",
            "undefined1 [16] h(int a) { if (a) return 1; return 0; }",
            "h",
        ),
        (
            "ghidra: a qualified jump-table stub name",
            "void switchD_0010101c::caseD_0(int a) { if (a) return; return; }",
            "switchD_0010101c::caseD_0",
        ),
    ];

    #[test]
    fn every_corpus_function_header_recovers_its_name_and_its_body() {
        for (label, text, name) in CORPUS_HEADERS {
            let cfgs = crate::csource::joern::parity_cfgs(text);
            assert_eq!(
                cfgs.keys().map(String::as_str).collect::<Vec<_>>(),
                vec![*name],
                "{label}: {text}"
            );
            assert_eq!(cfgs[*name].nodes.len(), 3, "{label}: {:?}", cfgs[*name]);
        }
    }

    #[test]
    fn the_specifier_rule_is_structural_rather_than_a_word_list() {
        // The measured reason: over 4,287 captured Ghidra functions the word
        // between the type and the name was `__rustcall`, `__cdecl`,
        // `__thiscall`, `__stdcall` -- and `processEntry`, which is not a
        // calling convention at all. A whitelist is a list that goes stale, so
        // the test uses a word no list would ever hold.
        for middle in ["__rustcall", "processEntry", "totally_made_up_word", "Z"] {
            let text = format!("undefined8 {middle} f(int a) {{ if (a) return 1; return 0; }}");
            let cfgs = crate::csource::joern::parity_cfgs(&text);
            assert_eq!(
                cfgs.keys().map(String::as_str).collect::<Vec<_>>(),
                vec!["f"],
                "{text}"
            );
        }
    }

    #[test]
    fn the_whole_type_run_lands_in_the_specifiers_and_not_in_the_declarator() {
        // Recovery alone does not pin this. `eat_declarator` skips a type word
        // too, for the pointer forms the specifier run cannot reach, so a
        // regression in `identifier_is_a_specifier` still yields the right
        // function -- with the type words filed under the declarator that does
        // not declare them. Asserting the two node extents is what tells the
        // two rules apart.
        let text = "undefined8 __rustcall FUN_00101169(int a) { return a; }";
        let bad = errors(text);
        assert!(bad.is_empty(), "{text}: {bad:?}");
        let tree = parse(text).into_parts().0;
        let arena = tree.arena();
        let spans = tree.token_spans(text);
        let extent = |tag: NodeTag| -> Vec<String> {
            arena
                .preorder_roots()
                .filter(|n| arena.tag(*n) == Some(tag.as_u16()))
                .filter_map(|n| arena.span(n, &spans))
                .map(|s| text[s.range()].trim().to_string())
                .collect()
        };
        assert_eq!(
            extent(NodeTag::DeclSpecifiers),
            vec!["undefined8 __rustcall".to_string()],
            "the convention word belongs to the specifier run"
        );
        assert_eq!(extent(NodeTag::DeclName), vec!["FUN_00101169".to_string()]);
    }

    #[test]
    fn an_angle_bracket_run_is_only_read_as_a_register_list_when_it_can_be_one() {
        // `<` and `>` are operators. The rule that lets IDA's
        // `__spoils<R1,R2,R3,R12,LR>` through must not also let arithmetic
        // through, so it asks for a reserved-namespace spelling and for an
        // identifier after the `>`. Neither line below may become a
        // declaration of `c`.
        // Each fixture fails a different half of the test, and each names the
        // identifier it would have swallowed: `x` is not reserved, and `3`
        // cannot follow a register list.
        for (text, named) in [("x<y> c;", "x"), ("__x<y> 3;", "__x")] {
            let tree = parse(text).into_parts().0;
            let arena = tree.arena();
            let spans = tree.token_spans(text);
            let names: Vec<String> = arena
                .preorder_roots()
                .filter(|n| arena.tag(*n) == Some(NodeTag::DeclName.as_u16()))
                .filter_map(|n| arena.span(n, &spans))
                .map(|s| text[s.range()].to_string())
                .collect();
            assert_eq!(names, vec![named.to_string()], "{text}");
        }
        // ...and the construct it exists for still parses clean.
        let text = "void __spoils<R1,R2,R3,R12,LR> f(char a) { return; }";
        let bad = errors(text);
        assert!(bad.is_empty(), "{text}: {bad:?}");
    }

    #[test]
    fn a_trailing_attribute_never_eats_a_k_and_r_parameter_list() {
        // The trade the `starts_declaration` guard exists to refuse: reading
        // `size_t a;` as an attribute of `add` would consume the parameter
        // declarations and lose the definition, buying binja's dialect with
        // K&R's.
        let text = "int add(a, b) size_t a; size_t b; { return a + b; }\n";
        let tree = parse(text).into_parts().0;
        let functions = tree.functions(text);
        assert_eq!(functions.len(), 1, "{:?}", errors(text));
        assert_eq!(functions[0].name, "add");
        // ...and the keyword-typed form it already handled stays handled.
        let text = "int add(a, b) int a; int b; { return a + b; }\n";
        assert_eq!(parse(text).into_parts().0.functions(text)[0].name, "add");
    }

    #[test]
    fn a_trailing_attribute_cannot_reach_past_a_missing_semicolon() {
        // Anchored to the `)` of a parameter list. Without that anchor a
        // forgotten semicolon lets `after` be read as an attribute of `a` and
        // its body attached to the wrong name -- silently wrong, where the
        // status quo was merely lossy.
        let text = "int a\nint after(void) { return 2; }\n";
        let names: Vec<String> = parse(text)
            .into_parts()
            .0
            .functions(text)
            .into_iter()
            .map(|f| f.name)
            .collect();
        assert_eq!(names, vec!["after"], "{:?}", errors(text));
    }

    #[test]
    fn an_array_declaration_is_not_read_as_an_array_return_type() {
        // `undefined1 [16] f(void)` and `undefined1 auVar1 [16];` differ only
        // in what follows the bracket group, which is exactly what
        // `array_return_ahead` tests.
        let text = "void f(void) { undefined1 auVar1 [16]; auVar1[0] = 1; }";
        let bad = errors(text);
        assert!(bad.is_empty(), "{text}: {bad:?}");
        let tree = parse(text).into_parts().0;
        let arena = tree.arena();
        let spans = tree.token_spans(text);
        let names: Vec<String> = arena
            .preorder_roots()
            .filter(|n| arena.tag(*n) == Some(NodeTag::DeclName.as_u16()))
            .filter_map(|n| arena.span(n, &spans))
            .map(|s| text[s.range()].to_string())
            .collect();
        assert_eq!(names, vec!["f".to_string(), "auVar1".to_string()], "{text}");
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
