//! Bounded lookahead: the questions C's grammar cannot answer from one token.
//!
//! Spec: `docs/design/static-c-analysis/requirements.md` section 9 open
//! question 1 (the declaration-versus-expression ambiguity) and `REQ-SYN-4`
//! (every entry point is bounded).
//!
//! # Why there is no typedef table
//!
//! `A * b;` is a declaration when `A` names a type and a multiplication
//! otherwise, and the only way to *know* is to track every `typedef` through
//! every scope. This parser deliberately does not, because the requirements
//! say the difference is invisible to the artifact being built: both readings
//! are one straight-line item contributing one node with one successor
//! (`REQ-CFG-3`), and the initializer or right-hand side --- the part that can
//! contain a call, a `&&` or a `?:` --- is parsed identically either way. The
//! rule chosen instead is syntactic and stated in
//! [`Parser::starts_declaration`]: an identifier followed by pointers and
//! another identifier, in a position where a declaration is legal, is a
//! declaration. It is wrong for `a * b;` where both are variables, and the
//! consequence of being wrong is nil.
//!
//! The falsification is written down so a later measurement can settle it: if
//! a case is found where the two readings differ in the CFG --- a discarded
//! call, `a * b(c);` --- and it occurs in the corpus, a typedef *name set*
//! (not a scoped table) is the cheap fix and belongs here.
//!
//! # Why the cast decision is asymmetric
//!
//! `(A)(b)` is a cast when `A` is a type and a call otherwise, and the same
//! argument does *not* apply: the two readings differ in whether there is a
//! call, and a call is a node the parity layer counts. So the rule is
//! deliberately conservative in the direction that keeps the *expression*
//! reading: a parenthesised bare identifier is a cast only when the token after
//! it can begin an operand and cannot continue a binary expression. `(uint)x`
//! is a cast; `(f)(x)` is a call; `(size_t)-1` reads as a subtraction. The
//! mis-read cases all stay one straight-line expression with no diagnostic,
//! which is why the error count is not a proxy for this decision's accuracy.

use super::Parser;
use crate::csource::lex::TokenKind;
use crate::syntax::recover::SyncSet;
use crate::syntax::token::Tokens;

/// The comma operator's precedence level: the lowest, and the only one a
/// function argument or an initializer element excludes.
pub(super) const LEVEL_COMMA: u8 = 0;
/// Assignment, right-associative.
pub(super) const LEVEL_ASSIGN: u8 = 1;
/// The conditional operator `?:`, right-associative.
pub(super) const LEVEL_COND: u8 = 2;
/// Logical or, `||`.
pub(super) const LEVEL_LOR: u8 = 3;
/// Logical and, `&&`.
pub(super) const LEVEL_LAND: u8 = 4;
/// Bitwise or, `|`.
pub(super) const LEVEL_BOR: u8 = 5;
/// Bitwise exclusive or, `^`.
pub(super) const LEVEL_BXOR: u8 = 6;
/// Bitwise and, `&`.
pub(super) const LEVEL_BAND: u8 = 7;
/// Equality, `==` and `!=`.
pub(super) const LEVEL_EQ: u8 = 8;
/// Relational, `<`, `>`, `<=`, `>=`.
pub(super) const LEVEL_REL: u8 = 9;
/// Shifts, `<<` and `>>`.
pub(super) const LEVEL_SHIFT: u8 = 10;
/// Additive, `+` and `-`.
pub(super) const LEVEL_ADD: u8 = 11;
/// Multiplicative, `*`, `/` and `%`; the innermost binary level.
pub(super) const LEVEL_MUL: u8 = 12;
/// One past [`LEVEL_MUL`]: the prefix-operator level, which has no frame.
pub(super) const LEVEL_UNARY: u8 = 13;

/// Every binary level's bit set, the safe answer when a scan runs out of
/// budget: an over-approximation costs an abandoned node, an
/// under-approximation costs a misparse.
const ALL_LEVELS: u16 = (1 << LEVEL_UNARY) - 1;

/// How many tokens [`Parser::scan_levels`] reads before giving the safe answer.
const MAX_SCAN: u32 = 4096;

/// How many tokens the type-name shape test reads before giving up.
const MAX_TYPE_SCAN: u32 = 64;

/// How many tokens a `::`-qualified name may span before the shape is not
/// believed.
///
/// `core::ptr::const_ptr::<impl *const T>::as_ref` is 17; 64 leaves room for
/// the deepest Rust path either decompiler prints while still bounding a `<`
/// that turns out to be a comparison (`REQ-SYN-4`).
const MAX_QUALIFIED_NAME: u32 = 64;

/// How many `(T)` groups in a row the cast decision considers.
///
/// `(uint)(int)(short)x` is three; beyond that the shape is not C anyone
/// writes, and the bound is what keeps the decision O(1) per operand.
const MAX_CAST_CHAIN: usize = 8;

/// The precedence level `kind` binds at, or `None` when it is not a binary,
/// assignment, conditional or comma operator.
pub(super) fn level_of(kind: TokenKind) -> Option<u8> {
    use TokenKind::*;
    Some(match kind {
        Comma => LEVEL_COMMA,
        Eq | StarEq | SlashEq | PercentEq | PlusEq | MinusEq | ShlEq | ShrEq | AmpEq | CaretEq
        | PipeEq => LEVEL_ASSIGN,
        Question => LEVEL_COND,
        PipePipe => LEVEL_LOR,
        AmpAmp => LEVEL_LAND,
        Pipe => LEVEL_BOR,
        Caret => LEVEL_BXOR,
        Amp => LEVEL_BAND,
        EqEq | Ne => LEVEL_EQ,
        Lt | Gt | Le | Ge => LEVEL_REL,
        Shl | Shr => LEVEL_SHIFT,
        Plus | Minus => LEVEL_ADD,
        Star | Slash | Percent => LEVEL_MUL,
        _ => return None,
    })
}

/// Whether `kind` is one of the eleven assignment operators.
pub(super) fn is_assign_op(kind: TokenKind) -> bool {
    level_of(kind) == Some(LEVEL_ASSIGN)
}

/// Whether `kind` can begin a type name on its own --- a specifier or a
/// qualifier keyword, as opposed to an identifier that might name a typedef.
pub(super) fn is_type_keyword(kind: TokenKind) -> bool {
    use TokenKind::*;
    matches!(
        kind,
        KwVoid
            | KwChar
            | KwShort
            | KwInt
            | KwLong
            | KwFloat
            | KwDouble
            | KwSigned
            | KwUnsigned
            | KwBool
            | KwComplex
            | KwImaginary
            | KwInt128
            | KwStruct
            | KwUnion
            | KwEnum
            | KwConst
            | KwVolatile
            | KwRestrict
            | KwAtomic
            | KwTypeof
            | KwBuiltinVaList
    )
}

/// Whether `kind` can begin a declaration: a type keyword, a storage class, or
/// one of the GNU decorations gcc leaves in preprocessed output (`REQ-IN-3`).
pub(super) fn is_decl_start_keyword(kind: TokenKind) -> bool {
    use TokenKind::*;
    is_type_keyword(kind)
        || matches!(
            kind,
            KwTypedef
                | KwExtern
                | KwStatic
                | KwAuto
                | KwRegister
                | KwInline
                | KwNoreturn
                | KwThreadLocal
                | KwAlignas
                | KwAttribute
        )
}

/// The shape of the token run inside a pair of parentheses, as far as the cast
/// and `sizeof` decisions need to tell it apart from an expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TypeNameLook {
    /// Not a type name: the run begins with something only an expression can.
    No,
    /// A type name that begins with a keyword, so no identifier is in doubt.
    Keyword,
    /// A type name spelled `ident` followed by `*`, a qualifier, or a
    /// parenthesised `(*...)` --- none of which an expression can be, since
    /// `(a *)` and `(a (*))` do not parse.
    Pointerish,
    /// `(ident)` or `(ident[4])`: a type name *or* a parenthesised variable or
    /// subscript, and nothing inside the parentheses can say which.
    Bare,
}

impl Parser<'_> {
    /// The kind `n` tokens ahead, treating end of input as absent.
    pub(super) fn look(&self, n: u32) -> Option<TokenKind> {
        let raw = self.cursor.peek_at(n);
        if raw == Tokens::EOF {
            return None;
        }
        TokenKind::from_u16(raw)
    }

    /// The index just past the closer matching the opener at `offset`, or
    /// `None` if the input runs out or the scan exceeds its budget.
    pub(super) fn after_matching(&self, offset: u32) -> Option<u32> {
        use TokenKind::*;
        let mut depth = 0u32;
        let mut at = offset;
        for _ in 0..MAX_SCAN {
            match self.look(at)? {
                LParen | LBracket | LBrace => depth += 1,
                RParen | RBracket | RBrace => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Some(at + 1);
                    }
                }
                _ => {}
            }
            at += 1;
        }
        None
    }

    /// What the parenthesised run beginning with the `(` at `lparen` looks
    /// like: a type name, and if so of which kind.
    ///
    /// The shape test is deliberately structural rather than semantic: it never
    /// asks whether an identifier names a type, only whether the tokens around
    /// it are ones an expression could not contain. That is what makes it
    /// total, bounded and free of a typedef table.
    pub(super) fn type_name_in_parens(&self, lparen: u32) -> TypeNameLook {
        use TokenKind::*;
        if self.look(lparen) != Some(LParen) {
            return TypeNameLook::No;
        }
        let Some(first) = self.look(lparen + 1) else {
            return TypeNameLook::No;
        };
        if is_type_keyword(first) {
            return TypeNameLook::Keyword;
        }
        if first != Identifier {
            return TypeNameLook::No;
        }
        let mut at = lparen + 2;
        let mut pointerish = false;
        let mut saw_group = false;
        for _ in 0..MAX_TYPE_SCAN {
            match self.look(at) {
                Some(RParen) => {
                    return if pointerish {
                        TypeNameLook::Pointerish
                    } else {
                        TypeNameLook::Bare
                    }
                }
                Some(Star) | Some(KwConst) | Some(KwVolatile) | Some(KwRestrict)
                | Some(KwAtomic) => {
                    pointerish = true;
                    at += 1;
                }
                // `(a[0])` is `Bare`, not conclusive: it is equally a subscript
                // expression, and reading it as a type would eat the array
                // access in `sizeof(arr[0])`.
                Some(LBracket) => {
                    let Some(next) = self.after_matching(at) else {
                        return TypeNameLook::No;
                    };
                    at = next;
                }
                // `(fn_t (*)(void))` is an abstract declarator; `(f(x))` is a
                // call inside parentheses, and `(a * (b / c))` is arithmetic.
                // A `(` belongs to the type only when it groups a pointer,
                // which is the `(*` that no expression can spell...
                Some(LParen) if self.pointer_group_ends(at).is_some() => {
                    let Some(next) = self.pointer_group_ends(at) else {
                        return TypeNameLook::No;
                    };
                    pointerish = true;
                    saw_group = true;
                    at = next;
                }
                // ...or when it is the parameter list of a grouping already
                // seen. Requiring the grouping first is what keeps
                // `(a * (b / c))` arithmetic: a bare `*` makes a type name
                // *possible*, and a parameter list after nothing is not one.
                Some(LParen)
                    if saw_group
                        && (matches!(self.look(at + 1), Some(RParen) | Some(Ellipsis))
                            || self.look(at + 1).is_some_and(is_type_keyword)) =>
                {
                    let Some(next) = self.after_matching(at) else {
                        return TypeNameLook::No;
                    };
                    at = next;
                }
                _ => return TypeNameLook::No,
            }
        }
        TypeNameLook::No
    }

    /// Whether the `(` under the cursor opens a cast rather than a
    /// parenthesised expression.
    ///
    /// See the module docs for why the bare-identifier case is decided by the
    /// token *after* the closing parenthesis: that is the only evidence there
    /// is, and the tie is broken toward the expression reading because the
    /// expression reading is the one that can contain a call.
    pub(super) fn is_cast_ahead(&self) -> bool {
        // `(A)(B)(C)x` is one chain, and it must be decided from the inside
        // out: `(int)(x);` casts a parenthesised expression, while `(f)(x);`
        // calls a function, and the two differ only in the *last* group. So
        // collect the run of type-name-shaped groups, decide the innermost from
        // what follows the whole run, and propagate leftward --- a group that is
        // unambiguously a type name (a keyword or a pointer) is a cast whatever
        // its neighbour turned out to be.
        let mut looks = [TypeNameLook::No; MAX_CAST_CHAIN];
        let mut count = 0usize;
        let mut at = 0u32;
        while count < MAX_CAST_CHAIN {
            let look = self.type_name_in_parens(at);
            if look == TypeNameLook::No {
                break;
            }
            looks[count] = look;
            count += 1;
            let Some(next) = self.after_matching(at) else {
                break;
            };
            at = next;
        }
        if count == 0 {
            return false;
        }
        let mut is_cast = looks[count - 1] != TypeNameLook::Bare || self.follows_a_cast(at);
        for index in (0..count - 1).rev() {
            is_cast = looks[index] != TypeNameLook::Bare || is_cast;
        }
        is_cast
    }

    /// Whether the token at `at` is one only an operand can start with.
    ///
    /// Deliberately excludes `(`, `*`, `&`, `+` and `-`: each of those can just
    /// as well continue a binary expression, and the tie is broken toward the
    /// expression. The cost is real and worth stating --- decompiler output's
    /// `(uint)*puVar1` reads as a multiplication here --- but it costs no
    /// diagnostic, loses no call, and leaves one straight-line item either way.
    fn follows_a_cast(&self, at: u32) -> bool {
        use TokenKind::*;
        matches!(
            self.look(at),
            Some(Identifier)
                | Some(IntLiteral)
                | Some(FloatLiteral)
                | Some(CharLiteral)
                | Some(StringLiteral)
                | Some(Bang)
                | Some(Tilde)
                | Some(PlusPlus)
                | Some(MinusMinus)
                | Some(KwSizeof)
                | Some(KwAlignof)
                | Some(LBrace)
        )
    }

    /// The index just past `(` `*`+ `)` at `at`, or `None` if the group is
    /// anything else.
    ///
    /// The grouping parentheses of an abstract declarator --- the `(*)` of
    /// `fn_t (*)(void)` --- contain nothing but pointers and qualifiers.
    /// Accepting any group that merely *starts* with `*` reads
    /// `(var37 * (*(int *)(p) + 12))` as a type name, which is a
    /// multiplication by a dereference: it was eight of the eight remaining
    /// errors over the 11.9-million-line decompiled corpus, and this is the
    /// tightening that removed them.
    fn pointer_group_ends(&self, at: u32) -> Option<u32> {
        use TokenKind::*;
        if self.look(at) != Some(LParen) {
            return None;
        }
        let mut stars = 0u32;
        let mut inner = at + 1;
        for _ in 0..MAX_TYPE_SCAN {
            match self.look(inner) {
                Some(Star) => {
                    stars += 1;
                    inner += 1;
                }
                Some(KwConst) | Some(KwVolatile) | Some(KwRestrict) | Some(KwAtomic) => inner += 1,
                Some(RParen) if stars > 0 => return Some(inner + 1),
                _ => return None,
            }
        }
        None
    }

    /// Whether the parenthesised group under the cursor is followed by `{`, so
    /// that it is a compound literal rather than a cast.
    pub(super) fn compound_literal_ahead(&self) -> bool {
        self.after_matching(0).and_then(|at| self.look(at)) == Some(TokenKind::LBrace)
    }

    /// Which precedence levels the expression region starting at the cursor can
    /// contain, as a bit per level.
    ///
    /// This exists because [`crate::syntax::event::Events`] has no `precede`:
    /// a node cannot be wrapped around an already-emitted subtree, so the
    /// `Open` for every precedence level that will be used has to be emitted
    /// *before* the region's first operand. Opening all thirteen unconditionally
    /// is correct but pays ten abandoned nodes for every `x`; one bounded
    /// forward scan says which levels are actually reachable and typically cuts
    /// that to one or two.
    ///
    /// **The scan may over-approximate and may not under-approximate.** An
    /// extra bit costs one node that is opened and abandoned; a missing bit
    /// leaves an operator nobody consumes, which surfaces as a spurious error.
    /// So a `-` that turns out to be a prefix sign still sets the additive bit,
    /// and running out of budget returns every level rather than what was seen
    /// so far.
    pub(super) fn scan_levels(&self, min_level: u8) -> u16 {
        use TokenKind::*;
        let mut mask = 0u16;
        let mut depth = 0u32;
        let mut cond = 0u32;
        let mut at = 0u32;
        loop {
            if at >= MAX_SCAN {
                mask = ALL_LEVELS;
                break;
            }
            let Some(kind) = self.look(at) else { break };
            match kind {
                LParen | LBracket | LBrace => depth += 1,
                RParen | RBracket | RBrace => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                Semi if depth == 0 => break,
                Comma if depth == 0 && min_level > LEVEL_COMMA => break,
                Question if depth == 0 => {
                    cond += 1;
                    mask |= 1 << LEVEL_COND;
                }
                Colon if depth == 0 => {
                    if cond == 0 {
                        break;
                    }
                    cond -= 1;
                }
                other => {
                    if depth == 0 {
                        if let Some(level) = level_of(other) {
                            mask |= 1 << level;
                        }
                    }
                }
            }
            at += 1;
        }
        mask & !((1u16 << min_level) - 1) & ALL_LEVELS
    }

    /// How many tokens of `::`-qualified name follow the identifier at `at - 1`.
    ///
    /// # The construct
    ///
    /// Ghidra and angr both print C++ and Rust *qualified* names into files
    /// they label `.c`, and angr prints the generic form too:
    /// `std::thread::ThreadId::new::exhausted`,
    /// `core::ptr::const_ptr::<impl *const T>::as_ref`,
    /// `core::slice::<impl [T]>::iter_mut`. `::` is not a C token, so without
    /// this the name ends at the first colon and everything after it is
    /// garbage --- which costs the whole definition, and the corpus has 22
    /// angr cases and 7 Ghidra cases carrying one.
    ///
    /// The whole spelling is one name on purpose. Taking only the last
    /// component would collide every `caseD_0` stub in a file onto one entry,
    /// and `parity_cfgs` keys its output by name.
    ///
    /// # The bound
    ///
    /// `REQ-SYN-4`: the scan reads at most [`MAX_QUALIFIED_NAME`] tokens and
    /// returns what it had before the segment that ran over, so a `<` that is
    /// really a comparison cannot make this walk the file. Angle nesting is
    /// counted rather than matched pairwise because `Vec<Vec<T>>` lexes its
    /// tail as one `>>`.
    ///
    /// Returns `0` when the identifier is not qualified, which is the common
    /// case and costs one token of lookahead.
    pub(super) fn qualification_len(&self, at: u32) -> u32 {
        use TokenKind::*;
        let mut taken = 0u32;
        loop {
            let next = at + taken;
            if self.look(next) != Some(Colon) || self.look(next + 1) != Some(Colon) {
                return taken;
            }
            match self.look(next + 2) {
                Some(Identifier) => taken += 3,
                Some(Lt) => {
                    let Some(after) = self.angle_group_end(next + 2) else {
                        return taken;
                    };
                    taken = after - at;
                }
                _ => return taken,
            }
            if taken >= MAX_QUALIFIED_NAME {
                return taken;
            }
        }
    }

    /// The offset just past the `<...>` group starting at `at`, or `None` when
    /// it does not close within [`MAX_QUALIFIED_NAME`] tokens.
    ///
    /// Nesting is a signed count, not a stack, because the lexer folds `>>`
    /// into one token: a group closes when the count reaches zero, and `Shl`
    /// and `Shr` move it by two. An unbalanced run returns `None`, which the
    /// caller reads as "that `<` was a comparison after all".
    fn angle_group_end(&self, at: u32) -> Option<u32> {
        use TokenKind::*;
        let mut depth = 0i32;
        let mut cursor = at;
        while cursor < at + MAX_QUALIFIED_NAME {
            match self.look(cursor)? {
                Lt => depth += 1,
                Shl => depth += 2,
                Gt => depth -= 1,
                Shr => depth -= 2,
                // Nothing that ends a declarator may appear inside a name.
                Semi | LBrace | RBrace => return None,
                _ => {}
            }
            cursor += 1;
            if depth <= 0 {
                return if depth == 0 { Some(cursor) } else { None };
            }
        }
        None
    }

    /// Whether a declaration, rather than an expression statement, starts here.
    ///
    /// The rule and its justification are in the module docs. It is consulted
    /// only at block scope: at file scope nothing but a declaration is legal,
    /// so there is no ambiguity to resolve and none is invented.
    pub(super) fn starts_declaration(&self) -> bool {
        use TokenKind::*;
        let Some(first) = self.look(0) else {
            return false;
        };
        if is_decl_start_keyword(first) || first == KwStaticAssert {
            return true;
        }
        if first == KwExtension {
            return self
                .look(1)
                .is_some_and(|next| is_decl_start_keyword(next) || next == Identifier);
        }
        if first != Identifier {
            return false;
        }
        let mut at = 1u32;
        while matches!(
            self.look(at),
            Some(Star) | Some(KwConst) | Some(KwVolatile) | Some(KwRestrict)
        ) {
            at += 1;
            if at > 8 {
                return false;
            }
        }
        if self.look(at) != Some(Identifier) {
            return false;
        }
        // `u64 core::slice::sort::heapsort(...)` is a definition, and at block
        // scope --- where a dropped `}` puts one --- the qualification is the
        // only thing between it and being read as an expression. Without this
        // the follow test lands on the first `:` and fails, so a whole nested
        // definition is lost; `a_qualified_definition_survives_a_dropped_brace`
        // is the case that measured it.
        let at = at + 1 + self.qualification_len(at + 1);
        matches!(
            self.look(at),
            Some(Semi)
                | Some(Comma)
                | Some(Eq)
                | Some(LBracket)
                | Some(LParen)
                | Some(KwAttribute)
                | Some(KwAsm)
        )
    }

    /// Consume a balanced bracket group starting at the cursor's opener.
    ///
    /// The tool for every construct with no control flow and no lowering
    /// consequence --- an attribute, an `asm` operand list, a parameter list, a
    /// `struct` body, a `_Generic` selection. The tokens land in whatever node
    /// is open, so `REQ-GEN-2` still holds and a later consumer can re-read
    /// them; what is skipped is writing a grammar for them.
    ///
    /// Equivalent to [`Parser::eat_balanced_until`] with no follow set, which
    /// is the right call wherever the group's own brackets are the only thing
    /// that can end it: a `struct` body, a `sizeof` type name, a `typeof`
    /// operand. A construct that also has a *grammatical* terminator --- a
    /// parameter list, which a function body's `{` ends whether or not the `)`
    /// arrived --- must pass that terminator instead, or a single missing
    /// closer costs the rest of the file.
    pub(super) fn eat_balanced(&mut self) {
        self.eat_balanced_until(&SyncSet::EMPTY);
    }

    /// Consume a balanced bracket group, stopping early at `follow`.
    ///
    /// # Why the opener kinds are tracked and not merely counted
    ///
    /// The previous version added every opener to one untyped counter and
    /// subtracted every closer from it. On well-formed C that is exactly right
    /// and much cheaper. On *ill-formed* C --- the only input this function
    /// exists for --- it is wrong in a way that costs whole files. Walk
    /// `int a(void { return 1; }` and then two healthy functions with one
    /// counter: `(` 1, `{` 2, `}` 1, `(` 2, `)` 1, `{` 2, `}` 1 ... the count
    /// never returns to zero, so the parameter list swallows every later
    /// definition. A typed stack makes the shape visible --- the `}` closes the
    /// `{`, not the `(` --- but on its own it does not help, because the `(`
    /// really is unmatched and a stack that waits for its `)` waits forever.
    ///
    /// # Why a follow set is the actual fix
    ///
    /// What tree-sitter has here and delimiter arithmetic does not is the
    /// grammar: `function_definition -> declarator compound_statement` makes
    /// `{` a valid resume point at declarator level regardless of paren
    /// nesting, so a dropped `)` costs one function rather than the file.
    /// `follow` is that knowledge, supplied by the caller that has it: a kind
    /// which, seen at the group's *own* nesting level, means the group ended
    /// without its closer. The scan stops **before** such a token so the caller
    /// resumes on it. [`super::decl::DECLARATOR_FOLLOW`] is the one set that
    /// exists today and [`SyncSet::EMPTY`] is the honest default, because a
    /// caller that does not know its follow set must not pretend to.
    ///
    /// The check is deliberately confined to depth 1. `int f(int a[]) { }`
    /// nests a `[` inside the parameter list and `void g(void (*h)(void)) { }`
    /// nests a `(`; neither is over, and a follow test applied at every depth
    /// would end the group at the first `{` of a nested `struct` body.
    ///
    /// # Mismatched closers
    ///
    /// A closer that matches an opener deeper in the stack pops down to it:
    /// the groups in between were never closed, and `struct { int (*f)(void; }`
    /// should yield the struct body rather than the rest of the file. A closer
    /// that matches nothing open is left unconsumed --- it belongs to a
    /// construct enclosing this one, and eating it would steal the caller's
    /// terminator.
    ///
    /// # Termination
    ///
    /// Every iteration either bumps a token or returns, and the work budget
    /// (`REQ-SYN-4`) bounds the bumps, so the loop cannot spin.
    pub(super) fn eat_balanced_until(&mut self, follow: &SyncSet) {
        // The opener stack is borrowed from the parser rather than allocated
        // here. This runs once per attribute, parameter list, array suffix,
        // cast and `sizeof` type name --- tens of times per function --- and it
        // never re-enters itself, so one buffer whose capacity survives the
        // call is both correct and free. Handing it back on the single exit
        // path is what keeps that true.
        let mut open = std::mem::take(&mut self.brackets);
        open.clear();
        self.eat_balanced_into(follow, &mut open);
        self.brackets = open;
    }

    /// [`Parser::eat_balanced_until`]'s loop, over a caller-owned opener stack.
    ///
    /// Split out only so the buffer has one place to be returned from; every
    /// early exit below is an exit from *this* function.
    fn eat_balanced_into(&mut self, follow: &SyncSet, open: &mut Vec<TokenKind>) {
        use TokenKind::*;
        if self.at_eof() || !matches!(self.peek(), LParen | LBracket | LBrace) {
            return;
        }
        // `struct`/`union`/`enum` arms a legal `{` at the group's own level:
        // `void f(struct { int a; } x)` and `int g(enum e { A } x)` are the
        // only shapes that put one inside a parameter list, and without this
        // the follow set would cut them in half.
        let mut brace_is_legal = false;
        loop {
            if self.at_eof() {
                self.error("unterminated bracket group");
                return;
            }
            let kind = self.peek();
            if open.len() == 1
                && follow.contains(kind.as_u16())
                && !(kind == LBrace && brace_is_legal)
            {
                self.error(format!(
                    "unterminated bracket group: `{}` ends it without a closer",
                    kind.name()
                ));
                return;
            }
            match kind {
                LParen | LBracket | LBrace => open.push(kind),
                RParen | RBracket | RBrace => {
                    let want = match kind {
                        RParen => LParen,
                        RBracket => LBracket,
                        _ => LBrace,
                    };
                    match open.iter().rposition(|k| *k == want) {
                        Some(at) => open.truncate(at),
                        // A closer with nothing of its kind open belongs to an
                        // enclosing construct; leaving it is what keeps a stray
                        // `)` inside a struct body from costing the file.
                        None => {
                            self.error(format!(
                                "unterminated bracket group: `{}` closes nothing it opened",
                                kind.name()
                            ));
                            return;
                        }
                    }
                }
                _ => {}
            }
            // Only at the group's own level: a `struct` nested two deep does
            // not license a brace at level one.
            if open.len() == 1 {
                brace_is_legal = matches!(kind, KwStruct | KwUnion | KwEnum)
                    || (kind == Identifier && brace_is_legal);
            }
            self.bump();
            if open.is_empty() {
                return;
            }
            if !self.work.charge(1) {
                return;
            }
        }
    }

    /// Whether the bytes between two token starts contain a real line break.
    ///
    /// A backslash-newline is a splice, not a break: gcc's line-continuation
    /// rule is what lets a `#define` body run over five physical lines, and
    /// treating the first `\` as the end of the directive would leave the rest
    /// of the macro body to be parsed as C.
    pub(super) fn line_break_between(&self, from: u32, to: u32) -> bool {
        let Some(gap) = self.text.get(from as usize..to as usize) else {
            return true;
        };
        let bytes = gap.as_bytes();
        for (index, byte) in bytes.iter().enumerate() {
            if *byte != b'\n' {
                continue;
            }
            let mut before = index;
            if before > 0 && bytes[before - 1] == b'\r' {
                before -= 1;
            }
            if before > 0 && bytes[before - 1] == b'\\' {
                continue;
            }
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csource::parse::parse;
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

    /// The node tag names in `text`'s tree, in construction order.
    fn tags(text: &str) -> Vec<&'static str> {
        let tree = parse(text).into_parts().0;
        tree.arena()
            .preorder_roots()
            .filter_map(|node| tree.arena().tag(node))
            .filter_map(crate::csource::parse::tag::NodeTag::from_u16)
            .map(crate::csource::parse::tag::NodeTag::name)
            .collect()
    }

    #[test]
    fn a_keyword_cast_and_a_pointer_cast_are_casts() {
        for text in [
            "int f(void){ return (int)x; }",
            "int f(void){ return (unsigned long)x; }",
            "int f(void){ return (struct s *)x; }",
            "int f(void){ return (const char *)x; }",
            "int f(void){ return (undefined4 *)x; }",
            "int f(void){ return (code *)x; }",
        ] {
            assert!(errors(text).is_empty(), "{text}: {:?}", errors(text));
            assert!(tags(text).contains(&"cast_expr"), "{text} lost its cast");
        }
    }

    #[test]
    fn a_bare_identifier_cast_is_decided_by_what_follows_it() {
        // `(uint)uVar1` is decompiler output's most common cast shape.
        assert!(tags("int f(void){ return (uint)uVar1; }").contains(&"cast_expr"));
        assert!(tags("int f(void){ return (undefined4)0; }").contains(&"cast_expr"));
        // ...and the tie goes to the expression reading, because that is the
        // reading that can contain a call.
        let call = tags("int f(void){ return (g)(x); }");
        assert!(!call.contains(&"cast_expr"), "{call:?}");
        assert!(call.contains(&"call_args"));
        // A misread costs no diagnostic, which is the property that matters.
        assert!(errors("int f(void){ return (a) - 1; }").is_empty());
        assert!(errors("int f(void){ return (size_t)-1; }").is_empty());
    }

    #[test]
    fn a_parenthesised_call_keeps_its_call() {
        // The mis-read that would actually cost a CFG node: reading `(f(x))`
        // as a type name swallows the call into a token run. This is why an
        // inner parenthesised group counts as a type only when it starts `(*`.
        for text in [
            "int f(void){ return (g(x)); }",
            "int f(void){ if ((g(x))) return 1; return 0; }",
            "int f(void){ return (g(x)) + 1; }",
        ] {
            assert!(errors(text).is_empty(), "{text}: {:?}", errors(text));
            assert!(tags(text).contains(&"call_args"), "{text} lost its call");
            assert!(!tags(text).contains(&"cast_expr"), "{text} invented a cast");
        }
        // ...while a real abstract function-pointer type is still a type.
        assert!(tags("int f(void){ return (fn_t (*)(void))p; }").contains(&"cast_expr"));
    }

    #[test]
    fn a_cast_chain_is_decided_from_the_inside_out() {
        // `(int32_t)(unsigned char)*p` is two casts; `(f)(x)` is one call; and
        // `(int)(x)` is a cast of a parenthesised expression.
        assert_eq!(
            tags("int f(void){ return (int32_t)(unsigned char)*p; }")
                .iter()
                .filter(|t| **t == "cast_expr")
                .count(),
            2
        );
        assert!(tags("int f(void){ return (uint)(int)x; }").contains(&"cast_expr"));
        assert!(tags("int f(void){ return (int)(x); }").contains(&"cast_expr"));
        assert!(!tags("int f(void){ return (f)(x); }").contains(&"cast_expr"));
    }

    #[test]
    fn a_dereference_inside_a_product_is_not_an_abstract_declarator() {
        // `(a * (*p + 1))` is arithmetic; `(fn_t (*)(void))` is a type. Both
        // are `ident *` followed by a `(`, and only the shape of that group
        // separates them. This was the last defect the 11.9-million-line
        // decompiled sweep still reported.
        for text in [
            "int f(void){ return (a * (*p + 1)); }",
            "int f(void){ return (a * (b / c)); }",
            "int f(void){ return (a * (*p)); }",
        ] {
            assert!(errors(text).is_empty(), "{text}: {:?}", errors(text));
            assert!(!tags(text).contains(&"cast_expr"), "{text} invented a cast");
        }
        // The shape the sweep actually reported, which does contain one real
        // cast: `(int *)` casts `q`, and the outer product must stay a product.
        let real = "int f(void){ return (a * (*(int *)(q) + 12)); }";
        assert!(errors(real).is_empty(), "{:?}", errors(real));
        assert_eq!(tags(real).iter().filter(|t| **t == "cast_expr").count(), 1);
        assert_eq!(
            tags(real).iter().filter(|t| **t == "binary_expr").count(),
            2
        );
        assert!(tags("int f(void){ return (fn_t (*)(void))p; }").contains(&"cast_expr"));
        assert!(tags("int f(void){ return (node_t (*)[4])p; }").contains(&"cast_expr"));
    }

    #[test]
    fn a_type_valued_macro_argument_does_not_become_an_expression() {
        // Unpreprocessed `offsetof`: no C expression starts with `struct`.
        for text in [
            "int f(void){ return offsetof(struct s, m); }",
            "int f(void){ return container_of(p, struct s, m); }",
            "int f(void){ return SIZE(unsigned long); }",
        ] {
            assert!(errors(text).is_empty(), "{text}: {:?}", errors(text));
        }
    }

    #[test]
    fn a_parenthesised_expression_is_not_a_cast() {
        for text in [
            "int f(void){ return (a + b) * c; }",
            "int f(void){ return (*fp)(1); }",
            "int f(void){ return (a); }",
        ] {
            assert!(errors(text).is_empty(), "{text}");
            assert!(!tags(text).contains(&"cast_expr"), "{text} invented a cast");
        }
    }

    #[test]
    fn the_level_scan_never_misses_an_operator_that_is_present() {
        // The property the scan must have: over-approximation is free, an
        // under-approximation is a misparse. Exercised through the parser,
        // since a missed level surfaces there as an error diagnostic.
        for text in [
            "int f(void){ return a + b * c - d / e % g; }",
            "int f(void){ return a == b && c != d || e < f; }",
            "int f(void){ return a | b ^ c & d << e >> f; }",
            "int f(void){ return a ? b ? c : d : e; }",
            "int f(void){ a = b = c += d; }",
            "int f(void){ return (a, b, c); }",
            "int f(void){ return a && (b || c) && d; }",
            "int f(void){ int x = -a + -b; }",
            "int f(void){ g(a, b + c, *d); }",
            "int f(void){ return a[b + c][d] . e -> f; }",
        ] {
            assert!(errors(text).is_empty(), "{text}: {:?}", errors(text));
        }
    }

    #[test]
    fn a_line_splice_does_not_end_a_preprocessor_directive() {
        let text = "#define M(a) \\\n    do { a; } while (0)\nint f(void){ return 1; }\n";
        assert!(errors(text).is_empty(), "{:?}", errors(text));
        let tree = parse(text).into_parts().0;
        assert_eq!(tree.functions(text).len(), 1);
    }

    #[test]
    fn a_declaration_and_an_expression_statement_are_told_apart() {
        assert!(tags("int f(void){ mytype_t x; }").contains(&"decl"));
        assert!(tags("int f(void){ A * b; }").contains(&"decl"));
        assert!(tags("int f(void){ undefined4 uVar1; }").contains(&"decl"));
        let call = tags("int f(void){ foo(x); }");
        assert!(call.contains(&"expr_stmt"), "{call:?}");
        assert!(!call.contains(&"decl"));
        let index = tags("int f(void){ a[0] = 1; }");
        assert!(index.contains(&"expr_stmt"), "{index:?}");
        // The documented misread: harmless, one straight-line item either way.
        assert!(tags("int f(void){ a * b; }").contains(&"decl"));
    }

    /// Every function definition name `text` yields, in source order.
    fn definition_names(text: &str) -> Vec<String> {
        let tree = parse(text).into_parts().0;
        tree.functions(text).into_iter().map(|f| f.name).collect()
    }

    #[test]
    fn a_dropped_parameter_list_closer_costs_one_function_and_not_the_file() {
        // The defect the follow set exists for. With one untyped depth counter
        // the walk `( { } ( ) { } ...` never returns to zero, so the missing
        // `)` swallowed every later definition and the file recovered nothing.
        let text = "int a(void { return 1; }\nint b(void){return 2;}\nint c(void){return 3;}";
        assert_eq!(definition_names(text), vec!["a", "b", "c"]);
        // The same shape one level down. An array suffix cannot contain a `;`
        // either, so the bound is what is lost and the declaration still ends
        // where its `;` says it does.
        let bracket = "int a[3;\nint b(void){return 2;}\nint c(void){return 3;}";
        assert_eq!(definition_names(bracket), vec!["b", "c"]);
        // Both are errors, not silent recoveries.
        assert!(!errors(text).is_empty());
        assert!(!errors(bracket).is_empty());
        // A parameter list has the same two terminators.
        let semi = "int a(void;\nint b(void){return 2;}\nint c(void){return 3;}";
        assert_eq!(definition_names(semi), vec!["b", "c"]);
    }

    #[test]
    fn a_brace_that_opens_a_struct_body_does_not_end_a_parameter_list() {
        // The follow set says `{` ends a parameter list, which is wrong for the
        // one construct that may legally open a brace inside one. Every form of
        // it has to survive, or the fix trades a rare loss for a common one.
        for text in [
            "int a(struct {int x;} s) { return 1; }",
            "int a(struct S {int x;} s) { return 1; }",
            "int a(union {int x; long y;} s) { return 1; }",
            "int a(enum E {X,Y} s) { return 1; }",
            "int a(void) { return sizeof(struct {int x;}); }",
        ] {
            assert_eq!(definition_names(text), vec!["a"], "{text}");
            assert!(errors(text).is_empty(), "{text}: {:?}", errors(text));
        }
    }

    #[test]
    fn a_closer_with_nothing_open_is_left_for_the_caller() {
        // `}` cannot close a `(`. Popping to the matching opener keeps the
        // struct body bounded, so the two healthy definitions after it survive
        // instead of being eaten by a group that can never close.
        let text = "struct S { int (*f)(void; };\nint b(void){return 2;}\nint c(void){return 3;}";
        assert_eq!(definition_names(text), vec!["b", "c"]);
    }

    #[test]
    fn a_qualified_name_is_measured_whole_including_its_generic_segments() {
        // The measurement is indirect on purpose: `qualification_len` is only
        // useful if the name node ends up spanning what it counted.
        for (text, name) in [
            (
                "int std::thread::exhausted(void) { return 1; }",
                "std::thread::exhausted",
            ),
            (
                "u64 core::ptr::const_ptr::<impl *const T>::as_ref(u64 a) { return a; }",
                "core::ptr::const_ptr::<impl *const T>::as_ref",
            ),
            (
                "u64 core::slice::<impl [T]>::iter_mut(u64 a) { return a; }",
                "core::slice::<impl [T]>::iter_mut",
            ),
            (
                "int wrap::<Vec<Vec<T>>>::run(int a) { return a; }",
                "wrap::<Vec<Vec<T>>>::run",
            ),
        ] {
            assert_eq!(definition_names(text), vec![name.to_string()], "{text}");
        }
    }

    /// Every `DeclName`'s text, which is what a qualification either does or
    /// does not end up inside.
    fn declared_names(text: &str) -> Vec<String> {
        let tree = parse(text).into_parts().0;
        let arena = tree.arena();
        let spans = tree.token_spans(text);
        arena
            .preorder_roots()
            .filter(|n| {
                arena.tag(*n) == Some(crate::csource::parse::tag::NodeTag::DeclName.as_u16())
            })
            .filter_map(|n| arena.span(n, &spans))
            .map(|s| text[s.range()].to_string())
            .collect()
    }

    #[test]
    fn an_unclosed_angle_bracket_is_a_comparison_and_not_a_name() {
        // `<` is an operator far more often than a generic argument list, so a
        // segment that does not close is rejected rather than swallowed. The
        // name is the part that was complete, and the file keeps its shape.
        let text = "int f(void){ int a=1,b=2,c=3; if (a < b) return c; return 0; }";
        assert_eq!(definition_names(text), vec!["f"]);
        assert!(errors(text).is_empty(), "{:?}", errors(text));
        // Two ways a `::<` fails to close, both of which must leave the name at
        // `ns`. This is asserted on the `DeclName` text and not on the
        // recovered definitions, because both readings lose the definition ---
        // only the *span* says whether 64 tokens of garbage were taken into the
        // name, and a test that cannot see that catches no mutation of the
        // bound.
        let long_run = vec!["zz"; 70].join(" ");
        let overflowing = format!("int ns::<{long_run}> f(void) {{ return 1; }}");
        assert_eq!(declared_names(&overflowing), vec!["ns".to_string()]);
        let braced = "int ns::<a b { return 1; }";
        assert_eq!(declared_names(braced), vec!["ns".to_string()]);
        // ...and a `::<...>` that *does* close is taken whole, so the assertion
        // above is about the bound and not about the feature being off.
        assert_eq!(
            declared_names("int ns::<impl T>::run(void) { return 1; }"),
            vec!["ns::<impl T>::run".to_string()]
        );
    }

    #[test]
    fn a_balanced_group_is_consumed_whole_and_an_unbalanced_one_terminates() {
        assert!(errors("int f(void) __attribute__((noinline, aligned(16)));").is_empty());
        assert!(errors("void f(void){ __asm__ volatile (\"\" ::: \"memory\"); }").is_empty());
        // Unbalanced: a diagnostic and a return, never a hang.
        let _ = parse("int f(void) __attribute__((");
    }
}
