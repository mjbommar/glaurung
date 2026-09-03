//! `F-4` --- the C token kind space, and the keyword table that fills it.
//!
//! Spec: `docs/design/static-c-analysis/roadmap.md` stage S1, and
//! `docs/design/static-c-analysis/requirements.md` `REQ-IN-3` (the GNU C
//! surface) and `REQ-IN-4` (an illegal token is still a token).
//!
//! # Why an enum and not a `u16` constant block
//!
//! [`crate::syntax::token::Tokens`] stores an opaque `u16` tag per token and
//! never interprets it (`REQ-SYN-1`), so the C front end owns the whole
//! numbering. A `#[repr(u16)]` enum numbered densely from zero is the cheapest
//! way to stay inside the one value the substrate reserves: `Tokens::EOF` is
//! `u16::MAX` and `Tokens::MAX_KIND` is one below it, and a hundred-odd kinds
//! cannot reach either. `every_kind_fits_the_substrates_tag_space` asserts that
//! rather than assuming it.
//!
//! # Why several spellings share one kind
//!
//! `restrict`, `__restrict` and `__restrict__` mean the same thing to a parser,
//! and so do `asm`/`__asm__`/`__asm` and `inline`/`__inline`/`__inline__`. GNU
//! spells its keywords three ways so that a program can use the reserved-name
//! form in a header compiled as ISO C; the *grammar* sees one construct. Each
//! alias family therefore collapses to a single [`TokenKind`], and
//! [`TokenKind::name`] reports one canonical spelling. Nothing is lost: the
//! token's byte span still addresses the original spelling in the source text
//! (`REQ-GEN-2`), which is where a renderer or a diagnostic reads it from.
//!
//! # Which keywords are deliberately absent
//!
//! C23's `bool`, `true`, `false`, `nullptr`, `constexpr`, `static_assert`,
//! `alignas`, `alignof` and `thread_local` are **not** keywords here. Both
//! input dialects (`REQ-IN-1`) are C17-or-earlier in practice, and in that
//! dialect `typedef int bool;` and `enum { true = 1 };` are ordinary
//! declarations that a C23 keyword set would turn into syntax errors. Adding
//! them later is a table edit plus a dialect switch; wrongly rejecting real
//! input now is a coverage loss with no upside.

/// Declares the [`TokenKind`] enum together with the three things every entry
/// needs and no entry may be missing: a dense discriminant, a place in
/// [`TokenKind::ALL`], and a canonical spelling for [`TokenKind::name`].
///
/// One table rather than four parallel ones. The alternative --- an enum, a
/// separate `ALL` array, a separate `name` match --- is three lists that must
/// agree, and the failure when they do not is a silently mis-numbered kind
/// rather than a compile error.
macro_rules! token_kinds {
    ($( $variant:ident => $spelling:literal , )*) => {
        /// One C token's classification: the `u16` tag the substrate stores.
        ///
        /// Numbered densely from zero in the order written below --- literals
        /// and the identifier first, then keywords, then punctuators --- so
        /// that the group predicates ([`TokenKind::is_keyword`] and friends)
        /// are range checks rather than hundred-arm matches.
        #[repr(u16)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum TokenKind {
            $(
                #[doc = concat!("The `", $spelling, "` token kind.")]
                $variant,
            )*
        }

        impl TokenKind {
            /// Every kind, in discriminant order, which is what makes
            /// [`TokenKind::from_u16`] an array index instead of a match.
            pub const ALL: &'static [TokenKind] = &[ $( TokenKind::$variant, )* ];

            /// The canonical spelling of this kind, or a short description for
            /// the kinds that have no fixed spelling.
            ///
            /// For an alias family this is one member of it, not the spelling
            /// the source used; read the token's span for that.
            pub const fn name(self) -> &'static str {
                match self {
                    $( TokenKind::$variant => $spelling, )*
                }
            }
        }
    };
}

token_kinds! {
    // --- kinds with no fixed spelling ---------------------------------------
    Identifier => "identifier",
    IntLiteral => "integer literal",
    FloatLiteral => "floating literal",
    CharLiteral => "character literal",
    StringLiteral => "string literal",
    Unknown => "unknown token",

    // --- C11 keywords --------------------------------------------------------
    KwAlignas => "_Alignas",
    KwAlignof => "_Alignof",
    KwAtomic => "_Atomic",
    KwAuto => "auto",
    KwBool => "_Bool",
    KwBreak => "break",
    KwCase => "case",
    KwChar => "char",
    KwComplex => "_Complex",
    KwConst => "const",
    KwContinue => "continue",
    KwDefault => "default",
    KwDo => "do",
    KwDouble => "double",
    KwElse => "else",
    KwEnum => "enum",
    KwExtern => "extern",
    KwFloat => "float",
    KwFor => "for",
    KwGeneric => "_Generic",
    KwGoto => "goto",
    KwIf => "if",
    KwImaginary => "_Imaginary",
    KwInline => "inline",
    KwInt => "int",
    KwLong => "long",
    KwNoreturn => "_Noreturn",
    KwRegister => "register",
    KwRestrict => "restrict",
    KwReturn => "return",
    KwShort => "short",
    KwSigned => "signed",
    KwSizeof => "sizeof",
    KwStatic => "static",
    KwStaticAssert => "_Static_assert",
    KwStruct => "struct",
    KwSwitch => "switch",
    KwThreadLocal => "_Thread_local",
    KwTypedef => "typedef",
    KwUnion => "union",
    KwUnsigned => "unsigned",
    KwVoid => "void",
    KwVolatile => "volatile",
    KwWhile => "while",

    // --- GNU extensions that survive into preprocessed output ---------------
    KwAsm => "__asm__",
    KwAttribute => "__attribute__",
    KwBuiltinChooseExpr => "__builtin_choose_expr",
    KwBuiltinOffsetof => "__builtin_offsetof",
    KwBuiltinTypesCompatibleP => "__builtin_types_compatible_p",
    KwBuiltinVaArg => "__builtin_va_arg",
    KwBuiltinVaList => "__builtin_va_list",
    KwExtension => "__extension__",
    KwImag => "__imag__",
    KwInt128 => "__int128",
    KwLabel => "__label__",
    KwReal => "__real__",
    KwTypeof => "__typeof__",

    // --- punctuators ---------------------------------------------------------
    LBracket => "[",
    RBracket => "]",
    LParen => "(",
    RParen => ")",
    LBrace => "{",
    RBrace => "}",
    Dot => ".",
    Arrow => "->",
    PlusPlus => "++",
    MinusMinus => "--",
    Amp => "&",
    Star => "*",
    Plus => "+",
    Minus => "-",
    Tilde => "~",
    Bang => "!",
    Slash => "/",
    Percent => "%",
    Shl => "<<",
    Shr => ">>",
    Lt => "<",
    Gt => ">",
    Le => "<=",
    Ge => ">=",
    EqEq => "==",
    Ne => "!=",
    Caret => "^",
    Pipe => "|",
    AmpAmp => "&&",
    PipePipe => "||",
    Question => "?",
    Colon => ":",
    Semi => ";",
    Ellipsis => "...",
    Eq => "=",
    StarEq => "*=",
    SlashEq => "/=",
    PercentEq => "%=",
    PlusEq => "+=",
    MinusEq => "-=",
    ShlEq => "<<=",
    ShrEq => ">>=",
    AmpEq => "&=",
    CaretEq => "^=",
    PipeEq => "|=",
    Comma => ",",
    Hash => "#",
    HashHash => "##",
}

impl TokenKind {
    /// This kind as the `u16` tag [`crate::syntax::token::TokensBuilder::push`]
    /// stores.
    ///
    /// A plain `as` cast, which is exactly why the enum is `#[repr(u16)]`: the
    /// discriminant is the wire format rather than something derived from it.
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// The kind a `u16` tag denotes, or `None` when the tag names no kind.
    ///
    /// `None` is the honest answer for the sentinel tag
    /// [`crate::syntax::token::Tokens::EOF`], and for any tag that a different
    /// front end or a corrupt buffer produced; a caller that wants a total
    /// function maps it to [`TokenKind::Unknown`].
    pub fn from_u16(tag: u16) -> Option<TokenKind> {
        Self::ALL.get(tag as usize).copied()
    }

    /// Whether this kind is a C or GNU keyword.
    ///
    /// A range check over the discriminant, valid because the table above
    /// writes every keyword contiguously; `the_group_predicates_agree_with_the_tables`
    /// checks the layout the range depends on.
    pub const fn is_keyword(self) -> bool {
        let tag = self.as_u16();
        TokenKind::KwAlignas.as_u16() <= tag && tag <= TokenKind::KwTypeof.as_u16()
    }

    /// Whether this kind is a punctuator --- an operator, a bracket or a
    /// separator.
    pub const fn is_punctuator(self) -> bool {
        let tag = self.as_u16();
        TokenKind::LBracket.as_u16() <= tag && tag <= TokenKind::HashHash.as_u16()
    }

    /// Whether this kind is a literal: an integer, a float, a character or a
    /// string.
    ///
    /// [`TokenKind::Identifier`] is deliberately outside the set even though it
    /// also has no fixed spelling.
    pub const fn is_literal(self) -> bool {
        matches!(
            self,
            TokenKind::IntLiteral
                | TokenKind::FloatLiteral
                | TokenKind::CharLiteral
                | TokenKind::StringLiteral
        )
    }
}

/// The keyword `name` spells, or `None` when it is an ordinary identifier.
///
/// **A `match` on the string, not a `HashMap` and not a sorted table.** The
/// three candidates were weighed as follows. A `HashMap` built at runtime pays
/// a hash of every identifier in the file plus a one-off table build, and needs
/// a `OnceLock` to avoid rebuilding it per call. A sorted static array with
/// `binary_search` is allocation-free but relies on an ordering no compiler
/// checks, so a misplaced row silently stops matching one keyword --- the
/// failure is a keyword lexing as an identifier, which a parser reports far
/// from its cause. A `match` on `&str` costs nothing at startup, cannot go
/// stale, and is compiled into a switch on length followed by a short chain of
/// comparisons, which is the shape the sorted table was trying to approximate
/// by hand.
///
/// Alias families collapse here rather than in the enum: see the module docs.
pub fn keyword_kind(name: &str) -> Option<TokenKind> {
    let kind = match name {
        // C11.
        "_Alignas" => TokenKind::KwAlignas,
        "_Alignof" | "__alignof" | "__alignof__" => TokenKind::KwAlignof,
        "_Atomic" => TokenKind::KwAtomic,
        "auto" => TokenKind::KwAuto,
        "_Bool" => TokenKind::KwBool,
        "break" => TokenKind::KwBreak,
        "case" => TokenKind::KwCase,
        "char" => TokenKind::KwChar,
        "_Complex" | "__complex" | "__complex__" => TokenKind::KwComplex,
        "const" | "__const" | "__const__" => TokenKind::KwConst,
        "continue" => TokenKind::KwContinue,
        "default" => TokenKind::KwDefault,
        "do" => TokenKind::KwDo,
        "double" => TokenKind::KwDouble,
        "else" => TokenKind::KwElse,
        "enum" => TokenKind::KwEnum,
        "extern" => TokenKind::KwExtern,
        "float" => TokenKind::KwFloat,
        "for" => TokenKind::KwFor,
        "_Generic" => TokenKind::KwGeneric,
        "goto" => TokenKind::KwGoto,
        "if" => TokenKind::KwIf,
        "_Imaginary" => TokenKind::KwImaginary,
        "inline" | "__inline" | "__inline__" => TokenKind::KwInline,
        "int" => TokenKind::KwInt,
        "long" => TokenKind::KwLong,
        "_Noreturn" => TokenKind::KwNoreturn,
        "register" => TokenKind::KwRegister,
        "restrict" | "__restrict" | "__restrict__" => TokenKind::KwRestrict,
        "return" => TokenKind::KwReturn,
        "short" => TokenKind::KwShort,
        "signed" | "__signed" | "__signed__" => TokenKind::KwSigned,
        "sizeof" => TokenKind::KwSizeof,
        "static" => TokenKind::KwStatic,
        "_Static_assert" => TokenKind::KwStaticAssert,
        "struct" => TokenKind::KwStruct,
        "switch" => TokenKind::KwSwitch,
        "_Thread_local" | "__thread" => TokenKind::KwThreadLocal,
        "typedef" => TokenKind::KwTypedef,
        "union" => TokenKind::KwUnion,
        "unsigned" => TokenKind::KwUnsigned,
        "void" => TokenKind::KwVoid,
        "volatile" | "__volatile" | "__volatile__" => TokenKind::KwVolatile,
        "while" => TokenKind::KwWhile,

        // GNU.
        "asm" | "__asm" | "__asm__" => TokenKind::KwAsm,
        "__attribute" | "__attribute__" => TokenKind::KwAttribute,
        "__builtin_choose_expr" => TokenKind::KwBuiltinChooseExpr,
        "__builtin_offsetof" => TokenKind::KwBuiltinOffsetof,
        "__builtin_types_compatible_p" => TokenKind::KwBuiltinTypesCompatibleP,
        "__builtin_va_arg" => TokenKind::KwBuiltinVaArg,
        "__builtin_va_list" => TokenKind::KwBuiltinVaList,
        "__extension__" => TokenKind::KwExtension,
        "__imag" | "__imag__" => TokenKind::KwImag,
        "__int128" => TokenKind::KwInt128,
        "__label__" => TokenKind::KwLabel,
        "__real" | "__real__" => TokenKind::KwReal,
        "typeof" | "__typeof" | "__typeof__" => TokenKind::KwTypeof,

        _ => return None,
    };
    Some(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::token::Tokens;

    /// Every spelling `keyword_kind` accepts, so the tests below can sweep the
    /// table without restating it.
    const SPELLINGS: &[&str] = &[
        "_Alignas",
        "_Alignof",
        "__alignof",
        "__alignof__",
        "_Atomic",
        "auto",
        "_Bool",
        "break",
        "case",
        "char",
        "_Complex",
        "__complex",
        "__complex__",
        "const",
        "__const",
        "__const__",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "_Generic",
        "goto",
        "if",
        "_Imaginary",
        "inline",
        "__inline",
        "__inline__",
        "int",
        "long",
        "_Noreturn",
        "register",
        "restrict",
        "__restrict",
        "__restrict__",
        "return",
        "short",
        "signed",
        "__signed",
        "__signed__",
        "sizeof",
        "static",
        "_Static_assert",
        "struct",
        "switch",
        "_Thread_local",
        "__thread",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "__volatile",
        "__volatile__",
        "while",
        "asm",
        "__asm",
        "__asm__",
        "__attribute",
        "__attribute__",
        "__builtin_choose_expr",
        "__builtin_offsetof",
        "__builtin_types_compatible_p",
        "__builtin_va_arg",
        "__builtin_va_list",
        "__extension__",
        "__imag",
        "__imag__",
        "__int128",
        "__label__",
        "__real",
        "__real__",
        "typeof",
        "__typeof",
        "__typeof__",
    ];

    #[test]
    fn every_kind_fits_the_substrates_tag_space() {
        let largest = TokenKind::ALL
            .iter()
            .map(|kind| kind.as_u16())
            .max()
            .expect("the table is not empty");
        println!("TokenKind::ALL.len() = {}", TokenKind::ALL.len());
        println!("largest discriminant = {largest}");
        println!("Tokens::MAX_KIND     = {}", Tokens::MAX_KIND);
        assert!(
            largest <= Tokens::MAX_KIND,
            "kind {largest} would be clamped by TokensBuilder::push"
        );
        assert_ne!(
            largest,
            Tokens::EOF,
            "no kind may collide with the sentinel"
        );
    }

    #[test]
    fn discriminants_are_dense_and_round_trip_through_u16() {
        for (index, kind) in TokenKind::ALL.iter().enumerate() {
            assert_eq!(
                kind.as_u16(),
                index as u16,
                "{kind:?} is not at its own index"
            );
            assert_eq!(TokenKind::from_u16(index as u16), Some(*kind));
        }
        let past_the_end = TokenKind::ALL.len() as u16;
        assert_eq!(TokenKind::from_u16(past_the_end), None);
        assert_eq!(TokenKind::from_u16(Tokens::EOF), None);
    }

    #[test]
    fn the_group_predicates_agree_with_the_tables() {
        // The range checks assume keywords are contiguous and punctuators are
        // contiguous. Anything `keyword_kind` returns must land in the keyword
        // range, and no kind may belong to two groups.
        for spelling in SPELLINGS {
            let kind = keyword_kind(spelling).expect("a spelling in the table");
            assert!(kind.is_keyword(), "{spelling} -> {kind:?} is not a keyword");
            assert!(!kind.is_punctuator());
            assert!(!kind.is_literal());
        }
        let punctuators = TokenKind::ALL.iter().filter(|k| k.is_punctuator()).count();
        let keywords = TokenKind::ALL.iter().filter(|k| k.is_keyword()).count();
        println!("keywords = {keywords}, punctuators = {punctuators}");
        assert_eq!(punctuators, 48);
        assert_eq!(keywords, 57);
        for kind in TokenKind::ALL {
            let groups = [kind.is_keyword(), kind.is_punctuator(), kind.is_literal()]
                .iter()
                .filter(|held| **held)
                .count();
            assert!(groups <= 1, "{kind:?} belongs to two groups");
        }
    }

    #[test]
    fn an_alias_family_collapses_to_one_kind() {
        for family in [
            ["restrict", "__restrict", "__restrict__"],
            ["inline", "__inline", "__inline__"],
            ["asm", "__asm", "__asm__"],
            ["typeof", "__typeof", "__typeof__"],
            ["volatile", "__volatile", "__volatile__"],
        ] {
            let kinds: Vec<_> = family.iter().map(|s| keyword_kind(s)).collect();
            assert_eq!(kinds[0], kinds[1], "{family:?} disagreed");
            assert_eq!(kinds[1], kinds[2], "{family:?} disagreed");
            assert!(kinds[0].is_some());
        }
        assert_eq!(keyword_kind("__attribute"), keyword_kind("__attribute__"));
        assert_eq!(keyword_kind("__thread"), keyword_kind("_Thread_local"));
    }

    #[test]
    fn an_ordinary_identifier_is_not_a_keyword() {
        for name in [
            "x",
            "restricted",
            "_restrict",
            "Return",
            "undefined4",
            "__usercall",
            "bool",
            "true",
            "false",
            "nullptr",
            "static_assert",
            "thread_local",
            "",
        ] {
            assert_eq!(keyword_kind(name), None, "{name:?} must stay an identifier");
        }
    }

    #[test]
    fn every_name_is_the_spelling_the_table_gives_it() {
        assert_eq!(TokenKind::KwRestrict.name(), "restrict");
        assert_eq!(TokenKind::ShlEq.name(), "<<=");
        assert_eq!(TokenKind::Identifier.name(), "identifier");
        // Every keyword's canonical spelling must itself be a keyword, and map
        // back to the same kind -- the check that catches a typo in the table.
        for kind in TokenKind::ALL.iter().filter(|k| k.is_keyword()) {
            assert_eq!(
                keyword_kind(kind.name()),
                Some(*kind),
                "{kind:?}'s canonical spelling does not round-trip"
            );
        }
    }
}
