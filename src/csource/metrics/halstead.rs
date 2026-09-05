//! Halstead's token measures over the C token buffer.
//!
//! # The classification, stated rather than assumed
//!
//! Halstead is only reproducible if the operator/operand split is written
//! down, because implementations differ and the resulting numbers are not
//! comparable across them. This one is:
//!
//! * **Operands** are [`TokenKind::Identifier`] and the four literal kinds.
//!   Distinctness is by **lexeme**, so `i` used twice is one distinct operand
//!   and `1` and `1u` are two. The lexeme, not
//!   [`crate::syntax::token::Tokens::text`], which carries the trivia up to
//!   the next token and would make `a ` and `a;` two operands.
//! * **Operators** are keywords and punctuators. Distinctness is by **kind**,
//!   so `+` everywhere in the function is one distinct operator, and the
//!   keyword aliases the lexer folds together (`__const` and `const`) are one
//!   operator because they are one kind.
//! * **The closing half of a matched pair does not count.** `)`, `]` and `}`
//!   are skipped, so `f(x)` costs one operator for the call parentheses rather
//!   than two. This is the common convention and the one that makes `n1` a
//!   count of *operations* rather than of glyphs.
//! * **Lexer artifacts do not count at all.** [`TokenKind::Unknown`] is a byte
//!   the scanner could not classify and [`TokenKind::RegisterAnnotation`] is a
//!   decompiler's inline register note; neither is program text, and letting
//!   either into `n1` would make a metric of the input's noise.
//!
//! Every derived figure below is a pure function of `n1`, `n2`, `N1`, `N2`,
//! and all four are reported, so a caller who wants a different convention's
//! derived value can compute it instead of arguing with this one.

use std::collections::BTreeSet;

use crate::csource::lex::kind::TokenKind;
use crate::csource::lex::lexeme;
use crate::syntax::ids::TokenId;
use crate::syntax::token::Tokens;

/// Halstead's four counts and the three standard figures derived from them.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Halstead {
    /// `n1` --- distinct operators.
    pub distinct_operators: u32,
    /// `n2` --- distinct operands.
    pub distinct_operands: u32,
    /// `N1` --- total operator occurrences.
    pub total_operators: u32,
    /// `N2` --- total operand occurrences.
    pub total_operands: u32,
}

impl Halstead {
    /// `n = n1 + n2`.
    pub fn vocabulary(&self) -> u32 {
        self.distinct_operators
            .saturating_add(self.distinct_operands)
    }

    /// `N = N1 + N2`.
    pub fn length(&self) -> u32 {
        self.total_operators.saturating_add(self.total_operands)
    }

    /// `V = N * log2(n)`, and `0.0` for an empty vocabulary.
    ///
    /// Zero rather than an abstention: a function with no tokens genuinely has
    /// no volume, which is different from a volume we declined to compute.
    pub fn volume(&self) -> f64 {
        let vocabulary = self.vocabulary();
        if vocabulary == 0 {
            return 0.0;
        }
        f64::from(self.length()) * f64::from(vocabulary).log2()
    }

    /// `D = (n1 / 2) * (N2 / n2)`, and `0.0` when there are no operands.
    pub fn difficulty(&self) -> f64 {
        if self.distinct_operands == 0 {
            return 0.0;
        }
        (f64::from(self.distinct_operators) / 2.0)
            * (f64::from(self.total_operands) / f64::from(self.distinct_operands))
    }

    /// `E = D * V`.
    pub fn effort(&self) -> f64 {
        self.difficulty() * self.volume()
    }
}

/// Whether a kind contributes an operand occurrence.
fn is_operand(kind: TokenKind) -> bool {
    kind == TokenKind::Identifier || kind.is_literal()
}

/// Whether a kind contributes an operator occurrence, per the module docs:
/// keywords and punctuators, minus the closing half of each matched pair.
fn is_operator(kind: TokenKind) -> bool {
    if matches!(
        kind,
        TokenKind::RParen | TokenKind::RBracket | TokenKind::RBrace
    ) {
        return false;
    }
    kind.is_keyword() || kind.is_punctuator()
}

/// Measure the half-open token range `[first, end)` of `tokens` against `text`.
///
/// Total on any range (`REQ-SYN-2`): indices past the end of the buffer are
/// skipped rather than panicked on, so a caller holding a stale extent gets a
/// smaller measurement instead of an abort.
pub fn measure(tokens: &Tokens, text: &str, first: u32, end: u32) -> Halstead {
    let mut operator_kinds: BTreeSet<u16> = BTreeSet::new();
    let mut operand_texts: BTreeSet<&str> = BTreeSet::new();
    let mut total_operators = 0u32;
    let mut total_operands = 0u32;

    let limit = end.min(tokens.len() as u32);
    for index in first..limit {
        let id = TokenId::new(index);
        let raw = tokens.kind(id);
        let Some(kind) = TokenKind::from_u16(raw) else {
            continue;
        };
        if is_operand(kind) {
            total_operands = total_operands.saturating_add(1);
            // `Tokens::text` carries the trailing trivia up to the next token,
            // so `a ` and `a;` would be two distinct operands. `lexeme` is the
            // front end's own trimmed accessor and the one this must use.
            operand_texts.insert(lexeme(tokens, id, text));
        } else if is_operator(kind) {
            total_operators = total_operators.saturating_add(1);
            operator_kinds.insert(raw);
        }
    }

    Halstead {
        distinct_operators: operator_kinds.len() as u32,
        distinct_operands: operand_texts.len() as u32,
        total_operators,
        total_operands,
    }
}
