//! Line, token and parameter counts.
//!
//! # What a "code line" is here, and why it is defined that way
//!
//! The lexer does not store trivia --- whitespace and comments never become
//! tokens (`crate::csource::lex`) --- so there is no comment token to count.
//! Rather than add a second scanner that could disagree with the first, a
//! **code line** is defined as *a line on which at least one token begins*.
//! That is computed from the token buffer the parser actually consumed, so it
//! cannot drift from what was parsed.
//!
//! The complement splits into two, and both are reported rather than being
//! folded into one figure called "comments":
//!
//! * **blank lines** --- no non-whitespace bytes at all;
//! * **other lines** --- non-blank, but no token begins on them. Overwhelmingly
//!   comments, and also the continuation lines of a token that spans several
//!   lines. Calling that bucket `comment_lines` would be a claim the token
//!   buffer cannot support, so it is not called that.

use crate::syntax::ids::{Span, TokenId};
use crate::syntax::token::Tokens;

/// Byte offsets at which each line of a file starts, ascending, always
/// beginning with `0`.
///
/// Built once per file and shared by every function measured in it: the
/// alternative, a scan per span, is quadratic on a file with many functions.
#[derive(Debug, Clone)]
pub struct LineIndex {
    starts: Vec<u32>,
    len: u32,
}

impl LineIndex {
    /// Index `text`.
    ///
    /// Only `\n` starts a line, matching the substrate's own line handling; a
    /// lone `\r` does not.
    pub fn new(text: &str) -> Self {
        let mut starts = vec![0u32];
        for (offset, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                starts.push((offset as u32).saturating_add(1));
            }
        }
        Self {
            starts,
            len: text.len() as u32,
        }
    }

    /// The 1-based line `offset` falls on, clamped into the file.
    pub fn line(&self, offset: u32) -> u32 {
        let offset = offset.min(self.len);
        // `partition_point` is a binary search with no panic path, unlike
        // `binary_search`'s `unwrap` on the Err arm.
        self.starts.partition_point(|&start| start <= offset) as u32
    }

    /// How many lines the file has: one more than its `\n` count.
    pub fn line_count(&self) -> u32 {
        self.starts.len() as u32
    }
}

/// Line and token counts over one span.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SizeMetrics {
    /// 1-based first line of the span.
    pub first_line: u32,
    /// 1-based last line of the span.
    pub last_line: u32,
    /// `last_line - first_line + 1`.
    pub lines: u32,
    /// Lines in the span on which at least one token begins.
    pub code_lines: u32,
    /// Tokens in the span.
    pub tokens: u32,
    /// Bytes in the span.
    pub bytes: u32,
}

/// Measure the half-open token range `[first, end)`, which must cover `span`.
pub fn measure(tokens: &Tokens, index: &LineIndex, span: Span, first: u32, end: u32) -> SizeMetrics {
    let first_line = index.line(span.lo);
    let last_line = index.line(span.hi.saturating_sub(1).max(span.lo));

    let limit = end.min(tokens.len() as u32);
    let mut code_lines = 0u32;
    let mut previous = 0u32;
    let mut count = 0u32;
    for id in first..limit {
        count += 1;
        let line = index.line(tokens.start(TokenId::new(id)));
        // Token starts ascend, so a change of line is a new code line and no
        // set is needed to deduplicate them.
        if line != previous {
            code_lines += 1;
            previous = line;
        }
    }

    SizeMetrics {
        first_line,
        last_line,
        lines: last_line.saturating_sub(first_line).saturating_add(1),
        code_lines,
        tokens: count,
        bytes: span.hi.saturating_sub(span.lo),
    }
}

/// Whole-file line counts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileLines {
    /// Physical lines.
    pub lines: u32,
    /// Lines on which a token begins.
    pub code_lines: u32,
    /// Lines with no non-whitespace byte.
    pub blank_lines: u32,
    /// Non-blank lines with no token on them: comments, and continuation lines
    /// of multi-line tokens. See the module docs for why this is not called
    /// `comment_lines`.
    pub other_lines: u32,
}

/// Count the file's lines by category.
pub fn file_lines(text: &str, tokens: &Tokens, index: &LineIndex) -> FileLines {
    let total = index.line_count();
    let mut has_token = vec![false; total as usize + 1];
    for id in 0..tokens.len() as u32 {
        let line = index.line(tokens.start(TokenId::new(id)));
        if let Some(slot) = has_token.get_mut(line as usize) {
            *slot = true;
        }
    }

    let mut blank = 0u32;
    let mut code = 0u32;
    let mut other = 0u32;
    for (zero_based, line) in text.split('\n').enumerate() {
        let number = zero_based as u32 + 1;
        if has_token.get(number as usize).copied().unwrap_or(false) {
            code += 1;
        } else if line.trim().is_empty() {
            blank += 1;
        } else {
            other += 1;
        }
    }

    FileLines {
        lines: total,
        code_lines: code,
        blank_lines: blank,
        other_lines: other,
    }
}

/// How many parameters the parameter list covering the token range `extent`
/// declares.
///
/// The parser stores a parameter list as a balanced token run rather than a
/// structured child list (`crate::csource::parse::decl`), so this counts
/// top-level commas inside the outer parentheses and adds one. Two spellings
/// of "none" are recognised: an empty list, and the single token `void`. A
/// trailing `...` is *not* counted as a parameter, matching the usual
/// convention that a variadic function has the parameters it names.
///
/// A K&R-style definition, whose parentheses hold a bare identifier list, is
/// therefore counted by that list --- which is the number of parameters it has.
pub fn parameters(tokens: &Tokens, extent: Option<(u32, u32)>) -> u32 {
    let Some((first, end)) = extent else {
        return 0;
    };
    let limit = end.min(tokens.len() as u32);

    use crate::csource::lex::kind::TokenKind;
    let mut depth = 0i32;
    let mut commas = 0u32;
    let mut significant = 0u32;
    let mut only_void = true;
    for id in first..limit {
        let Some(kind) = TokenKind::from_u16(tokens.kind(TokenId::new(id))) else {
            continue;
        };
        match kind {
            TokenKind::LParen | TokenKind::LBracket => depth += 1,
            TokenKind::RParen | TokenKind::RBracket => depth -= 1,
            TokenKind::Comma if depth == 1 => commas += 1,
            _ => {}
        }
        if depth >= 1 && !matches!(kind, TokenKind::LParen | TokenKind::RParen) {
            significant += 1;
            if kind != TokenKind::KwVoid {
                only_void = false;
            }
        }
    }

    if significant == 0 || (only_void && significant == 1) {
        return 0;
    }
    commas.saturating_add(1)
}
