//! `F-4` --- the C lexer: text in, [`Tokens`] out, never a failure.
//!
//! Spec: `docs/design/static-c-analysis/roadmap.md` stage S1;
//! `docs/design/static-c-analysis/requirements.md` `REQ-IN-1` (two dialects,
//! one lexer), `REQ-IN-3` (the GNU surface), `REQ-IN-4` (ill-formed input must
//! not abort the file), `REQ-GEN-2` (spans survive) and `REQ-GEN-4` (explicit
//! stacks). The kind space is [`kind`]; the shared scanners this drives are
//! [`crate::syntax::scan`].
//!
//! # What this layer is, and what it deliberately is not
//!
//! [`tokenize`] classifies bytes and nothing else. It resolves no `#include`,
//! expands no macro and evaluates no `#if` (`REQ-IN-2`): both accepted dialects
//! arrive already preprocessed, and normalization
//! ([`crate::csource::normalize`]) has already run over the text. A `#` that
//! survives to here is a token like any other.
//!
//! It also does not decide what an identifier *means*. `undefined4`,
//! `__usercall` and `GLIBC_2` are identifiers; `::` is two colons; `@` is
//! [`kind::TokenKind::Unknown`] with a diagnostic. Every one of those is a
//! token, because `REQ-IN-4` says an illegal token must reach the parser as
//! something it can skip rather than as a reason to abandon the file.
//!
//! # Trivia is skipped, and the extent trap that follows from it
//!
//! Whitespace and comments never become tokens
//! (`docs/design/source-front-ends/substrate.md` §2.1). The buffer stores only
//! a start offset per token, so a token's *extent* --- `starts[i + 1] -
//! starts[i]` --- runs to the **next token** and therefore swallows the trivia
//! in between: for `int x;` the extents are `["int ", "x", ";"]`, and for
//! `x /* c */ ;` the first extent is `"x /* c */ "`. Interning
//! [`Tokens::text`] straight into a symbol table interns the trailing spaces
//! and the comment.
//!
//! [`lexeme`] is the fix, and it is the reason this module exposes a re-scan at
//! all: given a token start it re-runs the classifier and returns exactly the
//! bytes the token occupies. That is the same resolution Zig's tokenizer
//! reaches for the identical representation, and it is cheap because it scans
//! one token rather than the file.
//!
//! # Line splices
//!
//! C erases a backslash immediately followed by a newline in translation phase
//! 2, before tokenizing, so `re\`-newline-`turn` is the keyword `return`. gcc's
//! `-E` output normally re-emits whole tokens, but not always, and decompiler
//! output can contain anything --- so the construct is handled rather than
//! assumed away. It is handled **in place**, never by rewriting the text:
//!
//! * between tokens a splice is trivia, skipped like whitespace;
//! * inside an identifier or keyword it is transparent --- the token's extent
//!   covers the splice and the keyword lookup runs on the joined spelling, so
//!   `re\`-newline-`turn` lexes as one [`kind::TokenKind::KwReturn`];
//! * inside a string or character literal it is already handled by
//!   [`crate::syntax::scan::scan_escape`], which reports it as a line
//!   continuation that contributes no character;
//! * inside a `//` comment it continues the comment onto the next line, which
//!   is [`crate::syntax::scan::scan_line_comment`]'s behaviour under
//!   [`crate::syntax::scan::ScanConfig::line_splicing`].
//!
//! The one case left alone is a splice **inside a multi-character punctuator**
//! (`<\`-newline-`<=`), which lexes here as `<` then `<=`. It is recorded as a
//! known divergence rather than fixed: it does not occur in either input
//! dialect, and making the punctuator matcher splice-aware would put a
//! two-byte lookahead behind a variable-length skip in the hottest loop in the
//! lexer. `a_splice_inside_a_punctuator_is_the_documented_divergence` pins the
//! behaviour so the decision stays visible.
//!
//! The alternative design --- delete splices in a pre-pass and lex the result
//! --- was rejected because every offset would then address rewritten text,
//! and `REQ-GEN-2` requires spans into the *original* bytes so a finding can be
//! pointed at a line.
//!
//! # Why nothing here can fail
//!
//! [`tokenize`] returns [`Parsed<Tokens>`] rather than a `Result`
//! (`REQ-SYN-2`), every loop advances by at least one byte so total work is
//! bounded by the input length (`REQ-SYN-4`), and there is no recursion
//! anywhere (`REQ-SYN-3`, `REQ-GEN-4`). The one operation that could panic on
//! adversarial input is slicing a `&str` off a character boundary, so this
//! module never does it: classification reads `text.as_bytes()` and compares
//! ASCII, and the two places that do need text (splice joining and [`lexeme`])
//! go through `str::get`, which answers `None` instead of aborting. Input is
//! `&str` and therefore already valid UTF-8; a caller reading bytes off disk
//! converts with `String::from_utf8_lossy` first, which is what `REQ-NORM-4`
//! already requires of the normalization layer above.

pub mod kind;

use crate::syntax::diag::{Diagnostic, Diagnostics, Parsed};
use crate::syntax::ids::{Span, TokenId};
use crate::syntax::scan::{
    scan_block_comment, scan_char, scan_identifier, scan_line_comment, scan_number, scan_string,
    scan_whitespace, IssueKind, LiteralKind, ScanConfig, ScanIssue,
};
use crate::syntax::token::{Tokens, TokensBuilder};

pub use kind::{keyword_kind, TokenKind};

/// The [`ScanConfig`] this lexer drives the shared scanners with.
///
/// [`ScanConfig::C`] with one change: `$` is accepted in identifiers. That is a
/// GNU extension gcc and clang both enable by default, so it reaches us in real
/// preprocessed sources, and `REQ-IN-3` asks for the GNU surface rather than
/// the ISO one. Non-ASCII identifier bytes stay **off**, matching the advice in
/// `syntax::scan`: recognising them correctly needs Unicode tables the
/// substrate may not depend on, and in preprocessed C a non-ASCII byte outside
/// a literal or a comment is far more often decompiler noise than an
/// identifier. Such a byte becomes [`TokenKind::Unknown`], which the parser
/// skips, rather than silently joining the identifier next to it.
pub const C_SCAN: ScanConfig = ScanConfig {
    dollar_in_identifiers: true,
    ..ScanConfig::C
};

/// Turn C source text into a token buffer, reporting problems alongside it.
///
/// The entry point of the C front end's lexical layer, and a total function:
/// every byte sequence yields a buffer, no input panics, and no input loops
/// (`REQ-SYN-2`, `REQ-SYN-4`). Ill-formed text costs diagnostics and
/// [`TokenKind::Unknown`] tokens, never the file.
///
/// Offsets are byte offsets into `text` exactly as passed. Run
/// [`crate::csource::normalize`] *before* this, not after, or the spans will
/// address text nobody has.
pub fn tokenize(text: &str) -> Parsed<Tokens> {
    let mut diagnostics = Diagnostics::new();
    // Roughly one token per four bytes of C, measured across the fixture
    // corpus; over-reserving a little beats a dozen reallocations per file.
    let mut builder = TokensBuilder::with_capacity(text.len() / 4 + 1);
    let end = text.len();
    let mut at = 0usize;
    while at < end {
        at = skip_trivia(text, at, &mut diagnostics);
        if at >= end {
            break;
        }
        let (kind, len) = lex_one(text, at, &mut diagnostics);
        builder.push(kind.as_u16(), at as u32);
        // `max(1)` is the termination guarantee, not a fallback: every scanner
        // below already reports at least one byte, and this keeps that true if
        // one ever stops doing so.
        at = at.saturating_add(len.max(1));
    }
    Parsed::new(builder.finish(end as u32), diagnostics)
}

/// The lexeme of token `id`: the bytes it actually occupies, with the trailing
/// trivia its extent carries removed.
///
/// The trap named in the module docs, closed. Use this --- not
/// [`Tokens::text`] --- wherever a lexeme's spelling matters: interning an
/// identifier, reading a literal's digits, printing a token in a diagnostic.
/// A mismatched `src`, or an id past the end, yields `""` rather than a panic.
pub fn lexeme<'a>(tokens: &Tokens, id: TokenId, src: &'a str) -> &'a str {
    let at = tokens.start(id) as usize;
    if at >= src.len() {
        return "";
    }
    let len = lexeme_len(src, at);
    src.get(at..at + len).unwrap_or("")
}

/// How many bytes the token starting at `at` occupies.
///
/// `at` must be a token start as reported by a [`Tokens`] buffer built from the
/// same text; anything else re-lexes from the middle of a token and answers
/// about whatever starts there. Returns 0 at or past the end of the input.
pub fn lexeme_len(text: &str, at: usize) -> usize {
    if at >= text.len() {
        return 0;
    }
    // A throwaway sink: `Diagnostics::new` allocates nothing, and re-measuring
    // a token must not re-report its problems.
    let mut discarded = Diagnostics::new();
    lex_one(text, at, &mut discarded).1
}

/// Classify the one token starting at `at`, reporting its kind and byte length.
///
/// `at` must sit on a byte that starts a token: [`skip_trivia`] has already run
/// and the end of input has already been checked. The returned length is always
/// at least 1 for an in-range `at`, which is what bounds [`tokenize`]'s loop.
///
/// Order matters in exactly one place. String and character literals are tried
/// **before** identifiers, because `L"x"`, `u8"x"` and `U'c'` begin with
/// identifier characters and an identifier scan would swallow the prefix and
/// leave a dangling quote.
fn lex_one(text: &str, at: usize, diagnostics: &mut Diagnostics) -> (TokenKind, usize) {
    let bytes = text.as_bytes();
    if at >= bytes.len() {
        return (TokenKind::Unknown, 0);
    }

    if let Some(literal) = scan_string(text, at, C_SCAN) {
        report_literal(&literal.issues, LiteralKind::String, diagnostics);
        return (TokenKind::StringLiteral, literal.len);
    }
    if let Some(literal) = scan_char(text, at, C_SCAN) {
        report_literal(&literal.issues, LiteralKind::Char, diagnostics);
        return (TokenKind::CharLiteral, literal.len);
    }

    let (ident_len, spliced) = scan_spliced_identifier(text, at);
    if ident_len > 0 {
        let kind = if spliced {
            keyword_kind(&despliced(text, at, ident_len))
        } else {
            text.get(at..at + ident_len).and_then(keyword_kind)
        };
        return (kind.unwrap_or(TokenKind::Identifier), ident_len);
    }

    if let Some(number) = scan_number(text, at, C_SCAN) {
        for issue in &number.issues {
            diagnostics.push(issue.to_diagnostic());
        }
        let kind = if number.is_float {
            TokenKind::FloatLiteral
        } else {
            TokenKind::IntLiteral
        };
        return (kind, number.len);
    }

    if let Some((kind, len)) = punctuator(bytes, at) {
        return (kind, len);
    }

    // Nothing legal starts here (`REQ-IN-4`). Consume one whole character, not
    // one byte: a token start off a UTF-8 boundary would make every later
    // `Tokens::text` on it return a truncated slice.
    let width = text
        .get(at..)
        .and_then(|rest| rest.chars().next())
        .map_or(1, char::len_utf8);
    diagnostics.push(stray_byte(text, at, width));
    (TokenKind::Unknown, width.max(1))
}

/// Advance past every run of whitespace, comment and line splice starting at
/// `from`, and report an unterminated block comment on the way.
///
/// Returns the offset of the next token, or the end of the input when only
/// trivia remains. Each arm consumes at least one byte, so the loop terminates
/// on any input including one that ends mid-comment.
fn skip_trivia(text: &str, from: usize, diagnostics: &mut Diagnostics) -> usize {
    let bytes = text.as_bytes();
    let end = bytes.len();
    let mut at = from.min(end);
    while at < end {
        let spaces = scan_whitespace(text, at);
        if spaces > 0 {
            at += spaces;
            continue;
        }
        if let Some(comment) = scan_line_comment(text, at, C_SCAN) {
            at += comment.len.max(1);
            continue;
        }
        if let Some(comment) = scan_block_comment(text, at, C_SCAN) {
            if let Some(issue) = comment.issue {
                diagnostics.push(issue.to_diagnostic());
            }
            at += comment.len.max(1);
            continue;
        }
        if let Some(width) = splice_len(bytes, at) {
            at += width;
            continue;
        }
        break;
    }
    at
}

/// Turn a literal's scan issues into diagnostics, naming the literal's form.
///
/// The shared scanner reports one `UnterminatedLiteral` kind for both forms
/// because it is language-neutral; a C diagnostic should say which, so that
/// case is re-worded here and every other issue keeps the scanner's wording.
fn report_literal(issues: &[ScanIssue], kind: LiteralKind, diagnostics: &mut Diagnostics) {
    for issue in issues {
        if issue.kind == IssueKind::UnterminatedLiteral {
            let message = match kind {
                LiteralKind::String => "unterminated string literal",
                LiteralKind::Char => "unterminated character literal",
            };
            diagnostics.push(Diagnostic::error(issue.span, message));
        } else {
            diagnostics.push(issue.to_diagnostic());
        }
    }
}

/// The diagnostic for a byte that begins no C token, worded the way gcc words
/// it so the message is recognisable.
///
/// `width` is the character's byte length, so the span covers the whole
/// character rather than its lead byte.
fn stray_byte(text: &str, at: usize, width: usize) -> Diagnostic {
    let span = Span::new(at as u32, at.saturating_add(width) as u32);
    match text.get(at..at + width).and_then(|s| s.chars().next()) {
        Some(found) => Diagnostic::error(span, format!("stray {found:?} in program")),
        None => Diagnostic::error(span, "stray byte in program"),
    }
}

/// The length of the backslash-newline splice at `at`, or `None` when one does
/// not start there.
///
/// `\r\n` counts as one newline of two bytes, so a splice in a file with CRLF
/// endings is three bytes and never leaves a stray `\r` behind.
fn splice_len(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&b'\\') {
        return None;
    }
    match bytes.get(at + 1).copied() {
        Some(b'\r') if bytes.get(at + 2) == Some(&b'\n') => Some(3),
        Some(b'\r') | Some(b'\n') => Some(2),
        _ => None,
    }
}

/// Whether `b` may continue a C identifier under [`C_SCAN`].
///
/// The continuation rule spelled out locally because the substrate's copy is
/// private; keeping it here also keeps the splice loop below reading bytes
/// rather than re-entering the scanner one character at a time.
fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

/// The length of the identifier at `at` including any line splices inside it,
/// and whether one was crossed.
///
/// Returns `(0, false)` when no identifier starts there. The flag is what lets
/// [`lex_one`] borrow the spelling in the overwhelmingly common case and
/// allocate a joined copy only for the rare spliced one.
fn scan_spliced_identifier(text: &str, at: usize) -> (usize, bool) {
    let bytes = text.as_bytes();
    let head = scan_identifier(text, at, C_SCAN);
    if head == 0 {
        return (0, false);
    }
    let mut index = at + head;
    let mut spliced = false;
    while let Some(width) = splice_len(bytes, index) {
        let resumed = index + width;
        // A splice only joins the identifier when what follows could continue
        // it. `x\`-newline-`+` is the identifier `x`, a skipped splice and a
        // `+`, which is what the trivia skipper handles.
        if !matches!(bytes.get(resumed), Some(&b) if is_ident_continue(b)) {
            break;
        }
        spliced = true;
        index = resumed;
        while matches!(bytes.get(index), Some(&b) if is_ident_continue(b)) {
            index += 1;
        }
    }
    (index - at, spliced)
}

/// The text of `[at, at + len)` with its line splices removed, which is the
/// spelling C's translation phase 2 would have produced.
///
/// Allocates, and is therefore called only when [`scan_spliced_identifier`]
/// reports that a splice was actually crossed. A range that does not land on
/// character boundaries stops early rather than panicking.
fn despliced(text: &str, at: usize, len: usize) -> String {
    let bytes = text.as_bytes();
    let end = at.saturating_add(len).min(bytes.len());
    let mut joined = String::with_capacity(len);
    let mut index = at;
    while index < end {
        if let Some(width) = splice_len(bytes, index) {
            index += width;
            continue;
        }
        match text.get(index..end).and_then(|rest| rest.chars().next()) {
            Some(found) => {
                joined.push(found);
                index += found.len_utf8();
            }
            None => break,
        }
    }
    joined
}

/// The punctuator at `at` and its length, or `None` when none starts there.
///
/// Longest match, done by hand: three-byte forms are tested before two-byte
/// and two before one, inside a single dispatch on the first byte. A table plus
/// a loop would re-read the same bytes once per candidate length; this reads
/// each byte once, which matters because this is the arm most tokens in real C
/// take after identifiers.
///
/// C's digraphs (`<:`, `:>`, `<%`, `%>`, `%:`) are not recognised. Neither
/// input dialect emits them --- gcc's `-E` writes the primary spelling --- and
/// treating `<:` as `[` would mis-lex the `x<::y` that decompiler output does
/// produce.
fn punctuator(bytes: &[u8], at: usize) -> Option<(TokenKind, usize)> {
    use TokenKind::*;
    let first = *bytes.get(at)?;
    let second = bytes.get(at + 1).copied();
    let third = bytes.get(at + 2).copied();
    let found = match first {
        b'[' => (LBracket, 1),
        b']' => (RBracket, 1),
        b'(' => (LParen, 1),
        b')' => (RParen, 1),
        b'{' => (LBrace, 1),
        b'}' => (RBrace, 1),
        b';' => (Semi, 1),
        b',' => (Comma, 1),
        b'?' => (Question, 1),
        b':' => (Colon, 1),
        b'~' => (Tilde, 1),
        b'.' => match (second, third) {
            (Some(b'.'), Some(b'.')) => (Ellipsis, 3),
            _ => (Dot, 1),
        },
        b'<' => match (second, third) {
            (Some(b'<'), Some(b'=')) => (ShlEq, 3),
            (Some(b'<'), _) => (Shl, 2),
            (Some(b'='), _) => (Le, 2),
            _ => (Lt, 1),
        },
        b'>' => match (second, third) {
            (Some(b'>'), Some(b'=')) => (ShrEq, 3),
            (Some(b'>'), _) => (Shr, 2),
            (Some(b'='), _) => (Ge, 2),
            _ => (Gt, 1),
        },
        b'-' => match second {
            Some(b'>') => (Arrow, 2),
            Some(b'-') => (MinusMinus, 2),
            Some(b'=') => (MinusEq, 2),
            _ => (Minus, 1),
        },
        b'+' => match second {
            Some(b'+') => (PlusPlus, 2),
            Some(b'=') => (PlusEq, 2),
            _ => (Plus, 1),
        },
        b'&' => match second {
            Some(b'&') => (AmpAmp, 2),
            Some(b'=') => (AmpEq, 2),
            _ => (Amp, 1),
        },
        b'|' => match second {
            Some(b'|') => (PipePipe, 2),
            Some(b'=') => (PipeEq, 2),
            _ => (Pipe, 1),
        },
        b'*' => match second {
            Some(b'=') => (StarEq, 2),
            _ => (Star, 1),
        },
        b'/' => match second {
            Some(b'=') => (SlashEq, 2),
            _ => (Slash, 1),
        },
        b'%' => match second {
            Some(b'=') => (PercentEq, 2),
            _ => (Percent, 1),
        },
        b'^' => match second {
            Some(b'=') => (CaretEq, 2),
            _ => (Caret, 1),
        },
        b'!' => match second {
            Some(b'=') => (Ne, 2),
            _ => (Bang, 1),
        },
        b'=' => match second {
            Some(b'=') => (EqEq, 2),
            _ => (Eq, 1),
        },
        b'#' => match second {
            Some(b'#') => (HashHash, 2),
            _ => (Hash, 1),
        },
        _ => return None,
    };
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Lex `text` and return `(kind, lexeme)` for every token, which is what
    /// almost every assertion below wants to look at.
    fn lexed(text: &str) -> (Vec<(TokenKind, String)>, Vec<String>) {
        let parsed = tokenize(text);
        let tokens = parsed.value();
        let mut out = Vec::new();
        for index in 0..tokens.len() {
            let id = TokenId::new(index as u32);
            let kind = TokenKind::from_u16(tokens.kind(id)).expect("a kind this lexer emitted");
            out.push((kind, lexeme(tokens, id, text).to_string()));
        }
        let messages = parsed
            .diagnostics()
            .iter()
            .map(|d| d.render(text))
            .collect();
        (out, messages)
    }

    /// Just the kinds, for the shape assertions.
    fn kinds(text: &str) -> Vec<TokenKind> {
        lexed(text).0.into_iter().map(|(kind, _)| kind).collect()
    }

    #[test]
    fn a_small_function_lexes_into_the_tokens_it_is_written_from() {
        let (tokens, messages) = lexed("int main(void) { return 0; }");
        assert!(messages.is_empty(), "{messages:?}");
        let expected = [
            (TokenKind::KwInt, "int"),
            (TokenKind::Identifier, "main"),
            (TokenKind::LParen, "("),
            (TokenKind::KwVoid, "void"),
            (TokenKind::RParen, ")"),
            (TokenKind::LBrace, "{"),
            (TokenKind::KwReturn, "return"),
            (TokenKind::IntLiteral, "0"),
            (TokenKind::Semi, ";"),
            (TokenKind::RBrace, "}"),
        ];
        let got: Vec<(TokenKind, &str)> = tokens
            .iter()
            .map(|(kind, text)| (*kind, text.as_str()))
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn trivia_never_becomes_a_token_but_still_lands_in_the_extent() {
        let text = "x /* c */ ;\n// tail\ny";
        assert_eq!(
            kinds(text),
            [
                TokenKind::Identifier,
                TokenKind::Semi,
                TokenKind::Identifier
            ]
        );

        // The substrate's extent runs to the next token and so carries the
        // comment; `lexeme` is what trims it back (substrate.md 2.1).
        let parsed = tokenize(text);
        let tokens = parsed.value();
        assert_eq!(tokens.text(TokenId::new(0), text), "x /* c */ ");
        assert_eq!(lexeme(tokens, TokenId::new(0), text), "x");
        assert_eq!(tokens.text(TokenId::new(1), text), ";\n// tail\n");
        assert_eq!(lexeme(tokens, TokenId::new(1), text), ";");

        // And the whole-file property the buffer does promise still holds.
        let joined: String = (0..tokens.len())
            .map(|i| tokens.text(TokenId::new(i as u32), text))
            .collect();
        assert_eq!(
            joined, text,
            "the extents tile the source from the first token"
        );
    }

    #[test]
    fn every_punctuator_lexes_as_its_longest_form() {
        let punctuators: Vec<TokenKind> = TokenKind::ALL
            .iter()
            .copied()
            .filter(|kind| kind.is_punctuator())
            .collect();
        assert_eq!(punctuators.len(), 48);
        for kind in punctuators {
            let (tokens, messages) = lexed(kind.name());
            assert!(messages.is_empty(), "{kind:?}: {messages:?}");
            assert_eq!(
                tokens,
                [(kind, kind.name().to_string())],
                "{:?} did not lex as itself",
                kind.name()
            );
        }
        // The greedy cases, spelled out: each must not split.
        assert_eq!(kinds("<<="), [TokenKind::ShlEq]);
        assert_eq!(kinds(">>="), [TokenKind::ShrEq]);
        assert_eq!(kinds("..."), [TokenKind::Ellipsis]);
        assert_eq!(kinds("->"), [TokenKind::Arrow]);
        assert_eq!(kinds("##"), [TokenKind::HashHash]);
        // ... and the near misses must.
        assert_eq!(kinds("<<"), [TokenKind::Shl]);
        assert_eq!(kinds(".."), [TokenKind::Dot, TokenKind::Dot]);
        assert_eq!(kinds("a::b").len(), 4, "`::` is two colons in C");
        assert_eq!(kinds(">>>"), [TokenKind::Shr, TokenKind::Gt]);
    }

    #[test]
    fn keywords_are_recognised_and_lookalikes_are_not() {
        assert_eq!(kinds("__attribute__"), [TokenKind::KwAttribute]);
        assert_eq!(kinds("__extension__"), [TokenKind::KwExtension]);
        assert_eq!(kinds("__builtin_va_list"), [TokenKind::KwBuiltinVaList]);
        assert_eq!(kinds("__int128"), [TokenKind::KwInt128]);
        assert_eq!(kinds("_Static_assert"), [TokenKind::KwStaticAssert]);
        assert_eq!(kinds("__restrict__"), [TokenKind::KwRestrict]);
        assert_eq!(kinds("restrict"), [TokenKind::KwRestrict]);
        for name in ["undefined4", "restrict_", "_Bools", "Return", "bool"] {
            assert_eq!(kinds(name), [TokenKind::Identifier], "{name}");
        }
    }

    #[test]
    fn a_dollar_is_an_identifier_character_because_gcc_says_so() {
        assert_eq!(kinds("$a"), [TokenKind::Identifier]);
        assert_eq!(lexed("a$b").0[0].1, "a$b");
    }

    #[test]
    fn literals_carry_their_prefixes_and_their_suffixes() {
        let cases: [(&str, TokenKind); 12] = [
            ("0", TokenKind::IntLiteral),
            ("0x1f", TokenKind::IntLiteral),
            ("0b1011", TokenKind::IntLiteral),
            ("07u", TokenKind::IntLiteral),
            ("18446744073709551615ULL", TokenKind::IntLiteral),
            ("1.5", TokenKind::FloatLiteral),
            (".5f", TokenKind::FloatLiteral),
            ("1e10", TokenKind::FloatLiteral),
            ("0x1p3", TokenKind::FloatLiteral),
            ("'a'", TokenKind::CharLiteral),
            ("L'\\x41'", TokenKind::CharLiteral),
            ("u8\"hi\"", TokenKind::StringLiteral),
        ];
        for (text, kind) in cases {
            let (tokens, messages) = lexed(text);
            assert!(messages.is_empty(), "{text}: {messages:?}");
            assert_eq!(tokens, [(kind, text.to_string())], "{text}");
        }
        // A literal prefix must not be eaten as an identifier.
        assert_eq!(kinds("L\"x\""), [TokenKind::StringLiteral]);
        assert_eq!(kinds("Lx"), [TokenKind::Identifier]);
        // C's unbounded \x escape: one token, not a string plus an identifier.
        assert_eq!(lexed("\"\\x41BCDEF\"").0[0].1, "\"\\x41BCDEF\"");
    }

    #[test]
    fn an_unterminated_construct_is_reported_and_still_produces_a_token() {
        for (text, kind, wanted) in [
            (
                "\"abc",
                TokenKind::StringLiteral,
                "unterminated string literal",
            ),
            (
                "'a",
                TokenKind::CharLiteral,
                "unterminated character literal",
            ),
        ] {
            let (tokens, messages) = lexed(text);
            assert_eq!(tokens.len(), 1, "{text}");
            assert_eq!(tokens[0].0, kind, "{text}");
            assert_eq!(messages.len(), 1, "{text}: {messages:?}");
            assert!(messages[0].contains(wanted), "{text}: {messages:?}");
        }

        // An unterminated block comment is trivia to the end of the file: one
        // diagnostic, and no token at all.
        let parsed = tokenize("a /* unclosed");
        assert_eq!(parsed.value().len(), 1);
        assert_eq!(parsed.diagnostics().len(), 1);
        assert!(parsed
            .diagnostics()
            .iter()
            .next()
            .expect("a diagnostic")
            .message
            .contains("unterminated block comment"));
    }

    #[test]
    fn a_stray_byte_becomes_a_token_rather_than_a_reason_to_stop() {
        // `REQ-IN-4`: the file must keep lexing past the garbage.
        let (tokens, messages) = lexed("int a @ 1;");
        assert_eq!(
            kinds("int a @ 1;"),
            [
                TokenKind::KwInt,
                TokenKind::Identifier,
                TokenKind::Unknown,
                TokenKind::IntLiteral,
                TokenKind::Semi
            ]
        );
        assert_eq!(tokens[2].1, "@");
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(messages[0].contains("stray '@' in program"), "{messages:?}");

        // A multi-byte character is consumed whole, so no later span can start
        // off a character boundary.
        let (tokens, messages) = lexed("a \u{20ac} b");
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[1], (TokenKind::Unknown, "\u{20ac}".to_string()));
        assert_eq!(messages.len(), 1, "{messages:?}");
    }

    #[test]
    fn a_line_splice_is_transparent_inside_an_identifier() {
        assert_eq!(kinds("re\\\nturn"), [TokenKind::KwReturn]);
        assert_eq!(kinds("re\\\r\nturn"), [TokenKind::KwReturn]);
        assert_eq!(
            lexed("ab\\\ncd").0[0],
            (TokenKind::Identifier, "ab\\\ncd".to_string())
        );
        // Two splices in one identifier, and one that joins a digit run.
        assert_eq!(kinds("r\\\ne\\\nturn"), [TokenKind::KwReturn]);
        assert_eq!(lexed("a\\\n1").0[0].1, "a\\\n1");
    }

    #[test]
    fn a_line_splice_between_tokens_is_trivia() {
        assert_eq!(
            kinds("a\\\n+b"),
            [
                TokenKind::Identifier,
                TokenKind::Plus,
                TokenKind::Identifier
            ]
        );
        assert_eq!(kinds("\\\n"), []);
        // A lone trailing backslash is not a splice, and must not hang.
        assert_eq!(kinds("a\\"), [TokenKind::Identifier, TokenKind::Unknown]);
    }

    #[test]
    fn a_splice_inside_a_punctuator_is_the_documented_divergence() {
        // C phase 2 would make this one `<<=`. We lex `<` then `<=`, which the
        // module docs record; the test exists so the choice cannot drift
        // silently into a bug report.
        assert_eq!(kinds("<\\\n<="), [TokenKind::Lt, TokenKind::Le]);
    }

    #[test]
    fn a_splice_inside_a_string_is_the_scanners_line_continuation() {
        let (tokens, messages) = lexed("\"ab\\\ncd\"");
        assert!(messages.is_empty(), "{messages:?}");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].0, TokenKind::StringLiteral);
        assert_eq!(tokens[0].1, "\"ab\\\ncd\"");
    }

    #[test]
    fn a_line_comment_ending_in_a_backslash_swallows_the_next_line() {
        // C's translation phase 2, and a genuine C surprise: the `int x;` is
        // still inside the comment.
        assert_eq!(kinds("// c \\\nint x;\ny"), [TokenKind::Identifier]);
    }

    #[test]
    fn the_gnu_surface_that_shows_up_in_preprocessed_output_lexes() {
        let text = "__extension__ __inline__ __attribute__((__always_inline__)) \
                    unsigned __int128 f(__builtin_va_list ap) { __asm__ __volatile__(\"nop\"); }";
        let (tokens, messages) = lexed(text);
        assert!(messages.is_empty(), "{messages:?}");
        assert_eq!(tokens[0].0, TokenKind::KwExtension);
        assert_eq!(tokens[1].0, TokenKind::KwInline);
        assert_eq!(tokens[2].0, TokenKind::KwAttribute);
        assert!(tokens.iter().any(|(k, _)| *k == TokenKind::KwInt128));
        assert!(tokens.iter().any(|(k, _)| *k == TokenKind::KwBuiltinVaList));
        assert!(tokens.iter().any(|(k, _)| *k == TokenKind::KwAsm));
        assert!(tokens.iter().any(|(k, _)| *k == TokenKind::KwVolatile));
    }

    #[test]
    fn identical_input_yields_a_byte_identical_buffer() {
        // `REQ-SYN-5`.
        let text = "int f(void) { /* c */ return 'x' + 1.5e3; }";
        let first = tokenize(text);
        let second = tokenize(text);
        assert_eq!(first.value(), second.value());
        assert_eq!(first.diagnostics(), second.diagnostics());
    }

    #[test]
    fn no_input_panics_hangs_or_loses_a_byte() {
        // `REQ-SYN-2` and `REQ-SYN-4`. Each of these is a shape that has broken
        // a hand-written C lexer somewhere.
        let pathological: Vec<String> = vec![
            String::new(),
            "\\".into(),
            "\\\\".into(),
            "'".into(),
            "\"".into(),
            "'\\".into(),
            "\"\\".into(),
            "/*".into(),
            "//".into(),
            "0x".into(),
            "0b".into(),
            "1e".into(),
            "0x1.8".into(),
            ".".into(),
            "..".into(),
            "u8".into(),
            "L".into(),
            "'\\x".into(),
            "\u{20ac}".into(),
            "\u{20ac}\u{20ac}".into(),
            "\0\0\0".into(),
            "@#$%^".into(),
            "/*".repeat(5_000),
            "(".repeat(50_000),
            "\\\n".repeat(10_000),
            "0x".to_string() + &"f".repeat(10_000),
            "\"\\x".to_string() + &"4".repeat(10_000),
            format!("{}\n", "a\\".repeat(10_000)),
        ];
        for text in &pathological {
            let parsed = tokenize(text);
            let tokens = parsed.value();
            assert_eq!(tokens.end_of_input() as usize, text.len());
            // Offsets ascend strictly and stay inside the input, which is what
            // proves the loop advanced on every iteration.
            let mut previous: Option<u32> = None;
            for index in 0..tokens.len() {
                let start = tokens.start(TokenId::new(index as u32));
                assert!((start as usize) < text.len());
                if let Some(before) = previous {
                    assert!(start > before, "offsets did not advance in {text:?}");
                }
                previous = Some(start);
            }
        }
    }

    #[test]
    fn every_truncation_of_a_realistic_file_lexes_without_a_panic() {
        // Truncation is where a lexer's lookahead falls off the end, so every
        // prefix is exercised rather than a chosen few.
        let text = "int f(char *s) { /* c */ return s[0] == '\\n' ? 0x1p3 : \"a\\x41b\"[1]; }";
        for cut in 0..=text.len() {
            if !text.is_char_boundary(cut) {
                continue;
            }
            let parsed = tokenize(&text[..cut]);
            assert_eq!(parsed.value().end_of_input() as usize, cut);
        }
    }

    #[test]
    fn bytes_that_are_not_utf8_reach_the_lexer_replaced_and_still_lex() {
        // `REQ-NORM-4`: the caller converts lossily, and the replacement
        // character must behave like any other stray character.
        let raw = b"int a = \xff\xfe 1;";
        let text = String::from_utf8_lossy(raw);
        let parsed = tokenize(&text);
        assert!(!parsed.value().is_empty());
        assert!(parsed.diagnostics().len() >= 1);
        assert_eq!(parsed.value().end_of_input() as usize, text.len());
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

    /// Lex one file and report `(lines, tokens, diagnostics)`, reading it
    /// lossily the way `REQ-NORM-4` requires of every caller.
    fn measure(path: &Path) -> (usize, usize, Vec<String>) {
        let raw = std::fs::read(path).expect("a readable corpus file");
        let text = String::from_utf8_lossy(&raw).into_owned();
        let parsed = tokenize(&text);
        let messages = parsed
            .diagnostics()
            .iter()
            .map(|d| d.render(&text))
            .collect();
        (text.lines().count(), parsed.value().len(), messages)
    }

    #[test]
    fn the_clean_in_repo_corpus_lexes_with_zero_diagnostics() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files: Vec<PathBuf> = Vec::new();
        for relative in ["tests/decompiler_fixtures/src", "tests/decbench_corpus/src"] {
            files.extend(c_files(&root.join(relative)));
        }
        if files.is_empty() {
            println!("SKIP: no in-repo C corpus under {}", root.display());
            return;
        }
        let (mut lines, mut tokens, mut failures) = (0usize, 0usize, Vec::new());
        for path in &files {
            let (file_lines, file_tokens, messages) = measure(path);
            lines += file_lines;
            tokens += file_tokens;
            assert!(file_tokens > 0, "{} produced no tokens", path.display());
            if !messages.is_empty() {
                failures.push(format!("{}: {:?}", path.display(), messages));
            }
        }
        println!("in-repo corpus: {} files", files.len());
        println!("  lines       = {lines}");
        println!("  tokens      = {tokens}");
        println!("  diagnostics = {}", failures.len());
        assert!(
            failures.is_empty(),
            "C we own must lex clean; {} file(s) did not:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    #[test]
    fn real_decompiler_output_lexes_without_a_panic_or_an_empty_file() {
        // Lives outside the repository, so absence is a skip rather than a
        // failure. Diagnostics here are expected and are the number to report;
        // a panic, a hang or a file with no tokens is not.
        let Ok(home) = std::env::var("HOME") else {
            println!("SKIP: no HOME");
            return;
        };
        let dir = PathBuf::from(home).join(".cache/glaurung/decbench-full/tree/O0/zlib/decompiled");
        let files = c_files(&dir);
        if files.is_empty() {
            println!("SKIP: no decompiled corpus at {}", dir.display());
            return;
        }
        let (mut lines, mut tokens, mut diagnostics) = (0usize, 0usize, 0usize);
        let mut by_message: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for path in &files {
            let (file_lines, file_tokens, messages) = measure(path);
            assert!(file_tokens > 0, "{} produced no tokens", path.display());
            lines += file_lines;
            tokens += file_tokens;
            diagnostics += messages.len();
            for message in messages {
                // Strip the span and the snippet; only the wording is grouped.
                let wording = message
                    .split_once("error: ")
                    .map_or(message.clone(), |(_, rest)| rest.to_string());
                *by_message.entry(wording).or_default() += 1;
            }
        }
        let per_kloc = diagnostics as f64 * 1000.0 / lines.max(1) as f64;
        println!("decompiled corpus: {} files", files.len());
        println!("  lines            = {lines}");
        println!("  tokens           = {tokens}");
        println!("  diagnostics      = {diagnostics}");
        println!("  per KLOC         = {per_kloc:.3}");
        for (wording, count) in &by_message {
            println!("  {count:>6}  {wording}");
        }
    }
}
