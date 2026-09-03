//! Whitespace and comment scanning.
//!
//! `scan_whitespace`, `scan_line_comment` and `scan_block_comment` are split
//! into their own file because trivia is a sublanguage the token buffer never
//! sees --- the parent module doc explains why it is not stored --- and the
//! three scanners here share only `super::ScanConfig` and `super::ScanIssue`
//! with the scanners around them, nothing among themselves that a literal or
//! a number scanner also needs.

use super::{issue, newline_len, utf8_len, IssueKind, ScanConfig, ScanIssue};

/// Which of the two comment forms was scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommentKind {
    /// `//` to the end of the line.
    Line,
    /// `/* ... */`.
    Block,
}

/// A comment's extent and whether it closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comment {
    /// Bytes occupied, from the offset the scan started at.
    pub len: usize,
    /// Line or block.
    pub kind: CommentKind,
    /// Whether it closed: always true for a line comment, where the end of the
    /// input is a legitimate ending; false for a block comment that ran off the
    /// end.
    pub terminated: bool,
    /// The problem found, if any.
    pub issue: Option<ScanIssue>,
}

/// The length of the run of ASCII whitespace at `at`, or 0 at or past the end:
/// space, tab, newline, carriage return, vertical tab and form feed. Non-ASCII
/// space --- which Rust also accepts --- is excluded deliberately, because
/// recognising it needs the Unicode tables `REQ-SYN-6` forbids.
pub fn scan_whitespace(text: &str, at: usize) -> usize {
    let bytes = text.as_bytes();
    let start = at.min(bytes.len());
    let mut index = start;
    while let Some(&b) = bytes.get(index) {
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            index += 1;
        } else {
            break;
        }
    }
    index - start
}

/// Scan a `//` comment at `at`, or return `None` if one does not start there.
/// The comment runs to the newline and does *not* include it, the newline being
/// whitespace that belongs to the next trivia run. Under
/// [`ScanConfig::line_splicing`] a backslash immediately before a newline
/// continues it onto the next line --- C's translation phase 2, and the reason
/// a stray trailing backslash comments out the line after it.
pub fn scan_line_comment(text: &str, at: usize, cfg: ScanConfig) -> Option<Comment> {
    let bytes = text.as_bytes();
    if bytes.get(at) != Some(&b'/') || bytes.get(at + 1) != Some(&b'/') {
        return None;
    }
    let mut index = at + 2;
    while let Some(&b) = bytes.get(index) {
        if cfg.line_splicing && b == b'\\' {
            if let Some(width) = newline_len(bytes, index + 1) {
                index += 1 + width;
                continue;
            }
        }
        if newline_len(bytes, index).is_some() {
            break;
        }
        index += utf8_len(b);
    }
    Some(Comment {
        len: index.min(bytes.len()) - at,
        kind: CommentKind::Line,
        terminated: true,
        issue: None,
    })
}

/// Scan a `/* ... */` comment at `at`, or return `None` if none starts there.
/// Nesting is a counter, never recursion (`REQ-SYN-3`): a file of ten thousand
/// `/*` must produce a diagnostic, not a stack overflow that aborts before
/// anything can be reported. An unterminated comment consumes to the end of the
/// input and reports it, which is what every C compiler does and what stops the
/// lexer above from re-scanning those bytes as code.
pub fn scan_block_comment(text: &str, at: usize, cfg: ScanConfig) -> Option<Comment> {
    let bytes = text.as_bytes();
    if bytes.get(at) != Some(&b'/') || bytes.get(at + 1) != Some(&b'*') {
        return None;
    }
    let end = bytes.len();
    let mut depth: u32 = 1;
    let mut index = at + 2;
    let mut terminated = false;
    while index < end {
        let b = bytes[index];
        if b == b'*' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            depth -= 1;
            if depth == 0 {
                terminated = true;
                break;
            }
        } else if cfg.nested_block_comments && b == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            depth = depth.saturating_add(1);
        } else {
            index += utf8_len(b);
        }
    }
    let stop = index.min(end);
    Some(Comment {
        len: stop - at,
        kind: CommentKind::Block,
        terminated,
        issue: (!terminated).then(|| issue(IssueKind::UnterminatedBlockComment, at, stop)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitespace_stops_at_the_first_byte_that_is_not_ascii_space() {
        assert_eq!(scan_whitespace(" \t\r\n\x0b\x0c x", 0), 7);
        assert_eq!(scan_whitespace("x  ", 0), 0);
        assert_eq!(scan_whitespace("  x", 1), 1);
    }

    #[test]
    fn a_line_comment_runs_to_the_newline_without_consuming_it() {
        let found = scan_line_comment("// hi\nx", 0, ScanConfig::C).expect("a comment");
        assert_eq!(found.len, 5);
        assert_eq!(found.kind, CommentKind::Line);
        assert!(found.terminated);
        assert!(scan_line_comment("/ /", 0, ScanConfig::C).is_none());
    }

    #[test]
    fn a_line_comment_ending_in_a_backslash_swallows_the_next_line_in_c_only() {
        let text = "// a\\\nb\nc";
        let spliced = scan_line_comment(text, 0, ScanConfig::C).expect("a comment");
        assert_eq!(&text[..spliced.len], "// a\\\nb");
        let unspliced = scan_line_comment(text, 0, ScanConfig::RUST).expect("a comment");
        assert_eq!(&text[..unspliced.len], "// a\\");
    }

    #[test]
    fn a_block_comment_nests_only_when_the_configuration_says_it_does() {
        let text = "/* a /* b */ c */";
        let flat = scan_block_comment(text, 0, ScanConfig::C).expect("a comment");
        assert_eq!(&text[..flat.len], "/* a /* b */");
        assert!(flat.terminated);
        let nested = scan_block_comment(text, 0, ScanConfig::RUST).expect("a comment");
        assert_eq!(nested.len, text.len());
        assert!(nested.terminated);
    }

    #[test]
    fn an_unterminated_block_comment_consumes_to_the_end_and_reports_itself() {
        let text = "/* never closed";
        let found = scan_block_comment(text, 0, ScanConfig::C).expect("a comment");
        assert_eq!(found.len, text.len());
        assert!(!found.terminated);
        let reported = found.issue.expect("an issue");
        assert_eq!(reported.kind, IssueKind::UnterminatedBlockComment);
        assert_eq!(
            reported.to_diagnostic().message,
            "unterminated block comment"
        );
        let unclosed_nest = scan_block_comment("/* /* */", 0, ScanConfig::RUST).expect("a comment");
        assert!(!unclosed_nest.terminated);
    }
}
