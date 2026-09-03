//! `SB-1` --- source files, spans and position mapping.
//!
//! Spec: `docs/design/source-front-ends/substrate.md` sections 2.3 and 7.

use std::fmt;

use crate::syntax::ids::Span;

/// A 1-based line and 1-based column within a [`SourceFile`].
///
/// The column is measured in **bytes, not characters**. This is a deliberate
/// departure from what an editor usually shows a human, and it is made for
/// two reasons: the decompiler output this substrate parses is not reliably
/// valid UTF-8 to begin with (raw bytes surface as literal text in string and
/// comment content), and every downstream consumer in this crate --- spans,
/// slicing, diffing against a byte offset from disassembly --- already thinks
/// in bytes. Converting to a character column would require re-scanning the
/// line with a UTF-8 decoder on every lookup and would still be wrong the
/// moment a byte sequence is not valid UTF-8, so the byte count is reported
/// instead and left for a caller that wants a human-facing column to convert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LineCol {
    /// 1-based line number.
    pub line: u32,
    /// 1-based byte column within the line.
    pub col: u32,
}

/// A source file: its name, its text, and a line-start table computed once at
/// construction so that byte offset --- line/column mapping never re-scans
/// the text.
///
/// The line-start table records, for every line, the byte offset of its
/// first byte; `line_starts[0]` is always `0`. A `\r\n` line ending is
/// treated the same as a bare `\n`: the next line starts immediately after
/// the `\n`, and the trailing `\r` is trimmed from `line_text` rather than
/// counted as part of the following line.
#[derive(Debug, Clone)]
pub struct SourceFile {
    name: String,
    text: String,
    line_starts: Vec<u32>,
}

/// Scans `text` once for line starts. Always returns a non-empty vector whose
/// first element is `0`: an empty file has exactly one (empty) line.
fn compute_line_starts(text: &str) -> Vec<u32> {
    let mut starts = Vec::with_capacity(text.len() / 32 + 1);
    starts.push(0u32);
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            // The line following a `\n` starts on the byte right after it.
            // This also handles `\r\n`: the `\r` stays part of the line that
            // just ended, and `line_text` trims it on the way out.
            starts.push((i + 1) as u32);
        }
    }
    starts
}

impl SourceFile {
    /// Builds a source file, computing its line-start table once.
    ///
    /// Construction never fails: any `text`, including one containing bytes
    /// that would not be valid on their own, is accepted as-is because it
    /// arrived here as an already-validated `String`.
    pub fn new(name: impl Into<String>, text: impl Into<String>) -> Self {
        let text = text.into();
        let line_starts = compute_line_starts(&text);
        Self {
            name: name.into(),
            text,
            line_starts,
        }
    }

    /// The file's name, as given to [`SourceMap::add`] or [`SourceFile::new`].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The file's full text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The length of the text, in bytes.
    ///
    /// `u32` rather than `usize`: spans are `u32`-based (see
    /// `src/syntax/ids.rs`), and a translation unit is never accepted past
    /// that width.
    pub fn len(&self) -> u32 {
        self.text.len() as u32
    }

    /// Whether the file's text is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Maps a byte offset to a 1-based line and byte column.
    ///
    /// Runs in `O(log n)` in the number of lines via binary search over the
    /// precomputed line-start table --- never a linear scan, since this is
    /// called once per diagnostic and once per finding, both of which can
    /// number in the thousands over a large translation unit.
    ///
    /// An offset past the end of the text is clamped to the last valid
    /// offset rather than panicking or returning a nonsensical position: a
    /// diagnostic that points one byte past EOF (an unterminated string, a
    /// missing closing brace) is common and must still resolve to a real
    /// line.
    pub fn line_col(&self, offset: u32) -> LineCol {
        let offset = offset.min(self.len());
        let idx = match self.line_starts.binary_search(&offset) {
            Ok(i) => i,
            // `line_starts[0]` is always 0 <= offset, so the insertion point
            // for any offset >= 0 that isn't an exact match is at least 1;
            // `saturating_sub` is defensive, not load-bearing.
            Err(i) => i.saturating_sub(1),
        };
        let line_start = self.line_starts[idx];
        LineCol {
            line: idx as u32 + 1,
            col: offset - line_start + 1,
        }
    }

    /// The text of one 1-based line, excluding its line terminator.
    ///
    /// Returns `None` if `line` is `0` or past the last line. A trailing
    /// `\n` or `\r\n` is trimmed; a final line with no terminator (the file
    /// does not end in a newline) is returned as-is.
    pub fn line_text(&self, line: u32) -> Option<&str> {
        if line == 0 {
            return None;
        }
        let idx = (line - 1) as usize;
        let start = *self.line_starts.get(idx)? as usize;
        let mut end = self
            .line_starts
            .get(idx + 1)
            .map(|&s| s as usize)
            .unwrap_or(self.text.len());
        let bytes = self.text.as_bytes();
        if end > start && bytes.get(end - 1) == Some(&b'\n') {
            end -= 1;
        }
        if end > start && bytes.get(end - 1) == Some(&b'\r') {
            end -= 1;
        }
        self.text.get(start..end)
    }

    /// The text covered by `span`.
    ///
    /// Never panics: a span that is out of range or that does not fall on a
    /// UTF-8 character boundary (possible when a caller builds a `Span` from
    /// a raw byte offset rather than a token boundary) yields an empty
    /// string rather than a slicing panic.
    pub fn span_text(&self, span: Span) -> &str {
        let lo = span.lo as usize;
        let hi = span.hi as usize;
        self.text.get(lo..hi).unwrap_or("")
    }
}

/// An index into a [`SourceMap`]'s file list.
///
/// File-scoped, unlike the handles in `src/syntax/ids.rs`: a `FileId` is only
/// meaningful relative to the particular `SourceMap` that produced it, so it
/// lives next to `SourceMap` rather than in the shared id module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileId(u32);

impl FileId {
    /// The handle for index `raw`.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// The underlying index.
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// The underlying index as written.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileId#{}", self.0)
    }
}

/// Owns every [`SourceFile`] in a translation session and hands out
/// [`FileId`]s for them.
///
/// Files are appended in the order they are added and never removed, so a
/// `FileId` stays valid, and stays pointed at the same file, for the life of
/// the `SourceMap` that produced it (`REQ-SYN-5`: identical input, including
/// the order files are added in, yields identical ids).
#[derive(Debug, Clone, Default)]
pub struct SourceMap {
    files: Vec<SourceFile>,
}

impl SourceMap {
    /// An empty source map.
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Adds a file, returning the [`FileId`] it can be looked up by.
    pub fn add(&mut self, name: impl Into<String>, text: impl Into<String>) -> FileId {
        let id = FileId::new(self.files.len() as u32);
        self.files.push(SourceFile::new(name, text));
        id
    }

    /// The file for `id`.
    ///
    /// Panics if `id` was not produced by this `SourceMap`'s own `add`: that
    /// is a programming error in the caller (an id crossed between two
    /// source maps), not a property of parsed input, so it is held to the
    /// same contract as indexing any other arena in this crate rather than
    /// threaded through as a recoverable `Option`.
    pub fn file(&self, id: FileId) -> &SourceFile {
        &self.files[id.index()]
    }

    /// How many files this map holds.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether this map holds no files.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_file_has_one_empty_line() {
        let f = SourceFile::new("empty.c", "");
        assert!(f.is_empty());
        assert_eq!(f.len(), 0);
        assert_eq!(f.line_text(1), Some(""));
        assert_eq!(f.line_text(2), None);
        assert_eq!(f.line_col(0), LineCol { line: 1, col: 1 });
    }

    #[test]
    fn a_file_with_no_trailing_newline_still_reports_its_last_line() {
        let f = SourceFile::new("noeof.c", "int x;");
        assert_eq!(f.line_text(1), Some("int x;"));
        assert_eq!(f.line_text(2), None);
        assert_eq!(f.line_col(6), LineCol { line: 1, col: 7 });
    }

    #[test]
    fn a_file_ending_in_a_newline_has_a_trailing_virtual_empty_line() {
        let f = SourceFile::new("eof_nl.c", "int x;\n");
        assert_eq!(f.line_text(1), Some("int x;"));
        // Offset 7 (== len) is the position right after the newline: the
        // start of a second, empty, line -- exactly how an editor would
        // place a cursor there.
        assert_eq!(f.line_text(2), Some(""));
        assert_eq!(f.line_col(7), LineCol { line: 2, col: 1 });
    }

    #[test]
    fn crlf_line_endings_start_the_next_line_after_the_lf_and_trim_the_cr() {
        let f = SourceFile::new("crlf.c", "line1\r\nline2");
        assert_eq!(f.line_text(1), Some("line1"));
        assert_eq!(f.line_text(2), Some("line2"));
        // Byte 7 is the 'l' of "line2", right after "line1\r\n".
        assert_eq!(f.line_col(7), LineCol { line: 2, col: 1 });
    }

    #[test]
    fn an_offset_past_the_end_clamps_to_the_last_line() {
        let f = SourceFile::new("short.c", "abc");
        assert_eq!(f.line_col(3), f.line_col(1_000_000));
        assert_eq!(f.line_col(1_000_000), LineCol { line: 1, col: 4 });
    }

    #[test]
    fn an_offset_exactly_at_a_line_start_reports_column_one() {
        let f = SourceFile::new("multi.c", "aaa\nbbb\nccc");
        // "aaa\n" is 4 bytes, so "bbb" starts at offset 4.
        assert_eq!(f.line_col(4), LineCol { line: 2, col: 1 });
        // "bbb\n" ends at offset 8, so "ccc" starts there.
        assert_eq!(f.line_col(8), LineCol { line: 3, col: 1 });
    }

    #[test]
    fn line_col_matches_a_naive_scan_over_a_multiline_file() {
        let text = "int main(void) {\n  int x = 1;\r\n  return x;\n}\n";
        let f = SourceFile::new("naive.c", text);
        for offset in 0..=text.len() as u32 {
            let naive = naive_line_col(text, offset);
            assert_eq!(f.line_col(offset), naive, "offset {offset}");
        }
    }

    /// A deliberately linear reference implementation used only to check
    /// `SourceFile::line_col` against, per the SB-1 test requirement in
    /// `docs/design/source-front-ends/substrate.md` section 7.
    fn naive_line_col(text: &str, offset: u32) -> LineCol {
        let offset = offset.min(text.len() as u32) as usize;
        let mut line = 1u32;
        let mut line_start = 0usize;
        for (i, b) in text.bytes().enumerate() {
            if i >= offset {
                break;
            }
            if b == b'\n' {
                line += 1;
                line_start = i + 1;
            }
        }
        LineCol {
            line,
            col: (offset - line_start) as u32 + 1,
        }
    }

    #[test]
    fn span_text_returns_the_bytes_the_span_covers() {
        let f = SourceFile::new("s.c", "int x = 42;");
        let span = Span::new(4, 5);
        assert_eq!(f.span_text(span), "x");
    }

    #[test]
    fn span_text_never_panics_on_an_out_of_range_span() {
        let f = SourceFile::new("s.c", "abc");
        assert_eq!(f.span_text(Span::new(0, 1_000)), "");
        assert_eq!(f.span_text(Span::new(1_000, 2_000)), "");
    }

    #[test]
    fn source_map_hands_out_dense_file_ids_in_add_order() {
        let mut map = SourceMap::new();
        let a = map.add("a.c", "aaa");
        let b = map.add("b.c", "bbb");
        assert_eq!(a.raw(), 0);
        assert_eq!(b.raw(), 1);
        assert_eq!(map.len(), 2);
        assert_eq!(map.file(a).text(), "aaa");
        assert_eq!(map.file(b).name(), "b.c");
    }

    #[test]
    fn an_empty_source_map_reports_empty() {
        let map = SourceMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }
}
