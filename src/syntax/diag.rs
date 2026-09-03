//! `SB-5` --- diagnostics, and the "parsing never fails" contract.
//!
//! Spec: `docs/design/source-front-ends/substrate.md` sections 4 and 7.
//!
//! Every parser entry point in this substrate returns its product alongside a
//! [`Diagnostics`] list, never a `Result` (`REQ-SYN-2`). [`Parsed<T>`] is the
//! type that carries both halves of that contract in one value, so that
//! reaching for `Result` is simply not the ergonomic option: the product is
//! always available, and diagnostics are additional information rather than
//! an alternative outcome. This mirrors rust-analyzer's stated invariant
//! ("Parsing never fails, the parser produces `(T, Vec<Error>)` rather than
//! `Result<T, Error>`") for exactly the reason given in section 4 of the
//! design doc: a `Result`-returning parser cannot report a per-function
//! failure, and one bad byte must never void a whole file's output.

use std::fmt;

use crate::syntax::ids::{DiagId, Span};

/// How seriously a [`Diagnostic`] should be taken.
///
/// Two levels, not three. The natural third candidate is "info" or "hint" ---
/// rustc has one, and rust-analyzer's own diagnostic model carries a `hint`
/// level for IDE-only nudges (unused imports styled as fainter text, and the
/// like). Nothing in this substrate produces that kind of advisory output:
/// every diagnostic here comes from a parser or a recovery pass reporting
/// either "this cannot be part of a valid program" (`Error`) or "this parsed,
/// but something about it is suspicious" (`Warning`, reserved for a future
/// recovery pass; no producer exists yet in this module). A third level would
/// be dead weight carried for a producer that does not exist. `REQ-SYN-10`
/// applies here too: no abstraction before a second real consumer needs it,
/// and severities are cheap to add later since `Diagnostics::error_count`
/// et al. would need no call-site changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// The input could not be interpreted as the construct being parsed.
    /// Recovery still produces a partial tree and a span for the skipped
    /// text (`REQ-SYN-7`); an error never means "nothing came out."
    Error,
    /// The input parsed, but is worth flagging. No producer in this module
    /// emits one yet; the variant exists so a later recovery pass (e.g. a
    /// deprecated-syntax warning) has somewhere to put it without a
    /// signature change propagating through every sink.
    Warning,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        f.write_str(text)
    }
}

/// One recorded problem, always attached to a [`Span`] (`REQ-SYN-7`).
///
/// A `Diagnostic` is a record, not a control-flow signal: producing one never
/// stops the parser that produced it (`REQ-SYN-2`), and nothing here borrows
/// from the source text or the token buffer, so a `Diagnostic` outlives the
/// parse that created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Where in the source file the problem was found. For a recovered
    /// construct this is the span of the text that was skipped or
    /// misinterpreted, not merely the point recovery resumed at
    /// (`REQ-SYN-7`).
    pub span: Span,
    /// How seriously to take this diagnostic.
    pub severity: Severity,
    /// A human-readable description, already formatted --- there is no
    /// separate template/args split here. Rendering into a fuller report
    /// (with source text, line/column, a caret) is layered on top by
    /// [`Diagnostic::render`], not baked into this field.
    pub message: String,
    /// The set of things that would have been accepted at this point, for a
    /// "expected one of X, Y, Z" style message.
    ///
    /// Represented as `Vec<&'static str>` rather than a small-inline-array
    /// type: the crate has no `smallvec` dependency and `REQ-SYN-6` forbids
    /// adding one for this module, so the choice is between a hand-rolled
    /// inline enum and a plain `Vec`. A hand-rolled `SmallVec`-alike earns
    /// its complexity only when allocation shows up in a profile; nothing in
    /// this substrate has measured that yet (`REQ-SYN-10`'s "don't build the
    /// abstraction before it's needed" reasoning applies equally to a
    /// bespoke container as to a trait). `&'static str` because every
    /// grammar's "expected" vocabulary --- token and construct names --- is
    /// known at compile time; nothing here is ever a formatted or
    /// source-derived string. Most diagnostics expect a small, fixed set of
    /// alternatives (often one), so the `Vec` is typically short-lived and
    /// small, and an empty `Vec` allocates nothing.
    pub expected: Vec<&'static str>,
}

impl Diagnostic {
    /// An error diagnostic with no `expected` list.
    pub fn error(span: Span, message: impl Into<String>) -> Self {
        Self {
            span,
            severity: Severity::Error,
            message: message.into(),
            expected: Vec::new(),
        }
    }

    /// A warning diagnostic with no `expected` list.
    pub fn warning(span: Span, message: impl Into<String>) -> Self {
        Self {
            span,
            severity: Severity::Warning,
            message: message.into(),
            expected: Vec::new(),
        }
    }

    /// Attach an `expected` vocabulary to this diagnostic, replacing any
    /// existing one. Returns `self` so a diagnostic can be built in one
    /// expression: `Diagnostic::error(span, "unexpected token").expecting(&["+", "-"])`.
    pub fn expecting(mut self, expected: &[&'static str]) -> Self {
        self.expected = expected.to_vec();
        self
    }

    /// Render this diagnostic as a single human-readable line, given the
    /// full source text it applies to.
    ///
    /// This is deliberately *not* source-map-aware: `src/syntax/source.rs`
    /// (owning `SourceFile`/`SourceMap` and byte-offset-to-line/column
    /// mapping) is being written concurrently by another agent, and this
    /// module must not take a compile dependency on it (`REQ-SYN-1`'s
    /// layering discipline applies within the module too --- `diag.rs` sits
    /// below `source.rs` in the dependency order this design implies). This
    /// method therefore reports the byte span numerically rather than as a
    /// line/column pair.
    ///
    /// A future `SourceMap`-aware renderer belongs here, as a second method
    /// (e.g. `render_with_map`) once `source.rs` lands; it should produce a
    /// `file:line:column: severity: message` line and a caret under the
    /// offending text, in the style every other diagnostic-rendering tool
    /// uses. This method is the fallback that keeps `diag.rs` usable and
    /// testable on its own in the meantime.
    ///
    /// `text` is used only to clamp the rendered snippet to the actual
    /// source length, so a span produced from stale or truncated input never
    /// panics on an out-of-range slice; it degrades to an empty snippet
    /// instead.
    pub fn render(&self, text: &str) -> String {
        let len = text.len();
        let lo = (self.span.lo as usize).min(len);
        let hi = (self.span.hi as usize).min(len);
        // `lo`/`hi` are byte offsets from the caller; if they do not land on a
        // UTF-8 boundary (e.g. a span computed against different text), fall
        // back to an empty snippet rather than panicking on a bad slice.
        let snippet = text.get(lo..hi).unwrap_or("");
        if snippet.is_empty() {
            format!("{}: {}: {}", self.span, self.severity, self.message)
        } else {
            format!(
                "{}: {}: {} ({snippet:?})",
                self.span, self.severity, self.message
            )
        }
    }
}

/// An append-only collection of [`Diagnostic`]s, in insertion order
/// (`REQ-SYN-5`).
///
/// Every parser entry point in this substrate carries one of these alongside
/// its product rather than returning `Result` (`REQ-SYN-2`). Push is the only
/// way to add to it: there is no remove and no re-sort, so a `DiagId` handed
/// back by [`Diagnostics::push`] is valid for the lifetime of the collection
/// and always addresses the same diagnostic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics {
    entries: Vec<Diagnostic>,
}

impl Diagnostics {
    /// An empty diagnostic list.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record a diagnostic, returning the id that addresses it.
    ///
    /// Ids are assigned densely in insertion order (`REQ-SYN-5`), so the
    /// returned id is always `entries.len() - 1` at the time of the call ---
    /// identical input therefore yields identical ids across runs.
    pub fn push(&mut self, diagnostic: Diagnostic) -> DiagId {
        let id = DiagId::new(self.entries.len() as u32);
        self.entries.push(diagnostic);
        id
    }

    /// The number of diagnostics recorded, errors and warnings combined.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no diagnostics have been recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The diagnostic addressed by `id`, or `None` if `id` was not produced
    /// by this collection (e.g. it came from a different parse).
    pub fn get(&self, id: DiagId) -> Option<&Diagnostic> {
        self.entries.get(id.index())
    }

    /// All diagnostics, in insertion order (`REQ-SYN-5`).
    pub fn iter(&self) -> impl Iterator<Item = &Diagnostic> {
        self.entries.iter()
    }

    /// How many recorded diagnostics are [`Severity::Error`].
    pub fn error_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count()
    }

    /// How many recorded diagnostics are [`Severity::Warning`].
    pub fn warning_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .count()
    }

    /// Whether any recorded diagnostic is [`Severity::Error`]. A parse with
    /// only warnings still counts as having succeeded, in the sense the
    /// substrate cares about: it produced a usable `T`.
    pub fn has_errors(&self) -> bool {
        self.entries.iter().any(|d| d.severity == Severity::Error)
    }
}

impl<'a> IntoIterator for &'a Diagnostics {
    type Item = &'a Diagnostic;
    type IntoIter = std::slice::Iter<'a, Diagnostic>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// The `(T, Vec<Diagnostic>)` contract (`REQ-SYN-2`), given a name.
///
/// Every parser entry point in this substrate returns a `Parsed<T>` rather
/// than `Result<T, E>`: the product is always present, diagnostics ride
/// alongside it as additional information, and there is no error variant to
/// reach for instead of populating both. This is what makes "parsing never
/// fails" the easy thing to do rather than a discipline that has to be
/// remembered at every call site.
///
/// `T` is typically an event stream, an arena tree, or a CFG --- whatever the
/// entry point's product is --- but `Parsed` itself is generic and knows
/// nothing about parsing; it is exactly a bundle of a value and a diagnostic
/// list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed<T> {
    value: T,
    diagnostics: Diagnostics,
}

impl<T> Parsed<T> {
    /// Bundle a product with the diagnostics collected while producing it.
    pub fn new(value: T, diagnostics: Diagnostics) -> Self {
        Self { value, diagnostics }
    }

    /// A product with no diagnostics at all --- the fully clean parse.
    pub fn clean(value: T) -> Self {
        Self {
            value,
            diagnostics: Diagnostics::new(),
        }
    }

    /// Unbundle into the product and its diagnostics, consuming `self`. The
    /// usual way to finish handling a `Parsed<T>`: match or destructure the
    /// pair once both halves are needed.
    pub fn into_parts(self) -> (T, Diagnostics) {
        (self.value, self.diagnostics)
    }

    /// The product, by reference, without consuming the diagnostics.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// The diagnostics collected while producing [`Parsed::value`].
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diagnostics
    }

    /// Whether any recorded diagnostic is [`Severity::Error`]. A shorthand
    /// for `self.diagnostics().has_errors()`, since checking this is the
    /// most common thing a caller does with a `Parsed<T>` before deciding how
    /// much to trust `value()` for a downstream pass that cannot tolerate
    /// errors (the value itself is still always present and usable).
    pub fn has_errors(&self) -> bool {
        self.diagnostics.has_errors()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(lo: u32, hi: u32) -> Span {
        Span::new(lo, hi)
    }

    #[test]
    fn pushing_two_diagnostics_returns_ids_that_address_them_in_order() {
        let mut diags = Diagnostics::new();
        let first = diags.push(Diagnostic::error(span(0, 3), "first"));
        let second = diags.push(Diagnostic::warning(span(4, 5), "second"));

        assert_eq!(diags.get(first).unwrap().message, "first");
        assert_eq!(diags.get(second).unwrap().message, "second");
        assert_ne!(first, second);
    }

    #[test]
    fn insertion_order_is_preserved_by_iter() {
        let mut diags = Diagnostics::new();
        diags.push(Diagnostic::error(span(0, 1), "a"));
        diags.push(Diagnostic::error(span(1, 2), "b"));
        diags.push(Diagnostic::error(span(2, 3), "c"));

        let messages: Vec<&str> = diags.iter().map(|d| d.message.as_str()).collect();
        assert_eq!(messages, vec!["a", "b", "c"]);
    }

    #[test]
    fn error_and_warning_counts_are_tracked_independently() {
        let mut diags = Diagnostics::new();
        diags.push(Diagnostic::error(span(0, 1), "e1"));
        diags.push(Diagnostic::warning(span(1, 2), "w1"));
        diags.push(Diagnostic::error(span(2, 3), "e2"));

        assert_eq!(diags.error_count(), 2);
        assert_eq!(diags.warning_count(), 1);
        assert_eq!(diags.len(), 3);
        assert!(!diags.is_empty());
    }

    #[test]
    fn has_errors_is_false_for_a_warning_only_parse() {
        let mut diags = Diagnostics::new();
        diags.push(Diagnostic::warning(span(0, 1), "just a warning"));

        assert!(!diags.has_errors());

        let parsed = Parsed::new(42, diags);
        assert!(!parsed.has_errors());
        assert_eq!(*parsed.value(), 42);
    }

    #[test]
    fn has_errors_is_true_once_any_error_is_recorded() {
        let mut diags = Diagnostics::new();
        diags.push(Diagnostic::warning(span(0, 1), "fine"));
        diags.push(Diagnostic::error(span(1, 2), "not fine"));

        assert!(diags.has_errors());
    }

    #[test]
    fn an_empty_parsed_value_has_no_diagnostics_and_no_errors() {
        let parsed: Parsed<Vec<u8>> = Parsed::clean(Vec::new());

        assert!(parsed.diagnostics().is_empty());
        assert!(!parsed.has_errors());
        assert!(parsed.value().is_empty());
    }

    #[test]
    fn into_parts_hands_back_the_value_and_the_diagnostics_separately() {
        let mut diags = Diagnostics::new();
        diags.push(Diagnostic::error(span(0, 1), "oops"));
        let parsed = Parsed::new("tree", diags);

        let (value, diagnostics) = parsed.into_parts();
        assert_eq!(value, "tree");
        assert_eq!(diagnostics.len(), 1);
    }

    #[test]
    fn rendering_a_diagnostic_shows_the_span_severity_message_and_snippet() {
        let diag = Diagnostic::error(span(8, 13), "unexpected token").expecting(&["+", "-", ";"]);
        let text = "int x = hello;";

        let rendered = diag.render(text);
        assert_eq!(rendered, "8..13: error: unexpected token (\"hello\")");
        assert_eq!(diag.expected, vec!["+", "-", ";"]);
    }

    #[test]
    fn rendering_with_an_out_of_range_span_falls_back_to_no_snippet_rather_than_panicking() {
        let diag = Diagnostic::error(span(100, 200), "past the end");
        let rendered = diag.render("short");

        assert_eq!(rendered, "100..200: error: past the end");
    }

    #[test]
    fn expecting_replaces_any_previously_attached_list() {
        let diag = Diagnostic::error(span(0, 1), "x")
            .expecting(&["a"])
            .expecting(&["b", "c"]);

        assert_eq!(diag.expected, vec!["b", "c"]);
    }

    #[test]
    fn diagnostics_default_is_empty() {
        let diags = Diagnostics::default();
        assert!(diags.is_empty());
        assert_eq!(diags.len(), 0);
    }
}
