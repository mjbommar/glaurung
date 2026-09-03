//! `SB-6` --- the parser event stream and its sinks.
//!
//! Spec: `docs/design/source-front-ends/substrate.md` sections 3 and 7.
//!
//! The parser never builds a tree. It appends to a flat [`Events`] buffer, and
//! a [`Sink`] turns that buffer into whatever the caller wants: an arena tree
//! ([`crate::syntax::tree::TreeSink`]), a census that counts nodes and builds
//! nothing ([`TagCensus`]), later a control-flow graph. This is
//! rust-analyzer's design and it is kept for the invariant it states --- the
//! parser is independent of the tree structure and of the token representation
//! --- because that invariant is what makes a *second* grammar cheap: it emits
//! the same four events and reuses every sink, every diagnostic and every
//! benchmark already here.
//!
//! Two properties this module holds that the enum alone does not give you:
//!
//! * **Forward patching.** [`Events::open`] hands back a [`Marker`] whose tag
//!   can be rewritten later ([`Events::patch`]), and [`Events::close`] hands
//!   back a [`Closed`] whose tag can still be rewritten after the fact
//!   ([`Events::patch_closed`]). A parser that only learns a node's kind after
//!   consuming its first tokens --- C's declaration-versus-expression
//!   ambiguity is the motivating case --- rewrites the earlier `Open` instead
//!   of backtracking.
//! * **Balance is structural, not a convention.** A [`Marker`] is not `Copy`
//!   and is consumed by exactly one of `close`, `abandon` or `forget`, so
//!   "closed twice" and "closed a node that was never opened" cannot be
//!   written. Closing out of order *can* still be written --- markers are
//!   values, and nothing stops a parser holding two --- so it is detected,
//!   repaired by unwinding to the named marker, and recorded as a
//!   [`Violation`] rather than left to corrupt the tree.
//!
//! Nothing here panics on any input, including an [`Events`] handed over from
//! elsewhere with wildly unbalanced structure (`REQ-SYN-2`), and nothing here
//! recurses (`REQ-SYN-3`): the buffer is a `Vec` and every walk over it is a
//! `for` loop.

use std::collections::BTreeMap;

use crate::syntax::diag::{Diagnostic, Diagnostics};
use crate::syntax::ids::{DiagId, Span, TokenId};

/// One step of a parse, in the order the parser took it.
///
/// The four variants are the whole vocabulary: start a node, consume a token
/// into the node that is open, finish it, or record a problem. There is no
/// "fail" variant because parsing never fails (`REQ-SYN-2`) --- an `Error`
/// carries a [`DiagId`] into the parse's diagnostic list and the parser keeps
/// going, which is what lets one broken function coexist with a file's worth of
/// good ones.
///
/// The payloads are deliberately opaque. `tag` is a `u16` the substrate never
/// interprets, so no language's node kinds leak in here (`REQ-SYN-1`), and the
/// token is an index rather than a token, so the stream is independent of how
/// tokens are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Event {
    /// Start a node with a language-defined tag.
    Open {
        /// The language's node kind. [`Events::TOMBSTONE_TAG`] is reserved.
        tag: u16,
    },
    /// Consume a token into the innermost open node.
    Token {
        /// Index into the token buffer the parse is reading.
        id: TokenId,
    },
    /// Finish the innermost open node.
    Close,
    /// Record a problem already pushed to the parse's diagnostic list.
    Error {
        /// Index of the diagnostic this position refers to.
        diag: DiagId,
    },
}

/// A handle to an `Open` that is still on the parser's stack.
///
/// It is deliberately neither `Copy` nor `Clone`: a marker is *the* right to
/// close exactly one node, and moving that right into `close`, `abandon` or
/// `forget` consumes it. That is what makes "close the same node twice" and
/// "close a node nobody opened" unrepresentable rather than merely discouraged.
/// `#[must_use]` catches the remaining mistake --- opening a node and dropping
/// the marker on the floor --- at compile time where it can, and
/// [`Events::validate`] catches it at run time where it cannot.
#[must_use = "a Marker must be closed, abandoned or forgotten, or its node stays open"]
#[derive(Debug, PartialEq, Eq)]
pub struct Marker {
    /// Index of the `Open` event this marker owns.
    pos: u32,
}

impl Marker {
    /// Index of the `Open` event this marker owns.
    ///
    /// Exposed because a parser that keeps its own side table --- a speculative
    /// parse's rollback point, say --- needs to key it by something stable, and
    /// the event index is the only identity a not-yet-closed node has.
    pub const fn event_index(&self) -> u32 {
        self.pos
    }
}

/// A handle to a node that has been closed.
///
/// Returned by [`Events::close`] so the tag can still be rewritten
/// ([`Events::patch_closed`]). rust-analyzer's `CompletedMarker` exists for the
/// same reason: a grammar frequently parses a complete unit and only then reads
/// the token that says what the unit *was*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed {
    /// Index of the `Open` event.
    open: u32,
    /// Index of the matching `Close` event.
    close: u32,
}

impl Closed {
    /// Index of the node's `Open` event.
    pub const fn open_index(&self) -> u32 {
        self.open
    }

    /// Index of the node's `Close` event.
    pub const fn close_index(&self) -> u32 {
        self.close
    }
}

/// A structural problem in an event stream.
///
/// These are *our* bugs, not the input's: a well-formed parser never produces
/// one. They are values rather than panics anyway, because the substrate's
/// contract is that no input and no caller mistake takes the process down
/// (`REQ-SYN-2`), and because a partial tree plus a diagnostic is worth more to
/// a reverse engineer than an abort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// A marker was closed or abandoned while inner nodes were still open.
    ///
    /// Repaired by closing the inner nodes first, so the stream stays balanced;
    /// the tree that results is the one the parser would have got had it closed
    /// them itself.
    CloseOutOfOrder {
        /// Event index of the `Open` the caller named.
        named: u32,
        /// Event index of the `Open` that was actually innermost.
        innermost: u32,
        /// How many inner nodes had to be closed to reach the named one.
        unwound: u32,
    },
    /// An `Open` never reached a `Close`.
    UnclosedNode {
        /// Event index of the dangling `Open`.
        at: u32,
    },
    /// A `Close` had no `Open` to match.
    UnmatchedClose {
        /// Event index of the surplus `Close`.
        at: u32,
    },
}

impl Violation {
    /// A human-readable description, used as a diagnostic message.
    ///
    /// Spelled out here rather than at each call site so the wording is
    /// identical wherever a violation surfaces, which keeps the gates that
    /// diff diagnostic text stable (`REQ-SYN-5`).
    pub fn message(&self) -> String {
        match *self {
            Violation::CloseOutOfOrder {
                named,
                innermost,
                unwound,
            } => format!(
                "event stream: node opened at event {named} was closed while the node opened at \
                 event {innermost} was still open; {unwound} inner node(s) were closed to repair it"
            ),
            Violation::UnclosedNode { at } => {
                format!("event stream: node opened at event {at} was never closed")
            }
            Violation::UnmatchedClose { at } => {
                format!("event stream: close at event {at} has no matching open")
            }
        }
    }

    /// The violation as a [`Diagnostic`] at `span`.
    ///
    /// The span is supplied by the caller because an event carries no source
    /// position of its own --- only the tokens it refers to do --- and
    /// `REQ-SYN-7` wants every diagnostic to point somewhere. A caller with no
    /// better idea passes the span of the construct being parsed.
    pub fn to_diagnostic(&self, span: Span) -> Diagnostic {
        Diagnostic::error(span, self.message())
    }
}

/// The append-only event buffer a parser writes into.
///
/// It owns three things: the events themselves, the stack of `Open`s not yet
/// closed (so `close` can check nesting), and the violations found so far.
/// Everything is a `Vec`, so construction order is the only order there is and
/// identical input yields a byte-identical buffer (`REQ-SYN-5`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Events {
    events: Vec<Event>,
    open: Vec<u32>,
    violations: Vec<Violation>,
}

impl Events {
    /// The tag an abandoned node carries.
    ///
    /// `u16::MAX` is reserved by the substrate and must not be used as a
    /// language node kind. Abandoning a node that already has children cannot
    /// simply delete its `Open` --- that would shift every later event and
    /// invalidate every outstanding [`Marker`] --- so the `Open` stays put with
    /// this tag and no `Close` is ever emitted for it. [`drive`] skips it
    /// entirely, which reparents the abandoned node's children onto its parent,
    /// exactly as rust-analyzer's tombstone does.
    pub const TOMBSTONE_TAG: u16 = u16::MAX;

    /// An empty buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty buffer with room for `capacity` events.
    ///
    /// A parser knows roughly how many events a token buffer produces --- a few
    /// per token --- and pre-sizing keeps the hot path free of reallocation.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            events: Vec::with_capacity(capacity),
            open: Vec::new(),
            violations: Vec::new(),
        }
    }

    /// Adopt an event vector produced elsewhere.
    ///
    /// The buffer this returns has an empty open-stack, so it is a *finished*
    /// stream: use [`Events::validate`] to check it rather than the incremental
    /// checking `open`/`close` do. This exists for tests, for replaying a
    /// recorded stream, and for a parser that would rather emit events its own
    /// way and hand them over at the end.
    pub fn from_raw(events: Vec<Event>) -> Self {
        Self {
            events,
            open: Vec::new(),
            violations: Vec::new(),
        }
    }

    /// The events, in emission order.
    pub fn as_slice(&self) -> &[Event] {
        &self.events
    }

    /// The number of events emitted.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether no event has been emitted.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The event at `index`, or `None` if there is none.
    ///
    /// `Option` rather than a panicking index: an event index can come from a
    /// [`Marker`] that outlived the buffer it came from, and the substrate's
    /// answer to a bad handle is always "no", never an abort.
    pub fn get(&self, index: u32) -> Option<Event> {
        self.events.get(index as usize).copied()
    }

    /// How many nodes are open right now.
    ///
    /// This is the parser's nesting depth, which is what a depth bound
    /// (`REQ-SYN-4`) is checked against.
    pub fn depth(&self) -> usize {
        self.open.len()
    }

    /// The structural problems recorded while the buffer was being built.
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }

    /// Start a node with `tag`, returning the marker that will close it.
    ///
    /// The tag can be a placeholder: a parser that does not yet know what it is
    /// looking at opens with any tag it likes and rewrites it later with
    /// [`Events::patch`].
    pub fn open(&mut self, tag: u16) -> Marker {
        let pos = self.events.len() as u32;
        self.events.push(Event::Open { tag });
        self.open.push(pos);
        Marker { pos }
    }

    /// Consume `id` into the innermost open node.
    ///
    /// A token emitted with no node open is kept in the stream --- dropping
    /// events would make the buffer a lie --- and ignored by the tree sink,
    /// which has nowhere to put it.
    pub fn token(&mut self, id: TokenId) {
        self.events.push(Event::Token { id });
    }

    /// Record a problem at this point in the parse.
    ///
    /// The diagnostic itself lives in the parse's [`Diagnostics`]; the stream
    /// records only *where* it happened, so a sink can attach it to the node
    /// being built.
    pub fn error(&mut self, diag: DiagId) {
        self.events.push(Event::Error { diag });
    }

    /// Finish the node `marker` opened.
    ///
    /// If inner nodes are still open --- a parser bug, not an input problem ---
    /// they are closed first, a [`Violation::CloseOutOfOrder`] is recorded, and
    /// the stream stays balanced. The alternative, refusing to close, leaves a
    /// stream that no sink can consume, which turns one bug into a cascade.
    pub fn close(&mut self, marker: Marker) -> Closed {
        let unwound = self.unwind_to(marker.pos);
        for _ in 0..unwound {
            self.events.push(Event::Close);
        }
        let close = self.events.len() as u32;
        self.events.push(Event::Close);
        Closed {
            open: marker.pos,
            close,
        }
    }

    /// Turn the node `marker` opened into a no-op, keeping its children.
    ///
    /// This is the exit for a speculative parse that failed: the events already
    /// emitted stay where they are (so every other outstanding marker stays
    /// valid) and the node itself vanishes, its children becoming children of
    /// its parent. If the `Open` is still the last event --- the common case,
    /// nothing was parsed --- it is popped outright and the buffer is byte-for-
    /// byte as if `open` had never been called.
    pub fn abandon(&mut self, marker: Marker) {
        let unwound = self.unwind_to(marker.pos);
        for _ in 0..unwound {
            self.events.push(Event::Close);
        }
        if self.events.len() as u32 == marker.pos + 1 {
            self.events.pop();
            return;
        }
        if let Some(slot) = self.events.get_mut(marker.pos as usize) {
            *slot = Event::Open {
                tag: Self::TOMBSTONE_TAG,
            };
        }
    }

    /// Give up ownership of `marker` without closing or abandoning its node.
    ///
    /// The escape hatch for a parser that hands the closing responsibility to
    /// another routine through its own bookkeeping. It records nothing; if the
    /// node really is never closed, [`Events::validate`] reports it.
    pub fn forget(&self, marker: Marker) {
        let _ = marker;
    }

    /// Rewrite the tag of a node that is still open.
    ///
    /// The forward patch the design calls for: a parser that consumed a few
    /// tokens and only now knows whether it is looking at a declaration or an
    /// expression rewrites the `Open` it already emitted, instead of rewinding
    /// the token cursor and parsing the same text twice. Returns whether the
    /// patch landed, which is `false` only for a marker from a different
    /// buffer.
    pub fn patch(&mut self, marker: &Marker, tag: u16) -> bool {
        Self::patch_at(&mut self.events, marker.pos, tag)
    }

    /// Rewrite the tag of a node that has already been closed.
    ///
    /// Same motivation as [`Events::patch`], one step later: the grammar
    /// finished a unit and the token *after* it decided what the unit was.
    pub fn patch_closed(&mut self, closed: &Closed, tag: u16) -> bool {
        Self::patch_at(&mut self.events, closed.open, tag)
    }

    /// The tag currently recorded for an `Open` event, if `index` names one.
    ///
    /// A parser doing multi-step patching needs to read back what it wrote;
    /// returning `Option` rather than indexing keeps a stale index harmless.
    pub fn tag_at(&self, index: u32) -> Option<u16> {
        match self.events.get(index as usize) {
            Some(Event::Open { tag }) => Some(*tag),
            _ => None,
        }
    }

    /// Close every node still open, in innermost-first order.
    ///
    /// What a parser calls when it hits end of input with nodes on the stack:
    /// the result is a balanced stream describing a truncated but usable tree,
    /// plus one [`Violation::UnclosedNode`] per node it had to close. Returns
    /// how many it closed.
    pub fn close_all(&mut self) -> usize {
        let count = self.open.len();
        while let Some(pos) = self.open.pop() {
            self.violations.push(Violation::UnclosedNode { at: pos });
            self.events.push(Event::Close);
        }
        count
    }

    /// Every structural problem in the finished stream.
    ///
    /// Two sources, concatenated in that order: what was recorded while
    /// building (out-of-order closes, which a later scan cannot see because
    /// they were repaired), then a single forward scan for imbalance. The scan
    /// is what makes this meaningful for a stream from [`Events::from_raw`],
    /// which has no build history at all.
    pub fn validate(&self) -> Vec<Violation> {
        let mut found = self.violations.clone();
        let mut open: Vec<u32> = Vec::new();
        for (index, event) in self.events.iter().enumerate() {
            match event {
                Event::Open { tag } if *tag == Self::TOMBSTONE_TAG => {}
                Event::Open { .. } => open.push(index as u32),
                Event::Close => {
                    if open.pop().is_none() {
                        found.push(Violation::UnmatchedClose { at: index as u32 });
                    }
                }
                Event::Token { .. } | Event::Error { .. } => {}
            }
        }
        for pos in open {
            found.push(Violation::UnclosedNode { at: pos });
        }
        found
    }

    /// Push every structural problem into `diagnostics`, reported at `span`.
    ///
    /// Convenience for the common ending: validate, then hand the caller the
    /// `(product, diagnostics)` pair the error model requires. Returns how many
    /// diagnostics were added.
    pub fn report(&self, span: Span, diagnostics: &mut Diagnostics) -> usize {
        let found = self.validate();
        for violation in &found {
            diagnostics.push(violation.to_diagnostic(span));
        }
        found.len()
    }

    /// Rewrite the tag at `pos` if it names an `Open`.
    fn patch_at(events: &mut [Event], pos: u32, tag: u16) -> bool {
        match events.get_mut(pos as usize) {
            Some(Event::Open { tag: slot }) => {
                *slot = tag;
                true
            }
            _ => false,
        }
    }

    /// Pop the open-stack down to `pos`, returning how many inner nodes the
    /// caller must now close, and recording a violation if there were any.
    ///
    /// Returns `0` when `pos` is not on the stack at all, which is the
    /// "marker from another buffer" case: nothing is unwound and nothing is
    /// corrupted, and the surplus `Close` the caller goes on to emit is caught
    /// by [`Events::validate`].
    fn unwind_to(&mut self, pos: u32) -> u32 {
        let Some(depth) = self.open.iter().rposition(|&open| open == pos) else {
            return 0;
        };
        let unwound = (self.open.len() - depth - 1) as u32;
        if unwound > 0 {
            let innermost = self.open.last().copied().unwrap_or(pos);
            self.violations.push(Violation::CloseOutOfOrder {
                named: pos,
                innermost,
                unwound,
            });
        }
        self.open.truncate(depth);
        unwound
    }
}

/// A consumer of an event stream.
///
/// The whole point of the indirection: the parser writes one buffer and every
/// consumer that wants something different --- a tree, a census, a control-flow
/// graph --- reads it without the parser knowing they exist. A sink sees a
/// *balanced* stream because [`drive`] repairs imbalance before forwarding, so
/// an implementation may assume every `close` matches an earlier `open` and
/// still must not panic if it does not.
pub trait Sink {
    /// Start a node with a language-defined tag.
    fn open(&mut self, tag: u16);

    /// Consume a token into the innermost open node.
    fn token(&mut self, id: TokenId);

    /// Finish the innermost open node.
    fn close(&mut self);

    /// Note a recorded problem at this point.
    ///
    /// Defaulted to a no-op: most sinks do not care where the errors were, and
    /// making them all write an empty method would be noise.
    fn error(&mut self, diag: DiagId) {
        let _ = diag;
    }
}

/// Feed `events` to `sink`, repairing imbalance and reporting it.
///
/// The one place that knows the stream's structural rules, so no sink has to:
///
/// * a tombstone `Open` (see [`Events::TOMBSTONE_TAG`]) is skipped, which
///   reparents an abandoned node's children onto its parent;
/// * a `Close` with nothing open is dropped with a diagnostic, rather than
///   being forwarded to a sink that would have to guess what to do;
/// * nodes still open at the end are closed with a diagnostic.
///
/// Every problem becomes a diagnostic at `span` and none becomes a panic
/// (`REQ-SYN-2`). Returns how many diagnostics were added. The walk is a `for`
/// loop over a slice: no recursion, so a stream a hundred thousand nodes deep
/// costs heap, not stack (`REQ-SYN-3`).
pub fn drive<S: Sink + ?Sized>(
    events: &[Event],
    sink: &mut S,
    span: Span,
    diagnostics: &mut Diagnostics,
) -> usize {
    let mut depth: usize = 0;
    let mut reported = 0usize;
    for (index, event) in events.iter().enumerate() {
        match *event {
            Event::Open { tag } if tag == Events::TOMBSTONE_TAG => {}
            Event::Open { tag } => {
                sink.open(tag);
                depth += 1;
            }
            Event::Token { id } => sink.token(id),
            Event::Close => {
                if depth == 0 {
                    diagnostics
                        .push(Violation::UnmatchedClose { at: index as u32 }.to_diagnostic(span));
                    reported += 1;
                } else {
                    sink.close();
                    depth -= 1;
                }
            }
            Event::Error { diag } => sink.error(diag),
        }
    }
    if depth > 0 {
        diagnostics.push(Diagnostic::error(
            span,
            format!("event stream: {depth} node(s) were still open at the end of the stream"),
        ));
        reported += 1;
        for _ in 0..depth {
            sink.close();
        }
    }
    reported
}

/// A sink that counts and measures without building anything.
///
/// The second implementation of [`Sink`], and it exists to earn the trait
/// rather than to decorate it: it answers "how many nodes of each kind, how
/// deep, how many tokens" in one pass with no arena, no child lists and no
/// per-node allocation --- which is what a size report, a fuzzing oracle or a
/// "does this file contain any function at all" probe actually wants. If the
/// only sink were the tree builder, the indirection would be unjustified.
///
/// The per-tag counts are a `BTreeMap`, not a `HashMap`, because they are
/// reported and `REQ-SYN-5` makes report order a promise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TagCensus {
    by_tag: BTreeMap<u16, u32>,
    nodes: u32,
    tokens: u32,
    errors: u32,
    depth: usize,
    max_depth: usize,
}

impl TagCensus {
    /// An empty census.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many nodes the stream opened.
    pub fn nodes(&self) -> u32 {
        self.nodes
    }

    /// How many tokens the stream consumed.
    pub fn tokens(&self) -> u32 {
        self.tokens
    }

    /// How many `Error` events the stream carried.
    pub fn errors(&self) -> u32 {
        self.errors
    }

    /// The deepest nesting the stream reached.
    ///
    /// The cheapest possible check that a grammar is not producing the
    /// adversarially nested shapes `REQ-SYN-3` and `REQ-SYN-4` are about ---
    /// available without building a tree to measure.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// How many nodes carried `tag`.
    pub fn count(&self, tag: u16) -> u32 {
        self.by_tag.get(&tag).copied().unwrap_or(0)
    }

    /// Every tag seen, with its count, in ascending tag order.
    pub fn counts(&self) -> impl Iterator<Item = (u16, u32)> + '_ {
        self.by_tag.iter().map(|(tag, count)| (*tag, *count))
    }
}

impl Sink for TagCensus {
    fn open(&mut self, tag: u16) {
        self.nodes = self.nodes.saturating_add(1);
        let entry = self.by_tag.entry(tag).or_insert(0);
        *entry = entry.saturating_add(1);
        self.depth += 1;
        if self.depth > self.max_depth {
            self.max_depth = self.depth;
        }
    }

    fn token(&mut self, id: TokenId) {
        let _ = id;
        self.tokens = self.tokens.saturating_add(1);
    }

    fn close(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn error(&mut self, diag: DiagId) {
        let _ = diag;
        self.errors = self.errors.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tags used by the tests, standing in for a language's node kinds.
    const ROOT: u16 = 1;
    const DECL: u16 = 2;
    const EXPR: u16 = 3;

    fn events_for_a_two_level_tree() -> Events {
        let mut events = Events::new();
        let root = events.open(ROOT);
        let inner = events.open(DECL);
        events.token(TokenId::new(0));
        events.close(inner);
        events.token(TokenId::new(1));
        events.close(root);
        events
    }

    #[test]
    fn a_balanced_stream_records_exactly_the_events_the_parser_emitted() {
        let events = events_for_a_two_level_tree();
        assert_eq!(
            events.as_slice(),
            &[
                Event::Open { tag: ROOT },
                Event::Open { tag: DECL },
                Event::Token {
                    id: TokenId::new(0)
                },
                Event::Close,
                Event::Token {
                    id: TokenId::new(1)
                },
                Event::Close,
            ]
        );
        assert!(events.validate().is_empty());
        assert_eq!(events.depth(), 0);
    }

    #[test]
    fn forward_patching_rewrites_an_open_that_is_still_on_the_stack() {
        let mut events = Events::new();
        let marker = events.open(EXPR);
        events.token(TokenId::new(0));
        assert_eq!(events.tag_at(marker.event_index()), Some(EXPR));
        assert!(events.patch(&marker, DECL));
        assert_eq!(events.tag_at(marker.event_index()), Some(DECL));
        events.close(marker);
        assert_eq!(events.as_slice()[0], Event::Open { tag: DECL });
    }

    #[test]
    fn forward_patching_rewrites_a_node_that_is_already_closed() {
        let mut events = Events::new();
        let marker = events.open(EXPR);
        let closed = events.close(marker);
        assert!(events.patch_closed(&closed, DECL));
        assert_eq!(events.as_slice()[0], Event::Open { tag: DECL });
        assert_eq!(closed.open_index(), 0);
        assert_eq!(closed.close_index(), 1);
    }

    #[test]
    fn patching_a_marker_from_another_buffer_reports_failure_rather_than_panicking() {
        let mut donor = Events::new();
        let marker = donor.open(ROOT);
        let mut empty = Events::new();
        assert!(!empty.patch(&marker, DECL));
        assert_eq!(empty.tag_at(9_999), None);
        donor.close(marker);
    }

    #[test]
    fn abandoning_a_childless_node_leaves_the_buffer_as_if_it_never_opened() {
        let mut events = Events::new();
        let outer = events.open(ROOT);
        events.token(TokenId::new(0));
        let speculative = events.open(EXPR);
        events.abandon(speculative);
        events.close(outer);
        assert_eq!(
            events.as_slice(),
            &[
                Event::Open { tag: ROOT },
                Event::Token {
                    id: TokenId::new(0)
                },
                Event::Close,
            ]
        );
        assert!(events.validate().is_empty());
    }

    #[test]
    fn abandoning_a_node_with_children_tombstones_it_and_keeps_every_marker_valid() {
        let mut events = Events::new();
        let outer = events.open(ROOT);
        let speculative = events.open(EXPR);
        let kept = events.open(DECL);
        events.token(TokenId::new(0));
        events.close(kept);
        events.abandon(speculative);
        events.close(outer);

        assert_eq!(
            events.as_slice()[1],
            Event::Open {
                tag: Events::TOMBSTONE_TAG
            }
        );
        assert!(events.validate().is_empty(), "a tombstone needs no close");

        let mut census = TagCensus::new();
        let mut diagnostics = Diagnostics::new();
        drive(
            events.as_slice(),
            &mut census,
            Span::default(),
            &mut diagnostics,
        );
        assert_eq!(census.nodes(), 2, "the abandoned node is not a node");
        assert_eq!(census.count(EXPR), 0);
        assert_eq!(census.count(DECL), 1);
        assert_eq!(census.max_depth(), 2, "the child reparented onto the root");
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn abandoning_out_of_order_closes_the_inner_nodes_and_records_a_violation() {
        let mut events = Events::new();
        let outer = events.open(ROOT);
        let inner = events.open(DECL);
        events.token(TokenId::new(0));
        events.abandon(outer);
        assert!(matches!(
            events.violations(),
            [Violation::CloseOutOfOrder {
                named: 0,
                innermost: 1,
                unwound: 1
            }]
        ));
        assert_eq!(events.depth(), 0);
        events.forget(inner);
        let scan = events.validate();
        assert_eq!(scan.len(), 1, "only the recorded violation, no imbalance");
    }

    #[test]
    fn closing_out_of_order_unwinds_to_the_named_marker_and_stays_balanced() {
        let mut events = Events::new();
        let outer = events.open(ROOT);
        let inner = events.open(DECL);
        events.token(TokenId::new(0));
        events.close(outer);
        events.forget(inner);

        assert!(matches!(
            events.violations(),
            [Violation::CloseOutOfOrder {
                named: 0,
                innermost: 1,
                unwound: 1
            }]
        ));
        let mut open = 0i32;
        for event in events.as_slice() {
            match event {
                Event::Open { .. } => open += 1,
                Event::Close => open -= 1,
                _ => {}
            }
            assert!(open >= 0);
        }
        assert_eq!(open, 0, "the repair left the stream balanced");
    }

    #[test]
    fn close_all_closes_every_dangling_node_and_names_each_one() {
        let mut events = Events::new();
        let a = events.open(ROOT);
        let b = events.open(DECL);
        events.token(TokenId::new(0));
        assert_eq!(events.close_all(), 2);
        assert_eq!(events.depth(), 0);
        assert!(matches!(
            events.violations(),
            [
                Violation::UnclosedNode { at: 1 },
                Violation::UnclosedNode { at: 0 }
            ]
        ));
        events.forget(a);
        events.forget(b);
    }

    #[test]
    fn validate_finds_an_unclosed_node_in_a_stream_built_elsewhere() {
        let events = Events::from_raw(vec![
            Event::Open { tag: ROOT },
            Event::Token {
                id: TokenId::new(0),
            },
        ]);
        assert_eq!(events.validate(), vec![Violation::UnclosedNode { at: 0 }]);
    }

    #[test]
    fn validate_finds_a_surplus_close_in_a_stream_built_elsewhere() {
        let events = Events::from_raw(vec![Event::Open { tag: ROOT }, Event::Close, Event::Close]);
        assert_eq!(events.validate(), vec![Violation::UnmatchedClose { at: 2 }]);
    }

    #[test]
    fn an_unbalanced_stream_yields_diagnostics_and_never_panics() {
        let raw = vec![
            Event::Close,
            Event::Open { tag: ROOT },
            Event::Token {
                id: TokenId::new(0),
            },
            Event::Close,
            Event::Close,
            Event::Open { tag: DECL },
        ];
        let mut census = TagCensus::new();
        let mut diagnostics = Diagnostics::new();
        let reported = drive(&raw, &mut census, Span::new(4, 9), &mut diagnostics);
        assert_eq!(reported, 3, "two surplus closes and one dangling open");
        assert_eq!(diagnostics.len(), 3);
        assert!(diagnostics.has_errors());
        assert_eq!(census.nodes(), 2);
    }

    #[test]
    fn report_pushes_one_diagnostic_per_violation_at_the_span_it_is_given() {
        let events = Events::from_raw(vec![Event::Open { tag: ROOT }, Event::Close, Event::Close]);
        let mut diagnostics = Diagnostics::new();
        assert_eq!(events.report(Span::new(1, 2), &mut diagnostics), 1);
        let first = diagnostics.get(DiagId::new(0)).expect("pushed one");
        assert_eq!(first.span, Span::new(1, 2));
        assert!(first.message.contains("no matching open"));
    }

    #[test]
    fn a_census_counts_by_tag_in_ascending_tag_order() {
        let mut events = Events::new();
        let root = events.open(ROOT);
        for _ in 0..3 {
            let decl = events.open(DECL);
            events.token(TokenId::new(0));
            events.close(decl);
        }
        let expr = events.open(EXPR);
        events.error(DiagId::new(0));
        events.close(expr);
        events.close(root);

        let mut census = TagCensus::new();
        let mut diagnostics = Diagnostics::new();
        drive(
            events.as_slice(),
            &mut census,
            Span::default(),
            &mut diagnostics,
        );
        let counts: Vec<(u16, u32)> = census.counts().collect();
        assert_eq!(counts, vec![(ROOT, 1), (DECL, 3), (EXPR, 1)]);
        assert_eq!(census.tokens(), 3);
        assert_eq!(census.errors(), 1);
        assert_eq!(census.max_depth(), 2);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn driving_a_hundred_thousand_deep_stream_does_not_touch_the_native_stack() {
        const DEPTH: usize = 100_000;
        let mut raw = Vec::with_capacity(DEPTH * 2);
        for _ in 0..DEPTH {
            raw.push(Event::Open { tag: DECL });
        }
        raw.extend(std::iter::repeat_n(Event::Close, DEPTH));
        let mut census = TagCensus::new();
        let mut diagnostics = Diagnostics::new();
        assert_eq!(
            drive(&raw, &mut census, Span::default(), &mut diagnostics),
            0
        );
        assert_eq!(census.max_depth(), DEPTH);
        assert_eq!(census.nodes(), DEPTH as u32);
    }

    #[test]
    fn the_same_stream_drives_two_different_sinks_to_the_same_shape() {
        let events = events_for_a_two_level_tree();
        let mut first = TagCensus::new();
        let mut second = TagCensus::new();
        let mut diagnostics = Diagnostics::new();
        drive(
            events.as_slice(),
            &mut first,
            Span::default(),
            &mut diagnostics,
        );
        drive(
            events.as_slice(),
            &mut second,
            Span::default(),
            &mut diagnostics,
        );
        assert_eq!(first, second, "driving is deterministic");
    }

    #[test]
    fn a_boxed_sink_still_works_so_the_trait_is_usable_dynamically() {
        let events = events_for_a_two_level_tree();
        let mut sink: Box<dyn Sink> = Box::new(TagCensus::new());
        let mut diagnostics = Diagnostics::new();
        drive(
            events.as_slice(),
            sink.as_mut(),
            Span::default(),
            &mut diagnostics,
        );
        assert!(diagnostics.is_empty());
    }
}
