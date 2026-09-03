//! `SB-3` --- the struct-of-arrays token buffer and its cursor.
//!
//! Spec: `docs/design/source-front-ends/substrate.md` sections 2.1 and 7.
//!
//! # Why two vectors instead of one
//!
//! A token here is a `u16` tag plus a `u32` byte offset. As an array of structs
//! that pair costs 8 bytes: `u32` wants 4-byte alignment, so `(u16, u32)` is
//! padded by 2. As two parallel vectors it costs `2 + 4 = 6`, because per-field
//! alignment padding has nowhere to live. That is a 25% cut for this field set,
//! and the test `struct_of_arrays_beats_the_array_of_structs_control` measures
//! it on real vectors rather than trusting the arithmetic. It is also the shape
//! the Zig compiler settled on (`token_tags` alongside `token_starts`), for the
//! same two stated reasons: fewer wasted bytes, and better locality in the
//! parser's hot loop, which reads tags far more often than offsets.
//!
//! The trade is real and worth stating: reading "the whole token" now touches
//! two cache lines instead of one. That is the wrong trade for a debugger
//! walking tokens one at a time and the right one for a parser scanning tags.
//!
//! # Why a token's length is not stored
//!
//! It is implicit: `starts[i + 1] - starts[i]`. Dropping the length is what
//! keeps a token at 6 bytes, but it means **the last real token cannot be
//! measured without a following entry**. So a `Tokens` always ends with a
//! sentinel entry whose start is the end of the input. Every constructor path
//! goes through [`TokensBuilder::finish`], which appends it, so a `Tokens`
//! without its sentinel cannot be built --- see [`Tokens::EOF`].
//!
//! # What the implicit length actually measures
//!
//! Read the previous paragraph carefully, because the consequence is easy to
//! miss and expensive to discover later: `starts[i + 1] - starts[i]` is the
//! distance to the **next token**, not the length of token `i`'s lexeme. Those
//! are the same number only when tokens are contiguous. They are not, because
//! trivia is discarded (below), so a token's span runs from its first byte up to
//! the start of the next token and therefore **includes any whitespace or
//! comment that follows it**.
//!
//! The substrate cannot trim that, and the reason is `REQ-SYN-1`: deciding
//! where the lexeme ends and the trivia begins requires knowing what trivia
//! *is*, which is a language rule. Zig, the compiler this shape is taken from,
//! hits the same wall and solves it language-specifically --- its `tokenSlice`
//! uses the tag's fixed lexeme length for keywords and punctuation and
//! otherwise re-runs the tokenizer from the stored offset. A front end here has
//! the same two options, and either is a few lines at the call site:
//!
//! * trim [`Tokens::text`] with its own trivia predicate, or
//! * derive the length from the tag where the tag fixes it.
//!
//! What the buffer does guarantee is the whole-file property `SB-3` asks for:
//! the token texts concatenated, in order, reproduce the source exactly from
//! the first token's offset onward. Nothing is lost; it is attributed to the
//! preceding token instead of to a trivia entry.
//!
//! # Why trivia is discarded
//!
//! Whitespace and comments are **not** stored. This is the deliberate
//! divergence from `rowan`, whose lossless green tree keeps every byte so an
//! IDE can re-emit the source it parsed. Our consumers lower to LLIR and never
//! re-emit source, so trivia would be bytes with no reader --- roughly half the
//! entries in a typical C file, paid for on every parse. `REQ-SYN-9` records
//! the exit if that ever stops being true: retain trivia in a parallel array
//! keyed by token index, or adopt `rowan`. Neither is implied by anything
//! planned, and neither is pre-empted by this file.
//!
//! # Language neutrality
//!
//! `REQ-SYN-1`. Nothing here names a token kind, keyword or grammar rule of any
//! language. A `kind` is an opaque `u16` a front end supplies and the substrate
//! never interprets --- with the single reserved exception documented on
//! [`Tokens::EOF`].

use crate::syntax::ids::{Span, TokenId};

/// A finished, immutable token buffer: parallel tag and offset vectors.
///
/// Construct one with [`TokensBuilder`]. There is no public way to build a
/// `Tokens` that lacks its terminating sentinel, because a buffer without one
/// silently reports the wrong length for its last token --- the one bug this
/// representation invites.
///
/// # Invariants
///
/// * `kinds.len() == starts.len()`;
/// * `kinds.len() >= 1` --- the sentinel is always present;
/// * the final entry has kind [`Tokens::EOF`] and start equal to the end of the
///   input.
///
/// Nothing here requires `starts` to be sorted. A front end that emits
/// out-of-order offsets gets empty spans rather than an underflow, because
/// [`Span::new`] clamps a reversed pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokens {
    /// Language-defined tag per token, plus one [`Tokens::EOF`] sentinel.
    kinds: Vec<u16>,
    /// Byte offset into the `SourceFile` per token, plus the end of input.
    starts: Vec<u32>,
}

impl Tokens {
    /// The one token kind the substrate reserves for itself: the sentinel that
    /// terminates every buffer.
    ///
    /// **A language front end must never emit this value as a real token kind.**
    /// Avoiding it is free in practice: front ends number their kinds densely
    /// from zero (a `#[repr(u16)]` enum cast, or a generated table), so the top
    /// of the space is unreachable long before it is contended --- no real
    /// grammar has 65,535 distinct kinds. Reserving the *top* rather than zero
    /// is what makes that true; zero is the value a naive `Default` or a
    /// zero-initialized table produces.
    ///
    /// [`TokensBuilder::push`] enforces the reservation without panicking
    /// (`REQ-SYN-2`) by clamping to [`Tokens::MAX_KIND`]. The clamp direction is
    /// chosen deliberately: a stray tag can only ever be confused with another
    /// real tag, never with end-of-input, so it can never truncate a parse.
    pub const EOF: u16 = u16::MAX;

    /// The largest tag a language front end may use, one below [`Tokens::EOF`].
    pub const MAX_KIND: u16 = u16::MAX - 1;

    /// The buffer for an empty input: no real tokens, sentinel at offset 0.
    ///
    /// Provided so callers that short-circuit before lexing (an unreadable
    /// file, a zero-length translation unit) still hand downstream code a
    /// well-formed buffer rather than an `Option`.
    pub fn empty() -> Self {
        TokensBuilder::new().finish(0)
    }

    /// The number of **real** tokens, excluding the sentinel.
    ///
    /// This is the number a parser should reason about; the sentinel is an
    /// implementation device for measuring the last token, not a token.
    pub fn len(&self) -> usize {
        // The invariant guarantees at least the sentinel, but saturating_sub
        // keeps this total even if a future edit breaks that.
        self.kinds.len().saturating_sub(1)
    }

    /// Whether the buffer holds no real tokens.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The id of the sentinel entry --- one past the last real token.
    ///
    /// A cursor that runs off the end parks here, and every out-of-range
    /// accessor answers as if asked about this id.
    pub fn eof_id(&self) -> TokenId {
        TokenId::new(self.len() as u32)
    }

    /// The byte offset the input ends at, which is the sentinel's start.
    pub fn end_of_input(&self) -> u32 {
        // `last()` cannot be `None` given the invariant; the fallback keeps the
        // function total rather than relying on it.
        self.starts.last().copied().unwrap_or(0)
    }

    /// The tag of `id`, or [`Tokens::EOF`] if `id` is out of range.
    ///
    /// **Out-of-range access clamps; it never panics and never returns
    /// `Option`.** The choice is deliberate: a parser that reads past the end is
    /// buggy, but under `REQ-SYN-2` that bug must surface as a diagnostic from a
    /// parser that saw end-of-input, not as an abort or as an `Option` every
    /// call site would unwrap anyway. Clamping makes overrun behave exactly like
    /// reaching the end, which is the case every parser already handles.
    pub fn kind(&self, id: TokenId) -> u16 {
        self.kinds.get(id.index()).copied().unwrap_or(Self::EOF)
    }

    /// The start offset of `id`, clamped to the end of input when out of range.
    pub fn start(&self, id: TokenId) -> u32 {
        self.starts
            .get(id.index())
            .copied()
            .unwrap_or_else(|| self.end_of_input())
    }

    /// The span of `id`: from its own offset up to the **next token's** offset.
    ///
    /// Because trivia is not stored, that upper bound is not the end of the
    /// lexeme --- it is the start of whatever comes next, so trailing
    /// whitespace and comments fall inside the span. See the module docs; the
    /// substrate cannot narrow it without knowing what trivia is (`REQ-SYN-1`).
    /// For a diagnostic caret this is usually fine and always safe; for an
    /// identifier's text a front end trims with its own predicate.
    ///
    /// The sentinel and any out-of-range id yield the empty span at the end of
    /// input (`REQ-SYN-7`: a position, but no extent --- the same shape
    /// [`Span::empty_at`] gives a parser-inserted token).
    pub fn span(&self, id: TokenId) -> Span {
        let lo = self.start(id);
        match self.starts.get(id.index() + 1).copied() {
            Some(hi) => Span::new(lo, hi),
            None => Span::empty_at(lo),
        }
    }

    /// The source text of [`Tokens::span`] for `id`, as a borrow of `src`.
    ///
    /// This is the token **and any trivia up to the next token**, for the reason
    /// given on [`Tokens::span`]. Concatenating this over every id from 0 to
    /// `len()` reproduces `src` from the first token's offset onward, which is
    /// the corpus round-trip `SB-3` specifies; a caller that wants the bare
    /// lexeme trims the result with its own trivia predicate.
    ///
    /// `src` must be the file the offsets were produced from. If it is not ---
    /// a truncated buffer, or a different file --- this returns the largest
    /// valid prefix of the requested range rather than panicking: the range is
    /// clamped into `src` and then walked back to UTF-8 character boundaries,
    /// at most three bytes on each side. A range that survives none of that
    /// yields `""`. `str` indexing is the one operation in this file that would
    /// otherwise panic on a mismatch, so it is the one guarded here.
    pub fn text<'a>(&self, id: TokenId, src: &'a str) -> &'a str {
        let span = self.span(id);
        let mut lo = (span.lo as usize).min(src.len());
        let mut hi = (span.hi as usize).min(src.len());
        if hi < lo {
            hi = lo;
        }
        // Each loop runs at most three times: a UTF-8 boundary is never more
        // than three bytes away. No recursion (`REQ-SYN-3`).
        while lo > 0 && !src.is_char_boundary(lo) {
            lo -= 1;
        }
        while hi > lo && !src.is_char_boundary(hi) {
            hi -= 1;
        }
        src.get(lo..hi).unwrap_or("")
    }

    /// The tag vector, for a scan that reads tags and nothing else.
    ///
    /// Exposed because the whole point of the representation is that such a
    /// scan touches one contiguous run of `u16`s. The slice includes the
    /// trailing [`Tokens::EOF`] sentinel.
    pub fn kinds(&self) -> &[u16] {
        &self.kinds
    }

    /// The offset vector, including the trailing end-of-input entry.
    pub fn starts(&self) -> &[u32] {
        &self.starts
    }

    /// A cursor positioned at the first token.
    pub fn cursor(&self) -> Cursor<'_> {
        Cursor {
            tokens: self,
            pos: 0,
        }
    }
}

/// The only way to build a [`Tokens`].
///
/// A distinct type, rather than `push`/`finish` on `Tokens` itself, so that the
/// sentinel invariant is enforced by the type system: [`finish`](Self::finish)
/// consumes the builder and is the sole constructor of `Tokens`, so no
/// half-built buffer can escape a lexer that returned early.
#[derive(Debug, Clone, Default)]
pub struct TokensBuilder {
    kinds: Vec<u16>,
    starts: Vec<u32>,
}

impl TokensBuilder {
    /// An empty builder.
    pub fn new() -> Self {
        Self {
            kinds: Vec::new(),
            starts: Vec::new(),
        }
    }

    /// An empty builder with room for `capacity` tokens plus the sentinel.
    ///
    /// A lexer knows roughly how many tokens a file of `n` bytes yields, and
    /// reserving once is the difference between one allocation per vector and
    /// a dozen.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            kinds: Vec::with_capacity(capacity + 1),
            starts: Vec::with_capacity(capacity + 1),
        }
    }

    /// Push one token onto the buffer: language-defined tag `kind`, starting
    /// at byte `start`.
    ///
    /// `kind` is clamped to [`Tokens::MAX_KIND`], so a front end cannot
    /// accidentally fabricate an end-of-input marker in the middle of a buffer.
    /// See [`Tokens::EOF`] for why this is unreachable for a real grammar and
    /// why the clamp goes this direction.
    ///
    /// Offsets are stored exactly as given. Nothing checks that they ascend;
    /// a descending pair produces an empty span, not an underflow.
    pub fn push(&mut self, kind: u16, start: u32) {
        self.kinds.push(kind.min(Tokens::MAX_KIND));
        self.starts.push(start);
    }

    /// The number of tokens pushed so far.
    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    /// Whether nothing has been pushed yet.
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// Append the terminating sentinel and freeze the buffer.
    ///
    /// `end_of_input` is the length of the source text. It becomes the sentinel
    /// entry's start, which is what gives the **last real token its length**:
    /// without it, `starts[i + 1]` for the final `i` does not exist. Passing a
    /// value below the last token's start is not an error and does not panic;
    /// [`Span::new`] clamps, so that token ends up empty.
    pub fn finish(mut self, end_of_input: u32) -> Tokens {
        self.kinds.push(Tokens::EOF);
        self.starts.push(end_of_input);
        Tokens {
            kinds: self.kinds,
            starts: self.starts,
        }
    }
}

/// A cursor into a [`Tokens`]: a position, plus the lookahead and
/// backtracking a recursive-descent parser needs.
///
/// Every operation is O(1) and allocation-free: the cursor is two words, and
/// cloning it is how you take a checkpoint.
///
/// Past the last real token the cursor parks on the sentinel: [`peek`](Self::peek)
/// returns [`Tokens::EOF`] forever and [`bump`](Self::bump) stops advancing.
/// A parser that reads off the end is buggy, but it must produce a diagnostic
/// rather than abort (`REQ-SYN-2`), and it cannot do that from a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor<'a> {
    tokens: &'a Tokens,
    /// Index of the current token; never exceeds the sentinel's index.
    pos: u32,
}

impl<'a> Cursor<'a> {
    /// A cursor at the first token of `tokens`.
    pub fn new(tokens: &'a Tokens) -> Self {
        Self { tokens, pos: 0 }
    }

    /// The buffer being read.
    pub fn tokens(&self) -> &'a Tokens {
        self.tokens
    }

    /// The tag under the cursor, or [`Tokens::EOF`] at or past the end.
    pub fn peek(&self) -> u16 {
        self.tokens.kind(self.current())
    }

    /// The tag `n` tokens ahead, or [`Tokens::EOF`] if that is past the end.
    ///
    /// `peek_at(0)` is [`peek`](Self::peek). The addition saturates, so an
    /// absurd lookahead reads end-of-input rather than wrapping.
    pub fn peek_at(&self, n: u32) -> u16 {
        self.tokens.kind(TokenId::new(self.pos.saturating_add(n)))
    }

    /// The id under the cursor, clamped to the sentinel at the end.
    pub fn current(&self) -> TokenId {
        TokenId::new(self.pos)
    }

    /// The span under the cursor, empty at the end of input.
    ///
    /// Convenience for the common case of attaching a diagnostic to whatever
    /// the parser is looking at (`REQ-SYN-7`).
    pub fn span(&self) -> Span {
        self.tokens.span(self.current())
    }

    /// Consume the current token and return its id.
    ///
    /// At the end of input this returns the sentinel id and does not advance,
    /// so a parser loop that forgets to check [`is_eof`](Self::is_eof) spins on
    /// a stable position instead of running the index off into overflow. The
    /// spin is a parser bug, but a detectable one --- the position stops moving
    /// --- rather than a memory error or an abort.
    pub fn bump(&mut self) -> TokenId {
        let id = self.current();
        if (self.pos as usize) < self.tokens.len() {
            self.pos += 1;
        }
        id
    }

    /// Whether the current tag is `kind`.
    pub fn at(&self, kind: u16) -> bool {
        self.peek() == kind
    }

    /// Consume the current token if its tag is `kind`; report whether it did.
    pub fn eat(&mut self, kind: u16) -> bool {
        if self.at(kind) {
            self.bump();
            true
        } else {
            false
        }
    }

    /// The current index, for a checkpoint.
    pub fn pos(&self) -> u32 {
        self.pos
    }

    /// Restore a checkpoint taken with [`pos`](Self::pos).
    ///
    /// Backtracking is a position assignment and nothing else --- there is no
    /// state to unwind, which is most of why the token buffer is a flat array.
    /// A position past the sentinel is clamped to the sentinel rather than
    /// rejected, so a stale checkpoint from a different (longer) buffer degrades
    /// to end-of-input instead of panicking.
    pub fn set_pos(&mut self, pos: u32) {
        let eof = self.tokens.len() as u32;
        self.pos = pos.min(eof);
    }

    /// Whether the cursor has consumed every real token.
    pub fn is_eof(&self) -> bool {
        self.pos as usize >= self.tokens.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    /// `let x = 1;` split the way a C-family lexer would, trivia dropped.
    fn sample() -> (&'static str, Tokens) {
        //         0123456789
        let src = "let x = 1;";
        let mut b = TokensBuilder::new();
        b.push(1, 0); // "let"
        b.push(2, 4); // "x"
        b.push(3, 6); // "="
        b.push(4, 8); // "1"
        b.push(5, 9); // ";"
        (src, b.finish(src.len() as u32))
    }

    #[test]
    fn an_empty_buffer_still_carries_its_sentinel() {
        let tokens = Tokens::empty();
        assert_eq!(tokens.len(), 0);
        assert!(tokens.is_empty());
        assert_eq!(tokens.kinds().len(), 1, "the sentinel is not a token");
        assert_eq!(tokens.kind(tokens.eof_id()), Tokens::EOF);
        assert!(tokens.cursor().is_eof());
    }

    #[test]
    fn a_single_tokens_span_covers_it_exactly() {
        let src = "return";
        let mut b = TokensBuilder::new();
        b.push(7, 0);
        let tokens = b.finish(src.len() as u32);

        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens.span(TokenId::new(0)), Span::new(0, 6));
        assert_eq!(tokens.text(TokenId::new(0), src), "return");
    }

    #[test]
    fn the_last_tokens_length_comes_from_the_sentinel() {
        let (src, tokens) = sample();
        let last = TokenId::new(tokens.len() as u32 - 1);
        assert_eq!(tokens.span(last), Span::new(9, 10));
        assert_eq!(tokens.text(last, src), ";");
        assert_eq!(
            tokens.end_of_input(),
            src.len() as u32,
            "the sentinel start is what makes the last span measurable"
        );
    }

    #[test]
    fn text_round_trips_every_token_of_a_small_input() {
        let (src, tokens) = sample();
        let joined: String = (0..tokens.len())
            .map(|i| tokens.text(TokenId::new(i as u32), src))
            .collect();
        assert_eq!(joined, src, "the texts tile the source with no gap");
    }

    #[test]
    fn a_tokens_extent_runs_to_the_next_token_and_so_carries_its_trivia() {
        // This is the consequence of storing starts and no lengths, and it is
        // the thing to get wrong: the "length" is a distance to the next token,
        // and with trivia discarded that distance includes the trivia.
        let (src, tokens) = sample();
        let extents: Vec<&str> = (0..tokens.len())
            .map(|i| tokens.text(TokenId::new(i as u32), src))
            .collect();
        assert_eq!(extents, ["let ", "x ", "= ", "1", ";"]);

        // A front end recovers the bare lexeme with its own trivia predicate;
        // the substrate may not, because "what is whitespace" is a language
        // rule (`REQ-SYN-1`).
        let lexemes: Vec<&str> = extents
            .iter()
            .map(|t| t.trim_end_matches([' ', '\t', '\n']))
            .collect();
        assert_eq!(lexemes, ["let", "x", "=", "1", ";"]);
    }

    #[test]
    fn leading_trivia_is_the_only_source_text_no_token_accounts_for() {
        let src = "  /* c */ a b";
        let mut b = TokensBuilder::new();
        b.push(1, 10); // "a", after the comment
        b.push(1, 12); // "b"
        let tokens = b.finish(src.len() as u32);

        let joined: String = (0..tokens.len())
            .map(|i| tokens.text(TokenId::new(i as u32), src))
            .collect();
        assert_eq!(joined, "a b");
        assert_eq!(joined, &src[10..], "everything from the first token onward");
    }

    #[test]
    fn the_cursor_peeks_bumps_eats_and_backtracks() {
        let (_, tokens) = sample();
        let mut c = tokens.cursor();

        assert_eq!(c.peek(), 1);
        assert_eq!(c.peek_at(2), 3);
        assert!(c.at(1));
        assert!(!c.at(2));

        let checkpoint = c.pos();
        assert_eq!(c.bump(), TokenId::new(0));
        assert_eq!(c.peek(), 2);
        assert!(c.eat(2), "eat consumes a matching tag");
        assert!(!c.eat(99), "eat leaves a mismatching tag alone");
        assert_eq!(c.peek(), 3);

        c.set_pos(checkpoint);
        assert_eq!(c.peek(), 1, "backtracking is a position assignment");
        assert_eq!(c.pos(), 0);
    }

    #[test]
    fn reading_past_the_end_yields_the_sentinel_instead_of_panicking() {
        let (src, tokens) = sample();
        let mut c = tokens.cursor();
        for _ in 0..5 {
            c.bump();
        }
        assert!(c.is_eof());

        // Twenty bumps past the end: position parks, peek stays EOF.
        for _ in 0..20 {
            assert_eq!(c.bump(), tokens.eof_id());
        }
        assert_eq!(c.pos(), tokens.len() as u32);
        assert_eq!(c.peek(), Tokens::EOF);
        assert_eq!(c.peek_at(u32::MAX), Tokens::EOF, "lookahead saturates");
        assert!(c.span().is_empty());
        assert!(!c.eat(1));

        // Out-of-range ids behave as end-of-input rather than panicking.
        let wild = TokenId::new(9_999);
        assert_eq!(tokens.kind(wild), Tokens::EOF);
        assert_eq!(tokens.start(wild), tokens.end_of_input());
        assert_eq!(tokens.span(wild), Span::empty_at(src.len() as u32));
        assert_eq!(tokens.text(wild, src), "");

        // A stale checkpoint from a longer buffer clamps.
        c.set_pos(u32::MAX);
        assert_eq!(c.pos(), tokens.len() as u32);
    }

    #[test]
    fn text_never_panics_on_a_source_that_does_not_match_the_offsets() {
        let (_, tokens) = sample();
        // The wrong file: shorter, and multibyte, so a naive slice would either
        // index out of bounds or split a character.
        let wrong = "héllo";
        for i in 0..tokens.len() + 2 {
            let got = tokens.text(TokenId::new(i as u32), wrong);
            assert!(wrong.contains(got) || got.is_empty());
        }
    }

    #[test]
    fn a_reserved_kind_cannot_be_pushed_as_a_real_token() {
        let mut b = TokensBuilder::new();
        b.push(Tokens::EOF, 0);
        b.push(9, 1);
        let tokens = b.finish(2);

        assert_eq!(tokens.len(), 2, "the stray tag did not truncate the buffer");
        assert_eq!(tokens.kind(TokenId::new(0)), Tokens::MAX_KIND);
        assert!(!tokens.cursor().is_eof());
    }

    #[test]
    fn descending_offsets_yield_an_empty_span_rather_than_underflowing() {
        let mut b = TokensBuilder::new();
        b.push(1, 10);
        b.push(2, 4);
        let tokens = b.finish(0);

        assert!(tokens.span(TokenId::new(0)).is_empty());
        assert!(tokens.span(TokenId::new(1)).is_empty());
    }

    #[test]
    fn identical_input_yields_an_identical_buffer() {
        // `REQ-SYN-5`: construction order is the only thing that determines
        // ids, so two builds of the same input compare equal.
        let (_, a) = sample();
        let (_, b) = sample();
        assert_eq!(a, b);
    }

    #[test]
    fn struct_of_arrays_beats_the_array_of_structs_control() {
        const N: usize = 4096;

        let mut soa = TokensBuilder::with_capacity(N);
        let mut aos: Vec<(u16, u32)> = Vec::with_capacity(N + 1);
        for i in 0..N {
            let kind = (i % 64) as u16;
            let start = (i * 3) as u32;
            soa.push(kind, start);
            aos.push((kind, start));
        }
        let soa = soa.finish((N * 3) as u32);
        aos.push((Tokens::EOF, (N * 3) as u32));

        // Payload bytes actually occupied, by length rather than capacity, so
        // the comparison is about layout and not about growth policy.
        let soa_bytes =
            soa.kinds().len() * size_of::<u16>() + soa.starts().len() * size_of::<u32>();
        let aos_bytes = aos.len() * size_of::<(u16, u32)>();

        println!(
            "N = {N} tokens (+1 sentinel = {} entries)",
            soa.kinds().len()
        );
        println!("  size_of::<(u16, u32)>() = {}", size_of::<(u16, u32)>());
        println!("  SoA payload = {soa_bytes} bytes");
        println!("  AoS payload = {aos_bytes} bytes");
        println!(
            "  saving     = {} bytes ({:.1}%)",
            aos_bytes - soa_bytes,
            100.0 * (aos_bytes - soa_bytes) as f64 / aos_bytes as f64
        );
        println!(
            "  headers: size_of::<Tokens>() = {}, size_of::<Vec<(u16, u32)>>() = {}",
            size_of::<Tokens>(),
            size_of::<Vec<(u16, u32)>>()
        );

        // The pair pads to 8; the parallel vectors cost 2 + 4 = 6.
        assert_eq!(size_of::<(u16, u32)>(), 8, "the control is padded");
        assert_eq!(soa_bytes, (N + 1) * 6);
        assert_eq!(aos_bytes, (N + 1) * 8);
        assert!(
            soa_bytes * 4 <= aos_bytes * 3,
            "SoA must save at least 25%: {soa_bytes} vs {aos_bytes}"
        );

        // The two `Vec` headers are the fixed cost SoA pays for that saving;
        // they are amortized away by any real file.
        assert!(size_of::<Tokens>() > size_of::<Vec<(u16, u32)>>());
        assert!(
            soa_bytes + size_of::<Tokens>() < aos_bytes + size_of::<Vec<(u16, u32)>>(),
            "SoA still wins once the headers are counted"
        );
    }
}
