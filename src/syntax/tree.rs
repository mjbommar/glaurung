//! `SB-7` --- the struct-of-arrays arena tree.
//!
//! Spec: `docs/design/source-front-ends/substrate.md` sections 2.2 and 7.
//!
//! An [`Arena`] is parallel vectors, not a `Vec<Node>`: a `u16` tag, a `u32`
//! main token and two `u32` child slots per node, with anything wider spilling
//! into one flat `extra` table whose layout the tag decides. This is the shape
//! the Zig compiler settled on, and the reason is alignment: laid out as a
//! struct, a `{u16, u32, u32, u32}` node pays two bytes of padding it does not
//! use. The measurement of *our* field set, rather than someone else's, is
//! `soa_beats_array_of_structs_for_our_field_set` in this file's tests, and it
//! is printed rather than merely asserted so the number can be quoted.
//!
//! Two properties that are not in the Zig design and are load-bearing here:
//!
//! * **A token extent per node.** `REQ-SYN-7` says spans are total, and the
//!   four specced vectors cannot express a node's extent --- they record only
//!   its *defining* token, so a node's closing brace is nowhere. Zig recovers
//!   the extent with tag-dependent `firstToken`/`lastToken` walks, which this
//!   substrate cannot write because it must not interpret tags (`REQ-SYN-1`).
//!   So [`TreeSink`] records a half-open token range per node, and
//!   [`Arena::span`] is `O(1)` and exact. **This is the one deviation from
//!   section 2.2**, and it costs eight bytes per node.
//! * **The child encoding is the substrate's, not the language's.** Zig lets
//!   each tag decide what `lhs`/`rhs` mean; a language-blind arena cannot, so
//!   the top bit of `rhs` says "the children are a run in `extra`". See
//!   [`Arena::children`] for the whole encoding.
//!
//! Nothing here recurses --- not the builder, not the iterators, not `Drop`,
//! not `Debug` (`REQ-SYN-3`) --- because a hundred-thousand-deep expression
//! spine is exactly the shape decompiler output produces and a stack overflow
//! aborts the process with no diagnostic at all. Nothing here panics on any
//! input, including a [`NodeId`] from a different arena (`REQ-SYN-2`): every
//! accessor returns `Option` and every iterator ends.

use crate::syntax::diag::Diagnostics;
use crate::syntax::event::{drive, Event, Sink};
use crate::syntax::ids::{NodeId, Span, TokenId};

/// The "no such node" and "no such token" sentinel.
///
/// `u32::MAX` rather than `Option<NodeId>` in the vectors: an `Option<u32>` is
/// eight bytes once niche optimization has nowhere to go, which would undo most
/// of what the struct-of-arrays layout buys. A translation unit with four
/// billion nodes is not an input we accept, so the value is free.
pub const NO_NODE: u32 = u32::MAX;

/// The bit in `rhs` that says "the children are a run in `extra`".
///
/// Stealing the top bit caps an arena at 2^31 - 1 nodes, which is two orders of
/// magnitude past the 4 GiB translation unit `ids.rs` already refuses. The
/// alternative --- a fifth vector holding a child count --- costs four bytes
/// per node to encode one bit.
const EXTRA_FLAG: u32 = 1 << 31;

/// The largest number of nodes an arena can hold, given [`EXTRA_FLAG`].
pub const MAX_NODES: u32 = EXTRA_FLAG - 1;

/// How a node's children are stored, once `lhs`/`rhs` have been decoded.
///
/// Exposed because a language front end that reads `lhs`/`rhs` directly --- the
/// Zig-style "this tag means `lhs` is a type and `rhs` is a body" pattern ---
/// needs to know which encodings the substrate's own builder produces, so it
/// can avoid colliding with them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildSlots {
    /// A leaf: `lhs` and `rhs` are both [`NO_NODE`].
    None,
    /// One child in `lhs`; `rhs` is [`NO_NODE`].
    One(NodeId),
    /// Two children, in `lhs` and `rhs`.
    Two(NodeId, NodeId),
    /// Three or more children: `lhs` is the start of a run in `extra` and
    /// `rhs` is that run's length with [`EXTRA_FLAG`] set.
    Run {
        /// First index of the run in `extra`.
        start: u32,
        /// How many children the run holds.
        len: u32,
    },
}

/// A tree as parallel vectors, append-only during parsing.
///
/// Node ids are assigned densely in construction order, which for [`TreeSink`]
/// is pre-order: the first node opened is `NodeId(0)`. That is a determinism
/// promise (`REQ-SYN-5`) before it is a convenience --- every gate in this
/// programme is a diff, and ids that move make every diff unreadable.
///
/// The arena stores no parent pointers. Adding them would cost four bytes a
/// node to answer a question no consumer has asked yet; a walk that needs
/// parents can carry them on its own stack, which is what [`Preorder`] does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Arena {
    /// Language-defined node tag. The substrate never interprets it.
    tags: Vec<u16>,
    /// The node's defining token, or [`NO_NODE`].
    main: Vec<u32>,
    /// A child id, a run start in `extra`, or [`NO_NODE`].
    lhs: Vec<u32>,
    /// A child id, a run length with [`EXTRA_FLAG`], or [`NO_NODE`].
    rhs: Vec<u32>,
    /// First token of the node's whole subtree, or [`NO_NODE`].
    first_token: Vec<u32>,
    /// One past the last token of the node's whole subtree, or [`NO_NODE`].
    end_token: Vec<u32>,
    /// Flat side table: child runs, plus whatever a language spills here.
    extra: Vec<u32>,
    /// Nodes with no parent, in construction order.
    roots: Vec<NodeId>,
}

impl Arena {
    /// An empty arena.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty arena sized for `capacity` nodes.
    ///
    /// Six allocations up front instead of six growth curves; a parser knows
    /// its token count and a node count within a small factor of it.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            tags: Vec::with_capacity(capacity),
            main: Vec::with_capacity(capacity),
            lhs: Vec::with_capacity(capacity),
            rhs: Vec::with_capacity(capacity),
            first_token: Vec::with_capacity(capacity),
            end_token: Vec::with_capacity(capacity),
            extra: Vec::new(),
            roots: Vec::new(),
        }
    }

    /// How many nodes the arena holds.
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Whether the arena holds no nodes.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// Whether `node` addresses a node in this arena.
    ///
    /// The predicate every accessor applies before it reads, and the reason a
    /// [`NodeId`] from another arena is merely useless rather than dangerous.
    pub fn contains(&self, node: NodeId) -> bool {
        node.index() < self.tags.len()
    }

    /// The language-defined tag of `node`, or `None` if it is out of range.
    ///
    /// `Option` rather than clamping, here and throughout: a clamped read
    /// silently answers a question about a *different* node, which is the kind
    /// of wrong answer a reverse engineer acts on. `None` is a wrong handle
    /// saying so.
    pub fn tag(&self, node: NodeId) -> Option<u16> {
        self.tags.get(node.index()).copied()
    }

    /// The node's defining token: the first token it consumed directly, rather
    /// than through a child.
    ///
    /// `None` both for an out-of-range node and for a node that consumed no
    /// token of its own --- an expression whose whole text belongs to its
    /// operands, say. The two cases are distinguished by [`Arena::contains`].
    pub fn main_token(&self, node: NodeId) -> Option<TokenId> {
        match self.main.get(node.index()).copied() {
            Some(raw) if raw != NO_NODE => Some(TokenId::new(raw)),
            _ => None,
        }
    }

    /// The raw `lhs` word, uninterpreted.
    ///
    /// For a language front end using the Zig convention, where the tag decides
    /// what the word means. The substrate's own readers go through
    /// [`Arena::children`].
    pub fn lhs_raw(&self, node: NodeId) -> Option<u32> {
        self.lhs.get(node.index()).copied()
    }

    /// The raw `rhs` word, uninterpreted.
    pub fn rhs_raw(&self, node: NodeId) -> Option<u32> {
        self.rhs.get(node.index()).copied()
    }

    /// How `node`'s children are encoded in `lhs`/`rhs`.
    ///
    /// The encoding, in decode order, is:
    ///
    /// | `lhs` | `rhs` | meaning |
    /// |---|---|---|
    /// | [`NO_NODE`] | [`NO_NODE`] | no children |
    /// | id | [`NO_NODE`] | one child |
    /// | start | len \| [`EXTRA_FLAG`] | three or more children, in `extra` |
    /// | id | id | two children |
    ///
    /// `rhs == NO_NODE` is tested before the flag because [`NO_NODE`] also has
    /// the top bit set. Two children stay inline because two is the common
    /// arity in every C-family grammar --- a binary operator, an assignment, an
    /// if-without-else --- and paying an `extra` indirection for it would make
    /// the flat table the hot path.
    pub fn children(&self, node: NodeId) -> ChildSlots {
        let (Some(lhs), Some(rhs)) = (self.lhs_raw(node), self.rhs_raw(node)) else {
            return ChildSlots::None;
        };
        if rhs == NO_NODE {
            if lhs == NO_NODE {
                ChildSlots::None
            } else {
                ChildSlots::One(NodeId::new(lhs))
            }
        } else if rhs & EXTRA_FLAG != 0 {
            ChildSlots::Run {
                start: lhs,
                len: rhs & !EXTRA_FLAG,
            }
        } else {
            ChildSlots::Two(NodeId::new(lhs), NodeId::new(rhs))
        }
    }

    /// How many children `node` has. Zero for an out-of-range node.
    pub fn child_count(&self, node: NodeId) -> u32 {
        match self.children(node) {
            ChildSlots::None => 0,
            ChildSlots::One(_) => 1,
            ChildSlots::Two(_, _) => 2,
            ChildSlots::Run { len, .. } => len,
        }
    }

    /// The `index`th child of `node`, or `None`.
    ///
    /// `None` covers every way this can fail --- a bad node, an index past the
    /// end, a run pointing outside `extra`, a stored id that is not a node ---
    /// so a malformed arena degrades into a smaller tree rather than a crash.
    pub fn child(&self, node: NodeId, index: u32) -> Option<NodeId> {
        let raw = match self.children(node) {
            ChildSlots::None => return None,
            ChildSlots::One(child) => {
                if index == 0 {
                    child.raw()
                } else {
                    return None;
                }
            }
            ChildSlots::Two(left, right) => match index {
                0 => left.raw(),
                1 => right.raw(),
                _ => return None,
            },
            ChildSlots::Run { start, len } => {
                if index >= len {
                    return None;
                }
                *self.extra.get(start.checked_add(index)? as usize)?
            }
        };
        let child = NodeId::new(raw);
        self.contains(child).then_some(child)
    }

    /// `node`'s children, in order.
    ///
    /// A plain index loop over [`Arena::child`], so it holds no borrow of the
    /// arena's internals and cannot recurse.
    pub fn children_iter(&self, node: NodeId) -> Children<'_> {
        Children {
            arena: self,
            node,
            index: 0,
            len: self.child_count(node),
        }
    }

    /// The flat side table, uninterpreted.
    pub fn extra(&self) -> &[u32] {
        &self.extra
    }

    /// The run of `len` words starting at `start` in `extra`, or `None` if it
    /// does not fit.
    ///
    /// The read half of the "more than two children, or a tag-defined record"
    /// story. Bounds-checked rather than sliced, because the indices in `lhs`
    /// come from whatever wrote the node and the substrate does not get to
    /// assume that was itself.
    pub fn extra_run(&self, start: u32, len: u32) -> Option<&[u32]> {
        let start = start as usize;
        let end = start.checked_add(len as usize)?;
        self.extra.get(start..end)
    }

    /// Append `values` to `extra`, returning the index they start at.
    ///
    /// `None` if `extra` cannot hold them without crossing [`EXTRA_FLAG`],
    /// which is the point past which a run start stops being addressable.
    pub fn push_extra(&mut self, values: &[u32]) -> Option<u32> {
        let start = u32::try_from(self.extra.len()).ok()?;
        let end = start.checked_add(u32::try_from(values.len()).ok()?)?;
        if end >= EXTRA_FLAG {
            return None;
        }
        self.extra.extend_from_slice(values);
        Some(start)
    }

    /// The half-open token range `[first, end)` that `node` and its whole
    /// subtree cover, or `None` if it covered no tokens.
    ///
    /// This is what makes [`Arena::span`] exact and `O(1)`; see the module
    /// docs for why the four specced vectors cannot answer it.
    pub fn token_extent(&self, node: NodeId) -> Option<(u32, u32)> {
        let first = self.first_token.get(node.index()).copied()?;
        let end = self.end_token.get(node.index()).copied()?;
        (first != NO_NODE && end != NO_NODE && first < end).then_some((first, end))
    }

    /// The source span `node` covers, given the token buffer's spans.
    ///
    /// The token spans are a parameter rather than an owned field because the
    /// arena has no business owning the token buffer: the same tree is read
    /// against the tokens it was built from, and duplicating them per node
    /// would triple its size. Pass `&[Span]` in token order --- for the token
    /// buffer of `SB-3`, that is one span per token index.
    ///
    /// `None` for a node that covers no token, or whose extent falls outside
    /// `token_spans` --- the mismatched-buffer case, where a clamped answer
    /// would point at unrelated source text.
    pub fn span(&self, node: NodeId, token_spans: &[Span]) -> Option<Span> {
        let (first, end) = self.token_extent(node)?;
        let lo = token_spans.get(first as usize)?.lo;
        let hi = token_spans.get(end.checked_sub(1)? as usize)?.hi;
        Some(Span::new(lo, hi))
    }

    /// The nodes with no parent, in construction order.
    ///
    /// An event stream may open several top-level nodes --- a file is a list of
    /// declarations, and a recovered parse can leave more than one --- so
    /// "the root" is not a safe assumption and this is a slice.
    pub fn roots(&self) -> &[NodeId] {
        &self.roots
    }

    /// A pre-order walk of `node`'s subtree, using an explicit stack.
    ///
    /// Never native recursion (`REQ-SYN-3`). The walk is also bounded
    /// (`REQ-SYN-4`): it yields at most a fixed multiple of the arena's node
    /// count, so a hand-built arena containing a cycle terminates instead of
    /// hanging.
    pub fn preorder(&self, node: NodeId) -> Preorder<'_> {
        let mut stack = Vec::new();
        if self.contains(node) {
            stack.push(node);
        }
        Preorder {
            arena: self,
            stack,
            budget: self.budget(),
        }
    }

    /// A pre-order walk of every root's subtree, roots in construction order.
    pub fn preorder_roots(&self) -> Preorder<'_> {
        let mut stack: Vec<NodeId> = self.roots.iter().rev().copied().collect();
        stack.retain(|node| self.contains(*node));
        Preorder {
            arena: self,
            stack,
            budget: self.budget(),
        }
    }

    /// Append a node with `tag`, returning its id, or `None` if the arena is
    /// full.
    ///
    /// The node starts with no children, no main token and no extent; the
    /// builder fills those in as the parse closes it. `None` rather than a
    /// panic at [`MAX_NODES`] keeps the "never panics on any input" contract
    /// true even for the input nobody will ever write.
    pub fn push_node(&mut self, tag: u16) -> Option<NodeId> {
        let id = u32::try_from(self.tags.len()).ok()?;
        if id >= MAX_NODES {
            return None;
        }
        self.tags.push(tag);
        self.main.push(NO_NODE);
        self.lhs.push(NO_NODE);
        self.rhs.push(NO_NODE);
        self.first_token.push(NO_NODE);
        self.end_token.push(NO_NODE);
        Some(NodeId::new(id))
    }

    /// Rewrite `node`'s tag, reporting whether it landed.
    ///
    /// The arena-side counterpart of the event stream's forward patch, for a
    /// consumer that retags after the tree is built --- a lowering pass that
    /// resolves an ambiguity the parser left open.
    pub fn set_tag(&mut self, node: NodeId, tag: u16) -> bool {
        match self.tags.get_mut(node.index()) {
            Some(slot) => {
                *slot = tag;
                true
            }
            None => false,
        }
    }

    /// Set `node`'s defining token, reporting whether it landed.
    pub fn set_main_token(&mut self, node: NodeId, token: TokenId) -> bool {
        match self.main.get_mut(node.index()) {
            Some(slot) => {
                *slot = token.raw();
                true
            }
            None => false,
        }
    }

    /// Set `node`'s subtree token extent to the half-open range `[first, end)`.
    ///
    /// A reversed or empty range clears the extent rather than storing
    /// something [`Arena::span`] would have to defend against later.
    pub fn set_token_extent(&mut self, node: NodeId, first: u32, end: u32) -> bool {
        if !self.contains(node) {
            return false;
        }
        let index = node.index();
        let sane = first < end && first != NO_NODE && end != NO_NODE;
        let (stored_first, stored_end) = if sane {
            (first, end)
        } else {
            (NO_NODE, NO_NODE)
        };
        if let Some(slot) = self.first_token.get_mut(index) {
            *slot = stored_first;
        }
        if let Some(slot) = self.end_token.get_mut(index) {
            *slot = stored_end;
        }
        true
    }

    /// Record `children` as `node`'s children, spilling to `extra` past two.
    ///
    /// Reports whether it landed: `false` for an out-of-range node, for more
    /// children than [`EXTRA_FLAG`] can count, or for an `extra` table too full
    /// to take the run. On `false` the node keeps whatever children it had,
    /// which for a node being closed is none --- a subtree is lost, the tree
    /// stays walkable, and the caller counts the loss.
    pub fn set_children(&mut self, node: NodeId, children: &[NodeId]) -> bool {
        if !self.contains(node) {
            return false;
        }
        let (lhs, rhs) = match children {
            [] => (NO_NODE, NO_NODE),
            [only] => (only.raw(), NO_NODE),
            [left, right] => (left.raw(), right.raw()),
            many => {
                let Ok(len) = u32::try_from(many.len()) else {
                    return false;
                };
                if len >= EXTRA_FLAG {
                    return false;
                }
                let raw: Vec<u32> = many.iter().map(|child| child.raw()).collect();
                let Some(start) = self.push_extra(&raw) else {
                    return false;
                };
                (start, len | EXTRA_FLAG)
            }
        };
        if let Some(slot) = self.lhs.get_mut(node.index()) {
            *slot = lhs;
        }
        if let Some(slot) = self.rhs.get_mut(node.index()) {
            *slot = rhs;
        }
        true
    }

    /// Record `node` as a top-level node.
    pub fn push_root(&mut self, node: NodeId) -> bool {
        if !self.contains(node) {
            return false;
        }
        self.roots.push(node);
        true
    }

    /// The step budget a traversal gets: a fixed multiple of the node count.
    ///
    /// A well-formed tree visits each node once, so twice the node count is
    /// slack a real walk never uses and a cyclic one hits immediately.
    fn budget(&self) -> usize {
        self.tags.len().saturating_mul(2).saturating_add(8)
    }
}

/// The children of one node, in order.
///
/// Yielded by [`Arena::children_iter`].
#[derive(Debug, Clone)]
pub struct Children<'a> {
    arena: &'a Arena,
    node: NodeId,
    index: u32,
    len: u32,
}

impl Iterator for Children<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        while self.index < self.len {
            let index = self.index;
            self.index += 1;
            if let Some(child) = self.arena.child(self.node, index) {
                return Some(child);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some((self.len - self.index) as usize))
    }
}

/// A pre-order walk over an explicit stack.
///
/// Yielded by [`Arena::preorder`] and [`Arena::preorder_roots`]. The stack is
/// on the heap, so depth costs allocation rather than the thing that ends the
/// process: a hundred-thousand-deep spine walks fine here and would abort under
/// native recursion (`REQ-SYN-3`).
#[derive(Debug, Clone)]
pub struct Preorder<'a> {
    arena: &'a Arena,
    stack: Vec<NodeId>,
    budget: usize,
}

impl Iterator for Preorder<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        if self.budget == 0 {
            return None;
        }
        let node = self.stack.pop()?;
        self.budget -= 1;
        let count = self.arena.child_count(node);
        for index in (0..count).rev() {
            if let Some(child) = self.arena.child(node, index) {
                self.stack.push(child);
            }
        }
        Some(node)
    }
}

/// The frame [`TreeSink`] keeps per open node.
///
/// The children live in one shared buffer keyed by `child_base` rather than in
/// a `Vec` per frame: a parse opens a node per grammar rule, and a fresh
/// allocation per rule is the kind of cost that only shows up as a flat 20% on
/// a real file.
#[derive(Debug, Clone, Copy)]
struct Frame {
    /// The node this frame is building, or `None` if the arena refused it.
    node: Option<NodeId>,
    /// Where this frame's children start in the sink's shared child buffer.
    child_base: usize,
    /// First token the frame's subtree covers, or [`NO_NODE`].
    first_token: u32,
    /// One past the last token the frame's subtree covers, or [`NO_NODE`].
    end_token: u32,
}

/// The [`Sink`] that turns an event stream into an [`Arena`].
///
/// Node ids come out in pre-order --- the id is assigned when the node opens,
/// before any child exists --- so the first node opened is `NodeId(0)` and a
/// subtree occupies a contiguous id range. Both are determinism properties
/// (`REQ-SYN-5`) rather than accidents of the algorithm.
///
/// It never recurses: nesting lives in `stack`, on the heap.
#[derive(Debug, Clone, Default)]
pub struct TreeSink {
    arena: Arena,
    stack: Vec<Frame>,
    children: Vec<NodeId>,
    dropped_nodes: u32,
    stray_tokens: u32,
    lost_children: u32,
}

impl TreeSink {
    /// A sink building an empty arena.
    pub fn new() -> Self {
        Self::default()
    }

    /// A sink whose arena is sized for `capacity` nodes.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            arena: Arena::with_capacity(capacity),
            ..Self::default()
        }
    }

    /// How many nodes the arena refused because it was full.
    ///
    /// Zero on every real input; non-zero means the tree is a truncation of the
    /// parse and a caller reporting on it should say so rather than imply the
    /// file was that shape.
    pub fn dropped_nodes(&self) -> u32 {
        self.dropped_nodes
    }

    /// How many tokens arrived with no node open.
    ///
    /// They have nowhere to go in a tree, so they are counted and discarded.
    /// A non-zero count is a grammar bug: a token was consumed outside any
    /// production.
    pub fn stray_tokens(&self) -> u32 {
        self.stray_tokens
    }

    /// How many children could not be recorded because `extra` was full.
    pub fn lost_children(&self) -> u32 {
        self.lost_children
    }

    /// The arena built so far, closing anything still open.
    ///
    /// [`drive`] already balances the stream, so a non-empty stack here means
    /// the sink was driven by hand. Closing rather than discarding keeps the
    /// partial tree usable, which is the whole error model in miniature.
    pub fn finish(mut self) -> Arena {
        while !self.stack.is_empty() {
            self.close();
        }
        self.arena
    }
}

impl Sink for TreeSink {
    fn open(&mut self, tag: u16) {
        let node = self.arena.push_node(tag);
        if node.is_none() {
            self.dropped_nodes = self.dropped_nodes.saturating_add(1);
        }
        self.stack.push(Frame {
            node,
            child_base: self.children.len(),
            first_token: NO_NODE,
            end_token: NO_NODE,
        });
    }

    fn token(&mut self, id: TokenId) {
        let raw = id.raw();
        let Some(frame) = self.stack.last_mut() else {
            self.stray_tokens = self.stray_tokens.saturating_add(1);
            return;
        };
        if frame.first_token == NO_NODE || raw < frame.first_token {
            frame.first_token = raw;
        }
        let end = raw.saturating_add(1);
        if frame.end_token == NO_NODE || end > frame.end_token {
            frame.end_token = end;
        }
        if let Some(node) = frame.node {
            if self.arena.main_token(node).is_none() {
                self.arena.set_main_token(node, id);
            }
        }
    }

    fn close(&mut self) {
        let Some(frame) = self.stack.pop() else {
            return;
        };
        if let Some(node) = frame.node {
            let count = self.children.len() - frame.child_base;
            if !self
                .arena
                .set_children(node, &self.children[frame.child_base..])
            {
                self.lost_children = self
                    .lost_children
                    .saturating_add(count.min(u32::MAX as usize) as u32);
            }
            if frame.first_token != NO_NODE {
                self.arena
                    .set_token_extent(node, frame.first_token, frame.end_token);
            }
        }
        self.children.truncate(frame.child_base);

        match self.stack.last_mut() {
            Some(parent) => {
                if frame.first_token != NO_NODE
                    && (parent.first_token == NO_NODE || frame.first_token < parent.first_token)
                {
                    parent.first_token = frame.first_token;
                }
                if frame.end_token != NO_NODE
                    && (parent.end_token == NO_NODE || frame.end_token > parent.end_token)
                {
                    parent.end_token = frame.end_token;
                }
                if let Some(node) = frame.node {
                    self.children.push(node);
                }
            }
            None => {
                if let Some(node) = frame.node {
                    self.arena.push_root(node);
                }
            }
        }
    }
}

/// Build an arena from `events`, reporting any structural problem at `span`.
///
/// The ordinary entry point: it drives a [`TreeSink`], which means the stream
/// is balanced and tombstones are skipped before the sink ever sees them. It
/// returns a tree for every input, including a malformed one (`REQ-SYN-2`) ---
/// a partial tree plus a diagnostic, never a `Result` and never a panic.
pub fn build(events: &[Event], span: Span, diagnostics: &mut Diagnostics) -> Arena {
    let mut sink = TreeSink::with_capacity(events.len() / 2);
    drive(events, &mut sink, span, diagnostics);
    sink.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syntax::event::{Events, TagCensus};

    /// Tags used by the tests, standing in for a language's node kinds.
    const ROOT: u16 = 1;
    const DECL: u16 = 2;
    const EXPR: u16 = 3;

    fn spans(count: u32) -> Vec<Span> {
        (0..count).map(|i| Span::new(i * 10, i * 10 + 4)).collect()
    }

    fn build_clean(events: &Events) -> Arena {
        let mut diagnostics = Diagnostics::new();
        let arena = build(events.as_slice(), Span::default(), &mut diagnostics);
        assert!(diagnostics.is_empty(), "expected a well-formed stream");
        arena
    }

    #[test]
    fn ids_are_dense_and_assigned_in_pre_order() {
        let mut events = Events::new();
        let root = events.open(ROOT);
        let first = events.open(DECL);
        events.close(first);
        let second = events.open(EXPR);
        events.close(second);
        events.close(root);

        let arena = build_clean(&events);
        assert_eq!(arena.len(), 3);
        assert_eq!(arena.tag(NodeId::new(0)), Some(ROOT));
        assert_eq!(arena.tag(NodeId::new(1)), Some(DECL));
        assert_eq!(arena.tag(NodeId::new(2)), Some(EXPR));
        assert_eq!(arena.roots(), &[NodeId::new(0)]);
    }

    #[test]
    fn building_the_same_stream_twice_yields_byte_identical_arenas() {
        let mut events = Events::new();
        let root = events.open(ROOT);
        for index in 0..5u32 {
            let child = events.open(DECL);
            events.token(TokenId::new(index));
            events.close(child);
        }
        events.close(root);
        assert_eq!(build_clean(&events), build_clean(&events));
    }

    #[test]
    fn zero_one_and_two_children_stay_inline_and_three_spill_to_extra() {
        for count in 0..4u32 {
            let mut events = Events::new();
            let root = events.open(ROOT);
            for _ in 0..count {
                let child = events.open(DECL);
                events.close(child);
            }
            events.close(root);
            let arena = build_clean(&events);
            let root_id = NodeId::new(0);
            assert_eq!(arena.child_count(root_id), count, "count {count}");
            let kids: Vec<NodeId> = arena.children_iter(root_id).collect();
            let expected: Vec<NodeId> = (1..=count).map(NodeId::new).collect();
            assert_eq!(kids, expected, "count {count}");
            match (count, arena.children(root_id)) {
                (0, ChildSlots::None)
                | (1, ChildSlots::One(_))
                | (2, ChildSlots::Two(_, _))
                | (3, ChildSlots::Run { .. }) => {}
                (count, slots) => panic!("count {count} encoded as {slots:?}"),
            }
        }
    }

    #[test]
    fn a_wide_node_reads_its_children_back_out_of_extra_in_order() {
        const WIDTH: u32 = 500;
        let mut events = Events::new();
        let root = events.open(ROOT);
        for index in 0..WIDTH {
            let child = events.open(DECL);
            events.token(TokenId::new(index));
            events.close(child);
        }
        events.close(root);
        let arena = build_clean(&events);
        let kids: Vec<NodeId> = arena.children_iter(NodeId::new(0)).collect();
        assert_eq!(kids.len(), WIDTH as usize);
        assert_eq!(kids[0], NodeId::new(1));
        assert_eq!(kids[WIDTH as usize - 1], NodeId::new(WIDTH));
        let ChildSlots::Run { start, len } = arena.children(NodeId::new(0)) else {
            panic!("a 500-wide node must spill");
        };
        assert_eq!(len, WIDTH);
        let run = arena.extra_run(start, len).expect("the run is in range");
        assert_eq!(run.len(), WIDTH as usize);
    }

    #[test]
    fn the_main_token_is_the_first_token_the_node_consumed_itself() {
        let mut events = Events::new();
        let root = events.open(ROOT);
        let child = events.open(DECL);
        events.token(TokenId::new(0));
        events.close(child);
        events.token(TokenId::new(1));
        events.close(root);

        let arena = build_clean(&events);
        assert_eq!(arena.main_token(NodeId::new(1)), Some(TokenId::new(0)));
        assert_eq!(
            arena.main_token(NodeId::new(0)),
            Some(TokenId::new(1)),
            "a child's token is not the parent's defining token"
        );
    }

    #[test]
    fn a_node_that_consumed_no_token_has_no_main_token_and_no_span() {
        let mut events = Events::new();
        let root = events.open(ROOT);
        events.close(root);
        let arena = build_clean(&events);
        assert!(arena.contains(NodeId::new(0)));
        assert_eq!(arena.main_token(NodeId::new(0)), None);
        assert_eq!(arena.span(NodeId::new(0), &spans(4)), None);
    }

    #[test]
    fn a_span_covers_the_whole_subtree_including_a_trailing_closing_token() {
        // A node whose text is `{ x }`: the braces belong to the parent and the
        // identifier to the child, which is exactly the shape a main-token-only
        // arena cannot span.
        let mut events = Events::new();
        let root = events.open(ROOT);
        events.token(TokenId::new(0)); // {
        let child = events.open(EXPR);
        events.token(TokenId::new(1)); // x
        events.close(child);
        events.token(TokenId::new(2)); // }
        events.close(root);

        let arena = build_clean(&events);
        let token_spans = spans(3);
        assert_eq!(arena.token_extent(NodeId::new(0)), Some((0, 3)));
        assert_eq!(
            arena.span(NodeId::new(0), &token_spans),
            Some(Span::new(0, 24))
        );
        assert_eq!(
            arena.span(NodeId::new(1), &token_spans),
            Some(Span::new(10, 14))
        );
    }

    #[test]
    fn a_span_against_the_wrong_token_buffer_is_none_rather_than_wrong() {
        let mut events = Events::new();
        let root = events.open(ROOT);
        events.token(TokenId::new(9));
        events.close(root);
        let arena = build_clean(&events);
        assert_eq!(arena.span(NodeId::new(0), &spans(3)), None);
        assert_eq!(
            arena.span(NodeId::new(0), &spans(20)).map(|s| s.lo),
            Some(90)
        );
    }

    #[test]
    fn every_accessor_answers_none_for_a_node_from_another_arena() {
        let mut arena = Arena::new();
        let stranger = NodeId::new(4_000_000);
        assert!(!arena.contains(stranger));
        assert_eq!(arena.tag(stranger), None);
        assert_eq!(arena.main_token(stranger), None);
        assert_eq!(arena.lhs_raw(stranger), None);
        assert_eq!(arena.rhs_raw(stranger), None);
        assert_eq!(arena.children(stranger), ChildSlots::None);
        assert_eq!(arena.child_count(stranger), 0);
        assert_eq!(arena.child(stranger, 0), None);
        assert_eq!(arena.children_iter(stranger).count(), 0);
        assert_eq!(arena.token_extent(stranger), None);
        assert_eq!(arena.span(stranger, &spans(4)), None);
        assert_eq!(arena.preorder(stranger).count(), 0);
        assert!(!arena.set_tag(stranger, ROOT));
        assert!(!arena.set_children(stranger, &[]));
        assert!(!arena.push_root(stranger));
    }

    #[test]
    fn a_child_pointing_outside_the_arena_is_skipped_rather_than_followed() {
        let mut arena = Arena::new();
        let root = arena.push_node(ROOT).expect("room for one node");
        assert!(arena.set_children(root, &[NodeId::new(77), NodeId::new(78)]));
        assert_eq!(arena.child_count(root), 2, "the slots are still occupied");
        assert_eq!(arena.children_iter(root).count(), 0, "neither resolves");
        assert_eq!(arena.preorder(root).count(), 1);
    }

    #[test]
    fn a_cycle_in_a_hand_built_arena_terminates_instead_of_hanging() {
        let mut arena = Arena::new();
        let a = arena.push_node(ROOT).expect("room");
        let b = arena.push_node(DECL).expect("room");
        assert!(arena.set_children(a, &[b]));
        assert!(arena.set_children(b, &[a]));
        let visited = arena.preorder(a).count();
        assert!(visited > 0 && visited <= 2 * arena.len() + 8, "{visited}");
    }

    #[test]
    fn a_hundred_thousand_deep_tree_builds_and_walks_without_native_recursion() {
        const DEPTH: usize = 100_000;
        let mut raw: Vec<Event> = Vec::with_capacity(DEPTH * 3);
        for index in 0..DEPTH {
            raw.push(Event::Open { tag: DECL });
            raw.push(Event::Token {
                id: TokenId::new(index as u32),
            });
        }
        raw.extend(std::iter::repeat_n(Event::Close, DEPTH));

        let mut diagnostics = Diagnostics::new();
        let arena = build(&raw, Span::default(), &mut diagnostics);
        assert!(diagnostics.is_empty());
        assert_eq!(arena.len(), DEPTH);
        assert_eq!(arena.preorder(NodeId::new(0)).count(), DEPTH);
        assert_eq!(arena.preorder_roots().count(), DEPTH);
        assert_eq!(arena.token_extent(NodeId::new(0)), Some((0, DEPTH as u32)));
        // The arena is dropped here; a recursive Drop would abort the process.
    }

    #[test]
    fn an_unbalanced_stream_still_produces_a_walkable_tree_and_a_diagnostic() {
        let raw = vec![
            Event::Open { tag: ROOT },
            Event::Token {
                id: TokenId::new(0),
            },
            Event::Close,
            Event::Close,
            Event::Open { tag: DECL },
            Event::Token {
                id: TokenId::new(1),
            },
        ];
        let mut diagnostics = Diagnostics::new();
        let arena = build(&raw, Span::new(0, 8), &mut diagnostics);
        assert_eq!(diagnostics.len(), 2, "one surplus close, one dangling open");
        assert_eq!(arena.len(), 2);
        assert_eq!(arena.roots(), &[NodeId::new(0), NodeId::new(1)]);
        assert_eq!(arena.preorder_roots().count(), 2);
        assert_eq!(arena.main_token(NodeId::new(1)), Some(TokenId::new(1)));
    }

    #[test]
    fn a_token_with_no_node_open_is_counted_and_dropped_rather_than_misfiled() {
        let mut sink = TreeSink::new();
        sink.token(TokenId::new(0));
        sink.open(ROOT);
        sink.token(TokenId::new(1));
        sink.close();
        assert_eq!(sink.stray_tokens(), 1);
        let arena = sink.finish();
        assert_eq!(arena.len(), 1);
        assert_eq!(arena.main_token(NodeId::new(0)), Some(TokenId::new(1)));
    }

    #[test]
    fn finishing_a_sink_with_nodes_still_open_closes_them_rather_than_dropping_them() {
        let mut sink = TreeSink::new();
        sink.open(ROOT);
        sink.open(DECL);
        sink.token(TokenId::new(3));
        let arena = sink.finish();
        assert_eq!(arena.len(), 2);
        assert_eq!(arena.roots(), &[NodeId::new(0)]);
        assert_eq!(arena.children_iter(NodeId::new(0)).count(), 1);
        assert_eq!(arena.token_extent(NodeId::new(0)), Some((3, 4)));
    }

    #[test]
    fn an_abandoned_node_reparents_its_children_onto_its_grandparent() {
        let mut events = Events::new();
        let root = events.open(ROOT);
        let speculative = events.open(EXPR);
        let kept = events.open(DECL);
        events.token(TokenId::new(0));
        events.close(kept);
        events.abandon(speculative);
        events.close(root);

        let arena = build_clean(&events);
        assert_eq!(arena.len(), 2, "the abandoned node was never built");
        assert_eq!(arena.tag(NodeId::new(1)), Some(DECL));
        assert_eq!(
            arena.children_iter(NodeId::new(0)).collect::<Vec<_>>(),
            vec![NodeId::new(1)]
        );
    }

    #[test]
    fn a_forward_patched_tag_is_the_one_the_tree_gets() {
        let mut events = Events::new();
        let marker = events.open(EXPR);
        events.token(TokenId::new(0));
        assert!(events.patch(&marker, DECL));
        events.close(marker);
        let arena = build_clean(&events);
        assert_eq!(arena.tag(NodeId::new(0)), Some(DECL));
    }

    #[test]
    fn the_tree_sink_and_the_census_agree_on_the_same_stream() {
        let mut events = Events::new();
        let root = events.open(ROOT);
        for index in 0..4u32 {
            let child = events.open(DECL);
            events.token(TokenId::new(index));
            events.close(child);
        }
        events.close(root);

        let arena = build_clean(&events);
        let mut census = TagCensus::new();
        let mut diagnostics = Diagnostics::new();
        drive(
            events.as_slice(),
            &mut census,
            Span::default(),
            &mut diagnostics,
        );
        assert_eq!(census.nodes() as usize, arena.len());
        assert_eq!(census.count(DECL), arena.child_count(NodeId::new(0)));
        assert_eq!(census.max_depth(), 2);
    }

    #[test]
    fn extra_runs_are_bounds_checked_rather_than_sliced() {
        let mut arena = Arena::new();
        assert_eq!(arena.push_extra(&[1, 2, 3]), Some(0));
        assert_eq!(arena.extra_run(0, 3), Some(&[1u32, 2, 3][..]));
        assert_eq!(arena.extra_run(1, 3), None);
        assert_eq!(arena.extra_run(u32::MAX, 1), None);
        assert_eq!(arena.extra(), &[1, 2, 3]);
    }

    #[test]
    fn a_reversed_token_extent_is_cleared_rather_than_stored() {
        let mut arena = Arena::new();
        let node = arena.push_node(ROOT).expect("room");
        assert!(arena.set_token_extent(node, 9, 4));
        assert_eq!(arena.token_extent(node), None);
        assert!(arena.set_token_extent(node, 4, 9));
        assert_eq!(arena.token_extent(node), Some((4, 9)));
    }

    /// The array-of-structs control the struct-of-arrays layout is measured
    /// against: the four fields section 2.2 specifies, in one struct.
    #[derive(Clone, Copy, Default)]
    struct AosSpecced {
        tag: u16,
        main: u32,
        lhs: u32,
        rhs: u32,
    }

    /// The same control for the six per-node fields this arena actually keeps,
    /// which adds the token extent `REQ-SYN-7` needs.
    #[derive(Clone, Copy, Default)]
    struct AosActual {
        tag: u16,
        main: u32,
        lhs: u32,
        rhs: u32,
        first_token: u32,
        end_token: u32,
    }

    #[test]
    fn soa_beats_array_of_structs_for_our_field_set() {
        use std::mem::size_of;
        const N: usize = 250_000;

        let mut tags: Vec<u16> = Vec::with_capacity(N);
        let mut main: Vec<u32> = Vec::with_capacity(N);
        let mut lhs: Vec<u32> = Vec::with_capacity(N);
        let mut rhs: Vec<u32> = Vec::with_capacity(N);
        let mut first: Vec<u32> = Vec::with_capacity(N);
        let mut end: Vec<u32> = Vec::with_capacity(N);
        for index in 0..N as u32 {
            tags.push((index % 64) as u16);
            main.push(index);
            lhs.push(index);
            rhs.push(index);
            first.push(index);
            end.push(index + 1);
        }

        let mut specced_aos: Vec<AosSpecced> = Vec::with_capacity(N);
        let mut actual_aos: Vec<AosActual> = Vec::with_capacity(N);
        for index in 0..N as u32 {
            specced_aos.push(AosSpecced {
                tag: (index % 64) as u16,
                main: index,
                lhs: index,
                rhs: index,
            });
            actual_aos.push(AosActual {
                tag: (index % 64) as u16,
                main: index,
                lhs: index,
                rhs: index,
                first_token: index,
                end_token: index + 1,
            });
        }

        // Read every field back, so the controls hold the same data the
        // parallel vectors do and the comparison is like for like.
        let soa_sum: u64 = (0..N)
            .map(|i| {
                tags[i] as u64
                    + main[i] as u64
                    + lhs[i] as u64
                    + rhs[i] as u64
                    + first[i] as u64
                    + end[i] as u64
            })
            .sum();
        let aos_sum: u64 = actual_aos
            .iter()
            .map(|node| {
                node.tag as u64
                    + node.main as u64
                    + node.lhs as u64
                    + node.rhs as u64
                    + node.first_token as u64
                    + node.end_token as u64
            })
            .sum();
        let specced_sum: u64 = specced_aos
            .iter()
            .map(|node| node.tag as u64 + node.main as u64 + node.lhs as u64 + node.rhs as u64)
            .sum();
        assert_eq!(soa_sum, aos_sum, "the controls hold the same node data");
        assert!(specced_sum > 0);

        let soa_specced = tags.capacity() * size_of::<u16>()
            + (main.capacity() + lhs.capacity() + rhs.capacity()) * size_of::<u32>();
        let aos_specced = specced_aos.capacity() * size_of::<AosSpecced>();
        let soa_actual = soa_specced + (first.capacity() + end.capacity()) * size_of::<u32>();
        let aos_actual = actual_aos.capacity() * size_of::<AosActual>();

        println!("nodes                     = {N}");
        println!(
            "specced 4 fields: SoA     = {soa_specced} bytes ({} B/node)",
            soa_specced as f64 / N as f64
        );
        println!(
            "specced 4 fields: AoS     = {aos_specced} bytes ({} B/node, struct {} B)",
            aos_specced as f64 / N as f64,
            size_of::<AosSpecced>()
        );
        println!(
            "specced 4 fields: saving  = {} bytes ({:.2}%)",
            aos_specced - soa_specced,
            100.0 * (aos_specced - soa_specced) as f64 / aos_specced as f64
        );
        println!(
            "actual  6 fields: SoA     = {soa_actual} bytes ({} B/node)",
            soa_actual as f64 / N as f64
        );
        println!(
            "actual  6 fields: AoS     = {aos_actual} bytes ({} B/node, struct {} B)",
            aos_actual as f64 / N as f64,
            size_of::<AosActual>()
        );
        println!(
            "actual  6 fields: saving  = {} bytes ({:.2}%)",
            aos_actual - soa_actual,
            100.0 * (aos_actual - soa_actual) as f64 / aos_actual as f64
        );

        assert!(
            soa_specced < aos_specced,
            "SoA {soa_specced} did not beat AoS {aos_specced}"
        );
        assert!(
            soa_actual < aos_actual,
            "SoA {soa_actual} did not beat AoS {aos_actual}"
        );
    }
}
