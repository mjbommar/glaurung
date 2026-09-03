//! The handles every layer of the substrate passes around.
//!
//! All five are lifetime-free `Copy` newtypes over `u32`, for the reason the
//! sibling `axeyum` crate states for its term arena: a handle that carries a
//! lifetime leaks the arena's borrow into every signature that touches it, and
//! a handle that carries a pointer cannot survive the arena being cloned or
//! serialized. Indices survive both.
//!
//! `u32` rather than `usize` is deliberate. A translation unit larger than 4 GiB
//! is not an input we accept, and halving the width of every child pointer is
//! most of what makes the struct-of-arrays node arena worth having --- see
//! `docs/design/source-front-ends/substrate.md` section 2.

use std::fmt;
use std::ops::Range;

/// A half-open byte range `[lo, hi)` into one [`crate::syntax::source::SourceFile`].
///
/// Spans are total: every token, AST node and CFG node carries one, including
/// nodes the parser recovered from an error (`REQ-SYN-7`). A span never spans
/// two files; cross-file positions go through the source map's file index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Span {
    /// Start byte offset, inclusive.
    pub lo: u32,
    /// End byte offset, exclusive.
    pub hi: u32,
}

impl Span {
    /// A span covering `[lo, hi)`.
    ///
    /// `hi` is clamped up to `lo`, so a reversed pair yields an empty span at
    /// `lo` rather than a span whose length underflows.
    pub const fn new(lo: u32, hi: u32) -> Self {
        Self {
            lo,
            hi: if hi < lo { lo } else { hi },
        }
    }

    /// The empty span at `offset`, used for a token the parser inserted during
    /// recovery: it has a position but consumed no input.
    pub const fn empty_at(offset: u32) -> Self {
        Self {
            lo: offset,
            hi: offset,
        }
    }

    /// Length in bytes.
    pub const fn len(&self) -> u32 {
        self.hi - self.lo
    }

    /// Whether the span covers no bytes.
    pub const fn is_empty(&self) -> bool {
        self.lo == self.hi
    }

    /// Whether `offset` falls inside the half-open range.
    pub const fn contains(&self, offset: u32) -> bool {
        self.lo <= offset && offset < self.hi
    }

    /// The smallest span covering both operands.
    pub fn to(self, other: Span) -> Span {
        Span::new(self.lo.min(other.lo), self.hi.max(other.hi))
    }

    /// The span as a slice index.
    pub const fn range(&self) -> Range<usize> {
        self.lo as usize..self.hi as usize
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..{}", self.lo, self.hi)
    }
}

/// Declares a `u32` newtype handle with the accessors every arena index needs.
macro_rules! index_handle {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u32);

        impl $name {
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

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}#{}", stringify!($name), self.0)
            }
        }
    };
}

index_handle! {
    /// An index into a [`crate::syntax::intern::SymbolTable`].
    ///
    /// Symbols are assigned densely in first-seen order, so identical input
    /// yields identical symbols (`REQ-SYN-5`).
    Symbol
}

index_handle! {
    /// An index into a [`crate::syntax::token::Tokens`] buffer.
    TokenId
}

index_handle! {
    /// An index into a [`crate::syntax::tree::Arena`]'s node vectors.
    NodeId
}

index_handle! {
    /// An index into the diagnostic list a parse returns alongside its product.
    DiagId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reversed_bounds_yield_an_empty_span_rather_than_underflowing() {
        let span = Span::new(20, 10);
        assert!(span.is_empty());
        assert_eq!(span.len(), 0);
        assert_eq!(span.lo, 20);
    }

    #[test]
    fn contains_is_half_open() {
        let span = Span::new(4, 7);
        assert!(!span.contains(3));
        assert!(span.contains(4));
        assert!(span.contains(6));
        assert!(!span.contains(7), "hi is exclusive");
    }

    #[test]
    fn to_covers_both_operands_in_either_order() {
        let a = Span::new(10, 20);
        let b = Span::new(4, 7);
        assert_eq!(a.to(b), Span::new(4, 20));
        assert_eq!(b.to(a), Span::new(4, 20));
    }

    #[test]
    fn an_inserted_token_has_a_position_but_no_extent() {
        let span = Span::empty_at(12);
        assert!(span.is_empty());
        assert_eq!(span.range(), 12..12);
    }

    #[test]
    fn handles_round_trip_their_index() {
        assert_eq!(NodeId::new(7).index(), 7);
        assert_eq!(TokenId::new(0).raw(), 0);
        assert_eq!(Symbol::new(3).to_string(), "Symbol#3");
    }
}
