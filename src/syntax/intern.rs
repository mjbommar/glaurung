//! `SB-2` --- symbol interning.
//!
//! Spec: `docs/design/source-front-ends/substrate.md` sections 2.3 and 7.

use std::collections::HashMap;

use crate::syntax::ids::Symbol;

/// Interns strings into dense [`Symbol`] handles.
///
/// Two names that read as the same identifier text --- across an entire
/// translation unit, and across every language front end that shares this
/// substrate --- collapse to one `Symbol`, so downstream code compares a
/// `u32` instead of a string.
///
/// Symbols are assigned **densely, in first-seen order**: the first distinct
/// string interned gets `Symbol#0`, the second distinct string gets
/// `Symbol#1`, and so on, regardless of how many times each is looked up
/// afterward. This is `REQ-SYN-5` and it is load-bearing, not incidental:
/// every gate in this programme is a diff against a previous run, and a
/// non-deterministic numbering (a `HashMap` iteration order, say) would make
/// every such diff noise. Feed the same sequence of strings to two
/// `SymbolTable`s and they produce identical symbols for identical input.
///
/// Storage is deliberately simple: a `Vec<String>` holds the canonical text
/// for each symbol (indexed by the symbol itself) and a `HashMap<String,
/// Symbol>` maps text back to its symbol for `intern`/`get`. This duplicates
/// every string's bytes once, in exchange for never touching unsafe code or
/// a self-referential borrow to share storage between the two directions;
/// see `REQ-SYN-6`. The duplication is a plain memory/complexity trade a
/// future change could revisit (e.g. an interner crate that stores strings
/// once behind an index), but nothing here depends on it.
#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    /// Canonical text for symbol `i`, at index `i`.
    strings: Vec<String>,
    /// Reverse lookup from text to the symbol already assigned to it.
    lookup: HashMap<String, Symbol>,
}

impl SymbolTable {
    /// An empty table.
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            lookup: HashMap::new(),
        }
    }

    /// Interns `s`, returning its existing `Symbol` if this exact text has
    /// been interned before, or assigning it the next dense id otherwise.
    pub fn intern(&mut self, s: &str) -> Symbol {
        if let Some(&sym) = self.lookup.get(s) {
            return sym;
        }
        let sym = Symbol::new(self.strings.len() as u32);
        self.strings.push(s.to_string());
        self.lookup.insert(s.to_string(), sym);
        sym
    }

    /// The text a previously interned `sym` stands for.
    ///
    /// A `Symbol` this table never produced (from another table, or built by
    /// hand with [`Symbol::new`]) resolves to `""` rather than panicking:
    /// there is no interned text to return, and a lookup miss is not a
    /// property of parsed input that should ever crash a caller.
    pub fn resolve(&self, sym: Symbol) -> &str {
        self.strings
            .get(sym.index())
            .map(String::as_str)
            .unwrap_or("")
    }

    /// Looks up `s` without interning it, for a caller that wants to know
    /// whether a name has already been seen (e.g. to check a keyword table)
    /// without growing the table on a miss.
    pub fn get(&self, s: &str) -> Option<Symbol> {
        self.lookup.get(s).copied()
    }

    /// How many distinct strings have been interned.
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// Whether no strings have been interned yet.
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_the_same_string_twice_returns_the_same_symbol() {
        let mut t = SymbolTable::new();
        let a = t.intern("foo");
        let b = t.intern("foo");
        assert_eq!(a, b);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn distinct_strings_get_distinct_symbols() {
        let mut t = SymbolTable::new();
        let a = t.intern("foo");
        let b = t.intern("bar");
        assert_ne!(a, b);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn symbols_are_assigned_densely_in_first_seen_order() {
        let mut t = SymbolTable::new();
        let a = t.intern("alpha");
        let b = t.intern("beta");
        let a_again = t.intern("alpha");
        let c = t.intern("gamma");
        assert_eq!(a.raw(), 0);
        assert_eq!(b.raw(), 1);
        assert_eq!(a_again.raw(), 0);
        assert_eq!(c.raw(), 2);
    }

    #[test]
    fn identical_input_sequences_produce_identical_symbol_numbering() {
        let names = ["foo", "bar", "foo", "baz", "bar", "qux"];
        let mut t1 = SymbolTable::new();
        let mut t2 = SymbolTable::new();
        let syms1: Vec<Symbol> = names.iter().map(|n| t1.intern(n)).collect();
        let syms2: Vec<Symbol> = names.iter().map(|n| t2.intern(n)).collect();
        assert_eq!(syms1, syms2);
    }

    #[test]
    fn resolve_returns_the_original_text() {
        let mut t = SymbolTable::new();
        let sym = t.intern("hello");
        assert_eq!(t.resolve(sym), "hello");
    }

    #[test]
    fn resolve_on_an_unknown_symbol_returns_empty_rather_than_panicking() {
        let t = SymbolTable::new();
        let bogus = Symbol::new(42);
        assert_eq!(t.resolve(bogus), "");
    }

    #[test]
    fn get_finds_an_interned_string_without_interning_a_new_one() {
        let mut t = SymbolTable::new();
        let sym = t.intern("known");
        assert_eq!(t.get("known"), Some(sym));
        assert_eq!(t.get("unknown"), None);
        assert_eq!(t.len(), 1, "get must not intern on a miss");
    }

    #[test]
    fn an_empty_table_reports_empty() {
        let t = SymbolTable::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn an_empty_string_is_a_valid_symbol() {
        let mut t = SymbolTable::new();
        let sym = t.intern("");
        assert_eq!(t.resolve(sym), "");
        assert_eq!(t.get(""), Some(sym));
    }
}
