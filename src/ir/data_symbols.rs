//! Source names for static storage, taken from the image's own symbol table.
//!
//! # What this fixes
//!
//! A function-scoped `static int counter;` becomes an unnamed object in
//! `.bss`. Every access to it is a load or store against an absolute address,
//! so the renderer had only the address to print and spelled it
//! `glaurung_global_4040`. The name is not lost, though: for any image that
//! retains a symbol table the object is right there as an `OBJECT` symbol —
//! `static_function.static_var` at `0x4040` in our own clang samples — and a
//! reader who sees `static_function_static_var` learns something that
//! `glaurung_global_4040` cannot tell them.
//!
//! This is a **symbol-table** fact, not a DWARF one. The distinction matters
//! because it decides how often the improvement applies: the samples that
//! motivated this module carry no `.debug_*` sections at all, and an ordinary
//! release build with an unstripped symbol table is far more common than one
//! shipping DWARF.
//!
//! # Why exact-start matching, and nothing looser
//!
//! The obvious generalisation — find the nearest preceding symbol — is a trap,
//! and two mature decompilers fall into it on one of our own samples. Given
//! `mprotect((void *)((unsigned long)main & ~0xFFF), ...)`, which page-aligns
//! a *runtime-computed* address, both angr 9.3.3 and Ghidra 12.1.3 report
//! `mprotect(_init, 0x1000, 5)`: the computed page base collided with the
//! address of `_init`, the nearest symbol won, and the masking arithmetic
//! disappeared from the output entirely. The reader is then told, in valid-
//! looking C, that the program changed the protection of `_init`. It did not.
//!
//! So the rule here is deliberately the strictest one that still fixes the
//! motivating case: **the address must equal the start of a sized data
//! object.** Not "nearest", not "within a page", not "inside the object at a
//! non-zero offset". An address we cannot name to that standard keeps its
//! synthetic `glaurung_global_*` spelling, which is ugly and honest, and never
//! asserts an identity the image does not support.
//!
//! Interior addresses (`&arr[2]`) therefore keep the synthetic name today.
//! That is a knowingly-accepted gap: naming them requires rendering
//! `name + offset` through the tentative-object machinery in
//! [`crate::ir::ast`], and until that exists a wrong name is far worse than a
//! missing one.

use std::collections::BTreeMap;

/// One named data object from an image's symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSymbol {
    /// Virtual address of the object's first byte.
    pub address: u64,
    /// Size in bytes as declared by the symbol table. Always non-zero: a
    /// zero-sized symbol names no storage and is rejected at construction.
    pub size: u64,
    /// The symbol's name, sanitised to a valid C identifier.
    pub name: String,
}

/// Data-object names for one image, keyed by exact start address.
///
/// Construction filters aggressively; lookup is then a plain exact-match on a
/// map, so no caller can accidentally reintroduce nearest-symbol behaviour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DataSymbols {
    by_address: BTreeMap<u64, DataSymbol>,
}

impl DataSymbols {
    /// An empty table. Every lookup misses, so the renderer keeps its
    /// synthetic names — the behaviour before this module existed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from `(address, size, name)` triples, one per symbol-table entry.
    ///
    /// Rejects, in order: zero addresses (undefined symbols), zero sizes
    /// (markers such as `__TMC_END__` and `_edata`, which name a boundary
    /// rather than an object — and which are exactly what a nearest-symbol
    /// search latches onto), names that sanitise to nothing useful, and names
    /// reserved by the C implementation.
    ///
    /// When two symbols claim one address the lexicographically smaller name
    /// wins, so the table does not depend on symbol-table order.
    pub fn from_entries<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = (u64, u64, S)>,
        S: AsRef<str>,
    {
        let mut by_address: BTreeMap<u64, DataSymbol> = BTreeMap::new();
        for (address, size, raw) in entries {
            if address == 0 || size == 0 {
                continue;
            }
            let raw = raw.as_ref();
            if raw.is_empty() || !is_nameable(raw) {
                continue;
            }
            let name = crate::ir::ast::sanitize_c_ident(raw);
            match by_address.get(&address) {
                Some(existing) if existing.name <= name => continue,
                _ => {}
            }
            by_address.insert(
                address,
                DataSymbol {
                    address,
                    size,
                    name,
                },
            );
        }
        Self { by_address }
    }

    /// The source name for static storage beginning **exactly** at `address`.
    ///
    /// Returns `None` for an interior address, an unsized symbol, or an
    /// address the image does not describe. See the module docs for why this
    /// is not a nearest-symbol search.
    pub fn name_for(&self, address: u64) -> Option<&str> {
        self.by_address.get(&address).map(|s| s.name.as_str())
    }

    /// Number of named objects.
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    /// Whether the table names nothing.
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }
}

/// Whether a raw symbol name should be allowed to name storage in output C.
///
/// Rejects the toolchain's own scaffolding. These are real, sized objects in
/// some images, so size alone does not exclude them, and printing
/// `_GLOBAL_OFFSET_TABLE_` where the program meant "the GOT slot for `printf`"
/// tells the reader less than the address does.
fn is_nameable(raw: &str) -> bool {
    const REJECTED: &[&str] = &[
        "_GLOBAL_OFFSET_TABLE_",
        "_DYNAMIC",
        "__dso_handle",
        "__abi_tag",
        "__TMC_END__",
        "_edata",
        "_end",
        "__bss_start",
        "__data_start",
        "completed.0",
    ];
    if REJECTED.contains(&raw) {
        return false;
    }
    // Compiler-emitted array/table scaffolding: init/fini arrays, frame
    // bookkeeping. Named after the mechanism, never after program data.
    !(raw.starts_with("__frame_")
        || raw.starts_with("__do_global_")
        || raw.starts_with("__FRAME_")
        || raw.starts_with("__GNU_EH_FRAME"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_a_function_scoped_static_by_exact_address() {
        // The motivating case, verbatim from `readelf -sW` on
        // samples/.../clang/O0/hello-c-clang-O0: a `static int` inside
        // `static_function`, which the renderer spelled `glaurung_global_4040`.
        let table = DataSymbols::from_entries([(0x4040u64, 4u64, "static_function.static_var")]);
        assert_eq!(table.name_for(0x4040), Some("static_function_static_var"));
    }

    #[test]
    fn dot_qualified_names_become_valid_c_identifiers() {
        let table = DataSymbols::from_entries([(0x4040u64, 4u64, "outer.inner.deep")]);
        // A '.' is not legal in a C identifier; the rendered name must compile.
        let name = table.name_for(0x4040).expect("named");
        assert!(!name.contains('.'), "not a C identifier: {name}");
        assert_eq!(name, "outer_inner_deep");
    }

    #[test]
    fn an_interior_address_is_not_named() {
        // `&arr[1]` of a 16-byte object. Naming it would require rendering an
        // offset; asserting the object's own name here would be a lie.
        let table = DataSymbols::from_entries([(0x4040u64, 16u64, "arr")]);
        assert_eq!(table.name_for(0x4044), None);
    }

    #[test]
    fn no_nearest_symbol_fallback() {
        // The angr/Ghidra failure mode, as a test. A computed page base at
        // 0x1000 must NOT pick up `_init`-like symbols that merely precede it.
        let table =
            DataSymbols::from_entries([(0x900u64, 8u64, "before"), (0x2000u64, 8u64, "after")]);
        assert_eq!(table.name_for(0x1000), None);
    }

    #[test]
    fn zero_sized_markers_are_rejected() {
        // `__TMC_END__` is what angr printed for a static counter it could not
        // name. A boundary marker names no storage, so it never enters.
        let table = DataSymbols::from_entries([(0x4040u64, 0u64, "__TMC_END__")]);
        assert_eq!(table.name_for(0x4040), None);
        assert!(table.is_empty());
    }

    #[test]
    fn toolchain_scaffolding_is_rejected_even_when_sized() {
        for raw in [
            "_GLOBAL_OFFSET_TABLE_",
            "_DYNAMIC",
            "__dso_handle",
            "__frame_dummy_init_array_entry",
            "__do_global_dtors_aux_fini_array_entry",
            "__FRAME_END__",
        ] {
            let table = DataSymbols::from_entries([(0x4000u64, 8u64, raw)]);
            assert_eq!(table.name_for(0x4000), None, "should reject {raw}");
        }
    }

    #[test]
    fn undefined_symbols_are_rejected() {
        let table = DataSymbols::from_entries([(0u64, 8u64, "imported")]);
        assert!(table.is_empty());
    }

    #[test]
    fn duplicate_addresses_resolve_independently_of_input_order() {
        let forward =
            DataSymbols::from_entries([(0x40u64, 4u64, "alpha"), (0x40u64, 4u64, "beta")]);
        let reverse =
            DataSymbols::from_entries([(0x40u64, 4u64, "beta"), (0x40u64, 4u64, "alpha")]);
        assert_eq!(forward.name_for(0x40), reverse.name_for(0x40));
        assert_eq!(forward.name_for(0x40), Some("alpha"));
    }

    #[test]
    fn an_empty_table_names_nothing() {
        let table = DataSymbols::new();
        assert!(table.is_empty());
        assert_eq!(table.name_for(0x4040), None);
    }
}
