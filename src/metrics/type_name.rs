//! `T-2`, `T-3` --- type-name normalization and width-only matching.
//!
//! Spec: `docs/design/static-c-analysis/implementation-inventory.md` section 5.
//!
//! This module ports two pieces of DecBench's `type_match.py` byte-for-byte:
//! `normalize_type` (a type spelling maps to a *set* of equivalent spellings,
//! and two types match iff the sets intersect) and the "uncommitted type"
//! handling (`undefined4`, `_DWORD`, `int4`... recover a variable's *width*
//! but not a committed C type, so they are allowed to match a ground-truth
//! scalar of the same width and nothing else).
//!
//! **Faithfulness over cleverness.** The reference never parses a type, only
//! rewrites strings, in a specific order, with specific quirks (see
//! [`normalize_type`]'s doc for two of them). This file reproduces that order
//! exactly rather than reorganising it into something that "means the same
//! thing" -- on inputs like `"long long int"` and `"_Bool"` the literal order
//! changes the answer, and the whole point of this module is to reproduce
//! the reference's score, not to improve on it (`implementation-inventory.md`
//! section 9, landmine 2, about a neighbouring component, states the house
//! attitude generally).
//!
//! **Data structures.** Two things are deliberately *not* used here:
//!
//! * A runtime `HashMap` for the alias table. [`TYPE_ALIASES`] is a plain
//!   `&'static [(&'static str, &'static str)]` walked with a linear scan.
//!   Thirty-seven entries, looked up a handful of times per variable, is not
//!   a hot path worth a `match`-based perfect hash or a lazily built
//!   `HashMap`; a linear scan is the simplest thing that is obviously
//!   correct and stays `HashMap`-free (`K-4` in `crate::metrics`: nothing
//!   that iterates a `HashMap` may reach output, and a table this size makes
//!   the point moot regardless).
//! * A `HashSet` for the per-type form collection. [`TypeForms`] wraps a
//!   `Vec<String>` deduplicated on insert. The inventory's data-structure
//!   column names `SmallVec<[Symbol; 4]>` of *interned* forms, but the forms
//!   here are not drawn from a fixed vocabulary the way the alias table's
//!   outputs are: qualifier-stripping, whitespace collapse and `*`
//!   tightening all operate on the caller's arbitrary input string (a struct
//!   name, a decompiler-invented spelling, anything), so a form is in
//!   general a *substring-derived* value with no `'static` lifetime to
//!   borrow. Interning it would need a session-wide string interner this
//!   module has no reason to own. `Vec<String>` is the simplest type that
//!   is: (a) `HashSet`-free, so insertion order -- and therefore output --
//!   stays deterministic without relying on a fixed hasher; (b) correct for
//!   the actual sizes here, which the reference's own algorithm bounds to a
//!   handful of elements (see [`TypeForms`]); and (c) `smallvec`-free, since
//!   this crate carries no such dependency (`src/syntax/diag.rs` makes the
//!   same call for the same reason). No `Symbol`/interner type exists
//!   elsewhere in the crate for this module to reuse, so introducing one
//!   here would be new machinery for a single call site.

/// `TYPE_MAP` from `type_match.py`, verbatim and in the reference's own
/// order (so a diff against the Python is a diff, not a re-derivation).
///
/// Every entry recovers a spelling some decompiler backend actually emits
/// for a *committed* type it could only partially recover:
///
/// * `undefined*`/`_BYTE`/`_WORD`/`_DWORD`/`_QWORD`/`_BOOL`/`__intN` are
///   Ghidra's and IDA's placeholder spellings for "N bytes, sign/type
///   unknown."
/// * `int1`/`int2`/`int4`/`int8` (and the `uint*` forms) are kuna's SLEIGH
///   spellings, which size `intN` in **bytes**, not bits -- `int4` is four
///   bytes, matching the `undefinedN` convention above. Without this row
///   kuna's `type_match` score is unfairly close to zero, because every one
///   of its "int4" locals would otherwise compare against a `char`-sized (or
///   nothing) `TYPE_MAP` miss.
/// * `long` maps to `long long` (not `long int`) because LP64 makes plain
///   `long` eight bytes -- the same width as DWARF's `long int`/`long long`
///   -- on every target this benchmark runs against.
/// * The `u?int*_t`/`size_t`/`ssize_t` rows fold the C99 fixed-width and
///   POSIX aliases onto the same five-way canonical vocabulary
///   (`char`/`short`/`int`/`long long`/`bool`) so a stdint-spelled ground
///   truth and a plain-int decompiler output can still meet in the middle.
///
/// Looked up with [`type_alias`], a linear scan -- see the module doc for
/// why that beats a `HashMap` here.
const TYPE_ALIASES: &[(&str, &str)] = &[
    ("undefined8", "long long"),
    ("undefined4", "int"),
    ("undefined2", "short"),
    ("undefined1", "char"),
    ("undefined", "char"),
    ("__int64", "long long"),
    ("__int32", "int"),
    ("__int16", "short"),
    ("__int8", "char"),
    ("_QWORD", "long long"),
    ("_DWORD", "int"),
    ("_WORD", "short"),
    ("_BYTE", "char"),
    ("_BOOL", "bool"),
    ("int1", "char"),
    ("int2", "short"),
    ("int4", "int"),
    ("int8", "long long"),
    ("uint1", "char"),
    ("uint2", "short"),
    ("uint4", "int"),
    ("uint8", "long long"),
    ("uint", "int"),
    ("ulong", "long long"),
    ("long", "long long"),
    ("ushort", "short"),
    ("uchar", "char"),
    ("uint64_t", "long long"),
    ("uint32_t", "int"),
    ("uint16_t", "short"),
    ("uint8_t", "char"),
    ("int64_t", "long long"),
    ("int32_t", "int"),
    ("int16_t", "short"),
    ("int8_t", "char"),
    ("size_t", "long long"),
    ("ssize_t", "long long"),
];

/// `QUALIFIERS` from `type_match.py`, verbatim and in the reference's own
/// order.
///
/// Stripped as `"{qualifier} "` (the trailing space is part of the pattern,
/// so a qualifier only strips as a leading word, not as a bare substring)
/// from a type spelling before matching, since a ground-truth `unsigned int`
/// and a decompiled `int` (or vice versa) are the same recovered width and
/// this metric does not credit signedness. Order matters only in that later
/// qualifiers strip from the result of earlier ones -- irrelevant in
/// practice since real spellings carry at most one or two of these, but
/// preserved anyway per this module's "reproduce, don't reorganise" rule.
const QUALIFIERS: [&str; 7] = [
    "unsigned", "signed", "const", "volatile", "register", "static", "extern",
];

/// The `(original, replacement)` rewrite rules `normalize_type` applies
/// after qualifier stripping, verbatim and in the reference's own order.
///
/// Each rule folds a DWARF-style multi-word spelling onto the shorter form
/// `TYPE_ALIASES` and the rest of the metric use as canonical. The order is
/// load-bearing in a way that is easy to miss: every already-produced form is
/// re-scanned by every later rule (see [`normalize_type`]'s doc for the
/// substring-overlap consequence), so moving a rule changes which forms a
/// type ends up with.
const REWRITES: [(&str, &str); 6] = [
    ("long long int", "long long"),
    ("long int", "long long"),
    ("short int", "short"),
    ("_Bool", "bool"),
    ("Bool", "bool"),
    ("boolean", "bool"),
];

/// Looks `spelling` up in [`TYPE_ALIASES`], an exact (not substring) match.
///
/// `None` means "not a recognized placeholder/alias spelling" -- which is
/// the common case, since most ground-truth and decompiled type strings
/// (`int`, `struct Foo *`, `MyEnum`...) are not one of the 37 rows.
fn type_alias(spelling: &str) -> Option<&'static str> {
    TYPE_ALIASES
        .iter()
        .find(|(key, _)| *key == spelling)
        .map(|(_, value)| *value)
}

/// The set of spellings one type string normalizes to.
///
/// Produced by [`normalize_type`]; two types are considered the same type
/// iff [`types_match`] finds their `TypeForms` overlap. See the module doc
/// for why this wraps a deduplicated `Vec<String>` rather than a `HashSet`
/// or an interned/`SmallVec` collection: forms are derived from arbitrary
/// caller input, not drawn from a fixed vocabulary, and `HashSet` iteration
/// order is not the insertion-order determinism this crate's metrics commit
/// to (`K-4` in `crate::metrics`).
///
/// In practice this holds a handful of elements -- the reference's own
/// algorithm (qualifier-strip once, up to six rewrite rules, a whitespace
/// collapse, a `*`-tightening pass, one re-alias pass) bounds it well below
/// what would make a linear `contains`/`intersects` scan worth replacing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypeForms(Vec<String>);

impl TypeForms {
    /// The empty form set (what [`normalize_type`] returns for `""`, and
    /// what an all-whitespace input reduces to as well -- see that
    /// function's doc).
    #[must_use]
    pub fn empty() -> Self {
        TypeForms(Vec::new())
    }

    /// Whether this holds no spellings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of distinct spellings recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether `form` is one of the recorded spellings, compared exactly and
    /// case-sensitively -- the same semantics as Python's `in` on a
    /// `set[str]`.
    #[must_use]
    pub fn contains(&self, form: &str) -> bool {
        self.0.iter().any(|f| f == form)
    }

    /// The recorded spellings in insertion order (deduplicated, but
    /// otherwise unsorted -- callers that need a canonical order for
    /// display or comparison should sort this themselves; the type does not
    /// impose one so a lookup never pays for a sort it doesn't need).
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Inserts `form` unless it is already present.
    ///
    /// The linear `contains` scan is the `HashSet`-avoidance this type
    /// exists for: see the module doc. It is `O(len)` per insert, `O(len^2)`
    /// over one `normalize_type` call, and `len` here is always small.
    fn insert(&mut self, form: String) {
        if !self.contains(&form) {
            self.0.push(form);
        }
    }
}

/// Normalizes a type string to the set of spellings it is equivalent to.
///
/// Ports `type_match.py`'s `normalize_type` line for line, in its exact
/// order: an empty input short-circuits to the empty set; the alias-table
/// lookup; the qualifier strip; the six `REWRITES` rules, each re-scanning
/// every form produced so far (not just the original string); a whitespace
/// collapse; a `*`-tightening pass; and finally a **second** alias-table
/// lookup over every form produced up to that point. Two types match iff
/// [`types_match`] finds their `normalize_type` outputs intersect.
///
/// The reference never parses the input as a type -- it is pure string
/// rewriting, and this port stays pure string rewriting for the same
/// reason: any actual parsing (splitting a pointer suffix, recognizing an
/// array dimension, distinguishing `struct Foo` from `Foo`) would produce
/// answers the reference does not, and the entire point of this module is
/// to reproduce DecBench's score without running DecBench.
///
/// # Two things this reproduces on purpose, not by mistake
///
/// Because every `REWRITES` rule re-scans forms already produced by earlier
/// rules (not just the caller's original string), a form can accumulate a
/// second, overlapping rewrite:
///
/// * `"long long int"` contains `"long int"` as a substring (`long `**`long
///   int`**), so after the first rule turns it into `"long long"`, the
///   *second* rule (`"long int" -> "long long"`) also fires on the
///   surviving original `"long long int"` form, producing a third form:
///   `"long long long"`. Confirmed against the live reference:
///   `normalize_type("long long int")` returns
///   `{"long long", "long long int", "long long long"}`.
/// * `"_Bool"` contains `"Bool"` as a substring, so after the `"_Bool" ->
///   "bool"` rule fires, the later `"Bool" -> "bool"` rule *also* fires on
///   the original `"_Bool"` form (which is still present), turning it into
///   `"_bool"`. Confirmed: `normalize_type("_Bool")` returns `{"_Bool",
///   "_bool", "bool"}`.
///
/// Neither of these is a type C would ever spell (`long long long` is not
/// legal C, and `_bool` is not a standard spelling), but they are real
/// members of the reference's output sets, and a ground-truth or
/// decompiled type that happens to be spelled `"long long long"` (unlikely,
/// but not impossible from a fuzzed or hand-written fixture) would match
/// `"long long int"` under the reference's rules. This port reproduces both
/// quirks exactly rather than "fixing" them, per this module's stated goal.
#[must_use]
pub fn normalize_type(type_str: &str) -> TypeForms {
    if type_str.is_empty() {
        return TypeForms::empty();
    }

    let trimmed = type_str.trim();
    let base = type_alias(trimmed).unwrap_or(trimmed).to_string();

    let mut forms = TypeForms::empty();
    forms.insert(base.clone());

    let mut stripped = base;
    for qualifier in QUALIFIERS {
        stripped = stripped.replace(&format!("{qualifier} "), "");
    }
    let stripped = stripped.trim().to_string();
    if !stripped.is_empty() {
        forms.insert(stripped);
    }

    for (original, replacement) in REWRITES {
        // A fresh snapshot per rule, exactly matching the reference's
        // `for form in list(forms)`: a rule sees every form produced by
        // rules before it, but not forms it adds itself mid-iteration.
        let snapshot = forms.0.clone();
        for form in snapshot {
            if form.contains(original) {
                forms.insert(form.replace(original, replacement));
            }
        }
    }

    let mut collapsed = TypeForms::empty();
    for form in &forms.0 {
        let c = collapse_whitespace(form);
        if !c.is_empty() {
            collapsed.insert(c);
        }
    }
    let mut forms = collapsed;

    let snapshot = forms.0.clone();
    for form in snapshot {
        forms.insert(tighten_stars(&form));
    }

    let snapshot = forms.0.clone();
    for form in snapshot {
        if let Some(mapped) = type_alias(&form) {
            forms.insert(mapped.to_string());
        }
    }

    forms
}

/// Whether `a` and `b` denote the same type under [`normalize_type`]: their
/// form sets intersect.
///
/// A nested linear scan, not a hash-set intersection: both sides hold at
/// most a handful of elements (see [`TypeForms`]), so this is the simplest
/// thing that is obviously correct rather than a premature hash lookup.
#[must_use]
pub fn types_match(a: &TypeForms, b: &TypeForms) -> bool {
    a.0.iter().any(|x| b.0.iter().any(|y| x == y))
}

/// Collapses every run of whitespace in `s` to a single ASCII space and
/// trims the ends, mirroring `re.sub(r"\s+", " ", f).strip()`.
///
/// `split_whitespace` already splits on (and therefore drops) leading and
/// trailing whitespace runs and treats any interior run as one boundary, so
/// joining its tokens with a single space reproduces the regex substitution
/// without building one. Operates on `char`s throughout, so this never
/// slices a `&str` at a non-`char` boundary regardless of the input's
/// script.
fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Removes whitespace immediately preceding a `*`, mirroring
/// `re.sub(r"\s*\*", "*", f)`: every run of whitespace that is directly
/// followed by a `*` disappears; whitespace anywhere else (including
/// trailing whitespace with no `*` after it) is left alone.
///
/// Implemented as a single left-to-right pass that buffers a pending
/// whitespace run and only commits it to the output once it is known
/// *not* to be immediately followed by a `*` (a `*` discards the buffer
/// instead of flushing it). This reproduces `re.sub`'s greedy,
/// leftmost-non-overlapping match semantics for `\s*\*` without a regex
/// engine: each `*` in the input consumes exactly the whitespace run
/// immediately before it, once. Iterates by `char`, so multi-byte input is
/// handled without ever indexing a `&str` at a non-`char` boundary.
fn tighten_stars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_ws = String::new();
    for ch in s.chars() {
        if ch == '*' {
            pending_ws.clear();
            out.push('*');
        } else if ch.is_whitespace() {
            pending_ws.push(ch);
        } else {
            out.push_str(&pending_ws);
            pending_ws.clear();
            out.push(ch);
        }
    }
    out.push_str(&pending_ws);
    out
}

/// Whether `type_str` (after trimming) is one of the fixed "uncommitted"
/// spellings a decompiler emits for "N bytes, no committed C type" --
/// mirrors `_UNCOMMITTED_TYPES.match(t)` from the reference, minus the `*`
/// check (that lives in [`uncommitted_size`], matching the reference's own
/// split between the regex and the wrapping function).
///
/// `undefined\d*` in the reference is the one open-ended alternative (any
/// number of trailing digits, including none); everything else is a fixed,
/// finite set of literal spellings, reproduced here as exact matches rather
/// than a regex engine.
#[must_use]
pub fn is_uncommitted_type(type_str: &str) -> bool {
    let t = type_str.trim();

    if let Some(digits) = t.strip_prefix("undefined") {
        if digits.chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }

    matches!(
        t,
        "__int8"
            | "__int16"
            | "__int32"
            | "__int64"
            | "__uint8"
            | "__uint16"
            | "__uint32"
            | "__uint64"
            | "_BYTE"
            | "_WORD"
            | "_DWORD"
            | "_QWORD"
            | "int1"
            | "int2"
            | "int3"
            | "int4"
            | "int5"
            | "int6"
            | "int7"
            | "int8"
            | "uint1"
            | "uint2"
            | "uint3"
            | "uint4"
            | "uint5"
            | "uint6"
            | "uint7"
            | "uint8"
            | "byte"
            | "word"
            | "dword"
            | "qword"
            | "uchar"
    )
}

/// The byte width `type_str` (after trimming) is known to name, from
/// `_UNCOMMITTED_WIDTH` in the reference.
///
/// Note this is a smaller table than [`is_uncommitted_type`]'s pattern set:
/// e.g. `"undefined123"` and `"int3"` both satisfy `is_uncommitted_type`
/// (they match the reference's regex) but have no entry here, because the
/// reference's `_UNCOMMITTED_WIDTH` dict only names the widths that its
/// SLEIGH/Ghidra/IDA sources actually emit (1, 2, 4, 8 bytes). Those
/// unlisted spellings fall through to `None` here exactly as they do in
/// `_uncommitted_size` -- unless the caller supplies an explicit `size` of
/// 1, 2, 4 or 8, which [`uncommitted_size`] checks first.
#[must_use]
pub fn uncommitted_width(type_str: &str) -> Option<u64> {
    let t = type_str.trim();
    match t {
        "undefined" | "undefined1" | "byte" | "uchar" | "_BYTE" | "int1" | "uint1" | "__int8"
        | "__uint8" => Some(1),
        "undefined2" | "word" | "_WORD" | "int2" | "uint2" | "__int16" | "__uint16" => Some(2),
        "undefined4" | "dword" | "_DWORD" | "int4" | "uint4" | "__int32" | "__uint32" => Some(4),
        "undefined8" | "qword" | "_QWORD" | "int8" | "uint8" | "__int64" | "__uint64" => Some(8),
        _ => None,
    }
}

/// The ground-truth scalar spellings an uncommitted type of `width` bytes
/// is allowed to match, from `_SIZE_SCALARS` in the reference.
///
/// Integer and `bool` only. A committed `float`/`double` ground truth is
/// deliberately excluded: if the decompiler only recovered a width, a
/// floating-point ground truth is a type it demonstrably failed to
/// recover, not a match. Pointers and aggregates never appear here at all,
/// which is what keeps `undefined8` from matching `char *` (see the tests).
/// Any width other than 1, 2, 4 or 8 (there is no such width in the
/// reference's tables) yields an empty slice.
#[must_use]
pub fn size_scalars(width: u64) -> &'static [&'static str] {
    match width {
        1 => &["char", "bool"],
        2 => &["short"],
        4 => &["int"],
        8 => &["long long"],
        _ => &[],
    }
}

/// The byte width an uncommitted (width-only) decompiler type recovers, or
/// `None` if `type_str` is not uncommitted at all.
///
/// Ports `_uncommitted_size` from the reference. `size` is the caller's
/// already-known variable size (DWARF's `DW_AT_byte_size`, or a
/// decompiler's own size field); pass `None` when it is unavailable, which
/// is how the reference treats a missing/`None` `var.size`. A pointer
/// spelling (containing `*`) is never uncommitted, regardless of what
/// `is_uncommitted_type` would otherwise say -- a pointer is a committed
/// type, just possibly to something unresolved.
///
/// When `size` is exactly 1, 2, 4 or 8, it wins over the spelling-based
/// [`uncommitted_width`] lookup (matching the reference's `if size in
/// _UNCOMMITTED... : return int(size)` check, which runs first): a known
/// size is stronger evidence than the type string, and it is what lets an
/// unlisted-but-still-uncommitted spelling like `"undefined123"` still
/// resolve to a width when the size field backs it up.
#[must_use]
pub fn uncommitted_size(type_str: &str, size: Option<u64>) -> Option<u64> {
    let t = type_str.trim();
    if t.contains('*') || !is_uncommitted_type(t) {
        return None;
    }
    if let Some(sz) = size {
        if matches!(sz, 1 | 2 | 4 | 8) {
            return Some(sz);
        }
    }
    uncommitted_width(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_is_the_empty_set() {
        let forms = normalize_type("");
        assert!(forms.is_empty());
        assert!(forms.as_slice().is_empty());
    }

    #[test]
    fn whitespace_only_reduces_to_the_empty_set() {
        // Python takes a different early-return path for "" than for an
        // all-whitespace string (see `normalize_type`'s doc), but both end
        // up empty. Confirmed against the reference: `normalize_type("
        // ")` returns `set()`.
        let forms = normalize_type("   \t  ");
        assert!(forms.is_empty());
    }

    #[test]
    fn unknown_type_normalizes_to_itself_only() {
        let forms = normalize_type("MyWeirdEnum");
        assert_eq!(forms.as_slice(), &["MyWeirdEnum".to_string()]);
    }

    #[test]
    fn every_type_alias_round_trips() {
        for (key, value) in TYPE_ALIASES {
            let key_forms = normalize_type(key);
            let value_forms = normalize_type(value);
            assert!(
                key_forms.contains(value),
                "normalize_type({key:?}) = {key_forms:?} does not contain alias target {value:?}"
            );
            assert!(
                types_match(&key_forms, &value_forms),
                "normalize_type({key:?}) does not match normalize_type({value:?})"
            );
        }
    }

    #[test]
    fn unsigned_long_matches_long() {
        let a = normalize_type("unsigned long");
        let b = normalize_type("long");
        // "long" aliases to "long long" (LP64); "unsigned long" strips its
        // qualifier to "long", which then re-aliases to "long long" too.
        assert!(types_match(&a, &b));
        assert!(a.contains("long long"));
    }

    #[test]
    fn long_long_int_matches_long_long() {
        let a = normalize_type("long long int");
        let b = normalize_type("long long");
        assert!(types_match(&a, &b));
        // The documented quirk: a third, non-C form also appears.
        assert!(a.contains("long long long"));
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn char_pointer_star_spacing_is_tightened() {
        let a = normalize_type("char *");
        let b = normalize_type("char*");
        assert!(types_match(&a, &b));
        assert!(a.contains("char*"));
        assert!(b.contains("char*"));
    }

    #[test]
    fn bool_family_matches() {
        let a = normalize_type("_Bool");
        let b = normalize_type("bool");
        assert!(types_match(&a, &b));
        // The documented quirk: "_Bool" also contains "Bool" as a
        // substring, so the later "Bool" -> "bool" rule fires on it too.
        assert!(a.contains("_bool"));
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn undefined8_matches_long_but_not_char_pointer() {
        let undefined8 = normalize_type("undefined8");
        let long_long = normalize_type("long long");
        let char_ptr = normalize_type("char *");
        assert!(types_match(&undefined8, &long_long));
        assert!(!types_match(&undefined8, &char_ptr));

        // The width-only path: undefined8 is 8 bytes, and 8 bytes matches
        // the "long long" ground-truth scalar and nothing pointer-shaped.
        let width = uncommitted_size("undefined8", None).expect("undefined8 is uncommitted");
        assert_eq!(width, 8);
        assert!(size_scalars(width).contains(&"long long"));
        assert!(!size_scalars(width).contains(&"char *"));

        // A pointer spelling is never uncommitted, even if it were somehow
        // an otherwise-matching token.
        assert_eq!(uncommitted_size("undefined8 *", None), None);
    }

    #[test]
    fn int4_is_four_bytes_not_four_bits() {
        // kuna's SLEIGH spellings size intN in BYTES.
        assert_eq!(uncommitted_width("int4"), Some(4));
        assert_eq!(uncommitted_size("int4", None), Some(4));
        assert!(size_scalars(4).contains(&"int"));

        let a = normalize_type("int4");
        let b = normalize_type("int");
        assert!(types_match(&a, &b));
    }

    #[test]
    fn size_t_and_ssize_t() {
        let size_t = normalize_type("size_t");
        let ssize_t = normalize_type("ssize_t");
        let long_long = normalize_type("long long");
        assert!(types_match(&size_t, &long_long));
        assert!(types_match(&ssize_t, &long_long));
        assert!(types_match(&size_t, &ssize_t));
    }

    #[test]
    fn uncommitted_width_table_matches_size_scalars_domain() {
        // Every width uncommitted_width can produce has a non-empty
        // size_scalars entry, and vice versa for the four real widths.
        for width in [1u64, 2, 4, 8] {
            assert!(!size_scalars(width).is_empty());
        }
        assert!(size_scalars(3).is_empty());
        assert!(size_scalars(0).is_empty());
    }

    #[test]
    fn uncommitted_type_with_unlisted_digit_suffix_needs_an_explicit_size() {
        // "undefined123" satisfies the reference's regex (any number of
        // trailing digits) but has no entry in _UNCOMMITTED_WIDTH, so only
        // an explicit size resolves it.
        assert!(is_uncommitted_type("undefined123"));
        assert_eq!(uncommitted_width("undefined123"), None);
        assert_eq!(uncommitted_size("undefined123", None), None);
        assert_eq!(uncommitted_size("undefined123", Some(4)), Some(4));

        // Likewise int3/uint5: matched by u?int[1-8] but absent from the
        // width table.
        assert!(is_uncommitted_type("int3"));
        assert_eq!(uncommitted_width("int3"), None);
        assert_eq!(uncommitted_size("int3", Some(8)), Some(8));
    }

    #[test]
    fn does_not_panic_on_long_or_non_ascii_input() {
        let long_input = "x".repeat(10_000);
        let forms = normalize_type(&long_input);
        assert!(!forms.is_empty());

        let unicode_inputs = [
            "\u{1F600}",    // an emoji, well outside any char-boundary trap
            "结构体 *",     // CJK identifier with a pointer suffix
            "  \u{00A0}  ", // NBSP, a Unicode whitespace char std treats as such
            "long\u{00A0}long",
        ];
        for input in unicode_inputs {
            let _ = normalize_type(input);
            let _ = is_uncommitted_type(input);
            let _ = uncommitted_size(input, Some(4));
        }
    }

    #[test]
    fn qualifiers_only_strip_as_a_leading_word() {
        // "unsigned" without a trailing space is not a qualifier occurrence
        // per the reference's `replace(f"{q} ", "")`; this is a type name
        // (however unlikely) that happens to start with the word.
        let forms = normalize_type("unsignedish");
        assert!(forms.contains("unsignedish"));
    }

    /// Runs the reference Python (`type_match.normalize_type`) over a
    /// generated corpus of type strings and asserts this module agrees with
    /// it, both on the exact form sets and on the pairwise `types_match`
    /// verdict over every ordered pair. Requires the DecBench checkout;
    /// skips cleanly (passing) when it is not present, per this repo's rule
    /// against depending on an out-of-repo checkout in a committed test.
    #[test]
    fn differential_against_live_decbench_python() {
        differential::run();
    }

    /// Isolated so `differential_against_live_decbench_python` stays short;
    /// see its doc for what this proves.
    mod differential {
        use super::super::{normalize_type, types_match};
        use std::collections::BTreeSet;
        use std::path::PathBuf;
        use std::process::Command;

        fn decbench_dir() -> PathBuf {
            std::env::var("DECBENCH_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/nas4/data/workspace-infosec/decbench"))
        }

        fn scratch_dir() -> PathBuf {
            let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".to_string());
            let dir = PathBuf::from(base).join("glaurung-type-name-differential");
            let _ = std::fs::create_dir_all(&dir);
            dir
        }

        /// The candidate type strings the differential runs over: every
        /// `TYPE_ALIASES` key and value, the `REWRITES`-triggering C
        /// spellings, every `QUALIFIERS` word applied to a handful of
        /// bases, and a handful of pointer/array spellings.
        fn candidate_type_strings() -> Vec<String> {
            let mut v: Vec<String> = Vec::new();

            for (key, value) in super::super::TYPE_ALIASES {
                v.push((*key).to_string());
                v.push((*value).to_string());
            }

            for s in [
                "long long int",
                "long int",
                "short int",
                "_Bool",
                "Bool",
                "boolean",
                "void",
                "float",
                "double",
                "long",
                "int",
                "char",
                "short",
                "bool",
                "unsigned long",
                "signed char",
                "unsignedish",
            ] {
                v.push(s.to_string());
            }

            let bases = [
                "long long",
                "int",
                "short",
                "char",
                "bool",
                "long",
                "long long int",
                "long int",
            ];
            for qualifier in super::super::QUALIFIERS {
                for base in bases {
                    v.push(format!("{qualifier} {base}"));
                }
            }

            for s in [
                "char *",
                "char*",
                "int **",
                "void*",
                "long long *",
                "struct Foo *",
                "char[10]",
                "int[4]",
                "unsigned char *",
                "undefined8 *",
                "undefined4",
                "_DWORD",
                "int4",
                "byte",
                "qword",
                "uchar",
                "  spaced   out   type  ",
                "",
            ] {
                v.push(s.to_string());
            }

            v.sort();
            v.dedup();
            v
        }

        /// Calls the live reference's `normalize_type` on every candidate,
        /// returning `None` if the DecBench checkout/venv is not available.
        fn python_forms(
            candidates: &[String],
        ) -> Option<std::collections::BTreeMap<String, BTreeSet<String>>> {
            let decbench_dir = decbench_dir();
            let python = decbench_dir.join(".venv").join("bin").join("python");
            if !python.is_file() {
                return None;
            }

            let dir = scratch_dir();
            let input_path = dir.join("candidates.json");
            let output_path = dir.join("forms.json");

            let input_json = serde_json::to_string(candidates).expect("serialize candidates");
            std::fs::write(&input_path, input_json).expect("write candidates.json");

            let script = r#"
import json
import sys

from decbench.metrics.type_match import normalize_type

with open(sys.argv[1]) as f:
    candidates = json.load(f)

out = {s: sorted(normalize_type(s)) for s in candidates}

with open(sys.argv[2], "w") as f:
    json.dump(out, f)
"#;

            let output = Command::new(&python)
                .arg("-c")
                .arg(script)
                .arg(&input_path)
                .arg(&output_path)
                .env("PYTHONPATH", &decbench_dir)
                .output();

            let output = match output {
                Ok(o) => o,
                Err(_) => return None,
            };
            if !output.status.success() {
                eprintln!(
                    "reference python invocation failed: stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                return None;
            }

            let raw = std::fs::read_to_string(&output_path).ok()?;
            let parsed: std::collections::BTreeMap<String, Vec<String>> =
                serde_json::from_str(&raw).ok()?;
            Some(
                parsed
                    .into_iter()
                    .map(|(k, v)| (k, v.into_iter().collect::<BTreeSet<_>>()))
                    .collect(),
            )
        }

        pub(super) fn run() {
            let candidates = candidate_type_strings();
            let Some(python_forms) = python_forms(&candidates) else {
                eprintln!(
                    "SKIP differential_against_live_decbench_python: DecBench checkout not \
                     found (looked for {:?}); this is expected outside the environment that \
                     has /nas4 mounted",
                    decbench_dir().join(".venv").join("bin").join("python")
                );
                return;
            };

            let mut set_mismatches: Vec<String> = Vec::new();
            let mut rust_forms_by_candidate: std::collections::BTreeMap<String, BTreeSet<String>> =
                std::collections::BTreeMap::new();

            for candidate in &candidates {
                let rust: BTreeSet<String> = normalize_type(candidate)
                    .as_slice()
                    .iter()
                    .cloned()
                    .collect();
                let python = python_forms.get(candidate).cloned().unwrap_or_default();
                if rust != python {
                    set_mismatches.push(format!("{candidate:?}: rust={rust:?} python={python:?}"));
                }
                rust_forms_by_candidate.insert(candidate.clone(), rust);
            }

            let mut pairs_compared: u64 = 0;
            let mut pairs_agreeing: u64 = 0;
            let mut pair_mismatches: Vec<String> = Vec::new();

            for a in &candidates {
                let rust_a = normalize_type(a);
                let python_a = &python_forms[a];
                for b in &candidates {
                    let rust_b = normalize_type(b);
                    let python_b = &python_forms[b];

                    let rust_verdict = types_match(&rust_a, &rust_b);
                    let python_verdict = !python_a.is_disjoint(python_b);

                    pairs_compared += 1;
                    if rust_verdict == python_verdict {
                        pairs_agreeing += 1;
                    } else if pair_mismatches.len() < 20 {
                        pair_mismatches.push(format!(
                            "({a:?}, {b:?}): rust={rust_verdict} python={python_verdict}"
                        ));
                    }
                }
            }

            println!(
                "type_name differential: {} candidate strings, {} exact form-set matches, \
                 {} mismatches; {} pairs compared, {} agreeing, {} disagreeing",
                candidates.len(),
                candidates.len() - set_mismatches.len(),
                set_mismatches.len(),
                pairs_compared,
                pairs_agreeing,
                pairs_compared - pairs_agreeing,
            );

            if !set_mismatches.is_empty() {
                for line in &set_mismatches {
                    eprintln!("form-set mismatch: {line}");
                }
            }
            if !pair_mismatches.is_empty() {
                for line in &pair_mismatches {
                    eprintln!("pairwise mismatch: {line}");
                }
            }

            assert!(
                set_mismatches.is_empty(),
                "{} candidate(s) had a form-set mismatch against the live reference",
                set_mismatches.len()
            );
            assert!(
                pair_mismatches.is_empty() && pairs_agreeing == pairs_compared,
                "{} of {} pairs disagreed with the live reference",
                pairs_compared - pairs_agreeing,
                pairs_compared
            );
        }
    }
}
