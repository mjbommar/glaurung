//! The scalar C type model the lowering needs, and nothing else.
//!
//! Two questions decide every op the lowering emits: how many bits does this
//! value occupy, and is it signed. That is the whole model. Aggregates,
//! pointers and floating point are represented only so the census can *name*
//! them when it refuses --- a type this module cannot answer those two
//! questions for must not reach the emitter.
//!
//! # Why the widths are hard-coded to LP64
//!
//! The fixture corpus is built for `x86_64-linux-gnu` and the differential runs
//! against those binaries, so `long` is 64 bits and plain `char` is signed.
//! This is the ABI of the thing being compared against, not a guess: a
//! different target would need its own table, and the lowering would be wrong
//! rather than approximate if it kept this one.

use crate::ir::types::Width;

/// An integer type: the width it occupies and whether it is signed.
///
/// `rank` is C's integer conversion rank, which the usual arithmetic
/// conversions need and which width alone cannot supply --- `long` and
/// `long long` are both 64 bits on LP64 but do not have the same rank, and
/// `_Bool` and `unsigned char` are both 8 bits and do not promote alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntType {
    /// Width in bits (8, 16, 32 or 64).
    pub width: Width,
    /// Whether the type is signed.
    pub signed: bool,
    /// C integer conversion rank: `_Bool` 0, `char` 1, `short` 2, `int` 3,
    /// `long` 4, `long long` 5.
    pub rank: u8,
}

impl IntType {
    /// `_Bool`.
    pub const BOOL: IntType = IntType {
        width: Width::W8,
        signed: false,
        rank: 0,
    };
    /// `int`, the type every arithmetic result promotes to at minimum.
    pub const INT: IntType = IntType {
        width: Width::W32,
        signed: true,
        rank: 3,
    };
    /// `unsigned int`.
    pub const UINT: IntType = IntType {
        width: Width::W32,
        signed: false,
        rank: 3,
    };
    /// `long` under LP64.
    pub const LONG: IntType = IntType {
        width: Width::W64,
        signed: true,
        rank: 4,
    };
    /// `unsigned long` under LP64.
    pub const ULONG: IntType = IntType {
        width: Width::W64,
        signed: false,
        rank: 4,
    };

    /// The integer promotion: anything of lower rank than `int` becomes `int`,
    /// because `int` can represent every value of every such type on LP64.
    pub fn promote(self) -> IntType {
        if self.rank < IntType::INT.rank {
            IntType::INT
        } else {
            self
        }
    }

    /// The usual arithmetic conversions' common type of two integer operands,
    /// after promotion (C17 6.3.1.8).
    pub fn common(self, other: IntType) -> IntType {
        let (a, b) = (self.promote(), other.promote());
        if a == b {
            return a;
        }
        if a.signed == b.signed {
            return if a.rank >= b.rank { a } else { b };
        }
        let (unsigned, signed) = if a.signed { (b, a) } else { (a, b) };
        if unsigned.rank >= signed.rank {
            unsigned
        } else if signed.width.bits() > unsigned.width.bits() {
            // The signed type represents every value of the unsigned one.
            signed
        } else {
            IntType {
                width: signed.width,
                signed: false,
                rank: signed.rank,
            }
        }
    }
}

/// A C type, to the depth the lowering distinguishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CType {
    /// `void` --- a function result only; a `void` object is not a type here.
    Void,
    /// An integer or character type.
    Int(IntType),
    /// A floating type. Carried so the census can name it; **not lowerable**
    /// --- see [`CType::unsupported_reason`].
    Float { bits: u16 },
    /// A pointer. Carried so the census can name it.
    Pointer,
    /// An array, struct, union or enum. Carried so the census can name it.
    Aggregate(&'static str),
}

impl CType {
    /// The integer type, when this is one.
    pub fn as_int(&self) -> Option<IntType> {
        match self {
            CType::Int(t) => Some(*t),
            _ => None,
        }
    }

    /// Why this type cannot be lowered, or `None` when it can.
    ///
    /// Naming the reason rather than returning a bare `false` is what lets the
    /// feasibility census say *which* capability is missing, which is the
    /// finding the roadmap asks for.
    pub fn unsupported_reason(&self) -> Option<&'static str> {
        match self {
            CType::Int(_) | CType::Void => None,
            // `Domain` is a bit-vector interface: no float add, no float
            // compare, no int/float conversion anywhere in `src/exec`.
            CType::Float { .. } => Some("floating-point type (no FP in the exec Domain)"),
            CType::Pointer => Some("pointer type"),
            CType::Aggregate(what) => Some(match *what {
                "array" => "array type",
                "struct" => "struct type",
                "union" => "union type",
                "enum" => "enum type",
                _ => "aggregate type",
            }),
        }
    }
}

/// One recognised specifier keyword, reduced to the axes that matter.
#[derive(Debug, Default, Clone, Copy)]
struct Spec {
    void: bool,
    bool_: bool,
    char_: bool,
    short_: bool,
    int_: bool,
    long_: u8,
    signed_: bool,
    unsigned_: bool,
    float_: u16,
    aggregate: Option<&'static str>,
    /// A `<stdint.h>`-style name resolved from [`TYPEDEF_TABLE`].
    typedef: Option<IntType>,
    /// Whether anything at all was recognised.
    any: bool,
}

/// The fixed-width and pointer-sized typedefs of the LP64 C library, resolved
/// by name.
///
/// These are not a guess about the corpus: they are the definitions
/// `x86_64-linux-gnu`'s headers give, and the fixture binaries were built with
/// those headers. A source file that defines its own `typedef` of one of these
/// names would be mis-typed here, which is why [`from_specifier_tokens`] is only
/// ever consulted for a name that appears where a type must.
const TYPEDEF_TABLE: &[(&str, IntType)] = &[
    ("int8_t", int(8, true, 1)),
    ("uint8_t", int(8, false, 1)),
    ("int16_t", int(16, true, 2)),
    ("uint16_t", int(16, false, 2)),
    ("int32_t", int(32, true, 3)),
    ("uint32_t", int(32, false, 3)),
    ("int64_t", int(64, true, 4)),
    ("uint64_t", int(64, false, 4)),
    ("intptr_t", int(64, true, 4)),
    ("uintptr_t", int(64, false, 4)),
    ("ptrdiff_t", int(64, true, 4)),
    ("size_t", int(64, false, 4)),
    ("ssize_t", int(64, true, 4)),
    ("intmax_t", int(64, true, 5)),
    ("uintmax_t", int(64, false, 5)),
    ("int_fast8_t", int(8, true, 1)),
    ("uint_fast8_t", int(8, false, 1)),
    ("int_least8_t", int(8, true, 1)),
    ("uint_least8_t", int(8, false, 1)),
    ("bool", IntType::BOOL),
    ("_Bool", IntType::BOOL),
];

const fn int(bits: u16, signed: bool, rank: u8) -> IntType {
    IntType {
        width: Width(bits),
        signed,
        rank,
    }
}

/// Resolve a declaration's specifier keywords, given as source lexemes in
/// order, to a [`CType`].
///
/// Storage-class and qualifier keywords are ignored on purpose: `static`,
/// `const`, `register` and `inline` change neither width nor signedness, which
/// are the only two questions this model answers. An unrecognised specifier
/// yields `None` rather than a default, so a caller refuses instead of
/// inventing an `int`.
pub fn from_specifier_tokens<'a>(words: impl IntoIterator<Item = &'a str>) -> Option<CType> {
    let mut spec = Spec::default();
    for word in words {
        match word {
            "void" => set(&mut spec, |s| s.void = true),
            "_Bool" | "bool" => set(&mut spec, |s| s.bool_ = true),
            "char" => set(&mut spec, |s| s.char_ = true),
            "short" => set(&mut spec, |s| s.short_ = true),
            "int" => set(&mut spec, |s| s.int_ = true),
            "long" => set(&mut spec, |s| s.long_ = s.long_.saturating_add(1)),
            "signed" | "__signed__" => set(&mut spec, |s| s.signed_ = true),
            "unsigned" => set(&mut spec, |s| s.unsigned_ = true),
            "float" => set(&mut spec, |s| s.float_ = 32),
            "double" => set(&mut spec, |s| s.float_ = if s.long_ > 0 { 128 } else { 64 }),
            "_Complex" | "_Imaginary" => set(&mut spec, |s| s.float_ = 128),
            "__int128" => set(&mut spec, |s| s.aggregate = Some("__int128")),
            "struct" => set(&mut spec, |s| s.aggregate = Some("struct")),
            "union" => set(&mut spec, |s| s.aggregate = Some("union")),
            "enum" => set(&mut spec, |s| s.aggregate = Some("enum")),
            "const" | "volatile" | "restrict" | "__restrict" | "__restrict__" | "static"
            | "extern" | "register" | "auto" | "inline" | "__inline" | "__inline__"
            | "_Noreturn" | "_Thread_local" | "_Atomic" | "typedef" | "__extension__" => {}
            other => {
                // `struct point` --- the tag name follows the keyword and names
                // no type of its own, so it is consumed rather than refused.
                // Without this the aggregate case reported the whole specifier
                // run as an unknown type instead of saying "struct".
                if spec.aggregate.is_some() {
                    continue;
                }
                if let Some((_, t)) = TYPEDEF_TABLE.iter().find(|(n, _)| *n == other) {
                    // A second type word after a resolved typedef means the
                    // first was not a type at all; refuse rather than guess.
                    if spec.typedef.is_some() {
                        return None;
                    }
                    set(&mut spec, |s| s.typedef = Some(*t));
                } else {
                    return None;
                }
            }
        }
    }
    finish(spec)
}

fn set(spec: &mut Spec, f: impl FnOnce(&mut Spec)) {
    f(spec);
    spec.any = true;
}

fn finish(spec: Spec) -> Option<CType> {
    if !spec.any {
        return None;
    }
    if let Some(what) = spec.aggregate {
        return Some(CType::Aggregate(what));
    }
    if spec.float_ != 0 {
        return Some(CType::Float { bits: spec.float_ });
    }
    if let Some(t) = spec.typedef {
        // `unsigned size_t` is not C; a typedef never combines with a
        // width/sign keyword, so any combination is a refusal.
        if spec.int_ || spec.char_ || spec.short_ || spec.long_ > 0 || spec.unsigned_ {
            return None;
        }
        return Some(CType::Int(t));
    }
    if spec.void {
        return Some(CType::Void);
    }
    if spec.bool_ {
        return Some(CType::Int(IntType::BOOL));
    }
    let unsigned = spec.unsigned_;
    if spec.char_ {
        // Plain `char` is signed on x86-64 Linux; `signed char` and
        // `unsigned char` are distinct types of the same rank.
        return Some(CType::Int(int(8, !unsigned, 1)));
    }
    if spec.short_ {
        return Some(CType::Int(int(16, !unsigned, 2)));
    }
    match spec.long_ {
        0 => {
            if spec.int_ || spec.signed_ || spec.unsigned_ {
                Some(CType::Int(int(32, !unsigned, 3)))
            } else {
                None
            }
        }
        1 => Some(CType::Int(int(64, !unsigned, 4))),
        _ => Some(CType::Int(int(64, !unsigned, 5))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ty(words: &[&str]) -> Option<CType> {
        from_specifier_tokens(words.iter().copied())
    }

    #[test]
    fn the_plain_integer_spellings_resolve_to_lp64_widths() {
        assert_eq!(ty(&["int"]), Some(CType::Int(IntType::INT)));
        assert_eq!(ty(&["unsigned", "int"]), Some(CType::Int(IntType::UINT)));
        assert_eq!(ty(&["unsigned"]), Some(CType::Int(IntType::UINT)));
        assert_eq!(ty(&["long"]), Some(CType::Int(IntType::LONG)));
        assert_eq!(ty(&["unsigned", "long"]), Some(CType::Int(IntType::ULONG)));
        assert_eq!(ty(&["long", "long"]), Some(CType::Int(int(64, true, 5))));
        assert_eq!(ty(&["short"]), Some(CType::Int(int(16, true, 2))));
        assert_eq!(ty(&["char"]), Some(CType::Int(int(8, true, 1))));
        assert_eq!(
            ty(&["unsigned", "char"]),
            Some(CType::Int(int(8, false, 1)))
        );
        assert_eq!(ty(&["void"]), Some(CType::Void));
    }

    #[test]
    fn qualifiers_and_storage_classes_do_not_change_the_type() {
        assert_eq!(
            ty(&["static", "const", "int"]),
            Some(CType::Int(IntType::INT))
        );
        assert_eq!(ty(&["const"]), None, "a qualifier alone names no type");
    }

    #[test]
    fn stdint_typedefs_resolve_and_do_not_combine() {
        assert_eq!(ty(&["uint32_t"]), Some(CType::Int(int(32, false, 3))));
        assert_eq!(ty(&["size_t"]), Some(CType::Int(int(64, false, 4))));
        assert_eq!(ty(&["unsigned", "size_t"]), None);
        assert_eq!(ty(&["my_handle_t"]), None, "an unknown name is a refusal");
    }

    #[test]
    fn float_and_aggregate_types_are_named_not_lowered() {
        assert!(matches!(ty(&["double"]), Some(CType::Float { bits: 64 })));
        assert!(matches!(ty(&["float"]), Some(CType::Float { bits: 32 })));
        assert_eq!(ty(&["struct", "point"]), Some(CType::Aggregate("struct")));
        assert!(ty(&["double"])
            .unwrap()
            .unsupported_reason()
            .is_some_and(|r| r.contains("floating")));
    }

    #[test]
    fn the_usual_arithmetic_conversions_follow_c17_6_3_1_8() {
        let uchar = int(8, false, 1);
        let sshort = int(16, true, 2);
        // Everything below `int` promotes to `int`.
        assert_eq!(uchar.common(sshort), IntType::INT);
        assert_eq!(uchar.promote(), IntType::INT);
        // Same rank, different signedness: unsigned wins.
        assert_eq!(IntType::INT.common(IntType::UINT), IntType::UINT);
        // A wider signed type represents every value of a narrower unsigned one.
        assert_eq!(IntType::UINT.common(IntType::LONG), IntType::LONG);
        // Equal width, unsigned of higher-or-equal rank wins.
        assert_eq!(IntType::LONG.common(IntType::ULONG), IntType::ULONG);
    }
}
