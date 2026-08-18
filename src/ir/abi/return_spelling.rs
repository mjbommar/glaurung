//! How a synthesised aggregate return type is SPELLED in C, and read back.
//!
//! [`super`] answers which registers a result lives in. This module answers a
//! different question: what to call the type when the class has no source-level
//! name, and how to recover the class from that name later.
//!
//! Each class contributes the same trio -- a `tag` (the struct name a
//! declaration uses), a `definition` (the full `struct { ... };` the recompiled
//! C needs), and a parse-back that turns the tag into the class parameters. The
//! parse-back exists because the renderer sees only a type STRING by the time it
//! has to decide how many registers the result occupies.
//!
//! Split out on 2026-08-18 when the AAPCS64 `x8` and HFA classes took `abi.rs`
//! past 1,000 LOC. The register facts and the spellings had grown into one file
//! because every new class needs both; they are two reasons to change.

/// The synthesised C tag for a result the callee writes into the caller's
/// buffer through [`indirect_result_register`].
///
/// A declaration is the ONLY way to make a C compiler emit the `x8` setup: the
/// register is not an argument slot, so no argument list can name it, and
/// nothing else in the recovered body can put an address there. Declaring the
/// callee as returning an object of the right SIZE reproduces the contract
/// exactly, and the object's fields never have to be recovered — AAPCS64 copies
/// it as raw storage.
///
/// Only sizes past the 16-byte register cutoff are tagged. At or below it the
/// result is in registers and this spelling would be actively wrong.
pub fn indirect_return_tag(bytes: u16) -> Option<String> {
    (bytes > 16).then(|| format!("struct __glaurung_indirect_{bytes}"))
}

/// The self-contained definition that puts [`indirect_return_tag`] in scope.
pub fn indirect_return_definition(bytes: u16) -> Option<String> {
    let tag = indirect_return_tag(bytes)?;
    Some(format!("{tag} {{ unsigned char __bytes[{bytes}]; }};"))
}

/// The buffer size a spelling produced by [`indirect_return_tag`] denotes.
pub fn indirect_return_bytes(return_type: &str) -> Option<u16> {
    let bytes = return_type
        .strip_prefix("struct __glaurung_indirect_")?
        .parse::<u16>()
        .ok()?;
    (bytes > 16).then_some(bytes)
}

/// The synthesised C tag for an AAPCS64 homogeneous float aggregate result.
///
/// `double` has no more of a builtin spelling for "two members in `d0:d1`" than
/// `rax + xmm0` had for the split banks: naming the member type alone declares
/// `d0` and discards every other member. The tag's members are chosen for their
/// ABI classes — a struct of N identical floating-point members IS an HFA of N
/// members by construction — so no source field recovery is required.
pub fn hfa_return_tag(member_bytes: u8, members: u8) -> Option<&'static str> {
    Some(match (member_bytes, members) {
        (4, 2) => "struct __glaurung_hfa_2f",
        (4, 3) => "struct __glaurung_hfa_3f",
        (4, 4) => "struct __glaurung_hfa_4f",
        (8, 2) => "struct __glaurung_hfa_2d",
        (8, 3) => "struct __glaurung_hfa_3d",
        (8, 4) => "struct __glaurung_hfa_4d",
        _ => return None,
    })
}

/// The self-contained definition that puts [`hfa_return_tag`] in scope.
pub fn hfa_return_definition(member_bytes: u8, members: u8) -> Option<&'static str> {
    Some(match (member_bytes, members) {
        (4, 2) => "struct __glaurung_hfa_2f { float __m0; float __m1; };",
        (4, 3) => "struct __glaurung_hfa_3f { float __m0; float __m1; float __m2; };",
        (4, 4) => "struct __glaurung_hfa_4f { float __m0; float __m1; float __m2; float __m3; };",
        (8, 2) => "struct __glaurung_hfa_2d { double __m0; double __m1; };",
        (8, 3) => "struct __glaurung_hfa_3d { double __m0; double __m1; double __m2; };",
        (8, 4) => {
            "struct __glaurung_hfa_4d { double __m0; double __m1; double __m2; double __m3; };"
        }
        _ => return None,
    })
}

/// The member width and count a spelling produced by [`hfa_return_tag`] denotes.
pub fn hfa_return_members(return_type: &str) -> Option<(u8, u8)> {
    [4u8, 8]
        .into_iter()
        .flat_map(|member_bytes| (2u8..=4).map(move |members| (member_bytes, members)))
        .find(|(member_bytes, members)| {
            hfa_return_tag(*member_bytes, *members) == Some(return_type)
        })
}

/// The synthesised C tag for a System V AMD64 result split across the integer
/// and SSE result banks.
///
/// [`ReturnClass::IntegerPair`] had a builtin spelling: the double-word integer
/// is INTEGER, INTEGER by construction, so `unsigned __int128` IS that ABI
/// contract and needs no aggregate reconstruction. `rax + xmm0` has no builtin
/// equivalent, and a declaration naming either bank alone silently discards the
/// other eightbyte's bytes — which is exactly the defect this spelling exists to
/// close.
///
/// The members are chosen for their EIGHTBYTE CLASSES, not for the source
/// fields: `unsigned long` classifies INTEGER and `double` classifies SSE, and
/// those two facts are the entire contract. One tag per bank ORDER therefore
/// serves every aggregate of that shape, and no field recovery is required.
pub fn split_bank_return_tag(integer_first: bool) -> &'static str {
    if integer_first {
        "struct __glaurung_split_is"
    } else {
        "struct __glaurung_split_si"
    }
}

/// The self-contained definition that puts [`split_bank_return_tag`] in scope.
///
/// Emitted at block scope above the callee declaration that names it, for the
/// same reason `SymbolRecord::required_structs` is: a sliced one-function
/// fragment has to declare everything it names, and nothing above the signature
/// line survives that slice.
pub fn split_bank_return_definition(integer_first: bool) -> &'static str {
    if integer_first {
        "struct __glaurung_split_is { unsigned long __integer; double __sse; };"
    } else {
        "struct __glaurung_split_si { double __sse; unsigned long __integer; };"
    }
}

/// The bank order a return-type spelling denotes, or `None` for every other
/// type. `Some(true)` is `integer_first`, matching [`ReturnClass::SplitBanks`].
pub fn split_bank_return_order(return_type: &str) -> Option<bool> {
    [true, false]
        .into_iter()
        .find(|integer_first| split_bank_return_tag(*integer_first) == return_type)
}

/// The synthesised C tag for a System V AMD64 result in the SSE result PAIR.
///
/// Same argument as [`split_bank_return_tag`], one class over: no builtin C
/// type returns in `xmm0:xmm1`, and a declaration naming `double` alone claims
/// `xmm0` and silently discards everything the callee left in `xmm1`.
///
/// There are two tags because there are two OCCUPANCIES, not because there are
/// two field layouts. Both tags are sixteen bytes and both return in
/// `xmm0:xmm1` — the register contract is identical. What differs is how much
/// of `xmm1` the callee defined, and therefore how much of it a caller may read
/// back: `{double; double;}` moves eight bytes out of the high register and
/// `{double; float;}` moves four. Using the full spelling for a twelve-byte
/// result would read four bytes that were never stored.
///
/// `None` for any other occupancy: see [`ReturnClass::SsePair`].
pub fn sse_pair_return_tag(high_bytes: u8) -> Option<&'static str> {
    match high_bytes {
        8 => Some("struct __glaurung_sse_pair"),
        4 => Some("struct __glaurung_sse_pair_half"),
        _ => None,
    }
}

/// The self-contained definition that puts [`sse_pair_return_tag`] in scope,
/// emitted at block scope for the same reason [`split_bank_return_definition`]
/// is.
pub fn sse_pair_return_definition(high_bytes: u8) -> Option<&'static str> {
    match high_bytes {
        8 => Some("struct __glaurung_sse_pair { double __sse0; double __sse1; };"),
        4 => Some("struct __glaurung_sse_pair_half { double __sse0; float __sse1; };"),
        _ => None,
    }
}

/// The second-eightbyte occupancy a return-type spelling denotes, or `None` for
/// every other type. Matches [`ReturnClass::SsePair`]'s `high_bytes`.
pub fn sse_pair_return_high_bytes(return_type: &str) -> Option<u8> {
    [8, 4]
        .into_iter()
        .find(|high_bytes| sse_pair_return_tag(*high_bytes) == Some(return_type))
}

/// Every self-contained definition a synthesised aggregate return spelling
/// needs in scope, or `None` when the type is not one of them.
///
/// One entry point so a renderer emitting these declarations does not have to
/// enumerate the classes that have them; adding a class here is what puts its
/// tag in scope everywhere it is already declared.
/// `String` rather than `&'static str` because the indirect class's definition
/// carries a SIZE. That size is a property of the callee's declared type and
/// cannot come from a fixed table without capping how large a result this model
/// admits — a cap that would silently drop back to today's behaviour for the
/// one shape past it rather than reporting anything.
pub fn synthesised_return_definition(return_type: &str) -> Option<String> {
    if let Some(integer_first) = split_bank_return_order(return_type) {
        return Some(split_bank_return_definition(integer_first).to_string());
    }
    if let Some(definition) =
        sse_pair_return_high_bytes(return_type).and_then(sse_pair_return_definition)
    {
        return Some(definition.to_string());
    }
    if let Some((member_bytes, members)) = hfa_return_members(return_type) {
        return hfa_return_definition(member_bytes, members).map(str::to_string);
    }
    indirect_return_bytes(return_type).and_then(indirect_return_definition)
}
