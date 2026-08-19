//! Which registers a declared by-value aggregate result actually occupies.
//!
//! [`crate::ir::abi::return_registers`] answers a different question than it
//! looks like it answers. `["rax", "eax", "ax", "al", "xmm0"]` is a list of
//! SPELLINGS of one logical result — four names for the same bits, plus the SSE
//! bank's name for the same role. Nothing in it can say `rax:rdx`, because that
//! is not another spelling: it is two registers holding different bytes of one
//! value. Adding `rdx` to the list would assert that `rdx` is another name for
//! `rax`, which is false everywhere else in the pipeline.
//!
//! System V AMD64 has four distinct result contracts, and picking the wrong one
//! produces C that compiles and returns the wrong bytes:
//!
//! | source result | storage | [`ReturnClass`] |
//! |---|---|---|
//! | `<= 8` bytes, all integer | `rax` | `Single` |
//! | `<= 16` bytes, all integer | `rax:rdx` | `IntegerPair` |
//! | `<= 16` bytes, integer + double | `rax` + `xmm0` | `SplitBanks` |
//! | `<= 16` bytes, all floating point | `xmm0:xmm1` | `SsePair` |
//! | `> 16` bytes | caller's buffer via a hidden pointer | `Memory` |
//!
//! This module derives that class from a DECLARED type. Machine evidence alone
//! cannot: at `-O2` an unused `idiv` remainder leaves a dedicated definition of
//! `rdx` reaching the `RET` of an ordinary `int` function, which is
//! indistinguishable from the high eightbyte of a pair by liveness. A wrong
//! class there would retype the callee for every caller, so the aggregate shape
//! is taken from DWARF or not taken at all.

use crate::debug::dwarf::DwarfTypeKind;
use crate::ir::abi::{sysv_amd64_return_class, Eightbyte, ReturnClass};
use crate::ir::call_args::CallConv;
use crate::ir::dwarf_type_env::DwarfTypeEnv;

/// The largest aggregate whose eightbytes are worth enumerating. Past the ABI's
/// own 16-byte cutoff the object is MEMORY however its fields are typed.
const MAX_REGISTER_RETURN_BYTES: u64 = 16;

/// How `c_type` is returned, when that can be proven from the recorded layout.
///
/// `None` means "not classifiable", which is the answer for every scalar (they
/// already have a working single-register contract), for every convention whose
/// aggregate rules are not modelled here, and for any aggregate whose fields
/// this reader cannot place. Fail closed: keeping today's behaviour is always
/// available, and a wrong class never is.
pub(crate) fn declared_return_class(
    c_type: &str,
    cc: CallConv,
    type_env: Option<&DwarfTypeEnv<'_>>,
) -> Option<ReturnClass> {
    // The eightbyte algorithm, the 16-byte cutoff, and the `rax:rdx`/`xmm0`
    // banks are all System V AMD64 facts. AAPCS64 has its own, simpler rule and
    // gets its own reader below. Win64 returns every aggregate wider than one
    // register through a hidden pointer; it is not modelled, and there is no
    // Windows lane in `tests/decompiler_fixtures/` to measure it against.
    match cc {
        CallConv::SysVAmd64 => {}
        CallConv::Aarch64 => return aapcs64_return_class(c_type, type_env?),
        CallConv::Win64 | CallConv::Cdecl32 | CallConv::Arm | CallConv::ArmHardFloat => {
            return None
        }
    }
    let type_env = type_env?;
    let layout = type_env.aggregate_layout(c_type)?;
    // A union's eightbyte class is the join over every member's overlapping
    // class, and a member this reader cannot place would silently drop out of
    // that join. Refuse the whole shape instead.
    if layout.kind != DwarfTypeKind::Struct {
        return None;
    }
    let size = layout.byte_size;
    if size > MAX_REGISTER_RETURN_BYTES {
        return sysv_amd64_return_class(size, &[]);
    }
    let mut eightbytes = vec![None::<Eightbyte>; usize::try_from(size.div_ceil(8)).ok()?];
    classify_fields(c_type, 0, type_env, &mut eightbytes, 0)?;
    let eightbytes = eightbytes.into_iter().collect::<Option<Vec<_>>>()?;
    sysv_amd64_return_class(size, &eightbytes)
}

/// How AAPCS64 returns a declared composite result.
///
/// THE RULE, from the Arm Procedure Call Standard (IHI 0055, "Result return"):
/// if `void f(T)` would pass a `T` in registers, a `T` result comes back in
/// those same registers. Applied through the parameter-passing rules that
/// means, for a Composite Type, in this order:
///
/// * an HFA or HVA (1-4 members, all the SAME floating-point or vector type)
///   -> `v0`..`v3`, one member per register, WHATEVER its size — four
///   `double`s is thirty-two bytes and still a register result;
/// * otherwise larger than 16 bytes -> indirectly, through a caller-allocated
///   block whose address arrives in `x8`;
/// * otherwise -> `x0` and `x1`, the object copied as if stored to memory and
///   reloaded, so a size that is not a multiple of eight leaves the tail of the
///   last register UNSPECIFIED.
///
/// The ORDER is load-bearing and is why the size test cannot come first: the
/// indirect rule's own statement excludes HFAs, and `{double x4}` sits on the
/// wrong side of the 16-byte cutoff.
///
/// The last clause is why the pair class is not gated on the object filling
/// both registers: a twelve-byte `{int32_t a,b,c;}` is `x0:x1` with four bytes
/// of `x1` defined, exactly as a sixteen-byte one is with eight.
///
/// AAPCS64 has no equivalent of System V's SPLIT-BANK class. HOMOGENEITY, not
/// per-eightbyte field class, is what routes a composite to the vector bank, so
/// `{int32_t; double;}` is not homogeneous and returns wholly in `x0:x1` where
/// System V would split it across `rax` and `xmm0` — and so does
/// `{double; float; float;}`, whose two eightbytes are BOTH all-float. That
/// last shape is why the eightbyte classification cannot stand in for the
/// homogeneity test: it was used as a proxy while there was no vector-bank
/// return class, and it refused a shape that really is `x0:x1`. Measured on
/// 2026-08-18 with `aarch64-linux-gnu-gcc -O1`: `struct {double d; float a;
/// float b;}` returns through `fmov x0, d30` and `x1`, not through `v0`.
fn aapcs64_return_class(c_type: &str, type_env: &DwarfTypeEnv<'_>) -> Option<ReturnClass> {
    let layout = type_env.aggregate_layout(c_type)?;
    // A union's members overlap, so neither the homogeneity walk nor the
    // eightbyte join below can see a member it cannot place drop out of the
    // answer; refuse the whole shape, exactly as the System V reader does.
    if layout.kind != DwarfTypeKind::Struct {
        return None;
    }
    // Homogeneity first, and before any size test: an HFA is a register result
    // at every size the ABI admits.
    if let Some((member_bytes, members)) = homogeneous_float_members(c_type, type_env) {
        // ONE member is a scalar `float`/`double` result in `s0`/`d0`, which
        // the existing single-register contract already spells correctly.
        return (members >= 2).then_some(ReturnClass::HomogeneousFloat {
            member_bytes,
            members,
        });
    }
    let size = layout.byte_size;
    if size > MAX_REGISTER_RETURN_BYTES {
        return Some(ReturnClass::IndirectBuffer {
            bytes: u16::try_from(size).ok()?,
        });
    }
    // At or below one register the existing single-register contract is right.
    if size <= 8 {
        return None;
    }
    let mut eightbytes = vec![None::<Eightbyte>; usize::try_from(size.div_ceil(8)).ok()?];
    classify_fields(c_type, 0, type_env, &mut eightbytes, 0)?;
    let eightbytes = eightbytes.into_iter().collect::<Option<Vec<_>>>()?;
    match sysv_amd64_return_class(size, &eightbytes)? {
        // Every 9..=16 byte composite that is not an HFA is `x0:x1`, whatever
        // System V would have made of its eightbytes. The eightbyte walk is
        // reused only as a PROOF THAT EVERY FIELD WAS PLACED: a shape this
        // reader cannot lay out is one it must not claim a class for.
        ReturnClass::IntegerPair | ReturnClass::SplitBanks { .. } | ReturnClass::SsePair { .. } => {
            Some(ReturnClass::IntegerPair)
        }
        // Unreachable for a 9..=16 byte object; enumerated rather than
        // wildcarded so that a new class has to be decided for here too.
        ReturnClass::Single
        | ReturnClass::Memory
        | ReturnClass::HomogeneousFloat { .. }
        | ReturnClass::IndirectBuffer { .. } => None,
    }
}

/// The member width and count of a HOMOGENEOUS FLOATING-POINT AGGREGATE, or
/// `None` for every other declared type.
///
/// AAPCS64's definition (IHI 0055, "Homogeneous Aggregates") is a Composite
/// Type with 1 to 4 members, all of the same Fundamental Data Type, where that
/// type is floating point. This reads exactly that and nothing broader:
///
/// * every member's representation spelling must be the SAME `float` or
///   `double`, recorded at the size that spelling implies;
/// * the members must tile the object from offset zero with no gap and no
///   padding, which is what makes "N members" a fact about the STORAGE rather
///   than about the field list;
/// * 1 to 4 members, because a fifth has no register.
///
/// Deliberately narrower than the ABI: a nested struct of floats, and an array
/// member, are both HFAs to AAPCS64 and are refused here. Refusing costs the
/// shape the vector-bank class and leaves it on its existing path; claiming one
/// wrongly reads a member out of a register the callee never wrote.
fn homogeneous_float_members(c_type: &str, type_env: &DwarfTypeEnv<'_>) -> Option<(u8, u8)> {
    let layout = type_env.aggregate_layout(c_type)?;
    if layout.kind != DwarfTypeKind::Struct || layout.fields.is_empty() {
        return None;
    }
    let members = u8::try_from(layout.fields.len()).ok()?;
    if members > 4 {
        return None;
    }
    let spelling = type_env.representation_spelling(&layout.fields.first()?.c_type);
    let member_bytes = match spelling.as_str() {
        "float" => 4u8,
        "double" => 8,
        // `long double` is class X87 on System V and a 16-byte quad here; this
        // model has no register for either, and a guess would be a wrong one.
        _ => return None,
    };
    for (index, field) in layout.fields.iter().enumerate() {
        if type_env.representation_spelling(&field.c_type) != spelling
            || field.size != u64::from(member_bytes)
            || field.offset != u64::try_from(index).ok()? * u64::from(member_bytes)
        {
            return None;
        }
    }
    (layout.byte_size == u64::from(members) * u64::from(member_bytes))
        .then_some((member_bytes, members))
}

/// How much of the SECOND eightbyte a declared type occupies when it is passed
/// BY VALUE in the SSE argument PAIR, or `None` for every other shape.
///
/// System V classifies a by-value ARGUMENT with the same eightbyte algorithm it
/// classifies a result with; only the register assignment differs, and for the
/// all-SSE two-eightbyte class the two assignments coincide in shape — the
/// result takes `xmm0:xmm1` while an argument takes the next two registers of
/// the SSE argument bank. So the classification is reused rather than
/// duplicated, and `high_bytes` means here exactly what it means there: how many
/// bytes of the second register the object actually occupies, which is a fact
/// about the OBJECT and not about the register.
///
/// ONLY the all-SSE pair is answered here, deliberately. `Memory` does not
/// transfer at all — it means "hidden pointer, and every declared argument
/// shifts one slot right" for a result and "on the stack" for an argument — and
/// the ONE-eightbyte INTEGER class already has a working positional model in
/// `types_recover::locked_sysv_amd64_parameter_storage`. The two-eightbyte
/// INTEGER class is [`declared_integer_pair_parameter_high_bytes`] below.
/// Everything not proven to be this one class answers `None` and keeps the
/// behaviour it had.
pub(crate) fn declared_sse_pair_parameter_high_bytes(
    c_type: &str,
    cc: CallConv,
    type_env: Option<&DwarfTypeEnv<'_>>,
) -> Option<u8> {
    match declared_return_class(c_type, cc, type_env)? {
        ReturnClass::SsePair { high_bytes } => Some(high_bytes),
        ReturnClass::Single
        | ReturnClass::IntegerPair
        | ReturnClass::SplitBanks { .. }
        | ReturnClass::Memory
        | ReturnClass::HomogeneousFloat { .. }
        | ReturnClass::IndirectBuffer { .. } => None,
    }
}

/// How much of the SECOND eightbyte a declared type occupies when it is passed
/// BY VALUE in the INTEGER argument PAIR, or `None` for every other shape.
///
/// The sibling of [`declared_sse_pair_parameter_high_bytes`] one bank over, and
/// it exists because the claim that this class "already has a working
/// positional model" was wrong. `locked_sysv_amd64_parameter_storage` places a
/// parameter from its TYPE HINT, and a sixteen-byte aggregate has no scalar
/// hint at all: the projection sees `None`, declines wholesale, and the
/// declaration collapses to ONE parameter. Measured on 2026-08-18 —
/// `uint32_t mv203_consume_narrow(struct mv203_narrow v)` (16 bytes, four
/// `uint32_t`) recovered as `f(long)` with its second eightbyte read from a
/// variable nothing defines, and every caller passed half the object.
///
/// `high_bytes` means what it means for the SSE pair: how many bytes of the
/// second register the OBJECT occupies. A twelve-byte `{int32_t a,b,c;}` leaves
/// four bytes of the high register undefined, and declaring the high half eight
/// bytes wide would make a caller read four bytes past the object.
///
/// AAPCS64 reaches this the same way and means the same thing: a composite that
/// is not an HFA and not larger than sixteen bytes is `x0:x1`, "copied as if
/// stored to memory and reloaded", so a size that is not a multiple of eight
/// leaves the tail of the second register unspecified. `declared_return_class`
/// already applies that rule; this reads its answer rather than restating it.
pub(crate) fn declared_integer_pair_parameter_high_bytes(
    c_type: &str,
    cc: CallConv,
    type_env: Option<&DwarfTypeEnv<'_>>,
) -> Option<u8> {
    match declared_return_class(c_type, cc, type_env)? {
        ReturnClass::IntegerPair => {}
        ReturnClass::Single
        | ReturnClass::SsePair { .. }
        | ReturnClass::SplitBanks { .. }
        | ReturnClass::Memory
        | ReturnClass::HomogeneousFloat { .. }
        | ReturnClass::IndirectBuffer { .. } => return None,
    }
    // The class proves 9..=16 bytes; the SIZE is what says how much of the
    // second register is live, and it is read from the layout rather than
    // assumed to be a whole register.
    //
    // Only the widths a C scalar can name are admitted. An eleven-byte object
    // leaves three bytes of the second register live, and there is no three-byte
    // parameter type: rounding up would make a caller read a byte it never
    // stored, and rounding down would drop one the callee reads. Fail closed —
    // the shape keeps the behaviour it has, exactly as `sse_pair_return_tag`
    // declines every occupancy but four and eight.
    let size = type_env?.aggregate_layout(c_type)?.byte_size;
    let high_bytes = u8::try_from(size.checked_sub(8)?).ok()?;
    matches!(high_bytes, 1 | 2 | 4 | 8).then_some(high_bytes)
}

/// Merge every field of `c_type` into the eightbyte classes it overlaps.
///
/// `base` is the aggregate's offset within the outermost object, so a nested
/// struct straddling the eightbyte boundary is classified where its bytes
/// actually land rather than where its own layout starts.
fn classify_fields(
    c_type: &str,
    base: u64,
    type_env: &DwarfTypeEnv<'_>,
    eightbytes: &mut [Option<Eightbyte>],
    depth: u8,
) -> Option<()> {
    // Nesting is bounded by the 16-byte cutoff in practice; the counter exists
    // so a malformed self-referential layout terminates rather than recursing.
    if depth > 4 {
        return None;
    }
    let layout = type_env.aggregate_layout(c_type)?;
    if layout.kind != DwarfTypeKind::Struct || layout.fields.is_empty() {
        return None;
    }
    for field in &layout.fields {
        let offset = base.checked_add(field.offset)?;
        if field.size == 0 {
            return None;
        }
        let spelling = type_env.representation_spelling(&field.c_type);
        let class = match scalar_eightbyte_class(&spelling, field.size) {
            Some(class) => class,
            // An ARRAY of a scalar, which is a shape the field record states
            // and this walk used to refuse. See
            // [`array_member_eightbyte_class`].
            None => match array_member_eightbyte_class(&spelling, type_env) {
                Some(class) => class,
                None => {
                    // Not a scalar this reader can place. A nested struct still
                    // can be, by recursion; anything else (union, bitfield,
                    // unresolved alias) fails the whole classification.
                    classify_fields(&field.c_type, offset, type_env, eightbytes, depth + 1)?;
                    continue;
                }
            },
        };
        let first = usize::try_from(offset / 8).ok()?;
        let last = usize::try_from(offset.checked_add(field.size)?.saturating_sub(1) / 8).ok()?;
        for slot in first..=last {
            let slot = eightbytes.get_mut(slot)?;
            // The ABI's class join: an eightbyte is SSE only when every field
            // touching it is floating point. One integer field anywhere in it
            // makes the whole eightbyte INTEGER.
            *slot = Some(match (*slot, class) {
                (None, class) => class,
                (Some(Eightbyte::Sse), Eightbyte::Sse) => Eightbyte::Sse,
                _ => Eightbyte::Integer,
            });
        }
    }
    Some(())
}

/// The C spelling of a declared BY-VALUE aggregate returned WHOLLY in the
/// integer result register, or `None` for every other shape.
///
/// A one-eightbyte aggregate result needed no rewrite — one register, one value
/// — so it was left to the ordinary path, and the ordinary path infers the
/// return type from the RETURNED EXPRESSION rather than from the class. That is
/// how `struct hfa197_tagged { float value; int32_t tag; }` came to be declared
/// `float`: its low four bytes hold a `float`, the reaching expression is
/// float-shaped, and the declaration that follows returns in `xmm0`. System V
/// says the opposite — SSE merged with INTEGER in one eightbyte yields INTEGER
/// — so the eight bytes the callee computed correctly were handed back in the
/// wrong bank. `agr198_make_bits` is declared `double` by the same route.
///
/// The spelling is UNSIGNED and sized from the object: the bytes are storage,
/// not a signed quantity, and a wider declaration would return bytes past the
/// object while a narrower one would drop bytes the caller reads. Sizes with no
/// exact C spelling round UP to the next one, which is safe in this direction
/// only: the ABI leaves the rest of the register unspecified, so a three-byte
/// object declared `unsigned int` hands back one byte nobody may read.
pub(crate) fn single_class_aggregate_return_c_type(
    c_type: &str,
    cc: CallConv,
    type_env: Option<&DwarfTypeEnv<'_>>,
) -> Option<&'static str> {
    match declared_return_class(c_type, cc, type_env)? {
        ReturnClass::Single => {}
        ReturnClass::IntegerPair
        | ReturnClass::SsePair { .. }
        | ReturnClass::SplitBanks { .. }
        | ReturnClass::Memory
        | ReturnClass::HomogeneousFloat { .. }
        | ReturnClass::IndirectBuffer { .. } => return None,
    }
    // `declared_return_class` answers only for AGGREGATES — it needs a recorded
    // layout — so reaching here proves the declared type is one, and no scalar
    // return can be redeclared by this path.
    match type_env?.aggregate_layout(c_type)?.byte_size {
        1 => Some("unsigned char"),
        2 => Some("unsigned short"),
        3 | 4 => Some("unsigned int"),
        5..=8 => Some("unsigned long"),
        _ => None,
    }
}

/// The eightbyte class every element of an ARRAY member contributes, when the
/// element spelling proves one.
///
/// System V classifies an array member by classifying each of its elements, and
/// every element of an array has the SAME class — so the class covers the
/// array's whole byte extent and the element COUNT never has to be recovered.
/// That matters here: `DwarfField` carries the array's total size and the
/// element spelling with an empty bound (`uint32_t[]`), never the bound itself.
///
/// Without this arm the whole classification declined, because an array member
/// is neither a scalar nor a nested struct to recurse into. Measured on
/// 2026-08-18: `struct mv203_narrow { uint32_t q[4]; }` — sixteen bytes, plainly
/// `rdi:rsi` — had no class at all, so a by-value parameter of that type
/// collapsed to a single `long` and its second eightbyte was read from a
/// variable nothing defined.
///
/// A nested aggregate element (`struct S v[2]`) is refused rather than
/// recursed into: the elements after the first sit at offsets this function
/// does not compute, and a class claimed for the wrong bytes is the failure
/// this module exists to avoid.
fn array_member_eightbyte_class(spelling: &str, type_env: &DwarfTypeEnv<'_>) -> Option<Eightbyte> {
    let element = type_env.representation_spelling(spelling.strip_suffix("[]")?);
    match element.as_str() {
        // `long double` is class X87 and is absent for the same reason it is
        // absent from `scalar_eightbyte_class`: this model has no register for
        // it. It is not a `builtin_scalar_type` either, so it declines twice.
        "float" | "double" => Some(Eightbyte::Sse),
        _ if element.ends_with('*') && !element[..element.len() - 1].contains('*') => {
            Some(Eightbyte::Integer)
        }
        _ if crate::ir::dwarf_type_env::builtin_scalar_type(&element) => Some(Eightbyte::Integer),
        _ => None,
    }
}

/// The eightbyte class of one scalar field, when its spelling proves one.
///
/// The size is checked against the spelling rather than trusted: a `double`
/// recorded with a size other than eight is not a shape this classifier has
/// modelled, and guessing would be exactly the failure this module exists to
/// avoid.
fn scalar_eightbyte_class(spelling: &str, size: u64) -> Option<Eightbyte> {
    match spelling {
        "float" if size == 4 => Some(Eightbyte::Sse),
        "double" if size == 8 => Some(Eightbyte::Sse),
        // `long double` is class X87 and returns on the x87 stack, which this
        // model has no register for. It is deliberately absent.
        "float" | "double" => None,
        _ if spelling.ends_with('*') && !spelling[..spelling.len() - 1].contains('*') => {
            (size == 8).then_some(Eightbyte::Integer)
        }
        _ if crate::ir::dwarf_type_env::builtin_scalar_type(spelling) => {
            (size <= 8).then_some(Eightbyte::Integer)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug::dwarf::{DwarfField, DwarfType};

    fn field(offset: u64, name: &str, c_type: &str, size: u64) -> DwarfField {
        DwarfField {
            offset,
            name: name.to_string(),
            c_type: c_type.to_string(),
            size,
        }
    }

    fn structure(name: &str, byte_size: u64, fields: Vec<DwarfField>) -> DwarfType {
        DwarfType {
            kind: DwarfTypeKind::Struct,
            name: name.to_string(),
            byte_size,
            fields,
            variants: Vec::new(),
            typedef_target: None,
            source_file: None,
        }
    }

    /// The exact shapes `195_by_value_aggregates` compiles, in one table.
    fn corpus() -> Vec<DwarfType> {
        vec![
            structure(
                "bv195_pair",
                8,
                vec![field(0, "a", "int32_t", 4), field(4, "b", "int32_t", 4)],
            ),
            structure(
                "bv195_quad",
                16,
                vec![
                    field(0, "a", "int32_t", 4),
                    field(4, "b", "int32_t", 4),
                    field(8, "c", "int32_t", 4),
                    field(12, "d", "int32_t", 4),
                ],
            ),
            structure(
                "bv195_mixed",
                16,
                vec![
                    field(0, "tag", "int32_t", 4),
                    field(8, "value", "double", 8),
                ],
            ),
            structure("bv195_big", 32, vec![field(0, "v", "int64_t[4]", 32)]),
            structure(
                "double_first",
                16,
                vec![
                    field(0, "value", "double", 8),
                    field(8, "tag", "int32_t", 4),
                ],
            ),
            structure(
                "two_doubles",
                16,
                vec![field(0, "x", "double", 8), field(8, "y", "double", 8)],
            ),
            // `197_homogeneous_float_aggregates`, exactly as it compiles.
            structure(
                "hfa197_quad4f",
                16,
                vec![
                    field(0, "a", "float", 4),
                    field(4, "b", "float", 4),
                    field(8, "c", "float", 4),
                    field(12, "d", "float", 4),
                ],
            ),
            structure(
                "hfa197_trio3f",
                12,
                vec![
                    field(0, "a", "float", 4),
                    field(4, "b", "float", 4),
                    field(8, "c", "float", 4),
                ],
            ),
            structure(
                "hfa197_tagged",
                8,
                vec![field(0, "value", "float", 4), field(4, "tag", "int32_t", 4)],
            ),
            structure(
                "two_floats",
                8,
                vec![field(0, "a", "float", 4), field(4, "b", "float", 4)],
            ),
            DwarfType {
                kind: DwarfTypeKind::Union,
                name: "bits".to_string(),
                byte_size: 8,
                fields: vec![field(0, "i", "int64_t", 8), field(0, "d", "double", 8)],
                variants: Vec::new(),
                typedef_target: None,
                source_file: None,
            },
        ]
    }

    #[test]
    fn each_sysv_boundary_gets_its_own_class() {
        let types = corpus();
        let env = DwarfTypeEnv::new(&types);
        let class = |name: &str| declared_return_class(name, CallConv::SysVAmd64, Some(&env));

        assert_eq!(class("struct bv195_pair"), Some(ReturnClass::Single));
        assert_eq!(class("struct bv195_quad"), Some(ReturnClass::IntegerPair));
        assert_eq!(
            class("struct bv195_mixed"),
            Some(ReturnClass::SplitBanks {
                integer_first: true
            })
        );
        assert_eq!(class("struct bv195_big"), Some(ReturnClass::Memory));
        assert_eq!(
            class("struct double_first"),
            Some(ReturnClass::SplitBanks {
                integer_first: false
            })
        );
    }

    /// The all-SSE class, and the occupancy of its second eightbyte.
    ///
    /// The three positives of `197_homogeneous_float_aggregates` differ only in
    /// member widths and the resulting SIZE, and the size is the entire reason
    /// `high_bytes` exists: `{float,float,float}` is twelve bytes, so the ABI
    /// stores four bytes into `xmm1` and leaves four undefined. Both sixteen-
    /// byte shapes must land on the full occupancy and the twelve-byte one on
    /// the half, or the recovery reads a fourth member that was never stored.
    #[test]
    fn an_all_float_aggregate_is_an_sse_pair_with_a_measured_occupancy() {
        let types = corpus();
        let env = DwarfTypeEnv::new(&types);
        let class = |name: &str| declared_return_class(name, CallConv::SysVAmd64, Some(&env));

        assert_eq!(
            class("struct two_doubles"),
            Some(ReturnClass::SsePair { high_bytes: 8 })
        );
        assert_eq!(
            class("struct hfa197_quad4f"),
            Some(ReturnClass::SsePair { high_bytes: 8 })
        );
        assert_eq!(
            class("struct hfa197_trio3f"),
            Some(ReturnClass::SsePair { high_bytes: 4 })
        );
        // `hfa197_tagged` is the NEGATIVE: it CONTAINS a float, but the
        // eightbyte it shares with an `int32_t` joins to INTEGER, so the whole
        // object comes back in `rax` and must never reach the SSE bank.
        assert_eq!(class("struct hfa197_tagged"), Some(ReturnClass::Single));
        // One all-SSE eightbyte is `xmm0` ALONE — a pair needs two of them, and
        // an eight-byte float aggregate must not acquire a second register.
        assert_eq!(class("struct two_floats"), Some(ReturnClass::Single));
    }

    /// The ARGUMENT side of the same class, and everything it must refuse.
    ///
    /// A by-value all-SSE aggregate is one source parameter in two SSE argument
    /// registers, so its declared spelling is its two EIGHTBYTES and the second
    /// one carries the occupancy. Every other class answers `None`: the integer
    /// classes already have a positional model, and `Memory` means two
    /// completely different things on the two sides.
    #[test]
    fn the_argument_side_reuses_only_the_all_sse_pair() {
        let types = corpus();
        let env = DwarfTypeEnv::new(&types);
        let high = |name: &str| {
            declared_sse_pair_parameter_high_bytes(name, CallConv::SysVAmd64, Some(&env))
        };

        assert_eq!(high("struct two_doubles"), Some(8));
        assert_eq!(high("struct hfa197_quad4f"), Some(8));
        // Twelve bytes: the high register holds FOUR defined bytes, so the
        // second eightbyte is declared `float` and moves four.
        assert_eq!(high("struct hfa197_trio3f"), Some(4));
        // The negative that makes the rest mean something: `hfa197_tagged`
        // contains a float, but its single eightbyte joins to INTEGER, so it
        // arrives in an integer register and must never reach the SSE bank.
        assert_eq!(high("struct hfa197_tagged"), None);
        // One all-SSE eightbyte is `xmm0` ALONE and must not acquire a partner.
        assert_eq!(high("struct two_floats"), None);
        // The other classes do not transfer.
        assert_eq!(high("struct bv195_quad"), None);
        assert_eq!(high("struct bv195_mixed"), None);
        assert_eq!(high("struct double_first"), None);
        assert_eq!(high("struct bv195_big"), None);
        assert_eq!(high("double"), None);
        assert_eq!(high("int"), None);
        // System V only, exactly as the return side is.
        for cc in [
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Aarch64,
            CallConv::Arm,
            CallConv::ArmHardFloat,
        ] {
            assert_eq!(
                declared_sse_pair_parameter_high_bytes("struct two_doubles", cc, Some(&env)),
                None,
                "{cc:?} acquired the System V SSE argument pair"
            );
        }
        assert_eq!(
            declared_sse_pair_parameter_high_bytes("struct two_doubles", CallConv::SysVAmd64, None),
            None
        );
    }

    #[test]
    fn unmodelled_shapes_refuse_to_classify_rather_than_guess() {
        let types = corpus();
        let env = DwarfTypeEnv::new(&types);
        let class = |name: &str| declared_return_class(name, CallConv::SysVAmd64, Some(&env));

        // A union's members overlap, so a member this reader cannot place would
        // vanish from the class join instead of blocking it.
        assert_eq!(class("union bits"), None);
        // A scalar already has a working single-register contract.
        assert_eq!(class("int"), None);
        assert_eq!(class("struct bv195_quad *"), None);
        // No layout, no class.
        assert_eq!(class("struct never_declared"), None);
        assert_eq!(
            declared_return_class("struct bv195_quad", CallConv::SysVAmd64, None),
            None
        );
    }

    #[test]
    fn other_conventions_do_not_inherit_the_sysv_eightbyte_rules() {
        let types = corpus();
        let env = DwarfTypeEnv::new(&types);
        for cc in [
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Arm,
            CallConv::ArmHardFloat,
        ] {
            assert_eq!(
                declared_return_class("struct bv195_quad", cc, Some(&env)),
                None,
                "{cc:?} acquired the System V aggregate contract"
            );
        }
        // AAPCS64 has a register-pair result of its own and answers with it,
        // but it must reach that answer by its OWN rule — see
        // `aapcs64_puts_every_non_homogeneous_composite_in_the_register_pair`,
        // where `bv195_mixed` is the case the two rules disagree about.
        assert_eq!(
            declared_return_class("struct bv195_quad", CallConv::Aarch64, Some(&env)),
            Some(ReturnClass::IntegerPair)
        );
    }

    /// AAPCS64's composite result rule, and every place it parts company with
    /// System V's.
    ///
    /// The register PAIR is the whole point: `x1` is also the second argument
    /// register, so a caller that does not model it reads its own argument back
    /// where the high half belongs.
    #[test]
    fn aapcs64_puts_every_non_homogeneous_composite_in_the_register_pair() {
        let mut types = corpus();
        // `198_aggregate_return_edges`, exactly as it compiles: twelve bytes of
        // `int32_t`, so `x1` is HALF occupied and the object still comes back
        // in the pair.
        types.push(structure(
            "agr198_trio",
            12,
            vec![
                field(0, "a", "int32_t", 4),
                field(4, "b", "int32_t", 4),
                field(8, "c", "int32_t", 4),
            ],
        ));
        let env = DwarfTypeEnv::new(&types);
        let class = |name: &str| declared_return_class(name, CallConv::Aarch64, Some(&env));

        assert_eq!(class("struct bv195_quad"), Some(ReturnClass::IntegerPair));
        // Twelve bytes is the same class as sixteen. AAPCS64 copies the object
        // as if stored to memory, so the tail of `x1` is unspecified rather
        // than the object being moved somewhere else — which is why the class
        // is not gated on the pair being full.
        assert_eq!(class("struct agr198_trio"), Some(ReturnClass::IntegerPair));
        // THE DISAGREEMENT WITH SYSTEM V. `{int32_t; double;}` classifies
        // INTEGER,SSE and splits across `rax` and `xmm0` under System V. Under
        // AAPCS64 what routes a composite to the vector bank is HOMOGENEITY,
        // and a struct of an int and a double is not homogeneous, so the whole
        // object is in `x0:x1`.
        assert_eq!(class("struct bv195_mixed"), Some(ReturnClass::IntegerPair));
        assert_eq!(class("struct double_first"), Some(ReturnClass::IntegerPair));

        // HFAs are a class of their own, in `v0`..`v3` — one MEMBER per
        // register, which is what parts company with System V's `xmm0:xmm1`.
        // Pinned separately in `an_aapcs64_hfa_gets_one_register_per_member`.
        assert_eq!(
            class("struct two_doubles"),
            Some(ReturnClass::HomogeneousFloat {
                member_bytes: 8,
                members: 2
            })
        );

        // Eight bytes or fewer of NON-homogeneous composite is ONE register and
        // already has a working contract.
        assert_eq!(class("struct bv195_pair"), None);
        assert_eq!(class("struct hfa197_tagged"), None);
        // Over sixteen bytes AAPCS64 returns indirectly through `x8`, which is
        // NOT this crate's `Memory` — that one means System V's hidden pointer
        // in the first ARGUMENT register, and answering it would shift every
        // declared argument one slot right.
        assert_eq!(
            class("struct bv195_big"),
            Some(ReturnClass::IndirectBuffer { bytes: 32 })
        );
        // And the shapes this reader cannot place stay unplaced.
        assert_eq!(class("union bits"), None);
        assert_eq!(class("int"), None);
        assert_eq!(class("struct never_declared"), None);
        assert_eq!(
            declared_return_class("struct bv195_quad", CallConv::Aarch64, None),
            None
        );
    }

    /// AAPCS64's HOMOGENEOUS FLOAT AGGREGATE, and everything that is not one.
    ///
    /// `197_homogeneous_float_aggregates` is the fixture, and `trio3f` is the
    /// case that proves the class cannot reuse [`ReturnClass::SsePair`]. System
    /// V packs `{float,float,float}` into `xmm0:xmm1` at two floats apiece, so
    /// its second register is a HALF-OCCUPIED eightbyte and the class carries an
    /// occupancy. AAPCS64 gives each member a whole register:
    /// `aarch64-linux-gnu-gcc` reads `s0`, `s1` and `s2` after the call at both
    /// `-O0` and `-O2` and never touches `s3`. Three registers, four bytes each,
    /// no occupancy anywhere.
    #[test]
    fn an_aapcs64_hfa_gets_one_register_per_member() {
        let mut types = corpus();
        types.push(structure(
            "hfa197_pair2d",
            16,
            vec![field(0, "x", "double", 8), field(8, "y", "double", 8)],
        ));
        // All-float WITHOUT being homogeneous: sixteen bytes whose two
        // eightbytes both classify SSE under System V, and which AAPCS64
        // returns in `x0:x1` because the member types differ. This is the shape
        // the eightbyte proxy over-refused, confirmed with the same compiler on
        // 2026-08-18: the result leaves through `fmov x0, d30`.
        types.push(structure(
            "double_then_floats",
            16,
            vec![
                field(0, "d", "double", 8),
                field(8, "a", "float", 4),
                field(12, "b", "float", 4),
            ],
        ));
        let env = DwarfTypeEnv::new(&types);
        let class = |name: &str| declared_return_class(name, CallConv::Aarch64, Some(&env));
        let hfa = |member_bytes, members| {
            Some(ReturnClass::HomogeneousFloat {
                member_bytes,
                members,
            })
        };

        assert_eq!(class("struct hfa197_pair2d"), hfa(8, 2));
        assert_eq!(class("struct hfa197_quad4f"), hfa(4, 4));
        // Three of four registers. `s3` is not written, and nothing about the
        // class says it is: the count IS the member count.
        assert_eq!(class("struct hfa197_trio3f"), hfa(4, 3));
        assert_eq!(class("struct two_doubles"), hfa(8, 2));
        // EIGHT bytes, and still two registers. This is where a "one register
        // fits, so it is Single" shortcut would have refused an HFA — measured
        // with `aarch64-linux-gnu-gcc -O1`: `struct {float a, b;}` returns in
        // `s0` AND `s1`, not packed into `x0`.
        assert_eq!(class("struct two_floats"), hfa(4, 2));

        // THE NEGATIVE CONTROL. `hfa197_tagged` CONTAINS a float and must never
        // reach the vector bank: its members are not the same type, so it is
        // not homogeneous and comes back in `x0`.
        assert_eq!(class("struct hfa197_tagged"), None);
        // All-float, not homogeneous: the integer pair, not `v0`..`v3`.
        assert_eq!(
            class("struct double_then_floats"),
            Some(ReturnClass::IntegerPair)
        );
        // A scalar `double` is `d0` ALONE and must not acquire a second
        // register just because its neighbours return pairs.
        assert_eq!(class("double"), None);
        assert_eq!(class("float"), None);
        // And the vector bank is AAPCS64's. No other convention inherits it.
        for cc in [
            CallConv::SysVAmd64,
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Arm,
            CallConv::ArmHardFloat,
        ] {
            assert_ne!(
                declared_return_class("struct hfa197_quad4f", cc, Some(&env)),
                hfa(4, 4),
                "{cc:?} acquired the AAPCS64 vector-bank result"
            );
        }
    }

    /// AAPCS64's INDIRECT result, and the reason it is not `Memory`.
    ///
    /// Over sixteen bytes and not an HFA, the caller allocates the object and
    /// passes its address in `x8`. `Memory` in this crate means System V's
    /// contract — hidden pointer in the FIRST ARGUMENT register, every declared
    /// argument shifted one slot right, buffer address handed back in the result
    /// register — and AAPCS64 does none of those three things.
    #[test]
    fn an_over_wide_aapcs64_composite_returns_through_x8_and_not_through_memory() {
        let mut types = corpus();
        // `198_aggregate_return_edges`, exactly as it compiles. Twenty bytes is
        // deliberately not a multiple of eight: AAPCS64 copies the object as if
        // stored to memory and reloaded, so the size travels with the class.
        types.push(structure(
            "agr198_five",
            20,
            vec![
                field(0, "a", "int32_t", 4),
                field(4, "b", "int32_t", 4),
                field(8, "c", "int32_t", 4),
                field(12, "d", "int32_t", 4),
                field(16, "e", "int32_t", 4),
            ],
        ));
        // Four doubles is THIRTY-TWO bytes and still an HFA, which is why the
        // size test cannot come first.
        types.push(structure(
            "quad_double",
            32,
            vec![
                field(0, "a", "double", 8),
                field(8, "b", "double", 8),
                field(16, "c", "double", 8),
                field(24, "d", "double", 8),
            ],
        ));
        let env = DwarfTypeEnv::new(&types);
        let class = |name: &str| declared_return_class(name, CallConv::Aarch64, Some(&env));

        assert_eq!(
            class("struct agr198_five"),
            Some(ReturnClass::IndirectBuffer { bytes: 20 })
        );
        assert_eq!(
            class("struct bv195_big"),
            Some(ReturnClass::IndirectBuffer { bytes: 32 })
        );
        // THE ORDER TEST: thirty-two bytes, past the cutoff, and still in
        // `d0`..`d3` because it is homogeneous.
        assert_eq!(
            class("struct quad_double"),
            Some(ReturnClass::HomogeneousFloat {
                member_bytes: 8,
                members: 4
            })
        );
        // Sixteen bytes is the last size that fits the pair, and must not
        // acquire a buffer.
        assert_eq!(class("struct bv195_quad"), Some(ReturnClass::IntegerPair));
        // System V's own MEMORY class is untouched: the same shape there still
        // answers `Memory`, which is a different contract and a different
        // variant.
        assert_eq!(
            declared_return_class("struct bv195_big", CallConv::SysVAmd64, Some(&env)),
            Some(ReturnClass::Memory)
        );
        // And no other convention acquires the `x8` contract.
        for cc in [
            CallConv::Win64,
            CallConv::Cdecl32,
            CallConv::Arm,
            CallConv::ArmHardFloat,
        ] {
            assert_eq!(
                declared_return_class("struct agr198_five", cc, Some(&env)),
                None,
                "{cc:?} acquired the AAPCS64 indirect result"
            );
        }
    }

    /// A field straddling the boundary makes BOTH eightbytes integer, and a
    /// nested struct is classified where its bytes land, not where it starts.
    #[test]
    fn nested_and_straddling_fields_are_placed_by_absolute_offset() {
        let types = vec![
            structure("inner", 8, vec![field(0, "value", "double", 8)]),
            structure(
                "outer",
                16,
                vec![
                    field(0, "tag", "int64_t", 8),
                    field(8, "nested", "struct inner", 8),
                ],
            ),
        ];
        let env = DwarfTypeEnv::new(&types);
        assert_eq!(
            declared_return_class("struct outer", CallConv::SysVAmd64, Some(&env)),
            Some(ReturnClass::SplitBanks {
                integer_first: true
            })
        );
    }

    /// An ARRAY member is placed by its element class over its whole extent.
    ///
    /// Before `array_member_eightbyte_class` this walk had no arm for an array
    /// at all: the member is neither a scalar it can place nor a struct it can
    /// recurse into, so the whole aggregate answered `None`. Both shapes below
    /// are ordinary System V classes with nothing exotic about them —
    /// `203_string_move_copies`'s sixteen-byte `{uint32_t q[4];}` is `rax:rdx`
    /// as a result and `rdi:rsi` as an argument, and `198`'s eight-byte
    /// `{int32_t v[2];}` is one register.
    #[test]
    fn an_array_member_is_classified_by_its_element() {
        let types = vec![
            structure("mv203_narrow", 16, vec![field(0, "q", "uint32_t[]", 16)]),
            structure("agr198_arr2", 8, vec![field(0, "v", "int32_t[]", 8)]),
            structure("float_pair", 16, vec![field(0, "v", "double[]", 16)]),
            // A nested-aggregate element has offsets this walk does not
            // compute, so it is refused rather than guessed at.
            structure("inner_arr", 8, vec![field(0, "a", "int32_t", 4)]),
            structure(
                "of_structs",
                16,
                vec![field(0, "v", "struct inner_arr[]", 16)],
            ),
        ];
        let env = DwarfTypeEnv::new(&types);
        let class = |name: &str| declared_return_class(name, CallConv::SysVAmd64, Some(&env));

        assert_eq!(class("struct mv203_narrow"), Some(ReturnClass::IntegerPair));
        assert_eq!(class("struct agr198_arr2"), Some(ReturnClass::Single));
        assert_eq!(
            class("struct float_pair"),
            Some(ReturnClass::SsePair { high_bytes: 8 })
        );
        assert_eq!(class("struct of_structs"), None);
    }

    /// A two-eightbyte INTEGER aggregate passed BY VALUE occupies two argument
    /// registers, and the second one's OCCUPANCY is the object's, not the
    /// register's.
    #[test]
    fn an_integer_pair_parameter_reports_its_second_eightbyte() {
        let types = corpus();
        let env = DwarfTypeEnv::new(&types);
        let high = |name: &str| {
            declared_integer_pair_parameter_high_bytes(name, CallConv::SysVAmd64, Some(&env))
        };

        assert_eq!(high("struct bv195_quad"), Some(8));
        // One eightbyte, all-SSE, memory and split-bank shapes are not this
        // class and must keep the behaviour they had.
        assert_eq!(high("struct bv195_pair"), None);
        assert_eq!(high("struct two_doubles"), None);
        assert_eq!(high("struct bv195_mixed"), None);
        assert_eq!(high("struct bv195_big"), None);

        // Twelve bytes: four of the second register are live. The float twin of
        // this shape is `hfa197_trio3f`, which is an SSE pair and not this.
        let trio = vec![structure(
            "agr198_trio",
            12,
            vec![
                field(0, "a", "int32_t", 4),
                field(4, "b", "int32_t", 4),
                field(8, "c", "int32_t", 4),
            ],
        )];
        let trio_env = DwarfTypeEnv::new(&trio);
        assert_eq!(
            declared_integer_pair_parameter_high_bytes(
                "struct agr198_trio",
                CallConv::SysVAmd64,
                Some(&trio_env)
            ),
            Some(4)
        );
    }

    /// A one-eightbyte aggregate result is spelled from its CLASS, so the
    /// declaration names the bank the ABI actually uses.
    ///
    /// `hfa197_tagged` is the shape that proves it matters: its low four bytes
    /// hold a `float`, so a declaration inferred from the returned expression
    /// said `float` and returned in `xmm0` where System V says `rax`.
    #[test]
    fn a_single_class_aggregate_is_spelled_from_its_size() {
        let types = corpus();
        let env = DwarfTypeEnv::new(&types);
        let spelling = |name: &str| {
            single_class_aggregate_return_c_type(name, CallConv::SysVAmd64, Some(&env))
        };

        assert_eq!(spelling("struct hfa197_tagged"), Some("unsigned long"));
        assert_eq!(spelling("struct bv195_pair"), Some("unsigned long"));
        assert_eq!(spelling("struct two_floats"), Some("unsigned long"));
        // Every multi-register and memory class keeps its own contract.
        assert_eq!(spelling("struct bv195_quad"), None);
        assert_eq!(spelling("struct two_doubles"), None);
        assert_eq!(spelling("struct bv195_mixed"), None);
        assert_eq!(spelling("struct bv195_big"), None);
        // A scalar has no aggregate layout and therefore no class to spell:
        // this path can never redeclare an ordinary return.
        assert_eq!(spelling("double"), None);
        assert_eq!(spelling("int32_t"), None);

        let narrow = vec![
            structure("one", 4, vec![field(0, "a", "int32_t", 4)]),
            structure(
                "bytes3",
                3,
                vec![
                    field(0, "a", "uint8_t", 1),
                    field(1, "b", "uint8_t", 1),
                    field(2, "c", "uint8_t", 1),
                ],
            ),
        ];
        let narrow_env = DwarfTypeEnv::new(&narrow);
        let narrow_spelling = |name: &str| {
            single_class_aggregate_return_c_type(name, CallConv::SysVAmd64, Some(&narrow_env))
        };
        assert_eq!(narrow_spelling("struct one"), Some("unsigned int"));
        // Three bytes round UP: the ABI leaves the rest of the register
        // unspecified, so the extra byte is one nobody may read.
        assert_eq!(narrow_spelling("struct bytes3"), Some("unsigned int"));
    }
}
