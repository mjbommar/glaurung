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
    // banks are all System V AMD64 facts. Win64 returns every aggregate wider
    // than one register through a hidden pointer, and AAPCS has its own HFA
    // rules; neither is modelled, and neither has fixtures to measure against.
    if cc != CallConv::SysVAmd64 {
        return None;
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
            None => {
                // Not a scalar this reader can place. A nested struct still can
                // be, by recursion; anything else (array, union, bitfield,
                // unresolved alias) fails the whole classification.
                classify_fields(&field.c_type, offset, type_env, eightbytes, depth + 1)?;
                continue;
            }
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

    #[test]
    fn unmodelled_shapes_refuse_to_classify_rather_than_guess() {
        let types = corpus();
        let env = DwarfTypeEnv::new(&types);
        let class = |name: &str| declared_return_class(name, CallConv::SysVAmd64, Some(&env));

        // Two SSE eightbytes return in `xmm0:xmm1`; there is no second float
        // result register in the value model.
        assert_eq!(class("struct two_doubles"), None);
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
            CallConv::Aarch64,
            CallConv::Arm,
            CallConv::ArmHardFloat,
        ] {
            assert_eq!(
                declared_return_class("struct bv195_quad", cc, Some(&env)),
                None,
                "{cc:?} acquired the System V aggregate contract"
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
}
