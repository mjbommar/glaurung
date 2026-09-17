//! The structured variable inventory a consumer needs to match our locals
//! against source ones without re-parsing the C we emitted.
//!
//! # Why this exists
//!
//! DecBench's `type_match` correspondence needs, per recovered variable, a
//! name, a C type, a storage kind, and — for the two anchor stages that do not
//! depend on spelling at all — an ABI argument index or a frame offset. When a
//! producer supplies none of that, DecBench falls back to regex-parsing the
//! emitted C (`metrics/type_match.py`), and under the local-variable
//! correspondence work those *inferred* variables have their evidence stripped
//! (`metrics/variable_match.py`) and are dropped outright in address-only mode
//! unless they carry an `arg_index` or a `stack_offset`. So a producer that
//! stays silent is not merely undescribed, it is actively penalised: its
//! variables cannot reach the `argument` or `stack` matching stages even though
//! it knows the answers.
//!
//! We know the answers. `RecoveredPrototype` holds each parameter's ABI slot
//! and type hint; `StackLocalFacts::frame_coordinates` holds the exact
//! `(base, displacement)` each promoted local was minted from, and already
//! WITHHOLDS any name reachable from two coordinates rather than guessing.
//! This module is the join, and nothing more — it computes no new facts.
//!
//! # The one rule
//!
//! **A variable is reported only if its name actually appears in the rendered
//! text.** This is not the text-parsing DecBench objects to; it is the reverse.
//! We never invent a variable from the C. We take a variable we independently
//! know about and refuse to report it unless the render agrees it survived.
//!
//! That filter is load-bearing because the render happens after ~77 rewrite
//! passes: dead-store elimination, copy propagation and canary recognition all
//! delete locals that `StackLocalFacts` still describes. Reporting one of those
//! would name a variable the consumer cannot find, which is worse than
//! reporting nothing — it is a claim about output that is false.
//!
//! # What this is NOT
//!
//! It carries no addresses and no line numbers. Those need instruction origin
//! to survive lowering, and it does not: `lower_block` calls
//! `lower_op(&ins.op, ..)` and drops `ins.va`. Emitting a *guessed* address
//! would be worse than emitting none, because a plausible wrong address passes
//! a consumer's validation (it is a real instruction start inside the function)
//! and silently mis-attributes the evidence. dewolf and Reko take the same
//! position for the same reason: direct facts where they are proven, silence
//! where they are not.

use std::collections::{BTreeMap, HashMap};

use crate::ir::stack_locals::StackLocalFacts;
use crate::ir::types_recover::RecoveredPrototype;

/// One recovered local or parameter, as a consumer sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredVariable {
    /// Immutable semantic-graph identity when storage evidence is unambiguous.
    pub static_variable: Option<crate::ir::function_ir::StaticVariable>,
    /// Immutable structural type identity when recovery retained typed
    /// provenance rather than only rendered C text.
    pub static_type: Option<crate::ir::function_ir::StaticType>,
    /// The identifier as it appears in the rendered C.
    pub name: String,
    /// The declared C type, or `"long"` when only the width is known.
    pub ctype: String,
    /// `"arg"` for an ABI parameter, `"stack"` for a promoted frame slot.
    pub kind: &'static str,
    /// Zero-based ABI parameter position. `None` for a stack local.
    pub arg_index: Option<usize>,
    /// Frame displacement the slot was minted from, signed, in the frame's own
    /// coordinate space. `None` for a parameter, and `None` for a local whose
    /// coordinate `StackLocalFacts` withheld as ambiguous.
    pub stack_offset: Option<i64>,
    /// Access width in bytes, when the promotion pass proved one.
    pub size: Option<u8>,
    /// Machine addresses this variable is read or written at, ascending.
    ///
    /// EMPTY MEANS "NOT CLAIMED", never "there are none". Populated only for a
    /// promoted stack slot whose frame coordinate survived
    /// `variable_addresses`' fail-closed rules; a parameter carries none,
    /// because a register's live range is not a storage coordinate and
    /// deriving it needs liveness this join deliberately does not do.
    pub addresses: Vec<u64>,
}

/// Whether `name` appears in `text` as a whole identifier.
///
/// Deliberately not a substring test: `var1` is a substring of `var10`, and a
/// prefix match would report a variable the render never emitted. Rust has no
/// regex in this crate's dependency-free path, so the boundary check is done on
/// the byte either side of each occurrence.
fn mentions_identifier(text: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let bytes = text.as_bytes();
    let name_bytes = name.as_bytes();
    let mut from = 0usize;
    while let Some(found) = text[from..].find(name) {
        let start = from + found;
        let end = start + name_bytes.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
        if from >= text.len() {
            break;
        }
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Join the prototype and the stack-promotion facts into the reported
/// inventory, keeping only variables the render actually mentions.
///
/// Ordering is deterministic — parameters by ABI slot, then locals by name —
/// because the output is compared across runs and a `HashMap` iteration order
/// would make two identical decompilations disagree.
pub fn recovered_variables(
    text: &str,
    prototype: Option<&RecoveredPrototype>,
    facts: &StackLocalFacts,
    pointer_width: u8,
) -> Vec<RecoveredVariable> {
    recovered_variables_with_addresses(text, prototype, facts, pointer_width, &HashMap::new())
}

/// [`recovered_variables`], sourcing machine addresses from the LLIR.
///
/// One call rather than two, because "join the coordinates, then build the
/// inventory" is an ordering every caller would otherwise have to know and
/// could get wrong. `lf` should be the function BEFORE canonicalisation: its
/// `va`s are the machine's own and no pass has synthesised instructions into
/// it.
pub fn recovered_variables_from_llir(
    text: &str,
    prototype: Option<&RecoveredPrototype>,
    facts: &StackLocalFacts,
    pointer_width: u8,
    lf: &crate::ir::types::LlirFunction,
) -> Vec<RecoveredVariable> {
    let addresses =
        crate::ir::variable_addresses::stack_slot_addresses(lf, &facts.frame_coordinates);
    recovered_variables_with_addresses(text, prototype, facts, pointer_width, &addresses)
}

/// [`recovered_variables_from_llir`] with graph-owned storage identities.
pub fn recovered_variables_from_llir_with_identity(
    text: &str,
    prototype: Option<&RecoveredPrototype>,
    facts: &StackLocalFacts,
    pointer_width: u8,
    lf: &crate::ir::types::LlirFunction,
    image_sha256: &str,
    lift_profile: &str,
) -> Vec<RecoveredVariable> {
    let mut variables = recovered_variables_from_llir(text, prototype, facts, pointer_width, lf);
    let function_id = crate::ir::function_ir::function_id(image_sha256, lift_profile, lf.entry_va);
    for variable in &mut variables {
        let static_type = match (variable.kind, variable.arg_index) {
            ("arg", Some(position)) => prototype
                .and_then(|prototype| prototype.parameter(position))
                .and_then(|parameter| parameter.hint)
                .map(|hint| {
                    use crate::ir::function_ir::RecoveredTypeShape;
                    use crate::ir::types_recover::TypeHint;
                    let shape = match hint {
                        TypeHint::Pointer { pointee_width } => RecoveredTypeShape::DataPointer {
                            pointee_width,
                            pointer_width,
                        },
                        TypeHint::Int { signed, width } => {
                            RecoveredTypeShape::Integer { signed, width }
                        }
                        TypeHint::Float { width } => RecoveredTypeShape::Float { width },
                        TypeHint::BoolLike => RecoveredTypeShape::BoolLike,
                        TypeHint::CodePointer => RecoveredTypeShape::CodePointer { pointer_width },
                    };
                    crate::ir::function_ir::recovered_static_type(
                        image_sha256,
                        shape,
                        &variable.ctype,
                        "glaurung-recovered-type-v1",
                    )
                }),
            _ => None,
        };
        let origin = match variable.kind {
            "arg" => variable.arg_index.map(|position| {
                crate::ir::function_ir::StaticVariableOrigin::AbiArgument {
                    position,
                    recovery_profile: "glaurung-recovered-variable-v1".to_string(),
                }
            }),
            "stack" => {
                let candidates = facts
                    .frame_coordinates
                    .iter()
                    .filter(|(promoted_name, _)| {
                        promoted_name.as_str() == variable.name
                            || facts.source_names.get(*promoted_name) == Some(&variable.name)
                    })
                    .map(|(_, coordinate)| coordinate)
                    .collect::<Vec<_>>();
                match candidates.as_slice() {
                    [(base, displacement)] => {
                        Some(crate::ir::function_ir::StaticVariableOrigin::FrameStorage {
                            base: (*base).clone(),
                            displacement: *displacement,
                            recovery_profile: "glaurung-recovered-variable-v1".to_string(),
                        })
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        variable.static_variable = origin.map(|origin| {
            crate::ir::function_ir::recovered_static_variable(
                image_sha256,
                &function_id,
                &variable.name,
                static_type.as_ref().map(|node| node.id.as_str()),
                origin,
            )
        });
        variable.static_type = static_type;
    }
    variables
}

/// [`recovered_variables`], with machine addresses joined in by promoted name.
///
/// `addresses` comes from [`crate::ir::variable_addresses::stack_slot_addresses`],
/// which keys on the same promoted names `StackLocalFacts` uses, so the join
/// here is a lookup rather than a match.
pub fn recovered_variables_with_addresses(
    text: &str,
    prototype: Option<&RecoveredPrototype>,
    facts: &StackLocalFacts,
    pointer_width: u8,
    addresses: &HashMap<String, Vec<u64>>,
) -> Vec<RecoveredVariable> {
    let mut out = Vec::new();

    // --- parameters -------------------------------------------------------
    //
    // `naming::apply_role_names` spells the Nth ABI parameter `argN`, and the
    // renderer prints the signature from this same prototype, so the name is
    // not a guess. An authoritative DWARF name may have replaced it, in which
    // case the `argN` spelling is absent from the text and the mention filter
    // correctly drops it rather than reporting a name the C does not contain.
    if let Some(prototype) = prototype {
        for parameter in prototype.parameters() {
            let name = format!("arg{}", parameter.slot);
            if !mentions_identifier(text, &name) {
                continue;
            }
            let ctype = parameter
                .hint
                .map(|hint| {
                    crate::ir::types_recover::c_type_for_hint_with_pointer_width(
                        hint,
                        pointer_width,
                    )
                    .to_string()
                })
                .unwrap_or_else(|| "long".to_string());
            out.push(RecoveredVariable {
                static_variable: None,
                static_type: None,
                name,
                ctype,
                kind: "arg",
                arg_index: Some(parameter.slot),
                stack_offset: None,
                size: None,
                addresses: Vec::new(),
            });
        }
    }

    // --- promoted stack locals -------------------------------------------
    //
    // Keyed by the promoted NAME, which is what both the render and
    // `frame_coordinates` use. A name with no coordinate is still reported:
    // the kind and type are useful on their own, and `stack_offset: None` is an
    // honest "this slot's coordinate was withheld" rather than a wrong number.
    let mut locals: BTreeMap<&str, ()> = BTreeMap::new();
    for name in facts.sizes.keys() {
        locals.insert(name.as_str(), ());
    }
    for name in facts.frame_coordinates.keys() {
        locals.insert(name.as_str(), ());
    }
    for name in facts.source_types.keys() {
        locals.insert(name.as_str(), ());
    }
    for name in locals.keys() {
        // An authoritative source name replaces the `local_N` spelling at the
        // presentation boundary, so look for whichever one the render used.
        let rendered = facts
            .source_names
            .get(*name)
            .filter(|source| mentions_identifier(text, source))
            .map(|source| source.as_str())
            .or_else(|| mentions_identifier(text, name).then_some(*name));
        let Some(rendered) = rendered else {
            continue;
        };
        out.push(RecoveredVariable {
            static_variable: None,
            static_type: None,
            name: rendered.to_string(),
            ctype: facts
                .source_types
                .get(*name)
                .cloned()
                .unwrap_or_else(|| "long".to_string()),
            kind: "stack",
            arg_index: None,
            stack_offset: facts
                .frame_coordinates
                .get(*name)
                .map(|(_base, displacement)| *displacement),
            size: facts.sizes.get(*name).copied(),
            // Keyed by the PROMOTED name, not the rendered one: a DWARF or
            // analyst name replaces the spelling at the presentation boundary,
            // long after the coordinate join that produced these.
            addresses: addresses.get(*name).cloned().unwrap_or_default(),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn facts() -> StackLocalFacts {
        StackLocalFacts {
            sizes: HashMap::from([("local_18".to_string(), 4u8)]),
            source_types: HashMap::from([("local_18".to_string(), "int".to_string())]),
            source_names: HashMap::new(),
            parameter_slots: HashMap::new(),
            machine_saved_slots: Default::default(),
            frame_coordinates: HashMap::from([(
                "local_18".to_string(),
                ("rbp".to_string(), -24i64),
            )]),
        }
    }

    #[test]
    fn a_promoted_local_reports_its_frame_offset_type_and_size() {
        let text = "long f(void) {\n    int local_18;\n    local_18 = 3;\n    return local_18;\n}";
        let vars = recovered_variables(text, None, &facts(), 8);
        assert_eq!(vars.len(), 1, "{vars:#?}");
        let v = &vars[0];
        assert_eq!(v.name, "local_18");
        assert_eq!(v.kind, "stack");
        assert_eq!(v.ctype, "int");
        assert_eq!(v.stack_offset, Some(-24));
        assert_eq!(v.size, Some(4));
        assert_eq!(v.arg_index, None);
    }

    #[test]
    fn recovered_identity_uses_frame_coordinate_not_rendered_name() {
        let lf = crate::ir::types::LlirFunction {
            entry_va: 0x401000,
            blocks: Vec::new(),
        };
        let image_sha256 = "ab".repeat(32);
        let first = recovered_variables_from_llir_with_identity(
            "long f(void) { int local_18; return local_18; }",
            None,
            &facts(),
            8,
            &lf,
            &image_sha256,
            "glaurung-raw-llir-v1",
        );
        let mut renamed_facts = facts();
        renamed_facts
            .source_names
            .insert("local_18".to_string(), "count".to_string());
        let renamed = recovered_variables_from_llir_with_identity(
            "long f(void) { int count; return count; }",
            None,
            &renamed_facts,
            8,
            &lf,
            &image_sha256,
            "glaurung-raw-llir-v1",
        );
        assert_eq!(first.len(), 1);
        assert_eq!(renamed.len(), 1);
        assert_eq!(
            first[0].static_variable.as_ref().unwrap().id,
            renamed[0].static_variable.as_ref().unwrap().id
        );
        assert_ne!(first[0].name, renamed[0].name);
    }

    #[test]
    fn recovered_parameter_uses_structural_type_identity() {
        let mut prototype = RecoveredPrototype::default();
        prototype.apply_locked_parameters(
            crate::ir::call_args::CallConv::SysVAmd64,
            &[Some(crate::ir::types_recover::TypeHint::Int {
                signed: false,
                width: 4,
            })],
        );
        let lf = crate::ir::types::LlirFunction {
            entry_va: 0x401000,
            blocks: Vec::new(),
        };
        let variables = recovered_variables_from_llir_with_identity(
            "unsigned int f(unsigned int arg0) { return arg0; }",
            Some(&prototype),
            &StackLocalFacts::default(),
            8,
            &lf,
            &"ab".repeat(32),
            "glaurung-raw-llir-v1",
        );
        let variable = variables.first().expect("one recovered parameter");
        let static_variable = variable
            .static_variable
            .as_ref()
            .expect("parameter storage identity");
        let static_type = variable
            .static_type
            .as_ref()
            .expect("structured recovered type");
        assert_eq!(
            static_variable.type_id.as_deref(),
            Some(static_type.id.as_str())
        );
        assert!(matches!(
            static_type.origin,
            crate::ir::function_ir::StaticTypeOrigin::Recovered {
                shape: crate::ir::function_ir::RecoveredTypeShape::Integer {
                    signed: false,
                    width: 4,
                },
                ..
            }
        ));
    }

    /// The render happens after ~77 rewrite passes, several of which DELETE
    /// locals that `StackLocalFacts` still describes. Reporting one of those
    /// names a variable the consumer cannot find in the C.
    #[test]
    fn a_local_the_render_dropped_is_not_reported() {
        let text = "long f(void) {\n    return 3;\n}";
        assert!(recovered_variables(text, None, &facts(), 8).is_empty());
    }

    /// `var1` is a substring of `var10`. A prefix match would report a variable
    /// the render never emitted.
    #[test]
    fn a_name_that_is_only_a_prefix_of_another_is_not_a_mention() {
        assert!(!mentions_identifier("long var10;", "var1"));
        assert!(mentions_identifier("long var1;", "var1"));
        assert!(mentions_identifier("return var1;", "var1"));
        assert!(mentions_identifier("f(var1, x)", "var1"));
        assert!(!mentions_identifier("long my_var1;", "var1"));
        assert!(!mentions_identifier("", "var1"));
        assert!(!mentions_identifier("long var1;", ""));
    }

    /// An ambiguous frame coordinate is WITHHELD by `stack_locals`, and this
    /// must report that as absence rather than inventing a displacement.
    #[test]
    fn a_withheld_coordinate_reports_no_offset_rather_than_a_wrong_one() {
        let mut f = facts();
        f.frame_coordinates.clear();
        let text = "long f(void) {\n    int local_18;\n    return local_18;\n}";
        let vars = recovered_variables(text, None, &f, 8);
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].stack_offset, None, "a withheld coordinate is None");
        assert_eq!(vars[0].size, Some(4), "the other facts still survive");
    }

    /// Two identical decompilations must report identical inventories, so the
    /// order cannot come from a `HashMap` walk.
    #[test]
    fn the_inventory_order_is_deterministic() {
        let mut f = StackLocalFacts::default();
        for name in ["local_c", "local_18", "local_4", "stack_0"] {
            f.sizes.insert(name.to_string(), 4);
        }
        let text = "long f(void) { int local_c; int local_18; int local_4; int stack_0; }";
        let first: Vec<String> = recovered_variables(text, None, &f, 8)
            .into_iter()
            .map(|v| v.name)
            .collect();
        for _ in 0..8 {
            let again: Vec<String> = recovered_variables(text, None, &f, 8)
                .into_iter()
                .map(|v| v.name)
                .collect();
            assert_eq!(first, again);
        }
        assert_eq!(first, ["local_18", "local_4", "local_c", "stack_0"]);
    }
}
