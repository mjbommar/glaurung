use std::collections::HashMap;

use crate::ir::call_args::CallConv;
use crate::ir::types_recover::TypeHint;

use super::{
    callback_api_identity, merge_pair, merge_prototype_fact, message_identity_result,
    AbstractValue, CallbackState, DeclarationSource, FunctionPrototypeFact,
};

#[test]
fn declaration_authority_is_total_and_has_stable_metadata_labels() {
    let ordered = [
        DeclarationSource::Inferred,
        DeclarationSource::Pdb,
        DeclarationSource::Dwarf,
        DeclarationSource::Analyst,
    ];
    assert!(ordered.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        ordered.map(DeclarationSource::label),
        ["inferred", "pdb", "dwarf", "analyst"]
    );
    assert_eq!(
        DeclarationSource::strongest(
            (DeclarationSource::Pdb, "pdb"),
            (DeclarationSource::Dwarf, "dwarf"),
        ),
        (DeclarationSource::Dwarf, "dwarf")
    );
}

#[test]
fn conditional_fact_requires_both_arms_to_agree() {
    let known = AbstractValue::Scalar(7);

    assert_eq!(merge_pair(Some(known.clone()), None), None);
    assert_eq!(merge_pair(None, Some(known.clone())), None);
    assert_eq!(
        merge_pair(Some(known.clone()), Some(known.clone())),
        Some(known)
    );
    assert_eq!(
        merge_pair(
            Some(AbstractValue::Scalar(7)),
            Some(AbstractValue::Scalar(8))
        ),
        None
    );
}

#[test]
fn callback_identity_tracks_only_recognized_registration_apis() {
    let names = HashMap::from([
        (0x30, "unrelated".to_string()),
        (0x20, "signal@plt".to_string()),
        (0x10, "sigaction@GLIBC_2.2.5".to_string()),
    ]);

    assert_eq!(
        callback_api_identity(&names).as_ref(),
        &[(0x10, "sigaction.sa_handler"), (0x20, "signal.handler")]
    );
}

#[test]
fn message_identity_preserves_literals_and_marks_forwarded_parameters() {
    for (input, expected) in [
        (AbstractValue::Data(0x401000), AbstractValue::Data(0x401000)),
        (AbstractValue::Scalar(7), AbstractValue::Scalar(7)),
        (
            AbstractValue::Parameter(3),
            AbstractValue::FormatParameter(3),
        ),
        (
            AbstractValue::FormatParameter(4),
            AbstractValue::FormatParameter(4),
        ),
    ] {
        let mut state = CallbackState::default();
        state.registers.insert("rsi".to_string(), input);
        assert_eq!(
            message_identity_result(&state, CallConv::SysVAmd64, 1),
            Some(expected)
        );
    }
}

#[test]
fn partial_type_evidence_does_not_truncate_an_exact_caller_arity() {
    let mut prototypes = HashMap::new();
    let mut partial_hints = vec![None; 6];
    partial_hints[4] = Some(TypeHint::Pointer { pointee_width: 1 });
    merge_prototype_fact(
        &mut prototypes,
        0x401000,
        FunctionPrototypeFact {
            parameter_hints: partial_hints,
            parameter_arity_is_exact: false,
            output_kind: None,
            source: "literal-format callers",
        },
    );
    merge_prototype_fact(
        &mut prototypes,
        0x401000,
        FunctionPrototypeFact {
            parameter_hints: vec![None; 7],
            parameter_arity_is_exact: true,
            output_kind: None,
            source: "agreeing direct caller stack bound",
        },
    );

    let fact = &prototypes[&0x401000];
    assert!(fact.parameter_arity_is_exact);
    assert_eq!(fact.parameter_hints.len(), 7);
    assert_eq!(
        fact.parameter_hints[4],
        Some(TypeHint::Pointer { pointee_width: 1 })
    );
}
