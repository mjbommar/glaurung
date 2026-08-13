use crate::core::{DataType, Field};

use super::{
    ObjectTypeKey, TypeAuthority, TypeConflict, TypeEvidence, TypeField, TypeShape, TypeStore,
    TypeStoreError,
};

fn evidence(authority: TypeAuthority, source: &str) -> TypeEvidence {
    TypeEvidence::new(authority, source)
}

#[test]
fn recursive_nominal_types_import_independently_of_input_order() {
    let i32_type =
        DataType::new_primitive("i32".into(), "int".into(), 4, Some(4), Some("dwarf".into()));
    let node_pointer = DataType::new_pointer(
        "node_ptr".into(),
        "Node *".into(),
        8,
        Some(8),
        "node".into(),
        Vec::new(),
        Some("dwarf".into()),
    );
    let node = DataType::new_struct(
        "node".into(),
        "Node".into(),
        16,
        Some(8),
        vec![
            Field {
                name: "next".into(),
                type_id: "node_ptr".into(),
                offset: 0,
            },
            Field {
                name: "value".into(),
                type_id: "i32".into(),
                offset: 8,
            },
        ],
        Some("dwarf".into()),
    );

    let mut forward = TypeStore::default();
    let forward_report = forward.import_data_types(
        &[node.clone(), i32_type.clone(), node_pointer.clone()],
        evidence(TypeAuthority::Debug, "dwarf"),
    );
    let mut reverse = TypeStore::default();
    let reverse_report = reverse.import_data_types(
        &[node_pointer, i32_type, node],
        evidence(TypeAuthority::Debug, "dwarf"),
    );

    assert!(forward_report.conflicts.is_empty());
    assert!(reverse_report.conflicts.is_empty());
    assert_eq!(forward.records(), reverse.records());
    let node_id = forward.resolve_external("node").expect("node type");
    let pointer_id = forward.resolve_external("node_ptr").expect("pointer type");
    assert!(matches!(
        forward.get(node_id).and_then(|record| record.selected_shape()),
        Some(TypeShape::Struct { fields, .. })
            if fields.first() == Some(&TypeField { name: "next".into(), type_id: pointer_id, offset: 0 })
    ));
    assert!(matches!(
        forward.get(pointer_id).and_then(|record| record.selected_shape()),
        Some(TypeShape::Pointer { pointee, .. }) if *pointee == node_id
    ));
    assert!(forward.verify().is_empty());
}

#[test]
fn anonymous_inferred_shapes_are_interned_once() {
    let mut store = TypeStore::default();
    let shape = TypeShape::Primitive {
        name: "unsigned int".into(),
        size: 4,
        alignment: Some(4),
    };

    let first = store
        .intern_anonymous(
            shape.clone(),
            evidence(TypeAuthority::Inference, "memory-width"),
        )
        .expect("intern first shape");
    let second = store
        .intern_anonymous(shape, evidence(TypeAuthority::Inference, "return-use"))
        .expect("reuse shape");

    assert_eq!(first, second);
    assert_eq!(store.records().len(), 1);
    assert_eq!(store.get(first).expect("interned type").evidence().len(), 2);
    assert!(store.verify().is_empty());
}

#[test]
fn weaker_conflicting_evidence_cannot_overwrite_analyst_type() {
    let analyst = DataType::new_primitive(
        "word".into(),
        "uint32_t".into(),
        4,
        Some(4),
        Some("analyst".into()),
    );
    let inferred = DataType::new_primitive(
        "word".into(),
        "uint64_t".into(),
        8,
        Some(8),
        Some("inference".into()),
    );
    let mut store = TypeStore::default();
    store.import_data_types(&[analyst], evidence(TypeAuthority::Analyst, "analyst"));
    let report = store.import_data_types(
        &[inferred],
        evidence(TypeAuthority::Inference, "width-guess"),
    );

    let id = store.resolve_external("word").expect("word type");
    let record = store.get(id).expect("word record");
    assert!(matches!(
        record.selected_shape(),
        Some(TypeShape::Primitive { size: 4, .. })
    ));
    assert_eq!(record.alternatives().len(), 1);
    assert_eq!(
        report.conflicts,
        vec![(id, TypeConflict::IncompatibleDefinition)]
    );
    assert!(store.verify().is_empty());
}

#[test]
fn missing_references_remain_explicit_and_unselected() {
    let pointer = DataType::new_pointer(
        "dangling".into(),
        "Missing *".into(),
        8,
        Some(8),
        "missing".into(),
        Vec::new(),
        Some("pdb".into()),
    );
    let mut store = TypeStore::default();
    let report = store.import_data_types(&[pointer], evidence(TypeAuthority::Debug, "pdb"));

    let id = store
        .resolve_external("dangling")
        .expect("reserved identity");
    let record = store.get(id).expect("dangling record");
    assert!(record.selected_shape().is_none());
    assert!(record
        .conflicts()
        .contains(&TypeConflict::MissingReference("missing".into())));
    assert_eq!(report.conflicts.len(), 1);
    assert!(store.verify().is_empty());
}

#[test]
fn stable_function_object_identity_joins_type_evidence_without_overwrite() {
    let mut store = TypeStore::default();
    let narrow = store
        .intern_anonymous(
            TypeShape::Primitive {
                name: "uint32_t".into(),
                size: 4,
                alignment: Some(4),
            },
            evidence(TypeAuthority::Debug, "dwarf"),
        )
        .expect("intern narrow type");
    let wide = store
        .intern_anonymous(
            TypeShape::Primitive {
                name: "uint64_t".into(),
                size: 8,
                alignment: Some(8),
            },
            evidence(TypeAuthority::Inference, "access-width"),
        )
        .expect("intern wide type");
    let key = ObjectTypeKey {
        function_entry: 0x401000,
        object: crate::ir::mir::ObjectId(3),
    };

    store
        .bind_object_type(key, narrow, evidence(TypeAuthority::Debug, "dwarf-local"))
        .expect("bind debug type");
    store
        .bind_object_type(key, wide, evidence(TypeAuthority::Inference, "width-guess"))
        .expect("retain inferred alternative");

    let binding = store.object_type(key).expect("object type binding");
    assert_eq!(binding.selected(), narrow);
    assert_eq!(binding.alternatives().collect::<Vec<_>>(), vec![wide]);
    assert!(store.verify().is_empty());
}

#[test]
fn anonymous_shapes_with_unknown_references_are_rejected_without_mutation() {
    let mut store = TypeStore::default();
    let result = store.intern_anonymous(
        TypeShape::Pointer {
            pointee: super::TypeId(usize::MAX),
            size: 8,
            alignment: Some(8),
            attributes: Vec::new(),
        },
        evidence(TypeAuthority::Inference, "bad-pointer"),
    );

    assert_eq!(
        result,
        Err(TypeStoreError::UnknownReference(super::TypeId(usize::MAX)))
    );
    assert!(store.records().is_empty());
}
