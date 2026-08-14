use std::process::Command;
use std::sync::Arc;

use crate::analysis::cfg::Budgets;
use crate::ir::call_args::CallConv;
use crate::program::types::{TypeAuthority, TypeShape};

use super::session::ProgramSession;

fn real_test_session() -> (ProgramSession, u64) {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let source = directory.path().join("session.c");
    let executable = directory.path().join("session");
    std::fs::write(
        &source,
        "__attribute__((noinline)) int session_target(int x) { return x + 1; }\n\
         int main(void) { return session_target(4); }\n",
    )
    .expect("write real C fixture");
    let output = Command::new("cc")
        .args(["-g", "-O0", "-o"])
        .arg(&executable)
        .arg(&source)
        .output()
        .expect("host C compiler is available");
    assert!(
        output.status.success(),
        "compile real session fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let session = ProgramSession::from_path(&executable).expect("fixture is a real object");
    let entry = session
        .image()
        .defined_text_symbol_address("session_target")
        .expect("fixture target symbol");
    (session, entry)
}

fn focused_budgets() -> Budgets {
    Budgets {
        max_functions: 1,
        max_blocks: 64,
        max_instructions: 4_096,
        timeout_ms: 5_000,
        total_timeout_ms: 0,
    }
}

fn real_recursive_type_session() -> ProgramSession {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let source = directory.path().join("recursive_types.c");
    let executable = directory.path().join("recursive_types");
    std::fs::write(
        &source,
        "typedef enum Direction { LEFT = 0, RIGHT = 1 } Direction;\n\
         typedef struct Node {\n\
             int value;\n\
             struct Node *next;\n\
         } Node;\n\
         __attribute__((noinline)) int node_value(Node *node, Direction direction) {\n\
             return node ? node->value + direction : 0;\n\
         }\n\
         int main(void) { Node node = { 7, 0 }; return node_value(&node, RIGHT); }\n",
    )
    .expect("write real recursive type fixture");
    let output = Command::new("cc")
        .args(["-g", "-O0", "-o"])
        .arg(&executable)
        .arg(&source)
        .output()
        .expect("host C compiler is available");
    assert!(
        output.status.success(),
        "compile real recursive type fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ProgramSession::from_path(&executable).expect("fixture is a real object")
}

#[test]
fn exact_discovery_is_reused_within_one_session() {
    let (session, entry) = real_test_session();

    let first = session.discover_functions(&focused_budgets(), &[entry]);
    let after_first = session.discovery_cache_stats();
    let second = session.discover_functions(&focused_budgets(), &[entry]);
    let after_second = session.discovery_cache_stats();

    assert!(
        !first.is_empty(),
        "the real test executable entry is discoverable"
    );
    assert_eq!(
        first
            .iter()
            .map(|function| function.entry_point.value)
            .collect::<Vec<_>>(),
        second
            .iter()
            .map(|function| function.entry_point.value)
            .collect::<Vec<_>>()
    );
    assert_eq!(after_first.misses, 1);
    assert_eq!(after_first.hits, 0);
    assert_eq!(after_second.misses, 1);
    assert_eq!(after_second.hits, 1);
    assert_eq!(after_second.evictions, 0);

    session.clear_caches();
    let cleared = session.discovery_cache_stats();
    assert_eq!(cleared.entries, 0);
    assert_eq!(cleared.hits, 0);
    assert_eq!(cleared.misses, 0);
    assert_eq!(cleared.evictions, 0);
}

#[test]
fn discovery_cache_key_includes_budgets_and_normalized_seeds() {
    let (session, entry) = real_test_session();
    let mut wider = focused_budgets();
    wider.max_blocks += 1;

    let _ = session.discover_functions(&focused_budgets(), &[entry, entry]);
    let _ = session.discover_functions(&focused_budgets(), &[entry]);
    let _ = session.discover_functions(&wider, &[entry]);

    let stats = session.discovery_cache_stats();
    assert_eq!(stats.hits, 1, "duplicate seeds normalize to the same key");
    assert_eq!(stats.misses, 2, "a budget change requires new discovery");
    assert_eq!(stats.entries, 2);
}

#[test]
fn session_exposes_the_images_single_canonical_target() {
    let (session, _) = real_test_session();

    assert!(std::ptr::eq(session.target(), session.image().target()));
    assert_eq!(session.target().id(), crate::target::TargetId::X86_64);
    assert_eq!(
        session.target().calling_convention(),
        Some(crate::target::CallConv::SysVAmd64)
    );
}

#[test]
fn real_debug_types_are_imported_once_and_shared_by_every_environment() {
    let session = real_recursive_type_session();

    let first_debug = session.debug_types();
    let second_debug = session.debug_types();
    assert!(Arc::ptr_eq(&first_debug, &second_debug));
    let debug_node = first_debug
        .iter()
        .find(|record| {
            record.kind == crate::debug::dwarf::DwarfTypeKind::Struct && record.name == "Node"
        })
        .expect("Node DWARF layout");
    assert_eq!(
        debug_node
            .fields
            .iter()
            .find(|field| field.name == "value")
            .expect("value debug field")
            .size,
        4
    );
    assert_eq!(
        debug_node
            .fields
            .iter()
            .find(|field| field.name == "next")
            .expect("next debug field")
            .size,
        u64::from(session.target().address_bits().expect("address width")) / 8
    );

    let first_store = session.type_store();
    let second_store = session.type_store();
    assert!(Arc::ptr_eq(&first_store, &second_store));
    assert!(first_store.verify().is_empty());

    let node_id = first_store
        .resolve_external("dwarf:struct:Node")
        .expect("recursive Node identity");
    let node = first_store.get(node_id).expect("recursive Node record");
    let fields = match node.selected_shape() {
        Some(TypeShape::Struct { fields, .. }) => fields,
        other => panic!("expected Node structure, got {other:?}"),
    };
    let next_id = fields
        .iter()
        .find(|field| field.name == "next")
        .expect("next field")
        .type_id;
    assert!(matches!(
        first_store
            .get(next_id)
            .and_then(|record| record.selected_shape()),
        Some(TypeShape::Pointer {
            pointee,
            alignment: None,
            ..
        }) if *pointee == node_id
    ));
    let value_id = fields
        .iter()
        .find(|field| field.name == "value")
        .expect("value field")
        .type_id;
    assert!(matches!(
        first_store
            .get(value_id)
            .and_then(|record| record.selected_shape()),
        Some(TypeShape::Primitive {
            size: 4,
            alignment: None,
            ..
        })
    ));
    assert!(node.evidence().iter().any(|evidence| {
        evidence.authority == TypeAuthority::Debug
            && evidence.source == "dwarf"
            && evidence
                .format_source
                .as_deref()
                .is_some_and(|source| source.ends_with("recursive_types.c"))
    }));

    let direction_id = first_store
        .resolve_external("dwarf:enum:Direction")
        .expect("Direction enum identity");
    let underlying_id = match first_store
        .get(direction_id)
        .and_then(|record| record.selected_shape())
    {
        Some(TypeShape::Enum { underlying, .. }) => *underlying,
        other => panic!("expected Direction enum, got {other:?}"),
    };
    assert!(matches!(
        first_store
            .get(underlying_id)
            .and_then(|record| record.selected_shape()),
        Some(TypeShape::Primitive { name, size: 4, .. }) if name == "enum-underlying"
    ));

    let names = std::collections::HashMap::new();
    let first_environment =
        session.environment(&focused_budgets(), CallConv::SysVAmd64, &names, &[]);
    let mut wider = focused_budgets();
    wider.max_blocks += 1;
    let second_environment = session.environment(&wider, CallConv::SysVAmd64, &names, &[]);
    assert!(std::ptr::eq(
        first_environment.types(),
        first_store.as_ref()
    ));
    assert!(std::ptr::eq(
        second_environment.types(),
        first_store.as_ref()
    ));
}

/// Negative control: an image with no debug information must yield an empty
/// canonical store. Absent evidence is not permission to invent types.
#[test]
fn a_real_image_without_debug_information_produces_no_invented_types() {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let source = directory.path().join("no_debug_types.c");
    let executable = directory.path().join("no_debug_types");
    std::fs::write(
        &source,
        "typedef struct Node {\n\
             int value;\n\
             struct Node *next;\n\
         } Node;\n\
         __attribute__((noinline)) int node_value(Node *node) {\n\
             return node ? node->value : 0;\n\
         }\n\
         int main(void) { Node node = { 7, 0 }; return node_value(&node); }\n",
    )
    .expect("write real no-debug fixture");
    let output = Command::new("cc")
        .args(["-O0", "-g0", "-s", "-o"])
        .arg(&executable)
        .arg(&source)
        .output()
        .expect("host C compiler is available");
    assert!(
        output.status.success(),
        "compile real no-debug fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let session = ProgramSession::from_path(&executable).expect("fixture is a real object");

    assert!(
        session.debug_types().is_empty(),
        "a stripped image has no DWARF type records"
    );
    let store = session.type_store();
    assert!(store.verify().is_empty());
    assert!(
        store.records().is_empty(),
        "no debug evidence must import no types, got {} records",
        store.records().len()
    );
    assert!(store.resolve_external("dwarf:struct:Node").is_none());
}

/// Negative control: two translation units may legally define the same struct
/// tag with different layouts. The import must retain both as a conflict rather
/// than let the last record silently win.
#[test]
fn same_named_debug_layouts_from_different_units_are_retained_as_conflicts() {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let narrow = directory.path().join("narrow.c");
    let wide = directory.path().join("wide.c");
    let executable = directory.path().join("conflicting_layouts");
    std::fs::write(
        &narrow,
        "struct Conflict { int only; };\n\
         __attribute__((noinline)) int narrow_use(struct Conflict *value) {\n\
             return value->only;\n\
         }\n\
         long wide_use(void);\n\
         int main(void) {\n\
             struct Conflict value = { 3 };\n\
             return narrow_use(&value) + (int) wide_use();\n\
         }\n",
    )
    .expect("write narrow layout unit");
    std::fs::write(
        &wide,
        "struct Conflict { long first; long second; };\n\
         __attribute__((noinline)) long wide_use(void) {\n\
             struct Conflict value = { 11, 12 };\n\
             return value.first + value.second;\n\
         }\n",
    )
    .expect("write wide layout unit");
    let output = Command::new("cc")
        .args(["-g", "-O0", "-o"])
        .arg(&executable)
        .arg(&narrow)
        .arg(&wide)
        .output()
        .expect("host C compiler is available");
    assert!(
        output.status.success(),
        "compile conflicting layout fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let session = ProgramSession::from_path(&executable).expect("fixture is a real object");

    let debug_layouts = session
        .debug_types()
        .iter()
        .filter(|record| {
            record.kind == crate::debug::dwarf::DwarfTypeKind::Struct && record.name == "Conflict"
        })
        .map(|record| record.byte_size)
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        debug_layouts.len() > 1,
        "fixture must really carry two distinct Conflict layouts, saw {debug_layouts:?}"
    );

    let store = session.type_store();
    assert!(store.verify().is_empty());
    let conflict_id = store
        .resolve_external("dwarf:struct:Conflict")
        .expect("Conflict identity");
    let record = store.get(conflict_id).expect("Conflict record");
    assert!(
        record
            .conflicts()
            .contains(&crate::program::types::TypeConflict::IncompatibleDefinition),
        "disagreeing debug layouts must be recorded as a conflict, got {:?}",
        record.conflicts()
    );
    let mut retained = record
        .alternatives()
        .chain(record.selected_shape())
        .filter_map(|shape| match shape {
            TypeShape::Struct { size, .. } => Some(*size),
            _ => None,
        })
        .collect::<Vec<_>>();
    retained.sort_unstable();
    retained.dedup();
    assert_eq!(
        retained,
        debug_layouts.into_iter().collect::<Vec<_>>(),
        "every disagreeing layout must be retained, not overwritten"
    );
}
