use std::process::Command;
use std::sync::Arc;

use crate::analysis::cfg::Budgets;
use crate::ir::call_args::CallConv;
use crate::program::symbols::{
    AddressSymbol, AddressUnknown, NameMatch, SymbolAuthority, SymbolBinding, SymbolConflict,
    SymbolDefinition, SymbolIncompleteness, SymbolKind, SymbolSource,
};
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

/// Compile one real fixture and own the resulting session. The temporary
/// directory is dropped on return; the session already owns the image bytes.
fn compiled_session(units: &[(&str, &str)], flags: &[&str]) -> ProgramSession {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let executable = directory.path().join("fixture");
    let mut command = Command::new("cc");
    command.args(flags).arg("-o").arg(&executable);
    for (name, contents) in units {
        let source = directory.path().join(name);
        std::fs::write(&source, contents).expect("write real C fixture");
        command.arg(&source);
    }
    let output = command.output().expect("host C compiler is available");
    assert!(
        output.status.success(),
        "compile real symbol fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ProgramSession::from_path(&executable).expect("fixture is a real object")
}

const SYMBOL_FIXTURE: &str = "#include <stdio.h>\n\
     __attribute__((noinline)) int symbol_target(int x) { return x + 1; }\n\
     int main(void) { printf(\"%d\\n\", symbol_target(4)); return 0; }\n";

#[test]
fn real_object_symbols_import_once_with_exact_provenance() {
    let session = compiled_session(&[("symbols.c", SYMBOL_FIXTURE)], &["-g", "-O0"]);

    let first = session.symbol_store();
    let second = session.symbol_store();
    assert!(Arc::ptr_eq(&first, &second), "one image, one symbol store");
    assert!(first.verify().is_empty(), "{:?}", first.verify());

    let id = first
        .symbol_by_linkage("symbol_target")
        .expect("the defined text symbol is imported");
    let record = first.get(id).expect("record");
    let selected = record
        .selected()
        .expect("an object symbol has a definition");
    assert_eq!(selected.kind, SymbolKind::Function);
    assert_eq!(selected.binding, SymbolBinding::Global);
    let entry = session
        .image()
        .defined_text_symbol_address("symbol_target")
        .expect("fixture target symbol");
    match selected.definition {
        SymbolDefinition::Defined { address, size } => {
            assert_eq!(address, entry);
            assert!(size.is_some_and(|size| size > 0), "ELF states a FUNC size");
        }
        other => panic!("expected a defined symbol, got {other:?}"),
    }
    assert!(
        selected.evidence().iter().any(|evidence| {
            evidence.authority == SymbolAuthority::Binary
                && evidence.source == SymbolSource::ObjectSymbolTable
        }),
        "the object symbol table is exact binary evidence, got {:?}",
        selected.evidence()
    );
    assert!(
        record
            .names()
            .all(|name| name.match_kind == NameMatch::Exact),
        "every imported name is read verbatim, never a resemblance"
    );
    assert!(record.conflicts().is_empty());
}

#[test]
fn contextual_address_queries_resolve_exact_starts_offsets_and_unknowns() {
    let session = compiled_session(&[("symbols.c", SYMBOL_FIXTURE)], &["-g", "-O0"]);
    let store = session.symbol_store();
    let entry = session
        .image()
        .defined_text_symbol_address("symbol_target")
        .expect("fixture target symbol");
    let id = store.symbol_by_linkage("symbol_target").expect("identity");

    match store.resolve_address(entry) {
        AddressSymbol::Exact { symbols } => assert!(symbols.contains(&id)),
        other => panic!("expected an exact start, got {other:?}"),
    }
    match store.resolve_address(entry + 4) {
        AddressSymbol::Containing { symbols, offset } => {
            assert!(symbols.contains(&id));
            assert_eq!(offset, 4);
        }
        other => panic!("expected a containing range, got {other:?}"),
    }
    assert!(
        matches!(
            store.resolve_address(0xdead_0000_0000),
            AddressSymbol::Unknown(AddressUnknown::NoSymbolEvidence)
        ),
        "an unmapped address is an explicit unknown, not a nearest guess"
    );
}

#[test]
fn real_dynamic_imports_preserve_module_version_and_binding() {
    let session = compiled_session(&[("symbols.c", SYMBOL_FIXTURE)], &["-g", "-O0"]);
    let store = session.symbol_store();

    let id = store
        .symbol_by_linkage("printf")
        .expect("the dynamic import is present");
    let record = store.get(id).expect("record");
    let selected = record.selected().expect("an import has a definition state");
    assert_eq!(selected.definition, SymbolDefinition::Undefined);
    assert_eq!(selected.kind, SymbolKind::Function);
    assert_eq!(selected.binding, SymbolBinding::Global);
    assert!(
        selected.evidence().iter().any(|evidence| {
            evidence.source == SymbolSource::ImportTable
                && evidence
                    .module
                    .as_deref()
                    .is_some_and(|module| !module.is_empty())
        }),
        "an import records its defining module, got {:?}",
        selected.evidence()
    );
    assert!(
        selected.evidence().iter().any(|evidence| {
            evidence
                .version
                .as_deref()
                .is_some_and(|version| version.contains('_'))
        }),
        "ELF symbol versions are retained, got {:?}",
        selected.evidence()
    );

    let weak = store
        .symbol_by_linkage("__cxa_finalize")
        .and_then(|id| store.get(id))
        .and_then(|record| record.selected());
    assert_eq!(
        weak.map(|fact| fact.binding),
        Some(SymbolBinding::Weak),
        "a weak binding is preserved, not normalized to global"
    );
}

#[test]
fn real_relocations_index_exact_reference_sites() {
    let session = compiled_session(&[("symbols.c", SYMBOL_FIXTURE)], &["-g", "-O0"]);
    let store = session.symbol_store();
    let id = store.symbol_by_linkage("printf").expect("dynamic import");

    let references = store.references_to(id).collect::<Vec<_>>();
    assert!(
        !references.is_empty(),
        "the loader relocation naming printf must be indexed"
    );
    for reference in &references {
        assert_eq!(reference.symbol, id);
        assert_eq!(reference.evidence.source, SymbolSource::DynamicRelocation);
        assert!(
            reference.format_type.is_some(),
            "the exact format relocation type is retained"
        );
        assert_eq!(
            session.image().memory_kind_at(reference.site),
            Some(crate::program::image::ImageMemoryKind::Writable),
            "a loader-bound slot is mapped writable storage"
        );
        assert!(store
            .references_at(reference.site)
            .any(|indexed| indexed.symbol == id));
    }
}

/// Negative control: a stripped image must not invent a single name. Only the
/// dynamic table survives, and the store must say so rather than look complete.
#[test]
fn a_real_stripped_image_invents_no_symbols() {
    let debug = compiled_session(&[("symbols.c", SYMBOL_FIXTURE)], &["-g", "-O0"]);
    let entry = debug
        .image()
        .defined_text_symbol_address("symbol_target")
        .expect("fixture target symbol");

    let stripped = compiled_session(&[("symbols.c", SYMBOL_FIXTURE)], &["-O0", "-s"]);
    let store = stripped.symbol_store();
    assert!(store.verify().is_empty(), "{:?}", store.verify());

    assert!(
        store.symbol_by_linkage("symbol_target").is_none(),
        "a stripped image cannot name its own functions"
    );
    assert!(store.symbol_by_linkage("main").is_none());
    assert!(
        store.symbols_named("symbol_target").is_empty(),
        "no alias may resurrect a stripped name"
    );
    assert!(
        matches!(
            store.resolve_address(entry),
            AddressSymbol::Unknown(AddressUnknown::NoSymbolEvidence)
        ),
        "an unnamed address stays explicitly unknown, got {:?}",
        store.resolve_address(entry)
    );
    assert!(
        !store.is_complete()
            && store
                .incompleteness()
                .contains(&SymbolIncompleteness::NoObjectSymbolTable),
        "the missing object symbol table is a declared incompleteness, got {:?}",
        store.incompleteness()
    );
    for record in store.records() {
        let selected = record.selected().expect("every record has a state");
        assert!(
            !matches!(selected.definition, SymbolDefinition::Defined { .. }),
            "the stripped dynamic table defines nothing, but {} claims {:?}",
            record.linkage_name(),
            selected.definition
        );
        assert!(selected
            .evidence()
            .iter()
            .all(|evidence| evidence.source != SymbolSource::ObjectSymbolTable));
    }
}

/// Negative control: two translation units may legally define distinct local
/// symbols with the same spelling. Both must survive as an explicit conflict.
#[test]
fn same_named_local_symbols_from_different_units_are_retained_as_conflicts() {
    let session = compiled_session(
        &[
            (
                "unit_a.c",
                "static __attribute__((noinline)) int helper(int x) { return x + 1; }\n\
                 __attribute__((noinline)) int use_a(int x) { return helper(x); }\n\
                 int use_b(int);\n\
                 int main(void) { return use_a(1) + use_b(2); }\n",
            ),
            (
                "unit_b.c",
                "static __attribute__((noinline)) int helper(int x) { return x * 3; }\n\
                 __attribute__((noinline)) int use_b(int x) { return helper(x); }\n",
            ),
        ],
        &["-O0"],
    );
    let store = session.symbol_store();
    assert!(store.verify().is_empty(), "{:?}", store.verify());

    let id = store.symbol_by_linkage("helper").expect("local symbol");
    let record = store.get(id).expect("record");
    assert!(
        record
            .conflicts()
            .contains(&SymbolConflict::IncompatibleDefinition),
        "two local definitions of one name are a retained conflict"
    );
    let mut addresses = record
        .selected()
        .into_iter()
        .chain(record.alternatives())
        .filter_map(|fact| match fact.definition {
            SymbolDefinition::Defined { address, .. } => Some(address),
            _ => None,
        })
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    assert_eq!(
        addresses.len(),
        2,
        "both real definitions must be retained, got {addresses:?}"
    );
    for address in addresses {
        assert!(
            matches!(store.resolve_address(address), AddressSymbol::Exact { ref symbols } if symbols.contains(&id)),
            "each retained definition stays addressable at {address:#x}"
        );
    }
    assert_eq!(
        record.selected().map(|fact| fact.binding),
        Some(SymbolBinding::Local),
        "a static function keeps its local binding"
    );
}

#[test]
fn real_portable_executable_imports_and_exports_carry_their_module() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let executable = root.join(
        "samples/binaries/platforms/windows/i386/export/windows/i686/O0/hello-c-mingw32-O0.exe",
    );
    let session = ProgramSession::from_path(&executable).expect("checked-in PE image");
    let store = session.symbol_store();
    assert!(store.verify().is_empty(), "{:?}", store.verify());

    let imports = store
        .records()
        .iter()
        .filter(|record| {
            record.selected().is_some_and(|fact| {
                fact.evidence()
                    .iter()
                    .any(|evidence| evidence.source == SymbolSource::ImportTable)
            })
        })
        .collect::<Vec<_>>();
    assert!(!imports.is_empty(), "a real PE declares imports");
    for record in imports {
        let selected = record.selected().expect("checked");
        assert_eq!(
            selected.definition,
            SymbolDefinition::Undefined,
            "{} is imported and therefore undefined here",
            record.linkage_name()
        );
        assert!(
            selected.evidence().iter().any(|evidence| {
                evidence.source == SymbolSource::ImportTable
                    && evidence
                        .module
                        .as_deref()
                        .is_some_and(|module| module.to_ascii_lowercase().ends_with(".dll"))
            }),
            "{} must name the DLL it comes from, got {:?}",
            record.linkage_name(),
            selected.evidence()
        );
    }
}

#[test]
fn real_portable_executable_exports_resolve_by_address() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let library =
        root.join("samples/binaries/platforms/windows/vendor/realworld/win10-dismapi.dll");
    let session = ProgramSession::from_path(&library).expect("checked-in PE library");
    let store = session.symbol_store();
    assert!(store.verify().is_empty(), "{:?}", store.verify());

    let exported = store
        .records()
        .iter()
        .filter(|record| {
            record.selected().is_some_and(|fact| {
                fact.evidence()
                    .iter()
                    .any(|evidence| evidence.source == SymbolSource::ExportTable)
            })
        })
        .collect::<Vec<_>>();
    assert!(!exported.is_empty(), "a real DLL declares exports");
    for record in exported {
        let SymbolDefinition::Defined { address, .. } =
            record.selected().expect("checked").definition
        else {
            panic!("{} is exported and must be defined", record.linkage_name());
        };
        assert!(
            matches!(store.resolve_address(address), AddressSymbol::Exact { ref symbols } if symbols.contains(&record.id)),
            "the export at {address:#x} resolves to its own identity"
        );
    }
}

#[test]
fn real_mangled_symbols_carry_a_demangled_alias_with_its_scheme() {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let source = directory.path().join("mangled.cpp");
    let executable = directory.path().join("mangled");
    std::fs::write(
        &source,
        "namespace glaurung {\n\
         __attribute__((noinline)) int add(int a, int b) { return a + b; }\n\
         }\n\
         int main() { return glaurung::add(1, 2); }\n",
    )
    .expect("write real C++ fixture");
    let output = std::process::Command::new("c++")
        .args(["-O0", "-o"])
        .arg(&executable)
        .arg(&source)
        .output()
        .expect("host C++ compiler is available");
    assert!(
        output.status.success(),
        "compile real C++ fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let session = ProgramSession::from_path(&executable).expect("fixture is a real object");
    let store = session.symbol_store();
    assert!(store.verify().is_empty(), "{:?}", store.verify());

    let id = store
        .symbol_by_linkage("_ZN8glaurung3addEii")
        .expect("the mangled linkage name is the identity");
    let record = store.get(id).expect("record");
    let demangled = record
        .names()
        .find(|name| {
            matches!(
                name.form,
                crate::program::symbols::NameForm::Demangled(
                    crate::program::symbols::DemangleScheme::Itanium
                )
            )
        })
        .expect("an itanium alias with its scheme");
    assert_eq!(demangled.text, "glaurung::add(int, int)");
    assert_eq!(demangled.match_kind, NameMatch::Exact);
    assert_eq!(store.symbols_named(&demangled.text), &[id]);
    assert!(
        store.symbol_by_linkage(&demangled.text).is_none(),
        "a demangled spelling is an alias, never the linkage identity"
    );
}

/// A real, checked-in binary with a PLT, DWARF, `.eh_frame`, and enough
/// functions that a per-function parse would show up as an obvious multiple.
fn parse_budget_sample() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("samples/binaries/platforms/linux/amd64/export/native/gcc/O2/hello-gcc-O2")
}

fn parse_budget_budgets(max_functions: usize) -> Budgets {
    Budgets {
        max_functions,
        max_blocks: 4_096,
        max_instructions: 200_000,
        timeout_ms: 10_000,
        total_timeout_ms: 0,
    }
}

/// Indexing an image is EXACTLY one parse.
///
/// `.eh_frame` function extents used to be recovered by reopening the file the
/// constructor had already opened, so the single-owner claim in this module's
/// documentation cost two parses to make.
#[test]
fn indexing_one_image_parses_the_object_exactly_once() {
    let bytes = std::fs::read(parse_budget_sample()).expect("read the checked-in sample");
    let (image, parses) = crate::decompile::profile::count_object_parses(|| {
        crate::program::image::ProgramImage::from_bytes(bytes).expect("index a real ELF")
    });

    assert_eq!(
        parses, 1,
        "ProgramImage must own the only parse of its bytes"
    );
    assert!(!image.plt_stub_ranges().is_empty(), "sample has a PLT");
    assert!(
        !image.eh_frame_functions().is_empty(),
        "sample has .eh_frame FDEs"
    );
}

/// Whole-binary discovery must not parse the object once per function.
///
/// This is the invariant, not the absolute number: PLT-stub membership,
/// no-return import contracts, exception sites, and DWARF overrides were each
/// answered by reopening the object at a per-function or per-branch site, so a
/// 49-function binary cost 58 parses and a 1146-function one cost 40865. If any
/// of those regresses to a per-function parse, the two counts below diverge.
#[test]
fn discovery_parse_count_does_not_scale_with_the_number_of_functions() {
    let session = ProgramSession::from_path(&parse_budget_sample()).expect("index a real ELF");
    // Warm the image's lazily recovered program-level indices so the comparison
    // measures the discovery walk rather than one-off session setup.
    let _ = crate::decompile::profile::count_object_parses(|| {
        session.discover_functions(&parse_budget_budgets(1), &[])
    });

    let (few, few_parses) = crate::decompile::profile::count_object_parses(|| {
        session.discover_functions(&parse_budget_budgets(4), &[])
    });
    let (many, many_parses) = crate::decompile::profile::count_object_parses(|| {
        session.discover_functions(&parse_budget_budgets(4_096), &[])
    });

    assert!(
        many.len() >= few.len().saturating_mul(4),
        "the wide run must do materially more work: {} vs {}",
        many.len(),
        few.len()
    );
    assert_eq!(
        few_parses,
        many_parses,
        "object parses scaled with function count: {} functions cost {} parses, \
         {} functions cost {}",
        few.len(),
        few_parses,
        many.len(),
        many_parses
    );
    assert!(
        many_parses <= 8,
        "one whole-binary discovery took {many_parses} object parses"
    );
}

/// Address-scoped discovery reuses the session image and parses nothing.
///
/// Recovering one direct callee's contract used to cost four parses — the
/// no-return import tables, the PLT section table, and the jump-table decoder —
/// and a single `decompile_all` runs this path hundreds of times.
#[test]
fn address_scoped_discovery_reuses_the_session_image() {
    let session = ProgramSession::from_path(&parse_budget_sample()).expect("index a real ELF");
    let functions = session.discover_functions(&parse_budget_budgets(4_096), &[]);
    let entries: Vec<u64> = functions
        .iter()
        .take(8)
        .map(|function| function.entry_point.value)
        .collect();
    assert!(entries.len() >= 4, "sample yields several functions");

    let (recovered, parses) = crate::decompile::profile::count_object_parses(|| {
        entries
            .iter()
            .filter(|entry| {
                crate::analysis::cfg::discover_function_image_at(
                    session.image(),
                    &parse_budget_budgets(1),
                    **entry,
                )
                .is_some()
            })
            .count()
    });

    assert!(recovered > 0, "at least one entry re-discovers");
    assert_eq!(
        parses, 0,
        "{recovered} address-scoped discoveries reopened the object {parses} times"
    );
}
