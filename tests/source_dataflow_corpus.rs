//! The crate's dataflow over Glaurung's own decompiler fixture corpus.
//!
//! This is the one `csource::dataflow` unit test that did not move to
//! cindergraph with the extraction: it reads `tests/decompiler_fixtures/src`,
//! which is a Glaurung corpus, so it stays here as a test of the dependency
//! against the input Glaurung cares about. Cindergraph carries its own copy of
//! the same gate over its vendored fixtures
//! (`the_corpus_recovers_a_type_for_almost_every_declared_binding`).
//!
//! The corpus is in the repository, so a missing directory is a failure, not
//! a skip: a test that returns early on a bad path passes over nothing.
//!
//! Two things moved when the crate replaced the copy, and both are pinned
//! rather than relaxed. The crate interns *unresolved* identities -- a macro
//! constant such as `LCS_MAX` used as an array bound -- as bindings with an
//! empty type and lists them in `DataFlow::unresolved_bindings`; the copy
//! silently dropped them, so the typed rate is over declared bindings
//! (568 of 4,170 here are unresolved; over all bindings the rate is 86.4%).
//! And a pointer referenced only by `sizeof` is now an unused value binding,
//! which is correct: `sizeof` does not read it.

use cindergraph::dataflow::analyze;

#[test]
fn the_corpus_recovers_a_type_for_almost_every_binding() {
    // The gate the plan states: every binding resolves to a specifier or is
    // explicitly empty, and the empty count is reported rather than assumed.
    let root =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/src");
    let entries = std::fs::read_dir(&root)
        .unwrap_or_else(|err| panic!("{} is the in-tree corpus: {err}", root.display()));
    let mut files = 0usize;
    let mut bindings = 0usize;
    let mut unresolved_bindings = 0usize;
    let mut typed = 0usize;
    let mut conflicts = 0usize;
    let mut unused_names: Vec<String> = Vec::new();
    let mut untyped_examples: Vec<String> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("c") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        files += 1;
        for flow in analyze(&text).into_parts().0 {
            // The three tables are one row per binding and must agree.
            assert_eq!(flow.names.len(), flow.types.len(), "{}", flow.name);
            bindings += flow.names.len();
            unresolved_bindings += flow.unresolved_bindings.len();
            for binding in &flow.unresolved_bindings {
                assert!(flow.types[binding.0 as usize].is_empty(), "{}", flow.name);
            }
            for (index, ty) in flow.types.iter().enumerate() {
                if ty.is_empty() {
                    if untyped_examples.len() < 8 {
                        untyped_examples.push(format!(
                            "{}:{}",
                            flow.name,
                            flow.names.get(index).cloned().unwrap_or_default()
                        ));
                    }
                } else {
                    typed += 1;
                }
            }
            conflicts += flow.type_conflicts().len();
            for binding in flow.unused_bindings() {
                unused_names.push(format!("{}:{}", flow.name, flow.names[binding.0 as usize]));
            }
        }
    }

    assert!(files > 0, "no .c files under {}", root.display());
    assert!(bindings > 1000, "only {bindings} bindings");
    let declared = bindings - unresolved_bindings;
    let rate = typed as f64 / declared as f64;
    eprintln!(
        "corpus types: {typed}/{bindings} total; {unresolved_bindings} unresolved; \
         {typed}/{declared} declared = {:.1}%  conflicts={conflicts}  unused={}",
        rate * 100.0,
        unused_names.len()
    );
    if !untyped_examples.is_empty() {
        eprintln!("  untyped examples: {untyped_examples:?}");
    }
    // Hand-written C declares a type for everything it binds. A rate below
    // this means the reader is losing declarations, not that the corpus is
    // untyped.
    assert!(
        rate > 0.95,
        "only {:.1}% of bindings carry a type",
        rate * 100.0
    );
    // Well-typed source cannot contain a type conflict: a C compiler would
    // have rejected it. Any is a bug in the reader.
    assert_eq!(conflicts, 0, "type conflicts in hand-written C");
    // Hand-written C declares nothing it does not use, which is what makes the
    // same count meaningful on a decompiler's output -- and the one exception
    // is pinned by name: a pointer referenced only by `sizeof`.
    assert_eq!(
        unused_names,
        vec!["sizeof_array_versus_pointer:pointer"],
        "unused value bindings in hand-written C"
    );
}
