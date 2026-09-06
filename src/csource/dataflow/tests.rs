//! Tests for the reaching-definitions analysis.
//!
//! Each of the corpus assertions at the end is a bound that a real
//! over-report tripped during development, kept so the same class of mistake
//! fails here rather than shipping as a plausible-looking number.

use super::*;
use std::collections::BTreeMap;

fn one(text: &str) -> DataFlow {
analyze(text).into_parts().0.into_iter().next().unwrap()
}

fn edge_names(flow: &DataFlow) -> Vec<String> {
let mut names: Vec<String> = flow.edges.iter().map(|e| e.name.clone()).collect();
names.sort();
names.dedup();
names
}

#[test]
fn a_definition_reaches_the_use_after_it() {
let flow = one("int f(void) { int x = 1; return x; }");
assert_eq!(edge_names(&flow), vec!["x"]);
assert_eq!(flow.edges.len(), 1);
let definition = &flow.definitions[flow.edges[0].def as usize];
assert_eq!(definition.kind, DefKind::Declaration);
}

#[test]
fn a_later_assignment_kills_an_earlier_one() {
let flow = one("int f(void) { int x = 1; x = 2; return x; }");
// Only the second write reaches the return.
assert_eq!(flow.edges.len(), 1, "{:?}", flow.edges);
let definition = &flow.definitions[flow.edges[0].def as usize];
assert_eq!(definition.kind, DefKind::Assignment);
}

#[test]
fn both_arms_of_a_branch_reach_the_join() {
let flow = one("int f(int c) { int x = 0; if (c) { x = 1; } else { x = 2; } return x; }");
let reaching: Vec<&Definition> = flow
    .definitions_reaching(
        flow.uses
            .iter()
            .position(|u| u.name == "x")
            .and_then(|_| {
                flow.uses
                    .iter()
                    .enumerate()
                    .filter(|(_, u)| u.name == "x")
                    .map(|(i, _)| i as u32)
                    .next_back()
            })
            .expect("a use of x"),
    )
    .collect();
// The two arms reach; the initializer does not, both arms kill it.
assert_eq!(reaching.len(), 2, "{reaching:?}");
assert!(reaching.iter().all(|d| d.kind == DefKind::Assignment));
}

#[test]
fn a_loop_carries_a_definition_backwards() {
// `sum` is read on an iteration that a later write reaches, which only
// a fixpoint over the back edge finds.
let flow = one("int f(int n) { int sum = 0; for (int i = 0; i < n; i++) { sum = sum + i; } return sum; }");
let sum_uses: Vec<u32> = flow
    .uses
    .iter()
    .enumerate()
    .filter(|(_, u)| u.name == "sum")
    .map(|(i, _)| i as u32)
    .collect();
assert!(!sum_uses.is_empty());
// The read inside the loop sees both the initializer and the loop's
// own write.
let inside = sum_uses[0];
let kinds: Vec<DefKind> = flow.definitions_reaching(inside).map(|d| d.kind).collect();
assert!(kinds.contains(&DefKind::Declaration), "{kinds:?}");
assert!(kinds.contains(&DefKind::Assignment), "{kinds:?}");
}

#[test]
fn a_parameter_is_a_definition_at_the_entry() {
let flow = one("int f(int a) { return a; }");
assert_eq!(flow.edges.len(), 1);
let definition = &flow.definitions[flow.edges[0].def as usize];
assert_eq!(definition.kind, DefKind::Parameter);
assert_eq!(definition.name, "a");
}

#[test]
fn a_shadowed_declaration_is_a_different_variable() {
// The inner `x` must not be confused with the outer one: the return
// sees the outer write, and the inner write reaches nothing.
let flow = one("int f(void) { int x = 1; { int x = 2; (void)x; } return x; }");
let outer_return = flow
    .uses
    .iter()
    .enumerate()
    .filter(|(_, u)| u.name == "x")
    .map(|(i, _)| i as u32)
    .next_back()
    .expect("a use of x");
let reaching: Vec<&Definition> = flow.definitions_reaching(outer_return).collect();
assert_eq!(reaching.len(), 1, "{reaching:?}");
// The one that reaches is the OUTER declaration, at the lower offset.
assert!(reaching[0].span.lo < 30, "{:?}", reaching[0]);
}

#[test]
fn a_compound_assignment_both_reads_and_writes() {
let flow = one("int f(int a) { int x = 1; x += a; return x; }");
let kinds: Vec<DefKind> = flow.definitions.iter().map(|d| d.kind).collect();
assert!(kinds.contains(&DefKind::CompoundAssignment), "{kinds:?}");
// `x` is still read by the `+=` itself.
assert!(flow.uses.iter().filter(|u| u.name == "x").count() >= 2);
}

#[test]
fn an_increment_both_reads_and_writes() {
let flow = one("int f(void) { int i = 0; i++; return i; }");
let kinds: Vec<DefKind> = flow.definitions.iter().map(|d| d.kind).collect();
assert!(kinds.contains(&DefKind::IncDec), "{kinds:?}");
}

#[test]
fn a_read_before_any_write_is_reported_unresolved() {
// `g` is a global: nothing in this function defines it.
let flow = one("int f(void) { return g; }");
assert_eq!(flow.unresolved_uses.len(), 1, "{:?}", flow.uses);
assert_eq!(flow.uses[flow.unresolved_uses[0] as usize].name, "g");
}

#[test]
fn a_store_through_a_pointer_does_not_kill() {
// Nothing here knows what `p` points at, so the write to `x` before it
// must still reach the read after it. Over-approximating is the safe
// direction and this pins it.
let flow = one("int f(int *p) { int x = 1; *p = 2; return x; }");
let read = flow
    .uses
    .iter()
    .enumerate()
    .filter(|(_, u)| u.name == "x")
    .map(|(i, _)| i as u32)
    .next_back()
    .expect("a use of x");
assert_eq!(flow.definitions_reaching(read).count(), 1);
}

#[test]
fn analysis_is_total_on_input_that_is_not_c() {
for junk in ["", "\u{0}\u{1}", "int f(", "}}}", "\u{4e2d}\u{6587}"] {
    let flows = analyze(junk).into_parts().0;
    for flow in &flows {
        assert!(flow.edges.len() <= flow.definitions.len() * flow.uses.len() + 1);
    }
}
}

#[test]
fn output_is_deterministic() {
let text = "int f(int n) { int s = 0; for (int i = 0; i < n; i++) { s += i; } return s; }";
assert_eq!(one(text), one(text));
}

#[test]
fn a_store_nothing_reads_is_dead() {
let flow = one("int f(void) { int x = 1; x = 2; return 0; }");
// Both writes of `x` are dead: nothing reads it.
assert_eq!(flow.dead_stores.len(), 2, "{:?}", flow.definitions);
}

#[test]
fn a_store_something_reads_is_not_dead() {
let flow = one("int f(void) { int x = 1; return x; }");
assert!(flow.dead_stores.is_empty(), "{:?}", flow.dead_stores);
}

#[test]
fn an_overwritten_store_is_dead_and_the_survivor_is_not() {
let flow = one("int f(void) { int x = 1; x = 2; return x; }");
assert_eq!(flow.dead_stores.len(), 1);
let dead = &flow.definitions[flow.dead_stores[0] as usize];
assert_eq!(dead.kind, DefKind::Declaration, "the first write is the dead one");
}

#[test]
fn an_unread_parameter_is_not_a_dead_store() {
let flow = one("int f(int unused) { return 0; }");
assert!(flow.dead_stores.is_empty(), "{:?}", flow.dead_stores);
}

#[test]
fn a_decompiler_temporary_that_is_never_read_is_reported() {
// The shape a decompiler actually emits: a named slot assigned from a
// call and then ignored.
let flow = one("int f(int a) { int v1; v1 = g(a); return a; }");
let dead: Vec<&str> = flow
    .dead_stores
    .iter()
    .map(|i| flow.definitions[*i as usize].name.as_str())
    .collect();
assert!(dead.contains(&"v1"), "{dead:?}");
}

#[test]
fn the_fixture_corpus_analyzes_without_a_contradiction() {
let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    .join("tests/decompiler_fixtures/src");
let Ok(entries) = std::fs::read_dir(&root) else {
    return; // corpus absent in a source-only checkout
};
let mut files = 0usize;
let mut functions = 0usize;
let mut edges = 0usize;
let mut dead = 0usize;
let mut unresolved = 0usize;

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
        functions += 1;
        edges += flow.edges.len();
        dead += flow.dead_stores.len();
        unresolved += flow.unresolved_uses.len();

        for edge in &flow.edges {
            let definition = flow
                .definitions
                .get(edge.def as usize)
                .expect("edge names a real definition");
            let use_ = flow.uses.get(edge.use_ as usize).expect("edge names a real use");
            // An edge is about one variable, and both ends agree.
            assert_eq!(definition.binding, use_.binding, "{}", flow.name);
            assert_eq!(edge.name, use_.name, "{}", flow.name);
        }
        // The two defect sets are disjoint from what they describe: a
        // use is unresolved exactly when no edge enters it.
        for index in &flow.unresolved_uses {
            assert!(
                !flow.edges.iter().any(|e| e.use_ == *index),
                "{}: use {} is both reached and unresolved",
                flow.name,
                index
            );
        }
        for index in &flow.dead_stores {
            assert!(
                !flow.edges.iter().any(|e| e.def == *index),
                "{}: definition {} is both read and dead",
                flow.name,
                index
            );
        }
    }
}

assert!(files > 100, "corpus not found: {files} files");
assert!(functions > 500, "only {functions} functions");
assert!(edges > 1000, "only {edges} edges over {functions} functions");

// Hand-written C should barely have any dead stores. This bound is
// deliberately loose --- the corpus grows --- but it is tight enough
// to fail if a change starts calling ordinary code dead. Each round of
// over-reporting this analysis went through tripped exactly here:
// 897 when a bare `int x;` counted as a store, 460 when a write to a
// global counted, 27 when `++a[i]` counted as a write to `a`.
assert!(
    dead * 20 < functions,
    "{dead} dead stores over {functions} hand-written functions is too many \
     to be real; something is counting a non-store as a store"
);
assert!(unresolved < functions * 3, "{unresolved} unresolved uses");
eprintln!(
    "corpus: {files} files, {functions} functions, {edges} edges, \
     {dead} dead stores, {unresolved} unresolved uses"
);
}

// --- declared types ---------------------------------------------------------

/// The declared type of the binding named `name`.
fn type_of(flow: &DataFlow, name: &str) -> Option<CType> {
    flow.type_of(flow.binding_named(name)?).cloned()
}

#[test]
fn a_local_carries_the_type_it_was_declared_with() {
    let flow = one("int f(void) { unsigned long total = 0; return (int)total; }");
    let ty = type_of(&flow, "total").expect("a type for total");
    assert_eq!(ty.specifiers, "unsigned long");
    assert_eq!(ty.pointer_depth, 0);
    assert_eq!(ty.render(), "unsigned long");
}

#[test]
fn a_parameter_carries_its_type_including_pointer_depth() {
    let flow = one("int f(const char *name, int n) { return n; }");
    let name = type_of(&flow, "name").expect("a type for name");
    assert_eq!(name.specifiers, "const char");
    assert_eq!(name.pointer_depth, 1);
    assert!(name.is_const);
    let n = type_of(&flow, "n").expect("a type for n");
    assert_eq!(n.specifiers, "int");
    assert_eq!(n.pointer_depth, 0);
}

#[test]
fn one_declaration_of_several_names_gives_each_its_own_shape() {
    // The specifiers apply to all three; the stars and brackets do not.
    let flow = one("int f(void) { int a = 1, *b, c[4]; return a; }");
    let a = type_of(&flow, "a").expect("a");
    let b = type_of(&flow, "b").expect("b");
    let c = type_of(&flow, "c").expect("c");
    assert_eq!((a.specifiers.as_str(), a.pointer_depth, a.array_rank), ("int", 0, 0));
    assert_eq!((b.specifiers.as_str(), b.pointer_depth, b.array_rank), ("int", 1, 0));
    assert_eq!((c.specifiers.as_str(), c.pointer_depth, c.array_rank), ("int", 0, 1));
}

#[test]
fn a_struct_tag_is_recorded_as_written() {
    let flow = one("int f(void) { struct point *p; return (int)(long)p; }");
    let ty = type_of(&flow, "p").expect("a type for p");
    assert_eq!(ty.specifiers, "struct point");
    assert_eq!(ty.pointer_depth, 1);
    assert_eq!(ty.render(), "struct point *");
}

#[test]
fn a_typedef_from_a_header_stays_an_opaque_name() {
    // No `#include` resolution, so `uint32_t` is a name and nothing claims to
    // know its width. Recording the spelling is the honest answer.
    let flow = one("int f(void) { uint32_t n = 0; return (int)n; }");
    let ty = type_of(&flow, "n").expect("a type for n");
    assert_eq!(ty.specifiers, "uint32_t");
}

#[test]
fn qualifiers_are_flagged_and_ignored_when_comparing_shape() {
    let flow = one("int f(void) { const volatile int a = 1; int b = 2; return a + b; }");
    let a = type_of(&flow, "a").expect("a");
    let b = type_of(&flow, "b").expect("b");
    assert!(a.is_const && a.is_volatile);
    assert!(!b.is_const && !b.is_volatile);
    assert!(a.same_shape(&b), "const int and int are the same shape");
}

#[test]
fn two_spellings_we_cannot_resolve_are_reported_as_different() {
    // Without `#include`, `uint32_t` and `unsigned int` are two opaque names.
    // Saying they differ is honest; guessing they match would not be.
    let flow = one("int f(void) { uint32_t a = 0; unsigned int b = 0; return (int)(a + b); }");
    let a = type_of(&flow, "a").expect("a");
    let b = type_of(&flow, "b").expect("b");
    assert!(!a.same_shape(&b));
}

#[test]
fn a_multidimensional_array_counts_every_rank() {
    let flow = one("int f(void) { int m[4][4]; return m[0][0]; }");
    let ty = type_of(&flow, "m").expect("m");
    assert_eq!(ty.array_rank, 2, "{ty:?}");
}

#[test]
fn a_declaration_without_an_initializer_still_has_a_type() {
    // `int x;` writes nothing -- it is not a definition -- but it is a binding
    // and it has a type. The two facts are independent.
    let flow = one("int f(int n) { unsigned long slot; slot = (unsigned long)n; return (int)slot; }");
    let binding = flow
        .definitions
        .iter()
        .find(|d| d.name == "slot")
        .map(|d| d.binding)
        .expect("a binding for slot");
    let ty = flow.type_of(binding).expect("a type for slot");
    assert_eq!(ty.specifiers, "unsigned long");
}

#[test]
fn well_typed_source_has_no_type_conflicts() {
    let flow = one("int f(int n) { int a = n; int b = a; return b; }");
    assert!(flow.type_conflicts().is_empty(), "{:?}", flow.type_conflicts());
}

#[test]
fn a_free_binding_has_no_type() {
    // A global's type is not knowable from one translation unit.
    let flow = one("int f(void) { return g; }");
    assert!(flow.type_of(Binding::FREE).is_none());
}

#[test]
fn type_recovery_is_deterministic() {
    let text = "int f(const char *s, int n) { unsigned long t = 0; return (int)t; }";
    assert_eq!(one(text).types, one(text).types);
}


#[test]
fn a_declared_name_is_reachable_even_when_nothing_mentions_it_again() {
    // `int *b;` writes nothing and reads nothing, so it is in neither the
    // definition list nor the use list. Without the binding-name table there
    // is no way to ask about it at all, and an unused local is unreportable.
    let flow = one("int f(void) { int a = 1, *b, c[4]; return a; }");
    let binding = flow.binding_named("b").expect("a binding for b");
    let ty = flow.type_of(binding).expect("a type for b");
    assert_eq!((ty.specifiers.as_str(), ty.pointer_depth), ("int", 1));
}

#[test]
fn an_unused_local_is_reported_and_a_parameter_is_not() {
    let flow = one("int f(int unused_param) { int unused_local; return 0; }");
    let unused: Vec<&str> = flow
        .unused_bindings()
        .iter()
        .filter_map(|b| flow.names.get(b.0 as usize).map(|s| s.as_str()))
        .collect();
    assert_eq!(unused, vec!["unused_local"], "{unused:?}");
}

#[test]
fn the_corpus_recovers_a_type_for_almost_every_binding() {
    // The gate the plan states: every binding resolves to a specifier or is
    // explicitly empty, and the empty count is reported rather than assumed.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/decompiler_fixtures/src");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    let mut bindings = 0usize;
    let mut typed = 0usize;
    let mut conflicts = 0usize;
    let mut unused = 0usize;
    let mut untyped_examples: Vec<String> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("c") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for flow in analyze(&text).into_parts().0 {
            // The three tables are one row per binding and must agree.
            assert_eq!(flow.names.len(), flow.types.len(), "{}", flow.name);
            bindings += flow.names.len();
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
            unused += flow.unused_bindings().len();
        }
    }

    assert!(bindings > 1000, "only {bindings} bindings");
    let rate = typed as f64 / bindings as f64;
    eprintln!(
        "corpus types: {typed}/{bindings} = {:.1}%  conflicts={conflicts}  unused={unused}",
        rate * 100.0
    );
    if !untyped_examples.is_empty() {
        eprintln!("  untyped examples: {untyped_examples:?}");
    }
    // Hand-written C declares a type for everything it binds. A rate below
    // this means the reader is losing declarations, not that the corpus is
    // untyped.
    assert!(rate > 0.95, "only {:.1}% of bindings carry a type", rate * 100.0);
    // Well-typed source cannot contain a type conflict: a C compiler would
    // have rejected it. Any is a bug in the reader.
    assert_eq!(conflicts, 0, "type conflicts in hand-written C");
    // And hand-written C declares nothing it does not use, which is what makes
    // the same count meaningful on a decompiler's output.
    assert_eq!(unused, 0, "unused bindings in hand-written C");
}

