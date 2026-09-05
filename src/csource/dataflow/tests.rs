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
