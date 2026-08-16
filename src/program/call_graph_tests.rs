use std::process::Command;

use crate::analysis::cfg::Budgets;
use crate::program::call_graph::{CallTarget, FunctionId, ProgramCallGraph};
use crate::program::session::ProgramSession;

/// Compile one real program and open a session on it.
///
/// Real binaries only: an interprocedural graph over synthesized `Function`
/// values would prove nothing about what discovery actually records.
fn session_for(source_text: &str, name: &str) -> ProgramSession {
    let directory = tempfile::tempdir().expect("temporary fixture directory");
    let source = directory.path().join(format!("{name}.c"));
    let executable = directory.path().join(name);
    std::fs::write(&source, source_text).expect("write real C fixture");
    let output = Command::new("cc")
        .args(["-g", "-O0", "-o"])
        .arg(&executable)
        .arg(&source)
        .output()
        .expect("host C compiler is available");
    assert!(
        output.status.success(),
        "compile fixture {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ProgramSession::from_path(&executable).expect("fixture is a real object")
}

const CHAIN: &str = "\
__attribute__((noinline)) int leaf(int x) { return x + 1; }
__attribute__((noinline)) int middle(int x) { return leaf(x) * 2; }
__attribute__((noinline)) int top(int x) { return middle(x) - 3; }
int main(void) { return top(4); }
";

const MUTUAL: &str = "\
int pong(int x);
__attribute__((noinline)) int ping(int x) { return x <= 0 ? 0 : pong(x - 1); }
__attribute__((noinline)) int pong(int x) { return x <= 0 ? 1 : ping(x - 1); }
int main(void) { return ping(7); }
";

const SELF: &str = "\
__attribute__((noinline)) int down(int x) { return x <= 0 ? 0 : down(x - 1); }
int main(void) { return down(5); }
";

fn id_of(session: &ProgramSession, symbol: &str) -> FunctionId {
    let va = session
        .image()
        .defined_text_symbol_address(symbol)
        .unwrap_or_else(|| panic!("fixture defines {symbol}"));
    FunctionId::new(session.image(), va)
}

#[test]
fn every_discovered_function_is_a_node_including_roots() {
    let session = session_for(CHAIN, "chain");
    let budgets = Budgets::default();
    let functions = session.discover_functions(&budgets, &[]);
    let graph = session.call_graph(&budgets, &[]);

    // The `core::CallGraph` this replaces omits roots from `nodes` entirely,
    // because only callees are ever added. Every discovered function is a node
    // here, so `main` — which calls but is never called — is present.
    assert_eq!(graph.functions().len(), functions.len());
    let main = id_of(&session, "main");
    assert!(
        graph.functions().contains(&main),
        "root function must be a node"
    );
    assert!(graph.component_of(main).is_some());
}

#[test]
fn edges_follow_the_source_call_chain() {
    let session = session_for(CHAIN, "chain");
    let budgets = Budgets::default();
    let graph = session.call_graph(&budgets, &[]);

    let top = id_of(&session, "top");
    let middle = id_of(&session, "middle");
    let leaf = id_of(&session, "leaf");

    assert!(graph
        .known_callees(top)
        .contains(&CallTarget::Internal(middle)));
    assert!(graph
        .known_callees(middle)
        .contains(&CallTarget::Internal(leaf)));

    // Three source calls deep. This is the depth that
    // `recover_direct_callee_definition` cannot reach today: it analyzes one
    // callee plus one grandcallee layer, so `leaf` is invisible from `top`.
    let main = id_of(&session, "main");
    assert!(graph
        .known_callees(main)
        .contains(&CallTarget::Internal(top)));
}

#[test]
fn condensation_orders_callees_before_callers() {
    let session = session_for(CHAIN, "chain");
    let budgets = Budgets::default();
    let graph = session.call_graph(&budgets, &[]);

    let position = |id: FunctionId| {
        graph
            .component_of(id)
            .expect("discovered function has a component")
    };
    // Reverse topological: a callee's component is emitted before its caller's,
    // which is the order a bottom-up monotone propagation must visit.
    assert!(position(id_of(&session, "leaf")) < position(id_of(&session, "middle")));
    assert!(position(id_of(&session, "middle")) < position(id_of(&session, "top")));
    assert!(position(id_of(&session, "top")) < position(id_of(&session, "main")));
}

#[test]
fn mutual_recursion_becomes_one_component() {
    let session = session_for(MUTUAL, "mutual");
    let budgets = Budgets::default();
    let graph = session.call_graph(&budgets, &[]);

    let ping = id_of(&session, "ping");
    let pong = id_of(&session, "pong");
    assert!(
        graph.shares_component(ping, pong),
        "ping/pong must condense into one component"
    );
    assert!(graph.is_recursive(ping));
    assert!(graph.is_recursive(pong));

    let main = id_of(&session, "main");
    assert!(!graph.shares_component(main, ping));
    assert!(!graph.is_recursive(main));
}

#[test]
fn direct_self_recursion_is_recursive_in_a_singleton_component() {
    let session = session_for(SELF, "selfrec");
    let budgets = Budgets::default();
    let graph = session.call_graph(&budgets, &[]);

    let down = id_of(&session, "down");
    assert!(graph.is_recursive(down), "a self-call is a cycle");
    let component = graph.component_of(down).expect("component");
    assert_eq!(
        graph.component_members(component),
        &[down],
        "self recursion is a one-member component"
    );
    assert!(graph.recursive_component_count() >= 1);
}

#[test]
fn the_graph_is_identical_across_repeated_builds() {
    let session = session_for(CHAIN, "chain");
    let budgets = Budgets::default();
    let functions = session.discover_functions(&budgets, &[]);

    // Determinism is load-bearing: `Function::callees` is a `HashSet`, so an
    // edge order taken from hash iteration would make every downstream fact
    // run-dependent. Build the graph repeatedly from the same functions.
    let first = ProgramCallGraph::from_discovered(session.image(), &functions);
    for _ in 0..8 {
        let again = ProgramCallGraph::from_discovered(session.image(), &functions);
        assert_eq!(first, again, "condensation must be deterministic");
    }
}

#[test]
fn the_session_reuses_one_graph_per_discovery_key() {
    let session = session_for(CHAIN, "chain");
    let budgets = Budgets::default();

    let first = session.call_graph(&budgets, &[]);
    let second = session.call_graph(&budgets, &[]);
    assert!(
        std::sync::Arc::ptr_eq(&first, &second),
        "same key must return the same artifact"
    );

    session.clear_caches();
    let third = session.call_graph(&budgets, &[]);
    assert!(
        !std::sync::Arc::ptr_eq(&first, &third),
        "clear_caches must drop the retained graph"
    );
    assert_eq!(*first, *third, "a rebuild must reproduce the same graph");
}

#[test]
fn unanalyzed_call_targets_are_external_not_dropped() {
    let session = session_for(CHAIN, "chain");
    let budgets = Budgets::default();
    let functions = session.discover_functions(&budgets, &[]);
    let middle = id_of(&session, "middle");
    let leaf = id_of(&session, "leaf");

    // Withhold `leaf` from the analyzed set, exactly as a budget cut or an
    // unanalyzed import would. `middle` still calls it, and that call must be
    // classified as an unanalyzed target rather than dropped: otherwise "calls
    // something we did not analyze" is indistinguishable from "calls nothing",
    // and a consumer would read the second as a proven leaf.
    let without_leaf: Vec<_> = functions
        .iter()
        .filter(|function| FunctionId::new(session.image(), function.entry_point.value) != leaf)
        .cloned()
        .collect();
    let graph = ProgramCallGraph::from_discovered(session.image(), &without_leaf);

    assert!(
        !graph.functions().contains(&leaf),
        "leaf was withheld from the analyzed set"
    );
    assert!(
        graph
            .known_callees(middle)
            .contains(&CallTarget::External(leaf.entry_va())),
        "an unanalyzed target must survive as External, not vanish"
    );
    assert!(
        !graph
            .known_callees(middle)
            .contains(&CallTarget::Internal(leaf)),
        "a withheld function must not be claimed as analyzed"
    );
}
