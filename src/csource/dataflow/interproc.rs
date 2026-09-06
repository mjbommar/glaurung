//! Dependence that crosses a call, by summary rather than by inlining.
//!
//! The intraprocedural analysis in [`super::solve`] stops at the call: a call
//! reads its arguments and defines nothing. That is safe and it is also the
//! reason `reaches(source, sink)` --- the query a code property graph is
//! actually used for --- cannot be asked. This module answers it.
//!
//! # Summaries, not inlining
//!
//! For each function, compute once which parameters flow to the return value
//! and which flow to which other parameter. A caller then *applies* the
//! summary instead of re-analysing the callee.
//!
//! Inlining is easier to write and does not terminate on recursion. Summaries
//! do, because the lattice is finite --- a summary is a set of (parameter,
//! destination) pairs and there are finitely many --- so iterating over the
//! call graph to a fixed point converges. `f` calling `g` calling `f` costs
//! one extra round, not an infinite descent.
//!
//! # Where this refuses, and why refusing is the point
//!
//! Three cases produce [`Flow::Unknown`] rather than a yes or a no:
//!
//! * **An indirect call.** `p(x)` names no callee, and
//!   [`super::super::metrics`]'s call graph deliberately contributes no edge
//!   for one. A summary cannot be applied to a function that was not named.
//! * **A callee this unit does not define.** `memcpy(dst, src, n)` is an edge
//!   to a name whose body is elsewhere. What it does with its arguments is not
//!   knowable from one translation unit, and guessing "it propagates" or "it
//!   does not" would be a claim rather than an analysis. A curated table of
//!   libc effects is the obvious next increment and deliberately not smuggled
//!   in here.
//! * **A recursion depth or work bound exceeded.** Bounded rather than
//!   unbounded, so a pathological call graph costs an `Unknown` and not a
//!   hang.
//!
//! A caller that treats `Unknown` as `No` gets an unsound answer; the type
//! exists so that mistake has to be written down.

use std::collections::BTreeMap;

use super::model::Binding;
use super::DataFlow;

/// Whether a value reaches somewhere.
///
/// Three-valued on purpose. A reachability analysis that answers only yes or
/// no has to lie about the cases it cannot see, and on decompiler output ---
/// full of indirect calls and functions whose bodies are elsewhere --- those
/// are not rare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flow {
    /// A path was found.
    Yes,
    /// No path exists, and every step of the search was decidable.
    No,
    /// The search met something it could not resolve: an indirect call, a
    /// callee defined elsewhere, or a bound.
    Unknown,
}

impl Flow {
    /// This verdict's stable name, for a serialized field.
    pub const fn name(self) -> &'static str {
        match self {
            Flow::Yes => "yes",
            Flow::No => "no",
            Flow::Unknown => "unknown",
        }
    }

    /// The weaker of two verdicts, for combining independent searches.
    ///
    /// `Yes` wins over everything --- one path is enough. `Unknown` beats `No`,
    /// because a search that could not see everywhere has not proven absence.
    pub fn or(self, other: Flow) -> Flow {
        match (self, other) {
            (Flow::Yes, _) | (_, Flow::Yes) => Flow::Yes,
            (Flow::Unknown, _) | (_, Flow::Unknown) => Flow::Unknown,
            _ => Flow::No,
        }
    }
}

/// Where a value that entered a function can end up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sink {
    /// The function's return value.
    Return,
    /// Through the pointer passed as parameter `n`, which the callee may write.
    Parameter(u32),
}

/// What one function does with the values passed to it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summary {
    /// The function's name.
    pub name: String,
    /// How many parameters it declares.
    pub parameters: u32,
    /// `(parameter index, sink)` pairs: this parameter's value can reach that
    /// sink.
    pub flows: Vec<(u32, Sink)>,
    /// Whether the body contained something this analysis could not resolve,
    /// so a caller applying this summary inherits an `Unknown` rather than a
    /// clean `No`.
    pub complete: bool,
}

impl Summary {
    /// Whether parameter `index` reaches `sink`.
    pub fn flows_to(&self, index: u32, sink: Sink) -> bool {
        self.flows.contains(&(index, sink))
    }
}

/// Every function's summary, keyed by name, at a fixed point.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summaries {
    by_name: BTreeMap<String, Summary>,
}

impl Summaries {
    /// The summary of `name`, when this unit defines it.
    pub fn get(&self, name: &str) -> Option<&Summary> {
        self.by_name.get(name)
    }

    /// Every summary, in name order.
    pub fn iter(&self) -> impl Iterator<Item = &Summary> {
        self.by_name.values()
    }

    /// How many functions are summarized.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether nothing was summarized.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }
}

/// The most rounds the fixed point may take.
///
/// A summary only ever grows --- a flow is added, never removed --- so the
/// iteration is monotone over a finite lattice and terminates on its own. This
/// bounds the pathological case rather than the normal one, and a run that hits
/// it marks every summary incomplete rather than reporting a clean answer from
/// a half-finished analysis.
const MAX_ROUNDS: usize = 16;

/// Compute a summary for every function in `flows`, to a fixed point.
///
/// `flows` is the per-function analysis [`super::analyze`] already produced;
/// this adds nothing to it and only reads.
pub fn summarize(flows: &[DataFlow]) -> Summaries {
    let mut by_name: BTreeMap<String, Summary> = BTreeMap::new();
    for flow in flows {
        by_name.insert(
            flow.name.clone(),
            Summary {
                name: flow.name.clone(),
                parameters: parameter_count(flow),
                flows: Vec::new(),
                complete: true,
            },
        );
    }

    let mut rounds = 0usize;
    loop {
        rounds += 1;
        let mut changed = false;
        for flow in flows {
            let (found, complete) = local_flows(flow, &by_name);
            let Some(summary) = by_name.get_mut(&flow.name) else {
                continue;
            };
            for pair in found {
                if !summary.flows.contains(&pair) {
                    summary.flows.push(pair);
                    changed = true;
                }
            }
            if summary.complete != complete {
                summary.complete = complete;
                changed = true;
            }
        }
        if !changed {
            break;
        }
        if rounds >= MAX_ROUNDS {
            // Did not converge in the bound. Every summary becomes incomplete,
            // so a caller gets `Unknown` rather than a confident answer from a
            // half-finished fixed point.
            for summary in by_name.values_mut() {
                summary.complete = false;
            }
            break;
        }
    }

    for summary in by_name.values_mut() {
        summary.flows.sort_unstable();
        summary.flows.dedup();
    }
    Summaries { by_name }
}

/// How many parameters `flow`'s function declares.
fn parameter_count(flow: &DataFlow) -> u32 {
    flow.definitions
        .iter()
        .filter(|definition| definition.kind == super::DefKind::Parameter)
        .count() as u32
}

/// One round of a function's own flows, given the summaries so far.
///
/// Returns the pairs found and whether the body was fully resolvable.
///
/// The call-site rule is what makes this interprocedural. A parameter reaching
/// an argument of `g(...)` propagates **only as far as `g`'s own summary says
/// it does**: to this function's return if `g` returns it and the result is
/// returned here, and nowhere if `g` drops it. An earlier version had no
/// call-site rule at all and reported a flow whenever a parameter was read
/// anywhere before a return, which made `int b(int y) { return a(y); }` flow
/// even when `a` returns a constant --- an answer that is right by accident and
/// wrong in general.
fn local_flows(flow: &DataFlow, known: &BTreeMap<String, Summary>) -> (Vec<(u32, Sink)>, bool) {
    let mut found: Vec<(u32, Sink)> = Vec::new();
    let mut complete = true;

    let call_sites = flow.call_sites();
    for site in &call_sites {
        if site.callee.is_none() {
            // An indirect call: no name, so no summary can be applied.
            complete = false;
        } else if let Some(name) = &site.callee {
            if !known.contains_key(name) {
                // A callee defined elsewhere. What it does with its arguments
                // is not knowable from one translation unit.
                complete = false;
            }
        }
    }

    for index in 0..parameter_count(flow) {
        let Some(parameter) = flow
            .definitions
            .iter()
            .filter(|d| d.kind == super::DefKind::Parameter)
            .nth(index as usize)
        else {
            continue;
        };
        let binding = parameter.binding;

        // Direct: the parameter itself, or a local carrying it, is returned.
        if returns_binding(flow, binding, &call_sites, known) {
            found.push((index, Sink::Return));
        }

        // Escaping: `&p` handed to something means the callee may write
        // through it, so a value here can reach whatever that names.
        if flow
            .definitions
            .iter()
            .any(|d| d.binding == binding && d.kind == super::DefKind::AddressTaken)
        {
            found.push((index, Sink::Parameter(index)));
        }
    }

    found.sort_unstable();
    found.dedup();
    (found, complete)
}

/// Whether a value in `binding` reaches a `return` in this function.
///
/// Two ways it can: read directly by a return, or passed to a call whose
/// summary says that argument reaches the callee's return, where the call's
/// result is itself returned.
fn returns_binding(
    flow: &DataFlow,
    binding: Binding,
    call_sites: &[CallSite],
    known: &BTreeMap<String, Summary>,
) -> bool {
    // Every binding the value can reach without leaving this function.
    let mut reached = reachable_bindings(flow, binding);

    // Then, once per round, extend through calls whose summaries propagate.
    for site in call_sites {
        let Some(name) = &site.callee else { continue };
        let Some(summary) = known.get(name) else {
            continue;
        };
        for (position, argument) in site.arguments.iter().enumerate() {
            if !reached.contains(argument) {
                continue;
            }
            if summary.flows_to(position as u32, Sink::Return) {
                // The call's result carries the value. Anything the result is
                // assigned to now carries it too.
                for target in &site.results {
                    if !reached.contains(target) {
                        reached.push(*target);
                    }
                }
                if site.result_is_returned {
                    return true;
                }
            }
        }
    }

    // A read that is *only* a call argument does not itself reach the return:
    // whether the value gets there is the callee's summary to decide, and the
    // loop above already asked. Without this exclusion `return a(y);` looks
    // like a return of `y` on a node with no write, and every call would
    // propagate regardless of what the callee does with the argument.
    flow.uses.iter().any(|use_| {
        reached.contains(&use_.binding)
            && is_return_node(flow, use_.node)
            && !is_call_argument(call_sites, use_.binding)
    })
}

/// Whether `binding` appears only as an argument to some call.
fn is_call_argument(call_sites: &[CallSite], binding: Binding) -> bool {
    call_sites
        .iter()
        .any(|site| site.arguments.contains(&binding))
}

/// One call in a function body, reduced to what a summary needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    /// The callee's name, or `None` for an indirect call.
    pub callee: Option<String>,
    /// The binding passed at each argument position, in order.
    ///
    /// A position holding an expression rather than a bare name contributes
    /// [`Binding::FREE`], which no real binding equals, so it neither
    /// propagates nor blocks.
    pub arguments: Vec<Binding>,
    /// Bindings the call's result is assigned to.
    pub results: Vec<Binding>,
    /// Whether the call's result is itself returned.
    pub result_is_returned: bool,
}

/// Every binding a value in `seed` can reach without leaving this function.
///
/// Follows data dependence: a read of a tainted binding taints whatever the
/// enclosing statement writes. Node-level granularity, so it
/// over-approximates --- the safe direction, and the same choice the
/// intraprocedural analysis makes about aliasing.
fn reachable_bindings(flow: &DataFlow, seed: Binding) -> Vec<Binding> {
    let mut seen = vec![seed];
    let mut frontier = vec![seed];
    let mut guard = 0usize;
    let bound = flow.edges.len() + flow.definitions.len() + 2;
    while let Some(binding) = frontier.pop() {
        guard += 1;
        if guard > bound {
            break;
        }
        for use_ in &flow.uses {
            if use_.binding != binding {
                continue;
            }
            for candidate in &flow.definitions {
                if candidate.node == use_.node
                    && candidate.effect_at >= use_.span.lo
                    && !seen.contains(&candidate.binding)
                {
                    seen.push(candidate.binding);
                    frontier.push(candidate.binding);
                }
            }
        }
    }
    seen
}

/// Whether CFG node `node` holds no write.
///
/// The dataflow model does not carry node kinds, so a return node is
/// approximated as one nothing writes on. That is why [`Summary::complete`]
/// exists: this is a heuristic and the type says so.
fn is_return_node(flow: &DataFlow, node: u32) -> bool {
    !flow.definitions.iter().any(|d| d.node == node)
}

/// Whether a value in `source`'s parameter `index` can reach `sink`.
///
/// The query a code property graph is used for, answered across calls. Three
/// valued: `Unknown` when the search met an indirect call, a callee this unit
/// does not define, or a bound --- see the module docs on why that is a
/// separate answer from `No`.
pub fn reaches(summaries: &Summaries, source: &str, index: u32, sink: &str) -> Flow {
    let Some(start) = summaries.get(source) else {
        return Flow::Unknown;
    };
    if index >= start.parameters {
        return Flow::No;
    }
    if source == sink {
        return Flow::Yes;
    }

    // Walk the call graph forward from `source`, carrying the fact that this
    // parameter's value is live. Bounded by the number of summaries, so a
    // cycle costs a repeat visit and not a hang.
    let mut seen: Vec<&str> = vec![source];
    let mut frontier: Vec<(&str, u32)> = vec![(source, index)];
    let mut sound = start.complete;

    while let Some((name, position)) = frontier.pop() {
        let Some(summary) = summaries.get(name) else {
            sound = false;
            continue;
        };
        if !summary.complete {
            sound = false;
        }
        if name == sink {
            return Flow::Yes;
        }
        for other in summaries.iter() {
            if seen.contains(&other.name.as_str()) {
                continue;
            }
            // `other` receives this value when it is called with it. Without a
            // call-site record per callee pair this is the conservative
            // reading: any function whose summary propagates position
            // `position` is a candidate.
            if summary.flows_to(position, Sink::Return) && other.parameters > position {
                seen.push(other.name.as_str());
                frontier.push((other.name.as_str(), position));
            }
        }
        if seen.len() > summaries.len() + 1 {
            return Flow::Unknown;
        }
    }

    if sound {
        Flow::No
    } else {
        Flow::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csource::dataflow::analyze;

    fn summaries(text: &str) -> Summaries {
        summarize(&analyze(text).into_parts().0)
    }

    #[test]
    fn every_function_gets_a_summary() {
        let s = summaries("int a(int x) { return x; }\nint b(int y) { return a(y); }");
        assert_eq!(s.len(), 2);
        assert!(s.get("a").is_some() && s.get("b").is_some());
    }

    #[test]
    fn a_summary_records_the_parameter_count() {
        let s = summaries("int f(int a, int b, int c) { return a; }");
        assert_eq!(s.get("f").expect("f").parameters, 3);
    }

    #[test]
    fn a_parameter_returned_directly_flows_to_the_return() {
        let s = summaries("int f(int a, int b) { return a; }");
        let f = s.get("f").expect("f");
        assert!(f.flows_to(0, Sink::Return), "{:?}", f.flows);
    }

    #[test]
    fn a_parameter_returned_through_a_local_still_flows() {
        let s = summaries("int f(int a) { int t = a; return t; }");
        let f = s.get("f").expect("f");
        assert!(f.flows_to(0, Sink::Return), "{:?}", f.flows);
    }

    #[test]
    fn recursion_terminates() {
        // The fixed point must converge rather than descend forever.
        let s = summaries("int f(int n) { if (n > 0) { return f(n - 1); } return n; }");
        assert!(s.get("f").is_some());
    }

    #[test]
    fn mutual_recursion_terminates() {
        let s = summaries(
            "int a(int n) { return b(n); }\nint b(int n) { if (n > 0) { return a(n - 1); } return n; }",
        );
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn summarizing_is_total_on_input_that_is_not_c() {
        for junk in ["", "\u{0}\u{1}", "int f(", "}}}"] {
            let _ = summaries(junk);
        }
    }

    #[test]
    fn summaries_are_deterministic() {
        let text = "int a(int x) { return x; }\nint b(int y) { return a(y) + y; }";
        assert_eq!(summaries(text), summaries(text));
    }

    #[test]
    fn a_flow_verdict_combines_conservatively() {
        assert_eq!(Flow::Yes.or(Flow::No), Flow::Yes);
        assert_eq!(Flow::No.or(Flow::Unknown), Flow::Unknown);
        assert_eq!(Flow::No.or(Flow::No), Flow::No);
        // Unknown must never weaken to No: a search that could not see
        // everywhere has not proven absence.
        assert_eq!(Flow::Unknown.or(Flow::No), Flow::Unknown);
    }
}

#[cfg(test)]
mod negative_tests {
    use super::*;
    use crate::csource::dataflow::analyze;

    fn summaries(text: &str) -> Summaries {
        summarize(&analyze(text).into_parts().0)
    }

    #[test]
    fn a_parameter_that_is_not_returned_does_not_flow_to_the_return() {
        // The test that separates an analysis from a rubber stamp: `b` is
        // never read on any path to the return, so claiming it flows there
        // would make every summary useless.
        let s = summaries("int f(int a, int b) { return a; }");
        let f = s.get("f").expect("f");
        assert!(f.flows_to(0, Sink::Return), "a should flow: {:?}", f.flows);
        assert!(!f.flows_to(1, Sink::Return), "b must not flow: {:?}", f.flows);
    }

    #[test]
    fn an_unused_parameter_flows_nowhere() {
        let s = summaries("int f(int a, int unused) { return a + 1; }");
        let f = s.get("f").expect("f");
        assert!(!f.flows_to(1, Sink::Return), "{:?}", f.flows);
    }

    #[test]
    fn a_constant_return_carries_no_parameter() {
        let s = summaries("int f(int a, int b) { return 0; }");
        let f = s.get("f").expect("f");
        assert!(f.flows.is_empty(), "nothing flows to a constant: {:?}", f.flows);
    }
}

#[cfg(test)]
mod cross_call_tests {
    use super::*;
    use crate::csource::dataflow::analyze;

    fn summaries(text: &str) -> Summaries {
        summarize(&analyze(text).into_parts().0)
    }

    #[test]
    fn a_value_returned_through_a_callee_flows_to_the_caller_return() {
        // The whole point of the module: `b`'s parameter reaches its return
        // only because `a` returns what it is given.
        let s = summaries("int a(int x) { return x; }\nint b(int y) { return a(y); }");
        let b = s.get("b").expect("b");
        assert!(
            b.flows_to(0, Sink::Return),
            "y should reach b's return through a: {:?}",
            b.flows
        );
    }

    #[test]
    fn a_callee_that_drops_its_argument_does_not_propagate() {
        let s = summaries("int a(int x) { return 0; }\nint b(int y) { return a(y); }");
        let b = s.get("b").expect("b");
        assert!(
            !b.flows_to(0, Sink::Return),
            "a returns a constant, so nothing should flow: {:?}",
            b.flows
        );
    }
}


#[cfg(test)]
mod corpus_tests {
    use super::*;
    use crate::csource::dataflow::analyze;

    /// Summarizing 900 real functions must terminate, agree with itself, and
    /// keep every invariant the type promises.
    #[test]
    fn the_fixture_corpus_summarizes_consistently() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/decompiler_fixtures/src");
        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };
        let mut functions = 0usize;
        let mut summarized = 0usize;
        let mut flows = 0usize;
        let mut incomplete = 0usize;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("c") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let analyzed = analyze(&text).into_parts().0;
            functions += analyzed.len();
            let summaries = summarize(&analyzed);
            summarized += summaries.len();
            for summary in summaries.iter() {
                flows += summary.flows.len();
                if !summary.complete {
                    incomplete += 1;
                }
                // Every flow names a parameter this function actually has.
                for (index, sink) in &summary.flows {
                    assert!(
                        *index < summary.parameters,
                        "{}: flow from parameter {index} of {}",
                        summary.name,
                        summary.parameters
                    );
                    if let Sink::Parameter(other) = sink {
                        assert!(
                            *other < summary.parameters,
                            "{}: flow to parameter {other}",
                            summary.name
                        );
                    }
                }
            }
            // Determinism, on real input rather than a two-line fixture.
            assert_eq!(summaries, summarize(&analyzed), "{}", path.display());
        }

        assert!(functions > 500, "only {functions} functions");
        assert_eq!(summarized, functions, "a function lost its summary");
        eprintln!(
            "corpus summaries: {summarized} functions, {flows} parameter flows, \
             {incomplete} incomplete"
        );
    }
}
