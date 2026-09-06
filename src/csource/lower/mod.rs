//! `S4` --- lowering the S1 C syntax tree to [`LlirFunction`].
//!
//! Plan: `docs/design/static-c-analysis/roadmap.md` section 6. The point of
//! reaching LLIR is that [`crate::exec::interp`] is *the one* interpreter: a
//! front end that produces an `LlirFunction` inherits concrete execution,
//! symbolic execution and every solver behind the `Solver` trait without a line
//! of new engine code. Stage S5 --- bounded equivalence between a source
//! function and its decompilation --- is unreachable without it, and every
//! metric the project has today is structural and therefore blind to the
//! defect classes that matter (`docs/design/metrics-research/`).
//!
//! # What this is not
//!
//! Not a C compiler. The roadmap's scope discipline is quoted verbatim:
//! "Lowering only needs to cover what the fixtures and the corpus contain. It
//! is not a C compiler: no linking, no ABI lowering beyond what `ir::abi`
//! already models, no preprocessor." A construct outside the covered set costs
//! a [`LowerError`] naming it, never a silently wrong lowering --- an
//! approximate answer here would be indistinguishable from a decompiler defect
//! at the point where S5 reports one.
//!
//! # The value representation, stated once
//!
//! Every lowered C value of scalar type `T` lives in a [`VReg::Temp`] holding
//! the value **reduced mod 2^width(T) and then extended to 64 bits according to
//! `T`'s signedness** --- sign-extended when `T` is signed, zero-extended when
//! it is not.
//!
//! This one invariant is what makes the lowering correct on an interpreter that
//! cannot tell it the width of a temporary. [`crate::exec::interp`]'s
//! `op_width` takes the destination register's width and a `Temp` has none, so
//! every `Op::Bin` over temporaries executes at 64 bits whatever the C types
//! were. Rather than fight that, the lowering computes at 64 bits and then
//! *renormalizes* --- `Trunc` to `width(T)`, then `SExt`/`ZExt` back to 64 ---
//! after every operation that can overflow the C type. `int` addition therefore
//! wraps at 32 bits, as C says it does, and a signed comparison of two
//! sign-extended 64-bit values agrees with the same comparison at 32.
//!
//! It also makes conversion trivial and, importantly, *source-type
//! independent*: converting a canonical value to type `C` is `Trunc` to
//! `width(C)` followed by the extension `C`'s signedness asks for, regardless of
//! what type the value had before. That is why a `?:` whose arms have different
//! types can convert once in the join block, after the arms have already
//! written their results.
//!
//! # Block layout
//!
//! `LlirFunction` is addressed by VA because it was built for lifted code.
//! Synthetic blocks get synthetic VAs from [`build::BLOCK_BASE`], and a block's
//! `end_va` is set to **the start VA of its intended fall-through successor**,
//! which is exactly the contract `Machine::run_function` reads it under ("a
//! block's `end_va` is the start of its fall-through successor"). A block with
//! no fall-through gets [`build::NO_FALLTHROUGH_VA`], which no block starts at,
//! so a lowering bug surfaces as a loud `Outcome::NoBlock(0)` instead of
//! silently running the next block.
//!
//! # No recursion over user input
//!
//! Both the expression and the statement lowering walk an explicit job stack.
//! The reason is recorded in `roadmap.md` section 0: a recursive scan in the
//! sibling workspace overflowed the stack and aborted the process, so no
//! per-function result could be reported and the harness read the exit as a
//! crash. Decompiler C nests exactly that deeply.

pub mod build;
pub mod ctype;
#[cfg(feature = "exec")]
pub mod differential;
pub mod expr;
pub mod func;
pub mod literal;
pub mod stmt;
pub mod value;

#[cfg(test)]
mod census_tests;
#[cfg(all(test, feature = "exec"))]
mod differential_tests;
// Every test in here lowers a function and *runs* it on `crate::exec`'s
// interpreter -- that is the point of the module, not an implementation
// detail -- so it needs the same `exec` gate its two neighbours carry.
// Without it the two lanes that build without `exec` (`triage-core` and
// `triage-parsers-extra`) fail to compile the test target, which is invisible
// to every other lane and to `cargo test`.
#[cfg(all(test, feature = "exec"))]
mod tests;

pub use ctype::CType;
pub use func::{lower_function, lower_named_function, LoweredFunction, ParamSlot};

use crate::syntax::ids::NodeId;

/// Why a function could not be lowered.
///
/// One variant, carrying the construct's own name and the byte offset it starts
/// at, because the only useful thing a caller can do with a refusal is report
/// *which* construct is missing. A census over the fixture corpus is then a
/// frequency table over `what`, which is how the coverage question in
/// `roadmap.md` section 6 gets a number instead of an opinion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LowerError {
    /// The construct that is not covered, named the way the report should read
    /// it (e.g. `"pointer type"`, `"call expression"`, `"switch statement"`).
    pub what: String,
    /// Byte offset into the source text where the construct starts, or 0 when
    /// the construct has no token of its own.
    pub offset: u32,
}

impl LowerError {
    /// Refuse `what`, locating it at `offset`.
    pub fn new(what: impl Into<String>, offset: u32) -> Self {
        Self {
            what: what.into(),
            offset,
        }
    }
}

impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported at byte {}: {}", self.offset, self.what)
    }
}

impl std::error::Error for LowerError {}

/// A node the lowering reached but does not model.
pub(crate) fn unsupported<T>(
    what: impl Into<String>,
    node: NodeId,
    ctx: &func::Ctx<'_>,
) -> Result<T, LowerError> {
    Err(LowerError::new(what, ctx.offset_of(node)))
}

#[cfg(test)]
mod coverage {
    //! Corpus lowering coverage: the number phase 2.5 of
    //! `docs/development/roadmap/source-semantics.md` gates on.
    use super::*;

    #[test]
    fn corpus_coverage() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/src");
        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };
        let mut total = 0usize;
        let mut ok = 0usize;
        let mut reasons: std::collections::BTreeMap<String, usize> = Default::default();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("c") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let (tree, _) = crate::csource::parse::parse(&text).into_parts();
            for func in tree.functions(&text) {
                if func.name.is_empty() {
                    continue;
                }
                total += 1;
                match crate::csource::lower::func::lower_named_function(&text, &func.name) {
                    Ok(_) => ok += 1,
                    Err(e) => {
                        let what = e.to_string();
                        let key = what
                            .split(": ")
                            .nth(1)
                            .unwrap_or(&what)
                            .split_whitespace()
                            .take(4)
                            .collect::<Vec<_>>()
                            .join(" ");
                        *reasons.entry(key).or_default() += 1;
                    }
                }
            }
        }
        let mut top: Vec<_> = reasons.into_iter().collect();
        top.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        eprintln!(
            "COVERAGE {ok}/{total} = {:.1}%",
            ok as f64 / total as f64 * 100.0
        );
        for (reason, count) in top.iter().take(10) {
            eprintln!("   {count:4}  {reason}");
        }

        assert!(total > 500, "corpus not found: {total} functions");
        // A ratchet, not a target. Phase 3 of
        // `docs/development/roadmap/source-semantics.md` is gated on this
        // number, so it must not fall silently: a lowering change that refuses
        // something it used to accept fails here rather than shrinking the
        // population a later feasibility claim is measured over.
        assert!(
            ok * 100 / total >= 34,
            "lowering coverage fell to {ok}/{total}"
        );
        // "pointer type" was 325 of 732 refusals before pointers were admitted
        // as a lowerable type. It must not come back as a whole-type refusal.
        let bare_pointer = top
            .iter()
            .find(|(reason, _)| reason == "pointer type")
            .map(|(_, count)| *count)
            .unwrap_or(0);
        assert_eq!(
            bare_pointer, 0,
            "a bare `pointer type` refusal returned; pointers are lowerable"
        );
    }
}

#[cfg(test)]
mod construct_census {
    //! What each corpus function *needs*, not what it is refused for first.
    //!
    //! The coverage census reports the first `LowerError`, which makes it a
    //! queue: fixing pointers revealed calls, and fixing calls will reveal
    //! whatever is behind those. This asks the other question --- which
    //! constructs does each function contain --- so a capability bundle can be
    //! costed before it is built rather than after.
    use crate::csource::parse::tag::NodeTag;
    use std::collections::{BTreeMap, BTreeSet};

    /// One capability the lowering may or may not have.
    const FLOAT: &str = "float";
    const POINTER: &str = "pointer";
    const ARRAY: &str = "array/subscript";
    const AGGREGATE: &str = "struct/union member";
    const CALL_INTRA: &str = "call (defined here)";
    const CALL_EXTERN: &str = "call (external)";
    const SWITCH: &str = "switch";
    const GOTO: &str = "goto/label";
    const GLOBAL: &str = "global reference";

    #[test]
    fn what_each_function_needs() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/src");
        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };

        // Per function: the set of capabilities it uses.
        let mut needs: Vec<BTreeSet<&'static str>> = Vec::new();
        let mut per_construct: BTreeMap<&'static str, usize> = BTreeMap::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("c") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let (tree, _) = crate::csource::parse::parse(&text).into_parts();
            let arena = tree.arena();
            let defined: BTreeSet<String> = tree
                .functions(&text)
                .iter()
                .map(|f| f.name.clone())
                .collect();
            let flows = crate::csource::dataflow::analyze(&text).into_parts().0;

            for func in tree.functions(&text) {
                if func.name.is_empty() {
                    continue;
                }
                let mut set: BTreeSet<&'static str> = BTreeSet::new();
                let span = func.span;
                let body = text.get(span.lo as usize..span.hi as usize).unwrap_or("");

                for node in arena.preorder(func.node) {
                    match arena.tag(node).and_then(NodeTag::from_u16) {
                        Some(NodeTag::IndexSuffix) => {
                            set.insert(ARRAY);
                        }
                        Some(NodeTag::MemberSuffix) => {
                            set.insert(AGGREGATE);
                        }
                        Some(NodeTag::SwitchStmt) => {
                            set.insert(SWITCH);
                        }
                        Some(NodeTag::GotoStmt) | Some(NodeTag::LabelStmt) => {
                            set.insert(GOTO);
                        }
                        _ => {}
                    }
                }
                // Types, read from the text of the definition: cheap and good
                // enough for a census that only needs to bucket.
                if body.contains("float") || body.contains("double") {
                    set.insert(FLOAT);
                }
                if body.contains('*') {
                    set.insert(POINTER);
                }
                if body.contains("struct ") || body.contains("union ") {
                    set.insert(AGGREGATE);
                }

                if let Some(flow) = flows.iter().find(|f| f.name == func.name) {
                    for call in &flow.calls {
                        match call.callee.as_deref() {
                            Some(name) if defined.contains(name) => {
                                set.insert(CALL_INTRA);
                            }
                            Some(_) => {
                                set.insert(CALL_EXTERN);
                            }
                            None => {
                                set.insert(CALL_EXTERN);
                            }
                        }
                    }
                    if !flow.unresolved_uses.is_empty() {
                        set.insert(GLOBAL);
                    }
                }

                for item in &set {
                    *per_construct.entry(item).or_default() += 1;
                }
                needs.push(set);
            }
        }

        let total = needs.len();
        let clean = needs.iter().filter(|s| s.is_empty()).count();
        eprintln!("CONSTRUCTS over {total} functions ({clean} need nothing beyond scalars)");
        let mut rows: Vec<_> = per_construct.into_iter().collect();
        rows.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
        for (name, count) in &rows {
            eprintln!("   {count:4}  {name}");
        }

        assert!(total > 500, "corpus not found: {total} functions");
        // The census must keep finding the shape of the corpus. A collapse
        // here means the detector broke, not that the corpus changed.
        assert!(clean > 50, "only {clean} scalar-only functions");

        // What a cumulative bundle buys: add capabilities cheapest-first and
        // report how many functions become fully covered.
        eprintln!("CUMULATIVE (functions fully covered by the bundle):");
        let order = [
            POINTER,
            CALL_INTRA,
            ARRAY,
            GLOBAL,
            SWITCH,
            AGGREGATE,
            GOTO,
            CALL_EXTERN,
            FLOAT,
        ];
        let mut have: BTreeSet<&'static str> = BTreeSet::new();
        for cap in order {
            have.insert(cap);
            let covered = needs.iter().filter(|s| s.is_subset(&have)).count();
            eprintln!(
                "   +{:22} -> {covered:4} / {total}  ({:.0}%)",
                cap,
                covered as f64 / total as f64 * 100.0
            );
        }
    }
}

#[cfg(test)]
mod unresolved_census {
    //! Of the names the lowering cannot resolve, how many are file-scope
    //! variables and how many are object-like macros?
    //!
    //! The two look identical to a parser with no preprocessor -- both are a
    //! `NameRef` with no declaration in scope -- and they need completely
    //! different fixes. A global needs an address and a memory model; a
    //! `#define N 8` needs a constant substituted.
    use std::collections::BTreeMap;

    #[test]
    fn macros_versus_globals() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/src");
        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };
        let mut macro_const = 0usize;
        let mut macro_other = 0usize;
        let mut file_scope = 0usize;
        let mut unknown = 0usize;
        let mut examples: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("c") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };

            // Object-like macros: `#define NAME rest`, no parameter list.
            let mut defines: BTreeMap<String, String> = BTreeMap::new();
            for line in text.lines() {
                let line = line.trim_start();
                let Some(rest) = line.strip_prefix("#define ") else {
                    continue;
                };
                let mut parts = rest.splitn(2, char::is_whitespace);
                let Some(name) = parts.next() else { continue };
                if name.contains('(') {
                    continue;
                } // function-like
                defines.insert(
                    name.to_string(),
                    parts.next().unwrap_or("").trim().to_string(),
                );
            }

            let (tree, _) = crate::csource::parse::parse(&text).into_parts();
            // File-scope declarations: a `Decl` not inside any function body.
            let function_spans: Vec<_> = tree.functions(&text).iter().map(|f| f.span).collect();
            let spans = tree.token_spans(&text);
            let arena = tree.arena();
            let mut globals: Vec<String> = Vec::new();
            for root_node in arena.roots().iter().copied() {
                for node in arena.preorder(root_node) {
                    if arena.tag(node)
                        != Some(crate::csource::parse::tag::NodeTag::DeclName.as_u16())
                    {
                        continue;
                    }
                    let Some(sp) = arena.span(node, &spans) else {
                        continue;
                    };
                    if function_spans
                        .iter()
                        .any(|f| f.lo <= sp.lo && sp.hi <= f.hi)
                    {
                        continue;
                    }
                    if let Some(name) = text.get(sp.lo as usize..sp.hi as usize) {
                        globals.push(name.to_string());
                    }
                }
            }

            for flow in crate::csource::dataflow::analyze(&text).into_parts().0 {
                for index in &flow.unresolved_uses {
                    let name = &flow.uses[*index as usize].name;
                    if let Some(body) = defines.get(name) {
                        // A macro whose body is a bare integer literal is a
                        // constant; anything else needs real expansion.
                        if body.parse::<i64>().is_ok()
                            || body
                                .trim_end_matches(|c| "uUlL".contains(c))
                                .parse::<i64>()
                                .is_ok()
                            || body.starts_with("0x")
                        {
                            macro_const += 1;
                            examples
                                .entry("macro constant")
                                .or_default()
                                .push(name.clone());
                        } else {
                            macro_other += 1;
                            examples
                                .entry("macro, not a constant")
                                .or_default()
                                .push(name.clone());
                        }
                    } else if globals.contains(name) {
                        file_scope += 1;
                        examples
                            .entry("file-scope variable")
                            .or_default()
                            .push(name.clone());
                    } else {
                        unknown += 1;
                        examples.entry("neither").or_default().push(name.clone());
                    }
                }
            }
        }
        let total = macro_const + macro_other + file_scope + unknown;
        eprintln!("UNRESOLVED NAMES: {total}");
        eprintln!("   {macro_const:4}  object-like macro whose body is an integer literal");
        eprintln!("   {macro_other:4}  object-like macro, body is not a literal");
        eprintln!("   {file_scope:4}  file-scope variable (a real global)");
        eprintln!("   {unknown:4}  neither (extern, libc, or a name from a header)");
        for (kind, mut names) in examples {
            names.sort();
            names.dedup();
            eprintln!("   {kind}: {:?}", &names[..names.len().min(6)]);
        }
    }
}

#[cfg(test)]
mod call_census {
    //! What the callees actually are, for the 274 functions now refused for a
    //! call.
    //!
    //! Same method as [`super::unresolved_census`], and it exists for the same
    //! reason: "support calls" is three different pieces of work depending on
    //! what the callee turns out to be, and the refusal reason cannot tell them
    //! apart. A callee defined in the same translation unit needs an inliner. A
    //! libc callee needs a model or an uninterpreted result. A callee that is
    //! not a function at all --- an unexpanded macro, a compiler builtin ---
    //! needs neither.
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn what_the_callees_are() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/decompiler_fixtures/src");
        let Ok(entries) = std::fs::read_dir(&root) else {
            return;
        };

        let mut sites: BTreeMap<String, usize> = BTreeMap::new();
        let mut kinds: BTreeMap<&'static str, usize> = BTreeMap::new();
        // Functions refused for a call, by the kind of callee they contain. A
        // function needs *every* callee it contains, so it is counted under the
        // hardest one.
        let mut blocked_by: BTreeMap<&'static str, usize> = BTreeMap::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("c") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let (tree, _) = crate::csource::parse::parse(&text).into_parts();
            let defined: BTreeSet<String> = tree
                .functions(&text)
                .iter()
                .map(|f| f.name.clone())
                .collect();
            let flows = crate::csource::dataflow::analyze(&text).into_parts().0;
            // A name `#define`d in this file and *called* is a function-like
            // macro the parser could not expand, not a function.
            let macro_names = defined_macro_names(&text);

            for func in tree.functions(&text) {
                if func.name.is_empty() {
                    continue;
                }
                let refused_for_a_call =
                    match crate::csource::lower::func::lower_named_function(&text, &func.name) {
                        Ok(_) => false,
                        Err(e) => e.to_string().contains("call expression"),
                    };
                let Some(flow) = flows.iter().find(|f| f.name == func.name) else {
                    continue;
                };
                let mut worst: Option<&'static str> = None;
                for call in &flow.calls {
                    let Some(name) = call.callee.as_deref() else {
                        continue;
                    };
                    *sites.entry(name.to_string()).or_default() += 1;
                    let kind = classify(name, &defined, &macro_names);
                    *kinds.entry(kind).or_default() += 1;
                    // Hardest first: an inliner is more work than a builtin.
                    worst = Some(match (worst, kind) {
                        (Some(INTRA), _) | (_, INTRA) => INTRA,
                        (Some(LIBC), _) | (_, LIBC) => LIBC,
                        (Some(w), _) => w,
                        (None, k) => k,
                    });
                }
                if refused_for_a_call {
                    if let Some(kind) = worst {
                        *blocked_by.entry(kind).or_default() += 1;
                    }
                }
            }
        }

        eprintln!("CALL SITES by callee kind:");
        let mut ranked: Vec<_> = kinds.iter().collect();
        ranked.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
        for (kind, count) in ranked {
            eprintln!("   {count:4}  {kind}");
        }
        eprintln!("FUNCTIONS refused for a call, by the hardest callee they contain:");
        let mut ranked: Vec<_> = blocked_by.iter().collect();
        ranked.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
        for (kind, count) in ranked {
            eprintln!("   {count:4}  {kind}");
        }
        eprintln!("TOP callees:");
        let mut ranked: Vec<_> = sites.iter().collect();
        ranked.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
        for (name, count) in ranked.iter().take(25) {
            eprintln!("   {count:4}  {name}");
        }

        assert!(
            sites.values().sum::<usize>() > 100,
            "corpus not found: {} call sites",
            sites.values().sum::<usize>()
        );
    }

    const INTRA: &str = "defined in this file (needs an inliner)";
    const LIBC: &str = "external function (needs a model or an unknown)";
    const BUILTIN: &str = "compiler builtin (needs a one-line model)";
    const MACRO: &str = "function-like macro (not a function at all)";

    /// Which of the four kinds of work a callee name implies.
    fn classify(
        name: &str,
        defined: &BTreeSet<String>,
        macro_names: &BTreeSet<String>,
    ) -> &'static str {
        if defined.contains(name) {
            INTRA
        } else if name.starts_with("__builtin_") {
            BUILTIN
        } else if macro_names.contains(name) {
            MACRO
        } else {
            LIBC
        }
    }

    /// Every name this file `#define`s, object-like or function-like.
    ///
    /// Deliberately looser than
    /// [`crate::csource::lower::func`]'s macro scan, which takes only
    /// integer-literal bodies: here the question is whether the name is a macro
    /// at all, not what it expands to.
    fn defined_macro_names(text: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for line in text.lines() {
            let line = line.trim_start();
            let Some(rest) = line.strip_prefix("#define") else {
                continue;
            };
            let rest = rest.trim_start();
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            if end > 0 {
                out.insert(rest[..end].to_string());
            }
        }
        out
    }
}
