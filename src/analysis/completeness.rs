//! Turning "a discovery budget fired" into something the rendered output says.
//!
//! `analysis::cfg` records a bounded walk's truncation on the `Function` it
//! produced (`FunctionFlags::CFG_INCOMPLETE`). That record is only worth
//! carrying if the product surfaces it, so this module owns the one thing the
//! decompiler entry points need from it: the analyst-visible note.
//!
//! It lives apart from `cfg.rs` because the wording is a rendering decision,
//! not a discovery one, and apart from `python_bindings::ir` because more than
//! one entry point emits it.
//!
//! ## What the note may and may not claim
//!
//! It may claim that a named budget fired during this specific function's walk:
//! that is exactly what the flag records. It may NOT claim how much is missing.
//! A budgeted walk stops without enumerating what it would have reached, so the
//! number of unwalked blocks is not merely unrecorded, it is unrecoverable
//! after the fact. Inventing a count would replace a silent omission with a
//! confident wrong number, which is worse.

use crate::analysis::cfg::Budgets;
use crate::core::function::Function;

/// The stable token every incompleteness note starts with.
///
/// Consumers (and tests) match on this rather than on the prose, so the wording
/// can improve without breaking them.
pub const CFG_INCOMPLETE_MARKER: &str = "GLAURUNG-INCOMPLETE";

/// A C-comment note for a function whose CFG walk a budget cut short, or
/// `None` for a function walked to completion.
///
/// `budgets` supplies the limit VALUES; the function supplies which of them
/// fired. Both halves are needed for the note to be actionable -- "max_blocks
/// stopped it" is not useful without knowing it was 256.
pub fn cfg_incompleteness_note(function: &Function, budgets: &Budgets) -> Option<String> {
    let fired = function.cfg_incomplete_budgets();
    if fired.is_empty() {
        return None;
    }
    let named: Vec<String> = fired
        .iter()
        .map(|name| format!("{name}={}", budget_value(budgets, name)))
        .collect();
    Some(format!(
        "// {CFG_INCOMPLETE_MARKER}: control-flow recovery for this function \
stopped at the\n\
         // discovery budget {}. The body below is a PARTIAL control-flow \
graph:\n\
         // blocks past the budget were never walked, never lifted, and are \
absent from\n\
         // everything derived from this text. How much is missing is not \
known -- a\n\
         // bounded walk stops without enumerating what it did not reach. \
Re-run with a\n\
         // larger budget for a complete body.",
        join_and(&named)
    ))
}

/// The configured value of the budget field `name`.
fn budget_value(budgets: &Budgets, name: &str) -> u64 {
    match name {
        "max_blocks" => budgets.max_blocks as u64,
        "max_instructions" => budgets.max_instructions as u64,
        "timeout_ms" => budgets.timeout_ms,
        "total_timeout_ms" => budgets.total_timeout_ms,
        // Unreachable while `Function::cfg_incomplete_budgets` and this match
        // agree; zero rather than a panic keeps a diagnostic from becoming an
        // outage if they ever drift.
        _ => 0,
    }
}

/// `"a"`, `"a and b"`, `"a, b and c"` -- prose for a list of budget names.
fn join_and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::{Address, AddressKind};
    use crate::core::function::{FunctionFlags, FunctionKind};

    fn function() -> Function {
        let entry = Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap();
        Function::new("f".to_string(), entry, FunctionKind::Normal).unwrap()
    }

    fn budgets() -> Budgets {
        Budgets {
            max_functions: 1,
            max_blocks: 256,
            max_instructions: 2_000,
            timeout_ms: 5_000,
            total_timeout_ms: 0,
        }
    }

    #[test]
    fn complete_function_gets_no_note() {
        assert!(cfg_incompleteness_note(&function(), &budgets()).is_none());
    }

    #[test]
    fn block_limit_note_names_the_budget_and_its_value() {
        let mut f = function();
        f.add_flag(FunctionFlags::CFG_BLOCK_LIMIT);
        let note = cfg_incompleteness_note(&f, &budgets()).expect("note");
        assert!(note.starts_with("// GLAURUNG-INCOMPLETE:"), "{note}");
        assert!(note.contains("max_blocks=256"), "{note}");
        assert!(!note.contains("max_instructions"), "{note}");
        // Every line is a comment, so prepending it can never break a build.
        assert!(note.lines().all(|line| line.starts_with("//")), "{note}");
    }

    #[test]
    fn two_budgets_are_both_named() {
        let mut f = function();
        f.add_flag(FunctionFlags::CFG_BLOCK_LIMIT);
        f.add_flag(FunctionFlags::CFG_INSTRUCTION_LIMIT);
        let note = cfg_incompleteness_note(&f, &budgets()).expect("note");
        assert!(
            note.contains("max_blocks=256 and max_instructions=2000"),
            "{note}"
        );
    }

    #[test]
    fn the_note_never_claims_a_count() {
        let mut f = function();
        f.add_flag(FunctionFlags::CFG_BLOCK_LIMIT);
        let note = cfg_incompleteness_note(&f, &budgets()).expect("note");
        assert!(note.contains("not known"), "{note}");
    }
}
