//! Low-Level Intermediate Representation (LLIR) — Phase 2 kickoff.
//!
//! This is the first, deliberately small IR in Glaurung's lifting pipeline.
//! It exists to turn machine instructions into a machine-analysable,
//! architecture-agnostic three-address form that downstream passes (data-flow,
//! xref recovery, a future mid-IR/SSA lifter) can consume without knowing the
//! source ISA.
//!
//! Design principles:
//! 1. **Semantic preservation first.** When we cannot lift an instruction
//!    faithfully, emit [`Op::Unknown`] carrying the source mnemonic instead
//!    of silently dropping it.
//! 2. **Three-address, non-SSA.** SSA comes at the next layer. Keeping this
//!    layer non-SSA lets the lifter stay tiny (~200 LoC per arch) and keeps
//!    the output readable for unit tests.
//! 3. **Flags are virtual registers.** x86 `cmp`/`add` side-effects go into
//!    explicit [`VReg::Flag`] writes so condition-code consumers can read
//!    them as ordinary values.
//! 4. **Tiny scope.** v1 supports a handful of x86-64 mnemonics
//!    (mov, add, sub, cmp, test, push, pop, call, ret, jmp, jcc, nop, lea).
//!    Anything else becomes [`Op::Unknown`] and is reported to the caller.
//!
//! This file defines the IR; [`lift_x86`] contains the lifter.

pub mod aapcs64_indirect_result;
pub mod abi;
pub mod arm32_prologue;
pub mod arm64_prologue;
pub(crate) mod arm_input_evidence;
pub mod ast;
pub mod call_args;
pub mod call_contracts;
pub mod call_result_split;
pub mod callee_return_bank;
pub mod callee_return_pair;
pub(crate) mod caller_arity;
pub mod canary;
pub mod cfg_edges;
pub mod const_fold;
pub mod control_semantics;
pub mod copy_prop;
pub mod dce;
pub mod dead_stores;
pub mod definedness;
pub mod direct_output;
pub mod dwarf_fields;
pub(crate) mod dwarf_type_env;
pub mod effect_census;
pub(crate) mod effectful_loop;
pub mod exception_recover;
pub mod expr_reconstruct;
pub mod expression_width;
pub mod function_tables;
pub mod got_fold;
pub mod guard_chain;
pub(crate) mod guarded_call;
pub mod guarded_switch;
pub mod health;
pub mod high_variables;
pub mod indirect_targets;
pub mod label_prune;
pub(crate) mod latch_predicate;
pub(crate) mod lazy_call_select;
pub mod lift_arm32;
pub mod lift_arm64;
pub mod lift_function;
pub mod lift_x86;
pub mod loop_form;
pub(crate) mod machine_register;
pub(crate) mod memory_objects;
pub(crate) mod memory_ssa;
pub mod mir;
pub mod name_resolve;
pub mod naming;
pub mod pass_stats;
pub mod pdb_fields;
pub(crate) mod prototype_width;
pub mod readonly_fold;
pub mod regview;
pub mod return_class;
pub mod select_fold;
pub mod soft_helpers;
pub mod ssa;
pub mod stack_idiom;
pub mod stack_locals;
pub mod strings_fold;
pub mod structure;
pub mod structure_accounting;
pub mod structured_reaching;
pub mod switch_ladder;
pub mod symbol_env;
pub mod terminal_loop;
pub mod typed_simplify;
pub mod types;
pub mod types_recover;
pub mod use_def;
pub mod value_number;
pub mod value_split;
pub mod vector_copy;
pub mod verify_defs;
pub mod widen;
pub mod winapi_prototypes;
pub mod x86_prologue;
pub mod x87;

#[cfg(test)]
mod effect_census_tests;
#[cfg(test)]
mod health_tests;

pub use types::*;
