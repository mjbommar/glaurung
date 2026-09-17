//! Runtime evidence that can be correlated with, but is not owned by, static analysis.
//!
//! The decompiler describes possible program semantics. This module describes
//! captured process state and observed events. The two domains meet through
//! explicit identities and evidence relations; runtime pages never mutate a
//! [`crate::program::ProgramImage`].

pub mod behavior;
pub mod bundle;
pub mod capsule;
pub mod correlation;
pub mod corruption;
pub mod crash;
pub mod elf_core;
pub mod event_correlation;
pub mod input;
pub mod instruction_trace;
pub mod memory;
pub mod stack_objects;
