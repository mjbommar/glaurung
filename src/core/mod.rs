//! Core data types for Glaurung binary analysis.
//!
//! This module contains the fundamental types used throughout the system,
//! starting with the Address type which is the foundation for all location
//! references in binary analysis.

pub mod address;
pub mod address_range;
pub mod address_space;
pub mod artifact;
pub mod basic_block;
pub mod binary;
pub mod disassembler;
pub mod id;
pub mod instruction;
pub mod pattern;
pub mod register;
pub mod relocation;
pub mod section;
pub mod segment;
pub mod string_literal;
pub mod symbol;
pub mod tool_metadata;
pub mod triage;
