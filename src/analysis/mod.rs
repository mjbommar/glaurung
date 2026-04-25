//! Analysis-time program and memory views.
//!
//! This module provides lightweight, safe data structures used during
//! analysis: a `BinaryView` container that aggregates sections/segments
//! and image base metadata, and a `MemoryView` trait for bounded reads
//! by `core::address::Address` with simple VA↔RVA↔FileOffset translation.

pub mod aarch64_literals;
pub mod cfg;
pub mod elf_got;
pub mod elf_plt;
pub mod entry;
pub mod macho_stubs;
pub mod memory;
pub mod pe_iat;
pub mod view;
pub mod vtable;
pub mod xrefs;
