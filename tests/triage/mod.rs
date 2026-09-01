//! Integration tests for triage functionality.
//!
//! These tests validate the triage system end-to-end using real sample files
//! and focus on integration between components rather than isolated unit testing.

mod adversarial;
mod budgets;
mod determinism_json;
mod entropy_real;
mod io;
mod ioc_integration;
mod packers_real;
mod real_files;
mod sniffers;
mod suspicious_integration;
mod symbols_elf;
mod symbols_macho;
mod symbols_pe;
mod truncation_json;
