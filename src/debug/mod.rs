//! Debug-info ingestion (#157).
//!
//! When a binary ships with debug info — DWARF for ELF/Mach-O, PDB for
//! PE — those tables are the authoritative source for function names,
//! signatures, address ranges (including non-contiguous chunks), and
//! types. This module reads them so Glaurung's heuristics-driven layers
//! 0–1 can short-circuit to ground truth on `-g` builds.
//!
//! v1 ships DWARF function discovery only:
//! - `DW_TAG_subprogram` → name (linkage_name preferred), address ranges
//!   (low_pc/high_pc OR DW_AT_ranges → multi-chunk functions), language,
//!   parameter count.
//!
//! Out of scope for v1: DWARF type ingestion (#172 will cover this), PDB
//! parsing (Tier-B), line-table → source-line mapping (#161).

pub mod dwarf;

pub use dwarf::{extract_dwarf_functions, DwarfFunction};
