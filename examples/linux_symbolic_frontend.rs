//! Inspect strict Linux AArch64 ET_REL handler admission.
//!
//! Usage:
//! `cargo run --example linux_symbolic_frontend -- <object> <handler>`

use std::collections::BTreeMap;
use std::path::PathBuf;

use glaurung::analysis::linux_symbolic_frontend::admit_linux_aarch64_handler;
use glaurung::ir::types::Op;
use serde::Serialize;

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    object: String,
    handler: String,
    admitted: bool,
    error: Option<String>,
    section: Option<String>,
    section_index: Option<usize>,
    section_offset: Option<u64>,
    synthetic_va: Option<u64>,
    size: Option<u64>,
    blocks: usize,
    llir_ops: usize,
    opaque_intrinsics: usize,
    opaque_intrinsic_counts: BTreeMap<String, usize>,
    relocations: Vec<RelocationReport>,
    external_calls: BTreeMap<u64, String>,
    local_calls: BTreeMap<u64, String>,
}

#[derive(Serialize)]
struct RelocationReport {
    handler_offset: u64,
    kind: String,
    target_symbol: String,
    target_va: u64,
    addend: i64,
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let Some(object_path) = args.next().map(PathBuf::from) else {
        eprintln!("usage: linux_symbolic_frontend <object> <handler>");
        std::process::exit(2);
    };
    let Some(handler) = args.next().and_then(|value| value.into_string().ok()) else {
        eprintln!("usage: linux_symbolic_frontend <object> <handler>");
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("usage: linux_symbolic_frontend <object> <handler>");
        std::process::exit(2);
    }
    let object_name = object_path.display().to_string();
    let data = match std::fs::read(&object_path) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("cannot read {}: {error}", object_path.display());
            std::process::exit(2);
        }
    };

    let report = match admit_linux_aarch64_handler(&data, &handler) {
        Ok(admitted) => {
            let llir_ops = admitted
                .llir
                .blocks
                .iter()
                .map(|block| block.instrs.len())
                .sum();
            let opaque_intrinsics = admitted
                .llir
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .filter(|instruction| matches!(instruction.op, Op::Intrinsic { .. }))
                .count();
            let mut opaque_intrinsic_counts = BTreeMap::new();
            for name in admitted
                .llir
                .blocks
                .iter()
                .flat_map(|block| &block.instrs)
                .filter_map(|instruction| match &instruction.op {
                    Op::Intrinsic { name, .. } => Some(name.clone()),
                    _ => None,
                })
            {
                *opaque_intrinsic_counts.entry(name).or_insert(0) += 1;
            }
            Report {
                schema: "glaurung-linux-symbolic-frontend-v1",
                object: object_name,
                handler: admitted.symbol,
                admitted: true,
                error: None,
                section: Some(admitted.section),
                section_index: Some(admitted.section_index),
                section_offset: Some(admitted.section_offset),
                synthetic_va: Some(admitted.synthetic_va),
                size: Some(admitted.size),
                blocks: admitted.llir.blocks.len(),
                llir_ops,
                opaque_intrinsics,
                opaque_intrinsic_counts,
                relocations: admitted
                    .relocations
                    .into_iter()
                    .map(|relocation| RelocationReport {
                        handler_offset: relocation.handler_offset,
                        kind: relocation.kind,
                        target_symbol: relocation.target_symbol,
                        target_va: relocation.target_va,
                        addend: relocation.addend,
                    })
                    .collect(),
                external_calls: admitted.external_calls,
                local_calls: admitted.local_calls,
            }
        }
        Err(error) => Report {
            schema: "glaurung-linux-symbolic-frontend-v1",
            object: object_name,
            handler,
            admitted: false,
            error: Some(error.to_string()),
            section: None,
            section_index: None,
            section_offset: None,
            synthetic_va: None,
            size: None,
            blocks: 0,
            llir_ops: 0,
            opaque_intrinsics: 0,
            opaque_intrinsic_counts: BTreeMap::new(),
            relocations: Vec::new(),
            external_calls: BTreeMap::new(),
            local_calls: BTreeMap::new(),
        },
    };
    let json = match serde_json::to_string_pretty(&report) {
        Ok(json) => json,
        Err(error) => {
            eprintln!("cannot serialize report: {error}");
            std::process::exit(1);
        }
    };
    println!("{json}");
    if !report.admitted {
        std::process::exit(1);
    }
}
