//! PDB-backed field hints for decompiler memory operands.
//!
//! This pass is deliberately conservative. It does not infer the concrete
//! struct type of a base register yet; instead, when a PE/PDB cache is
//! available, it annotates simple `base + constant` operands with a small
//! set of PDB field candidates for that displacement.

use std::collections::BTreeMap;
use std::path::Path;

use crate::ir::ast::{Expr, Function, PdbFieldHint, Stmt};
use crate::symbols::pdb::PdbIngestor;

const MAX_HINT_CANDIDATES: usize = 3;

const DEFAULT_WINDOWS_FIELD_LAYOUTS: &[&str] = &[
    "_EPROCESS",
    "_KTHREAD",
    "_KPROCESS",
    "_ETHREAD",
    "_KPRCB",
    "_KTRAP_FRAME",
    "_KAPC_STATE",
    "_KWAIT_BLOCK",
    "_FILE_OBJECT",
    "_DEVICE_OBJECT",
    "_IRP",
    "_DRIVER_OBJECT",
    "_HANDLE_TABLE",
    "_PEB",
    "_TEB",
    "_KAPC",
    "_KSEMAPHORE",
    "_KEVENT",
    "_KDPC",
    "_RTL_AVL_TREE",
    "_EX_FAST_REF",
    "_EX_PUSH_LOCK",
    "_DISPATCHER_HEADER",
    "_LARGE_INTEGER",
    "_LIST_ENTRY",
    "_UNICODE_STRING",
    "_OBJECT_TYPE",
    "_OBJECT_HEADER",
];

#[derive(Debug, Clone, Default)]
pub struct PdbFieldMap {
    by_offset: BTreeMap<i64, Vec<PdbFieldHint>>,
}

impl PdbFieldMap {
    fn hints_for_disp(&self, disp: i64) -> Option<&[PdbFieldHint]> {
        if disp <= 0 {
            return None;
        }
        let hints = self.by_offset.get(&disp)?;
        if hints.is_empty() || hints.len() > MAX_HINT_CANDIDATES {
            return None;
        }
        Some(hints)
    }

    fn insert(&mut self, hint: PdbFieldHint) {
        let Ok(offset) = i64::try_from(hint.offset) else {
            return;
        };
        let slot = self.by_offset.entry(offset).or_default();
        if slot.iter().any(|existing| {
            existing.type_name == hint.type_name && existing.field_name == hint.field_name
        }) {
            return;
        }
        slot.push(hint);
        slot.sort_by(|a, b| {
            a.type_name
                .cmp(&b.type_name)
                .then_with(|| a.field_name.cmp(&b.field_name))
        });
    }
}

pub fn collect_pdb_field_map(path: &str, cache_dir: &Path) -> PdbFieldMap {
    let mut out = PdbFieldMap::default();
    if path.is_empty() || !cache_dir.is_dir() {
        return out;
    }
    let Ok(Some(source)) = PdbIngestor::from_pe_cache(path, cache_dir) else {
        return out;
    };
    for layout_name in DEFAULT_WINDOWS_FIELD_LAYOUTS {
        let Ok(Some(layout)) = source.find_struct_layout(layout_name) else {
            continue;
        };
        for field in layout.fields {
            if field.name.is_empty() {
                continue;
            }
            out.insert(PdbFieldHint {
                type_name: layout.name.clone(),
                field_name: field.name,
                field_type: field.type_name,
                offset: field.byte_offset,
            });
        }
    }
    out
}

pub fn annotate_function_fields(function: &mut Function, field_map: &PdbFieldMap) {
    for stmt in &mut function.body {
        annotate_stmt(stmt, field_map);
    }
}

fn annotate_stmt(stmt: &mut Stmt, field_map: &PdbFieldMap) {
    match stmt {
        Stmt::Assign { src, .. } => annotate_expr(src, field_map),
        Stmt::Store { addr, src } => {
            annotate_expr(addr, field_map);
            annotate_expr(src, field_map);
        }
        Stmt::Call { target, args } => {
            annotate_expr(target, field_map);
            for arg in args {
                annotate_expr(arg, field_map);
            }
        }
        Stmt::Return { value } => {
            if let Some(value) = value {
                annotate_expr(value, field_map);
            }
        }
        Stmt::If {
            cond,
            then_body,
            else_body,
        } => {
            annotate_expr(cond, field_map);
            for stmt in then_body {
                annotate_stmt(stmt, field_map);
            }
            if let Some(else_body) = else_body {
                for stmt in else_body {
                    annotate_stmt(stmt, field_map);
                }
            }
        }
        Stmt::While { cond, body } => {
            annotate_expr(cond, field_map);
            for stmt in body {
                annotate_stmt(stmt, field_map);
            }
        }
        Stmt::Push { value } => annotate_expr(value, field_map),
        Stmt::Switch {
            discriminant,
            cases,
            default,
        } => {
            annotate_expr(discriminant, field_map);
            for (_, body) in cases {
                for stmt in body {
                    annotate_stmt(stmt, field_map);
                }
            }
            if let Some(default) = default {
                for stmt in default {
                    annotate_stmt(stmt, field_map);
                }
            }
        }
        Stmt::Pop { .. }
        | Stmt::Goto { .. }
        | Stmt::Label(_)
        | Stmt::Break | Stmt::Nop
        | Stmt::Unknown(_)
        | Stmt::Comment(_) => {}
    }
}

fn annotate_expr(expr: &mut Expr, field_map: &PdbFieldMap) {
    match expr {
        Expr::Deref { addr, .. } => annotate_expr(addr, field_map),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            annotate_expr(lhs, field_map);
            annotate_expr(rhs, field_map);
        }
        Expr::Un { src, .. } => annotate_expr(src, field_map),
        Expr::Lea {
            base,
            index,
            scale,
            disp,
            segment,
        } => {
            if base.is_some() && index.is_none() {
                if let Some(hints) = field_map.hints_for_disp(*disp) {
                    *expr = Expr::PdbFieldAddr {
                        base: base.clone(),
                        index: index.clone(),
                        scale: *scale,
                        disp: *disp,
                        segment: segment.clone(),
                        hints: hints.to_vec(),
                    };
                }
            }
        }
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Unknown(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ast::{render, Function};
    use crate::ir::types::VReg;

    #[test]
    fn annotate_function_fields_adds_bounded_pdb_hint() {
        let mut map = PdbFieldMap::default();
        map.insert(PdbFieldHint {
            type_name: "_KTHREAD".to_string(),
            field_name: "TrapFrame".to_string(),
            field_type: Some("_KTRAP_FRAME *".to_string()),
            offset: 0x90,
        });
        let mut function = Function {
            name: "sub_1000".to_string(),
            entry_va: 0x1000,
            body: vec![Stmt::Assign {
                dst: VReg::phys("rax"),
                src: Expr::Deref {
                    addr: Box::new(Expr::Lea {
                        base: Some(VReg::phys("rcx")),
                        index: None,
                        scale: 1,
                        disp: 0x90,
                        segment: None,
                    }),
                    size: 8,
                },
            }],
        };

        annotate_function_fields(&mut function, &map);
        let text = render(&function);
        assert!(text.contains("_KTHREAD.TrapFrame: _KTRAP_FRAME *"));
    }

    #[test]
    fn collect_pdb_field_map_includes_kernel_trap_frame_field() {
        let path = Path::new("tests/fixtures/msvc-pdb/ntoskrnl.exe");
        let cache = Path::new("tests/fixtures/msvc-pdb");
        if !path.exists() || !cache.join("ntkrnlmp.pdb").exists() {
            return;
        }
        let map = collect_pdb_field_map(path.to_str().unwrap_or(""), cache);
        let hints = map.hints_for_disp(0x188).expect("expected bounded hints");
        assert!(hints
            .iter()
            .any(|hint| hint.type_name == "_KTRAP_FRAME" && hint.field_name == "SegSs"));
    }
}
