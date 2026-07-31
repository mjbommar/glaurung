//! Recover relocation-proven local function-pointer tables.
//!
//! A decompiled load through an input image VA is not standalone C: that VA is
//! not mapped in the rebuilt object.  Conversely, turning an arbitrary computed
//! call into a direct call guesses away writable data.  This pass only annotates
//! a table when a real defined data symbol has pointer-sized storage, every slot
//! has an exact dynamic relocation, and every relocation resolves to an exact
//! defined function symbol.  Anything less remains the original dereference.

use std::collections::HashMap;

use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationKind,
    RelocationTarget, SymbolKind,
};

use crate::ir::ast::{Expr, Function, FunctionTableTarget, Stmt};
use crate::ir::types::{BinOp, VReg};

const MIN_ENTRIES: usize = 2;
const MAX_ENTRIES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionPointerTable {
    pub va: u64,
    pub name: String,
    pub pointer_size: u8,
    pub targets: Vec<FunctionTableTarget>,
}

/// Collect complete local function-pointer tables from an object.
pub fn collect_function_pointer_tables(data: &[u8]) -> Vec<FunctionPointerTable> {
    let Ok(object) = object::read::File::parse(data) else {
        return Vec::new();
    };
    let Some(pointer_size) = object
        .architecture()
        .address_size()
        .map(|size| size.bytes())
    else {
        return Vec::new();
    };
    if !matches!(pointer_size, 4 | 8) {
        return Vec::new();
    }

    let mut function_names: HashMap<u64, String> = HashMap::new();
    for symbol in object.symbols().chain(object.dynamic_symbols()) {
        if !symbol.is_definition() || symbol.kind() != SymbolKind::Text || symbol.address() == 0 {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() || crate::ir::name_resolve::is_internal_alias(name) {
            continue;
        }
        function_names
            .entry(symbol.address())
            .or_insert_with(|| name.to_string());
    }

    let mut relocated_targets = HashMap::new();
    if let Some(relocations) = object.dynamic_relocations() {
        for (place, relocation) in relocations {
            if relocation.size() != 0 && relocation.size() != pointer_size.saturating_mul(8) {
                continue;
            }
            let target = relocation_target_va(&object, &relocation);
            if let Some(target) = target {
                relocated_targets.insert(place, target);
            }
        }
    }

    let mut tables = Vec::new();
    for symbol in object.symbols() {
        if !symbol.is_definition() || symbol.kind() != SymbolKind::Data || symbol.address() == 0 {
            continue;
        }
        let size = symbol.size();
        if size == 0 || size % u64::from(pointer_size) != 0 {
            continue;
        }
        let Ok(entry_count) = usize::try_from(size / u64::from(pointer_size)) else {
            continue;
        };
        if !(MIN_ENTRIES..=MAX_ENTRIES).contains(&entry_count) {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }

        let mut targets = Vec::with_capacity(entry_count);
        for index in 0..entry_count {
            let Some(place) = symbol
                .address()
                .checked_add((index as u64).saturating_mul(u64::from(pointer_size)))
            else {
                targets.clear();
                break;
            };
            let Some(target_va) = relocated_targets.get(&place).copied() else {
                targets.clear();
                break;
            };
            let Some(target_name) = function_names.get(&target_va) else {
                targets.clear();
                break;
            };
            targets.push(FunctionTableTarget {
                va: target_va,
                name: target_name.clone(),
            });
        }
        if targets.len() == entry_count {
            tables.push(FunctionPointerTable {
                va: symbol.address(),
                name: name.to_string(),
                pointer_size,
                targets,
            });
        }
    }
    tables.sort_by_key(|table| table.va);
    tables
}

fn relocation_target_va(
    object: &object::read::File<'_>,
    relocation: &object::Relocation,
) -> Option<u64> {
    match relocation.target() {
        RelocationTarget::Absolute
            if !relocation.has_implicit_addend()
                && is_image_relative(object.architecture(), relocation.flags()) =>
        {
            u64::try_from(relocation.addend()).ok()
        }
        RelocationTarget::Symbol(index)
            if !relocation.has_implicit_addend()
                && relocation.kind() == RelocationKind::Absolute =>
        {
            object
                .symbol_by_index(index)
                .ok()?
                .address()
                .checked_add_signed(relocation.addend())
        }
        RelocationTarget::Section(index)
            if !relocation.has_implicit_addend()
                && relocation.kind() == RelocationKind::Absolute =>
        {
            object
                .section_by_index(index)
                .ok()?
                .address()
                .checked_add_signed(relocation.addend())
        }
        _ => None,
    }
}

fn is_image_relative(architecture: Architecture, flags: RelocationFlags) -> bool {
    let RelocationFlags::Elf { r_type } = flags else {
        return false;
    };
    match architecture {
        Architecture::X86_64 | Architecture::X86_64_X32 => {
            matches!(
                r_type,
                object::elf::R_X86_64_RELATIVE | object::elf::R_X86_64_RELATIVE64
            )
        }
        Architecture::I386 => r_type == object::elf::R_386_RELATIVE,
        Architecture::Aarch64 => r_type == object::elf::R_AARCH64_RELATIVE,
        Architecture::Aarch64_Ilp32 => r_type == object::elf::R_AARCH64_P32_RELATIVE,
        Architecture::Arm => r_type == object::elf::R_ARM_RELATIVE,
        Architecture::Riscv32 | Architecture::Riscv64 => r_type == object::elf::R_RISCV_RELATIVE,
        Architecture::LoongArch32 | Architecture::LoongArch64 => {
            r_type == object::elf::R_LARCH_RELATIVE
        }
        _ => false,
    }
}

/// Replace exact pointer-sized loads from complete tables with semantic entries.
pub fn resolve_function_table_entries(function: &mut Function, tables: &[FunctionPointerTable]) {
    if tables.is_empty() {
        return;
    }
    resolve_body(&mut function.body, tables, &HashMap::new());
}

fn resolve_body(
    body: &mut [Stmt],
    tables: &[FunctionPointerTable],
    inherited_definitions: &HashMap<VReg, Expr>,
) {
    let mut definitions = inherited_definitions.clone();
    for statement in body {
        match statement {
            Stmt::IndirectGoto { target } | Stmt::Push { value: target } => {
                resolve_expr(target, tables, &definitions);
                promote_table_copy(target, &definitions);
            }
            Stmt::Assign { src, .. } => resolve_expr(src, tables, &definitions),
            Stmt::Store { addr, src, .. } => {
                resolve_expr(addr, tables, &definitions);
                resolve_expr(src, tables, &definitions);
            }
            Stmt::Call { target, args, .. } => {
                resolve_expr(target, tables, &definitions);
                promote_table_copy(target, &definitions);
                for argument in args {
                    resolve_expr(argument, tables, &definitions);
                }
            }
            Stmt::Return { value } => {
                if let Some(value) = value {
                    resolve_expr(value, tables, &definitions);
                }
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                resolve_expr(cond, tables, &definitions);
                resolve_body(then_body, tables, &definitions);
                if let Some(else_body) = else_body {
                    resolve_body(else_body, tables, &definitions);
                }
                definitions.clear();
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                resolve_expr(cond, tables, &definitions);
                resolve_body(body, tables, &definitions);
                definitions.clear();
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                resolve_body(std::slice::from_mut(init.as_mut()), tables, &definitions);
                resolve_expr(cond, tables, &definitions);
                resolve_body(body, tables, &definitions);
                resolve_body(std::slice::from_mut(step.as_mut()), tables, &definitions);
                definitions.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                resolve_expr(discriminant, tables, &definitions);
                for (_, case) in cases {
                    resolve_body(case, tables, &definitions);
                }
                if let Some(default) = default {
                    resolve_body(default, tables, &definitions);
                }
                definitions.clear();
            }
            Stmt::Pop { .. }
            | Stmt::Goto { .. }
            | Stmt::Label(_)
            | Stmt::Break
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_)
            | Stmt::Throw { .. }
            | Stmt::TryCatch { .. } => {}
        }

        if let Stmt::Assign { dst, src } = statement {
            definitions.insert(dst.clone(), src.clone());
        } else if matches!(statement, Stmt::Call { .. } | Stmt::IndirectGoto { .. }) {
            // Unversioned physical registers may be clobbered by a transfer.
            // Never carry an address proof across that boundary.
            definitions.clear();
        }
    }
}

fn resolve_expr(
    expression: &mut Expr,
    tables: &[FunctionPointerTable],
    definitions: &HashMap<VReg, Expr>,
) {
    match expression {
        Expr::Deref { addr, .. } => resolve_expr(addr, tables, definitions),
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            resolve_expr(lhs, tables, definitions);
            resolve_expr(rhs, tables, definitions);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            resolve_expr(cond, tables, definitions);
            resolve_expr(if_true, tables, definitions);
            resolve_expr(if_false, tables, definitions);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
            resolve_expr(src, tables, definitions)
        }
        Expr::FunctionTableEntry { index, .. } => resolve_expr(index, tables, definitions),
        Expr::WideArithmetic { args, .. } => {
            for argument in args {
                resolve_expr(argument, tables, definitions);
            }
        }
        Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Unknown(_) => {}
    }

    let replacement = match expression {
        Expr::Deref { addr, size } => tables.iter().find_map(|table| {
            if *size != table.pointer_size {
                return None;
            }
            let index = indexed_table_address(addr, table.va, table.pointer_size, definitions, 0)?;
            Some(Expr::FunctionTableEntry {
                table_va: table.va,
                table_name: table.name.clone(),
                pointer_size: table.pointer_size,
                index: Box::new(index),
                targets: table.targets.clone(),
            })
        }),
        _ => None,
    };
    if let Some(replacement) = replacement {
        *expression = replacement;
    }
}

fn promote_table_copy(expression: &mut Expr, definitions: &HashMap<VReg, Expr>) {
    let Some(replacement) = copied_table_entry(expression, definitions, 0) else {
        return;
    };
    *expression = replacement;
}

fn copied_table_entry(
    expression: &Expr,
    definitions: &HashMap<VReg, Expr>,
    depth: usize,
) -> Option<Expr> {
    if depth >= 16 {
        return None;
    }
    match strip_cast(expression) {
        entry @ Expr::FunctionTableEntry { .. } => Some(entry.clone()),
        Expr::Reg(register) => {
            copied_table_entry(definitions.get(register)?, definitions, depth + 1)
        }
        _ => None,
    }
}

fn indexed_table_address(
    address: &Expr,
    table_va: u64,
    pointer_size: u8,
    definitions: &HashMap<VReg, Expr>,
    depth: usize,
) -> Option<Expr> {
    if depth >= 16 {
        return None;
    }
    match strip_cast(address) {
        Expr::Reg(register) => indexed_table_address(
            definitions.get(register)?,
            table_va,
            pointer_size,
            definitions,
            depth + 1,
        ),
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => table_base_and_index(lhs, 1, rhs, 1, table_va, pointer_size, definitions, depth)
            .or_else(|| {
                table_base_and_index(rhs, 1, lhs, 1, table_va, pointer_size, definitions, depth)
            }),
        Expr::Lea {
            base: Some(base),
            index: Some(index),
            scale,
            disp: 0,
            segment: None,
        }
        | Expr::PdbFieldAddr {
            base: Some(base),
            index: Some(index),
            scale,
            disp: 0,
            segment: None,
            ..
        } => {
            let base = Expr::Reg(base.clone());
            let index = Expr::Reg(index.clone());
            table_base_and_index(
                &base,
                1,
                &index,
                *scale,
                table_va,
                pointer_size,
                definitions,
                depth,
            )
            .or_else(|| {
                table_base_and_index(
                    &index,
                    *scale,
                    &base,
                    1,
                    table_va,
                    pointer_size,
                    definitions,
                    depth,
                )
            })
        }
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn table_base_and_index(
    base: &Expr,
    base_scale: u8,
    index: &Expr,
    index_scale: u8,
    table_va: u64,
    pointer_size: u8,
    definitions: &HashMap<VReg, Expr>,
    depth: usize,
) -> Option<Expr> {
    if base_scale != 1 || !is_table_base(base, table_va, definitions, depth + 1) {
        return None;
    }
    scaled_index(index, index_scale, pointer_size, definitions, depth + 1)
}

fn strip_cast(expression: &Expr) -> &Expr {
    match expression {
        Expr::Cast { expr, .. } => strip_cast(expr),
        _ => expression,
    }
}

fn is_table_base(
    expression: &Expr,
    table_va: u64,
    definitions: &HashMap<VReg, Expr>,
    depth: usize,
) -> bool {
    if depth >= 16 {
        return false;
    }
    match strip_cast(expression) {
        Expr::Named { va, .. } | Expr::Addr(va) => *va == table_va,
        Expr::Reg(register) => definitions
            .get(register)
            .is_some_and(|definition| is_table_base(definition, table_va, definitions, depth + 1)),
        _ => false,
    }
}

fn scaled_index(
    expression: &Expr,
    outer_scale: u8,
    pointer_size: u8,
    definitions: &HashMap<VReg, Expr>,
    depth: usize,
) -> Option<Expr> {
    if depth >= 16 {
        return None;
    }
    if outer_scale == pointer_size {
        return Some(strip_cast(expression).clone());
    }
    if outer_scale != 1 {
        return None;
    }
    let expression = strip_cast(expression);
    match expression {
        Expr::Reg(register) => scaled_index(
            definitions.get(register)?,
            1,
            pointer_size,
            definitions,
            depth + 1,
        ),
        Expr::Bin {
            op: BinOp::Mul,
            lhs,
            rhs,
        } => {
            if matches!(strip_cast(lhs), Expr::Const(scale) if *scale == i64::from(pointer_size)) {
                Some(strip_cast(rhs).clone())
            } else if matches!(strip_cast(rhs), Expr::Const(scale) if *scale == i64::from(pointer_size))
            {
                Some(strip_cast(lhs).clone())
            } else {
                None
            }
        }
        Expr::Bin {
            op: BinOp::Shl,
            lhs,
            rhs,
        } if matches!(strip_cast(rhs), Expr::Const(shift) if (1_i64.checked_shl(*shift as u32) == Some(i64::from(pointer_size)))) => {
            Some(strip_cast(lhs).clone())
        }
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } if is_zero(lhs, definitions, depth + 1) => {
            scaled_index(rhs, 1, pointer_size, definitions, depth + 1)
        }
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } if is_zero(rhs, definitions, depth + 1) => {
            scaled_index(lhs, 1, pointer_size, definitions, depth + 1)
        }
        _ => None,
    }
}

fn is_zero(expression: &Expr, definitions: &HashMap<VReg, Expr>, depth: usize) -> bool {
    if depth >= 16 {
        return false;
    }
    match strip_cast(expression) {
        Expr::Const(0) => true,
        Expr::Reg(register) => definitions
            .get(register)
            .is_some_and(|definition| is_zero(definition, definitions, depth + 1)),
        _ => false,
    }
}
