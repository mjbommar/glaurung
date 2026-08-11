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
    let Ok(object) = crate::decompile::profile::parse_object(data) else {
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

    let relocated_targets = relocation_targets(&object, pointer_size);

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

/// `relocated place VA -> target VA` for every dynamic relocation whose target
/// this pass can prove.
fn relocation_targets(object: &object::read::File<'_>, pointer_size: u8) -> HashMap<u64, u64> {
    let mut targets = HashMap::new();
    let Some(relocations) = object.dynamic_relocations() else {
        return targets;
    };
    for (place, relocation) in relocations {
        if relocation.size() != 0 && relocation.size() != pointer_size.saturating_mul(8) {
            continue;
        }
        if let Some(target) = relocation_target_va(object, &relocation, place, pointer_size) {
            targets.insert(place, target);
        }
    }
    targets
}

/// The value an ELF `Rel` (no explicit addend) relocation carries IN PLACE.
///
/// ELF32 uses `Rel`, not `Rela`: `R_386_RELATIVE` and `R_ARM_RELATIVE` have no
/// addend field, and the value to be relocated is stored at the relocated
/// address itself. `object` reports `addend() == 0` and
/// `has_implicit_addend() == true` for them, so reading only the explicit addend
/// saw every 32-bit function-pointer table as a run of null entries and
/// recovered none of them — the `ops[tag]` dispatch in a 32-bit binary stayed a
/// load from an input-image VA that is not mapped in the rebuilt C.
fn implicit_relative_addend(
    object: &object::read::File<'_>,
    place: u64,
    pointer_size: u8,
) -> Option<u64> {
    let width = usize::from(pointer_size);
    for section in object.sections() {
        if section.address() == 0 {
            continue; // a non-allocated section: its "address" is not a VA
        }
        let Some(offset) = place.checked_sub(section.address()) else {
            continue;
        };
        if offset.saturating_add(width as u64) > section.size() {
            continue;
        }
        let (Ok(data), Ok(offset)) = (section.data(), usize::try_from(offset)) else {
            continue;
        };
        let Some(bytes) = data.get(offset..).and_then(|rest| rest.get(..width)) else {
            continue; // NOBITS (`.bss`) has a range but no file content
        };
        return match (width, object.is_little_endian()) {
            (4, true) => Some(u64::from(u32::from_le_bytes(bytes.try_into().ok()?))),
            (4, false) => Some(u64::from(u32::from_be_bytes(bytes.try_into().ok()?))),
            (8, true) => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
            (8, false) => Some(u64::from_be_bytes(bytes.try_into().ok()?)),
            _ => None,
        };
    }
    None
}

fn relocation_target_va(
    object: &object::read::File<'_>,
    relocation: &object::Relocation,
    place: u64,
    pointer_size: u8,
) -> Option<u64> {
    match relocation.target() {
        RelocationTarget::Absolute
            if is_image_relative(object.architecture(), relocation.flags()) =>
        {
            if relocation.has_implicit_addend() {
                return implicit_relative_addend(object, place, pointer_size);
            }
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
                if let Some(else_body) = else_body.as_deref_mut() {
                    resolve_body(else_body, tables, &definitions);
                }
                forget_definitions_written_in(then_body, &mut definitions);
                if let Some(else_body) = else_body.as_deref() {
                    forget_definitions_written_in(else_body, &mut definitions);
                }
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                resolve_expr(cond, tables, &definitions);
                resolve_body(body, tables, &definitions);
                forget_definitions_written_in(body, &mut definitions);
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
                forget_definitions_written_in(
                    std::slice::from_ref(init.as_ref()),
                    &mut definitions,
                );
                forget_definitions_written_in(body, &mut definitions);
                forget_definitions_written_in(
                    std::slice::from_ref(step.as_ref()),
                    &mut definitions,
                );
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                resolve_expr(discriminant, tables, &definitions);
                for (_, case) in cases.iter_mut() {
                    resolve_body(case, tables, &definitions);
                }
                if let Some(default) = default.as_deref_mut() {
                    resolve_body(default, tables, &definitions);
                }
                for (_, case) in cases.iter() {
                    forget_definitions_written_in(case, &mut definitions);
                }
                if let Some(default) = default.as_deref() {
                    forget_definitions_written_in(default, &mut definitions);
                }
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

/// Drop every definition a nested body could have overwritten, and keep the rest.
///
/// A structured statement used to `clear()` the whole table, which is sound but
/// throws away proofs the branch cannot touch. That mattered: a bounds-checked
/// dispatcher (`if (tag < 0 || tag >= 5) return -1; return ops[tag](a, b);`)
/// materialises its table base BEFORE the guards, so after two early-return
/// `if`s nothing remained to prove the base with and the 32-bit PIC `ops[tag]`
/// stayed an unresolvable load through an input-image VA.
///
/// A definition the nested body never writes still reaches the statements after
/// it. A call or indirect transfer anywhere inside it can leave any UNVERSIONED
/// physical register in an unknown state, so those are all forgotten — an
/// SSA-versioned name is defined exactly once and cannot be one of them.
fn forget_definitions_written_in(body: &[Stmt], definitions: &mut HashMap<VReg, Expr>) {
    if definitions.is_empty() {
        return;
    }
    let mut written = Vec::new();
    let clobbers_registers = collect_written(body, &mut written, 0);
    for register in written {
        definitions.remove(&register);
    }
    if clobbers_registers {
        definitions.retain(|register, _| match register {
            VReg::Phys(name) => name.contains('#'),
            _ => true,
        });
    }
}

/// Push every register `body` assigns into `out`; return whether it also
/// contains a transfer that can clobber unversioned physical registers.
fn collect_written(body: &[Stmt], out: &mut Vec<VReg>, depth: usize) -> bool {
    if depth >= 32 {
        return true; // too deep to enumerate: assume the worst
    }
    let mut clobbers = false;
    for statement in body {
        match statement {
            Stmt::Assign { dst, .. } => out.push(dst.clone()),
            Stmt::Call { .. } | Stmt::IndirectGoto { .. } => clobbers = true,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                clobbers |= collect_written(then_body, out, depth + 1);
                if let Some(else_body) = else_body {
                    clobbers |= collect_written(else_body, out, depth + 1);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                clobbers |= collect_written(body, out, depth + 1);
            }
            Stmt::For {
                init, step, body, ..
            } => {
                clobbers |= collect_written(std::slice::from_ref(init.as_ref()), out, depth + 1);
                clobbers |= collect_written(body, out, depth + 1);
                clobbers |= collect_written(std::slice::from_ref(step.as_ref()), out, depth + 1);
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    clobbers |= collect_written(case, out, depth + 1);
                }
                if let Some(default) = default {
                    clobbers |= collect_written(default, out, depth + 1);
                }
            }
            _ => {}
        }
    }
    clobbers
}

fn resolve_expr(
    expression: &mut Expr,
    tables: &[FunctionPointerTable],
    definitions: &HashMap<VReg, Expr>,
) {
    match expression {
        Expr::Deref { addr, .. } => resolve_expr(addr, tables, definitions),
        Expr::Call { target, args, .. } => {
            resolve_expr(target, tables, definitions);
            for argument in args {
                resolve_expr(argument, tables, definitions);
            }
        }
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
        // 32-bit PIC reaches its own data through a materialised
        // `_GLOBAL_OFFSET_TABLE_` base plus a link-time displacement:
        // `mov 0x10(%eax,%edx,4),%eax` with `eax` holding the GOT. The base
        // register alone is therefore NOT the table; base + disp is. Resolve
        // the register to its constant address and fold the displacement in
        // before asking whether it names the table.
        Expr::Lea {
            base: Some(base),
            index: Some(index),
            scale,
            disp,
            segment: None,
        } if *disp != 0 => {
            let base_va = constant_address(&Expr::Reg(base.clone()), definitions, depth + 1)?;
            if base_va.checked_add_signed(*disp) != Some(table_va) {
                return None;
            }
            scaled_index(
                &Expr::Reg(index.clone()),
                *scale,
                pointer_size,
                definitions,
                depth + 1,
            )
        }
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

/// The constant image address `expression` denotes, following register copies.
fn constant_address(
    expression: &Expr,
    definitions: &HashMap<VReg, Expr>,
    depth: usize,
) -> Option<u64> {
    if depth >= 16 {
        return None;
    }
    match strip_cast(expression) {
        Expr::Named { va, .. } | Expr::Addr(va) => Some(*va),
        // ARM literal-pool values reach this pass as integers. The result is
        // still checked for exact equality with a relocation-proven table VA.
        Expr::Const(value) => u64::try_from(*value).ok(),
        Expr::Reg(register) => constant_address(definitions.get(register)?, definitions, depth + 1),
        // `_GLOBAL_OFFSET_TABLE_` is materialised in two instructions
        // (`call __x86.get_pc_thunk.bx; add $GOT,%ebx`), and the pair survives
        // as two statements whenever the intermediate has a second reader — so
        // the base has to be summed here rather than relying on constant
        // folding having already collapsed it.
        Expr::Bin {
            op: BinOp::Add,
            lhs,
            rhs,
        } => {
            let (base, offset) = match (
                literal_displacement(strip_cast(lhs)),
                literal_displacement(strip_cast(rhs)),
            ) {
                (_, Some(offset)) => (strip_cast(lhs), offset),
                (Some(offset), _) => (strip_cast(rhs), offset),
                _ => return None,
            };
            constant_address(base, definitions, depth + 1)?.checked_add_signed(offset)
        }
        _ => None,
    }
}

/// Numeric displacement, independent of the lifter's address-vs-integer tag.
fn literal_displacement(expression: &Expr) -> Option<i64> {
    match expression {
        Expr::Const(value) => Some(*value),
        Expr::Addr(va) => i64::try_from(*va).ok(),
        _ => None,
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
    constant_address(expression, definitions, depth) == Some(table_va)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// ELF32 relocations are `Rel`: the value to relocate lives at the relocated
    /// address, not in an addend field. Read from a real armhf binary whose
    /// `.data` (`objdump -s -j .data`) holds `c4080000` at 0x11008 under an
    /// `R_ARM_RELATIVE` entry (`readelf -r`).
    #[test]
    fn elf32_rel_relocations_read_their_addend_from_the_relocated_place() {
        const SAMPLE: &str = "samples/binaries/platforms/linux/amd64/cross/armhf/c2_demo-armhf-gcc";
        let data = std::fs::read(SAMPLE).unwrap_or_else(|_| panic!("missing sample {SAMPLE}"));
        let object = crate::decompile::profile::parse_object(&*data).expect("parse armhf sample");
        assert_eq!(
            object.architecture().address_size().map(|s| s.bytes()),
            Some(4)
        );

        let targets = relocation_targets(&object, 4);
        assert_eq!(
            targets.get(&0x11008),
            Some(&0x8c4),
            "R_ARM_RELATIVE at 0x11008 carries its addend in place; \
             resolved targets were {:?}",
            {
                let mut sorted: Vec<_> = targets.iter().map(|(k, v)| (*k, *v)).collect();
                sorted.sort_unstable();
                sorted
            }
        );
        assert!(
            targets.values().any(|&target| target != 0),
            "every relative relocation resolved to 0 — the in-place addend was not read"
        );
    }

    fn ops_table() -> FunctionPointerTable {
        FunctionPointerTable {
            va: 0x4004,
            name: "ops".into(),
            pointer_size: 4,
            targets: vec![
                FunctionTableTarget {
                    va: 0x113d,
                    name: "h_add".into(),
                },
                FunctionTableTarget {
                    va: 0x1157,
                    name: "h_sub".into(),
                },
            ],
        }
    }

    /// `mov 0x10(%eax,%edx,4),%eax` with `eax` holding `_GLOBAL_OFFSET_TABLE_`:
    /// the base register alone is not the table, base + displacement is. This is
    /// how EVERY 32-bit PIC binary reaches its own function-pointer tables.
    #[test]
    fn a_got_relative_table_load_resolves_through_its_displacement() {
        let mut function = Function {
            name: "dispatch".into(),
            entry_va: 0x11c5,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("rax#2"),
                    src: Expr::Bin {
                        op: BinOp::Add,
                        lhs: Box::new(Expr::Addr(0x11d0)),
                        rhs: Box::new(Expr::Const(0x2e24)),
                    },
                },
                Stmt::Assign {
                    dst: VReg::phys("rax#3"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(VReg::phys("rax#2")),
                            index: Some(VReg::phys("rdx#1")),
                            scale: 4,
                            disp: 0x10,
                            segment: None,
                        }),
                        size: 4,
                    },
                },
            ],
        };

        resolve_function_table_entries(&mut function, &[ops_table()]);

        let Stmt::Assign { src, .. } = &function.body[1] else {
            panic!("statement shape changed");
        };
        assert!(
            matches!(
                src,
                Expr::FunctionTableEntry { table_va: 0x4004, table_name, .. }
                    if table_name == "ops"
            ),
            "expected the ops[] entry, got {src:?}"
        );
    }

    /// The wrong displacement names a different object and must not resolve.
    #[test]
    fn a_got_relative_load_at_the_wrong_displacement_is_left_alone() {
        let load = Expr::Deref {
            addr: Box::new(Expr::Lea {
                base: Some(VReg::phys("rax#2")),
                index: Some(VReg::phys("rdx#1")),
                scale: 4,
                disp: 0x20,
                segment: None,
            }),
            size: 4,
        };
        let mut function = Function {
            name: "dispatch".into(),
            entry_va: 0x11c5,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("rax#2"),
                    src: Expr::Addr(0x3ff4),
                },
                Stmt::Assign {
                    dst: VReg::phys("rax#3"),
                    src: load.clone(),
                },
            ],
        };

        resolve_function_table_entries(&mut function, &[ops_table()]);

        let Stmt::Assign { src, .. } = &function.body[1] else {
            panic!("statement shape changed");
        };
        assert_eq!(*src, load);
    }

    /// The table base is materialised BEFORE the bounds guards, so the proof has
    /// to survive an intervening `if` that never writes it.
    #[test]
    fn a_table_base_survives_a_guard_that_does_not_write_it() {
        let mut function = Function {
            name: "dispatch".into(),
            entry_va: 0x11c5,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("rax#2"),
                    src: Expr::Addr(0x3ff4),
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: crate::ir::types::CmpOp::Slt,
                        lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
                        rhs: Box::new(Expr::Const(0)),
                    },
                    then_body: vec![Stmt::Return {
                        value: Some(Expr::Const(-1)),
                    }],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: VReg::phys("rax#3"),
                    src: Expr::Deref {
                        addr: Box::new(Expr::Lea {
                            base: Some(VReg::phys("rax#2")),
                            index: Some(VReg::phys("rdx#1")),
                            scale: 4,
                            disp: 0x10,
                            segment: None,
                        }),
                        size: 4,
                    },
                },
            ],
        };

        resolve_function_table_entries(&mut function, &[ops_table()]);

        let Stmt::Assign { src, .. } = &function.body[2] else {
            panic!("statement shape changed");
        };
        assert!(
            matches!(src, Expr::FunctionTableEntry { .. }),
            "a guard that never writes the base erased the proof: {src:?}"
        );
    }

    /// A guard that DOES redefine the base invalidates it, as before.
    #[test]
    fn a_guard_that_rewrites_the_table_base_invalidates_it() {
        let load = Expr::Deref {
            addr: Box::new(Expr::Lea {
                base: Some(VReg::phys("rax#2")),
                index: Some(VReg::phys("rdx#1")),
                scale: 4,
                disp: 0x10,
                segment: None,
            }),
            size: 4,
        };
        let mut function = Function {
            name: "dispatch".into(),
            entry_va: 0x11c5,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("rax#2"),
                    src: Expr::Addr(0x3ff4),
                },
                Stmt::If {
                    cond: Expr::Const(1),
                    then_body: vec![Stmt::Assign {
                        dst: VReg::phys("rax#2"),
                        src: Expr::Const(0),
                    }],
                    else_body: None,
                },
                Stmt::Assign {
                    dst: VReg::phys("rax#3"),
                    src: load.clone(),
                },
            ],
        };

        resolve_function_table_entries(&mut function, &[ops_table()]);

        let Stmt::Assign { src, .. } = &function.body[2] else {
            panic!("statement shape changed");
        };
        assert_eq!(*src, load);
    }

    /// A 64-bit `Rela` image keeps using the explicit addend field.
    #[test]
    fn elf64_rela_relocations_still_use_the_explicit_addend() {
        const SAMPLE: &str =
            "samples/binaries/platforms/linux/amd64/export/native/gcc/O0/hello-c-gcc-O0";
        let data = std::fs::read(SAMPLE).unwrap_or_else(|_| panic!("missing sample {SAMPLE}"));
        let object = crate::decompile::profile::parse_object(&*data).expect("parse amd64 sample");
        let targets = relocation_targets(&object, 8);
        assert!(
            targets.values().any(|&target| target != 0),
            "no relative relocation resolved on a RELA image"
        );
    }

    #[test]
    fn arm32_literal_pool_table_base_resolves_to_the_table() {
        const TABLE_VA: u64 = 0x20028;
        let (pool, base, index) = (VReg::phys("r3#3"), VReg::phys("r3#4"), VReg::phys("r2#1"));
        let mut definitions: HashMap<VReg, Expr> = HashMap::new();
        definitions.insert(pool.clone(), Expr::Const(0x1fb88));
        definitions.insert(
            base.clone(),
            Expr::Bin {
                op: BinOp::Add,
                lhs: Box::new(Expr::Reg(pool)),
                rhs: Box::new(Expr::Addr(0x4a0)),
            },
        );

        assert_eq!(
            constant_address(&Expr::Reg(base.clone()), &definitions, 0),
            Some(TABLE_VA)
        );
        assert!(is_table_base(
            &Expr::Reg(base.clone()),
            TABLE_VA,
            &definitions,
            0
        ));
        let address = Expr::Lea {
            base: Some(base),
            index: Some(index.clone()),
            scale: 4,
            disp: 0,
            segment: None,
        };
        assert_eq!(
            indexed_table_address(&address, TABLE_VA, 4, &definitions, 0),
            Some(Expr::Reg(index))
        );
    }

    #[test]
    fn a_constant_base_that_is_not_the_table_does_not_match() {
        const TABLE_VA: u64 = 0x20028;
        let base = VReg::phys("r3#4");
        let mut definitions: HashMap<VReg, Expr> = HashMap::new();
        definitions.insert(base.clone(), Expr::Const(0x20030));

        assert!(!is_table_base(
            &Expr::Reg(base.clone()),
            TABLE_VA,
            &definitions,
            0
        ));
        let address = Expr::Lea {
            base: Some(base),
            index: Some(VReg::phys("r2#1")),
            scale: 4,
            disp: 0,
            segment: None,
        };
        assert_eq!(
            indexed_table_address(&address, TABLE_VA, 4, &definitions, 0),
            None
        );
    }
}
