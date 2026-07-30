//! Lift bounded read-only lookup-table loads into portable AST expressions.
//!
//! Optimising compilers commonly lower a switch whose arms only return constants
//! to a range guard followed by a load from `.rodata`.  Rendering the load as
//! `*(int *)(0x20ac + index * 4)` preserves the original image's address but not
//! standalone C semantics: the recompiled function has no object mapped at that
//! link-time VA.  This pass retains the original load as a fail-closed fallback
//! and materialises each guard-proven table entry as a conditional value.  C's
//! conditional operator evaluates only the selected arm, so every in-range load
//! is portable while an unproved index keeps the original machine expression.

use std::collections::HashMap;

use object::{Object, ObjectSection};

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::{BinOp, CmpOp, VReg};

const MAX_GUARDED_ENTRIES: usize = 64;

#[derive(Debug, Clone)]
struct ReadonlyRegion {
    base: u64,
    bytes: Vec<u8>,
}

/// Read-only object bytes addressed by their image VAs.
#[derive(Debug, Clone, Default)]
pub struct ReadonlyData {
    regions: Vec<ReadonlyRegion>,
    little_endian: bool,
}

/// Collect constant-data sections once per input object.
pub fn collect_readonly_data(data: &[u8]) -> ReadonlyData {
    let Ok(object) = object::read::File::parse(data) else {
        return ReadonlyData::default();
    };
    let little_endian = object.is_little_endian();
    let mut regions = Vec::new();
    for section in object.sections() {
        let name = section.name().unwrap_or("").to_ascii_lowercase();
        let readonly_data = name == ".rodata"
            || name == ".rdata"
            || name.contains("rodata")
            || name.contains("__const")
            || name == "__text.__const";
        if !readonly_data {
            continue;
        }
        let Ok(bytes) = section.data() else {
            continue;
        };
        if !bytes.is_empty() {
            regions.push(ReadonlyRegion {
                base: section.address(),
                bytes: bytes.to_vec(),
            });
        }
    }
    ReadonlyData {
        regions,
        little_endian,
    }
}

impl ReadonlyData {
    fn read_integer(&self, address: u64, width: u8) -> Option<i64> {
        if !matches!(width, 1 | 2 | 4 | 8) {
            return None;
        }
        let region = self.regions.iter().find(|region| {
            address >= region.base
                && address
                    .checked_add(u64::from(width))
                    .is_some_and(|end| end <= region.base.saturating_add(region.bytes.len() as u64))
        })?;
        let offset = usize::try_from(address.checked_sub(region.base)?).ok()?;
        let slice = region.bytes.get(offset..offset + usize::from(width))?;
        let mut bytes = [0u8; 8];
        if self.little_endian {
            bytes[..slice.len()].copy_from_slice(slice);
            let value = u64::from_le_bytes(bytes);
            (value <= i64::MAX as u64).then_some(value as i64)
        } else {
            bytes[8 - slice.len()..].copy_from_slice(slice);
            let value = u64::from_be_bytes(bytes);
            (value <= i64::MAX as u64).then_some(value as i64)
        }
    }
}

#[derive(Debug, Clone)]
struct Guard {
    index_root: String,
    inclusive_max: usize,
}

/// Replace guard-bounded reads from constant tables with portable values.
pub fn fold_guarded_readonly_lookups(function: &mut Function, data: &ReadonlyData) {
    if data.regions.is_empty() {
        return;
    }
    fold_body(&mut function.body, data, &HashMap::new(), None);
}

fn fold_body(
    body: &mut [Stmt],
    data: &ReadonlyData,
    inherited_aliases: &HashMap<String, String>,
    active_guard: Option<&Guard>,
) {
    let mut aliases = inherited_aliases.clone();
    let mut current_guard = active_guard.cloned();
    for statement in body {
        match statement {
            Stmt::Assign {
                dst: VReg::Phys(dst),
                src,
            } => {
                fold_expr(src, data, &aliases, current_guard.as_ref());
                if let Some(source) = source_register(src) {
                    aliases.insert(dst.clone(), resolve_alias(source, &aliases));
                } else {
                    aliases.remove(dst);
                }
                if current_guard
                    .as_ref()
                    .is_some_and(|guard| guard.index_root == *dst)
                {
                    current_guard = None;
                }
            }
            Stmt::Assign { src, .. } => fold_expr(src, data, &aliases, current_guard.as_ref()),
            Stmt::Store { addr, src, .. } => {
                fold_expr(addr, data, &aliases, current_guard.as_ref());
                fold_expr(src, data, &aliases, current_guard.as_ref());
            }
            Stmt::Call {
                target, args, dst, ..
            } => {
                fold_expr(target, data, &aliases, current_guard.as_ref());
                for argument in args {
                    fold_expr(argument, data, &aliases, current_guard.as_ref());
                }
                if let Some(VReg::Phys(dst)) = dst {
                    aliases.remove(dst);
                    if current_guard
                        .as_ref()
                        .is_some_and(|guard| guard.index_root == *dst)
                    {
                        current_guard = None;
                    }
                }
            }
            Stmt::Return { value: Some(value) } | Stmt::Push { value } => {
                fold_expr(value, data, &aliases, current_guard.as_ref())
            }
            Stmt::IndirectGoto { target } => {
                fold_expr(target, data, &aliases, current_guard.as_ref())
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                fold_expr(cond, data, &aliases, current_guard.as_ref());
                let guard = bounded_guard(cond, &aliases);
                fold_body(
                    then_body,
                    data,
                    &aliases,
                    guard.as_ref().or(current_guard.as_ref()),
                );
                if let Some(else_body) = else_body {
                    fold_body(else_body, data, &aliases, current_guard.as_ref());
                }
                // Definitions in either branch need a join proof before aliases
                // or an enclosing bound can be reused after the conditional.
                aliases.clear();
                current_guard = None;
            }
            Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
                fold_expr(cond, data, &aliases, current_guard.as_ref());
                // A loop body can change its index before a later iteration's
                // lookup. Only guards recovered inside that iteration may fold.
                fold_body(body, data, &HashMap::new(), None);
                aliases.clear();
                current_guard = None;
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                fold_body(std::slice::from_mut(init.as_mut()), data, &aliases, None);
                fold_expr(cond, data, &aliases, None);
                fold_body(body, data, &HashMap::new(), None);
                fold_body(std::slice::from_mut(step.as_mut()), data, &aliases, None);
                aliases.clear();
                current_guard = None;
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                fold_expr(discriminant, data, &aliases, current_guard.as_ref());
                for (_, case) in cases {
                    // Cases can fall through, so a sibling's writes make inherited
                    // alias/guard state unsafe without explicit case-edge SSA.
                    fold_body(case, data, &HashMap::new(), None);
                }
                if let Some(default) = default {
                    fold_body(default, data, &HashMap::new(), None);
                }
                aliases.clear();
                current_guard = None;
            }
            Stmt::Pop {
                target: VReg::Phys(dst),
            } => {
                aliases.remove(dst);
                if current_guard
                    .as_ref()
                    .is_some_and(|guard| guard.index_root == *dst)
                {
                    current_guard = None;
                }
            }
            Stmt::Goto { .. } | Stmt::Label(_) | Stmt::Break => {
                aliases.clear();
                current_guard = None;
            }
            Stmt::Return { value: None }
            | Stmt::Pop { .. }
            | Stmt::Nop
            | Stmt::Unknown(_)
            | Stmt::Comment(_) => {}
        }
    }
}

fn fold_expr(
    expression: &mut Expr,
    data: &ReadonlyData,
    aliases: &HashMap<String, String>,
    active_guard: Option<&Guard>,
) {
    match expression {
        Expr::Deref { addr, size } => {
            fold_expr(addr, data, aliases, active_guard);
            let Some(guard) = active_guard else {
                return;
            };
            let Some((base, index)) = indexed_address(addr, *size) else {
                return;
            };
            let Some(index_name) = source_register(&index) else {
                return;
            };
            if resolve_alias(index_name, aliases) != guard.index_root {
                return;
            }
            let count = guard.inclusive_max.saturating_add(1);
            if count == 0 || count > MAX_GUARDED_ENTRIES {
                return;
            }
            let mut values = Vec::with_capacity(count);
            for slot in 0..count {
                let Some(address) =
                    base.checked_add((slot as u64).saturating_mul(u64::from(*size)))
                else {
                    return;
                };
                let Some(value) = data.read_integer(address, *size) else {
                    return;
                };
                values.push(value);
            }
            let lookup_width = *size;
            let mut replacement = Expr::Deref {
                addr: addr.clone(),
                size: lookup_width,
            };
            for (slot, value) in values.into_iter().enumerate().rev() {
                replacement = Expr::Select {
                    cond: Box::new(Expr::Cmp {
                        op: CmpOp::Eq,
                        lhs: Box::new(index.clone()),
                        rhs: Box::new(Expr::Const(slot as i64)),
                    }),
                    if_true: Box::new(Expr::Const(value)),
                    if_false: Box::new(replacement),
                    width: lookup_width,
                };
            }
            *expression = replacement;
        }
        Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
            fold_expr(lhs, data, aliases, active_guard);
            fold_expr(rhs, data, aliases, active_guard);
        }
        Expr::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            fold_expr(cond, data, aliases, active_guard);
            fold_expr(if_true, data, aliases, active_guard);
            fold_expr(if_false, data, aliases, active_guard);
        }
        Expr::Un { src, .. } | Expr::Cast { expr: src, .. } => {
            fold_expr(src, data, aliases, active_guard)
        }
        Expr::Addr(_)
        | Expr::Named { .. }
        | Expr::StringLit { .. }
        | Expr::StackAddr { .. }
        | Expr::Reg(_)
        | Expr::Const(_)
        | Expr::FloatConst { .. }
        | Expr::Lea { .. }
        | Expr::PdbFieldAddr { .. }
        | Expr::Unknown(_) => {}
    }
}

fn bounded_guard(condition: &Expr, aliases: &HashMap<String, String>) -> Option<Guard> {
    let Expr::Cmp { op, lhs, rhs } = condition else {
        return None;
    };
    let inclusive_max = match op {
        CmpOp::Ule => constant_usize(rhs)?,
        CmpOp::Ult => constant_usize(rhs)?.checked_sub(1)?,
        _ => return None,
    };
    if inclusive_max >= MAX_GUARDED_ENTRIES {
        return None;
    }
    let index = source_register(lhs)?;
    Some(Guard {
        index_root: resolve_alias(index, aliases),
        inclusive_max,
    })
}

fn indexed_address(address: &Expr, width: u8) -> Option<(u64, Expr)> {
    let Expr::Bin {
        op: BinOp::Add,
        lhs,
        rhs,
    } = strip_casts(address)
    else {
        return None;
    };
    if let Some(base) = constant_u64(lhs) {
        return scaled_index(rhs, width).map(|index| (base, index));
    }
    let base = constant_u64(rhs)?;
    scaled_index(lhs, width).map(|index| (base, index))
}

fn scaled_index(expression: &Expr, width: u8) -> Option<Expr> {
    let Expr::Bin {
        op: BinOp::Mul,
        lhs,
        rhs,
    } = strip_casts(expression)
    else {
        return (width == 1).then(|| expression.clone());
    };
    if constant_u64(lhs) == Some(u64::from(width)) {
        return Some((**rhs).clone());
    }
    if constant_u64(rhs) == Some(u64::from(width)) {
        return Some((**lhs).clone());
    }
    None
}

fn strip_casts(mut expression: &Expr) -> &Expr {
    while let Expr::Cast { expr, .. } = expression {
        expression = expr;
    }
    expression
}

fn source_register(expression: &Expr) -> Option<&str> {
    match strip_casts(expression) {
        Expr::Reg(VReg::Phys(name)) => Some(name),
        _ => None,
    }
}

fn resolve_alias(name: &str, aliases: &HashMap<String, String>) -> String {
    let mut current = name;
    for _ in 0..=aliases.len() {
        let Some(next) = aliases.get(current) else {
            break;
        };
        if next == current {
            break;
        }
        current = next;
    }
    current.to_string()
}

fn constant_u64(expression: &Expr) -> Option<u64> {
    match strip_casts(expression) {
        Expr::Addr(address) => Some(*address),
        Expr::Named { va, .. } => Some(*va),
        Expr::Const(value) => u64::try_from(*value).ok(),
        _ => None,
    }
}

fn constant_usize(expression: &Expr) -> Option<usize> {
    usize::try_from(constant_u64(expression)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_pinned_switch_result_table_from_real_elf() {
        let path =
            std::path::Path::new("tests/decompiler_fixtures/build/04_switch_shapes-clang-O2.so");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(path).expect("read pinned switch fixture");
        let data = collect_readonly_data(&bytes);
        assert_eq!(
            constant_u64(&Expr::Named {
                va: 0x2080,
                name: "CSWTCH.5".into(),
            }),
            Some(0x2080)
        );
        assert_eq!(data.read_integer(0x20ac, 4), Some(303));
        assert_eq!(data.read_integer(0x20b0, 4), Some(399));
        assert_eq!(data.read_integer(0x20c0, 4), Some(302));
    }

    #[test]
    fn guarded_alias_lookup_materialises_readonly_values_with_fallback() {
        let mut section_bytes = vec![0u8; 0xac];
        section_bytes.extend([303u32, 399, 301].into_iter().flat_map(u32::to_le_bytes));
        let data = ReadonlyData {
            regions: vec![ReadonlyRegion {
                base: 0x2000,
                bytes: section_bytes,
            }],
            little_endian: true,
        };
        let mut function = Function {
            name: "lookup".into(),
            entry_va: 0,
            body: vec![
                Stmt::Assign {
                    dst: VReg::phys("var1"),
                    src: Expr::Cast {
                        signed: false,
                        width: 8,
                        expr: Box::new(Expr::Cast {
                            signed: false,
                            width: 4,
                            expr: Box::new(Expr::Reg(VReg::phys("var0"))),
                        }),
                    },
                },
                Stmt::If {
                    cond: Expr::Cmp {
                        op: CmpOp::Ule,
                        lhs: Box::new(Expr::Cast {
                            signed: false,
                            width: 8,
                            expr: Box::new(Expr::Cast {
                                signed: false,
                                width: 4,
                                expr: Box::new(Expr::Reg(VReg::phys("var0"))),
                            }),
                        }),
                        rhs: Box::new(Expr::Const(2)),
                    },
                    then_body: vec![Stmt::Assign {
                        dst: VReg::phys("ret"),
                        src: Expr::Deref {
                            addr: Box::new(Expr::Bin {
                                op: BinOp::Add,
                                lhs: Box::new(Expr::Addr(0x20ac)),
                                rhs: Box::new(Expr::Bin {
                                    op: BinOp::Mul,
                                    lhs: Box::new(Expr::Cast {
                                        signed: true,
                                        width: 8,
                                        expr: Box::new(Expr::Cast {
                                            signed: true,
                                            width: 4,
                                            expr: Box::new(Expr::Reg(VReg::phys("var1"))),
                                        }),
                                    }),
                                    rhs: Box::new(Expr::Const(4)),
                                }),
                            }),
                            size: 4,
                        },
                    }],
                    else_body: None,
                },
            ],
        };
        let mut call_clobbered = function.clone();
        call_clobbered.body.insert(
            1,
            Stmt::Call {
                target: Expr::Named {
                    va: 0x1000,
                    name: "next_index".into(),
                },
                args: vec![],
                dst: Some(VReg::phys("var1")),
                call_spec: None,
            },
        );
        let mut guard_clobbered = function.clone();
        let Stmt::If { then_body, .. } = &mut guard_clobbered.body[1] else {
            panic!("expected guarded lookup");
        };
        then_body.insert(
            0,
            Stmt::Assign {
                dst: VReg::phys("var0"),
                src: Expr::Const(99),
            },
        );

        fold_guarded_readonly_lookups(&mut function, &data);
        fold_guarded_readonly_lookups(&mut call_clobbered, &data);
        fold_guarded_readonly_lookups(&mut guard_clobbered, &data);

        let rendered = crate::ir::ast::render(&function);
        assert!(rendered.contains("303"), "{rendered}");
        assert!(rendered.contains("399"), "{rendered}");
        assert!(rendered.contains("301"), "{rendered}");
        assert!(rendered.contains("?"), "{rendered}");
        assert!(
            rendered.contains("0x20ac"),
            "fallback load must remain:\n{rendered}"
        );
        let clobbered = crate::ir::ast::render(&call_clobbered);
        assert!(
            !clobbered.contains("?"),
            "stale alias folded after call:\n{clobbered}"
        );
        assert!(clobbered.contains("0x20ac"), "{clobbered}");
        let invalid_guard = crate::ir::ast::render(&guard_clobbered);
        assert!(
            !invalid_guard.contains("?"),
            "lookup folded after guard root changed:\n{invalid_guard}"
        );
    }
}
