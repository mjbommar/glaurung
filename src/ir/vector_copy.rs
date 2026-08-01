//! Recover complete 128-bit memory copies from untouched packed XMM lanes.
//!
//! The x86 lifter represents packed arithmetic as four independent dword
//! lanes.  That is necessary for lane-wise operations, but a plain MOVUPS
//! load followed by a MOVUPS store is one 16-byte transport.  Rejoining only
//! the exact load/store batches keeps that identity available to the C backend
//! without hiding any intervening packed computation.

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::types::VReg;

#[derive(Clone)]
struct LaneLoad {
    wide: VReg,
    address: Expr,
}

fn lane_name(register: &VReg) -> Option<(String, usize)> {
    let VReg::Phys(name) = register else {
        return None;
    };
    let (wide, lane_and_version) = name.rsplit_once("_d")?;
    if !wide.starts_with("xmm") {
        return None;
    }
    let (lane, version) = lane_and_version
        .split_once('#')
        .map_or((lane_and_version, None), |(lane, version)| {
            (lane, Some(version))
        });
    let wide = version.map_or_else(|| wide.to_string(), |version| format!("{wide}#{version}"));
    Some((wide, lane.parse().ok()?))
}

fn adjacent_address(first: &Expr, candidate: &Expr, delta: i64) -> bool {
    let (
        Expr::Lea {
            base: first_base,
            index: first_index,
            scale: first_scale,
            disp: first_disp,
            segment: first_segment,
        },
        Expr::Lea {
            base,
            index,
            scale,
            disp,
            segment,
        },
    ) = (first, candidate)
    else {
        return false;
    };
    base == first_base
        && index == first_index
        && scale == first_scale
        && segment == first_segment
        && *disp == first_disp.saturating_add(delta)
}

fn load_batch_at(body: &[Stmt], start: usize) -> Option<LaneLoad> {
    let batch = body.get(start..start + 4)?;
    let Stmt::Assign {
        dst: first_dst,
        src: Expr::Deref {
            addr: first_addr,
            size: 4,
        },
    } = &batch[0]
    else {
        return None;
    };
    let (wide, first_lane) = lane_name(first_dst)?;
    if first_lane != 0 {
        return None;
    }
    for (lane, statement) in batch.iter().enumerate() {
        let Stmt::Assign {
            dst,
            src: Expr::Deref { addr, size: 4 },
        } = statement
        else {
            return None;
        };
        if lane_name(dst) != Some((wide.clone(), lane))
            || !adjacent_address(first_addr, addr, (lane * 4) as i64)
        {
            return None;
        }
    }
    Some(LaneLoad {
        wide: VReg::phys(wide),
        address: first_addr.as_ref().clone(),
    })
}

fn lane_store_batch_at(body: &[Stmt], start: usize) -> Option<(VReg, Expr)> {
    let batch = body.get(start..start + 4)?;
    let Stmt::Store {
        addr: first_addr,
        src: Expr::Reg(first_src),
        size: 4,
    } = &batch[0]
    else {
        return None;
    };
    let (wide_name, first_lane) = lane_name(first_src)?;
    if first_lane != 0 {
        return None;
    }
    for (lane, statement) in batch.iter().enumerate() {
        let Stmt::Store {
            addr,
            src: Expr::Reg(src),
            size: 4,
        } = statement
        else {
            return None;
        };
        if lane_name(src) != Some((wide_name.clone(), lane))
            || !adjacent_address(first_addr, addr, (lane * 4) as i64)
        {
            return None;
        }
    }
    Some((VReg::phys(wide_name), first_addr.clone()))
}

fn store_batch_at(body: &[Stmt], start: usize, wide: &VReg) -> Option<Expr> {
    let (candidate_wide, address) = lane_store_batch_at(body, start)?;
    (candidate_wide == *wide).then_some(address)
}

fn recover_body(body: &mut Vec<Stmt>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_body(then_body);
                if let Some(else_body) = else_body {
                    recover_body(else_body);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => recover_body(body),
            Stmt::For { body, .. } => recover_body(body),
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    recover_body(case);
                }
                if let Some(default) = default {
                    recover_body(default);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                recover_body(try_body);
                for catch in catches {
                    recover_body(&mut catch.body);
                }
            }
            _ => {}
        }
    }

    let mut replacements = Vec::new();
    for index in 0..body.len().saturating_sub(7) {
        let Some(load) = load_batch_at(body, index) else {
            continue;
        };
        let store_index = if store_batch_at(body, index + 4, &load.wide).is_some() {
            Some(index + 4)
        } else if (load_batch_at(body, index + 4).is_some_and(|other| other.wide != load.wide)
            || lane_store_batch_at(body, index + 4).is_some_and(|(other, _)| other != load.wide))
            && store_batch_at(body, index + 8, &load.wide).is_some()
        {
            Some(index + 8)
        } else {
            None
        };
        let Some(store_index) = store_index else {
            continue;
        };
        let destination = store_batch_at(body, store_index, &load.wide)
            .expect("candidate store batch was checked");
        replacements.push((
            store_index,
            Stmt::Store {
                addr: destination,
                src: Expr::Reg(load.wide.clone()),
                size: 16,
            },
        ));
        replacements.push((
            index,
            Stmt::Assign {
                dst: load.wide,
                src: Expr::Deref {
                    addr: Box::new(load.address),
                    size: 16,
                },
            },
        ));
    }
    replacements.sort_by_key(|(start, _)| std::cmp::Reverse(*start));
    for (start, statement) in replacements {
        body.splice(start..start + 4, [statement]);
    }
}

/// Rejoin exact four-lane load/store batches into one 128-bit copy.
pub fn recover_wide_copies(function: &mut Function) {
    recover_body(&mut function.body);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(base: &str, disp: i64) -> Expr {
        Expr::Lea {
            base: Some(VReg::phys(base)),
            index: Some(VReg::phys("rax")),
            scale: 4,
            disp,
            segment: None,
        }
    }

    #[test]
    fn rejoins_two_interleaved_plain_vector_transports() {
        let mut body = Vec::new();
        for register in ["xmm0", "xmm1"] {
            let base_disp = if register == "xmm0" { 0 } else { 16 };
            for lane in 0..4 {
                body.push(Stmt::Assign {
                    dst: VReg::phys(format!("{register}_d{lane}")),
                    src: Expr::Deref {
                        addr: Box::new(address("rsi", base_disp + lane * 4)),
                        size: 4,
                    },
                });
            }
        }
        for register in ["xmm0", "xmm1"] {
            let base_disp = if register == "xmm0" { 0 } else { 16 };
            for lane in 0..4 {
                body.push(Stmt::Store {
                    addr: address("rdi", base_disp + lane * 4),
                    src: Expr::Reg(VReg::phys(format!("{register}_d{lane}"))),
                    size: 4,
                });
            }
        }
        let mut function = Function {
            name: "copy".into(),
            entry_va: 0,
            body,
        };

        recover_wide_copies(&mut function);

        assert_eq!(function.body.len(), 4, "{:#?}", function.body);
        assert!(matches!(
            &function.body[0],
            Stmt::Assign { dst: VReg::Phys(name), src: Expr::Deref { size: 16, .. } }
                if name == "xmm0"
        ));
        assert!(matches!(
            &function.body[2],
            Stmt::Store { src: Expr::Reg(VReg::Phys(name)), size: 16, .. }
                if name == "xmm0"
        ));
    }

    #[test]
    fn leaves_lane_computation_between_load_and_store_explicit() {
        let mut body = Vec::new();
        for lane in 0..4 {
            body.push(Stmt::Assign {
                dst: VReg::phys(format!("xmm0_d{lane}")),
                src: Expr::Deref {
                    addr: Box::new(address("rsi", lane * 4)),
                    size: 4,
                },
            });
        }
        body.push(Stmt::Assign {
            dst: VReg::phys("xmm0_d0"),
            src: Expr::Const(0),
        });
        for lane in 0..4 {
            body.push(Stmt::Store {
                addr: address("rdi", lane * 4),
                src: Expr::Reg(VReg::phys(format!("xmm0_d{lane}"))),
                size: 4,
            });
        }
        let original = body.clone();
        let mut function = Function {
            name: "computed".into(),
            entry_va: 0,
            body,
        };

        recover_wide_copies(&mut function);

        assert_eq!(function.body, original);
    }
}
