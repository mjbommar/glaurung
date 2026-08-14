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

/// The whole-register name a lifted scalar-view bridge defines.
///
/// `synchronise_xmm_views` (`src/ir/lift_x86.rs`) appends
/// `Op::Concat { dst: xmmN, hi: xmmN_d1, lo: xmmN_d0 }` to any instruction that
/// wrote lanes but not the whole-register name, so a later scalar read still
/// sees a defined value. It runs per instruction and therefore cannot know
/// whether that view is ever read; a plain 128-bit `movups` load gets one
/// unconditionally. Lowered, the concat is `dst = hi | lo`.
fn scalar_view_bridge_target(statement: &Stmt) -> Option<String> {
    let Stmt::Assign {
        dst: VReg::Phys(dst),
        src:
            Expr::Bin {
                op: crate::ir::types::BinOp::Or,
                lhs,
                rhs,
            },
    } = statement
    else {
        return None;
    };
    if !dst.starts_with("xmm") {
        return None;
    }
    let (Expr::Reg(hi), Expr::Reg(lo)) = (lhs.as_ref(), rhs.as_ref()) else {
        return None;
    };
    (lane_name(hi) == Some((dst.clone(), 1)) && lane_name(lo) == Some((dst.clone(), 0)))
        .then(|| dst.clone())
}

/// Whether `register` is read anywhere in `body`, at any nesting depth.
///
/// Deliberately whole-function and deliberately coarse: a bridge is skipped
/// only when its scalar view is read nowhere at all. Rejoining the lanes stops
/// defining `xmmN_d0`/`xmmN_d1`, so a bridge that survived the rejoin would
/// overwrite the recovered value with undefined operands. Over-approximating
/// the reads fails closed, keeping the explicit lane form.
///
/// `dead_stores::stmt_reads` already walks every statement and expression
/// shape, including nested bodies; duplicating that match here would only add
/// a second place to forget a variant.
fn reads_register(body: &[Stmt], register: &VReg) -> bool {
    body.iter().any(|statement| {
        // A bridge's own read of its lanes is not a read of the view itself.
        if scalar_view_bridge_target(statement)
            .is_some_and(|target| matches!(register, VReg::Phys(name) if *name == target))
        {
            return false;
        }
        crate::ir::dead_stores::stmt_reads(statement, register)
    })
}

/// Whole-register xmm views that a bridge defines and nothing ever reads.
///
/// Computed once over the whole function, because `recover_body` recurses into
/// nested bodies and a read may live in any of them.
fn dead_scalar_views(body: &[Stmt]) -> std::collections::HashSet<String> {
    fn collect(body: &[Stmt], out: &mut std::collections::HashSet<String>) {
        for statement in body {
            if let Some(target) = scalar_view_bridge_target(statement) {
                out.insert(target);
            }
            for nested in child_bodies(statement) {
                collect(nested, out);
            }
        }
    }
    fn read_anywhere(body: &[Stmt], register: &VReg) -> bool {
        reads_register(body, register)
            || body.iter().any(|statement| {
                child_bodies(statement)
                    .into_iter()
                    .any(|nested| read_anywhere(nested, register))
            })
    }
    let mut targets = std::collections::HashSet::new();
    collect(body, &mut targets);
    targets.retain(|name| !read_anywhere(body, &VReg::phys(name)));
    targets
}

fn child_bodies(statement: &Stmt) -> Vec<&Vec<Stmt>> {
    match statement {
        Stmt::If {
            then_body,
            else_body,
            ..
        } => std::iter::once(then_body)
            .chain(else_body.as_ref())
            .collect(),
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
            vec![body]
        }
        Stmt::Switch { cases, default, .. } => cases
            .iter()
            .map(|(_, case)| case)
            .chain(default.as_ref())
            .collect(),
        Stmt::TryCatch { try_body, catches } => std::iter::once(try_body)
            .chain(catches.iter().map(|catch| &catch.body))
            .collect(),
        _ => Vec::new(),
    }
}

/// Delete every provably-dead scalar-view bridge, at any nesting depth.
///
/// Done as a pre-pass so the batch matcher below never has to reason about
/// bridges at all. Removing a definition nothing reads is correct on its own
/// terms; it also happens to be required, because rejoining the lanes stops
/// defining `xmmN_d0`/`xmmN_d1` and a surviving bridge would then overwrite the
/// recovered value with undefined operands.
fn drop_dead_scalar_views(body: &mut Vec<Stmt>, dead: &std::collections::HashSet<String>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                drop_dead_scalar_views(then_body, dead);
                if let Some(else_body) = else_body {
                    drop_dead_scalar_views(else_body, dead);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } | Stmt::For { body, .. } => {
                drop_dead_scalar_views(body, dead)
            }
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    drop_dead_scalar_views(case, dead);
                }
                if let Some(default) = default {
                    drop_dead_scalar_views(default, dead);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                drop_dead_scalar_views(try_body, dead);
                for catch in catches {
                    drop_dead_scalar_views(&mut catch.body, dead);
                }
            }
            _ => {}
        }
    }
    body.retain(|statement| {
        !scalar_view_bridge_target(statement).is_some_and(|target| dead.contains(&target))
    });
}

/// How many statements anywhere in `body` read `register`.
///
/// Used to prove a lane batch has exactly one consumer. Counting statements
/// rather than occurrences is enough: the store batch reads each lane once, so
/// a second consumer of any kind pushes the count above one.
fn count_reading_statements(body: &[Stmt], register: &VReg) -> usize {
    body.iter()
        .map(|statement| {
            usize::from(crate::ir::dead_stores::stmt_reads(statement, register))
                + child_bodies(statement)
                    .into_iter()
                    .map(|nested| count_reading_statements(nested, register))
                    .sum::<usize>()
        })
        .sum()
}

/// Wide registers whose lane values have exactly one reader each.
///
/// `recover_wide_copies` replaces four lane loads with one 16-byte load into
/// the whole-register name, which stops defining the lanes. That is only sound
/// when nothing else reads them. `188_vector_transport::vt188_copy_two_streams`
/// copies one source into TWO destinations, so clang emits one load batch
/// feeding two store batches; rejoining the first pair left the second store
/// reading lanes nothing defines any more, and it silently wrote garbage.
///
/// The actual lane `VReg`s are collected rather than rebuilt from the wide
/// name. `lane_name` folds a value version into the wide half — `xmm0_d0#3`
/// parses to wide `xmm0#3`, lane 0 — so `format!("{wide}_d{lane}")` yields
/// `xmm0#3_d0`, which names nothing and silently made every batch look
/// exclusive.
///
/// Counted once up front: this pass only removes and replaces statements, so a
/// count taken before mutation still decides correctly.
fn exclusive_lane_registers(body: &[Stmt]) -> std::collections::HashSet<String> {
    fn collect(
        body: &[Stmt],
        out: &mut std::collections::HashMap<String, std::collections::BTreeSet<VReg>>,
    ) {
        for statement in body {
            if let Stmt::Assign { dst, .. } = statement {
                if let Some((wide, _)) = lane_name(dst) {
                    out.entry(wide).or_default().insert(dst.clone());
                }
            }
            for nested in child_bodies(statement) {
                collect(nested, out);
            }
        }
    }
    let mut lanes: std::collections::HashMap<String, std::collections::BTreeSet<VReg>> =
        std::collections::HashMap::new();
    collect(body, &mut lanes);
    lanes
        .into_iter()
        .filter(|(_, registers)| {
            registers
                .iter()
                .all(|register| count_reading_statements(body, register) <= 1)
        })
        .map(|(wide, _)| wide)
        .collect()
}

fn recover_body(body: &mut Vec<Stmt>, exclusive: &std::collections::HashSet<String>) {
    for statement in body.iter_mut() {
        match statement {
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                recover_body(then_body, exclusive);
                if let Some(else_body) = else_body {
                    recover_body(else_body, exclusive);
                }
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => recover_body(body, exclusive),
            Stmt::For { body, .. } => recover_body(body, exclusive),
            Stmt::Switch { cases, default, .. } => {
                for (_, case) in cases {
                    recover_body(case, exclusive);
                }
                if let Some(default) = default {
                    recover_body(default, exclusive);
                }
            }
            Stmt::TryCatch { try_body, catches } => {
                recover_body(try_body, exclusive);
                for catch in catches {
                    recover_body(&mut catch.body, exclusive);
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
        // Rejoining stops defining the lanes, so a second consumer would be
        // left reading values nothing writes.
        if !matches!(&load.wide, VReg::Phys(name) if exclusive.contains(name)) {
            continue;
        }
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
    let dead = dead_scalar_views(&function.body);
    if !dead.is_empty() {
        drop_dead_scalar_views(&mut function.body, &dead);
    }
    let exclusive = exclusive_lane_registers(&function.body);
    recover_body(&mut function.body, &exclusive);
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

    /// The lowered form of `synchronise_xmm_views`' scalar-view bridge:
    /// `Op::Concat { dst, hi, lo }` becomes `dst = hi | lo`.
    fn scalar_view_bridge(register: &str) -> Stmt {
        Stmt::Assign {
            dst: VReg::phys(register),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Or,
                lhs: Box::new(Expr::Reg(VReg::phys(format!("{register}_d1")))),
                rhs: Box::new(Expr::Reg(VReg::phys(format!("{register}_d0")))),
            },
        }
    }

    fn is_scalar_view_bridge(statement: &Stmt) -> bool {
        super::scalar_view_bridge_target(statement).is_some()
    }

    /// Lane loads, the lifter's scalar-view bridge, then lane stores.
    ///
    /// `synchronise_xmm_views` (src/ir/lift_x86.rs) appends
    /// `%xmm0 = concat %xmm0_d1:%xmm0_d0` to any instruction that wrote lanes
    /// but not the whole-register name, so a later scalar read sees a defined
    /// value. It runs per INSTRUCTION, so it cannot know whether the scalar view
    /// is ever read, and a plain 128-bit `movups` load gets one unconditionally.
    /// Lowered it is `xmm0 = xmm0_d1 | xmm0_d0`, and it lands exactly where this
    /// pass expects the store batch, so the 16-byte transport was never
    /// recovered and `__builtin_memmove` folding downstream never fired.
    ///
    /// This pass must run before copy propagation erases the transport
    /// identity, so the bridge cannot simply be left to DCE.

    /// Soundness: one load batch feeding TWO store batches must not be
    /// rejoined.
    ///
    /// Rejoining replaces the four lane loads with one 16-byte load into the
    /// whole-register name, so the lanes stop being defined. With a second
    /// consumer that leaves the other store batch reading values nothing
    /// writes. `188_vector_transport::vt188_copy_two_streams` is the real
    /// shape: `first_dst[i] = src[i]; second_dst[i] = src[i];` at clang -O2
    /// emitted one load feeding two stores, and rejoining the first pair wrote
    /// garbage into the second buffer while every other cell still passed.
    #[test]
    fn a_lane_batch_with_two_consumers_is_not_rejoined() {
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
        for destination in ["rdi", "rdx"] {
            for lane in 0..4 {
                body.push(Stmt::Store {
                    addr: address(destination, lane * 4),
                    src: Expr::Reg(VReg::phys(format!("xmm0_d{lane}"))),
                    size: 4,
                });
            }
        }
        let original = body.clone();
        let mut function = Function {
            name: "two_streams".into(),
            entry_va: 0,
            body,
        };

        recover_wide_copies(&mut function);

        assert_eq!(
            function.body, original,
            "a lane read by two store batches must keep its explicit lane form"
        );
    }

    #[test]
    fn a_dead_scalar_view_bridge_does_not_hide_the_transport() {
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
        body.push(scalar_view_bridge("xmm0"));
        for lane in 0..4 {
            body.push(Stmt::Store {
                addr: address("rdi", lane * 4),
                src: Expr::Reg(VReg::phys(format!("xmm0_d{lane}"))),
                size: 4,
            });
        }
        let mut function = Function {
            name: "bridged".into(),
            entry_va: 0,
            body,
        };

        recover_wide_copies(&mut function);

        assert!(
            matches!(
                &function.body[0],
                Stmt::Assign { dst: VReg::Phys(name), src: Expr::Deref { size: 16, .. } }
                    if name == "xmm0"
            ),
            "the 16-byte load must be recovered: {:#?}",
            function.body
        );
        assert!(
            function.body.iter().any(|statement| matches!(
                statement,
                Stmt::Store { src: Expr::Reg(VReg::Phys(name)), size: 16, .. } if name == "xmm0"
            )),
            "the 16-byte store must be recovered: {:#?}",
            function.body
        );
        // The bridge read lanes the rejoin no longer defines, so leaving it
        // would overwrite the recovered value with undefined operands.
        assert!(
            !function.body.iter().any(is_scalar_view_bridge),
            "the dead bridge must be removed with the lanes it read: {:#?}",
            function.body
        );
    }

    /// The control. A bridge whose scalar view IS read later is live, so the
    /// rejoin must not fire: recovering the 16-byte transport stops defining
    /// `xmm0_d0`/`xmm0_d1`, and the surviving bridge would then overwrite
    /// `xmm0` with undefined operands. Failing closed keeps the lane form.
    #[test]
    fn a_live_scalar_view_bridge_blocks_the_rejoin() {
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
        body.push(scalar_view_bridge("xmm0"));
        for lane in 0..4 {
            body.push(Stmt::Store {
                addr: address("rdi", lane * 4),
                src: Expr::Reg(VReg::phys(format!("xmm0_d{lane}"))),
                size: 4,
            });
        }
        // Somebody reads the whole-register view.
        body.push(Stmt::Assign {
            dst: VReg::phys("rax"),
            src: Expr::Reg(VReg::phys("xmm0")),
        });
        let original = body.clone();
        let mut function = Function {
            name: "live_bridge".into(),
            entry_va: 0,
            body,
        };

        recover_wide_copies(&mut function);

        assert_eq!(function.body, original);
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
