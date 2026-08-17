//! Give consumed ABI call results distinct source-level identities.
//!
//! Machine ABIs deliberately reuse one output register for every scalar call.
//! That storage reuse must not survive into the source AST: two adjacent calls
//! can have unrelated prototypes, and merging their destinations under one
//! role lets the later narrow result truncate the earlier wide one.  This pass
//! versions each attributed call destination, rewrites only uses reached by
//! that exact definition, and intersects the reaching identity at structured
//! joins.
//!
//! Every split call also gets a compatibility copy back to its architectural
//! output register.  Proven uses are rewritten to the fresh value and make the
//! copy dead.  Uses the structured walk cannot prove (notably loop-carried and
//! label-crossing values) retain the old register spelling and therefore keep
//! the pre-pass semantics instead of becoming undefined.
//!
//! An identity is per RESULT BANK, not per call, wherever the ABI's banks can
//! be told apart.  `rax` and `xmm0` hand back two independent values and a read
//! of one is never a read of the other, so they get separate storage keys —
//! exactly as AAPCS hard-float's `r0` and `s0` always have.  A callee whose
//! System V return class is [`crate::ir::abi::ReturnClass::SplitBanks`]
//! genuinely defines both at once, and that call's destination becomes a frame
//! object the two identities are read back out of.  The same holds one class
//! over for [`crate::ir::abi::ReturnClass::SsePair`], where the two registers
//! are `xmm0` and `xmm1` — a PAIR, not an alias set, which is why `xmm1` gets
//! its storage key here and never joins `abi::return_registers`.  Separation is
//! not free
//! without such a class: see the AArch64 arm of `result_storage` for the lane
//! that measured the cost of separating banks nothing can then re-attribute.

use std::collections::HashMap;

use crate::ir::ast::{Expr, Function, Stmt};
use crate::ir::call_args::CallConv;
use crate::ir::types::{BinOp, VReg};

/// A System V two-bank aggregate result is at most two eightbytes by
/// construction: past 16 bytes the ABI returns through memory.
const SPLIT_BANK_RESULT_BYTES: u16 = 16;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct FlowState {
    /// ABI output storage -> exact call-result value reaching this point.
    results: HashMap<String, VReg>,
    reachable: bool,
}

impl FlowState {
    fn entry() -> Self {
        Self {
            results: HashMap::new(),
            reachable: true,
        }
    }

    fn without_results(&self) -> Self {
        Self {
            results: HashMap::new(),
            reachable: self.reachable,
        }
    }
}

struct Splitter {
    cc: CallConv,
    next_result: usize,
}

/// Version each consumed ABI call result and its proven reaching uses.
pub fn split_call_result_lifetimes(function: &mut Function, cc: CallConv) {
    let mut splitter = Splitter { cc, next_result: 0 };
    splitter.walk_body(&mut function.body, &mut FlowState::entry());
}

impl Splitter {
    /// One logical storage key for all width views of an ABI output register.
    fn result_storage(&self, register: &VReg) -> Option<String> {
        let VReg::Phys(name) = register else {
            return None;
        };
        if crate::ir::abi::wide_integer_return_part(self.cc, name) == Some(1) {
            return Some("wide_integer_result_high".to_string());
        }
        // `xmm1` is the high half of the SSE result pair, and it is the one
        // result storage `is_return_register` deliberately cannot admit: that
        // predicate answers "is this a spelling of THE result", and `xmm1` is
        // not a spelling of `xmm0` any more than `rdx` is one of `rax`. Give it
        // its own key here, exactly as the wide integer pair's high half has
        // one, so a post-call read of it is attributable and a definition of it
        // kills the right identity. Nothing installs this key except an
        // `SsePair` call, so on every other call it stays inert.
        if crate::ir::abi::is_sse_pair_high_return_register(self.cc, name) {
            return Some("sse_result_high".to_string());
        }
        // A dword LANE of either SSE result register is its own quarter of the
        // returned object, not a width view of the whole: `regview::ssa_parent`
        // declines the vector bank, so a definition spelled `xmm0` never
        // reaches a use spelled `xmm0_d0`. Give each lane its own key — sharing
        // the register's would hand a reader of the SECOND float the bits of
        // the first.
        if let Some(offset) = crate::ir::abi::sse_pair_result_lane_offset(self.cc, name) {
            return Some(format!("sse_result_lane_{offset}"));
        }
        if !crate::ir::abi::is_return_register(self.cc, name) {
            return None;
        }
        let base = crate::ir::abi::ssa_base(name);
        Some(match self.cc {
            // `rax` and `xmm0` — and on i386 `rax` and the x87 stack top — are
            // two result BANKS, not two spellings of one, so a post-call SSE or
            // x87 read is not a read of the integer result.  Ask the machine
            // model which bank the name belongs to and key on that, which keeps
            // every WIDTH VIEW of one bank (`rax`/`eax`/`ax`/`al`) sharing its
            // key while the two banks stop sharing one.  Every call still
            // invalidates all of them before installing its attributed
            // destination below.
            CallConv::SysVAmd64 | CallConv::Win64 | CallConv::Cdecl32 => {
                crate::ir::abi::return_register_class(self.cc, base)
                    .and_then(|class| class.first().copied())
                    .unwrap_or(base)
                    .to_string()
            }
            // AAPCS64's banks are disjoint by the same argument, and separating
            // them here was MEASURED on 2026-08-16:
            // `175_float_matrix_kernel:aarch64:O0:dot_product_f32` went
            // pass -> fail, because that caller consumes the bank the call was
            // not attributed to and AAPCS64 has no modelled aggregate return
            // class to attribute the other one from (`abi::wide_integer_return_pair`
            // and `return_class::declared_return_class` are both System V only).
            // Fail closed: keep the collapse until there is a class to replace
            // it with.
            CallConv::Aarch64 => "x0".to_string(),
            // AAPCS hard-float has disjoint integer and FP result banks.  Keep
            // their identities distinct; every call still invalidates all of
            // them before installing its attributed destination below.
            CallConv::Arm | CallConv::ArmHardFloat => base.to_string(),
        })
    }

    /// The storage key a call DESTINATION may claim for the ordinary scalar
    /// contract.
    ///
    /// Deliberately narrower than [`Self::result_storage`], which answers what
    /// storage a READ observes. A dword lane is readable storage — that is why
    /// it has a key at all — but it is not a spelling of "the result", so a
    /// call landing on one is not evidence of a scalar result in it. Only a
    /// PROVEN `SsePair` return claims a lane destination, and it does so before
    /// this gate. Without the split the lane keeps exactly the treatment it has
    /// always had.
    fn destination_storage(&self, register: &VReg) -> Option<String> {
        if let VReg::Phys(name) = register {
            if crate::ir::abi::sse_pair_result_lane_offset(self.cc, name).is_some() {
                return None;
            }
        }
        self.result_storage(register)
    }

    fn fresh_result(&mut self, original: &VReg) -> VReg {
        let base = match original {
            VReg::Phys(name) => crate::ir::abi::ssa_base(name),
            VReg::Temp(_) | VReg::Flag(_) | VReg::FlagValue { .. } => "ret",
        };
        let result = VReg::phys(format!("{base}#call_lifetime_{}", self.next_result));
        self.next_result += 1;
        result
    }

    fn fresh_high_result(&self, high_register: &str) -> VReg {
        let index = self.next_result.saturating_sub(1);
        VReg::phys(format!("{high_register}#call_lifetime_high_{index}"))
    }

    fn wide_result_pair(
        &self,
        call_spec: Option<&crate::ir::call_contracts::CallSiteSpec>,
    ) -> Option<(&'static str, &'static str)> {
        let width = crate::ir::call_contracts::integer_c_type_width(
            &call_spec?.call_prototype.return_type,
            crate::ir::abi::machine_word_bytes(self.cc),
        )?;
        crate::ir::abi::wide_integer_return_pair(self.cc, width)
    }

    /// The bank order of a call whose callee returns in BOTH result banks.
    ///
    /// `None` for every other call, which is every call today except one whose
    /// callee has a DWARF-proven System V `SplitBanks` aggregate return
    /// (`ir::return_class`). Fail closed: an unproven return keeps the scalar
    /// single-bank contract it has always had.
    fn split_bank_order(
        &self,
        call_spec: Option<&crate::ir::call_contracts::CallSiteSpec>,
    ) -> Option<bool> {
        if self.cc != CallConv::SysVAmd64 {
            return None;
        }
        crate::ir::abi::split_bank_return_order(&call_spec?.call_prototype.return_type)
    }

    /// The second-eightbyte occupancy of a call whose callee returns in the SSE
    /// result PAIR (`xmm0:xmm1`).
    ///
    /// `None` for every other call, on the same fail-closed terms as
    /// [`Self::split_bank_order`]: only a DWARF-proven System V `SsePair`
    /// aggregate return reaches this, and everything else keeps the
    /// single-register scalar contract it has always had.
    fn sse_pair_high_bytes(
        &self,
        call_spec: Option<&crate::ir::call_contracts::CallSiteSpec>,
    ) -> Option<u8> {
        if self.cc != CallConv::SysVAmd64 {
            return None;
        }
        crate::ir::abi::sse_pair_return_high_bytes(&call_spec?.call_prototype.return_type)
    }

    /// Decompose an `xmm0:xmm1` call result into one identity per readable
    /// spelling of the two registers.
    ///
    /// Same mechanism as [`Self::split_bank_results`] — the destination becomes
    /// a frame object and each register's eightbyte is read back out of it —
    /// with two differences, both of them the point of this class.
    ///
    /// The HIGH read is `high_bytes` wide, not eight. A twelve-byte
    /// `{float,float,float}` leaves the top half of `xmm1` undefined, and a
    /// full eight-byte read there would manufacture a fourth member the callee
    /// never stored.
    ///
    /// And the four dword LANES that carry object bytes get identities too,
    /// because that is how a caller actually reads a returned float aggregate:
    /// the lifters scalarise packed operations into lanes, and a whole-register
    /// definition does not reach a lane read (`abi::sse_pair_result_lanes`).
    /// The lane at offset twelve is defined only when the object reaches that
    /// far — which is the same partial-occupancy fact stated on the register.
    fn sse_pair_results(
        &mut self,
        high_bytes: u8,
        buffer: &VReg,
        state: &mut FlowState,
    ) -> Vec<Stmt> {
        let object_bytes = high_bytes.saturating_add(8);
        let lanes = crate::ir::abi::sse_pair_result_lanes(self.cc)
            .iter()
            .filter(|(_, offset)| offset.saturating_add(4) <= object_bytes)
            .map(|(lane, offset)| (i64::from(*offset), 4u8, *lane));
        let mut compatibility = Vec::with_capacity(12);
        for (offset, size, register) in [(0i64, 8u8, "xmm0"), (8, high_bytes, "xmm1")]
            .into_iter()
            .chain(lanes)
        {
            let fresh = VReg::phys(format!("{register}#call_lifetime_{}", self.next_result));
            self.next_result += 1;
            let object = Expr::StackAddr {
                object: buffer.clone(),
                size: SPLIT_BANK_RESULT_BYTES,
            };
            let address = if offset == 0 {
                object
            } else {
                Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(object),
                    rhs: Box::new(Expr::Const(offset)),
                }
            };
            compatibility.push(Stmt::Assign {
                dst: fresh.clone(),
                src: Expr::Deref {
                    addr: Box::new(address),
                    size,
                },
            });
            compatibility.push(Stmt::Assign {
                dst: VReg::phys(register),
                src: Expr::Reg(fresh.clone()),
            });
            if state.reachable {
                if let Some(storage) = self.result_storage(&VReg::phys(register)) {
                    state.results.insert(storage, fresh);
                }
            }
        }
        compatibility
    }

    /// Decompose a two-bank call result into one identity per bank.
    ///
    /// The call's destination becomes a 16-byte frame object holding the whole
    /// returned aggregate, and each bank's eightbyte is read back out of it at
    /// the offset the ABI put it. That is the only decomposition this renderer
    /// can spell: there is no member-access node for a value base, and a scalar
    /// destination can name one bank at most. Reading the SSE eightbyte as
    /// eight raw bytes is exact — a float consumer reinterprets those bits
    /// back, which is what the machine store did too.
    fn split_bank_results(
        &mut self,
        integer_first: bool,
        buffer: &VReg,
        state: &mut FlowState,
    ) -> Vec<Stmt> {
        let mut compatibility = Vec::with_capacity(4);
        for (offset, register) in [
            (if integer_first { 0 } else { 8 }, "rax"),
            (if integer_first { 8 } else { 0 }, "xmm0"),
        ] {
            let fresh = VReg::phys(format!("{register}#call_lifetime_{}", self.next_result));
            self.next_result += 1;
            let object = Expr::StackAddr {
                object: buffer.clone(),
                size: SPLIT_BANK_RESULT_BYTES,
            };
            let address = if offset == 0 {
                object
            } else {
                Expr::Bin {
                    op: BinOp::Add,
                    lhs: Box::new(object),
                    rhs: Box::new(Expr::Const(offset)),
                }
            };
            compatibility.push(Stmt::Assign {
                dst: fresh.clone(),
                src: Expr::Deref {
                    addr: Box::new(address),
                    size: 8,
                },
            });
            compatibility.push(Stmt::Assign {
                dst: VReg::phys(register),
                src: Expr::Reg(fresh.clone()),
            });
            if state.reachable {
                if let Some(storage) = self.result_storage(&VReg::phys(register)) {
                    state.results.insert(storage, fresh);
                }
            }
        }
        compatibility
    }

    fn rewrite_reg(&self, register: &mut VReg, state: &FlowState) {
        if !state.reachable {
            return;
        }
        let Some(storage) = self.result_storage(register) else {
            return;
        };
        if let Some(result) = state.results.get(&storage) {
            *register = result.clone();
        }
    }

    fn rewrite_expr(&self, expression: &mut Expr, state: &FlowState) {
        match expression {
            Expr::Reg(register) => self.rewrite_reg(register, state),
            Expr::StackAddr { object, .. } => self.rewrite_reg(object, state),
            Expr::Lea { base, index, .. } | Expr::PdbFieldAddr { base, index, .. } => {
                if let Some(base) = base {
                    self.rewrite_reg(base, state);
                }
                if let Some(index) = index {
                    self.rewrite_reg(index, state);
                }
            }
            Expr::Deref { addr, .. } => self.rewrite_expr(addr, state),
            Expr::Call { target, args, .. } => {
                self.rewrite_expr(target, state);
                for argument in args {
                    self.rewrite_expr(argument, state);
                }
            }
            Expr::Bin { lhs, rhs, .. } | Expr::Cmp { lhs, rhs, .. } => {
                self.rewrite_expr(lhs, state);
                self.rewrite_expr(rhs, state);
            }
            Expr::Select {
                cond,
                if_true,
                if_false,
                ..
            } => {
                self.rewrite_expr(cond, state);
                self.rewrite_expr(if_true, state);
                self.rewrite_expr(if_false, state);
            }
            Expr::Un { src, .. } => self.rewrite_expr(src, state),
            Expr::Cast { expr, .. } | Expr::NumericConvert { expr, .. } => {
                self.rewrite_expr(expr, state)
            }
            Expr::FunctionTableEntry { index, .. } => self.rewrite_expr(index, state),
            Expr::WideArithmetic { args, .. } => {
                for argument in args {
                    self.rewrite_expr(argument, state);
                }
            }
            Expr::Const(_)
            | Expr::FloatConst { .. }
            | Expr::Addr(_)
            | Expr::Named { .. }
            | Expr::StringLit { .. }
            | Expr::Unknown(_) => {}
        }
    }

    fn kill_definition(&self, destination: &VReg, state: &mut FlowState) {
        if let Some(storage) = self.result_storage(destination) {
            state.results.remove(&storage);
        }
    }

    fn intersect(states: &[FlowState]) -> FlowState {
        let reachable = states
            .iter()
            .filter(|state| state.reachable)
            .collect::<Vec<_>>();
        let Some(first) = reachable.first() else {
            return FlowState::default();
        };
        let mut results = first.results.clone();
        results.retain(|storage, value| {
            reachable
                .iter()
                .skip(1)
                .all(|state| state.results.get(storage) == Some(value))
        });
        FlowState {
            results,
            reachable: true,
        }
    }

    fn body_contains_break(body: &[Stmt]) -> bool {
        body.iter().any(|statement| match statement {
            Stmt::Break => true,
            Stmt::If {
                then_body,
                else_body,
                ..
            } => {
                Self::body_contains_break(then_body)
                    || else_body.as_deref().is_some_and(Self::body_contains_break)
            }
            Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => {
                Self::body_contains_break(body)
            }
            Stmt::For { body, .. } => Self::body_contains_break(body),
            Stmt::Switch { cases, default, .. } => {
                cases
                    .iter()
                    .any(|(_, body)| Self::body_contains_break(body))
                    || default.as_deref().is_some_and(Self::body_contains_break)
            }
            Stmt::TryCatch { try_body, catches } => {
                Self::body_contains_break(try_body)
                    || catches
                        .iter()
                        .any(|catch| Self::body_contains_break(&catch.body))
            }
            _ => false,
        })
    }

    /// Transform a vector body, inserting compatibility copies after calls.
    fn walk_body(&mut self, body: &mut Vec<Stmt>, state: &mut FlowState) {
        let mut output = Vec::with_capacity(body.len());
        for mut statement in std::mem::take(body) {
            let compatibility = self.walk_stmt(&mut statement, state);
            output.push(statement);
            output.extend(compatibility);
        }
        *body = output;
    }

    /// Transform a statement. Calls return a compatibility copy for their
    /// enclosing vector body to insert immediately after the call.
    fn walk_stmt(&mut self, statement: &mut Stmt, state: &mut FlowState) -> Vec<Stmt> {
        match statement {
            Stmt::Assign { dst, src } => {
                self.rewrite_expr(src, state);
                self.kill_definition(dst, state);
            }
            Stmt::Store { addr, src, .. } => {
                self.rewrite_expr(addr, state);
                self.rewrite_expr(src, state);
            }
            Stmt::Call {
                target,
                args,
                dst,
                call_spec,
            } => {
                self.rewrite_expr(target, state);
                for argument in args {
                    self.rewrite_expr(argument, state);
                }
                // Every call clobbers every ABI result bank, regardless of
                // whether source-level consumption attributed a destination.
                state.results.clear();
                let Some(original) = dst.clone() else {
                    return Vec::new();
                };
                // A result the ABI put in BOTH SSE result registers is not one
                // scalar in one register, so it does not get a scalar
                // destination — and it is checked BEFORE the scalar storage
                // gate below, deliberately. The attributed destination of such
                // a call is routinely a dword LANE (`xmm0_d0`), which is not a
                // spelling of "the result" and which `result_storage` therefore
                // declines; the proven return CLASS says where the value is
                // regardless of which spelling the attribution happened to
                // pick. Only a DWARF-proven System V `SsePair` return reaches
                // here, so nothing else is captured by the earlier position.
                if let Some(high_bytes) = self.sse_pair_high_bytes(call_spec.as_ref()) {
                    let buffer = VReg::phys(format!("split_result_{}", self.next_result));
                    self.next_result += 1;
                    *dst = Some(buffer.clone());
                    return self.sse_pair_results(high_bytes, &buffer, state);
                }
                let Some(storage) = self.destination_storage(&original) else {
                    return Vec::new();
                };
                // A result the ABI split across both banks is not one scalar
                // in one register, so it does not get a scalar destination.
                if let Some(integer_first) = self.split_bank_order(call_spec.as_ref()) {
                    let buffer = VReg::phys(format!("split_result_{}", self.next_result));
                    self.next_result += 1;
                    *dst = Some(buffer.clone());
                    return self.split_bank_results(integer_first, &buffer, state);
                }
                let wide_pair = self.wide_result_pair(call_spec.as_ref());
                let fresh = self.fresh_result(&original);
                *dst = Some(fresh.clone());
                if state.reachable {
                    state.results.insert(storage, fresh.clone());
                }
                let mut compatibility = Vec::with_capacity(if wide_pair.is_some() { 2 } else { 1 });
                if let Some((_, high_register)) = wide_pair.filter(|(low, _)| {
                    crate::ir::abi::ssa_base(match &original {
                        VReg::Phys(name) => name,
                        _ => "",
                    }) == *low
                }) {
                    let high = self.fresh_high_result(high_register);
                    if state.reachable {
                        let high_storage = self
                            .result_storage(&VReg::phys(high_register))
                            .expect("a wide return pair must expose its high storage");
                        state.results.insert(high_storage, high.clone());
                    }
                    compatibility.push(Stmt::Assign {
                        dst: high,
                        src: Expr::Cast {
                            signed: false,
                            width: crate::ir::abi::machine_word_bytes(self.cc),
                            expr: Box::new(Expr::Bin {
                                op: BinOp::Shr,
                                lhs: Box::new(Expr::Reg(fresh.clone())),
                                rhs: Box::new(Expr::Const(
                                    i64::from(crate::ir::abi::machine_word_bytes(self.cc)) * 8,
                                )),
                            }),
                        },
                    });
                }
                compatibility.push(Stmt::Assign {
                    dst: original,
                    src: Expr::Reg(fresh),
                });
                return compatibility;
            }
            Stmt::Return { value } => {
                if let Some(value) = value {
                    self.rewrite_expr(value, state);
                }
                state.reachable = false;
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                self.rewrite_expr(cond, state);
                let entry = state.clone();
                let mut then_state = entry.clone();
                self.walk_body(then_body, &mut then_state);
                let mut else_state = entry;
                if let Some(else_body) = else_body {
                    self.walk_body(else_body, &mut else_state);
                }
                *state = Self::intersect(&[then_state, else_state]);
            }
            Stmt::While { cond, body } => {
                let entry = state.clone();
                let original_body = body.clone();
                let mut candidate_body = original_body.clone();
                let mut candidate_state = entry.clone();
                self.walk_body(&mut candidate_body, &mut candidate_state);
                let preserves_entry = !Self::body_contains_break(&original_body)
                    && (!candidate_state.reachable || candidate_state.results == entry.results);
                if preserves_entry {
                    self.rewrite_expr(cond, &entry);
                    *body = candidate_body;
                    *state = entry;
                } else {
                    let mut inner_state = entry.without_results();
                    *body = original_body;
                    self.walk_body(body, &mut inner_state);
                    state.results.clear();
                }
            }
            Stmt::DoWhile { body, cond } => {
                let entry = state.clone();
                let original_body = body.clone();
                let mut candidate_body = original_body.clone();
                let mut candidate_state = entry.clone();
                self.walk_body(&mut candidate_body, &mut candidate_state);
                let preserves_entry = !Self::body_contains_break(&original_body)
                    && (!candidate_state.reachable || candidate_state.results == entry.results);
                if preserves_entry {
                    self.rewrite_expr(cond, &candidate_state);
                    *body = candidate_body;
                    *state = candidate_state;
                } else {
                    let mut inner_state = entry.without_results();
                    *body = original_body;
                    self.walk_body(body, &mut inner_state);
                    self.rewrite_expr(cond, &inner_state);
                    state.results.clear();
                    state.reachable &= inner_state.reachable;
                }
            }
            Stmt::For {
                init,
                cond,
                step,
                body,
            } => {
                // A Box<Stmt> cannot host the compatibility copy required for
                // a direct call. Leave such rare init/step calls unsplit.
                self.walk_embedded_stmt(init, state);
                let mut loop_state = state.without_results();
                self.rewrite_expr(cond, &loop_state);
                self.walk_body(body, &mut loop_state);
                self.walk_embedded_stmt(step, &mut loop_state);
                state.results.clear();
            }
            Stmt::Switch {
                discriminant,
                cases,
                default,
            } => {
                self.rewrite_expr(discriminant, state);
                let entry = state.clone();
                let mut exits = Vec::with_capacity(cases.len() + 1);
                for (_, body) in cases {
                    let mut case_state = entry.clone();
                    self.walk_body(body, &mut case_state);
                    exits.push(case_state);
                }
                if let Some(default) = default {
                    let mut default_state = entry;
                    self.walk_body(default, &mut default_state);
                    exits.push(default_state);
                } else {
                    exits.push(entry);
                }
                *state = Self::intersect(&exits);
            }
            Stmt::TryCatch { try_body, catches } => {
                let entry = state.clone();
                let mut exits = Vec::with_capacity(catches.len() + 1);
                let mut try_state = entry.clone();
                self.walk_body(try_body, &mut try_state);
                exits.push(try_state);
                for catch in catches {
                    let mut catch_state = entry.clone();
                    self.walk_body(&mut catch.body, &mut catch_state);
                    exits.push(catch_state);
                }
                *state = Self::intersect(&exits);
            }
            Stmt::Push { value } | Stmt::Throw { value } => {
                self.rewrite_expr(value, state);
                if matches!(statement, Stmt::Throw { .. }) {
                    state.reachable = false;
                }
            }
            Stmt::Pop { target } => self.kill_definition(target, state),
            Stmt::IndirectGoto { target } => {
                self.rewrite_expr(target, state);
                state.results.clear();
                state.reachable = false;
            }
            Stmt::Goto { .. } => {
                state.results.clear();
                state.reachable = false;
            }
            Stmt::Label(_) => {
                // A label can have predecessors outside the structured walk.
                state.results.clear();
                state.reachable = true;
            }
            Stmt::Break | Stmt::Nop | Stmt::Unknown(_) | Stmt::Comment(_) => {}
        }
        Vec::new()
    }

    fn walk_embedded_stmt(&mut self, statement: &mut Stmt, state: &mut FlowState) {
        if let Stmt::Call { target, args, .. } = statement {
            self.rewrite_expr(target, state);
            for argument in args {
                self.rewrite_expr(argument, state);
            }
            state.results.clear();
            return;
        }
        debug_assert!(self.walk_stmt(statement, state).is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::call_contracts::{CallPrototype, CallPrototypeAuthority, CallSiteSpec};

    fn reg(name: &str) -> VReg {
        VReg::phys(name)
    }

    fn call(name: &str) -> Stmt {
        Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: name.to_string(),
            },
            args: Vec::new(),
            dst: Some(reg("x0")),
            call_spec: None,
        }
    }

    fn wide_call(name: &str, cc: CallConv) -> Stmt {
        let prototype = CallPrototype {
            return_type: "unsigned long long".to_string(),
            parameter_types: Vec::new(),
            variadic: false,
            authority: CallPrototypeAuthority::Recovered,
        };
        Stmt::Call {
            target: Expr::Named {
                va: 0,
                name: name.to_string(),
            },
            args: Vec::new(),
            dst: Some(reg(crate::ir::abi::return_register(cc))),
            call_spec: Some(CallSiteSpec {
                callee_prototype: Some(prototype.clone()),
                call_prototype: prototype,
            }),
        }
    }

    fn store(slot: &str) -> Stmt {
        Stmt::Store {
            addr: Expr::Reg(reg(slot)),
            src: Expr::Reg(reg("x0")),
            size: 4,
        }
    }

    #[test]
    fn sequential_call_results_get_distinct_reaching_identities() {
        let mut function = Function {
            name: "decode_header".to_string(),
            entry_va: 0,
            body: vec![
                call("validate_header"),
                store("stack_validator"),
                call("read_be16"),
                store("stack_first"),
                call("read_be16"),
                store("stack_second"),
            ],
        };

        split_call_result_lifetimes(&mut function, CallConv::Aarch64);

        let call_results = function
            .body
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Call { dst: Some(dst), .. } => Some(dst.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let stored_results = function
            .body
            .iter()
            .filter_map(|statement| match statement {
                Stmt::Store {
                    src: Expr::Reg(src),
                    ..
                } => Some(src.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        assert_eq!(call_results.len(), 3);
        assert_eq!(stored_results, call_results);
        assert_ne!(call_results[0], call_results[1]);
        assert_ne!(call_results[1], call_results[2]);
    }

    #[test]
    fn an_overwrite_stops_the_call_result_from_reaching_a_later_read() {
        let mut function = Function {
            name: "overwrite".to_string(),
            entry_va: 0,
            body: vec![
                call("producer"),
                Stmt::Assign {
                    dst: reg("x0"),
                    src: Expr::Const(7),
                },
                store("stack_after_overwrite"),
            ],
        };

        split_call_result_lifetimes(&mut function, CallConv::Aarch64);

        assert!(function.body.iter().any(|statement| matches!(
            statement,
            Stmt::Store {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            } if name == "x0"
        )));
    }

    #[test]
    fn ilp32_wide_call_joins_low_and_high_abi_registers_into_one_scalar() {
        for (cc, low, high) in [
            (CallConv::Arm, "r0", "r1"),
            (CallConv::Cdecl32, "rax", "rdx"),
        ] {
            let mut function = Function {
                name: "fold_wide".to_string(),
                entry_va: 0,
                body: vec![
                    wide_call("widen_mul", cc),
                    Stmt::Store {
                        addr: Expr::Reg(reg("low_slot")),
                        src: Expr::Reg(reg(low)),
                        size: 4,
                    },
                    Stmt::Store {
                        addr: Expr::Reg(reg("high_slot")),
                        src: Expr::Reg(reg(high)),
                        size: 4,
                    },
                ],
            };

            split_call_result_lifetimes(&mut function, cc);

            let call_result = function.body.iter().find_map(|statement| match statement {
                Stmt::Call { dst: Some(dst), .. } => Some(dst.clone()),
                _ => None,
            });
            let Some(call_result) = call_result else {
                panic!("wide call lost its scalar destination: {function:#?}");
            };
            let stored = function
                .body
                .iter()
                .filter_map(|statement| match statement {
                    Stmt::Store {
                        src: Expr::Reg(src),
                        ..
                    } => Some(src.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(stored.first(), Some(&call_result), "{function:#?}");
            let high_result = stored.get(1).expect("missing high-half consumer");
            assert_ne!(
                high_result,
                &reg(high),
                "stale pre-call high half: {function:#?}"
            );
            assert!(
                function.body.iter().any(|statement| matches!(
                    statement,
                    Stmt::Assign {
                        dst,
                        src: Expr::Cast {
                            signed: false,
                            width: 4,
                            expr,
                        },
                    } if dst == high_result && matches!(
                        expr.as_ref(),
                        Expr::Bin {
                            op: crate::ir::types::BinOp::Shr,
                            lhs,
                            rhs,
                        } if lhs.as_ref() == &Expr::Reg(call_result.clone())
                            && rhs.as_ref() == &Expr::Const(32)
                    )
                )),
                "wide call did not define its high ABI part from the scalar result: {function:#?}"
            );
        }
    }

    /// `rax` and `xmm0` are two result BANKS, not two spellings of one, so a
    /// post-call SSE read must not be rewritten to the integer call result.
    /// Every WIDTH VIEW of one bank still shares that bank's identity.
    #[test]
    fn the_two_x86_64_result_banks_do_not_share_one_identity() {
        for cc in [CallConv::SysVAmd64, CallConv::Win64] {
            let splitter = Splitter { cc, next_result: 0 };
            let storage = |name: &str| splitter.result_storage(&reg(name));
            assert_eq!(storage("rax"), Some("rax".to_string()), "{cc:?}");
            assert_eq!(storage("eax"), storage("rax"), "{cc:?}");
            assert_eq!(storage("al"), storage("rax"), "{cc:?}");
            assert_eq!(storage("xmm0"), Some("xmm0".to_string()), "{cc:?}");
            assert_ne!(storage("xmm0"), storage("rax"), "{cc:?}");
        }
        // i386 returns floating point on the x87 stack, and that bottom slot is
        // the same disjoint-bank case under a different spelling.
        let splitter = Splitter {
            cc: CallConv::Cdecl32,
            next_result: 0,
        };
        assert_eq!(
            splitter.result_storage(&reg("st0")),
            Some("st0".to_string())
        );
        assert_ne!(
            splitter.result_storage(&reg("st0")),
            splitter.result_storage(&reg("eax"))
        );
    }

    /// A result the System V ABI splits across both banks is decomposed into
    /// one identity per bank, read out of the frame object the call now
    /// returns into. Nothing else can carry both halves: a scalar destination
    /// names one bank at most.
    #[test]
    fn a_split_bank_return_gets_one_identity_per_bank() {
        for (integer_first, integer_offset, sse_offset) in [(true, 0, 8), (false, 8, 0)] {
            let prototype = CallPrototype {
                return_type: crate::ir::abi::split_bank_return_tag(integer_first).to_string(),
                parameter_types: Vec::new(),
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            };
            let mut function = Function {
                name: "consume_both_banks".to_string(),
                entry_va: 0,
                body: vec![
                    Stmt::Call {
                        target: Expr::Named {
                            va: 0,
                            name: "make_mixed".to_string(),
                        },
                        args: Vec::new(),
                        dst: Some(reg("rax")),
                        call_spec: Some(CallSiteSpec {
                            callee_prototype: Some(prototype.clone()),
                            call_prototype: prototype,
                        }),
                    },
                    Stmt::Store {
                        addr: Expr::Reg(reg("integer_slot")),
                        src: Expr::Reg(reg("rax")),
                        size: 8,
                    },
                    Stmt::Store {
                        addr: Expr::Reg(reg("sse_slot")),
                        src: Expr::Reg(reg("xmm0")),
                        size: 8,
                    },
                ],
            };

            split_call_result_lifetimes(&mut function, CallConv::SysVAmd64);

            let Some(Stmt::Call {
                dst: Some(buffer), ..
            }) = function.body.first()
            else {
                panic!("the call lost its destination: {function:#?}");
            };
            let offset_of = |register: &str| {
                function.body.iter().find_map(|statement| match statement {
                    Stmt::Assign {
                        dst,
                        src: Expr::Deref { addr, size: 8 },
                    } if matches!(dst, VReg::Phys(name) if name.starts_with(register)) => {
                        Some(match addr.as_ref() {
                            Expr::StackAddr { object, size: 16 } if object == buffer => 0,
                            Expr::Bin {
                                op: BinOp::Add,
                                lhs,
                                rhs,
                            } => match (lhs.as_ref(), rhs.as_ref()) {
                                (Expr::StackAddr { object, size: 16 }, Expr::Const(offset))
                                    if object == buffer =>
                                {
                                    *offset
                                }
                                _ => panic!("unexpected split address: {function:#?}"),
                            },
                            _ => panic!("unexpected split address: {function:#?}"),
                        })
                    }
                    _ => None,
                })
            };
            assert_eq!(offset_of("rax"), Some(integer_offset), "{function:#?}");
            assert_eq!(offset_of("xmm0"), Some(sse_offset), "{function:#?}");

            let stored = function
                .body
                .iter()
                .filter_map(|statement| match statement {
                    Stmt::Store {
                        src: Expr::Reg(src),
                        ..
                    } => Some(src.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(stored.len(), 2, "{function:#?}");
            assert_ne!(stored[0], stored[1], "{function:#?}");
            for (index, expected) in [(0, "rax"), (1, "xmm0")] {
                assert!(
                    matches!(&stored[index], VReg::Phys(name) if name.starts_with(expected)
                        && name.contains("#call_lifetime_")),
                    "bank {expected} was not read from its own call result: {function:#?}"
                );
            }
        }
    }

    /// A result in the SSE result PAIR is decomposed into one identity per
    /// readable spelling of `xmm0:xmm1` — the two whole registers AND the dword
    /// lanes that carry object bytes, because a whole-register definition does
    /// not reach a lane read.
    ///
    /// The twelve-byte case is what the occupancy is for: the high register
    /// carries four defined bytes, so the read out of it is four wide and the
    /// lane at offset twelve does not exist at all. A model that filled both
    /// eightbytes would hand back a fourth member the callee never stored.
    #[test]
    fn an_sse_pair_return_defines_every_spelling_the_object_reaches() {
        for (high_bytes, defined) in [
            (
                8u8,
                vec![
                    ("xmm0", 0i64, 8u8),
                    ("xmm1", 8, 8),
                    ("xmm0_d0", 0, 4),
                    ("xmm0_d1", 4, 4),
                    ("xmm1_d0", 8, 4),
                    ("xmm1_d1", 12, 4),
                ],
            ),
            (
                4,
                vec![
                    ("xmm0", 0, 8),
                    ("xmm1", 8, 4),
                    ("xmm0_d0", 0, 4),
                    ("xmm0_d1", 4, 4),
                    ("xmm1_d0", 8, 4),
                ],
            ),
        ] {
            let prototype = CallPrototype {
                return_type: crate::ir::abi::sse_pair_return_tag(high_bytes)
                    .expect("a modelled occupancy")
                    .to_string(),
                parameter_types: Vec::new(),
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            };
            let mut function = Function {
                name: "consume_both_sse_registers".to_string(),
                entry_va: 0,
                body: vec![Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "make_floats".to_string(),
                    },
                    args: Vec::new(),
                    // The attributed destination of such a call is routinely a
                    // dword LANE, which `result_storage` declines. The proven
                    // class must carry the decomposition anyway.
                    dst: Some(reg("xmm0_d0#1")),
                    call_spec: Some(CallSiteSpec {
                        callee_prototype: Some(prototype.clone()),
                        call_prototype: prototype,
                    }),
                }],
            };

            split_call_result_lifetimes(&mut function, CallConv::SysVAmd64);

            let Some(Stmt::Call {
                dst: Some(buffer), ..
            }) = function.body.first()
            else {
                panic!("the call lost its destination: {function:#?}");
            };
            assert!(
                matches!(buffer, VReg::Phys(name) if name.starts_with("split_result_")),
                "the destination stayed a scalar: {function:#?}"
            );
            let reads = function
                .body
                .iter()
                .filter_map(|statement| match statement {
                    Stmt::Assign {
                        dst: VReg::Phys(name),
                        src: Expr::Deref { addr, size },
                    } => {
                        let offset = match addr.as_ref() {
                            Expr::StackAddr { object, size: 16 } if object == buffer => 0,
                            Expr::Bin {
                                op: BinOp::Add,
                                lhs,
                                rhs,
                            } => match (lhs.as_ref(), rhs.as_ref()) {
                                (Expr::StackAddr { object, size: 16 }, Expr::Const(offset))
                                    if object == buffer =>
                                {
                                    *offset
                                }
                                _ => panic!("unexpected split address: {function:#?}"),
                            },
                            _ => panic!("unexpected split address: {function:#?}"),
                        };
                        Some((crate::ir::abi::ssa_base(name).to_string(), offset, *size))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            let expected = defined
                .iter()
                .map(|(register, offset, size)| ((*register).to_string(), *offset, *size))
                .collect::<Vec<_>>();
            assert_eq!(reads, expected, "high_bytes={high_bytes}: {function:#?}");
            // Nothing reads past the object, in either shape: the upper halves
            // of both registers (`_d2`, `_d3`) are not part of the result.
            assert!(
                reads
                    .iter()
                    .all(|(_, offset, size)| offset + i64::from(*size)
                        <= i64::from(high_bytes) + 8),
                "a read ran past the returned object: {function:#?}"
            );
        }
    }

    /// Fail closed: a call with no proven split-bank return keeps the scalar
    /// destination it has always had, frame object and all.
    #[test]
    fn an_unproven_return_keeps_its_scalar_destination() {
        let mut function = Function {
            name: "ordinary".to_string(),
            entry_va: 0,
            body: vec![Stmt::Call {
                target: Expr::Named {
                    va: 0,
                    name: "producer".to_string(),
                },
                args: Vec::new(),
                dst: Some(reg("rax")),
                call_spec: None,
            }],
        };

        split_call_result_lifetimes(&mut function, CallConv::SysVAmd64);

        assert!(
            !function.body.iter().any(|statement| matches!(
                statement,
                Stmt::Assign {
                    src: Expr::Deref { .. },
                    ..
                }
            )),
            "an unproven return acquired a split-bank frame object: {function:#?}"
        );
    }

    /// Fail closed on the other side of the SSE-pair gate: a call destined for
    /// a dword LANE is not evidence of a pair. Without a proven class the lane
    /// keeps exactly the treatment it has always had — none — rather than
    /// acquiring a frame object because it looked like a float.
    #[test]
    fn a_lane_destination_without_a_proven_class_is_not_a_pair() {
        for return_type in ["double", "long", "float"] {
            let prototype = CallPrototype {
                return_type: return_type.to_string(),
                parameter_types: Vec::new(),
                variadic: false,
                authority: CallPrototypeAuthority::Recovered,
            };
            let mut function = Function {
                name: "ordinary_float".to_string(),
                entry_va: 0,
                body: vec![Stmt::Call {
                    target: Expr::Named {
                        va: 0,
                        name: "producer".to_string(),
                    },
                    args: Vec::new(),
                    dst: Some(reg("xmm0_d0#1")),
                    call_spec: Some(CallSiteSpec {
                        callee_prototype: Some(prototype.clone()),
                        call_prototype: prototype,
                    }),
                }],
            };

            split_call_result_lifetimes(&mut function, CallConv::SysVAmd64);

            assert_eq!(
                function.body.len(),
                1,
                "{return_type} acquired a decomposition: {function:#?}"
            );
            assert!(
                matches!(function.body.first(), Some(Stmt::Call { dst: Some(dst), .. })
                    if *dst == reg("xmm0_d0#1")),
                "{return_type} lost its destination: {function:#?}"
            );
        }
    }

    #[test]
    fn a_shared_result_identity_survives_a_structured_join() {
        let mut function = Function {
            name: "branch".to_string(),
            entry_va: 0,
            body: vec![
                call("producer"),
                Stmt::If {
                    cond: Expr::Const(1),
                    then_body: vec![store("stack_then")],
                    else_body: Some(vec![store("stack_else")]),
                },
                store("stack_join"),
            ],
        };

        split_call_result_lifetimes(&mut function, CallConv::Aarch64);

        let result = function.body.iter().find_map(|statement| match statement {
            Stmt::Call { dst: Some(dst), .. } => Some(dst.clone()),
            _ => None,
        });
        let Some(result) = result else {
            panic!("call result was not versioned: {function:#?}");
        };
        let mut stores = Vec::new();
        fn collect(body: &[Stmt], stores: &mut Vec<VReg>) {
            for statement in body {
                match statement {
                    Stmt::Store {
                        src: Expr::Reg(src),
                        ..
                    } => stores.push(src.clone()),
                    Stmt::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        collect(then_body, stores);
                        if let Some(else_body) = else_body {
                            collect(else_body, stores);
                        }
                    }
                    _ => {}
                }
            }
        }
        collect(&function.body, &mut stores);
        assert_eq!(stores, vec![result.clone(), result.clone(), result]);
    }

    #[test]
    fn an_ambiguous_loop_keeps_the_compatibility_storage() {
        let mut function = Function {
            name: "loop".to_string(),
            entry_va: 0,
            body: vec![
                call("before_loop"),
                Stmt::While {
                    cond: Expr::Reg(reg("x0")),
                    body: vec![store("stack_before_call"), call("inside_loop")],
                },
                store("stack_after_loop"),
            ],
        };

        split_call_result_lifetimes(&mut function, CallConv::Aarch64);

        let Stmt::While { cond, .. } = &function.body[2] else {
            panic!("compatibility copy must immediately follow the call: {function:#?}");
        };
        assert_eq!(cond, &Expr::Reg(reg("x0")));
        assert!(matches!(
            function.body.last(),
            Some(Stmt::Store {
                src: Expr::Reg(VReg::Phys(name)),
                ..
            }) if name == "x0"
        ));
    }
}
