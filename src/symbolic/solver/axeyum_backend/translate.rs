//! Translation of glaurung's [`Expr`] IR into `axeyum-ir` terms.
//!
//! [`Translator`] walks one expression DAG against a shared [`TermArena`],
//! memoizing by [`ExprId`] so a shared subexpression is built once, and
//! interning each symbolic input as a `SymbolId` recorded in `sym_map` for
//! model lift-back. Widths follow glaurung's `Expr` exactly; nothing here
//! widens, narrows or folds on its own.
//!
//! Both entry points live here because both construct a [`Translator`]
//! directly: `translate_query` for the query-plus-symbol-map shape the one-shot
//! and snapshot backends want, `translate_path` for the bare arena-plus-terms
//! shape the unsat-proof path wants.

use super::*;

pub(super) fn translate_query(
    pool: &ExprPool,
    asserts: &[Assert],
    arena: &mut TermArena,
) -> Result<TranslatedQuery, IrError> {
    let mut translator = Translator {
        pool,
        arena,
        memo: HashMap::new(),
        sym_map: Vec::new(),
    };
    let mut assertions = Vec::with_capacity(asserts.len());
    for &(expr, expected) in asserts {
        assertions.push(translator.translate_assert(expr, expected)?);
    }
    Ok(TranslatedQuery {
        assertions,
        exprs: translator.memo.len(),
        sym_map: translator.sym_map,
    })
}

pub(super) fn translate_path(
    pool: &ExprPool,
    asserts: &[Assert],
) -> Result<(TermArena, Vec<TermId>), IrError> {
    let mut arena = TermArena::new();
    let assert_terms = {
        let mut translator = Translator {
            pool,
            arena: &mut arena,
            memo: HashMap::new(),
            sym_map: Vec::new(),
        };
        let mut terms = Vec::with_capacity(asserts.len());
        for &(expression, expected) in asserts {
            terms.push(translator.translate_assert(expression, expected)?);
        }
        terms
    };
    Ok((arena, assert_terms))
}

/// Translates glaurung's hash-consed BV IR into `axeyum-ir` terms, memoized
/// on `ExprId` so shared subterms are built once (preserving glaurung's
/// interning into axeyum's arena). Every `Expr` node maps to an axeyum
/// `BitVec` term; Bool is touched only at the three boundaries described in
/// `docs/axeyum-integration/02-interface-mapping.md` (Cmp lift, Ite cond,
/// assert truthiness).
pub(super) struct Translator<'a> {
    pool: &'a ExprPool,
    arena: &'a mut TermArena,
    memo: HashMap<ExprId, TermId>,
    sym_map: Vec<(u32, SymbolId)>,
}

impl<'a> Translator<'a> {
    /// Build the Bool assertion term for `(e, expected)`, mirroring z3's
    /// truthiness lowering: `e != 0` when expected, `e == 0` otherwise.
    fn translate_assert(&mut self, e: ExprId, expected: bool) -> Result<TermId, IrError> {
        let t = self.translate(e)?;
        let w = self.pool.width_of(e).bits() as u32;
        let zero = self.arena.bv_const(w, 0)?;
        let is_zero = self.arena.eq(t, zero)?; // Bool: e == 0
        if expected {
            self.arena.not(is_zero) // Bool: e != 0
        } else {
            Ok(is_zero)
        }
    }

    /// Translate a glaurung `ExprId` to an axeyum `BitVec` term.
    fn translate(&mut self, id: ExprId) -> Result<TermId, IrError> {
        if let Some(&t) = self.memo.get(&id) {
            return Ok(t);
        }
        // Clone the node so the immutable pool borrow is released before we
        // mutate the arena / recurse.
        let node = self.pool.get(id).clone();
        let t = match node {
            Expr::Const { value, width } => {
                let w = width.bits() as u32;
                if w > 128 {
                    self.arena.wide_bv_const(WideUint::from_u128(value, w))
                } else {
                    // Mask to width, matching glaurung's `ExprPool::constant`
                    // and z3_backend (both drop bits above the width).
                    // axeyum's `bv_const` strictly rejects an over-wide value,
                    // so masking keeps the two backends behaviorally identical.
                    let masked = if w >= 128 {
                        value
                    } else {
                        value & ((1u128 << w) - 1)
                    };
                    self.arena.bv_const(w, masked)?
                }
            }
            Expr::Sym { id: sid, width } => {
                let w = width.bits() as u32;
                let name = ExprPool::sym_name(sid, width);
                let symid = self.arena.declare(&name, Sort::BitVec(w))?;
                self.sym_map.push((sid, symid));
                self.arena.var(symid)
            }
            Expr::Bin { op, a, b, width } => {
                // Coerce both operands to the node width, exactly as
                // z3_backend does: glaurung's lifter emits width-mismatched
                // operands and relies on the solver to normalize. axeyum
                // strictly requires a shared sort, so we MUST coerce here.
                let tw = width.bits() as u32;
                let ta = self.translate_coerced(a, tw)?;
                let tb = self.translate_coerced(b, tw)?;
                match op {
                    BinOp::Add => self.arena.bv_add(ta, tb)?,
                    BinOp::Sub => self.arena.bv_sub(ta, tb)?,
                    BinOp::Mul => self.arena.bv_mul(ta, tb)?,
                    BinOp::Div => self.arena.bv_udiv(ta, tb)?, // glaurung Div is unsigned
                    BinOp::And => self.arena.bv_and(ta, tb)?,
                    BinOp::Or => self.arena.bv_or(ta, tb)?,
                    BinOp::Xor => self.arena.bv_xor(ta, tb)?,
                    BinOp::Shl => self.arena.bv_shl(ta, tb)?,
                    BinOp::Shr => self.arena.bv_lshr(ta, tb)?, // logical
                    BinOp::Sar => self.arena.bv_ashr(ta, tb)?, // arithmetic
                    // Source-level `&&` / `||` are NOT bitvector ALU ops. They
                    // booleanize both operands and yield 1 or 0 at the node
                    // width. This mirrors `ExprPool::render_smtlib` term for
                    // term -- `(ite (and (distinct a 0) (distinct b 0))
                    // (_ bv1 W) (_ bv0 W))` -- and that identity is load
                    // bearing: `ordered_replay` re-renders every imported
                    // native assertion pack through the text bridge and
                    // rejects the pack unless the two hash to the same
                    // constraint, so a divergent lowering here would not be a
                    // silent disagreement, it would break replay outright.
                    //
                    // Note the coercion order matters. `ta`/`tb` are already
                    // narrowed/widened to `tw`, and truncation can turn a
                    // non-zero value into zero, so the `!= 0` test must come
                    // after the coercion exactly as the text renderer does it.
                    BinOp::LogicalAnd | BinOp::LogicalOr => {
                        let zero = self.arena.bv_const(tw, 0)?;
                        let a_true = {
                            let a_zero = self.arena.eq(ta, zero)?;
                            self.arena.not(a_zero)?
                        };
                        let b_true = {
                            let b_zero = self.arena.eq(tb, zero)?;
                            self.arena.not(b_zero)?
                        };
                        let joined = if matches!(op, BinOp::LogicalAnd) {
                            self.arena.and(a_true, b_true)?
                        } else {
                            self.arena.or(a_true, b_true)?
                        };
                        let one = self.arena.bv_const(tw, 1)?;
                        self.arena.ite(joined, one, zero)?
                    }
                }
            }
            Expr::Un { op, a, .. } => {
                let ta = self.translate(a)?;
                match op {
                    UnOp::Not => self.arena.bv_not(ta)?,
                    UnOp::Neg => self.arena.bv_neg(ta)?,
                }
            }
            Expr::Cmp { op, a, b, width } => {
                // Cmp.width is the operand (comparison) width; coerce both.
                let tw = width.bits() as u32;
                let ta = self.translate_coerced(a, tw)?;
                let tb = self.translate_coerced(b, tw)?;
                let boolt = match op {
                    CmpOp::Eq => self.arena.eq(ta, tb)?,
                    CmpOp::Ne => {
                        let e = self.arena.eq(ta, tb)?;
                        self.arena.not(e)?
                    }
                    CmpOp::Ult => self.arena.bv_ult(ta, tb)?,
                    CmpOp::Ule => self.arena.bv_ule(ta, tb)?,
                    CmpOp::Slt => self.arena.bv_slt(ta, tb)?,
                    CmpOp::Sle => self.arena.bv_sle(ta, tb)?,
                };
                // Lift Bool -> BitVec(1) so it composes like glaurung expects.
                self.bv1_of_bool(boolt)?
            }
            Expr::ZExt { a, from, to } => {
                let ta = self.translate_coerced(a, from.bits() as u32)?;
                let by = (to.bits() as u32).saturating_sub(from.bits() as u32);
                self.arena.zero_ext(by, ta)?
            }
            Expr::SExt { a, from, to } => {
                let ta = self.translate_coerced(a, from.bits() as u32)?;
                let by = (to.bits() as u32).saturating_sub(from.bits() as u32);
                self.arena.sign_ext(by, ta)?
            }
            Expr::Trunc { a, to } => {
                // Ensure the source is at least `to` bits, then take low bits.
                let tw = to.bits() as u32;
                let ta = self.translate_coerced(a, tw)?;
                self.arena.extract(tw.saturating_sub(1), 0, ta)?
            }
            Expr::Extract { a, hi, lo } => {
                // glaurung's `hi` is EXCLUSIVE (result width = hi - lo, byte
                // extract of a 64-bit value is hi=64,lo=56); axeyum/SMT
                // `extract(H,L)` is INCLUSIVE. glaurung's own z3/SMT lowering
                // uses `hi - 1` as the inclusive top index -- mirror it. Also
                // ensure the source is >= hi bits wide before extracting.
                let ta = self.translate_coerced(a, hi as u32)?;
                self.arena
                    .extract((hi as u32).saturating_sub(1), lo as u32, ta)?
            }
            Expr::Concat { hi, lo, hi_w, lo_w } => {
                let th = self.translate_coerced(hi, hi_w.bits() as u32)?;
                let tl = self.translate_coerced(lo, lo_w.bits() as u32)?;
                // SMT-LIB concat(a,b): a is the high half. glaurung Concat{hi,lo}.
                self.arena.concat(th, tl)?
            }
            Expr::Ite { c, t, e, width } => {
                let tw = width.bits() as u32;
                let bc = self.to_bool(c)?;
                let tt = self.translate_coerced(t, tw)?;
                let te = self.translate_coerced(e, tw)?;
                self.arena.ite(bc, tt, te)?
            }
        };
        self.memo.insert(id, t);
        Ok(t)
    }

    /// Translate `id`, then coerce it to `target` bits (zero-extend if
    /// narrower, truncate low bits if wider) -- mirroring z3_backend's
    /// `coerce`, so width-mismatched operands from the lifter are normalized
    /// to a shared sort before axeyum's strict builders see them.
    fn translate_coerced(&mut self, id: ExprId, target: u32) -> Result<TermId, IrError> {
        let t = self.translate(id)?;
        let cur = self.pool.width_of(id).bits() as u32;
        self.coerce(t, cur, target)
    }

    /// Coerce term `t` (currently `cur` bits) to `target` bits.
    fn coerce(&mut self, t: TermId, cur: u32, target: u32) -> Result<TermId, IrError> {
        if cur == target {
            Ok(t)
        } else if cur < target {
            self.arena.zero_ext(target - cur, t)
        } else {
            self.arena.extract(target.saturating_sub(1), 0, t)
        }
    }

    /// Lift a Bool term to a BitVec(1): `ite(b, 1, 0)`.
    fn bv1_of_bool(&mut self, b: TermId) -> Result<TermId, IrError> {
        let one = self.arena.bv_const(1, 1)?;
        let zero = self.arena.bv_const(1, 0)?;
        self.arena.ite(b, one, zero)
    }

    /// Convert a glaurung BV condition to an axeyum Bool: `c != 0`.
    fn to_bool(&mut self, c: ExprId) -> Result<TermId, IrError> {
        let tc = self.translate(c)?;
        let w = self.pool.width_of(c).bits() as u32;
        let zero = self.arena.bv_const(w, 0)?;
        let is_zero = self.arena.eq(tc, zero)?;
        self.arena.not(is_zero)
    }
}
