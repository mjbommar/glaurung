//! Hash-consed bit-vector expression IR for symbolic execution.
//!
//! Expressions are interned in an [`ExprPool`]: structurally-equal terms share
//! one [`ExprId`], so building is cheap, equality is O(1), and (later) the
//! solver/constraint caches can key on ids. Every node carries an explicit
//! [`Width`] — the same discipline as the executable LLIR — so lowering to SMT
//! QF_BV is total. See
//! `docs/history/execution-engine-2026-06/architecture/symbolic-engine.md`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;

use crate::exec::concrete::{shift_reduction, ShiftReduction, DIVIDE_BY_ZERO_QUOTIENT};
use crate::ir::types::{BinOp, CmpOp, UnOp, Width};

/// An interned expression handle (index into its [`ExprPool`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExprId(pub u32);

/// A bit-vector expression node. Children are [`ExprId`]s into the same pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expr {
    /// A constant of an explicit width.
    Const {
        value: u128,
        width: Width,
    },
    /// A free symbolic variable (a fresh input).
    Sym {
        id: u32,
        width: Width,
    },
    Bin {
        op: BinOp,
        a: ExprId,
        b: ExprId,
        width: Width,
    },
    Un {
        op: UnOp,
        a: ExprId,
        width: Width,
    },
    /// Comparison predicate; result width is always 1.
    Cmp {
        op: CmpOp,
        a: ExprId,
        b: ExprId,
        width: Width,
    },
    ZExt {
        a: ExprId,
        from: Width,
        to: Width,
    },
    SExt {
        a: ExprId,
        from: Width,
        to: Width,
    },
    Trunc {
        a: ExprId,
        to: Width,
    },
    Extract {
        a: ExprId,
        hi: u16,
        lo: u16,
    },
    Concat {
        hi: ExprId,
        lo: ExprId,
        hi_w: Width,
        lo_w: Width,
    },
    Ite {
        c: ExprId,
        t: ExprId,
        e: ExprId,
        width: Width,
    },
}

/// An interning pool of expressions.
///
/// `Clone` is used to fork symbolic states; each forked state currently carries
/// its own pool copy (correct — its `ExprId`s stay valid within it). A shared
/// copy-on-write pool is a future optimization (see Phase 5 notes).
#[derive(Debug, Default, Clone)]
pub struct ExprPool {
    nodes: Vec<Expr>,
    intern: HashMap<Expr, ExprId>,
    next_sym: u32,
}

impl ExprPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Distinct interned nodes in the pool.
    ///
    /// This is the pool's *DAG* size. It is deliberately not the size of the
    /// tree any one node denotes: interning shares structural equals, so a node
    /// whose tree is astronomically large can be a handful of entries here.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the pool holds no nodes.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Intern a node, returning its (shared) id.
    pub fn intern(&mut self, e: Expr) -> ExprId {
        if let Some(id) = self.intern.get(&e) {
            return *id;
        }
        let id = ExprId(self.nodes.len() as u32);
        self.nodes.push(e.clone());
        self.intern.insert(e, id);
        id
    }

    /// The node behind an id.
    pub fn get(&self, id: ExprId) -> &Expr {
        &self.nodes[id.0 as usize]
    }

    /// Mint a fresh symbolic variable of the given width.
    pub fn fresh_symbol(&mut self, width: Width) -> ExprId {
        let id = self.next_sym;
        self.next_sym += 1;
        self.intern(Expr::Sym { id, width })
    }

    /// Convenience: an interned constant, reduced to `width`.
    pub fn constant(&mut self, width: Width, value: u128) -> ExprId {
        let v = if width.bits() >= 128 {
            value
        } else {
            value & ((1u128 << width.bits()) - 1)
        };
        self.intern(Expr::Const { value: v, width })
    }

    /// The bit width of an expression.
    pub fn width_of(&self, id: ExprId) -> Width {
        match self.get(id) {
            Expr::Const { width, .. } => *width,
            Expr::Sym { width, .. } => *width,
            Expr::Bin { width, .. } => *width,
            Expr::Un { width, .. } => *width,
            Expr::Cmp { .. } => Width::W1,
            Expr::ZExt { to, .. } => *to,
            Expr::SExt { to, .. } => *to,
            Expr::Trunc { to, .. } => *to,
            Expr::Extract { hi, lo, .. } => Width(hi - lo),
            Expr::Concat { hi_w, lo_w, .. } => Width(hi_w.bits() + lo_w.bits()),
            Expr::Ite { width, .. } => *width,
        }
    }

    /// Render an expression as an SMT-LIB2 QF_BV term.
    pub fn render_smtlib(&self, id: ExprId) -> String {
        match self.get(id) {
            Expr::Const { value, width } => format!("(_ bv{} {})", value, width.bits()),
            Expr::Sym { id, width } => format!("sym{}_{}", id, width.bits()),
            Expr::Bin { op, a, b, width } => {
                // Coerce both operands to the node width so the emitted
                // SMT-LIB is well-typed (the lifter emits width-mismatched
                // operands; the AST backends coerce, so the text must too).
                Self::render_bin(
                    *op,
                    &self.render_coerced(*a, width.bits()),
                    &self.render_coerced(*b, width.bits()),
                    width.bits(),
                )
            }
            Expr::Un { op, a, .. } => {
                let f = match op {
                    UnOp::Not => "bvnot",
                    UnOp::Neg => "bvneg",
                };
                format!("({} {})", f, self.render_smtlib(*a))
            }
            Expr::Cmp { op, a, b, width } => {
                let (pred, signed) = match op {
                    CmpOp::Eq => ("=", false),
                    CmpOp::Ne => ("distinct", false),
                    CmpOp::Ult => ("bvult", false),
                    CmpOp::Ule => ("bvule", false),
                    CmpOp::Slt => ("bvslt", true),
                    CmpOp::Sle => ("bvsle", true),
                };
                let _ = signed;
                format!(
                    "(ite ({} {} {}) (_ bv1 1) (_ bv0 1))",
                    pred,
                    self.render_coerced(*a, width.bits()),
                    self.render_coerced(*b, width.bits())
                )
            }
            Expr::ZExt { a, from, to } => format!(
                "((_ zero_extend {}) {})",
                to.bits() - from.bits(),
                self.render_coerced(*a, from.bits())
            ),
            Expr::SExt { a, from, to } => format!(
                "((_ sign_extend {}) {})",
                to.bits() - from.bits(),
                self.render_coerced(*a, from.bits())
            ),
            Expr::Trunc { a, to } => {
                // Ensure the source is at least `to` bits before extracting.
                format!(
                    "((_ extract {} 0) {})",
                    to.bits() - 1,
                    self.render_coerced(*a, to.bits())
                )
            }
            Expr::Extract { a, hi, lo } => {
                // Ensure the source is >= hi bits before extracting [hi-1:lo].
                format!(
                    "((_ extract {} {}) {})",
                    hi - 1,
                    lo,
                    self.render_coerced(*a, *hi)
                )
            }
            Expr::Concat { hi, lo, hi_w, lo_w } => format!(
                "(concat {} {})",
                self.render_coerced(*hi, hi_w.bits()),
                self.render_coerced(*lo, lo_w.bits())
            ),
            Expr::Ite { c, t, e, width } => format!(
                "(ite (= {} (_ bv1 1)) {} {})",
                self.render_smtlib(*c),
                self.render_coerced(*t, width.bits()),
                self.render_coerced(*e, width.bits())
            ),
        }
    }

    /// Render one term with deterministic nested `let` bindings for every
    /// reachable non-leaf DAG node. SMT-LIB `let` bindings are simultaneous,
    /// so nesting keeps each later definition in scope while preserving the
    /// pool's structural sharing instead of recursively expanding it.
    pub fn render_smtlib_shared(&self, root: ExprId) -> String {
        let mut order = Vec::new();
        let mut seen = HashSet::new();
        let mut stack = vec![(root, false)];
        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                order.push(id);
                continue;
            }
            if !seen.insert(id) || self.is_leaf(id) {
                continue;
            }
            stack.push((id, true));
            match *self.get(id) {
                Expr::Bin { a, b, .. } | Expr::Cmp { a, b, .. } => {
                    stack.push((b, false));
                    stack.push((a, false));
                }
                Expr::Un { a, .. }
                | Expr::ZExt { a, .. }
                | Expr::SExt { a, .. }
                | Expr::Trunc { a, .. }
                | Expr::Extract { a, .. } => stack.push((a, false)),
                Expr::Concat { hi, lo, .. } => {
                    stack.push((lo, false));
                    stack.push((hi, false));
                }
                Expr::Ite { c, t, e, .. } => {
                    stack.push((e, false));
                    stack.push((t, false));
                    stack.push((c, false));
                }
                Expr::Const { .. } | Expr::Sym { .. } => unreachable!("leaf returned above"),
            }
        }

        let bound = order
            .iter()
            .copied()
            .enumerate()
            .map(|(ordinal, id)| (id, ordinal))
            .collect::<BTreeMap<_, _>>();
        let mut rendered = String::new();
        for id in &order {
            write!(
                rendered,
                "(let ((g!{} {})) ",
                bound[id],
                self.render_shared_node(*id, &bound)
            )
            .expect("writing to a String cannot fail");
        }
        rendered.push_str(&self.render_shared_ref(root, &bound));
        rendered.extend(std::iter::repeat_n(')', order.len()));
        rendered
    }

    fn is_leaf(&self, id: ExprId) -> bool {
        matches!(self.get(id), Expr::Const { .. } | Expr::Sym { .. })
    }

    fn render_shared_ref(&self, id: ExprId, bound: &BTreeMap<ExprId, usize>) -> String {
        if let Some(ordinal) = bound.get(&id) {
            format!("g!{ordinal}")
        } else {
            self.render_smtlib(id)
        }
    }

    fn render_shared_coerced(
        &self,
        id: ExprId,
        target: u16,
        bound: &BTreeMap<ExprId, usize>,
    ) -> String {
        let current = self.width_of(id).bits();
        let inner = self.render_shared_ref(id, bound);
        if current == target {
            inner
        } else if current < target {
            format!("((_ zero_extend {}) {})", target - current, inner)
        } else {
            format!("((_ extract {} 0) {})", target - 1, inner)
        }
    }

    fn render_shared_node(&self, id: ExprId, bound: &BTreeMap<ExprId, usize>) -> String {
        match self.get(id) {
            Expr::Const { .. } | Expr::Sym { .. } => self.render_smtlib(id),
            Expr::Bin { op, a, b, width } => Self::render_bin(
                *op,
                &self.render_shared_coerced(*a, width.bits(), bound),
                &self.render_shared_coerced(*b, width.bits(), bound),
                width.bits(),
            ),
            Expr::Un { op, a, .. } => {
                let function = match op {
                    UnOp::Not => "bvnot",
                    UnOp::Neg => "bvneg",
                };
                format!("({function} {})", self.render_shared_ref(*a, bound))
            }
            Expr::Cmp { op, a, b, width } => {
                let predicate = match op {
                    CmpOp::Eq => "=",
                    CmpOp::Ne => "distinct",
                    CmpOp::Ult => "bvult",
                    CmpOp::Ule => "bvule",
                    CmpOp::Slt => "bvslt",
                    CmpOp::Sle => "bvsle",
                };
                format!(
                    "(ite ({predicate} {} {}) (_ bv1 1) (_ bv0 1))",
                    self.render_shared_coerced(*a, width.bits(), bound),
                    self.render_shared_coerced(*b, width.bits(), bound)
                )
            }
            Expr::ZExt { a, from, to } => format!(
                "((_ zero_extend {}) {})",
                to.bits() - from.bits(),
                self.render_shared_coerced(*a, from.bits(), bound)
            ),
            Expr::SExt { a, from, to } => format!(
                "((_ sign_extend {}) {})",
                to.bits() - from.bits(),
                self.render_shared_coerced(*a, from.bits(), bound)
            ),
            Expr::Trunc { a, to } => format!(
                "((_ extract {} 0) {})",
                to.bits() - 1,
                self.render_shared_coerced(*a, to.bits(), bound)
            ),
            Expr::Extract { a, hi, lo } => format!(
                "((_ extract {} {}) {})",
                hi - 1,
                lo,
                self.render_shared_coerced(*a, *hi, bound)
            ),
            Expr::Concat { hi, lo, hi_w, lo_w } => format!(
                "(concat {} {})",
                self.render_shared_coerced(*hi, hi_w.bits(), bound),
                self.render_shared_coerced(*lo, lo_w.bits(), bound)
            ),
            Expr::Ite { c, t, e, width } => format!(
                "(ite (= {} (_ bv1 1)) {} {})",
                self.render_shared_ref(*c, bound),
                self.render_shared_coerced(*t, width.bits(), bound),
                self.render_shared_coerced(*e, width.bits(), bound)
            ),
        }
    }

    /// Render one [`Expr::Bin`] from operand text already coerced to `width`
    /// bits. Both renderers funnel through here, so they cannot drift and the
    /// semantic corrections below are stated once.
    ///
    /// # Which side moves, and why
    ///
    /// SMT-LIB and [`crate::exec::Concrete`] disagree on two operations, and
    /// this function moves **SMT to the concrete domain**, never the reverse:
    ///
    /// * A shift distance at or above the operand width *saturates* in SMT-LIB
    ///   (`bvshl` of `1` by `32` at 32 bits is `0`) but is taken **modulo the
    ///   width** concretely (`1`), which is what x86 `shl`/`shr`/`sar` and A64
    ///   `LSLV`/`LSRV`/`ASRV` do.
    /// * Division by zero is all-ones under `bvudiv` and `0` concretely.
    ///
    /// The concrete domain is the reference for three reasons, in increasing
    /// order of force. It matches the hardware the LLIR is lifted from. It is
    /// the domain `crate::symbolic::symdomain::Symbolic` already folds
    /// constants in, so leaving the text alone left one pool answering `1` for
    /// a folded `1 << 32` and `0` for a symbolic one. And it is the domain a
    /// solver *model* is replayed in: an equivalence checker reads `unsat` as
    /// "equivalent", and an `unsat` carries no model, so nothing downstream can
    /// catch a miter that was unsatisfiable only because the solver was
    /// answering about a different function than the one that runs. That is a
    /// false `Equivalent` — the one verdict such a checker must never emit.
    /// The same mismatch in the other direction produces a spurious `sat`
    /// whose model does not reproduce, which `crate::csource::equiv` has to
    /// discard as `Unknown::WitnessUnconfirmed`.
    ///
    /// Changing `Concrete` instead was rejected: it would make the emulator
    /// disagree with the CPUs it emulates, which the `dev-oracle` differential
    /// against Unicorn checks directly.
    ///
    /// The masks are derived from `width`, never hardcoded: [`Width`] is a
    /// `u16` and [`Expr::Extract`]/[`Expr::Concat`] mint widths that are not
    /// powers of two, so the exact `b mod width` needs `bvurem` whenever the
    /// cheap `bvand` of `width - 1` would not be the same function.
    fn render_bin(op: BinOp, a: &str, b: &str, width: u16) -> String {
        let zero = format!("(_ bv0 {width})");
        match op {
            // Source-level short-circuit operators are truthiness tests, not
            // bit-vector functions.
            BinOp::LogicalAnd | BinOp::LogicalOr => {
                let predicate = if op == BinOp::LogicalAnd { "and" } else { "or" };
                format!(
                    "(ite ({predicate} (distinct {a} {zero}) (distinct {b} {zero})) \
                     (_ bv1 {width}) {zero})"
                )
            }
            BinOp::Add => format!("(bvadd {a} {b})"),
            BinOp::Sub => format!("(bvsub {a} {b})"),
            BinOp::Mul => format!("(bvmul {a} {b})"),
            BinOp::And => format!("(bvand {a} {b})"),
            BinOp::Or => format!("(bvor {a} {b})"),
            BinOp::Xor => format!("(bvxor {a} {b})"),
            // `Concrete` yields 0 for a divide by zero (a real divide fault is
            // modelled by a helper, not the value domain); `bvudiv` is all
            // ones. Guard it rather than leave the two functions different.
            BinOp::Div => format!(
                "(ite (= {b} {zero}) (_ bv{DIVIDE_BY_ZERO_QUOTIENT} {width}) (bvudiv {a} {b}))"
            ),
            BinOp::Shl | BinOp::Shr | BinOp::Sar => {
                let function = match op {
                    BinOp::Shl => "bvshl",
                    BinOp::Shr => "bvlshr",
                    _ => "bvashr",
                };
                format!("({function} {a} {})", Self::shift_distance(b, width))
            }
        }
    }

    /// The reduced shift distance as an SMT-LIB term.
    ///
    /// The *decision* comes from [`shift_reduction`], which `Concrete` obeys
    /// too; this function only renders it. A power-of-two width masks, which is
    /// the same function as the modulo and far cheaper for a bit-blasting
    /// solver; every other width needs the real `bvurem`.
    fn shift_distance(b: &str, width: u16) -> String {
        match shift_reduction(Width(width)) {
            ShiftReduction::Mask(mask) => format!("(bvand {b} (_ bv{mask} {width}))"),
            ShiftReduction::Modulo(modulus) => format!("(bvurem {b} (_ bv{modulus} {width}))"),
            ShiftReduction::Passthrough => b.to_string(),
        }
    }

    /// Render `id` coerced to `target` bits: zero-extend if narrower, extract
    /// low bits if wider. Mirrors the AST backends' `coerce` so the emitted
    /// SMT-LIB text is always well-typed.
    fn render_coerced(&self, id: ExprId, target: u16) -> String {
        let cur = self.width_of(id).bits();
        let inner = self.render_smtlib(id);
        if cur == target {
            inner
        } else if cur < target {
            format!("((_ zero_extend {}) {})", target - cur, inner)
        } else {
            format!("((_ extract {} 0) {})", target - 1, inner)
        }
    }

    /// If `id` is a constant, return its value.
    pub fn as_const(&self, id: ExprId) -> Option<u128> {
        match self.get(id) {
            Expr::Const { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Collect every free symbol `(id, width)` reachable from `root`. Memoized
    /// over visited nodes: expressions are a hash-consed DAG with heavy sharing
    /// (obfuscated code in particular), so a naive recursion is exponential.
    pub fn collect_syms(&self, root: ExprId, out: &mut std::collections::BTreeMap<u32, Width>) {
        let mut seen = std::collections::HashSet::new();
        self.collect_syms_rec(root, out, &mut seen);
    }

    fn collect_syms_rec(
        &self,
        root: ExprId,
        out: &mut std::collections::BTreeMap<u32, Width>,
        seen: &mut std::collections::HashSet<ExprId>,
    ) {
        if !seen.insert(root) {
            return;
        }
        match *self.get(root) {
            Expr::Const { .. } => {}
            Expr::Sym { id, width } => {
                out.insert(id, width);
            }
            Expr::Bin { a, b, .. } | Expr::Cmp { a, b, .. } => {
                self.collect_syms_rec(a, out, seen);
                self.collect_syms_rec(b, out, seen);
            }
            Expr::Un { a, .. }
            | Expr::ZExt { a, .. }
            | Expr::SExt { a, .. }
            | Expr::Trunc { a, .. }
            | Expr::Extract { a, .. } => self.collect_syms_rec(a, out, seen),
            Expr::Concat { hi, lo, .. } => {
                self.collect_syms_rec(hi, out, seen);
                self.collect_syms_rec(lo, out, seen);
            }
            Expr::Ite { c, t, e, .. } => {
                self.collect_syms_rec(c, out, seen);
                self.collect_syms_rec(t, out, seen);
                self.collect_syms_rec(e, out, seen);
            }
        }
    }

    /// The SMT-LIB symbol name for a free variable `(id, width)`.
    pub fn sym_name(id: u32, width: Width) -> String {
        format!("sym{}_{}", id, width.bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_shares_structural_equals() {
        let mut p = ExprPool::new();
        let a = p.intern(Expr::Const {
            value: 5,
            width: Width::W32,
        });
        let b = p.intern(Expr::Const {
            value: 5,
            width: Width::W32,
        });
        assert_eq!(a, b, "equal constants must share an id");
        let c = p.intern(Expr::Const {
            value: 6,
            width: Width::W32,
        });
        assert_ne!(a, c);
    }

    #[test]
    fn fresh_symbols_are_distinct() {
        let mut p = ExprPool::new();
        let s1 = p.fresh_symbol(Width::W32);
        let s2 = p.fresh_symbol(Width::W32);
        assert_ne!(s1, s2);
        assert_eq!(p.width_of(s1), Width::W32);
    }

    #[test]
    fn width_tracking() {
        let mut p = ExprPool::new();
        let s = p.fresh_symbol(Width::W32);
        let z = p.intern(Expr::ZExt {
            a: s,
            from: Width::W32,
            to: Width::W64,
        });
        assert_eq!(p.width_of(z), Width::W64);
        let cmp = p.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: s,
            b: s,
            width: Width::W32,
        });
        assert_eq!(p.width_of(cmp), Width::W1);
    }

    #[test]
    fn extension_rendering_coerces_to_declared_source_width() {
        let mut p = ExprPool::new();
        let wide = p.constant(Width::W64, 0x1_0000_0001);
        let z = p.intern(Expr::ZExt {
            a: wide,
            from: Width::W32,
            to: Width::W64,
        });
        assert_eq!(
            p.render_smtlib(z),
            "((_ zero_extend 32) ((_ extract 31 0) (_ bv4294967297 64)))"
        );
    }

    #[test]
    fn concat_rendering_coerces_to_declared_operand_widths() {
        let mut p = ExprPool::new();
        let hi = p.constant(Width(56), 0x12);
        let lo = p.constant(Width::W1, 1);
        let cat = p.intern(Expr::Concat {
            hi,
            lo,
            hi_w: Width(56),
            lo_w: Width::W8,
        });
        assert_eq!(
            p.render_smtlib(cat),
            "(concat (_ bv18 56) ((_ zero_extend 7) (_ bv1 1)))"
        );
    }

    #[test]
    fn smtlib_rendering_of_a_constraint() {
        // (bvadd sym0_32 (_ bv1 32)) == 0x100  → an Eq predicate term
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W32);
        let one = p.intern(Expr::Const {
            value: 1,
            width: Width::W32,
        });
        let sum = p.intern(Expr::Bin {
            op: BinOp::Add,
            a: x,
            b: one,
            width: Width::W32,
        });
        let k = p.intern(Expr::Const {
            value: 0x100,
            width: Width::W32,
        });
        let eq = p.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: sum,
            b: k,
            width: Width::W32,
        });
        let s = p.render_smtlib(eq);
        assert_eq!(
            s,
            "(ite (= (bvadd sym0_32 (_ bv1 32)) (_ bv256 32)) (_ bv1 1) (_ bv0 1))"
        );
    }

    #[test]
    fn source_logical_binops_render_as_booleanized_bitvectors() {
        let mut p = ExprPool::new();
        let lhs = p.fresh_symbol(Width::W32);
        let rhs = p.constant(Width::W32, 7);
        let either = p.intern(Expr::Bin {
            op: BinOp::LogicalOr,
            a: lhs,
            b: rhs,
            width: Width::W32,
        });

        let expected = concat!(
            "(ite (or (distinct sym0_32 (_ bv0 32)) ",
            "(distinct (_ bv7 32) (_ bv0 32))) (_ bv1 32) (_ bv0 32))"
        );
        assert_eq!(p.render_smtlib(either), expected);
        assert_eq!(
            p.render_smtlib_shared(either),
            format!("(let ((g!0 {expected})) g!0)")
        );
    }

    #[test]
    fn shared_smtlib_rendering_is_linear_in_the_expression_dag() {
        let mut p = ExprPool::new();
        let x = p.fresh_symbol(Width::W64);
        let one = p.constant(Width::W64, 1);
        let mut root = p.intern(Expr::Bin {
            op: BinOp::Add,
            a: x,
            b: one,
            width: Width::W64,
        });
        for _ in 0..24 {
            root = p.intern(Expr::Bin {
                op: BinOp::Xor,
                a: root,
                b: root,
                width: Width::W64,
            });
        }

        let rendered = p.render_smtlib_shared(root);
        assert!(rendered.starts_with("(let ((g!"));
        assert_eq!(rendered.matches("bvxor").count(), 24);
        assert_eq!(rendered.matches("bvadd").count(), 1);
        assert!(
            rendered.len() < 4_096,
            "shared DAG expanded: {} bytes",
            rendered.len()
        );
    }

    #[test]
    fn shared_smtlib_rendering_is_independent_of_pool_expression_ids() {
        fn diamond(pool: &mut ExprPool) -> ExprId {
            let x = pool.fresh_symbol(Width::W64);
            let one = pool.constant(Width::W64, 1);
            let mut root = pool.intern(Expr::Bin {
                op: BinOp::Add,
                a: x,
                b: one,
                width: Width::W64,
            });
            for _ in 0..4 {
                root = pool.intern(Expr::Bin {
                    op: BinOp::Xor,
                    a: root,
                    b: root,
                    width: Width::W64,
                });
            }
            root
        }

        let mut first = ExprPool::new();
        let first_root = diamond(&mut first);

        let mut shifted = ExprPool::new();
        shifted.constant(Width::W8, 7);
        let shifted_root = diamond(&mut shifted);

        assert_ne!(first_root, shifted_root);
        assert_eq!(
            first.render_smtlib_shared(first_root),
            shifted.render_smtlib_shared(shifted_root)
        );
    }
}

/// Differential tests: the SMT-LIB text this module renders must denote the
/// same function as [`crate::exec::Concrete`], the domain the engine executes
/// and the domain a solver model is replayed in.
///
/// The two disagree by default. SMT-LIB defines `bvshl`/`bvlshr`/`bvashr` to
/// saturate when the distance reaches the operand width, and `bvudiv` by zero
/// to be all-ones; the concrete domain takes the distance *modulo* the width
/// (x86 `shl`/`sal`, A64 `LSLV`) and yields `0` for a divide by zero. A miter
/// built for equivalence checking is `unsat` — "equivalent" — exactly when the
/// two functions agree under the *solver's* reading, so any disagreement here
/// is a way to prove two behaviourally different functions equivalent.
#[cfg(test)]
pub(crate) mod smt_concrete_agreement {
    use super::*;
    use crate::exec::domain::Domain;
    use crate::exec::Concrete;
    use std::collections::HashMap;

    // ------------------------------------------------------------------
    // A small, independent SMT-LIB2 QF_BV evaluator.
    //
    // It implements the *standard's* semantics (saturating shifts, all-ones
    // division by zero), deliberately not this module's, so agreement with
    // `Concrete` is a real check rather than the renderer marking its own
    // homework. It also runs everywhere, including CI lanes that provision no
    // solver binary; `solver_agrees_with_concrete` cross-checks it against a
    // real solver whenever one is on `PATH`.
    // ------------------------------------------------------------------

    #[derive(Debug, Clone)]
    enum Sexp {
        Atom(String),
        List(Vec<Sexp>),
    }

    fn parse(text: &str) -> Sexp {
        let spaced = text.replace('(', " ( ").replace(')', " ) ");
        let tokens: Vec<String> = spaced.split_whitespace().map(str::to_string).collect();
        let mut cursor = 0usize;
        let out = parse_at(&tokens, &mut cursor);
        assert_eq!(cursor, tokens.len(), "trailing tokens in {text:?}");
        out
    }

    fn parse_at(tokens: &[String], cursor: &mut usize) -> Sexp {
        let head = tokens[*cursor].clone();
        *cursor += 1;
        if head != "(" {
            return Sexp::Atom(head);
        }
        let mut items = Vec::new();
        while tokens[*cursor] != ")" {
            items.push(parse_at(tokens, cursor));
        }
        *cursor += 1;
        Sexp::List(items)
    }

    fn atom(s: &Sexp) -> String {
        match s {
            Sexp::Atom(a) => a.clone(),
            Sexp::List(_) => panic!("expected an atom, found a list"),
        }
    }

    fn all_ones(width: u16) -> u128 {
        if width >= 128 {
            u128::MAX
        } else if width == 0 {
            0
        } else {
            (1u128 << width) - 1
        }
    }

    fn signed_of(bits: u128, width: u16) -> i128 {
        if width == 0 || width >= 128 {
            return bits as i128;
        }
        if (bits >> (width - 1)) & 1 == 1 {
            (bits | !all_ones(width)) as i128
        } else {
            bits as i128
        }
    }

    type Env = HashMap<String, (u128, u16)>;

    /// Evaluate a ground bit-vector term, returning `(value, width)`.
    fn eval_bv(term: &Sexp, env: &Env) -> (u128, u16) {
        let items = match term {
            Sexp::Atom(name) => {
                return *env
                    .get(name)
                    .unwrap_or_else(|| panic!("unbound symbol {name}"))
            }
            Sexp::List(items) => items,
        };

        // Indexed operators: `((_ zero_extend n) x)`, `((_ extract h l) x)`.
        if let Sexp::List(head) = &items[0] {
            let (value, width) = eval_bv(&items[1], env);
            let name = atom(&head[1]);
            return match name.as_str() {
                "zero_extend" => {
                    let by: u16 = atom(&head[2]).parse().unwrap();
                    (value, width + by)
                }
                "sign_extend" => {
                    let by: u16 = atom(&head[2]).parse().unwrap();
                    let to = width + by;
                    ((signed_of(value, width) as u128) & all_ones(to), to)
                }
                "extract" => {
                    let hi: u16 = atom(&head[2]).parse().unwrap();
                    let lo: u16 = atom(&head[3]).parse().unwrap();
                    let to = hi - lo + 1;
                    ((value >> lo) & all_ones(to), to)
                }
                other => panic!("unsupported indexed operator {other}"),
            };
        }

        let head = atom(&items[0]);
        match head.as_str() {
            // `(_ bvN W)` — a bit-vector literal.
            "_" => {
                let literal = atom(&items[1]);
                let value: u128 = literal
                    .strip_prefix("bv")
                    .expect("bit-vector literal")
                    .parse()
                    .unwrap();
                let width: u16 = atom(&items[2]).parse().unwrap();
                (value & all_ones(width), width)
            }
            // `render_smtlib_shared` emits singly-bound, nested lets.
            "let" => {
                let mut inner = env.clone();
                if let Sexp::List(bindings) = &items[1] {
                    for binding in bindings {
                        if let Sexp::List(pair) = binding {
                            let bound = eval_bv(&pair[1], &inner);
                            inner.insert(atom(&pair[0]), bound);
                        }
                    }
                }
                eval_bv(&items[2], &inner)
            }
            "ite" => {
                if eval_bool(&items[1], env) {
                    eval_bv(&items[2], env)
                } else {
                    eval_bv(&items[3], env)
                }
            }
            "concat" => {
                let (hi, hi_w) = eval_bv(&items[1], env);
                let (lo, lo_w) = eval_bv(&items[2], env);
                let to = hi_w + lo_w;
                ((((hi << lo_w) | lo) & all_ones(to)), to)
            }
            "bvnot" => {
                let (a, w) = eval_bv(&items[1], env);
                (!a & all_ones(w), w)
            }
            "bvneg" => {
                let (a, w) = eval_bv(&items[1], env);
                (a.wrapping_neg() & all_ones(w), w)
            }
            _ => {
                let (a, aw) = eval_bv(&items[1], env);
                let (b, bw) = eval_bv(&items[2], env);
                assert_eq!(aw, bw, "operand width mismatch under {head}");
                let width = aw;
                let mask = all_ones(width);
                let raw = match head.as_str() {
                    "bvadd" => a.wrapping_add(b),
                    "bvsub" => a.wrapping_sub(b),
                    "bvmul" => a.wrapping_mul(b),
                    "bvand" => a & b,
                    "bvor" => a | b,
                    "bvxor" => a ^ b,
                    // SMT-LIB 2.6: division by zero is all ones, remainder by
                    // zero is the dividend.
                    "bvudiv" => {
                        if b == 0 {
                            mask
                        } else {
                            a / b
                        }
                    }
                    "bvurem" => {
                        if b == 0 {
                            a
                        } else {
                            a % b
                        }
                    }
                    // SMT-LIB 2.6: a distance at or above the width saturates.
                    // It does NOT wrap, which is the whole defect under test.
                    "bvshl" => {
                        if b >= u128::from(width) {
                            0
                        } else {
                            a.wrapping_shl(b as u32)
                        }
                    }
                    "bvlshr" => {
                        if b >= u128::from(width) {
                            0
                        } else {
                            a >> b
                        }
                    }
                    "bvashr" => {
                        let negative = width > 0 && (a >> (width - 1)) & 1 == 1;
                        if b >= u128::from(width) {
                            if negative {
                                mask
                            } else {
                                0
                            }
                        } else {
                            (signed_of(a, width) >> b) as u128
                        }
                    }
                    other => panic!("unsupported operator {other}"),
                };
                (raw & mask, width)
            }
        }
    }

    fn eval_bool(term: &Sexp, env: &Env) -> bool {
        let items = match term {
            Sexp::List(items) => items,
            Sexp::Atom(a) => panic!("expected a predicate, found atom {a}"),
        };
        let head = atom(&items[0]);
        match head.as_str() {
            "and" => items[1..].iter().all(|x| eval_bool(x, env)),
            "or" => items[1..].iter().any(|x| eval_bool(x, env)),
            "not" => !eval_bool(&items[1], env),
            _ => {
                let (a, _) = eval_bv(&items[1], env);
                let (b, bw) = eval_bv(&items[2], env);
                match head.as_str() {
                    "=" => a == b,
                    "distinct" => a != b,
                    "bvult" => a < b,
                    "bvule" => a <= b,
                    "bvslt" => signed_of(a, bw) < signed_of(b, bw),
                    "bvsle" => signed_of(a, bw) <= signed_of(b, bw),
                    other => panic!("unsupported predicate {other}"),
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // The case table.
    // ------------------------------------------------------------------

    /// `(op, a, b, width)` triples covering shift distances below, at and above
    /// the operand width, and division by zero, at several widths including one
    /// that is not a power of two.
    pub(crate) fn cases() -> Vec<(BinOp, u128, u128, Width)> {
        let mut out = Vec::new();
        for width in [
            Width(1),
            Width(8),
            Width(12),
            Width(16),
            Width::W32,
            Width::W64,
        ] {
            let bits = u128::from(width.bits());
            let top = all_ones(width.bits());
            let sign = if width.bits() == 0 {
                0
            } else {
                1u128 << (width.bits() - 1)
            };
            let lhs = [0u128, 1, 3, sign, top, 0x1234_5678 & top];
            let mut rhs = vec![
                0u128,
                1,
                bits / 2,
                bits.saturating_sub(1),
                bits,
                bits + 1,
                2 * bits,
                255,
            ];
            rhs.dedup();
            for a in lhs {
                for &b in &rhs {
                    // `b` is a domain value at the same width, so reduce it the
                    // way the pool's `constant` would.
                    let b = b & top;
                    for op in [BinOp::Shl, BinOp::Shr, BinOp::Sar, BinOp::Div] {
                        out.push((op, a, b, width));
                    }
                }
            }
        }
        // The measured case: `1u32 << 32` and `<< 33`, which x86 and A64 make
        // `1` and `2`, and which `bvshl` makes `0`.
        out.push((BinOp::Shl, 1, 32, Width::W32));
        out.push((BinOp::Shl, 1, 33, Width::W32));
        out
    }

    fn build(pool: &mut ExprPool, op: BinOp, a: u128, b: u128, width: Width) -> ExprId {
        let a = pool.constant(width, a);
        let b = pool.constant(width, b);
        pool.intern(Expr::Bin { op, a, b, width })
    }

    /// Every rendered term must denote what the concrete domain computes, under
    /// both renderers.
    #[test]
    fn rendered_smtlib_agrees_with_the_concrete_domain() {
        let env = Env::new();
        let mut mismatches: Vec<String> = Vec::new();
        for (op, a, b, width) in cases() {
            let expected = Concrete.binop(op, &a, &b, width);
            let mut pool = ExprPool::new();
            let root = build(&mut pool, op, a, b, width);
            for (label, text) in [
                ("render_smtlib", pool.render_smtlib(root)),
                ("render_smtlib_shared", pool.render_smtlib_shared(root)),
            ] {
                let (got, got_w) = eval_bv(&parse(&text), &env);
                assert_eq!(got_w, width.bits(), "{label} changed the result width");
                if got != expected {
                    mismatches.push(format!(
                        "{label}: {op:?} a={a:#x} b={b:#x} w={} -> smt {got:#x}, concrete {expected:#x}   [{text}]",
                        width.bits()
                    ));
                }
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} of {} rendered terms disagree with `Concrete`:\n{}",
            mismatches.len(),
            cases().len() * 2,
            mismatches.join("\n")
        );
    }

    /// The measured false-`Equivalent` case, spelled out: `117_modular_arithmetic.c`
    /// guards `e > 31` in the original and `e > 32` in the mutant, so the two
    /// differ at `e == 32` — but only if `1 << 32` is `1`, as the hardware and
    /// the concrete domain say, rather than `0`, as bare `bvshl` says.
    #[test]
    fn shift_by_the_width_wraps_and_does_not_saturate() {
        let env = Env::new();
        for (distance, expected) in [(31u128, 1u128 << 31), (32, 1), (33, 2), (64, 1)] {
            let mut pool = ExprPool::new();
            let root = build(&mut pool, BinOp::Shl, 1, distance, Width::W32);
            assert_eq!(
                Concrete.binop(BinOp::Shl, &1, &distance, Width::W32),
                expected,
                "the concrete domain is the reference and must wrap"
            );
            for text in [pool.render_smtlib(root), pool.render_smtlib_shared(root)] {
                assert_eq!(
                    eval_bv(&parse(&text), &env).0,
                    expected,
                    "1u32 << {distance} rendered as {text}"
                );
            }
        }
    }

    /// Division by zero is `0` concretely; bare `bvudiv` makes it all ones.
    #[test]
    fn division_by_zero_is_zero_not_all_ones() {
        let env = Env::new();
        for width in [Width::W8, Width(12), Width::W32, Width::W64] {
            let mut pool = ExprPool::new();
            let root = build(&mut pool, BinOp::Div, 7, 0, width);
            assert_eq!(Concrete.binop(BinOp::Div, &7, &0, width), 0);
            for text in [pool.render_smtlib(root), pool.render_smtlib_shared(root)] {
                assert_eq!(
                    eval_bv(&parse(&text), &env).0,
                    0,
                    "7 / 0 at {} bits rendered as {text}",
                    width.bits()
                );
            }
        }
    }

    /// The third leg: what the CPU actually does.
    ///
    /// Checking a renderer against our own emulator alone is a second-
    /// translation trap — both could be wrong the same way. These numbers are
    /// *measured*, from a program that shifts by a `volatile` count so gcc
    /// cannot fold the (C-undefined) wide shift and has to emit a real machine
    /// shift, making the observed answer the CPU's rule rather than the
    /// compiler's:
    ///
    /// ```text
    /// $ gcc --version | head -1
    /// gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0
    /// $ gcc -O1 -o shift3 shift3.c && ./shift3        # identical at -O0/-O2
    /// count=  0  shl32(1)=0x00000001 shr32(0x80000000)=0x80000000 sar32(-8)= -8 shl64(1)=0x0000000000000001
    /// count=  1  shl32(1)=0x00000002 shr32(0x80000000)=0x40000000 sar32(-8)= -4 shl64(1)=0x0000000000000002
    /// count= 31  shl32(1)=0x80000000 shr32(0x80000000)=0x00000001 sar32(-8)= -1 shl64(1)=0x0000000080000000
    /// count= 32  shl32(1)=0x00000001 shr32(0x80000000)=0x80000000 sar32(-8)= -8 shl64(1)=0x0000000100000000
    /// count= 33  shl32(1)=0x00000002 shr32(0x80000000)=0x40000000 sar32(-8)= -4 shl64(1)=0x0000000200000000
    /// count= 64  shl32(1)=0x00000001 shr32(0x80000000)=0x80000000 sar32(-8)= -8 shl64(1)=0x0000000000000001
    /// count=255  shl32(1)=0x80000000 shr32(0x80000000)=0x00000001 sar32(-8)= -1 shl64(1)=0x8000000000000000
    /// ```
    ///
    /// x86-64 masks the count to 5 bits for a 32-bit operand and 6 for a
    /// 64-bit one, i.e. it takes the count modulo the width — which is what
    /// [`Concrete`] does and what [`ExprPool::render_bin`] now makes the SMT
    /// text do. Bare `bvshl`/`bvlshr`/`bvashr` would give `0`, `0` and `-1`
    /// for every count at or above the width, agreeing with neither.
    ///
    /// There is deliberately no hardware row for division by zero: x86 `div`
    /// raises `#DE` rather than producing a value, so neither the concrete
    /// domain's `0` nor `bvudiv`'s all-ones is "what the CPU does". `0` is this
    /// engine's documented convention (a real divide fault is modelled by a
    /// helper, not the value domain); the requirement here is only that the
    /// solver be asked about the same convention the executor implements.
    #[test]
    fn concrete_and_smt_both_reproduce_the_hardware() {
        // (count, shl32(1), shr32(0x8000_0000), sar32(-8), shl64(1))
        let measured: [(u128, u128, u128, u128, u128); 7] = [
            (0, 0x0000_0001, 0x8000_0000, 0xFFFF_FFF8, 0x1),
            (1, 0x0000_0002, 0x4000_0000, 0xFFFF_FFFC, 0x2),
            (31, 0x8000_0000, 0x0000_0001, 0xFFFF_FFFF, 0x8000_0000),
            (32, 0x0000_0001, 0x8000_0000, 0xFFFF_FFF8, 0x1_0000_0000),
            (33, 0x0000_0002, 0x4000_0000, 0xFFFF_FFFC, 0x2_0000_0000),
            (64, 0x0000_0001, 0x8000_0000, 0xFFFF_FFF8, 0x1),
            (
                255,
                0x8000_0000,
                0x0000_0001,
                0xFFFF_FFFF,
                0x8000_0000_0000_0000,
            ),
        ];
        let env = Env::new();
        for (count, shl32, shr32, sar32, shl64) in measured {
            for (op, a, width, hardware) in [
                (BinOp::Shl, 1u128, Width::W32, shl32),
                (BinOp::Shr, 0x8000_0000u128, Width::W32, shr32),
                (BinOp::Sar, 0xFFFF_FFF8u128, Width::W32, sar32),
                (BinOp::Shl, 1u128, Width::W64, shl64),
            ] {
                assert_eq!(
                    Concrete.binop(op, &a, &count, width),
                    hardware,
                    "the concrete domain must reproduce {op:?} {a:#x} by {count} at {} bits",
                    width.bits()
                );
                let mut pool = ExprPool::new();
                let root = build(&mut pool, op, a, count, width);
                for text in [pool.render_smtlib(root), pool.render_smtlib_shared(root)] {
                    assert_eq!(
                        eval_bv(&parse(&text), &env).0,
                        hardware,
                        "the rendered SMT must reproduce {op:?} {a:#x} by {count} at {} bits: {text}",
                        width.bits()
                    );
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // The same differential against a real solver.
    // ------------------------------------------------------------------

    fn solver_binary() -> Option<(String, Vec<String>)> {
        if let Ok(custom) = std::env::var("GLAURUNG_SMT_SOLVER") {
            if !custom.is_empty() {
                return Some((custom, vec!["--lang".into(), "smt2".into()]));
            }
        }
        for (prog, args) in [
            ("z3", vec!["-in".to_string()]),
            ("bitwuzla", vec!["--lang".into(), "smt2".into()]),
            ("cvc5", vec!["--lang".into(), "smt2".into(), "-".into()]),
        ] {
            if std::process::Command::new(prog)
                .arg("--version")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok()
            {
                return Some((prog.to_string(), args));
            }
        }
        None
    }

    fn run_script(prog: &str, args: &[String], script: &str) -> String {
        use std::io::Write as _;
        let mut child = std::process::Command::new(prog)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawning the solver");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(script.as_bytes())
            .expect("writing the script");
        let out = child.wait_with_output().expect("solver output");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// Ask a real solver whether each rendered term can differ from what
    /// `Concrete` computes. `unsat` for every case is the only pass.
    ///
    /// Absence of a solver binary is a *loud* skip, not a pass: CI's `symbolic`
    /// lane provisions none. Set `GLAURUNG_REQUIRE_SOLVER=1` to make the
    /// absence a failure — the demand switch that keeps a silently-skipped test
    /// from being indistinguishable from a passing one.
    #[test]
    fn solver_agrees_with_the_concrete_domain() {
        let Some((prog, args)) = solver_binary() else {
            assert!(
                std::env::var("GLAURUNG_REQUIRE_SOLVER").is_err(),
                "GLAURUNG_REQUIRE_SOLVER=1 but no z3/bitwuzla/cvc5 on PATH"
            );
            eprintln!(
                "SKIPPED solver_agrees_with_the_concrete_domain: \
                 no z3/bitwuzla/cvc5 on PATH. The solver-free \
                 `rendered_smtlib_agrees_with_the_concrete_domain` still ran."
            );
            return;
        };

        // One script, one `check-sat` per case, in order.
        let all = cases();
        let mut script = String::from("(set-logic QF_BV)\n");
        for (op, a, b, width) in &all {
            let expected = Concrete.binop(*op, a, b, *width);
            let mut pool = ExprPool::new();
            let root = build(&mut pool, *op, *a, *b, *width);
            for text in [pool.render_smtlib(root), pool.render_smtlib_shared(root)] {
                script.push_str(&format!(
                    "(push 1)(assert (distinct {text} (_ bv{expected} {})))(check-sat)(pop 1)\n",
                    width.bits()
                ));
            }
        }
        let out = run_script(&prog, &args, &script);
        let verdicts: Vec<&str> = out.lines().map(str::trim).collect();
        assert_eq!(
            verdicts.len(),
            all.len() * 2,
            "{prog} returned {} verdicts for {} queries:\n{out}",
            verdicts.len(),
            all.len() * 2
        );
        let mut bad = Vec::new();
        for (index, verdict) in verdicts.iter().enumerate() {
            if *verdict != "unsat" {
                let (op, a, b, width) = all[index / 2];
                bad.push(format!(
                    "{op:?} a={a:#x} b={b:#x} w={} renderer={} -> {verdict}",
                    width.bits(),
                    if index % 2 == 0 { "smtlib" } else { "shared" }
                ));
            }
        }
        assert!(
            bad.is_empty(),
            "{prog}: {} of {} queries were not unsat, i.e. the rendered term can \
             differ from the concrete domain:\n{}",
            bad.len(),
            verdicts.len(),
            bad.join("\n")
        );
    }
}
