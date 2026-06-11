//! Hash-consed bit-vector expression IR for symbolic execution.
//!
//! Expressions are interned in an [`ExprPool`]: structurally-equal terms share
//! one [`ExprId`], so building is cheap, equality is O(1), and (later) the
//! solver/constraint caches can key on ids. Every node carries an explicit
//! [`Width`] — the same discipline as the executable LLIR — so lowering to SMT
//! QF_BV is total. See
//! `docs/design/execution-engine/02-architecture/symbolic-engine.md`.

use std::collections::HashMap;

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
            Expr::Bin { op, a, b, .. } => {
                let f = match op {
                    BinOp::Add => "bvadd",
                    BinOp::Sub => "bvsub",
                    BinOp::Mul => "bvmul",
                    BinOp::Div => "bvudiv",
                    BinOp::And => "bvand",
                    BinOp::Or => "bvor",
                    BinOp::Xor => "bvxor",
                    BinOp::Shl => "bvshl",
                    BinOp::Shr => "bvlshr",
                    BinOp::Sar => "bvashr",
                };
                format!(
                    "({} {} {})",
                    f,
                    self.render_smtlib(*a),
                    self.render_smtlib(*b)
                )
            }
            Expr::Un { op, a, .. } => {
                let f = match op {
                    UnOp::Not => "bvnot",
                    UnOp::Neg => "bvneg",
                };
                format!("({} {})", f, self.render_smtlib(*a))
            }
            Expr::Cmp { op, a, b, .. } => {
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
                    self.render_smtlib(*a),
                    self.render_smtlib(*b)
                )
            }
            Expr::ZExt { a, from, to } => format!(
                "((_ zero_extend {}) {})",
                to.bits() - from.bits(),
                self.render_smtlib(*a)
            ),
            Expr::SExt { a, from, to } => format!(
                "((_ sign_extend {}) {})",
                to.bits() - from.bits(),
                self.render_smtlib(*a)
            ),
            Expr::Trunc { a, to } => {
                format!(
                    "((_ extract {} 0) {})",
                    to.bits() - 1,
                    self.render_smtlib(*a)
                )
            }
            Expr::Extract { a, hi, lo } => {
                format!("((_ extract {} {}) {})", hi - 1, lo, self.render_smtlib(*a))
            }
            Expr::Concat { hi, lo, .. } => format!(
                "(concat {} {})",
                self.render_smtlib(*hi),
                self.render_smtlib(*lo)
            ),
            Expr::Ite { c, t, e, .. } => format!(
                "(ite (= {} (_ bv1 1)) {} {})",
                self.render_smtlib(*c),
                self.render_smtlib(*t),
                self.render_smtlib(*e)
            ),
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
}
