//! Instruction provenance carried by decompiler AST nodes.
//!
//! One source-like node can represent several machine instructions after
//! expression reconstruction, folding, hoisting, or tail duplication.  An
//! address scalar is therefore not a sufficient model. [`OriginSet`] stores a
//! deterministic, deduplicated set of instruction VAs and remains cheap for
//! the overwhelmingly common one-address case.

/// Ordered machine-instruction addresses that contributed to one AST node.
///
/// The representation is deliberately a sorted `Vec` rather than a hash set:
/// origins are normally tiny, iteration order is part of the public mapping
/// contract, and cloning a node for a proved duplicated tail must copy the
/// exact same provenance bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct OriginSet {
    addresses: Vec<u64>,
}

impl OriginSet {
    /// No machine instruction is known to own this synthetic node.
    pub const fn empty() -> Self {
        Self {
            addresses: Vec::new(),
        }
    }

    /// Provenance for a node produced by one machine instruction.
    pub fn one(address: u64) -> Self {
        Self {
            addresses: vec![address],
        }
    }

    /// Build a canonical set from addresses in any order.
    pub fn from_addresses(addresses: impl IntoIterator<Item = u64>) -> Self {
        let mut addresses = addresses.into_iter().collect::<Vec<_>>();
        addresses.sort_unstable();
        addresses.dedup();
        Self { addresses }
    }

    /// Whether no contributing instruction is currently known.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Number of distinct contributing machine instructions.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Addresses in stable ascending order.
    pub fn addresses(&self) -> &[u64] {
        &self.addresses
    }

    /// Deterministic set union, suitable for a newly folded or hoisted node.
    pub fn union(&self, other: &Self) -> Self {
        let mut merged = Vec::with_capacity(self.len().saturating_add(other.len()));
        let mut left = self.addresses.iter().copied().peekable();
        let mut right = other.addresses.iter().copied().peekable();

        while let (Some(a), Some(b)) = (left.peek().copied(), right.peek().copied()) {
            match a.cmp(&b) {
                std::cmp::Ordering::Less => {
                    merged.push(a);
                    left.next();
                }
                std::cmp::Ordering::Greater => {
                    merged.push(b);
                    right.next();
                }
                std::cmp::Ordering::Equal => {
                    merged.push(a);
                    left.next();
                    right.next();
                }
            }
        }
        merged.extend(left);
        merged.extend(right);
        Self { addresses: merged }
    }

    /// Add another node's provenance without changing deterministic ordering.
    pub fn merge(&mut self, other: &Self) {
        *self = self.union(other);
    }
}

impl FromIterator<u64> for OriginSet {
    fn from_iter<T: IntoIterator<Item = u64>>(iter: T) -> Self {
        Self::from_addresses(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::OriginSet;
    use crate::ir::ast::{render_c, render_decbench, Expr, Function, Stmt};
    use crate::ir::types::VReg;

    #[test]
    fn construction_sorts_and_deduplicates_non_contiguous_origins() {
        let origins = OriginSet::from_addresses([0x401008, 0x401000, 0x401008, 0x401020]);
        assert_eq!(origins.addresses(), &[0x401000, 0x401008, 0x401020]);
    }

    #[test]
    fn union_is_deterministic_commutative_and_deduplicated() {
        let left = OriginSet::from_addresses([9, 1, 5]);
        let right = OriginSet::from_addresses([7, 5, 3]);
        let expected = OriginSet::from_addresses([1, 3, 5, 7, 9]);

        assert_eq!(left.union(&right), expected);
        assert_eq!(right.union(&left), expected);
        assert_eq!(left.union(&right).union(&left), expected);
    }

    #[test]
    fn duplicated_node_keeps_an_independent_exact_origin_set() {
        let original = OriginSet::from_addresses([0x1000, 0x1004]);
        let mut duplicate = original.clone();
        assert_eq!(duplicate, original);

        duplicate.merge(&OriginSet::one(0x1010));
        assert_eq!(original.addresses(), &[0x1000, 0x1004]);
        assert_eq!(duplicate.addresses(), &[0x1000, 0x1004, 0x1010]);
    }

    #[test]
    fn reattributing_a_statement_unions_without_nesting() {
        let statement = Stmt::Nop
            .with_origins(OriginSet::from_addresses([0x1010, 0x1000]))
            .with_origins(OriginSet::from_addresses([0x1020, 0x1010]));

        assert_eq!(
            statement
                .origins()
                .expect("attributed statement")
                .addresses(),
            &[0x1000, 0x1010, 0x1020]
        );
        let Stmt::Origin { stmt, .. } = statement else {
            panic!("statement must have one origin wrapper");
        };
        assert!(matches!(*stmt, Stmt::Nop));
    }

    #[test]
    fn expression_origins_union_without_nesting_and_render_transparently() {
        let plain = Expr::Bin {
            op: crate::ir::types::BinOp::Add,
            lhs: Box::new(Expr::Reg(VReg::phys("arg0"))),
            rhs: Box::new(Expr::Const(1)),
        };
        let attributed = plain
            .clone()
            .with_origins(OriginSet::from_addresses([0x1010, 0x1004]))
            .with_origins(OriginSet::from_addresses([0x1014, 0x1010]));

        assert_eq!(
            attributed
                .origins()
                .expect("attributed expression")
                .addresses(),
            &[0x1004, 0x1010, 0x1014]
        );
        assert_eq!(attributed.semantic(), &plain);
        let Expr::Origin { expr, .. } = &attributed else {
            panic!("expression must have one origin wrapper");
        };
        assert!(!matches!(expr.as_ref(), Expr::Origin { .. }));

        let plain_function = Function {
            name: "increment".into(),
            entry_va: 0x1000,
            body: vec![Stmt::Return { value: Some(plain) }],
        };
        let attributed_function = Function {
            name: plain_function.name.clone(),
            entry_va: plain_function.entry_va,
            body: vec![Stmt::Return {
                value: Some(attributed),
            }],
        };
        assert_eq!(render_c(&attributed_function), render_c(&plain_function));
        assert_eq!(
            render_decbench(&attributed_function),
            render_decbench(&plain_function)
        );
    }

    #[test]
    fn attributed_control_comparison_does_not_add_parentheses() {
        let comparison = Expr::Cmp {
            op: crate::ir::types::CmpOp::Sle,
            lhs: Box::new(Expr::Reg(VReg::phys("b"))),
            rhs: Box::new(Expr::Reg(VReg::phys("a"))),
        };
        let function = |cond| Function {
            name: "ordered".into(),
            entry_va: 0x1000,
            body: vec![Stmt::If {
                cond,
                then_body: vec![Stmt::Return {
                    value: Some(Expr::Const(1)),
                }],
                else_body: None,
            }],
        };
        let plain = render_decbench(&function(comparison.clone()));
        let attributed =
            render_decbench(&function(comparison.with_origins(OriginSet::one(0x1000))));

        assert_eq!(attributed, plain);
        assert!(plain.contains("if (b <= a)"), "{plain}");
    }

    #[test]
    fn origin_wrappers_do_not_change_rendered_text() {
        let init = Stmt::Assign {
            dst: VReg::phys("i"),
            src: Expr::Const(0),
        };
        let step = Stmt::Assign {
            dst: VReg::phys("i"),
            src: Expr::Bin {
                op: crate::ir::types::BinOp::Add,
                lhs: Box::new(Expr::Reg(VReg::phys("i"))),
                rhs: Box::new(Expr::Const(1)),
            },
        };
        let body = Stmt::For {
            init: Box::new(init.clone()),
            cond: Expr::Const(1),
            step: Box::new(step.clone()),
            body: vec![Stmt::Nop],
        };
        let plain = Function {
            name: "count".to_string(),
            entry_va: 0x1000,
            body: vec![body.clone(), Stmt::Return { value: None }],
        };
        let attributed = Function {
            name: plain.name.clone(),
            entry_va: plain.entry_va,
            body: vec![
                Stmt::For {
                    init: Box::new(init.with_origins(OriginSet::one(0x1000))),
                    cond: Expr::Const(1),
                    step: Box::new(step.with_origins(OriginSet::one(0x1008))),
                    body: vec![Stmt::Nop.with_origins(OriginSet::one(0x1004))],
                }
                .with_origins(OriginSet::from_addresses([0x1000, 0x1004, 0x1008])),
                Stmt::Return { value: None }.with_origins(OriginSet::one(0x100c)),
            ],
        };

        assert_eq!(render_c(&attributed), render_c(&plain));
        assert_eq!(render_decbench(&attributed), render_decbench(&plain));
    }
}
