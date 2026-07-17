//! Deterministic native-expression packs for ordered trace replay.
//!
//! SMT-LIB remains the public, independently checkable trace payload. These
//! packs are an additive Glaurung-local replay aid: they preserve the exact
//! typed expression DAG needed to exercise the production native Axeyum
//! adapter without reparsing text or weakening sort checks.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ir::types::{BinOp, CmpOp, UnOp, Width};
use crate::symbolic::expr::{Expr, ExprId, ExprPool};
use crate::symbolic::solver::Assert;

const SCHEMA: &str = "glaurung-native-assertion-pack-v1";
const VERSION: u64 = 1;

/// One self-contained, topologically ordered native assertion DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeAssertionPack {
    schema: String,
    version: u64,
    expected: bool,
    root: u32,
    nodes: Vec<NativeExprNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum NativeExprNode {
    Const {
        value: String,
        width: u16,
    },
    Sym {
        id: u32,
        width: u16,
    },
    Bin {
        op: String,
        a: u32,
        b: u32,
        width: u16,
    },
    Un {
        op: String,
        a: u32,
        width: u16,
    },
    Cmp {
        op: String,
        a: u32,
        b: u32,
        width: u16,
    },
    Zext {
        a: u32,
        from: u16,
        to: u16,
    },
    Sext {
        a: u32,
        from: u16,
        to: u16,
    },
    Trunc {
        a: u32,
        to: u16,
    },
    Extract {
        a: u32,
        hi: u16,
        lo: u16,
    },
    Concat {
        hi: u32,
        lo: u32,
        hi_width: u16,
        lo_width: u16,
    },
    Ite {
        condition: u32,
        then_value: u32,
        else_value: u32,
        width: u16,
    },
}

impl NativeAssertionPack {
    /// Capture exactly the reachable native DAG behind one assertion.
    pub(crate) fn capture(pool: &ExprPool, assertion: Assert) -> Result<Self, String> {
        let mut order = Vec::new();
        let mut seen = BTreeSet::new();
        let mut stack = vec![(assertion.0, false)];
        while let Some((id, expanded)) = stack.pop() {
            if expanded {
                order.push(id);
                continue;
            }
            if !seen.insert(id) {
                continue;
            }
            stack.push((id, true));
            let children = children(pool.get(id));
            for child in children.into_iter().rev() {
                stack.push((child, false));
            }
        }

        let mut ordinals = BTreeMap::new();
        let mut nodes = Vec::with_capacity(order.len());
        for id in order {
            let ordinal = u32::try_from(nodes.len())
                .map_err(|_| "native assertion pack exceeds u32 node IDs".to_string())?;
            let node = encode_node(pool.get(id), &ordinals)?;
            ordinals.insert(id, ordinal);
            nodes.push(node);
        }
        let root = *ordinals
            .get(&assertion.0)
            .ok_or_else(|| "native assertion pack omitted its root".to_string())?;
        Ok(Self {
            schema: SCHEMA.to_string(),
            version: VERSION,
            expected: assertion.1,
            root,
            nodes,
        })
    }

    /// Serialize in one deterministic compact JSON representation.
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = serde_json::to_vec(self)
            .map_err(|error| format!("serialize native assertion pack: {error}"))?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Parse and validate a stored native pack before it reaches the solver.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let pack: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("parse native assertion pack: {error}"))?;
        pack.validate()?;
        Ok(pack)
    }

    /// Rebuild this pack inside a caller-owned expression pool.
    pub(crate) fn import_into(&self, pool: &mut ExprPool) -> Result<Assert, String> {
        self.validate()?;
        let mut imported = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let expression = decode_node(node, &imported)?;
            imported.push(pool.intern(expression));
        }
        let root = imported
            .get(self.root as usize)
            .copied()
            .ok_or_else(|| format!("native assertion root {} is out of range", self.root))?;
        Ok((root, self.expected))
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema != SCHEMA || self.version != VERSION {
            return Err(format!(
                "unsupported native assertion pack {} v{}",
                self.schema, self.version
            ));
        }
        if self.nodes.is_empty() || self.root as usize >= self.nodes.len() {
            return Err(format!(
                "native assertion root {} is invalid for {} nodes",
                self.root,
                self.nodes.len()
            ));
        }
        for (ordinal, node) in self.nodes.iter().enumerate() {
            validate_node(node, ordinal)?;
        }
        Ok(())
    }
}

fn children(node: &Expr) -> Vec<ExprId> {
    match node {
        Expr::Const { .. } | Expr::Sym { .. } => Vec::new(),
        Expr::Bin { a, b, .. } | Expr::Cmp { a, b, .. } => vec![*a, *b],
        Expr::Un { a, .. }
        | Expr::ZExt { a, .. }
        | Expr::SExt { a, .. }
        | Expr::Trunc { a, .. }
        | Expr::Extract { a, .. } => vec![*a],
        Expr::Concat { hi, lo, .. } => vec![*hi, *lo],
        Expr::Ite { c, t, e, .. } => vec![*c, *t, *e],
    }
}

fn ordinal(ordinals: &BTreeMap<ExprId, u32>, id: ExprId) -> Result<u32, String> {
    ordinals
        .get(&id)
        .copied()
        .ok_or_else(|| format!("native assertion child {} was not emitted first", id.0))
}

fn encode_node(node: &Expr, ordinals: &BTreeMap<ExprId, u32>) -> Result<NativeExprNode, String> {
    Ok(match node {
        Expr::Const { value, width } => NativeExprNode::Const {
            value: value.to_string(),
            width: width.bits(),
        },
        Expr::Sym { id, width } => NativeExprNode::Sym {
            id: *id,
            width: width.bits(),
        },
        Expr::Bin { op, a, b, width } => NativeExprNode::Bin {
            op: bin_op_name(*op).to_string(),
            a: ordinal(ordinals, *a)?,
            b: ordinal(ordinals, *b)?,
            width: width.bits(),
        },
        Expr::Un { op, a, width } => NativeExprNode::Un {
            op: un_op_name(*op).to_string(),
            a: ordinal(ordinals, *a)?,
            width: width.bits(),
        },
        Expr::Cmp { op, a, b, width } => NativeExprNode::Cmp {
            op: cmp_op_name(*op).to_string(),
            a: ordinal(ordinals, *a)?,
            b: ordinal(ordinals, *b)?,
            width: width.bits(),
        },
        Expr::ZExt { a, from, to } => NativeExprNode::Zext {
            a: ordinal(ordinals, *a)?,
            from: from.bits(),
            to: to.bits(),
        },
        Expr::SExt { a, from, to } => NativeExprNode::Sext {
            a: ordinal(ordinals, *a)?,
            from: from.bits(),
            to: to.bits(),
        },
        Expr::Trunc { a, to } => NativeExprNode::Trunc {
            a: ordinal(ordinals, *a)?,
            to: to.bits(),
        },
        Expr::Extract { a, hi, lo } => NativeExprNode::Extract {
            a: ordinal(ordinals, *a)?,
            hi: *hi,
            lo: *lo,
        },
        Expr::Concat { hi, lo, hi_w, lo_w } => NativeExprNode::Concat {
            hi: ordinal(ordinals, *hi)?,
            lo: ordinal(ordinals, *lo)?,
            hi_width: hi_w.bits(),
            lo_width: lo_w.bits(),
        },
        Expr::Ite { c, t, e, width } => NativeExprNode::Ite {
            condition: ordinal(ordinals, *c)?,
            then_value: ordinal(ordinals, *t)?,
            else_value: ordinal(ordinals, *e)?,
            width: width.bits(),
        },
    })
}

fn validate_node(node: &NativeExprNode, ordinal: usize) -> Result<(), String> {
    let child = |value: u32| {
        if value as usize >= ordinal {
            Err(format!(
                "native assertion node {ordinal} has non-topological child {value}"
            ))
        } else {
            Ok(())
        }
    };
    let width = |value: u16, label: &str| {
        if value == 0 {
            Err(format!("native assertion node {ordinal} has zero {label}"))
        } else {
            Ok(())
        }
    };
    match node {
        NativeExprNode::Const { value, width: bits } => {
            value.parse::<u128>().map_err(|error| {
                format!("native assertion node {ordinal} has invalid constant: {error}")
            })?;
            width(*bits, "width")
        }
        NativeExprNode::Sym { width: bits, .. } => width(*bits, "width"),
        NativeExprNode::Bin {
            op,
            a,
            b,
            width: bits,
        } => {
            parse_bin_op(op)?;
            child(*a)?;
            child(*b)?;
            width(*bits, "width")
        }
        NativeExprNode::Un { op, a, width: bits } => {
            parse_un_op(op)?;
            child(*a)?;
            width(*bits, "width")
        }
        NativeExprNode::Cmp {
            op,
            a,
            b,
            width: bits,
        } => {
            parse_cmp_op(op)?;
            child(*a)?;
            child(*b)?;
            width(*bits, "operand width")
        }
        NativeExprNode::Zext { a, from, to } | NativeExprNode::Sext { a, from, to } => {
            child(*a)?;
            width(*from, "source width")?;
            width(*to, "target width")?;
            if from >= to {
                return Err(format!(
                    "native assertion node {ordinal} has non-widening extension {from}->{to}"
                ));
            }
            Ok(())
        }
        NativeExprNode::Trunc { a, to } => {
            child(*a)?;
            width(*to, "target width")
        }
        NativeExprNode::Extract { a, hi, lo } => {
            child(*a)?;
            if *hi == 0 || lo >= hi {
                return Err(format!(
                    "native assertion node {ordinal} has invalid extract [{hi}:{lo}]"
                ));
            }
            Ok(())
        }
        NativeExprNode::Concat {
            hi,
            lo,
            hi_width,
            lo_width,
        } => {
            child(*hi)?;
            child(*lo)?;
            width(*hi_width, "high width")?;
            width(*lo_width, "low width")
        }
        NativeExprNode::Ite {
            condition,
            then_value,
            else_value,
            width: bits,
        } => {
            child(*condition)?;
            child(*then_value)?;
            child(*else_value)?;
            width(*bits, "width")
        }
    }
}

fn decode_node(node: &NativeExprNode, imported: &[ExprId]) -> Result<Expr, String> {
    let child = |id: u32| {
        imported
            .get(id as usize)
            .copied()
            .ok_or_else(|| format!("native assertion child {id} is out of range"))
    };
    Ok(match node {
        NativeExprNode::Const { value, width } => Expr::Const {
            value: value
                .parse()
                .map_err(|error| format!("invalid native constant {value}: {error}"))?,
            width: Width(*width),
        },
        NativeExprNode::Sym { id, width } => Expr::Sym {
            id: *id,
            width: Width(*width),
        },
        NativeExprNode::Bin { op, a, b, width } => Expr::Bin {
            op: parse_bin_op(op)?,
            a: child(*a)?,
            b: child(*b)?,
            width: Width(*width),
        },
        NativeExprNode::Un { op, a, width } => Expr::Un {
            op: parse_un_op(op)?,
            a: child(*a)?,
            width: Width(*width),
        },
        NativeExprNode::Cmp { op, a, b, width } => Expr::Cmp {
            op: parse_cmp_op(op)?,
            a: child(*a)?,
            b: child(*b)?,
            width: Width(*width),
        },
        NativeExprNode::Zext { a, from, to } => Expr::ZExt {
            a: child(*a)?,
            from: Width(*from),
            to: Width(*to),
        },
        NativeExprNode::Sext { a, from, to } => Expr::SExt {
            a: child(*a)?,
            from: Width(*from),
            to: Width(*to),
        },
        NativeExprNode::Trunc { a, to } => Expr::Trunc {
            a: child(*a)?,
            to: Width(*to),
        },
        NativeExprNode::Extract { a, hi, lo } => Expr::Extract {
            a: child(*a)?,
            hi: *hi,
            lo: *lo,
        },
        NativeExprNode::Concat {
            hi,
            lo,
            hi_width,
            lo_width,
        } => Expr::Concat {
            hi: child(*hi)?,
            lo: child(*lo)?,
            hi_w: Width(*hi_width),
            lo_w: Width(*lo_width),
        },
        NativeExprNode::Ite {
            condition,
            then_value,
            else_value,
            width,
        } => Expr::Ite {
            c: child(*condition)?,
            t: child(*then_value)?,
            e: child(*else_value)?,
            width: Width(*width),
        },
    })
}

fn bin_op_name(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "add",
        BinOp::Sub => "sub",
        BinOp::Mul => "mul",
        BinOp::Div => "div",
        BinOp::And => "and",
        BinOp::Or => "or",
        BinOp::Xor => "xor",
        BinOp::Shl => "shl",
        BinOp::Shr => "shr",
        BinOp::Sar => "sar",
    }
}

fn parse_bin_op(value: &str) -> Result<BinOp, String> {
    match value {
        "add" => Ok(BinOp::Add),
        "sub" => Ok(BinOp::Sub),
        "mul" => Ok(BinOp::Mul),
        "div" => Ok(BinOp::Div),
        "and" => Ok(BinOp::And),
        "or" => Ok(BinOp::Or),
        "xor" => Ok(BinOp::Xor),
        "shl" => Ok(BinOp::Shl),
        "shr" => Ok(BinOp::Shr),
        "sar" => Ok(BinOp::Sar),
        other => Err(format!("unsupported native binary operator {other:?}")),
    }
}

fn un_op_name(op: UnOp) -> &'static str {
    match op {
        UnOp::Not => "not",
        UnOp::Neg => "neg",
    }
}

fn parse_un_op(value: &str) -> Result<UnOp, String> {
    match value {
        "not" => Ok(UnOp::Not),
        "neg" => Ok(UnOp::Neg),
        other => Err(format!("unsupported native unary operator {other:?}")),
    }
}

fn cmp_op_name(op: CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "eq",
        CmpOp::Ne => "ne",
        CmpOp::Ult => "ult",
        CmpOp::Ule => "ule",
        CmpOp::Slt => "slt",
        CmpOp::Sle => "sle",
    }
}

fn parse_cmp_op(value: &str) -> Result<CmpOp, String> {
    match value {
        "eq" => Ok(CmpOp::Eq),
        "ne" => Ok(CmpOp::Ne),
        "ult" => Ok(CmpOp::Ult),
        "ule" => Ok(CmpOp::Ule),
        "slt" => Ok(CmpOp::Slt),
        "sle" => Ok(CmpOp::Sle),
        other => Err(format!("unsupported native comparison operator {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbolic::solver::pipe;

    #[test]
    fn native_pack_round_trips_shared_dag_to_identical_assertion_bytes() {
        let mut source = ExprPool::new();
        let x = source.fresh_symbol(Width::W64);
        let one = source.constant(Width::W64, 1);
        let shared = source.intern(Expr::Bin {
            op: BinOp::Add,
            a: x,
            b: one,
            width: Width::W64,
        });
        let root = source.intern(Expr::Bin {
            op: BinOp::Xor,
            a: shared,
            b: shared,
            width: Width::W64,
        });
        let assertion = (root, false);

        let pack = NativeAssertionPack::capture(&source, assertion).expect("capture pack");
        let bytes = pack.to_bytes().expect("serialize pack");
        let parsed = NativeAssertionPack::from_bytes(&bytes).expect("parse pack");
        let mut target = ExprPool::new();
        let imported = parsed.import_into(&mut target).expect("import pack");

        assert_eq!(
            pipe::assertion_line(&source, assertion),
            pipe::assertion_line(&target, imported)
        );
        assert_eq!(pack, parsed);
        assert_eq!(bytes, parsed.to_bytes().expect("reserialize pack"));
        assert_eq!(parsed.nodes.len(), 4, "shared child must be stored once");
    }

    #[test]
    fn native_pack_rejects_non_topological_children() {
        let bytes = br#"{"schema":"glaurung-native-assertion-pack-v1","version":1,"expected":true,"root":0,"nodes":[{"kind":"trunc","a":0,"to":8}]}"#;
        let error = NativeAssertionPack::from_bytes(bytes).expect_err("self child must fail");
        assert!(error.contains("non-topological child"), "{error}");
    }

    #[test]
    fn native_pack_round_trips_every_expression_variant() {
        let mut source = ExprPool::new();
        let x = source.fresh_symbol(Width::W8);
        let y = source.fresh_symbol(Width::W8);
        let one = source.constant(Width::W8, 1);
        let add = source.intern(Expr::Bin {
            op: BinOp::Add,
            a: x,
            b: one,
            width: Width::W8,
        });
        let inverted = source.intern(Expr::Un {
            op: UnOp::Not,
            a: add,
            width: Width::W8,
        });
        let condition = source.intern(Expr::Cmp {
            op: CmpOp::Eq,
            a: inverted,
            b: x,
            width: Width::W8,
        });
        let zero_extended = source.intern(Expr::ZExt {
            a: x,
            from: Width::W8,
            to: Width::W16,
        });
        let sign_extended = source.intern(Expr::SExt {
            a: y,
            from: Width::W8,
            to: Width::W16,
        });
        let combined = source.intern(Expr::Bin {
            op: BinOp::Xor,
            a: zero_extended,
            b: sign_extended,
            width: Width::W16,
        });
        let low = source.intern(Expr::Trunc {
            a: combined,
            to: Width::W8,
        });
        let high = source.intern(Expr::Extract {
            a: combined,
            hi: 16,
            lo: 8,
        });
        let concatenated = source.intern(Expr::Concat {
            hi: high,
            lo: low,
            hi_w: Width::W8,
            lo_w: Width::W8,
        });
        let root = source.intern(Expr::Ite {
            c: condition,
            t: concatenated,
            e: combined,
            width: Width::W16,
        });
        let assertion = (root, true);

        let pack = NativeAssertionPack::capture(&source, assertion).expect("capture pack");
        let bytes = pack.to_bytes().expect("serialize pack");
        let parsed = NativeAssertionPack::from_bytes(&bytes).expect("parse pack");
        let mut target = ExprPool::new();
        let imported = parsed.import_into(&mut target).expect("import pack");

        assert_eq!(
            pipe::assertion_line(&source, assertion),
            pipe::assertion_line(&target, imported)
        );
    }
}
