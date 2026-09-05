//! The reaching-definitions fixpoint.
//!
//! Pure graph work: it reads [`super::model::Definition`] and
//! [`super::model::Use`] positions and a [`Cfg`], and knows nothing about C.
//! That separation is deliberate --- the fixpoint is the part most likely to
//! be reused by a second front end, and it is the part that has to be right
//! about the lattice rather than about the grammar.

use std::collections::BTreeMap;

use crate::syntax::cfg::Cfg;
use crate::syntax::ids::NodeId;

use super::model::{Binding, DataFlow, DefKind, FlowEdge};

/// The reaching-definitions fixpoint, and the edges it implies.
///
/// Sets are `Vec<bool>` over definition indices rather than a bitset crate: a
/// function has tens of definitions, not thousands, and a dependency for this
/// would be a poor trade against `REQ-SYN-8`.
pub(super) fn solve(flow: &mut DataFlow, cfg: &Cfg) {
    let def_count = flow.definitions.len();
    let node_count = cfg.node_count();
    if def_count == 0 || node_count == 0 {
        flow.unresolved_uses = (0..flow.uses.len() as u32).collect();
        flow.dead_stores = (0..def_count as u32)
            .filter(|index| flow.definitions[*index as usize].kind != DefKind::Parameter)
            .collect();
        return;
    }

    // GEN and KILL per node.
    let mut gen: Vec<Vec<u32>> = vec![Vec::new(); node_count];
    for (index, definition) in flow.definitions.iter().enumerate() {
        if let Some(slot) = gen.get_mut(definition.node as usize) {
            slot.push(index as u32);
        }
    }
    // Definitions grouped by binding, so KILL is a lookup rather than a scan.
    let mut by_binding: BTreeMap<Binding, Vec<u32>> = BTreeMap::new();
    for (index, definition) in flow.definitions.iter().enumerate() {
        by_binding
            .entry(definition.binding)
            .or_default()
            .push(index as u32);
    }

    let mut out: Vec<Vec<bool>> = vec![vec![false; def_count]; node_count];
    let mut in_: Vec<Vec<bool>> = vec![vec![false; def_count]; node_count];

    // Iterate to a fixed point. The lattice is a finite powerset and the
    // transfer function is monotone, so this terminates; the bound is there
    // only so a graph the builder left malformed cannot spin.
    let bound = node_count.saturating_mul(def_count).saturating_add(8);
    for _ in 0..bound {
        let mut changed = false;
        for node in 0..node_count {
            let id = NodeId::new(node as u32);
            let mut incoming = vec![false; def_count];
            for predecessor in cfg.predecessors(id) {
                let source = &out[predecessor.index()];
                for (slot, value) in incoming.iter_mut().zip(source.iter()) {
                    *slot |= *value;
                }
            }
            if incoming != in_[node] {
                in_[node] = incoming.clone();
                changed = true;
            }

            // OUT = GEN | (IN - KILL).
            let mut next = incoming;
            for definition in &gen[node] {
                let binding = flow.definitions[*definition as usize].binding;
                // A write to the shared unresolved binding kills nothing: two
                // different globals share it, so killing would drop real edges.
                if !binding.is_free() {
                    if let Some(siblings) = by_binding.get(&binding) {
                        for sibling in siblings {
                            next[*sibling as usize] = false;
                        }
                    }
                }
                next[*definition as usize] = true;
            }
            if next != out[node] {
                out[node] = next;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // A use sees exactly one of two things.
    //
    // If any definition of its binding takes effect earlier on the *same*
    // node, the latest such definition is what it sees, and it sees nothing
    // else: a write on the path between two points on one straight-line node
    // kills everything that reached the node. Otherwise it sees whatever the
    // fixpoint says is live at the node's entry.
    //
    // Ordering by `effect_at` rather than by the target's position is what
    // makes `sum = sum + i` read the value that reached the statement.
    for (use_index, use_) in flow.uses.iter().enumerate() {
        let node = use_.node as usize;
        let live = in_
            .get(node)
            .cloned()
            .unwrap_or_else(|| vec![false; def_count]);

        let local_latest = flow
            .definitions
            .iter()
            .enumerate()
            .filter(|(_, definition)| {
                definition.binding == use_.binding
                    && definition.node == use_.node
                    && definition.effect_at <= use_.span.lo
            })
            .max_by_key(|(_, definition)| definition.effect_at)
            .map(|(index, _)| index);

        let reaching: Vec<usize> = match local_latest {
            Some(index) => vec![index],
            None => flow
                .definitions
                .iter()
                .enumerate()
                .filter(|(index, definition)| {
                    definition.binding == use_.binding
                        && live.get(*index).copied().unwrap_or(false)
                })
                .map(|(index, _)| index)
                .collect(),
        };

        for index in &reaching {
            flow.edges.push(FlowEdge {
                def: *index as u32,
                use_: use_index as u32,
                name: use_.name.clone(),
            });
        }
        if reaching.is_empty() {
            flow.unresolved_uses.push(use_index as u32);
        }
    }

    // A definition no edge leaves is a dead store. Parameters are excluded:
    // the caller wrote them and the signature is the contract.
    for (index, definition) in flow.definitions.iter().enumerate() {
        if definition.kind == DefKind::Parameter {
            continue;
        }
        // A write to a global, or to anything this function could not resolve,
        // escapes: the read that observes it is in another function, and this
        // analysis is intraprocedural. Calling it dead would flag every
        // constructor's witness variable.
        if definition.binding.is_free() {
            continue;
        }
        // Taking an address is not a store, so it cannot be a dead one.
        if definition.kind == DefKind::AddressTaken {
            continue;
        }
        if !flow.edges.iter().any(|edge| edge.def == index as u32) {
            flow.dead_stores.push(index as u32);
        }
    }
}

