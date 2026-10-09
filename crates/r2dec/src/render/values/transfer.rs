//! A repeated string operation as the element loop the machine runs (r2il `eval::block`): each
//! element read and written by byte copy, in ascending order, so overlapping regions behave as the
//! machine's do. A descending or unsettled direction has no spelling and stays a gap.

use r2ssa::{BlockTransferOp, InstId, MachineType, SSAOp, SsaGraph, ValueId};

use super::{Values, terms};
use crate::ast::{BinaryOp, CExpr, CStmt, CType};
use crate::prelude::{Helper, ResidualType};
use crate::symbol::{SymbolId, SymbolRole};

/// One part of a scan's or a compare's answer: the count reached, then the destination's element
/// compared last, then the source's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    Reached,
    Destination,
    Source,
}

impl Part {
    /// The part a byte offset into the answer names (r2il `eval::block` lays them out in order).
    fn at(offset: u32, count_bytes: u32, element_bytes: u32) -> Option<Self> {
        match offset {
            0 => Some(Self::Reached),
            at if at == count_bytes => Some(Self::Destination),
            at if Some(at) == count_bytes.checked_add(element_bytes) => Some(Self::Source),
            _ => None,
        }
    }
}

/// Whether `value` is a `SUBPIECE` of one part of a block operation's answer, which the walk
/// assigns, so no reader computes it in place.
pub(super) fn reads_answer(graph: &SsaGraph, value: ValueId) -> bool {
    answer_read(graph, value).is_some()
}

/// The `SUBPIECE` defining `value`, the part of the answer it reads, and the block operation.
fn answer_read(graph: &SsaGraph, value: ValueId) -> Option<(InstId, Part, InstId)> {
    let def = graph.inst(graph.def_inst(value)?)?;
    let r2ssa::InstPayload::Op(SSAOp::Subpiece { src, offset, .. }) = &def.payload else {
        return None;
    };
    let transfer = graph.inst(graph.def_inst(*src)?)?;
    let r2ssa::InstPayload::Op(SSAOp::BlockTransfer(op)) = &transfer.payload else {
        return None;
    };
    (op.answer == Some(*src)).then_some(())?;
    let part = Part::at(*offset, graph.var(op.count).size, op.element_size)?;
    Some((def.id, part, transfer.id))
}

impl Values<'_> {
    /// The loop `inst` runs, then each part of its answer some reader reads, assigned.
    pub(super) fn block_transfer(
        &self,
        inst: InstId,
        transfer: &BlockTransferOp<ValueId>,
    ) -> Option<CStmt> {
        if transfer.space != r2il::SpaceId::Ram || !self.little_endian {
            return None;
        }
        if self.graph.var(transfer.direction).constant_bits() != Some(0) {
            r2il::refusal_evidence!(
                "block-transfer",
                "{inst:?}: the direction is not a settled zero, so neither walk can be spelled"
            );
            return None;
        }
        let element_bits = transfer.element_size.checked_mul(8)?;
        let element = integer_type(element_bits)?;
        let address_bits = self.value_bits(transfer.destination)?;
        let address = integer_type(address_bits).filter(|_| address_bits >= 32)?;
        let count = integer_type(self.value_bits(transfer.count)?)?;
        let pointer_source = matches!(
            transfer.kind,
            r2il::BlockTransferKind::Move | r2il::BlockTransferKind::Compare(_)
        );
        let source = match pointer_source {
            true => address.clone(),
            false => element.clone(),
        };
        // The machine reads each operand once, before the walk: each is held, so a term that
        // reads memory is not read again after the walk writes it.
        let (to, from, limit) = (
            self.operand(transfer.destination, inst)?,
            self.operand(transfer.source, inst)?,
            self.operand(transfer.count, inst)?,
        );
        let stop = transfer.kind.stop();
        let cursor = self.cursor(
            match stop {
                Some(_) => "reached",
                None => "transferred",
            },
            &count,
        );
        let (to_var, from_var, limit_var) = (
            self.cursor("to", &address),
            self.cursor("from", &source),
            self.cursor("count", &count),
        );
        let mut stmts = vec![
            decl(&count, cursor, CExpr::UIntLit(0)),
            decl(&address, to_var, CExpr::cast(address.clone(), to)),
            decl(&source, from_var, CExpr::cast(source.clone(), from)),
            decl(&count, limit_var, CExpr::cast(count.clone(), limit)),
        ];
        let at = |base: SymbolId| element_at(&address, (base, cursor), transfer.element_size);
        let scalar = ResidualType::of(&element)?;
        let load = |base: SymbolId| Helper::Load(scalar).call(vec![at(base)]);
        // The cursor never passes the count, so the step cannot wrap.
        let step = CStmt::Expr(CExpr::assign(
            CExpr::var(cursor),
            CExpr::binary(BinaryOp::Add, CExpr::var(cursor), CExpr::UIntLit(1)),
        ));
        let mut parts = vec![(Part::Reached, CExpr::var(cursor))];
        let body = match stop {
            None => {
                let written = match pointer_source {
                    true => load(from_var),
                    false => CExpr::var(from_var),
                };
                vec![
                    CStmt::Expr(Helper::Store(scalar).call(vec![at(to_var), written])),
                    step,
                ]
            }
            Some(stop) => {
                let walk = Compared {
                    stop,
                    element: &element,
                    to: to_var,
                    from: from_var,
                    pointer_source,
                };
                self.compare_walk(&walk, &load, step, (&mut stmts, &mut parts))
            }
        };
        stmts.push(CStmt::While {
            cond: CExpr::binary(BinaryOp::Ne, CExpr::var(cursor), CExpr::var(limit_var)),
            body: Box::new(CStmt::Block(body)),
        });
        let bits = (self.value_bits(transfer.count)?, element_bits);
        self.assign_answer(inst, bits, &parts, &mut stmts);
        Some(CStmt::Block(stmts))
    }

    /// A scan's or a compare's body: the element held (and the source's, for a compare), the step,
    /// then the break where the stop holds.
    fn compare_walk(
        &self,
        walk: &Compared<'_>,
        load: &dyn Fn(SymbolId) -> CExpr,
        step: CStmt,
        (stmts, parts): (&mut Vec<CStmt>, &mut Vec<(Part, CExpr)>),
    ) -> Vec<CStmt> {
        let element = walk.element;
        let held = self.cursor("element", element);
        stmts.push(decl(element, held, CExpr::UIntLit(0)));
        parts.push((Part::Destination, CExpr::var(held)));
        let mut body = vec![CStmt::Expr(CExpr::assign(CExpr::var(held), load(walk.to)))];
        let compared = match walk.pointer_source {
            true => {
                let other = self.cursor("other", element);
                stmts.push(decl(element, other, CExpr::UIntLit(0)));
                parts.push((Part::Source, CExpr::var(other)));
                body.push(CStmt::Expr(CExpr::assign(
                    CExpr::var(other),
                    load(walk.from),
                )));
                CExpr::var(other)
            }
            false => CExpr::var(walk.from),
        };
        let op = match walk.stop {
            r2il::BlockStop::Equal => BinaryOp::Eq,
            r2il::BlockStop::Unequal => BinaryOp::Ne,
        };
        // The cursor counts an element before it is compared, so a stop leaves the count.
        body.push(step);
        body.push(CStmt::If {
            cond: CExpr::binary(op, compared, CExpr::var(held)),
            then_body: Box::new(CStmt::Block(vec![CStmt::Break])),
            else_body: None,
        });
        body
    }

    /// After the walk, each part of `inst`'s answer a reader reads, assigned to its name.
    fn assign_answer(
        &self,
        inst: InstId,
        (count_bits, element_bits): (u32, u32),
        parts: &[(Part, CExpr)],
        stmts: &mut Vec<CStmt>,
    ) {
        let mut answered = Vec::new();
        for (read, part, _) in self.answer_reads(inst) {
            let Some(output) = self.graph.inst(read).and_then(|inst| inst.output) else {
                continue;
            };
            let Some((name, held)) = self.names[output.0 as usize] else {
                continue;
            };
            let bits = match part {
                Part::Reached => count_bits,
                Part::Destination | Part::Source => element_bits,
            };
            let value = parts.iter().find(|(at, _)| *at == part).map(|(_, v)| v);
            // A read wider than its part would take the next part's bytes too.
            let (Some(value), Some(ty)) = (value, terms::c_type(&held)) else {
                continue;
            };
            if held.width_bits() > bits {
                continue;
            }
            stmts.push(CStmt::Expr(CExpr::assign(
                CExpr::var(name),
                CExpr::cast(ty, value.clone()),
            )));
            answered.push((read, output));
        }
        for (read, output) in answered {
            self.mark(read);
            self.assigns(output);
        }
    }

    /// Each `SUBPIECE` of `inst`'s answer, with the part it reads.
    fn answer_reads(&self, inst: InstId) -> Vec<(InstId, Part, InstId)> {
        let Some(answer) = self.graph.inst(inst).and_then(|inst| inst.output) else {
            return Vec::new();
        };
        self.graph
            .use_sites(answer)
            .iter()
            .filter_map(|site| self.graph.inst(site.inst)?.output)
            .filter_map(|value| answer_read(self.graph, value))
            .filter(|(_, _, transfer)| *transfer == inst)
            .collect()
    }

    fn value_bits(&self, value: ValueId) -> Option<u32> {
        match self.value_type(value)? {
            ty @ MachineType::Integer { .. } => Some(ty.width_bits()),
            _ => None,
        }
    }

    /// A variable of the walk's own, declared in its scope.
    fn cursor(&self, name: &str, ty: &CType) -> SymbolId {
        self.symbols
            .borrow_mut()
            .declare(name, ty.clone(), SymbolRole::RenderCursor)
    }
}

/// What a scan's or a compare's body reads: the stop, the element's type, the held operands.
struct Compared<'t> {
    stop: r2il::BlockStop,
    element: &'t CType,
    to: SymbolId,
    from: SymbolId,
    pointer_source: bool,
}

/// The address of the element at `cursor` from `base`, as the machine computes it at `address`'s
/// width, as the `void *` a byte copy takes.
fn element_at(address: &CType, (base, cursor): (SymbolId, SymbolId), size: u32) -> CExpr {
    let offset = CExpr::binary(
        BinaryOp::Mul,
        CExpr::cast(address.clone(), CExpr::var(cursor)),
        CExpr::cast(address.clone(), CExpr::UIntLit(u64::from(size))),
    );
    let sum = CExpr::binary(BinaryOp::Add, CExpr::var(base), offset);
    CExpr::cast(
        CType::Pointer(Box::new(CType::Void)),
        CExpr::cast(address.clone(), sum),
    )
}

fn decl(ty: &CType, name: SymbolId, init: CExpr) -> CStmt {
    CStmt::Decl {
        ty: ty.clone(),
        name,
        init: Some(init),
    }
}

fn integer_type(bits: u32) -> Option<CType> {
    matches!(bits, 8 | 16 | 32 | 64).then_some(CType::Int {
        bits,
        signedness: r2types::Signedness::Unsigned,
    })
}

#[cfg(test)]
mod tests {
    use super::Part;

    /// The answer is the count, then the destination's element, then the source's; any other
    /// offset names no part.
    #[test]
    fn an_answer_offset_names_its_part() {
        assert_eq!(Part::at(0, 8, 1), Some(Part::Reached));
        assert_eq!(Part::at(8, 8, 1), Some(Part::Destination));
        assert_eq!(Part::at(9, 8, 1), Some(Part::Source));
        assert_eq!(Part::at(4, 8, 1), None);
        assert_eq!(Part::at(10, 8, 1), None);
        assert_eq!(Part::at(16, 8, 8), Some(Part::Source));
    }
}
