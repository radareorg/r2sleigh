//! A call through a typed member, placed in the caller's convention (ROADMAP D171, call-boundary
//! ADR "S32 as built"). r2ssa's `MemberCalls` proves the target; this states the contract.

use r2source::{
    SourceCallArgumentSpec, SourceCallResult, SourceCallSiteInterface, SourceCarrierKind,
    SourceCarrierProjection, SourceFunctionInterface, SourceFunctionReturn, SourceLogicalValue,
    SourceParameterLocation, SourceResultWidth, SourceTypeGraph, SourceTypeKind,
};
use r2ssa::place::ParamClass;

use super::{Placement, Typed, carrier_bytes};

impl Placement<'_> {
    /// The contract of one proven member call, its type the callee's declaration (D166), or `None`
    /// where the type states none (ADR "S32 as built"). O(parameters + graph).
    pub(crate) fn member_call(
        &self,
        graph: &SourceTypeGraph,
        call: &r2ssa::MemberCall,
        revision: &[u8],
    ) -> Option<SourceCallSiteInterface> {
        let at = call.identity.instruction();
        let refuse = |why: &str| {
            r2il::refusal_evidence!("member-call", "{at:#x}: {why}");
            None
        };
        let signature = usize::try_from(call.signature_id)
            .ok()
            .and_then(|index| graph.signatures().get(index))?;
        // A subroutine type with no convention of its own is the program's, not an `ms_abi` caller's.
        if self.target.program.is_some() {
            return refuse("the caller runs under a convention the member's type does not state");
        }
        if !signature.prototyped() {
            return refuse("the member's type states no parameters");
        }
        if signature.variadic() {
            return refuse("the member is variadic, and nothing counts its tail");
        }
        let bits = self.model.pointer_bits;
        let classes = (signature.parameter_type_ids().iter())
            .map(|id| ParamClass::of(graph, *id, bits))
            .collect::<Vec<_>>();
        let placement = r2ssa::place::place(&self.target.convention, &classes);
        let Some((returns, return_value)) = self.member_result(graph, signature.return_type_id())
        else {
            return refuse("the member's result has no register");
        };
        let parameters = (signature.parameter_type_ids().iter())
            .zip(&placement.locations)
            .map(|(id, location)| logical(graph, *id, carrier_bytes(location)))
            .collect();
        let basis = r2source::Basis::DebugInfo;
        let typed = Typed {
            basis,
            parameters,
            returns,
            return_value,
            slots: Vec::new(),
            graph: Some(graph.clone()),
        };
        let name = format!("member@{at:#x}");
        let convention = self.target.convention.id;
        let callee = self.typed(&name, convention, &placement, typed)?;
        let callee = callee.with_types(r2source::Confidence::of(basis));
        let callee = self.carriers(&name, callee, None)?;
        let stacked = placement.locations.iter().any(|at| at.register().is_none());
        let callee = self.stacked_return(&name, callee, stacked)?;
        self.call_site(&callee, call, revision, placement.is_whole())
    }

    /// The call site's half of `callee`: each argument where the call leaves it, before the
    /// return address a call pushes, and the result `callee` states.
    fn call_site(
        &self,
        callee: &SourceFunctionInterface,
        call: &r2ssa::MemberCall,
        revision: &[u8],
        complete: bool,
    ) -> Option<SourceCallSiteInterface> {
        let spent = callee.return_mechanism().map_or(0, |mechanism| {
            i64::from(mechanism.stack_pointer_delta_bytes())
        });
        let arguments = callee.parameters().iter().map(|parameter| {
            let location = match parameter.location() {
                SourceParameterLocation::Stack {
                    offset,
                    size_bytes,
                    callee_offset,
                } => SourceParameterLocation::Stack {
                    offset: offset - spent,
                    size_bytes,
                    callee_offset: callee_offset - spent,
                },
                register => register,
            };
            SourceCallArgumentSpec::with_location(parameter.index(), location)
        });
        let result = match callee.return_kind() {
            SourceFunctionReturn::Register { storage } => SourceCallResult::Register {
                storage,
                width: (callee.result_width()).unwrap_or(SourceResultWidth::whole(storage)),
            },
            _ => SourceCallResult::Void,
        };
        let at = call.identity.instruction();
        let site = SourceCallSiteInterface::new(
            revision.to_vec(),
            call.identity,
            complete,
            callee.convention(),
            arguments,
            false,
            false,
            result,
        )
        .inspect_err(|error| {
            r2il::refusal_evidence!("member-call", "{at:#x}: no contract: {error:?}");
        })
        .ok()?;
        // A floor leaves the contract incomplete, and an incomplete contract holds no callee.
        match complete {
            true => (site.with_exact_callee_interface(callee.clone()))
                .inspect_err(|error| {
                    r2il::refusal_evidence!("member-call", "{at:#x}: callee disagrees: {error:?}");
                })
                .ok(),
            false => Some(site),
        }
    }

    /// Where a member's result arrives, as a declared callee's does (`Placement::result`):
    /// `void`, or the register its class takes. A record or wide value refuses.
    fn member_result(
        &self,
        graph: &SourceTypeGraph,
        id: u32,
    ) -> Option<(SourceFunctionReturn, Option<SourceLogicalValue>)> {
        let node = graph.types().get(usize::try_from(id).ok()?)?;
        if node.kind() == SourceTypeKind::Void {
            return Some((SourceFunctionReturn::Void, None));
        }
        let lanes = self.target.convention.typed_results();
        let storage = match ParamClass::of(graph, id, self.model.pointer_bits) {
            ParamClass::Integer(_) => lanes.integer?,
            ParamClass::Float(bytes) => lanes.float.map(|lane| r2source::CanonicalStorageId {
                size: u32::from(bytes).min(lane.size),
                ..lane
            })?,
            ParamClass::Unplaced(_) => return None,
        };
        let value = logical(graph, id, storage.size)?;
        Some((SourceFunctionReturn::Register { storage }, Some(value)))
    }
}

/// A value of node `id` in a carrier of `carrier_bytes`: its low bits where it is narrower.
fn logical(graph: &SourceTypeGraph, id: u32, carrier_bytes: u32) -> Option<SourceLogicalValue> {
    let bits = graph.types().get(usize::try_from(id).ok()?)?.size_bits();
    let kind = match bits == u64::from(carrier_bytes) * 8 {
        true => SourceCarrierKind::Full,
        false => SourceCarrierKind::LowBits,
    };
    Some(SourceLogicalValue::new(
        id,
        SourceCarrierProjection::new(kind, 0, bits),
    ))
}
