//! D2's calls: one written from its callsite certificate, to the callee r2types resolved or
//! through the value an indirect call reaches (doc/adr-decompiler-rewrite.md); any other is a gap.

use r2ssa::{
    InstId, InstPayload, MachineType, SSAOp, SemanticObligationInventory, SemanticObligationKind,
    SsaArtifact, ValueId,
};
use r2types::{CalleeClass, CalleeResolutionFacts, CallsiteKey};

use crate::symbol::ExternalKind;

/// Who a call reaches: a callee by name, or the function an indirect call's target value holds.
#[derive(Debug, Clone)]
pub(super) enum Callee {
    Named {
        name: String,
        kind: ExternalKind,
        address: Option<u64>,
    },
    Through(ValueId),
}

/// What one call is written from.
#[derive(Debug, Clone)]
pub(super) struct CallPlan {
    pub(super) callee: Callee,
    /// Each argument and the class the callee's signature passes it in.
    pub(super) arguments: Vec<(ValueId, MachineType)>,
    /// How many leading arguments the prototype names; the rest are its variadic tail.
    pub(super) fixed: usize,
    pub(super) variadic: bool,
    /// The value the call leaves in its result register and the class it is returned in.
    pub(super) result: Option<(ValueId, MachineType)>,
    pub(super) noreturn: bool,
}

/// The plan for the call at `inst`, where the facts state every argument, the result and the callee.
pub(super) fn plan(
    artifact: &SsaArtifact,
    resolution: Option<&CalleeResolutionFacts>,
    inventory: &SemanticObligationInventory,
    inst: InstId,
) -> Option<CallPlan> {
    let site = artifact.facts().call_sites.by_inst.get(inst)?;
    let certificate = artifact.certificates().callsites.get(site)?;
    // r2ssa states every argument and result, or refuses where a pass-through or gap leaves one open.
    let complete = certificate.arguments_complete
        && certificate.results_complete
        && certificate.stack_argument_values.is_empty();
    // Without the function's own interface, an undescribed call's arity drops a parameter it
    // passes through unwritten (boundaries.rs, convention_call_boundary); that count is no proof.
    let own_interface = artifact.machine_context().function_interface().is_some();
    if !complete || !(certificate.described || own_interface) {
        return None;
    }
    let graph = artifact.graph();
    let identity = resolution
        .and_then(|resolution| resolution.identity_for_callsite(CallsiteKey { at: inst }));
    let kind = identity.and_then(|identity| match identity.class {
        CalleeClass::Imported | CalleeClass::ExternalSymbol => Some(ExternalKind::Import),
        CalleeClass::Internal => Some(ExternalKind::Function),
        // A function no symbol names, at the address the call reaches.
        CalleeClass::RawAddress
            if identity.target_addr.is_some()
                && identity.target_addr == certificate.direct_target =>
        {
            Some(ExternalKind::Function)
        }
        _ => None,
    });
    let name = identity.and_then(|identity| {
        identity
            .display_name
            .as_deref()
            .or(identity.normalized_name.as_deref())
            .or(identity.raw_name.as_deref())
    });
    let callee = match (kind, name) {
        (Some(kind), Some(name)) => Callee::Named {
            name: crate::ast::c_identifier(name),
            kind,
            address: certificate
                .direct_target
                .or(identity.and_then(|i| i.target_addr)),
        },
        // An indirect call no identity names goes where its target value points.
        _ => match graph.inst(inst).map(|i| &i.payload) {
            Some(InstPayload::Op(SSAOp::CallInd { target, .. })) => Callee::Through(*target),
            _ => return None,
        },
    };
    let mut results = inventory
        .obligations_for_inst(inst)
        .filter(|o| o.id.kind == SemanticObligationKind::CallResult)
        .flat_map(|o| o.inputs.iter().copied())
        .collect::<Vec<_>>();
    results.sort_unstable();
    results.dedup();
    let result = match results.as_slice() {
        [] => None,
        // The result is what the boundary defines after the call, so the call is what assigns it.
        [one]
            if matches!(
                graph
                    .def_inst(*one)
                    .and_then(|def| graph.inst(def))
                    .map(|i| &i.payload),
                Some(InstPayload::Op(SSAOp::CallDefine { .. }))
            ) =>
        {
            Some(*one)
        }
        _ => return None,
    };
    // Each argument passes in the class its register says, which a signature, where there is one,
    // must agree with; C passes a float in the variadic tail as a double.
    let signature = identity.and_then(|identity| identity.signature.as_ref());
    let width = |value: ValueId| graph.var(value).size * 8;
    let fixed = match (certificate.variadic, certificate.fixed_argument_count) {
        (false, _) => certificate.argument_values.len(),
        (true, Some(fixed)) if fixed <= certificate.argument_values.len() => fixed,
        (true, _) => return None,
    };
    if signature.is_some_and(|signature| {
        signature.variadic != certificate.variadic || signature.params.len() != fixed
    }) {
        return None;
    }
    let located = |value: ValueId| {
        certificate
            .argument_certificates
            .iter()
            .find(|argument| argument.value == value)
            .and_then(|argument| match argument.location {
                r2ssa::CallArgumentLocation::Register { storage } => {
                    super::values::carrier_class(artifact, storage, storage.size * 8)
                }
                _ => None,
            })
    };
    let arguments = certificate
        .argument_values
        .iter()
        .enumerate()
        .map(|(position, value)| {
            let declared = signature
                .and_then(|signature| signature.params.get(position))
                .map(|ty| super::values::class_of(ty, width(*value)));
            let class = match declared {
                Some(None) => return None,
                Some(declared) => super::values::agreed(declared, located(*value))?,
                None => located(*value)?,
            };
            let promoted =
                position >= fixed && matches!(class, MachineType::Float { width_bits: 32 });
            (!promoted).then_some((*value, class))
        })
        .collect::<Option<Vec<_>>>()?;
    let result = match result {
        None => None,
        Some(value) => {
            // The boundary's result storage is the carrier's own: a double's lane of a vector register.
            let carrier = match artifact
                .facts()
                .boundaries
                .calls
                .get(site)
                .and_then(|boundary| boundary.result_kind)
            {
                Some(r2source::SourceCallResult::Register { storage }) => {
                    super::values::carrier_class(artifact, storage, storage.size * 8)
                }
                // Undescribed: the slot the result obligation names, at its own width.
                _ => inventory
                    .obligations_for_inst(inst)
                    .find_map(|o| match o.id.component {
                        r2ssa::SemanticObligationComponent::RegisterSlot { storage, .. }
                            if o.id.kind == SemanticObligationKind::CallResult =>
                        {
                            super::values::carrier_class(artifact, storage, storage.size * 8)
                        }
                        _ => None,
                    }),
            };
            let declared = match signature.map(|signature| signature.return_type.unaliased()) {
                Some(r2types::CTypeLike::Void) => return None,
                Some(ty) => Some(super::values::class_of(ty, width(value))?),
                None => None,
            };
            Some((value, super::values::agreed(declared, carrier)?))
        }
    };
    if matches!(callee, Callee::Through(_)) && certificate.variadic {
        return None;
    }
    Some(CallPlan {
        callee,
        arguments,
        fixed,
        variadic: certificate.variadic,
        result,
        // C may drop what follows a call it believes never returns, so only the source says so.
        noreturn: artifact
            .facts()
            .boundaries
            .calls
            .get(site)
            .and_then(|boundary| boundary.noreturn)
            == Some(true),
    })
}
