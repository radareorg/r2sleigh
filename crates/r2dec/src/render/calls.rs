//! D2's calls: one written from its callsite certificate and the callee r2types resolved
//! (doc/adr-decompiler-rewrite.md, "D2 and D3, as they are built"); any other is a gap.

use r2ssa::{
    InstId, InstPayload, MachineType, SSAOp, SemanticObligationInventory, SemanticObligationKind,
    SsaArtifact, ValueId,
};
use r2types::{CalleeClass, CalleeResolutionFacts, CallsiteKey};

use crate::symbol::ExternalKind;

/// What one call is written from.
#[derive(Debug, Clone)]
pub(super) struct CallPlan {
    pub(super) name: String,
    pub(super) kind: ExternalKind,
    pub(super) address: Option<u64>,
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
    // An arity read off the registers written before a call misses an argument passed through.
    let described = certificate.arguments_complete
        && certificate.results_complete
        && certificate.described
        && certificate.stack_argument_values.is_empty();
    if !described {
        return None;
    }
    let identity = resolution?.identity_for_callsite(CallsiteKey { at: inst })?;
    let kind = match identity.class {
        CalleeClass::Imported | CalleeClass::ExternalSymbol => ExternalKind::Import,
        CalleeClass::Internal if !identity.is_recursive => ExternalKind::Function,
        // A function no symbol names, at the address the call reaches.
        CalleeClass::RawAddress
            if identity.target_addr.is_some()
                && identity.target_addr == certificate.direct_target =>
        {
            ExternalKind::Function
        }
        _ => return None,
    };
    let name = identity
        .display_name
        .as_deref()
        .or(identity.normalized_name.as_deref())
        .or(identity.raw_name.as_deref())?;
    let mut results = inventory
        .obligations_for_inst(inst)
        .filter(|o| o.id.kind == SemanticObligationKind::CallResult)
        .flat_map(|o| o.inputs.iter().copied())
        .collect::<Vec<_>>();
    results.sort_unstable();
    results.dedup();
    let graph = artifact.graph();
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
    let signature = identity.signature.as_ref();
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
                    super::values::carrier_class(artifact, storage, width(value))
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
            let carrier = inventory
                .obligations_for_inst(inst)
                .find_map(|o| match o.id.component {
                    r2ssa::SemanticObligationComponent::RegisterSlot { storage, .. }
                        if o.id.kind == SemanticObligationKind::CallResult =>
                    {
                        super::values::carrier_class(artifact, storage, width(value))
                    }
                    _ => None,
                });
            let declared = match signature.map(|signature| signature.return_type.unaliased()) {
                Some(r2types::CTypeLike::Void) => return None,
                Some(ty) => Some(super::values::class_of(ty, width(value))?),
                None => None,
            };
            Some((value, super::values::agreed(declared, carrier)?))
        }
    };
    Some(CallPlan {
        name: crate::ast::c_identifier(name),
        kind,
        address: certificate.direct_target.or(identity.target_addr),
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
