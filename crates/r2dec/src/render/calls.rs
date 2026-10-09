//! D2's calls: one written from its callsite certificate, to the callee r2types resolved or
//! through the value an indirect call reaches (doc/adr-decompiler-rewrite.md); any other is a gap.

use r2ssa::{
    CallSiteTransfer, CanonicalStorageId, InstId, InstPayload, MachineType, SSAOp,
    SemanticObligationInventory, SemanticObligationKind, SsaArtifact, ValueId,
};
use r2types::{CalleeClass, CalleeResolutionFacts, CallsiteKey};

use crate::ast::{CExpr, CType};
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
    /// Whether each argument is passed in the outgoing stack area, where only integer bits travel.
    pub(super) stacked: Vec<bool>,
    /// How many leading arguments the prototype names; the rest are its variadic tail.
    pub(super) fixed: usize,
    pub(super) variadic: bool,
    /// The value the call leaves in its result register and the class it is returned in.
    pub(super) result: Option<(ValueId, MachineType)>,
    pub(super) noreturn: bool,
    /// For a tail transfer, the register and class its callee returns in; `Some(None)` where the
    /// facts state no result.
    pub(super) tail: Option<Option<(CanonicalStorageId, MachineType)>>,
    /// The callee's declared prototype, where C spells every type in it with no definition.
    pub(super) declared: Option<Prototype>,
}

/// A callee's fixed parameters and result at the types its declaration states.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Prototype {
    pub(super) params: Vec<CType>,
    pub(super) ret: CType,
}

impl Prototype {
    /// `signature` as C spells it, where it names `fixed` parameters and every type is spellable.
    pub(super) fn of(signature: &r2types::FunctionType, fixed: usize) -> Option<Self> {
        if signature.params.len() != fixed {
            return None;
        }
        let params = (signature.params.iter())
            .map(|ty| spellable(ty).filter(|ty| *ty != CType::Void))
            .collect::<Option<Vec<_>>>()?;
        let ret = spellable(&signature.return_type)?;
        Some(Self { params, ret })
    }
}

/// An argument of type `from` passed as the declared `to`: the cast C performs at a prototype.
pub(super) fn to_declared(argument: CExpr, from: &CType, to: &CType) -> CExpr {
    match from == to {
        true => argument,
        false => CExpr::cast(to.clone(), argument),
    }
}

/// What the call `plan` describes returns, read at `class`.
pub(super) fn read_result(plan: &CallPlan, call: CExpr, class: &MachineType) -> Option<CExpr> {
    match &plan.declared {
        Some(declared) => from_declared(call, &declared.ret, class),
        None => Some(call),
    }
}

/// A result of the declared type read at `class`. A signed result narrower than `class` reads
/// through its unsigned type, since the register above it holds no sign the machine extended.
pub(super) fn from_declared(call: CExpr, declared: &CType, class: &MachineType) -> Option<CExpr> {
    let target = super::terms::c_type(class)?;
    if *declared == target {
        return Some(call);
    }
    let narrower = match declared.unaliased() {
        CType::Int {
            bits,
            signedness: r2types::Signedness::Signed,
        } if *bits < class.width_bits() => Some(*bits),
        _ => None,
    };
    let call = match narrower {
        Some(bits) => CExpr::cast(CType::uint(bits), call),
        None => call,
    };
    Some(CExpr::cast(target, call))
}

/// Whether a value of the declared type is exactly what `class` holds: the same kind and width,
/// so converting between them changes no bit.
pub(super) fn held_as(declared: &CType, class: &MachineType, ptr_bits: u32) -> bool {
    let (float, bits) = match declared {
        CType::Const(inner) => return held_as(inner, class, ptr_bits),
        CType::Typedef { ty, .. } => return held_as(ty, class, ptr_bits),
        CType::Pointer(_) => (false, ptr_bits),
        CType::Int { bits, .. } => (false, *bits),
        CType::Bool => (false, 8),
        CType::Float(bits) => (true, *bits),
        _ => return false,
    };
    matches!(class, MachineType::Float { .. }) == float && class.width_bits() == bits
}

/// `ty` as C spells it with no definition of its own: a standard scalar, or a pointer to one, to
/// `void` or to `char`; a typedef is its target, `char` excepted. A tagged or unknown type is not.
pub(super) fn spellable(ty: &CType) -> Option<CType> {
    match ty {
        CType::Void | CType::Bool | CType::Float(32 | 64) => Some(ty.clone()),
        CType::Int {
            bits: 8 | 16 | 32 | 64,
            signedness: r2types::Signedness::Signed | r2types::Signedness::Unsigned,
        } => Some(ty.clone()),
        CType::Typedef { name, .. } if name == "char" => Some(ty.clone()),
        CType::Typedef { ty, .. } => spellable(ty),
        CType::Pointer(pointee) => Some(CType::Pointer(Box::new(spellable(pointee)?))),
        CType::Const(inner) => Some(CType::Const(Box::new(spellable(inner)?))),
        _ => None,
    }
}

/// Why a call has no plan: the first fact its C would need that the facts do not state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unplanned {
    /// A jump r2ssa found no call at: no refusal.
    NotACall,
    NoCertificate,
    ArgumentsIncomplete,
    ResultsIncomplete,
    /// No convention describes the call, and the function has no interface of its own.
    Undescribed,
    NoCallee,
    /// The obligations name more than the one value the boundary defines after the call.
    ResultUnclear,
    VariadicWithoutFixedCount,
    SignatureArity,
    ArgumentClass,
    ResultClass,
    IndirectVariadic,
}

/// The plan for the call at `inst`, where the facts state every argument, the result and the callee.
pub(super) fn plan(
    artifact: &SsaArtifact,
    resolution: Option<&CalleeResolutionFacts>,
    inventory: &SemanticObligationInventory,
    inst: InstId,
) -> Option<CallPlan> {
    planned(artifact, resolution, inventory, inst)
        .inspect_err(|why| {
            if *why != Unplanned::NotACall {
                r2il::refusal_evidence!("staged-call-plan", "{inst:?}: {why:?}");
            }
        })
        .ok()
}

fn planned(
    artifact: &SsaArtifact,
    resolution: Option<&CalleeResolutionFacts>,
    inventory: &SemanticObligationInventory,
    inst: InstId,
) -> Result<CallPlan, Unplanned> {
    let site = (artifact.facts().call_sites.by_inst.get(inst)).ok_or(Unplanned::NotACall)?;
    let certificate =
        (artifact.certificates().callsites.get(site)).ok_or(Unplanned::NoCertificate)?;
    // r2ssa states every argument and result, or refuses where a pass-through or gap leaves one open.
    check(
        certificate.arguments_complete,
        Unplanned::ArgumentsIncomplete,
    )?;
    check(certificate.results_complete, Unplanned::ResultsIncomplete)?;
    // Without the function's own interface, an undescribed call's arity drops a parameter it
    // passes through unwritten (boundaries.rs, convention_call_boundary); that count is no proof.
    let own_interface = artifact.machine_context().function_interface().is_some();
    check(
        certificate.described || own_interface,
        Unplanned::Undescribed,
    )?;
    let graph = artifact.graph();
    let identity = resolution
        .and_then(|resolution| resolution.identity_for_callsite(CallsiteKey { at: inst }));
    let callee = callee(certificate, identity, graph, inst).ok_or(Unplanned::NoCallee)?;
    let result = result_value(inventory, graph, inst).ok_or(Unplanned::ResultUnclear)?;
    // Each argument passes in the class its register says, which a signature, where there is one,
    // must agree with; C passes a float in the variadic tail as a double.
    let signature = identity.and_then(|identity| identity.signature.as_ref());
    let fixed = match (certificate.variadic, certificate.fixed_argument_count) {
        (false, _) => certificate.argument_values.len(),
        (true, Some(fixed)) if fixed <= certificate.argument_values.len() => fixed,
        (true, _) => return Err(Unplanned::VariadicWithoutFixedCount),
    };
    check(
        !signature.is_some_and(|signature| {
            signature.variadic != certificate.variadic || signature.params.len() != fixed
        }),
        Unplanned::SignatureArity,
    )?;
    let arguments =
        arguments(artifact, certificate, signature, fixed).ok_or(Unplanned::ArgumentClass)?;
    let result = match result {
        None => None,
        Some(value) => Some((
            value,
            result_class(artifact, (*site, inst), signature, value)
                .ok_or(Unplanned::ResultClass)?,
        )),
    };
    check(
        !(matches!(callee, Callee::Through(_)) && certificate.variadic),
        Unplanned::IndirectVariadic,
    )?;
    let tail = (certificate.transfer == CallSiteTransfer::TailCall).then(|| {
        tail_result(
            artifact,
            *site,
            signature.map(|signature| signature.return_type.unaliased()),
        )
    });
    let stacked = (arguments.iter())
        .map(|(value, _)| {
            !matches!(
                location(certificate, *value),
                Some(r2ssa::CallArgumentLocation::Register { .. })
            )
        })
        .collect();
    Ok(CallPlan {
        callee,
        arguments,
        stacked,
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
        tail,
        declared: None,
    })
}

fn check(holds: bool, otherwise: Unplanned) -> Result<(), Unplanned> {
    if holds { Ok(()) } else { Err(otherwise) }
}

/// The register a tail transfer's callee returns in and its class, as the boundary states it and a
/// signature, where there is one, agrees.
fn tail_result(
    artifact: &SsaArtifact,
    site: r2ssa::CallSiteId,
    declared: Option<&r2types::CTypeLike>,
) -> Option<(CanonicalStorageId, MachineType)> {
    let boundary = artifact.facts().boundaries.calls.get(&site)?;
    let Some(r2source::SourceCallResult::Register { storage }) = boundary.result_kind else {
        return None;
    };
    let carrier = super::values::carrier_class(artifact, storage, storage.size * 8);
    let declared = match declared {
        Some(r2types::CTypeLike::Void) => return None,
        Some(ty) => Some(super::values::class_of(ty, storage.size * 8)?),
        None => None,
    };
    Some((storage, super::values::agreed(declared, carrier)?))
}

/// Where the certificate places the argument `value`.
fn location(
    certificate: &r2ssa::CallsiteCertificate,
    value: ValueId,
) -> Option<&r2ssa::CallArgumentLocation> {
    (certificate.argument_certificates.iter())
        .find(|argument| argument.value == value)
        .map(|argument| &argument.location)
}

/// Who the call at `inst` reaches: the callee r2types names, or the value an indirect call's
/// target holds where no identity names it.
fn callee(
    certificate: &r2ssa::CallsiteCertificate,
    identity: Option<&r2types::CalleeIdentity>,
    graph: &r2ssa::SsaGraph,
    inst: InstId,
) -> Option<Callee> {
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
    match (kind, name) {
        (Some(kind), Some(name)) => Some(Callee::Named {
            name: crate::ast::c_identifier(name),
            kind,
            address: certificate
                .direct_target
                .or(identity.and_then(|i| i.target_addr)),
        }),
        // An indirect call no identity names goes where its target value points.
        _ => match graph.inst(inst).map(|i| &i.payload) {
            Some(InstPayload::Op(
                SSAOp::CallInd { target, .. } | SSAOp::BranchInd { target, .. },
            )) => Some(Callee::Through(*target)),
            _ => None,
        },
    }
}

/// The value the call at `inst` assigns its result to: `Some(None)` where it has none, `None` where
/// the obligations name more than the one value the boundary defines after the call.
fn result_value(
    inventory: &SemanticObligationInventory,
    graph: &r2ssa::SsaGraph,
    inst: InstId,
) -> Option<Option<ValueId>> {
    let mut results = inventory
        .obligations_for_inst(inst)
        .filter(|o| o.id.kind == SemanticObligationKind::CallResult)
        .flat_map(|o| o.inputs.iter().copied())
        .collect::<Vec<_>>();
    results.sort_unstable();
    results.dedup();
    match results.as_slice() {
        [] => Some(None),
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
            Some(Some(*one))
        }
        _ => None,
    }
}

/// Each argument and the class it passes in: its register's, which a signature, where there is
/// one, must agree with; C passes a float in the variadic tail as a double.
fn arguments(
    artifact: &SsaArtifact,
    certificate: &r2ssa::CallsiteCertificate,
    signature: Option<&r2types::FunctionType>,
    fixed: usize,
) -> Option<Vec<(ValueId, MachineType)>> {
    let width = |value: ValueId| artifact.graph().var(value).size * 8;
    // A register says its class; an outgoing stack slot carries the value's integer bits.
    let located = |value: ValueId| match location(certificate, value)? {
        r2ssa::CallArgumentLocation::Register { storage } => {
            super::values::carrier_class(artifact, *storage, storage.size * 8)
        }
        r2ssa::CallArgumentLocation::Stack { .. }
        | r2ssa::CallArgumentLocation::Variable { .. } => matches!(width(value), 8 | 16 | 32 | 64)
            .then(|| MachineType::Integer {
                width_bits: width(value),
                signedness: r2ssa::MachineSignedness::Unsigned,
            }),
    };
    certificate
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
        .collect::<Option<Vec<_>>>()
}

/// The class the call's result `value` is returned in: the boundary's carrier, a declared type
/// agreeing; `None` where a signature declares `void` or the two disagree.
fn result_class(
    artifact: &SsaArtifact,
    (site, inst): (r2ssa::CallSiteId, InstId),
    signature: Option<&r2types::FunctionType>,
    value: ValueId,
) -> Option<MachineType> {
    let inventory = artifact.obligations();
    let width = |value: ValueId| artifact.graph().var(value).size * 8;
    // The boundary's result storage is the carrier's own: a double's lane of a vector register.
    let carrier = match artifact
        .facts()
        .boundaries
        .calls
        .get(&site)
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
    super::values::agreed(declared, carrier)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spelled(expr: &CExpr) -> String {
        crate::codegen::CodeGenerator::new(crate::codegen::CodeGenConfig::default())
            .generate_expr(expr)
    }

    /// A declared `int` read through the 64-bit register: the 32-bit write that returned it
    /// zeroed the half above, so the read widens through `uint32_t`, never by sign.
    #[test]
    fn a_signed_declared_result_read_wider_widens_through_its_unsigned_type() {
        let call = CExpr::call(
            CExpr::External {
                name: "f".to_string(),
                kind: ExternalKind::Import,
            },
            Vec::new(),
        );
        let int32 = CType::Int {
            bits: 32,
            signedness: r2types::Signedness::Signed,
        };
        let wide = MachineType::Integer {
            width_bits: 64,
            signedness: r2ssa::MachineSignedness::Unsigned,
        };
        let read = from_declared(call.clone(), &int32, &wide).expect("an integer class");
        assert_eq!(spelled(&read), "(uint64_t)(uint32_t)f()");
        let same = MachineType::Integer {
            width_bits: 32,
            signedness: r2ssa::MachineSignedness::Unsigned,
        };
        let read = from_declared(call, &int32, &same).expect("an integer class");
        assert_eq!(spelled(&read), "(uint32_t)f()");
    }

    /// A tagged type needs a definition the unit does not hold, so the prototype is not spelled.
    #[test]
    fn a_prototype_naming_a_struct_is_not_spelled() {
        let node = CType::Pointer(Box::new(CType::Const(Box::new(CType::Struct(
            "node".to_string(),
        )))));
        let signature = r2types::FunctionType {
            return_type: CType::Void,
            params: vec![node],
            variadic: false,
        };
        assert_eq!(Prototype::of(&signature, 1), None);
    }
}
