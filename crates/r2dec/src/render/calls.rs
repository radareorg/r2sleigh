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
    pub(super) fn of(
        signature: &r2types::FunctionType,
        fixed: usize,
        defines: &dyn Fn(&str, bool) -> bool,
    ) -> Option<Self> {
        if signature.params.len() != fixed {
            return None;
        }
        let params = (signature.params.iter())
            .map(|ty| spellable(ty, defines).filter(|ty| *ty != CType::Void))
            .collect::<Option<Vec<_>>>()?;
        let ret = spellable(&signature.return_type, defines)?;
        Some(Self { params, ret })
    }

    /// `signature` at its carriers' widths alone, where it names `fixed` parameters and has a
    /// result exactly where the call defines one: a sign, a pointee or a name it states is unproven.
    pub(super) fn of_widths(
        signature: &r2types::FunctionType,
        fixed: usize,
        returns: bool,
        ptr_bits: u32,
    ) -> Option<Self> {
        if signature.params.len() != fixed {
            return None;
        }
        let width = |ty: &CType| match ty.unaliased() {
            CType::Int { bits, .. } if matches!(bits, 8 | 16 | 32 | 64) => Some(CType::uint(*bits)),
            CType::Pointer(_) | CType::Function { .. } | CType::UnprototypedFunction(_) => {
                Some(CType::uint(ptr_bits))
            }
            CType::Float(bits @ (32 | 64)) => Some(CType::Float(*bits)),
            _ => None,
        };
        let params = signature
            .params
            .iter()
            .map(width)
            .collect::<Option<Vec<_>>>()?;
        let ret = match (&signature.return_type, returns) {
            (CType::Void, false) => CType::Void,
            (CType::Void, true) => return None,
            (ty, _) => width(ty)?,
        };
        Some(Self { params, ret })
    }
}

/// An argument of type `from` passed as the declared `to`: the cast C performs at a prototype.
pub(super) fn to_declared(argument: CExpr, from: &CType, to: &CType) -> CExpr {
    if from == to {
        return argument;
    }
    // A literal the declared type holds is that number: C converts it there unchanged.
    match super::terms::at_sink(to, argument) {
        literal @ CExpr::IntLit(_) => literal,
        CExpr::Observed { ids, expr } if matches!(*expr, CExpr::IntLit(_)) => {
            CExpr::Observed { ids, expr }
        }
        other => CExpr::cast(to.clone(), other),
    }
}

/// The literal `text` passed as `to`: C converts a `char*` to a pointer to `const char` or to
/// `void` with no cast, and any other type takes one.
pub(super) fn text_as(text: &str, to: &CType) -> CExpr {
    let literal = CExpr::StringLit(text.to_owned());
    let implicit = match to {
        CType::Pointer(pointee) => {
            let pointee = match &**pointee {
                CType::Const(inner) => &**inner,
                other => other,
            };
            matches!(pointee, CType::Void)
                || matches!(pointee, CType::Typedef { name, .. } if name == "char")
        }
        _ => false,
    };
    match implicit {
        true => literal,
        false => CExpr::cast(to.clone(), literal),
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
        CType::Pointer(_) | CType::Function { .. } | CType::UnprototypedFunction(_) => {
            (false, ptr_bits)
        }
        CType::Int { bits, .. } => (false, *bits),
        CType::Bool => (false, 8),
        CType::Float(bits) => (true, *bits),
        _ => return false,
    };
    matches!(class, MachineType::Float { .. }) == float && class.width_bits() == bits
}

/// `ty` as C spells it: a standard scalar, a pointer to one, `void`, `char` or a tag the unit
/// `defines`, or a function pointer of such types; a typedef is its target, `char` excepted.
pub(super) fn spellable(ty: &CType, defines: &dyn Fn(&str, bool) -> bool) -> Option<CType> {
    match ty {
        CType::Void | CType::Bool | CType::Float(32 | 64) => Some(ty.clone()),
        CType::Int {
            bits: 8 | 16 | 32 | 64,
            signedness: r2types::Signedness::Signed | r2types::Signedness::Unsigned,
        } => Some(ty.clone()),
        CType::Typedef { name, .. } if name == "char" => Some(ty.clone()),
        CType::Typedef { ty, .. } => spellable(ty, defines),
        CType::Pointer(pointee) => Some(CType::Pointer(Box::new(pointee_spelling(
            pointee, defines,
        )?))),
        CType::Const(inner) => Some(CType::Const(Box::new(spellable(inner, defines)?))),
        CType::Function { ret, params } => Some(CType::Function {
            ret: Box::new(spellable(ret, defines)?),
            params: (params.iter())
                .map(|ty| spellable(ty, defines).filter(|ty| *ty != CType::Void))
                .collect::<Option<_>>()?,
        }),
        CType::UnprototypedFunction(ret) => Some(CType::UnprototypedFunction(Box::new(spellable(
            ret, defines,
        )?))),
        _ => None,
    }
}

/// What a pointer points at, as C spells it: a tag the unit `defines`, qualified or not, or any
/// spellable type.
fn pointee_spelling(ty: &CType, defines: &dyn Fn(&str, bool) -> bool) -> Option<CType> {
    match ty {
        CType::Struct(tag) => defines(tag, false).then(|| ty.clone()),
        CType::Union(tag) => defines(tag, true).then(|| ty.clone()),
        CType::Const(inner) => Some(CType::Const(Box::new(pointee_spelling(inner, defines)?))),
        ty => spellable(ty, defines),
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
            == Some(true)
            || never_comes_back(artifact, inst),
        tail,
        declared: None,
    })
}

/// Whether the CFG gives the block the call at `inst` ends no successor: the source's block graph
/// says its last call never comes back (r2engine's walk, from the callee's declaration).
fn never_comes_back(artifact: &SsaArtifact, inst: InstId) -> bool {
    let graph = artifact.graph();
    let Some(block) = graph.inst(inst).and_then(|at| graph.block(at.block)) else {
        return false;
    };
    let ends = matches!(
        artifact
            .function()
            .cfg()
            .get_block(block.addr)
            .map(|cfg| &cfg.terminator),
        Some(
            r2ssa::BlockTerminator::Call {
                fallthrough: None,
                ..
            } | r2ssa::BlockTerminator::IndirectCall { fallthrough: None }
        )
    );
    let last_call = block.insts.iter().rev().copied().find(|id| {
        matches!(
            graph.inst(*id).map(|at| &at.payload),
            Some(InstPayload::Op(SSAOp::Call { .. } | SSAOp::CallInd { .. }))
        )
    });
    ends && last_call == Some(inst)
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

    /// A literal passed at a declared signed type is the number where the type holds it, and a cast
    /// of its bits where it does not.
    #[test]
    fn a_literal_the_declared_type_holds_is_passed_as_the_number() {
        let int32 = CType::Int {
            bits: 32,
            signedness: r2types::Signedness::Signed,
        };
        let uint32 = CType::uint(32);
        let one = to_declared(CExpr::UIntLit(1), &uint32, &int32);
        assert_eq!(spelled(&one), "1");
        let high = to_declared(CExpr::UIntLit(0x8000_0000), &uint32, &int32);
        assert_eq!(spelled(&high), "(int32_t)0x80000000U");
        // C converts the `int` constant 1 to any integer type that holds it unchanged.
        let unsigned = to_declared(CExpr::UIntLit(1), &CType::uint(64), &uint32);
        assert_eq!(spelled(&unsigned), "1");
        // Past `INT_MAX` the constant is no `int`, so the conversion stays written.
        let wide = to_declared(CExpr::UIntLit(0x8000_0000), &uint32, &CType::uint(64));
        assert_eq!(spelled(&wide), "(uint64_t)0x80000000U");
        // A cast that truncates is no literal of the number it casts.
        let truncated = CExpr::cast(CType::uint(8), CExpr::UIntLit(0x101));
        let truncated = to_declared(truncated, &CType::uint(8), &int32);
        assert_eq!(spelled(&truncated), "(int32_t)(uint8_t)0x101U");
        let widened = CExpr::cast(CType::uint(32), CExpr::UIntLit(7));
        assert_eq!(spelled(&to_declared(widened, &uint32, &int32)), "7");
    }

    /// A callee body's prototype is spelled at its carriers' widths alone: the sign and pointee
    /// r2types read there are no declaration, and a `void` result where the call defines one is
    /// no prototype.
    #[test]
    fn a_prototype_from_a_callee_body_is_its_widths() {
        let signature = r2types::FunctionType {
            return_type: CType::Int {
                bits: 32,
                signedness: r2types::Signedness::Signed,
            },
            params: vec![
                CType::Pointer(Box::new(CType::Struct("node".to_string()))),
                CType::Int {
                    bits: 16,
                    signedness: r2types::Signedness::Signed,
                },
                CType::Float(64),
            ],
            variadic: false,
        };
        let widths = Prototype::of_widths(&signature, 3, true, 64).expect("every type has a width");
        assert_eq!(
            widths,
            Prototype {
                params: vec![CType::uint(64), CType::uint(16), CType::Float(64)],
                ret: CType::uint(32),
            }
        );
        assert_eq!(Prototype::of_widths(&signature, 2, true, 64), None);
        let void = r2types::FunctionType {
            return_type: CType::Void,
            ..signature
        };
        assert_eq!(Prototype::of_widths(&void, 3, true, 64), None);
        assert!(Prototype::of_widths(&void, 3, false, 64).is_some());
    }

    /// A tag is spelled behind a pointer only where the unit defines it, and a function pointer
    /// only where each of its types is spelled.
    #[test]
    fn a_prototype_names_a_struct_only_where_the_unit_defines_it() {
        let node = CType::Pointer(Box::new(CType::Const(Box::new(CType::Struct(
            "node".to_string(),
        )))));
        let int32 = CType::Int {
            bits: 32,
            signedness: r2types::Signedness::Signed,
        };
        let binary = CType::Function {
            ret: Box::new(int32.clone()),
            params: vec![int32.clone(), int32.clone()].into_boxed_slice(),
        };
        let signature = r2types::FunctionType {
            return_type: CType::Void,
            params: vec![node.clone(), binary.clone()],
            variadic: false,
        };
        assert_eq!(Prototype::of(&signature, 2, &|_, _| false), None);
        let defined = Prototype::of(&signature, 2, &|tag, union| tag == "node" && !union);
        assert_eq!(defined.map(|p| p.params), Some(vec![node, binary]));
        let by_value = r2types::FunctionType {
            params: vec![CType::Struct("node".to_string())],
            ..signature
        };
        assert_eq!(Prototype::of(&by_value, 1, &|_, _| true), None);
    }
}
