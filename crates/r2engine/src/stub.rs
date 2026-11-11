//! The import-stub route: the function at an address the program states is an import's stub renders
//! as its declaration, where its body is that one transfer (doc/adr-decompiler-rewrite.md).

/// The stub at `prepared`'s entry, where the program says that address is an import's and the body
/// is only the transfer to that import. A body that merely ends in one, or goes to another, is no stub.
pub(crate) fn import_stub(
    prepared: &r2ssa::SsaArtifact,
    facts: &r2types::FunctionFacts,
    program: &dyn crate::native::Program,
) -> Option<r2types::ImportStub> {
    let stated = program.import_at(prepared.function().entry)?;
    let at = lone_transfer(prepared)?;
    let Some(identity) = facts
        .callee_resolution()
        .and_then(|resolution| resolution.identity_for_callsite(at))
    else {
        r2il::refusal_evidence!(
            "import-stub-declaration",
            "{:#x}: the transfer resolves to no callee identity",
            prepared.function().entry
        );
        return None;
    };
    // An external symbol reached through a relocation slot is an import
    // by another name; an internal or unknown callee is not a stub's.
    if !matches!(
        identity.class,
        r2types::CalleeClass::Imported | r2types::CalleeClass::ExternalSymbol
    ) {
        r2il::refusal_evidence!(
            "import-stub-declaration",
            "{:#x}: the callee is {:?}, not an import: {:?}",
            prepared.function().entry,
            identity.class,
            identity
        );
        return None;
    }
    // The address the transfer reaches must be bound to the stated import: the container says which,
    // so a body that goes to another import (a patched stub) is a body, not this import's stub.
    let bound = identity
        .target_addr
        .and_then(|target| program.import_at(target));
    if bound.as_ref() != Some(&stated) {
        r2il::refusal_evidence!(
            "import-stub-declaration",
            "{:#x}: stated as the stub of `{stated}`, the transfer goes to {:?}, bound to {:?}",
            prepared.function().entry,
            identity.target_addr.map(|target| format!("{target:#x}")),
            bound
        );
        return None;
    }
    // The signature certified for this call site is the one a caller's call renders with: the
    // import's declaration at the slot the stub jumps through; the identity's own is by name.
    let certified = facts
        .callsites()
        .and_then(|callsites| callsites.by_callsite.get(at))
        .and_then(|fact| fact.callee_signature.clone());
    Some(r2types::ImportStub {
        entry: prepared.function().entry,
        name: stated,
        signature: certified.or_else(|| identity.signature.clone()),
    })
}

/// The one call site of a body that is only a tail transfer, with nothing a caller observes beside it.
fn lone_transfer(prepared: &r2ssa::SsaArtifact) -> Option<r2ssa::InstId> {
    let certificates = prepared.certificates();
    let [callsite] = certificates.callsites.values().collect::<Vec<_>>()[..] else {
        r2il::refusal_evidence!(
            "import-stub-declaration",
            "{:#x}: {} call sites, not one",
            prepared.function().entry,
            certificates.callsites.len()
        );
        return None;
    };
    if callsite.transfer != r2ssa::CallSiteTransfer::TailCall || !certificates.returns.is_empty() {
        r2il::refusal_evidence!(
            "import-stub-declaration",
            "{:#x}: transfer {:?}, {} return certificates",
            prepared.function().entry,
            callsite.transfer,
            certificates.returns.len()
        );
        return None;
    }
    let graph = prepared.graph();
    if let Some(inst) = observable_beside(prepared, callsite.at) {
        r2il::refusal_evidence!(
            "import-stub-declaration",
            "{:#x}: the body defines observable state beside the transfer: {:?} -> {:?} caller_supplied={}",
            prepared.function().entry,
            inst.payload,
            inst.output
                .and_then(|output| graph.value(output))
                .map(|value| (value.var.display_name(), value.canonical_storage)),
            inst.output
                .is_some_and(|output| graph.caller_supplied(output))
        );
        return None;
    }
    Some(callsite.at)
}

/// An instruction that defines state a caller observes beside the transfer at `at`: an effect
/// (`SSAOp::has_observable_effects`), a call, or a register write the transfer does not carry and
/// the convention preserves or passes.
fn observable_beside(
    prepared: &r2ssa::SsaArtifact,
    at: r2ssa::InstId,
) -> Option<&r2ssa::GraphInst> {
    let graph = prepared.graph();
    let machine = prepared.machine_context();
    let clobbered = machine
        .call_clobbered_carriers()
        .iter()
        .map(|storage| storage.location())
        .collect::<std::collections::BTreeSet<_>>();
    let arguments = (machine.function_interface().into_iter())
        .flat_map(|interface| interface.parameters())
        .filter_map(|parameter| Some(parameter.register_storage()?.location()))
        .collect::<std::collections::BTreeSet<_>>();
    let transfer_inputs = graph.inputs(at);
    graph.insts.iter().find(|inst| {
        if inst.id != at && effect(&inst.payload) {
            return true;
        }
        let Some(output) = inst.output else {
            return false;
        };
        if transfer_inputs.contains(&output) {
            return false;
        }
        // A write nothing reads and nothing carries out is the transfer's
        // own bookkeeping, such as the program counter it sets.
        if graph.use_sites(output).is_empty() && !prepared.live_out().contains(output) {
            return false;
        }
        graph
            .value(output)
            .and_then(|value| value.canonical_storage)
            .is_some_and(|storage| match storage.space {
                r2ssa::CanonicalStorageSpace::Ram => true,
                r2ssa::CanonicalStorageSpace::Register => {
                    let location = storage.location();
                    arguments.contains(&location) || !clobbered.contains(&location)
                }
                _ => false,
            })
    })
}

/// Whether an operation does something a caller observes besides its output: a call, or an effect
/// other than control flow and the boundary read a transfer makes (`CallUse`).
fn effect(payload: &r2ssa::InstPayload) -> bool {
    let r2ssa::InstPayload::Op(op) = payload else {
        return false;
    };
    match op {
        op if op.is_call() => true,
        r2ssa::SSAOp::CallUse { .. } => false,
        _ => !op.is_control_flow() && op.has_observable_effects(false),
    }
}
