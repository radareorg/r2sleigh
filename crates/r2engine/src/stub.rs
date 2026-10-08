//! The import-stub route: a function whose body is one tail transfer to an import and nothing
//! else renders as the import's declaration in either pipeline (AGENTS.md, route policy).

/// The import a stub transfers to, where `prepared` is one: no store, no other call, no register
/// written that the transfer does not carry, and a callee r2types resolves as an import.
pub(crate) fn import_stub(
    prepared: &r2ssa::SsaArtifact,
    facts: &r2types::FunctionFacts,
) -> Option<r2types::ImportStub> {
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
    let machine = prepared.machine_context();
    let clobbered = machine
        .call_clobbered_carriers()
        .iter()
        .map(|storage| storage.location())
        .collect::<std::collections::BTreeSet<_>>();
    let arguments = machine
        .abi_model()
        .argument_registers()
        .iter()
        .map(|slot| slot.storage().location())
        .collect::<std::collections::BTreeSet<_>>();
    let transfer_inputs = graph
        .inst(callsite.at)
        .map(|inst| inst.inputs.to_vec())
        .unwrap_or_default();
    let observable = graph.insts.iter().find(|inst| {
        if matches!(
            inst.payload,
            r2ssa::InstPayload::Op(r2ssa::SSAOp::Store { .. } | r2ssa::SSAOp::Call { .. })
        ) {
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
    });
    if let Some(inst) = observable {
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
    let Some(identity) = facts.callee_resolution().and_then(|resolution| {
        resolution.identity_for_callsite(r2types::CallsiteKey { at: callsite.at })
    }) else {
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
    let name = identity
        .display_name
        .as_deref()
        .or(identity.normalized_name.as_deref())
        .or(identity.raw_name.as_deref())?;
    // The signature certified for this call site is the one a caller's call renders with: the
    // import's declaration at the slot the stub jumps through; the identity's own is by name.
    let certified = facts
        .callsites()
        .and_then(|callsites| {
            callsites
                .by_callsite
                .get(&r2types::CallsiteKey { at: callsite.at })
        })
        .and_then(|fact| fact.callee_signature.clone());
    Some(r2types::ImportStub {
        entry: prepared.function().entry,
        name: name.to_owned(),
        signature: certified.or_else(|| identity.signature.clone()),
    })
}
