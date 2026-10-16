#![allow(dead_code)]

use std::ops::Deref;

#[derive(Clone, Copy)]
struct Exhausted;

struct SSAFunction {
    exhausted: Option<Exhausted>,
}

impl SSAFunction {
    fn exhausted(&self) -> Option<Exhausted> {
        self.exhausted
    }
}

struct DecompilePrepFacts {
    exhausted: Option<Exhausted>,
}

struct PreparedFunctionFacts;

impl PreparedFunctionFacts {
    fn exhausted(&self) -> Option<Exhausted> {
        None
    }
}

struct Prepared {
    ir: SSAFunction,
}

struct Sealed {
    ir: SSAFunction,
    prep: DecompilePrepFacts,
}

impl Sealed {
    fn function(&self) -> &SSAFunction {
        &self.ir
    }

    fn decompile_prep_facts(&self) -> &DecompilePrepFacts {
        &self.prep
    }
}

struct TrustedSeal {
    sealed: Sealed,
}

struct SsaArtifact {
    sealed: Sealed,
    facts: PreparedFunctionFacts,
}

impl SsaArtifact {
    fn facts(&self) -> &PreparedFunctionFacts {
        &self.facts
    }
}

impl Deref for SsaArtifact {
    type Target = SSAFunction;

    fn deref(&self) -> &SSAFunction {
        self.sealed.function()
    }
}

// The stage constructors read the flag of the pass they refuse: the owner of the refusal.
fn seal(prepared: Prepared) -> Result<Sealed, Exhausted> {
    if let Some(exhausted) = prepared.ir.exhausted() {
        return Err(exhausted);
    }
    let prep = DecompilePrepFacts { exhausted: None };
    if let Some(exhausted) = prep.exhausted {
        return Err(exhausted);
    }
    Ok(Sealed { ir: prepared.ir, prep })
}

fn collect(facts: PreparedFunctionFacts, sealed: Sealed) -> Result<SsaArtifact, Exhausted> {
    if let Some(exhausted) = facts.exhausted() {
        return Err(exhausted);
    }
    Ok(SsaArtifact { sealed, facts })
}

// A pass forwards its own result's flag into the function being prepared.
fn forward(ir: &SSAFunction, prep: &DecompilePrepFacts) -> bool {
    ir.exhausted().is_some() || prep.exhausted.is_some()
}

// Each re-checks what the seal refused.
fn through_the_facts(artifact: &SsaArtifact) -> bool {
    artifact.facts().exhausted().is_some()
}

fn through_the_prep_facts(sealed: &Sealed) -> bool {
    sealed.decompile_prep_facts().exhausted.is_some()
}

fn through_a_field(seal: &TrustedSeal) -> bool {
    seal.sealed.ir.exhausted().is_some()
}

fn through_deref(artifact: &SsaArtifact) -> bool {
    artifact.exhausted().is_some()
}

fn through_a_binding(artifact: &SsaArtifact) -> bool {
    let facts = artifact.facts();
    facts.exhausted().is_some()
}

#[cfg_attr(
    dylint_lib = "r2sleigh_lints",
    allow(exhausted_read_through_sealed_stage, reason = "a probe of the lint itself")
)]
fn allowed(artifact: &SsaArtifact) -> bool {
    artifact.facts().exhausted().is_some()
}

fn main() {
    let ir = SSAFunction { exhausted: None };
    let prep = DecompilePrepFacts { exhausted: None };
    let _ = forward(&ir, &prep);
    let sealed = Sealed { ir, prep };
    let _ = through_the_prep_facts(&sealed);
    let artifact = SsaArtifact { sealed, facts: PreparedFunctionFacts };
    let _ = (through_the_facts(&artifact), through_deref(&artifact), through_a_binding(&artifact));
    let _ = allowed(&artifact);
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_test_may_read_the_flag_of_what_it_built() {
        let facts = super::PreparedFunctionFacts;
        let artifact = super::SsaArtifact {
            sealed: super::Sealed {
                ir: super::SSAFunction { exhausted: None },
                prep: super::DecompilePrepFacts { exhausted: None },
            },
            facts,
        };
        assert!(artifact.facts().exhausted().is_none());
    }
}
