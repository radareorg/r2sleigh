//! What a call does, which production reads off the program's convention.

use r2il::{ArchSpec, R2ILBlock};

use crate::{
    CanonicalStorageId, DecompileInputs, SourceCallEffect, SourceCallSiteInterface,
    SourceFunctionInterface, SsaArtifact,
};

/// A call effect naming these registers clobbered and these preserved; every
/// register it does not preserve is clobbered either way.
pub(crate) fn call_effect(
    clobbered: impl IntoIterator<Item = CanonicalStorageId>,
    preserved: impl IntoIterator<Item = CanonicalStorageId>,
) -> Option<SourceCallEffect> {
    Some(SourceCallEffect::new(clobbered, preserved).expect("a call effect"))
}

/// Decompile-prepared SSA with these interfaces, under this call effect.
pub(crate) fn prepared_under(
    blocks: &[R2ILBlock],
    arch: &ArchSpec,
    function_interface: Option<SourceFunctionInterface>,
    call_site_interfaces: Vec<SourceCallSiteInterface>,
    call_effect: Option<SourceCallEffect>,
) -> Option<SsaArtifact> {
    SsaArtifact::for_decompile_with(
        blocks,
        DecompileInputs {
            arch: Some(arch),
            function_interface,
            call_effect,
            call_site_interfaces,
            ..Default::default()
        },
    )
}

/// Decompile-prepared SSA with these interfaces, under a call effect preserving these registers.
pub(crate) fn prepared(
    blocks: &[R2ILBlock],
    arch: &ArchSpec,
    function_interface: Option<SourceFunctionInterface>,
    call_site_interfaces: Vec<SourceCallSiteInterface>,
    preserved: impl IntoIterator<Item = CanonicalStorageId>,
) -> Option<SsaArtifact> {
    prepared_under(
        blocks,
        arch,
        function_interface,
        call_site_interfaces,
        call_effect([], preserved),
    )
}
