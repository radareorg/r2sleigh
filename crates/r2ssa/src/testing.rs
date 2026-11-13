//! A convention for tests, built from registers through `ConventionModel::new`.

use r2il::R2ILBlock;

use crate::{
    CanonicalStorageId, Conventions, DecompileInputs, SourceCallSiteInterface,
    SourceFunctionInterface, SsaArtifact,
};

/// A convention whose calls clobber `clobbered`, keep `preserved` and read nothing.
pub(crate) fn conventions(
    clobbered: impl IntoIterator<Item = CanonicalStorageId>,
    preserved: impl IntoIterator<Item = CanonicalStorageId>,
) -> Option<Conventions> {
    conventions_reading(clobbered, preserved, [])
}

/// A convention whose calls read `reads` as its integer arguments.
pub(crate) fn conventions_reading(
    clobbered: impl IntoIterator<Item = CanonicalStorageId>,
    preserved: impl IntoIterator<Item = CanonicalStorageId>,
    reads: impl IntoIterator<Item = CanonicalStorageId>,
) -> Option<Conventions> {
    let model = r2source::convention::testing::model(r2source::ConventionId::SysVAmd64)
        .arguments(r2source::convention::SlotClass::Integer, reads)
        .killed(clobbered)
        .preserved(preserved);
    Some(model.conventions())
}

/// Decompile-prepared SSA with these interfaces, under these conventions.
pub(crate) fn prepared_under(
    blocks: &[R2ILBlock],
    arch: &crate::Arch,
    function_interface: Option<SourceFunctionInterface>,
    call_site_interfaces: Vec<SourceCallSiteInterface>,
    conventions: Option<Conventions>,
) -> Option<SsaArtifact> {
    SsaArtifact::for_decompile_with(
        blocks,
        DecompileInputs {
            arch: Some(arch),
            function_interface,
            conventions,
            call_site_interfaces,
            ..Default::default()
        },
    )
}

/// Decompile-prepared SSA with these interfaces, under a convention preserving these registers.
pub(crate) fn prepared(
    blocks: &[R2ILBlock],
    arch: &crate::Arch,
    function_interface: Option<SourceFunctionInterface>,
    call_site_interfaces: Vec<SourceCallSiteInterface>,
    preserved: impl IntoIterator<Item = CanonicalStorageId>,
) -> Option<SsaArtifact> {
    prepared_under(
        blocks,
        arch,
        function_interface,
        call_site_interfaces,
        conventions([], preserved),
    )
}
