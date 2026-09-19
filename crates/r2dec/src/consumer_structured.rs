//! The one native route: the placed body, sealed with its lexical regions.

use crate::ast::CStmt;
use crate::structure::{ControlFlowStructureResult, ControlFlowStructurer};
use crate::structured_region::SealedStructuredBody;

pub(crate) struct RoutedBody {
    structured_body: SealedStructuredBody,
}

impl RoutedBody {
    pub(crate) fn structured_body(&self) -> Option<&SealedStructuredBody> {
        Some(&self.structured_body)
    }

    /// Transfer the final statement and its exact lexical authority together.
    pub(crate) fn into_marked_body(
        self,
    ) -> (
        CStmt,
        Option<crate::structured_region::SealedStructuredRegionArtifact>,
    ) {
        let (stmt, regions) = self.structured_body.into_marked_parts();
        (stmt, Some(regions))
    }
}

/// Every function renders natively, and placement is total: what comes back
/// is the body or a lowering refusal for a statement that could not be built.
pub(crate) fn primary_native_body(
    structurer: &mut ControlFlowStructurer<'_, '_>,
) -> ControlFlowStructureResult<RoutedBody> {
    let structured_body = structurer.structure_with_regions()?;
    Ok(RoutedBody { structured_body })
}
