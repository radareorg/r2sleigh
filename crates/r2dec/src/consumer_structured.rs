use crate::ast::CStmt;
use crate::structure::{ControlFlowStructureError, ControlFlowStructureResult};
use crate::structured_region::SealedStructuredBody;

pub(crate) struct RoutedBody {
    body_stmt: Option<CStmt>,
    structured_body: Option<SealedStructuredBody>,
}

impl RoutedBody {
    pub(crate) fn structured_body(&self) -> Option<&SealedStructuredBody> {
        self.structured_body.as_ref()
    }

    /// Transfer the final statement and its exact lexical authority together.
    /// Unstructured routes have no region proof and therefore cannot silently
    /// participate in declaration placement.
    pub(crate) fn into_marked_body(
        self,
    ) -> (
        CStmt,
        Option<crate::structured_region::SealedStructuredRegionArtifact>,
    ) {
        match (self.structured_body, self.body_stmt) {
            (Some(body), None) => {
                let (stmt, regions) = body.into_marked_parts();
                (stmt, Some(regions))
            }
            (None, Some(stmt)) => (stmt, None),
            _ => unreachable!("a routed body has exactly one statement owner"),
        }
    }
}

pub(crate) fn primary_native_body<'a, 'o, F, R>(
    structurer: &mut crate::ControlFlowStructurer<'a, 'o>,
    mut linearize: F,
    mut rollback_tentative_structure: R,
) -> ControlFlowStructureResult<RoutedBody>
where
    F: FnMut() -> ControlFlowStructureResult<Vec<CStmt>>,
    R: FnMut(),
{
    // Every function renders natively. The semantic artifact says what a
    // slice looks like from the interpreter's side; it is evidence about the
    // function, not permission to render one, and the summary routes that
    // pre-empted the native attempt turned bodies the certificates could have
    // proven into two lines of prose. What a reader gets when native lowering
    // refuses is the refusal's own comment.
    let structured = structurer.structure_with_regions();
    if let Err(ControlFlowStructureError::Lowering(error)) = &structured {
        return Err(ControlFlowStructureError::Lowering(*error));
    }
    // Structuring refuses as a whole when one edge will not lower, so a
    // function whose loop exits reach blocks the region never covered
    // rendered nothing at all: no statements, and none of its
    // obligations owned, while the rest of the body was understood.
    // Say what could not be structured and render the body without
    // structure, rather than withhold all of it.
    match structurer.safety_reason() {
        Some(reason) => {
            let reason = reason.to_string();
            rollback_tentative_structure();
            let mut stmts = vec![CStmt::comment(format!(
                "r2dec residual: {}; body rendered without structure",
                crate::sanitize_comment_text(&reason)
            ))];
            // When the linear form refuses too, its refusal is all the reader
            // was given -- "unrepresentable operation" -- and the reason
            // structuring gave up, which is the fact worth chasing, went with
            // the abandoned body. Say it before handing the refusal on.
            let linearized = linearize().inspect_err(|error| {
                r2il::refusal_evidence!(
                    "structuring-gave-up",
                    "reason={reason} then linearization refused: {error:?}"
                );
            })?;
            stmts.extend(linearized);
            let structured_body = structurer.seal_linearized_body(CStmt::Block(stmts))?;
            Ok(RoutedBody {
                body_stmt: None,
                structured_body: Some(structured_body),
            })
        }
        None => match structured {
            Ok(structured_body) => Ok(RoutedBody {
                body_stmt: None,
                structured_body: Some(structured_body),
            }),
            Err(ControlFlowStructureError::StructuredRegion(error)) => {
                Err(ControlFlowStructureError::StructuredRegion(error))
            }
            Err(ControlFlowStructureError::Lowering(_)) => {
                unreachable!("lowering refusal returned before route fallback")
            }
        },
    }
}
