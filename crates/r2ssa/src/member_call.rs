//! Calls whose target is a projected function-pointer member (ROADMAP D171, call-boundary ADR
//! "S32 as built"). r2ssa states the evidence; r2engine mints the call-site contract from it.

use r2source::{SourceCallSiteIdentity, SourceTypeKind};
use serde::Serialize;

use crate::dense::IdVec;
use crate::semantic::{CallSiteFacts, CallSiteId, CallSiteTransfer};

type Projected = std::collections::BTreeMap<StructuredAccessId, crate::AggregateAccessProjection>;
/// The interface's graph and, where the image binds struct data, the image's.
type Graphs<'a> = (
    &'a r2source::SourceTypeGraph,
    Option<&'a r2source::SourceTypeGraph>,
);
use crate::{
    AggregateAccessBinding, AggregateAccessProjectionFacts, SourceMachineContext, SsaGraph,
    StructuredAccessId,
};

/// A call whose target is the value one projected load read from a member typed pointer to code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MemberCall {
    pub identity: SourceCallSiteIdentity,
    /// The projected load; its projection names the root (D348).
    pub access: StructuredAccessId,
    /// The graph the member's type lives in: the interface's, or the image's for a data object.
    pub graph: crate::GraphOf,
    /// The member's `Code` signature in `graph`.
    pub signature_id: u32,
}

/// Why an indirect call is no member call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MemberCallRefusal {
    /// The function's interface carries no type graph, or no projections of its revision.
    NoTypeGraph,
    /// The target is not the result of a projected load: a copy, a phi, or a load through a
    /// loaded pointer (a vtable slot).
    TargetNotProjected,
    /// The member is not a pointer to code the graph describes.
    MemberNotCode,
    /// The source states a contract for this site other than a member's (a table or slot).
    Stated,
}

/// One row per call site: `None` where the site is direct, a tail call or has no raw identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberCalls(IdVec<CallSiteId, Option<Result<MemberCall, MemberCallRefusal>>>);

impl Default for MemberCalls {
    fn default() -> Self {
        Self(IdVec::from_fn(0, |_| None))
    }
}

impl MemberCalls {
    pub fn get(&self, site: CallSiteId) -> Option<Result<MemberCall, MemberCallRefusal>> {
        self.0.get(site).copied().flatten()
    }

    /// Whether `other`, from another seal of the same bytes, proves the same rows: the same site,
    /// signature and refusal per row; `access` is seal-local and is not compared.
    pub fn agrees(&self, other: &Self) -> bool {
        let key = |row: &Option<Result<MemberCall, MemberCallRefusal>>| {
            row.map(|row| row.map(|call| (call.identity, call.graph, call.signature_id)))
        };
        self.0.len() == other.0.len()
            && (self.0.iter().zip(other.0.iter())).all(|((_, a), (_, b))| key(a) == key(b))
    }

    /// Every proven member call, in call-site order.
    pub fn proven(&self) -> impl Iterator<Item = (CallSiteId, MemberCall)> + '_ {
        (self.0.iter()).filter_map(|(site, row)| Some((site, (*row)?.ok()?)))
    }
}

/// Each call site's row, from the projections of this revision. O(sites x log projections).
pub(crate) fn collect_member_calls(
    graph: &SsaGraph,
    call_sites: &CallSiteFacts,
    projections: &AggregateAccessProjectionFacts,
    machine_context: &SourceMachineContext,
) -> MemberCalls {
    let interface = machine_context.function_interface();
    let typed = interface.and_then(|interface| {
        let type_graph = interface.type_graph()?;
        let projected = projections.projections_for_revision(interface.revision_identity())?;
        let image = machine_context.data_structs().map(|image| &image.graph);
        Some(((type_graph, image), projected))
    });
    let rows = IdVec::from_fn(call_sites.by_id.len(), |id| {
        let row = row(graph, call_sites.by_id.get(&id)?, typed, machine_context);
        if let Some(Err(refusal)) = row {
            r2il::refusal_evidence!("member-call", "{id:?}: {refusal:?}");
        }
        row
    });
    MemberCalls(rows)
}

/// One call site's row: `None` where it is direct, a tail call or has no raw identity.
fn row(
    graph: &SsaGraph,
    site: &crate::semantic::CallSiteFact,
    typed: Option<(Graphs<'_>, &Projected)>,
    machine_context: &SourceMachineContext,
) -> Option<Result<MemberCall, MemberCallRefusal>> {
    let identity = site.raw_identity?;
    if site.direct_target.is_some() || site.transfer != CallSiteTransfer::Call {
        return None;
    }
    let Some(((interface_graph, image_graph), projected)) = typed else {
        return Some(Err(MemberCallRefusal::NoTypeGraph));
    };
    let access = (graph.def_inst(site.target)).map(|inst| StructuredAccessId { inst, ordinal: 0 });
    let projection = (access.and_then(|access| projected.get(&access))).filter(|projection| {
        projection.binding
            == AggregateAccessBinding::Read {
                result: site.target,
            }
    });
    let Some(projection) = projection else {
        return Some(Err(MemberCallRefusal::TargetNotProjected));
    };
    let type_graph = match projection.graph {
        crate::GraphOf::Interface => interface_graph,
        crate::GraphOf::Image => match image_graph {
            Some(graph) => graph,
            None => return Some(Err(MemberCallRefusal::NoTypeGraph)),
        },
    };
    let node = |id: u32| type_graph.types().get(usize::try_from(id).ok()?);
    let code = match node(projection.member_type_id).map(|ty| ty.kind()) {
        Some(SourceTypeKind::Pointer { target_type_id, .. }) => node(target_type_id),
        _ => None,
    };
    let signature_id = match code.map(|ty| ty.kind()) {
        Some(SourceTypeKind::Code { signature_id })
            if usize::try_from(signature_id)
                .is_ok_and(|index| index < type_graph.signatures().len()) =>
        {
            signature_id
        }
        _ => return Some(Err(MemberCallRefusal::MemberNotCode)),
    };
    // Checked last, so a member contract stated by an earlier seal still reads as its row.
    if machine_context.call_site_interface(identity).is_some()
        && !machine_context.is_member_call_site(identity)
    {
        return Some(Err(MemberCallRefusal::Stated));
    }
    Some(Ok(MemberCall {
        identity,
        access: projection.access,
        graph: projection.graph,
        signature_id,
    }))
}
