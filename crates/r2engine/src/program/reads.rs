//! What the program's calls to a function read of its result registers (doc/adr-resolved-bodies.md,
//! "Caller reads"): each caller is lifted, never prepared, so no answer waits on its own function.

use std::collections::BTreeMap;
use std::sync::Arc;

use r2il::R2ILOp;
use r2source::SourceResultReads;

use super::requests::SurveyQuery;
use super::{ProgramInputs, Source, View};
use crate::query::db::{Db, Query};

/// The reads at every call to one function, by its entry; `None` where no call reads either register.
pub(super) struct ResultReads;

impl<S: Source + 'static> Query<ProgramInputs<S>> for ResultReads {
    type Key = u64;
    type Value = Option<SourceResultReads>;
    const NAME: &'static str = "result-reads";

    /// Work: one lift per caller discovery found, each scanned to its call's block end.
    fn compute(db: &Db<ProgramInputs<S>>, &callee: &u64) -> Self::Value {
        let survey = db.get::<SurveyQuery>(&()).ok()?;
        let survey = Arc::clone(&survey.as_ref().as_ref().ok()?.0);
        let view = View::new(db, true);
        let walker = super::returns::Walking::new(view.clone(), true).ok()?;
        let mut reads = SourceResultReads::default();
        for &caller in survey.callers_of(callee) {
            let Some(Ok(thumb)) = survey.walked_in(caller) else {
                continue;
            };
            let target = walker.target(thumb);
            let Ok(slots) = crate::native::convention_slots(target) else {
                continue;
            };
            let Ok(body) = crate::body::lift_body(caller, target.disasm, &view, &BTreeMap::new())
            else {
                continue;
            };
            let calls = body.blocks.iter().flat_map(|block| {
                let ops = block.lifted.ops.iter().enumerate();
                ops.filter(
                    |(_, op)| matches!(op, R2ILOp::Call { target } if target.offset == callee),
                )
                .map(move |(index, _)| (&block.lifted, index))
            });
            for (lifted, index) in calls {
                reads = reads.and(r2ssa::caller_reads::reads_after_call(
                    lifted,
                    index,
                    slots.result_slot(),
                    slots.float_result_slot(),
                ));
            }
        }
        (reads.integer > 0 || reads.float > 0).then_some(reads)
    }
}
