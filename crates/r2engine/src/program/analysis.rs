//! One function's analysis, its callees' reads and its sealing, as queries (doc/adr-query-database.md, Q2).

use std::sync::Arc;

use super::{ProgramInputs, Source, View};
use crate::SealedFunctionAnalysis;
use crate::native::{CalleeRead, NativeRefusal, Prepared, Unreadable};
use crate::query::db::{Db, Hold, Query};

/// A shared answer compared by identity: a recomputed analysis is a new one, never backdated.
pub(super) struct Shared<T>(pub(super) Arc<T>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> PartialEq for Shared<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// One function's walk and preparation, by its entry and whether it is Thumb; the most recent only.
pub(super) struct Analysed;

/// An analysis, or why there is none; a refusal is never equal to another, so it is never backdated.
#[derive(Clone)]
pub(super) struct Analysis(pub(super) Result<Arc<Prepared>, NativeRefusal>);

impl PartialEq for Analysis {
    fn eq(&self, other: &Self) -> bool {
        matches!((&self.0, &other.0), (Ok(one), Ok(other)) if Arc::ptr_eq(one, other))
    }
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Analysed {
    type Key = (u64, bool);
    type Value = Analysis;
    const NAME: &'static str = "analysed";
    /// A prepared body is megabytes; a session asks about one function at a time.
    const CAPACITY: Option<usize> = Some(1);

    fn compute(db: &Db<ProgramInputs<S>>, &(entry, thumb): &(u64, bool)) -> Analysis {
        let view = View::new(db, true);
        let target = view
            .machine_in(thumb)
            .ok_or("no Sleigh specification for this architecture")
            .and_then(|machine| view.target_of(machine).map_err(|_| "unassembled"));
        let Ok(target) = target else {
            return Analysis(Err(NativeRefusal::Machine("the machine is not assembled")));
        };
        let analysed =
            crate::isolation::isolated(|| crate::native::analysed(&target, &view, entry));
        Analysis(
            analysed
                .unwrap_or_else(|panicked| Err(panicked.into()))
                .map(Arc::new),
        )
    }

    fn hold(value: &Analysis) -> Hold {
        match value.0.as_ref().is_err_and(NativeRefusal::stopped) {
            true => Hold::Stopped,
            false => Hold::Held,
        }
    }
}

/// What one callee's body proves, read with the root's decoder, by its entry and whether that decoder is Thumb.
pub(super) struct CalleeReads;

impl<S: Source + 'static> Query<ProgramInputs<S>> for CalleeReads {
    type Key = (u64, bool);
    type Value = Shared<CalleeRead>;
    const NAME: &'static str = "callee-reads";

    fn compute(db: &Db<ProgramInputs<S>>, &(address, thumb): &(u64, bool)) -> Shared<CalleeRead> {
        let view = View::new(db, true);
        let target = view
            .machine_in(thumb)
            .map(|machine| view.target_of(machine));
        let read = match target {
            Some(Ok(target)) => crate::native::callee_read(&target, &view, address),
            _ => CalleeRead {
                interface: None,
                facts: Err(Unreadable::NotPrepared),
            },
        };
        Shared(Arc::new(read))
    }

    fn hold(value: &Shared<CalleeRead>) -> Hold {
        match value.0.facts {
            Err(Unreadable::Stopped) => Hold::Stopped,
            _ => Hold::Held,
        }
    }
}

/// The type analysis sealed from one function's analysis; a refusal may be the request's stop, so none is held.
pub(super) struct Sealed;

/// A sealing, a refusal, or no analysis to seal.
#[derive(Clone)]
pub(super) enum Sealing {
    Sealed(Shared<SealedFunctionAnalysis>),
    Refused(std::rc::Rc<crate::EngineDecompileResponse>),
    Unanalysed,
}

impl PartialEq for Sealing {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (Self::Sealed(one), Self::Sealed(other)) if one == other)
    }
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Sealed {
    type Key = (u64, bool);
    type Value = Sealing;
    const NAME: &'static str = "sealed";
    const CAPACITY: Option<usize> = Some(1);

    fn compute(db: &Db<ProgramInputs<S>>, key: &(u64, bool)) -> Sealing {
        let analysis = db
            .get::<Analysed>(key)
            .expect("an analysis asks for no sealing");
        let Ok(prepared) = &analysis.0 else {
            return Sealing::Unanalysed;
        };
        let view = View::new(db, true);
        let target = view
            .machine_in(key.1)
            .map(|machine| view.target_of(machine));
        let Some(Ok(target)) = target else {
            return Sealing::Unanalysed;
        };
        let control = db.inputs().control.clone();
        let sealed = crate::isolation::isolated(|| {
            crate::native::sealed(&target, key.0, prepared, &control)
        });
        match sealed {
            Ok(Ok(sealed)) => Sealing::Sealed(Shared(Arc::new(sealed))),
            Ok(Err(refused)) => Sealing::Refused(std::rc::Rc::from(refused)),
            Err(panicked) => {
                Sealing::Refused(std::rc::Rc::new(crate::panicked_decompile_response(
                    prepared.name(),
                    &panicked,
                    crate::EnginePhase::Types,
                )))
            }
        }
    }

    fn hold(value: &Sealing) -> Hold {
        match value {
            Sealing::Sealed(_) => Hold::Held,
            _ => Hold::Stopped,
        }
    }
}
