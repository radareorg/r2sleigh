//! One function's analysis, its callees' reads and its sealing, as queries (doc/adr-query-database.md, Q2).

use std::rc::Rc;
use std::sync::Arc;

use super::{ProgramInputs, Source, View};
use crate::native::{CalleeRead, NativeRefusal, Prepared, Unreadable};
use crate::query::db::{Db, Hold, Query};
use crate::{EngineDecompileResponse, EngineSession, RenderTier, SealedFunctionAnalysis};

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
        let walk = db
            .get::<Walked>(&(entry, thumb))
            .expect("a walk asks for no analysis");
        let walk = match &walk.0 {
            Ok(walk) => walk,
            Err(refusal) => return Analysis(Err(refusal.clone())),
        };
        let analysed = crate::isolation::isolated(|| {
            crate::native::analysed_from(&target, &view, entry, walk)
        });
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

/// One function's walk through the dispatch tables it reads, by its entry and whether it is Thumb.
pub(super) struct Walked;

/// A walk, or why there is none; compared by identity, as an analysis is.
#[derive(Clone)]
pub(super) struct Walking(pub(super) Result<Arc<crate::native::Walk>, NativeRefusal>);

impl PartialEq for Walking {
    fn eq(&self, other: &Self) -> bool {
        matches!((&self.0, &other.0), (Ok(one), Ok(other)) if Arc::ptr_eq(one, other))
    }
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Walked {
    type Key = (u64, bool);
    type Value = Walking;
    const NAME: &'static str = "walked";
    /// A walk holds its lifted blocks; the values dropped past this keep what they read.
    const CAPACITY: Option<usize> = Some(64);

    fn compute(db: &Db<ProgramInputs<S>>, &(entry, thumb): &(u64, bool)) -> Walking {
        let view = View::new(db, true);
        let Some(Ok(target)) = view
            .machine_in(thumb)
            .map(|machine| view.target_of(machine))
        else {
            return Walking(Err(NativeRefusal::Machine("the machine is not assembled")));
        };
        let walked = crate::isolation::isolated(|| crate::native::walk(&target, &view, entry));
        Walking(
            walked
                .unwrap_or_else(|panicked| Err(panicked.into()))
                .map(Arc::new),
        )
    }

    fn hold(value: &Walking) -> Hold {
        match value.0.as_ref().is_err_and(NativeRefusal::stopped) {
            true => Hold::Stopped,
            false => Hold::Held,
        }
    }
}

/// What one callee's body proves, resolved alone, by its entry and whether it is Thumb.
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
        let walked = db
            .get::<Walked>(&(address, thumb))
            .expect("a walk asks for no callee");
        let read = match (target, &walked.0) {
            (_, Err(refusal)) if refusal.stopped() => CalleeRead {
                interface: None,
                facts: Err(Unreadable::Stopped),
            },
            (_, Err(_)) => CalleeRead {
                interface: None,
                facts: Err(Unreadable::NotWalked),
            },
            (Some(Ok(target)), Ok(walked)) => {
                crate::native::callee_read(&target, &view, address, walked)
            }
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

/// The type analysis sealed from one function's analysis.
pub(super) struct Sealed;

/// A sealing, a refusal and whether the request's control could have caused it, or no analysis to seal.
#[derive(Clone)]
pub(super) enum Sealing {
    Sealed(Shared<SealedFunctionAnalysis>),
    Refused {
        response: Rc<EngineDecompileResponse>,
        stopped: bool,
    },
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
        let response = match sealed {
            Ok(Ok(sealed)) => return Sealing::Sealed(Shared(Arc::new(sealed))),
            Ok(Err(refused)) => Rc::from(refused),
            Err(panicked) => Rc::new(crate::panicked_decompile_response(
                prepared.name(),
                &panicked,
                crate::EnginePhase::Types,
            )),
        };
        Sealing::Refused {
            response,
            stopped: control.stopped(),
        }
    }

    fn hold(value: &Sealing) -> Hold {
        match value {
            Sealing::Refused { stopped: true, .. } => Hold::Stopped,
            _ => Hold::Held,
        }
    }
}

/// One function rendered at one tier: a session redraws what it rendered.
pub(super) struct Rendered;

/// A rendering, or why the function has none.
#[derive(Clone)]
pub(super) struct Render(pub(super) Result<Rc<Drawn>, String>);

/// A rendering and whether the request's control could have cut it short.
pub(super) struct Drawn {
    pub(super) rendering: super::Rendering,
    stopped: bool,
}

impl PartialEq for Render {
    fn eq(&self, other: &Self) -> bool {
        matches!((&self.0, &other.0), (Ok(one), Ok(other)) if Rc::ptr_eq(one, other))
    }
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Rendered {
    type Key = (u64, bool, RenderTier);
    type Value = Render;
    const NAME: &'static str = "rendered";
    /// A rendering is the C text and its facts, far smaller than the analysis it is read from.
    const CAPACITY: Option<usize> = Some(16);

    fn compute(
        db: &Db<ProgramInputs<S>>,
        &(entry, thumb, tier): &(u64, bool, RenderTier),
    ) -> Render {
        let analysis = db
            .get::<Analysed>(&(entry, thumb))
            .expect("an analysis asks for no rendering");
        let prepared = match &analysis.0 {
            Ok(prepared) => prepared,
            Err(refusal) => return Render(Err(refusal.to_string())),
        };
        let function = prepared.artifact().artifact().function();
        let definition = r2dec::rendered_name_of(function.name.as_deref(), entry);
        let unread = prepared.unread().to_vec();
        let sealing = db
            .get::<Sealed>(&(entry, thumb))
            .expect("a sealing asks for no rendering");
        let control = db.inputs().control.clone();
        let response = match &*sealing {
            Sealing::Sealed(sealed) => {
                let render = || EngineSession::new().render_sealed(&sealed.0, tier, &control);
                crate::isolation::isolated(render).unwrap_or_else(|panicked| {
                    let phase = crate::EnginePhase::Structuring;
                    crate::panicked_decompile_response(&sealed.0.function_name, &panicked, phase)
                })
            }
            Sealing::Refused { response, .. } => EngineDecompileResponse::clone(response),
            Sealing::Unanalysed => {
                return Render(Err("the function has no analysis to render".to_owned()));
            }
        };
        let rendering = super::Rendering {
            response,
            definition,
            unread,
        };
        let stopped = control.stopped();
        Render(Ok(Rc::new(Drawn { rendering, stopped })))
    }

    fn hold(value: &Render) -> Hold {
        match &value.0 {
            Ok(drawn) if drawn.stopped => Hold::Stopped,
            _ => Hold::Held,
        }
    }
}
