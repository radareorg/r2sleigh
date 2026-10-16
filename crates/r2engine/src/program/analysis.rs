//! One function's analysis, its callees' reads and its sealing, as queries (doc/adr-query-database.md, Q2).

use std::rc::Rc;
use std::sync::Arc;

use super::{ProgramInputs, Source, View};
use crate::native::{CalleeRead, NativeRefusal, Prepared, Stated, Unreadable};
use crate::query::db::{Db, Hold, Query, Retention};
use crate::{EngineDecompileResponse, EngineSession, SealedFunctionAnalysis};

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

/// One function's analysis, sealing and rendering: its entry, whether it is Thumb, and whether
/// it reads its callers.
pub(super) type Key = (u64, bool, super::Callers);

/// One function's walk and preparation, by its key; the most recent only.
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
    type Key = Key;
    type Value = Analysis;
    const NAME: &'static str = "analysed";
    /// The function's analysis while its request reads it; asked again, it is computed again
    /// (doc/adr-memory-model.md, "Retention").
    const RETENTION: Retention = Retention::Newest;

    fn compute(db: &Db<ProgramInputs<S>>, &(entry, thumb, callers): &Key) -> Analysis {
        let view = View::new(db, true);
        let target = match target(&view, entry, thumb) {
            Ok(target) => target,
            Err(refusal) => return Analysis(Err(refusal)),
        };
        let walk = db
            .get::<Walked>(&(entry, thumb))
            .expect("a walk asks for no analysis");
        let walk = match walk.resolved() {
            Ok(walk) => walk,
            Err(refusal) => return Analysis(Err(refusal)),
        };
        let analysed = crate::isolation::isolated(|| {
            crate::native::analysed_from(&target, &view, (entry, walk), callers)
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

/// The machine the function at `entry` runs on, under its language's convention, or why there is none.
fn target<'a, S: Source + 'static>(
    view: &View<'a, S>,
    entry: u64,
    thumb: bool,
) -> Result<crate::native::NativeTarget<'a>, NativeRefusal> {
    let Some(machine) = view.machine_in(thumb) else {
        return Err(view.unloaded().map_or(
            NativeRefusal::Machine("the architecture has no Thumb decoder"),
            NativeRefusal::Unassembled,
        ));
    };
    view.target_of(machine, entry)
        .map_err(NativeRefusal::Unassembled)
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

impl Walking {
    /// The walk where its dispatch tables were read, for the analyses that need them resolved; the
    /// refusal otherwise. The listing and the index read the body whatever the tables did.
    pub(super) fn resolved(&self) -> Result<&Arc<crate::native::Walk>, NativeRefusal> {
        let walk = self.0.as_ref().map_err(Clone::clone)?;
        walk.refusal()
            .map_or(Ok(walk), |refusal| Err(refusal.clone()))
    }
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Walked {
    type Key = (u64, bool);
    type Value = Walking;
    const NAME: &'static str = "walked";
    /// A walk holds its lifted blocks: the newest is kept for the analysis that reads it.
    const RETENTION: Retention = Retention::Newest;

    fn compute(db: &Db<ProgramInputs<S>>, &(entry, thumb): &(u64, bool)) -> Walking {
        let view = View::new(db, true);
        let target = match target(&view, entry, thumb) {
            Ok(target) => target,
            Err(refusal) => return Walking(Err(refusal)),
        };
        let tables = || (*dispatch_tables(db, (entry, thumb)).0).clone();
        let walked = crate::isolation::isolated(|| {
            crate::native::walk_reading(&target, &view, entry, &tables)
        });
        Walking(
            walked
                .unwrap_or_else(|panicked| Err(panicked.into()))
                .map(Arc::new),
        )
    }

    fn hold(value: &Walking) -> Hold {
        match value.resolved().is_err_and(|refusal| refusal.stopped()) {
            true => Hold::Stopped,
            false => Hold::Held,
        }
    }
}

/// The dispatch tables one function's body reads, by its entry and whether it is Thumb: read once for the survey, the walk and the listings.
pub(super) struct DispatchTables;

impl<S: Source + 'static> Query<ProgramInputs<S>> for DispatchTables {
    type Key = (u64, bool);
    type Value = Shared<crate::native::Tables>;
    const NAME: &'static str = "dispatch-tables";
    const RETENTION: Retention = Retention::Held;

    fn compute(db: &Db<ProgramInputs<S>>, &(entry, thumb): &(u64, bool)) -> Self::Value {
        // The survey asks while it runs, so no mode is read: the key states the set.
        let view = View::new(db, false);
        let read = target(&view, entry, thumb).map(|target| {
            crate::isolation::isolated(|| crate::native::dispatch_tables(&target, &view, entry))
        });
        Shared(Arc::new(match read {
            Ok(Ok(tables)) => tables,
            Ok(Err(panicked)) => crate::native::Tables::refused(panicked.into()),
            Err(refusal) => crate::native::Tables::refused(refusal),
        }))
    }

    fn hold(value: &Self::Value) -> Hold {
        match value.0.refusal().is_some_and(NativeRefusal::stopped) {
            true => Hold::Stopped,
            false => Hold::Held,
        }
    }
}

/// The tables read for a body; a cycle reads as none, which is a walk following no table.
pub(super) fn dispatch_tables<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    key: (u64, bool),
) -> Shared<crate::native::Tables> {
    db.get::<DispatchTables>(&key).map_or_else(
        |cycle| {
            Shared(Arc::new(crate::native::Tables::refused(
                NativeRefusal::Prepare(format!("{cycle:?}")),
            )))
        },
        |tables| (*tables).clone(),
    )
}

/// What one callee's body proves, resolved alone, by its entry and whether it is Thumb.
pub(super) struct CalleeReads;

impl<S: Source + 'static> Query<ProgramInputs<S>> for CalleeReads {
    type Key = (u64, bool);
    type Value = Shared<CalleeRead>;
    const NAME: &'static str = "callee-reads";
    const RETENTION: Retention = Retention::Held;

    fn compute(db: &Db<ProgramInputs<S>>, &(address, thumb): &(u64, bool)) -> Shared<CalleeRead> {
        Shared(Arc::new(callee_read(
            db,
            (address, thumb),
            Stated::default(),
        )))
    }

    fn hold(value: &Shared<CalleeRead>) -> Hold {
        match value.0.facts {
            Err(Unreadable::Stopped) => Hold::Stopped,
            _ => Hold::Held,
        }
    }
}

/// One callee resolved on its walk against its imports and what else is `stated` of its callees.
pub(super) fn callee_read<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
    (address, thumb): (u64, bool),
    stated: Stated<'_>,
) -> CalleeRead {
    let unread = |reason| CalleeRead {
        interface: None,
        facts: Err(reason),
        owners: Default::default(),
    };
    let view = View::new(db, true);
    let target = view
        .machine_in(thumb)
        .map(|machine| view.target_of(machine, address));
    let walked = db
        .get::<Walked>(&(address, thumb))
        .expect("a walk asks for no callee");
    match (target, walked.resolved()) {
        (_, Err(refusal)) if refusal.stopped() => unread(Unreadable::Stopped),
        (_, Err(_)) => unread(Unreadable::NotWalked),
        (Some(Ok(target)), Ok(walked)) => {
            crate::native::callee_read(&target, &view, address, walked, stated)
        }
        _ => unread(Unreadable::NotPrepared),
    }
}

/// The type analysis sealed from one function's analysis.
pub(super) struct Sealed;

/// A sealing, a refusal and whether the request's control could have caused it, or why there is no
/// analysis to seal.
#[derive(Clone)]
pub(super) enum Sealing {
    Sealed(Shared<SealedFunctionAnalysis>),
    Refused {
        response: Rc<EngineDecompileResponse>,
        stopped: bool,
    },
    Unanalysed(NativeRefusal),
}

impl PartialEq for Sealing {
    fn eq(&self, other: &Self) -> bool {
        matches!((self, other), (Self::Sealed(one), Self::Sealed(other)) if one == other)
    }
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Sealed {
    type Key = Key;
    type Value = Sealing;
    const NAME: &'static str = "sealed";
    /// The sealing while its request reads it, as the analysis it seals.
    const RETENTION: Retention = Retention::Newest;

    fn compute(db: &Db<ProgramInputs<S>>, key: &Key) -> Sealing {
        let analysis = db
            .get::<Analysed>(key)
            .expect("an analysis asks for no sealing");
        let prepared = match &analysis.0 {
            Ok(prepared) => prepared,
            Err(refusal) => return Sealing::Unanalysed(refusal.clone()),
        };
        let view = View::new(db, true);
        let target = match target(&view, key.0, key.1) {
            Ok(target) => target,
            Err(refusal) => return Sealing::Unanalysed(refusal),
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
            Sealing::Unanalysed(refusal) if refusal.stopped() => Hold::Stopped,
            _ => Hold::Held,
        }
    }
}

/// One function rendered: a session redraws what it rendered.
pub(super) struct Rendered;

/// A rendering: the C, or the record of why the function has none (ROADMAP D29).
#[derive(Clone)]
pub(super) struct Render(pub(super) Rc<Drawn>);

/// A rendering and whether the request's control could have cut it short.
pub(super) struct Drawn {
    pub(super) rendering: super::Rendering,
    stopped: bool,
}

impl PartialEq for Render {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for Rendered {
    type Key = Key;
    type Value = Render;
    const NAME: &'static str = "rendered";
    /// The newest rendering, which a redraw reads; another function's is drawn again.
    const RETENTION: Retention = Retention::Newest;

    fn compute(db: &Db<ProgramInputs<S>>, key: &Key) -> Render {
        let entry = key.0;
        let control = db.inputs().control.clone();
        // A fact the container states, fixed for the program's life: no read to record.
        let language = db.inputs().source.container().languages.at(entry);
        let refused = |refusal: NativeRefusal| {
            let stopped = control.stopped() || refusal.stopped();
            let name = crate::native::Program::name_at(&View::new(db, true), entry);
            let name = name.unwrap_or_else(|| r2source::unnamed_function(entry));
            let rendering = super::Rendering::refused(&name, entry, language, refusal);
            Render(Rc::new(Drawn { rendering, stopped }))
        };
        // D32's admission is the container's fact, asked before any analysis is paid for.
        if let Err(unadmitted) = crate::route::admitted(&db.inputs().source.container().arch) {
            return refused(unadmitted);
        }
        let analysis = db
            .get::<Analysed>(key)
            .expect("an analysis asks for no rendering");
        let prepared = match &analysis.0 {
            Ok(prepared) => prepared,
            Err(refusal) => return refused(refusal.clone()),
        };
        let function = prepared.artifact().artifact().function();
        let definition = r2dec::rendered_name_of(function.name.as_deref(), entry);
        let unread = prepared.unread().to_vec();
        let sealing = db
            .get::<Sealed>(key)
            .expect("a sealing asks for no rendering");
        let response = match &*sealing {
            Sealing::Sealed(sealed) => {
                let render = || EngineSession::new().render_sealed(&sealed.0, &control);
                crate::isolation::isolated(render).unwrap_or_else(|panicked| {
                    let phase = crate::EnginePhase::Structuring;
                    crate::panicked_decompile_response(&sealed.0.function_name, &panicked, phase)
                })
            }
            Sealing::Refused { response, .. } => EngineDecompileResponse::clone(response),
            Sealing::Unanalysed(refusal) => return refused(refusal.clone()),
        };
        let rendering = super::Rendering {
            response: response.into(),
            definition,
            unread,
            language,
            refused: None,
        };
        let stopped = control.stopped();
        Render(Rc::new(Drawn { rendering, stopped }))
    }

    fn hold(value: &Render) -> Hold {
        match value.0.stopped {
            true => Hold::Stopped,
            false => Hold::Held,
        }
    }
}
