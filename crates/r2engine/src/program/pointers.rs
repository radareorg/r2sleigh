//! Which parameters of each callee take an address, read once per callee.
//!
//! A number that does not move with the program is an address only where it
//! is used as one, and handing it to a callee that loads through it is such a
//! use. An import answers from its declaration; any other callee from its own
//! prepared body, which is the owner of what that body does with a parameter.

use std::collections::BTreeMap;
use std::sync::Arc;

use r2ssa::CanonicalStorageId;

use super::{OpenProgram, ProgramInputs, Source, View};
use crate::query::db::{Db, Hold, Query, Retention};
use crate::query::{Callee, Parameters};
use r2source::confidence::Basis;

/// A callee's pointer parameters, and whether a call cycle or the request's stop cut the answer short.
#[derive(Clone, PartialEq)]
pub(super) struct Pointed {
    found: Arc<[(CanonicalStorageId, Basis)]>,
    cut: Cut,
}

/// What cut an answer short, the stop outranking the cycle.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Cut {
    #[default]
    Whole,
    Cycle,
    Stopped,
}

/// What the declaration or the body says of each parameter, with its strongest support.
pub(super) struct PointerParameters;

impl<S: Source + 'static> Query<ProgramInputs<S>> for PointerParameters {
    type Key = Callee;
    type Value = Pointed;
    const NAME: &'static str = "pointer-parameters";
    const RETENTION: Retention = Retention::Held;

    fn compute(db: &Db<ProgramInputs<S>>, &callee: &Callee) -> Pointed {
        let (found, cut) = derived(&View::new(db, true), callee);
        Pointed {
            found: found.into_iter().collect(),
            cut,
        }
    }

    /// An answer a cycle cut short depends on where the walk entered the cycle, so it is not held.
    fn hold(value: &Pointed) -> Hold {
        match value.cut {
            Cut::Whole => Hold::Held,
            Cut::Cycle => Hold::Transient,
            Cut::Stopped => Hold::Stopped,
        }
    }
}

impl<S: Source + 'static> Parameters for OpenProgram<S> {
    fn pointer_use(
        &self,
        callee: Callee,
        held: &dyn Fn(&CanonicalStorageId) -> bool,
    ) -> Option<Basis> {
        self.view().pointer_use(callee, held)
    }
}

impl<S: Source + 'static> Parameters for View<'_, S> {
    fn pointer_use(
        &self,
        callee: Callee,
        held: &dyn Fn(&CanonicalStorageId) -> bool,
    ) -> Option<Basis> {
        let (Callee::At(address) | Callee::ThroughSlot(address)) = callee;
        let target = self.target(address).ok()?;
        // A number in no argument register reaches no parameter, so the callee need not be read.
        if !crate::native::argument_slots(&target).iter().any(held) {
            return None;
        }
        let pointed = self.db.get::<PointerParameters>(&callee).ok()?;
        pointed
            .found
            .iter()
            .filter(|(storage, _)| held(storage))
            .map(|(_, support)| *support)
            .min()
    }
}

/// What the declaration or the body says, and what cut it short.
fn derived<S: Source + 'static>(
    view: &View<'_, S>,
    callee: Callee,
) -> (BTreeMap<CanonicalStorageId, Basis>, Cut) {
    let (Callee::At(address) | Callee::ThroughSlot(address)) = callee;
    let Ok(target) = view.target(address) else {
        return (BTreeMap::new(), Cut::Whole);
    };
    // A slot names its import only where the loader binds it and seals it, as pdd's CallSlot does.
    let import = match callee {
        Callee::At(_) => crate::native::Program::import_at(view, address),
        Callee::ThroughSlot(_) => crate::stated::sealed_import(view, address).map(str::to_owned),
    };
    if let Some(name) = import {
        let declared = crate::native::declared_pointers(&target, &name);
        let declared = declared
            .into_iter()
            .map(|storage| (storage, Basis::Declared));
        return (declared.collect(), Cut::Whole);
    }
    // A slot the loader fills with no import is a word of data, not a body to read.
    let Callee::At(address) = callee else {
        return (BTreeMap::new(), Cut::Whole);
    };
    body_pointers(view, &target, address)
}

/// A callee's summary off its walk, resolved alone, held per callee: no answer depends on whether
/// a root read the callee first. No type analysis is derived for it.
pub(super) struct CalleeSummary;

/// A summary, or why there is none; compared by identity, as a walk is.
#[derive(Clone)]
pub(super) struct Summarised(Result<Arc<r2ssa::PreparedCalleeSummary>, crate::native::Unreadable>);

impl PartialEq for Summarised {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Ok(one), Ok(other)) => Arc::ptr_eq(one, other),
            (Err(one), Err(other)) => one == other,
            _ => false,
        }
    }
}

impl<S: Source + 'static> Query<ProgramInputs<S>> for CalleeSummary {
    type Key = (u64, bool);
    type Value = Summarised;
    const NAME: &'static str = "callee-summary";
    const RETENTION: Retention = Retention::Held;

    /// Work: one walk and one preparation of the callee alone.
    fn compute(db: &Db<ProgramInputs<S>>, &(address, thumb): &(u64, bool)) -> Summarised {
        let view = View::new(db, true);
        let summary = (|| {
            let target = view
                .target(address)
                .map_err(|_| crate::native::Unreadable::NotWalked)?;
            let walked = db.get::<super::analysis::Walked>(&(address, thumb));
            let walked = walked.expect("a walk asks for no summary");
            match walked.resolved() {
                Ok(walked) => crate::native::callee_summary(&target, &view, address, walked),
                Err(refusal) if refusal.stopped() => Err(crate::native::Unreadable::Stopped),
                Err(_) => Err(crate::native::Unreadable::NotWalked),
            }
        })();
        Summarised(summary.map(Arc::new))
    }

    fn hold(value: &Summarised) -> Hold {
        match value.0 {
            Err(crate::native::Unreadable::Stopped) => Hold::Stopped,
            _ => Hold::Held,
        }
    }
}

/// What a callee's prepared body does with its parameters: loads or stores through one, or hands it on to a callee that does.
fn body_pointers<S: Source + 'static>(
    view: &View<'_, S>,
    target: &crate::native::NativeTarget<'_>,
    address: u64,
) -> (BTreeMap<CanonicalStorageId, Basis>, Cut) {
    // A root's read of the callee alone holds the same summary: reading it prepares nothing.
    let key = (address, target.cpu == "thumb");
    let read = view.db.held::<super::analysis::CalleeReads>(&key);
    let held = read.ok().flatten().and_then(|read| {
        let facts = read.0.facts.as_ref().ok();
        facts.map(|facts| Arc::new(facts.summary().clone()))
    });
    let summarised = match held {
        Some(summary) => Ok(std::rc::Rc::new(Summarised(Ok(summary)))),
        None => view.db.get::<CalleeSummary>(&key),
    };
    let summarised = summarised.expect("a summary asks for no pointer parameters");
    let summary = match &summarised.0 {
        Ok(summary) => Arc::clone(summary),
        Err(crate::native::Unreadable::Stopped) => return (BTreeMap::new(), Cut::Stopped),
        Err(_) => return (BTreeMap::new(), Cut::Whole),
    };
    let slots = crate::native::argument_slots(target);
    let mut found = summary
        .dereferenced_arguments()
        .iter()
        .filter_map(|index| slots.get(*index))
        .map(|storage| (*storage, Basis::Dereferenced))
        .collect::<BTreeMap<_, _>>();
    let mut cut = Cut::Whole;
    for (onward, there, here) in summary.forwarded_arguments() {
        let (Some(own), Some(theirs)) = (slots.get(here), slots.get(there)) else {
            continue;
        };
        if found.contains_key(own) {
            continue;
        }
        // A cycle back into a callee being read is cut, not followed.
        let Ok(pointed) = view.db.get::<PointerParameters>(&Callee::At(onward)) else {
            cut = cut.max(Cut::Cycle);
            continue;
        };
        cut = cut.max(pointed.cut);
        if let Some((_, support)) = pointed.found.iter().find(|(storage, _)| storage == theirs) {
            found.insert(*own, *support);
        }
    }
    (found, cut)
}
