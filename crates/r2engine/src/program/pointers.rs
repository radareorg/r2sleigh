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
use crate::query::db::{Db, Query};
use crate::query::{Callee, Parameters, Support};

/// A callee's pointer parameters, and whether a call cycle cut the answer short.
#[derive(Clone, PartialEq)]
pub(super) struct Pointed {
    found: Arc<[(CanonicalStorageId, Support)]>,
    cut: bool,
}

/// What the declaration or the body says of each parameter, with its strongest support.
pub(super) struct PointerParameters;

impl<S: Source + 'static> Query<ProgramInputs<S>> for PointerParameters {
    type Key = Callee;
    type Value = Pointed;
    const NAME: &'static str = "pointer-parameters";

    fn compute(db: &Db<ProgramInputs<S>>, &callee: &Callee) -> Pointed {
        let (found, cut) = derived(&View::new(db, true), callee);
        Pointed {
            found: found.into_iter().collect(),
            cut,
        }
    }

    /// An answer a cycle cut short depends on where the walk entered the cycle, so it is not held.
    fn stopped(value: &Pointed) -> bool {
        value.cut
    }
}

impl<S: Source + 'static> Parameters for OpenProgram<S> {
    fn pointer_use(
        &self,
        callee: Callee,
        held: &dyn Fn(&CanonicalStorageId) -> bool,
    ) -> Option<Support> {
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

/// What the declaration or the body says, and whether a call cycle cut it short.
fn derived<S: Source + 'static>(
    view: &View<'_, S>,
    callee: Callee,
) -> (BTreeMap<CanonicalStorageId, Support>, bool) {
    let (Callee::At(address) | Callee::ThroughSlot(address)) = callee;
    let Ok(target) = view.target(address) else {
        return (BTreeMap::new(), false);
    };
    if let Some(name) = crate::native::Program::import_at(view, address) {
        let declared = crate::native::declared_pointers(&target, &name);
        let declared = declared
            .into_iter()
            .map(|storage| (storage, Support::Declared));
        return (declared.collect(), false);
    }
    // A slot the loader fills with no import is a word of data, not a body to read.
    let Callee::At(address) = callee else {
        return (BTreeMap::new(), false);
    };
    body_pointers(view, &target, address)
}

/// What a callee's prepared body does with its parameters: loads or stores through one, or hands it on to a callee that does.
fn body_pointers<S: Source + 'static>(
    view: &View<'_, S>,
    target: &crate::native::NativeTarget<'_>,
    address: u64,
) -> (BTreeMap<CanonicalStorageId, Support>, bool) {
    // A callee some root has read already carries its summary; otherwise it
    // is prepared for this alone, which costs less than reading it whole.
    let key = (address, target.cpu == "thumb");
    let read = view.db.held::<super::analysis::CalleeReads>(&key);
    let held = read.ok().flatten().and_then(|read| {
        let facts = read.0.facts.as_ref().ok();
        facts.map(|facts| facts.summary().clone())
    });
    let Some(summary) = held.or_else(|| crate::native::callee_summary(target, view, address))
    else {
        return (BTreeMap::new(), false);
    };
    let slots = crate::native::argument_slots(target);
    let mut found = summary
        .dereferenced_arguments()
        .iter()
        .filter_map(|index| slots.get(*index))
        .map(|storage| (*storage, Support::Dereferenced))
        .collect::<BTreeMap<_, _>>();
    let mut cut = false;
    for (onward, there, here) in summary.forwarded_arguments() {
        let (Some(own), Some(theirs)) = (slots.get(here), slots.get(there)) else {
            continue;
        };
        if found.contains_key(own) {
            continue;
        }
        // A cycle back into a callee being read is cut, not followed.
        let Ok(pointed) = view.db.get::<PointerParameters>(&Callee::At(onward)) else {
            cut = true;
            continue;
        };
        cut |= pointed.cut;
        if let Some((_, support)) = pointed.found.iter().find(|(storage, _)| storage == theirs) {
            found.insert(*own, *support);
        }
    }
    (found, cut)
}
