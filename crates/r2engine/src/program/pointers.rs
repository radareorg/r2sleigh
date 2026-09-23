//! Which parameters of each callee take an address, read once per callee.
//!
//! A number that does not move with the program is an address only where it
//! is used as one, and handing it to a callee that loads through it is such a
//! use. An import answers from its declaration; any other callee from its own
//! prepared body, which is the owner of what that body does with a parameter.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use r2ssa::CanonicalStorageId;

use super::{OpenProgram, Source};
use crate::query::{Callee, Parameters, Revision, Support};

type Pointed = Arc<[(CanonicalStorageId, Support)]>;

/// Each callee's pointer parameters, for the revision they were read at.
#[derive(Default)]
pub(super) struct Pointers {
    at: Option<Revision>,
    by_callee: BTreeMap<Callee, Pointed>,
}

impl<S: Source> Parameters for OpenProgram<S> {
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
        self.pointer_parameters(callee, &mut BTreeSet::new())
            .0
            .iter()
            .filter(|(storage, _)| held(storage))
            .map(|(_, support)| *support)
            .min()
    }
}

impl<S: Source> OpenProgram<S> {
    /// A callee's pointer parameters, and whether a call cycle cut the answer short.
    ///
    /// An answer a cycle cut short depends on where the walk entered the
    /// cycle, so it is not kept: what is kept is the same whoever asked first.
    fn pointer_parameters(&self, callee: Callee, visiting: &mut BTreeSet<u64>) -> (Pointed, bool) {
        let revision = self.revision();
        {
            let mut cache = self
                .pointers
                .lock()
                .unwrap_or_else(|held| held.into_inner());
            if cache.at != Some(revision) {
                *cache = Pointers {
                    at: Some(revision),
                    by_callee: BTreeMap::new(),
                };
            }
            if let Some(known) = cache.by_callee.get(&callee) {
                return (Arc::clone(known), false);
            }
        }
        let (found, cut) = self.derived_pointers(callee, visiting);
        let found: Pointed = found.into_iter().collect();
        if !cut {
            let mut cache = self
                .pointers
                .lock()
                .unwrap_or_else(|held| held.into_inner());
            cache.by_callee.insert(callee, Arc::clone(&found));
        }
        (found, cut)
    }

    /// What the declaration or the body says, with each parameter's strongest support.
    fn derived_pointers(
        &self,
        callee: Callee,
        visiting: &mut BTreeSet<u64>,
    ) -> (BTreeMap<CanonicalStorageId, Support>, bool) {
        let address = match callee {
            Callee::At(address) | Callee::ThroughSlot(address) => address,
        };
        let Ok(target) = self.target(address) else {
            return (BTreeMap::new(), false);
        };
        if let Some(name) = crate::native::Program::import_at(self, address) {
            let declared = crate::native::declared_pointers(&target, &name);
            return (
                declared
                    .into_iter()
                    .map(|storage| (storage, Support::Declared))
                    .collect(),
                false,
            );
        }
        // A slot the loader fills with no import is a word of data, not a body to read.
        let Callee::At(address) = callee else {
            return (BTreeMap::new(), false);
        };
        if !visiting.insert(address) {
            return (BTreeMap::new(), true);
        }
        let found = self.body_pointers(&target, address, visiting);
        visiting.remove(&address);
        found
    }

    /// What a callee's prepared body does with its parameters: loads or stores through one, or hands it on to a callee that does.
    fn body_pointers(
        &self,
        target: &crate::native::NativeTarget<'_>,
        address: u64,
        visiting: &mut BTreeSet<u64>,
    ) -> (BTreeMap<CanonicalStorageId, Support>, bool) {
        let Some(summary) = crate::native::callee_summary(target, self, address) else {
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
            let (pointed, stopped) = self.pointer_parameters(Callee::At(onward), visiting);
            cut |= stopped;
            if let Some((_, support)) = pointed.iter().find(|(storage, _)| storage == theirs) {
                found.insert(*own, *support);
            }
        }
        (found, cut)
    }
}
