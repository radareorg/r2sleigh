//! Where the container states a function begins: the survey's seeds and every body walk's boundaries.

use std::collections::{BTreeMap, BTreeSet};

use super::{Imports, ProgramInputs, Source, SymbolKind};
use crate::query::db::{Db, Query, Retention};

/// Every function start the container states, and whether it states the code there is Thumb.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct StatedStarts {
    starts: BTreeMap<u64, bool>,
    /// Stated starts that hold no code the file backs, which begin no function (audit W29).
    placeless: BTreeSet<u64>,
}

impl StatedStarts {
    /// Whether the container states a function begins here.
    pub(super) fn holds(&self, vaddr: u64) -> bool {
        self.starts.contains_key(&vaddr)
    }

    /// Each stated start in address order, and whether its code is Thumb.
    pub(super) fn iter(&self) -> impl Iterator<Item = (u64, bool)> + '_ {
        self.starts.iter().map(|(vaddr, thumb)| (*vaddr, *thumb))
    }

    /// The stated starts dropped for holding no code, in address order.
    pub(super) fn placeless(&self) -> impl Iterator<Item = u64> + '_ {
        self.placeless.iter().copied()
    }
}

/// The program's stated starts, read once from the container and the decoded stubs.
pub(super) struct Stated;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Stated {
    type Key = ();
    type Value = StatedStarts;
    const NAME: &'static str = "stated-starts";
    const RETENTION: Retention = Retention::Held;

    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        let inputs = db.inputs();
        let container = inputs.source.container();
        let linkage = db.get::<Imports>(&()).expect("the imports ask for nothing");
        let imports = &linkage.stubs;
        let unnamed = &linkage.unnamed;
        // A frame begins a function (ROADMAP I) unless it is linkage code; one entered mid-function
        // is part of the function that jumps to it, though a function symbol there still begins one.
        let frames = (container.unwind.frames())
            .filter(|frame| frame.entry != r2abi::frames::FrameEntry::MidFunction)
            .filter(|frame| !linkage.holds(frame.start))
            .filter(|frame| {
                let covered = frame.start..frame.end.max(frame.start + 1);
                imports.range(covered.clone()).next().is_none()
                    && unnamed.range(covered).next().is_none()
            })
            .map(|frame| (frame.start, inputs.stated_thumb(frame.start)));
        let stated = (container.entries.iter())
            .map(|entry| (entry.vaddr, entry.thumb))
            .chain(
                (container.symbols.iter())
                    .filter(|symbol| symbol.defined && begins_a_function(inputs, symbol))
                    .map(|symbol| (symbol.vaddr, symbol.thumb)),
            )
            .chain(
                imports
                    .keys()
                    .chain(unnamed.keys())
                    .map(|vaddr| (*vaddr, false)),
            )
            .chain(frames);
        let mut starts = StatedStarts::default();
        // The first statement at an address decides its instruction set.
        for (vaddr, thumb) in stated {
            match inputs.places_function(vaddr) {
                true => _ = starts.starts.entry(vaddr).or_insert(thumb),
                false => _ = starts.placeless.insert(vaddr),
            }
        }
        starts
    }
}

/// A defined function symbol, or an export where the container states code: a directory states
/// no type, and an exported address in code is called from outside (PE).
fn begins_a_function<S: Source + 'static>(
    inputs: &ProgramInputs<S>,
    symbol: &r2abi::statement::Symbol,
) -> bool {
    let exported = symbol.origin.directory.is_some();
    symbol.kind == SymbolKind::Function || (exported && inputs.holds_code(symbol.vaddr))
}
