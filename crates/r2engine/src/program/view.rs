//! The program as a query reads it: every fact through the database, every byte recorded.

use std::collections::BTreeMap;
use std::rc::Rc;

use super::LoaderWrite;
use r2sleigh_lift::EmbeddedMachine;

use super::{Imports, NameDb, Names, ProgramInputs, Source, naming};
use crate::native::NativeTarget;
use crate::query::db::Db;

/// One open program, read through its database.
pub(crate) struct View<'a, S: Source + 'static> {
    pub(super) db: &'a Db<ProgramInputs<S>>,
    names: Rc<NameDb>,
    imports: Rc<BTreeMap<u64, naming::Stub>>,
}

impl<S: Source + 'static> Clone for View<'_, S> {
    fn clone(&self) -> Self {
        Self {
            db: self.db,
            names: Rc::clone(&self.names),
            imports: Rc::clone(&self.imports),
        }
    }
}

impl<'a, S: Source + 'static> View<'a, S> {
    /// The view a query reads through; the names and the stubs are asked once.
    pub(super) fn new(db: &'a Db<ProgramInputs<S>>) -> Self {
        let imports = db.get::<Imports>(&()).expect("the imports ask for nothing");
        let names = db
            .get::<Names>(&())
            .expect("the names ask only for the imports");
        Self { db, names, imports }
    }

    /// The view over tables the caller already holds for this revision.
    pub(super) fn with(
        db: &'a Db<ProgramInputs<S>>,
        names: Rc<NameDb>,
        imports: Rc<BTreeMap<u64, naming::Stub>>,
    ) -> Self {
        Self { db, names, imports }
    }

    pub(super) fn source(&self) -> &'a S {
        &self.db.inputs().source
    }

    /// The decoder for one instruction set.
    pub(super) fn machine_in(&self, thumb: bool) -> Option<&'a EmbeddedMachine> {
        match thumb {
            true => self.db.inputs().thumb_machine.as_ref(),
            false => self.db.inputs().machine.as_ref(),
        }
    }

    /// Whether the code at this address is Thumb: whichever is nearest below it of a mapping symbol and a function discovery placed, the container's statement winning a tie.
    pub(super) fn thumb_at(&self, vaddr: u64) -> bool {
        let inputs = self.db.inputs();
        let stated = inputs.mapped.range(..=vaddr).next_back();
        let derived = inputs.modes.range(..=vaddr).next_back();
        match (stated, derived) {
            (Some((at, thumb)), Some((from, _))) if at >= from => *thumb,
            (_, Some((_, thumb))) | (Some((_, thumb)), None) => *thumb,
            (None, None) => false,
        }
    }

    pub(super) fn machine_at(&self, vaddr: u64) -> Option<&'a EmbeddedMachine> {
        self.machine_in(self.thumb_at(vaddr))
    }

    /// Everything about the machine that does not change between functions.
    pub(super) fn target_of(
        &self,
        machine: &'a EmbeddedMachine,
    ) -> Result<NativeTarget<'a>, String> {
        let inputs = self.db.inputs();
        let assembled = inputs
            .assembled
            .as_ref()
            .ok_or("the program was not assembled for this address")?;
        Ok(NativeTarget {
            arch: &machine.arch,
            disasm: &machine.disasm,
            cpu: machine.cpu,
            convention: assembled.convention,
            call_effect: assembled.call_effect.as_ref(),
            compiler: &assembled.compiler,
            dwarf: &machine.dwarf,
            prototypes: &assembled.prototypes,
            declarations: &inputs.source.container().declarations,
        })
    }

    pub(super) fn target(&self, addr: u64) -> Result<NativeTarget<'a>, String> {
        self.target_of(
            self.machine_at(addr)
                .ok_or("no Sleigh specification for this architecture")?,
        )
    }

    /// Whether control comes back from a call to `callee`: false only where the program proves it never does.
    pub(super) fn comes_back(&self, callee: u64) -> bool {
        self.db
            .get::<super::returns::ComesBack>(&callee)
            .map_or(true, |answer| *answer)
    }
}

impl<S: Source + 'static> crate::body::Program for View<'_, S> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let read = self.source().read(vaddr, max)?;
        // Only what is mapped: no write can land in the unmapped rest.
        self.db
            .reads(vaddr..vaddr.saturating_add(read.len() as u64));
        Some(read)
    }

    /// The segment the container states holds this address; no write moves it.
    fn region(&self, vaddr: u64) -> Option<crate::body::Region> {
        let segment = self.source().container().segment_at(vaddr)?;
        let (start, end) = segment.range();
        Some(crate::body::Region {
            start,
            end,
            file_end: segment.file_end(),
            execute: segment.permissions.execute,
            write: segment.permissions.write,
        })
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        // A stub is a function of the program's as much as a body is.
        self.imports.contains_key(&vaddr)
            || self
                .db
                .inputs()
                .defined
                .get(&vaddr)
                .is_some_and(|function| *function)
    }

    fn returns(&self, callee: u64) -> bool {
        self.comes_back(callee)
    }

    fn returns_through(&self, slot: u64) -> bool {
        super::returns::Walking::new(self.clone(), false)
            .ok()
            .and_then(|walker| crate::discovery::Walker::declared(&walker, slot))
            .unwrap_or(true)
    }

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        let assembled = self.db.inputs().assembled.as_ref();
        assembled.and_then(|held| held.link.clone())
    }

    fn mode_register(&self) -> Option<r2il::Varnode> {
        let assembled = self.db.inputs().assembled.as_ref();
        assembled.and_then(|held| held.mode.clone())
    }
}

impl<S: Source + 'static> crate::native::Program for View<'_, S> {
    /// A query is no request's: nothing stops it but its own budgets.
    fn control(&self) -> crate::EngineExecutionControl {
        crate::EngineExecutionControl::default()
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        // The plain name: it keys the prototype table; a slot the loader fills is asked separately.
        self.names
            .text_at(vaddr)
            .map(str::to_owned)
            .or_else(|| self.db.inputs().slots.get(&vaddr).cloned())
    }

    fn holds_static_data(&self, vaddr: u64) -> bool {
        self.db.inputs().static_data.holds(vaddr)
    }

    fn loader_writes(&self) -> &[LoaderWrite] {
        &self.source().container().loader_writes
    }

    fn immutable(&self, range: &std::ops::Range<u64>) -> bool {
        self.source().container().immutable(range)
    }

    fn holds_code(&self, vaddr: u64) -> bool {
        match &self.db.inputs().code {
            Some(code) => code.holds(vaddr),
            None => crate::body::Program::region(self, vaddr).is_some_and(|region| region.execute),
        }
    }

    fn frame_saves(&self, entry: u64) -> Vec<r2source::SourceFrameSave> {
        let unwind = &self.source().container().unwind;
        unwind
            .at(entry)
            .map(|frame| {
                frame
                    .saves
                    .iter()
                    .map(|(register, entry_offset)| r2source::SourceFrameSave {
                        register: *register,
                        entry_offset: *entry_offset,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        &self.db.inputs().extents
    }

    fn import_at(&self, vaddr: u64) -> Option<String> {
        self.imports
            .get(&vaddr)
            .map(|stub| &stub.symbol)
            .or_else(|| self.db.inputs().slots.get(&vaddr))
            .cloned()
    }

    fn target_at(&self, vaddr: u64) -> Option<NativeTarget<'_>> {
        self.target(vaddr).ok()
    }
}
