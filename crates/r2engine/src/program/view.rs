//! The program as a query reads it: every fact through the database, every byte recorded.

use std::rc::Rc;

use super::LoaderWrite;
use crate::machine::Machine;

use super::starts::{Stated, StatedStarts};
use super::{Imports, NameDb, Names, ProgramInputs, Source, naming};
use crate::native::{NativeRefusal, NativeTarget};
use crate::query::db::Db;

/// Which instruction set the code the survey found is in.
pub(super) fn modes<S: Source + 'static>(
    db: &Db<ProgramInputs<S>>,
) -> Rc<super::requests::ModeMap> {
    db.get::<super::requests::Modes>(&())
        .expect("the survey reads no modes")
}

/// How this program spells a word in memory: the container states it, not the decoder (ARM BE8).
pub(super) fn endian<S: Source>(source: &S) -> r2il::Endianness {
    endianness(source.container().arch.endian)
}

/// The lift's spelling of a byte order the container states.
pub(super) fn endianness(endian: super::Endian) -> r2il::Endianness {
    match endian {
        super::Endian::Little => r2il::Endianness::Little,
        super::Endian::Big => r2il::Endianness::Big,
    }
}

/// One open program, read through its database.
pub(crate) struct View<'a, S: Source + 'static> {
    pub(super) db: &'a Db<ProgramInputs<S>>,
    names: Rc<NameDb>,
    imports: Rc<naming::Linkage>,
    /// Where the container states a function begins, which bounds every body walk.
    starts: Rc<StatedStarts>,
    /// Which set the code discovery found is in; empty for discovery itself, which decides it.
    modes: Rc<super::requests::ModeMap>,
}

impl<S: Source + 'static> Clone for View<'_, S> {
    fn clone(&self) -> Self {
        Self {
            db: self.db,
            names: Rc::clone(&self.names),
            imports: Rc::clone(&self.imports),
            starts: Rc::clone(&self.starts),
            modes: Rc::clone(&self.modes),
        }
    }
}

impl<'a, S: Source + 'static> View<'a, S> {
    /// The view a query reads through; the names, the stubs, the stated starts and, where asked, the modes are asked once.
    pub(super) fn new(db: &'a Db<ProgramInputs<S>>, with_modes: bool) -> Self {
        let imports = db.get::<Imports>(&()).expect("the imports ask for nothing");
        let names = db
            .get::<Names>(&())
            .expect("the names ask only for the imports");
        let starts = (db.get::<Stated>(&())).expect("the stated starts ask only for the imports");
        let modes = match with_modes {
            true => modes(db),
            false => Rc::default(),
        };
        Self {
            db,
            names,
            imports,
            starts,
            modes,
        }
    }

    /// Where the container states a function begins.
    pub(super) fn stated_starts(&self) -> &StatedStarts {
        &self.starts
    }

    /// The program's linkage code: its stubs and the sections that hold only linkage code.
    pub(super) fn linkage(&self) -> &naming::Linkage {
        &self.imports
    }

    pub(super) fn source(&self) -> &'a S {
        &self.db.inputs().source
    }

    /// Why the program's decoders did not load, where they did not.
    pub(super) fn unloaded(&self) -> Option<crate::native::Unassembled> {
        self.db.inputs().machines().err()
    }

    /// The decoder for one instruction set.
    pub(super) fn machine_in(&self, thumb: bool) -> Option<&'a Machine> {
        match thumb {
            true => self.db.inputs().machines().ok()?.thumb.as_ref(),
            false => Some(&self.db.inputs().machines().ok()?.machine),
        }
    }

    /// Whether the code at this address is Thumb: the nearer of the mapping symbol below it and the body
    /// placing it (`ModeMap::at`), the symbol winning a tie; unplaced, the symbol, the code before it, ARM.
    pub(super) fn thumb_at(&self, vaddr: u64) -> bool {
        use super::requests::Mode;
        let inputs = self.db.inputs();
        let stated = inputs.mapped.range(..=vaddr).next_back();
        match (stated, self.modes.at(vaddr)) {
            (Some((at, thumb)), Some(Mode::Placed(placed))) if *at >= placed.from => *thumb,
            (_, Some(Mode::Placed(placed))) => placed.thumb,
            (Some((_, thumb)), _) => *thumb,
            (None, Some(Mode::After(thumb))) => thumb,
            (None, None) => false,
        }
    }

    pub(super) fn machine_at(&self, vaddr: u64) -> Option<&'a Machine> {
        self.machine_in(self.thumb_at(vaddr))
    }

    /// Everything about the machine the function at `entry` is written for: its decoder, and
    /// the convention its language uses.
    pub(super) fn target_of(
        &self,
        machine: &'a Machine,
        entry: u64,
    ) -> Result<NativeTarget<'a>, crate::native::NativeRefusal> {
        let assembled = self.db.inputs().assembled_at(entry);
        self.target_under(machine, assembled.map_err(NativeRefusal::Unassembled)?)
    }

    /// A decoder under the program's default convention, for a walk that reads no boundary.
    pub(super) fn decoder_of(&self, machine: &'a Machine) -> Result<NativeTarget<'a>, String> {
        let assembled = self.db.inputs().assembled();
        let assembled = assembled.ok_or("the program was not assembled")?;
        self.target_under(machine, assembled)
            .map_err(|why| why.to_string())
    }

    /// What a call does under the program's default convention: a view of its held model.
    pub(super) fn default_call_effect(&self) -> Option<r2ssa::SourceCallEffect> {
        let assembled = self.db.inputs().assembled()?;
        let model = self
            .db
            .get::<super::Convention>(&assembled.convention)
            .ok()?;
        (*model).as_ref().ok()?.call_effect().ok()
    }

    /// The machine under one convention, its model the program's held one.
    fn target_under(
        &self,
        machine: &'a Machine,
        assembled: &'a super::Assembled,
    ) -> Result<NativeTarget<'a>, NativeRefusal> {
        let inputs = self.db.inputs();
        let model = self.db.get::<super::Convention>(&assembled.convention);
        let model = model.map_err(|cycle| NativeRefusal::Prepare(format!("{cycle:?}")))?;
        Ok(NativeTarget {
            arch: machine.tables(),
            disasm: &machine.disasm,
            cpu: machine.cpu,
            convention: (*model).clone()?,
            compiler: &assembled.compiler,
            dwarf: &machine.dwarf,
            imports: &assembled.imports,
            declarations: &inputs.source.container().declarations,
            data_model: assembled.data_model,
        })
    }

    pub(super) fn target(&self, addr: u64) -> Result<NativeTarget<'a>, String> {
        let machine = self.machine_at(addr);
        let machine = machine.ok_or("no Sleigh specification for this architecture")?;
        self.target_of(machine, addr).map_err(|why| why.to_string())
    }

    /// Whether control comes back from a call to `callee`: false only where the program proves it
    /// never does, or a runtime model says so under a premise the engine grants.
    pub(super) fn comes_back(&self, callee: u64) -> bool {
        self.db
            .get::<super::returns::ComesBack>(&callee)
            .map_or(true, |answer| answer.comes())
    }

    /// What a call to `callee` that never comes back takes for granted.
    pub(super) fn exit_premises(
        &self,
        callee: u64,
    ) -> std::collections::BTreeSet<r2source::Premise> {
        self.db
            .get::<super::returns::ComesBack>(&callee)
            .map(|answer| answer.premises().clone())
            .unwrap_or_default()
    }
}

impl<S: Source + 'static> crate::query::Decoders for View<'_, S> {
    fn at(&self, vaddr: u64) -> Option<&Machine> {
        self.machine_at(vaddr)
    }
}

impl<S: Source + 'static> crate::body::Program for View<'_, S> {
    fn loader_writes(&self) -> &[LoaderWrite] {
        &self.source().container().loader_writes
    }

    fn permanence(&self, range: &std::ops::Range<u64>) -> super::Permanence {
        self.source().container().permanence(range)
    }

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

    fn patched(&self, vaddr: u64) -> bool {
        self.source().patched(vaddr)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        self.starts.holds(vaddr)
    }

    fn returns(&self, callee: u64) -> bool {
        self.comes_back(callee)
    }

    fn exit_premises(&self, callee: u64) -> std::collections::BTreeSet<r2source::Premise> {
        View::exit_premises(self, callee)
    }

    /// A call through a slot that is not a kept loader binding is opaque, so it comes back.
    fn returns_through(&self, slot: u64) -> bool {
        crate::stated::sealed_import(self, slot).is_none()
            || super::returns::Walking::new(self.clone(), false)
                .ok()
                .and_then(|walker| crate::discovery::Walker::declared(&walker, slot))
                .is_none_or(|answer| answer.comes())
    }

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        let assembled = self.db.inputs().assembled();
        assembled.and_then(|held| held.link.clone())
    }
}

impl<S: Source + 'static> crate::native::Program for View<'_, S> {
    /// The request's control, which can stop the work but never enters an answer.
    fn control(&self) -> crate::EngineExecutionControl {
        self.db.inputs().control.clone()
    }

    /// A callee resolved against its result's owners; under `aa`, against its arity's too.
    fn read_callee(
        &self,
        address: u64,
        callers: super::World,
        _read: &mut dyn FnMut() -> crate::native::CalleeRead,
    ) -> std::sync::Arc<crate::native::CalleeRead> {
        let thumb = self.thumb_at(address);
        let demand = match callers {
            super::World::Closed => super::resolved::Demand::Arity,
            super::World::Open => super::resolved::Demand::Result,
        };
        let read = self
            .db
            .get::<super::resolved::Resolved>(&((address, thumb), demand));
        let read = read.expect("a callee's read asks for no other root");
        std::sync::Arc::clone(&read.0)
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

    fn holds_code(&self, vaddr: u64) -> bool {
        self.db.inputs().holds_code(vaddr)
    }

    fn places_function(&self, vaddr: u64) -> bool {
        self.db.inputs().places_function(vaddr)
    }

    fn closed_result(
        &self,
        entry: u64,
        open: &r2source::SourceFunctionInterface,
    ) -> Option<r2source::SourceClosedResult> {
        use super::fates::{CallBoundary, CalleeKey, World};
        // A survey that is itself preparing this body is a cycle, which reads as no evidence.
        let key = (CalleeKey::Entry(entry), World::Closed);
        let boundary = self.db.get::<CallBoundary>(&key).ok()?;
        let decided = super::fates::decide(open, (*boundary).as_ref()?);
        r2il::refusal_evidence!(
            "call-boundary",
            "{entry:#x}: closed world decides {decided:?}"
        );
        decided
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

    fn language_at(&self, vaddr: u64) -> r2abi::statement::SourceLanguage {
        self.source().container().languages.at(vaddr)
    }

    fn import_at(&self, vaddr: u64) -> Option<String> {
        self.imports
            .stubs
            .get(&vaddr)
            .map(|stub| &stub.symbol)
            .or_else(|| self.db.inputs().slots.get(&vaddr))
            .cloned()
    }

    fn target_at(&self, vaddr: u64) -> Option<NativeTarget<'_>> {
        self.target(vaddr).ok()
    }
}
