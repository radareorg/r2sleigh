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
    /// Whether the body walked through this view is Thumb, where the query's key states it.
    walking: Option<bool>,
}

impl<S: Source + 'static> Clone for View<'_, S> {
    fn clone(&self) -> Self {
        Self {
            db: self.db,
            names: Rc::clone(&self.names),
            imports: Rc::clone(&self.imports),
            starts: Rc::clone(&self.starts),
            modes: Rc::clone(&self.modes),
            walking: self.walking,
        }
    }
}

impl<'a, S: Source + 'static> View<'a, S> {
    /// What the row of the import sealed at `slot` states through `pick`, and the convention it
    /// is called under; `None` where no row binds it or the row states nothing there.
    fn import_through<T>(
        &self,
        slot: u64,
        pick: impl Fn(&r2abi::LibraryRow) -> Option<T>,
    ) -> Option<(T, std::sync::Arc<r2source::ConventionModel>)> {
        let name = crate::stated::sealed_import(self, slot)?;
        let walker = super::returns::Walking::new(self.clone(), false).ok()?;
        let target = walker.target(false);
        let picked = target.imports.bind(name).ok().and_then(pick)?;
        Some((picked, std::sync::Arc::clone(&target.convention)))
    }

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
            walking: None,
        }
    }

    /// The same view walking one body in the set its key states, so a callee's set is the
    /// transfer's and no mode is read.
    pub(super) fn walking(self, thumb: bool) -> Self {
        Self {
            walking: Some(thumb),
            ..self
        }
    }

    /// The set a call enters `callee` in: the walk's unless the transfer states the other one.
    fn entered(&self, callee: u64, foreign: bool) -> bool {
        match self.walking {
            _ if self.machine_in(true).is_none() => false,
            Some(thumb) => thumb != foreign,
            None => self.thumb_at(callee),
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
        let inputs = self.db.inputs();
        let ruled = self
            .convention_at(entry)
            .map_err(NativeRefusal::Unassembled)?;
        let assembled = inputs.assembled_of(ruled.id);
        let mut target =
            self.target_under(machine, assembled.map_err(NativeRefusal::Unassembled)?)?;
        // A function under another convention than the program's places its imports under the program's.
        if let Some(program) = inputs.assembled().filter(|it| it.convention != ruled.id) {
            target.program = Some(self.convention_of(program)?);
        }
        Ok(target)
    }

    /// The convention the function at `entry` runs under: its held `CalleeConvention`.
    pub(super) fn convention_at(
        &self,
        entry: u64,
    ) -> Result<super::Ruled, crate::native::Unassembled> {
        let ruled = self.db.get::<super::CalleeConvention>(&entry);
        (*ruled.expect("the convention asks for nothing")).clone()
    }

    /// A decoder under the program's default convention, for a walk that reads no boundary.
    pub(super) fn decoder_of(&self, machine: &'a Machine) -> Result<NativeTarget<'a>, String> {
        let assembled = self.db.inputs().assembled();
        let assembled = assembled.ok_or("the program was not assembled")?;
        self.target_under(machine, assembled)
            .map_err(|why| why.to_string())
    }

    /// One convention's held model and the specification it reads.
    fn convention_of(
        &self,
        assembled: &'a super::Assembled,
    ) -> Result<crate::native::Assembly<'a>, NativeRefusal> {
        let model = self.db.get::<super::Convention>(&assembled.convention);
        let model = model.map_err(|cycle| NativeRefusal::Prepare(format!("{cycle:?}")))?;
        Ok(crate::native::Assembly {
            convention: (*model).clone()?,
            compiler: &assembled.compiler,
        })
    }

    /// What a call runs under from the program's default convention: its held `AnyCall` model.
    pub(super) fn default_calls(&self) -> Option<std::sync::Arc<r2ssa::ConventionModel>> {
        let assembled = self.db.inputs().assembled()?;
        let model = self.db.get::<super::AnyCall>(&assembled.convention).ok()?;
        (*model).as_ref().ok().cloned()
    }

    /// The machine under one convention, its model the program's held one.
    fn target_under(
        &self,
        machine: &'a Machine,
        assembled: &'a super::Assembled,
    ) -> Result<NativeTarget<'a>, NativeRefusal> {
        let inputs = self.db.inputs();
        let machines = inputs.machines().map_err(NativeRefusal::Unassembled)?;
        let assembly = self.convention_of(assembled)?;
        let call = self.db.get::<super::AnyCall>(&assembled.convention);
        let call = call.map_err(|cycle| NativeRefusal::Prepare(format!("{cycle:?}")))?;
        Ok(NativeTarget {
            arch: machine.tables(),
            disasm: &machine.disasm,
            cpu: machine.cpu,
            convention: assembly.convention,
            call: (*call).clone()?,
            compiler: assembly.compiler,
            program: None,
            dwarf: &machine.dwarf,
            imports: &machines.imports,
            declarations: &inputs.source.container().declarations,
            data_model: machines.data_model,
        })
    }

    pub(super) fn target(&self, addr: u64) -> Result<NativeTarget<'a>, String> {
        let machine = self.machine_at(addr);
        let machine = machine.ok_or("no Sleigh specification for this architecture")?;
        self.target_of(machine, addr).map_err(|why| why.to_string())
    }

    /// `ComesBack`'s key: a callee and whether it is entered in Thumb, which only a machine with
    /// both sets can be.
    pub(super) fn returns_key(&self, callee: u64, thumb: bool) -> (u64, bool) {
        (callee, thumb && self.machine_in(true).is_some())
    }

    /// Whether a call to `callee`, Thumb where `thumb`, comes back: false only where the program
    /// proves it never does, or a runtime model says so under a premise the engine grants.
    pub(super) fn comes_back(&self, callee: u64, thumb: bool) -> bool {
        self.db
            .get::<super::returns::ComesBack>(&self.returns_key(callee, thumb))
            .map_or(true, |answer| answer.comes())
    }

    /// Why a call to `callee` never comes back, where `ComesBack` says it does not.
    pub(super) fn exit(&self, callee: u64, thumb: bool) -> Option<crate::discovery::Never> {
        let key = self.returns_key(callee, thumb);
        match &*self.db.get::<super::returns::ComesBack>(&key).ok()? {
            crate::discovery::Return::Never(never) => Some(never.clone()),
            crate::discovery::Return::Comes => None,
        }
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

    fn returns(&self, callee: u64, foreign: bool) -> bool {
        self.comes_back(callee, self.entered(callee, foreign))
    }

    fn exit(&self, callee: u64, foreign: bool) -> Option<crate::discovery::Never> {
        View::exit(self, callee, self.entered(callee, foreign))
    }

    /// A call through a slot that is not a kept loader binding is opaque, so it comes back.
    fn exit_through(&self, slot: u64) -> Option<crate::discovery::Never> {
        crate::stated::sealed_import(self, slot)?;
        let walker = super::returns::Walking::new(self.clone(), false).ok()?;
        match crate::discovery::Walker::declared(&walker, slot)? {
            crate::discovery::Return::Never(never) => Some(never),
            crate::discovery::Return::Comes => None,
        }
    }

    fn halts_on_through(&self, slot: u64) -> Option<crate::body::Halting> {
        let cited = |row: &r2abi::LibraryRow| Some((row.halts_on?, r2source::Citation::of(row)?));
        let (((index, halt), citation), model) = self.import_through(slot, cited)?;
        let register = model.argument(r2abi::SlotClass::Integer, index.into());
        register.map(|register| (register, halt, citation))
    }

    fn halts_on(&self, callee: u64) -> Option<crate::body::Halting> {
        let halting = self.db.get::<super::HaltingStubs>(&()).ok()?;
        halting.get(&callee).copied()
    }

    fn holds_values(&self) -> bool {
        let halting = self.db.get::<super::HaltingStubs>(&()).ok();
        self.binds_handles() || halting.is_some_and(|halting| !halting.is_empty())
    }

    fn binds_handles(&self) -> bool {
        self.source().container().format == r2abi::statement::Format::Pe
    }

    fn interrupt_halts(&self, arch: &str, vector: u64) -> Option<r2source::Citation> {
        r2source::Citation::interrupt(super::kernel(self.source().container()), arch, vector)
    }

    fn yields_through(&self, slot: u64) -> Option<(r2source::CanonicalStorageId, r2abi::Handle)> {
        let (handle, model) = self.import_through(slot, |row| row.yields)?;
        let register = model.result_registers(r2abi::SlotClass::Integer).next();
        register.map(|register| (register, handle))
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

    fn note_rebuilt(&self) {
        self.db.note_rebuilt();
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

    fn callee_statement(
        &self,
        address: u64,
        _read: &mut dyn FnMut() -> crate::native::CalleeRead,
    ) -> std::sync::Arc<crate::native::CalleeRead> {
        let key = (address, self.thumb_at(address));
        let read = self.db.get::<super::analysis::CalleeReads>(&key);
        std::sync::Arc::clone(&read.expect("a statement asks for no other root").0)
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

    /// The result `CallBoundary` decided for the function at `entry` from its open read's supply
    /// (doc/adr-result-side.md, section 3; D317).
    fn closed_result(&self, entry: u64) -> Option<r2source::SourceClosedDecision> {
        use super::fates::{CallBoundary, CalleeKey, World};
        let key = (CalleeKey::Entry(entry), World::Closed);
        let boundary = self.db.get::<CallBoundary>(&key).ok()?;
        match boundary.as_ref() {
            Some(CallBoundary::Sites { result, .. }) => result.decision(),
            _ => None,
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

    fn kept_at(&self, entry: u64) -> Option<std::collections::BTreeSet<r2ssa::CanonicalStorageId>> {
        let key = (entry, self.thumb_at(entry));
        let kept = self.db.get::<super::fates::KeptAcross>(&key).ok()?;
        (*kept).as_ref().map(|kept| kept.kept_registers().collect())
    }

    fn site_convention_at(&self, callee: u64) -> Option<std::sync::Arc<r2ssa::ConventionModel>> {
        let inputs = self.db.inputs();
        let id = match self.import_at(callee) {
            Some(name) => {
                let machines = inputs.machines().ok()?;
                machines.imports.bound(&name).then_some(())?;
                inputs.assembled()?.convention
            }
            // A body takes its own model where it is stated; one under a refused row runs under the join.
            None => {
                (self.convention_at(callee).ok())
                    .filter(|ruled| ruled.stated)?
                    .id
            }
        };
        let model = self.db.get::<super::Convention>(&id).ok()?;
        (*model)
            .as_ref()
            .ok()
            .filter(|model| model.refused.is_none())
            .cloned()
    }
}
