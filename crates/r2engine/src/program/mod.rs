//! A program someone opened, and everything the engine derives from it.
//!
//! Whoever opened the binary hands over its bytes and what its container
//! states, through `Source`. The engine derives the rest -- the names, the
//! import stubs decoded out of their bytes, what is defined at each address --
//! and keeps it current as the bytes move. It never opens anything, so the
//! whole derivation runs just as well over a program built from byte literals.

pub mod info;
pub mod naming;
mod pointers;
mod requests;
mod returns;
pub mod source;

pub use requests::{
    AnalysisRefused, EdgeKind, FunctionGraph, FunctionListing, GraphBlock, GraphEdge, Rendering,
    Syscall,
};

pub use source::*;

use std::collections::BTreeMap;

use r2sleigh_lift::EmbeddedMachine;

use std::rc::Rc;

use crate::names::NameDb;
use crate::native::{NativeRefusal, NativeTarget, Prepared};
use crate::query::db::{Db, Inputs, Query};
use crate::query::{Consulted, Decoders, Memo, Moved, Revision};

/// Everything a native request needs that is not the decoder itself.
struct Assembled {
    /// Which architecture and compiler specification this was built for, so a
    /// second instruction set in one program gets its own rather than this one.
    machine: (String, &'static str),
    conventions: r2abi::Conventions,
    /// What the default convention says a call does; both instruction sets share one register file.
    call_effect: Option<r2source::SourceCallEffect>,
    compiler: r2abi::CompilerSpec,
    prototypes: r2abi::Prototypes,
    /// The register a call returns through, in the coordinates the lift spells.
    link: Option<r2il::Varnode>,
    /// The register a call writes the instruction set of its target to.
    mode: Option<r2il::Varnode>,
}

/// One open program: its source, its decoders, and the tables read out of both.
pub struct OpenProgram<S: Source + 'static> {
    /// The source and the decoders, and every fact derived from them that has
    /// moved onto queries (doc/adr-query-database.md).
    db: Db<ProgramInputs<S>>,
    /// The name table and the import stubs as of the last `ensure_current`:
    /// the database's answers, held for the request that reads them.
    names: Rc<NameDb>,
    imports: Rc<BTreeMap<u64, naming::Stub>>,
    /// Whether a function begins at each address the binary defines, indexed
    /// once.
    ///
    /// The engine asks this per call target and per branch target of every
    /// body it walks, and answering it by scanning the symbol table made the
    /// walk cost one pass over every symbol per edge. Read from the container
    /// alone, so no write moves it.
    defined: BTreeMap<u64, bool>,
    /// Where the loaded sections lie, indexed once from the container, which no write moves.
    extents: r2types::ProgramExtents,
    /// Where static data can live, by `Section::holds_static_data`, indexed
    /// once the same way: a string is looked for per address a line or a
    /// body names, and scanning every section for each was one pass per
    /// question.
    static_data: r2types::ProgramExtents,
    /// Where the container states instructions lie, indexed once the same
    /// way; `None` where it states no section holds any.
    code: Option<r2types::ProgramExtents>,
    /// Whether each function discovery found is Thumb, by its entry.
    ///
    /// Derived from the whole program, since a function nothing states is in
    /// the instruction set its callers enter it in; only a program with a
    /// second decoder pays for it.
    modes: BTreeMap<u64, bool>,
    /// Whether the code from each ARM mapping symbol on is Thumb, as the
    /// container states it; this can switch inside one function, as a veneer
    /// does.
    mapped: BTreeMap<u64, bool>,
    /// Which revision of the bytes `modes` was discovered at.
    modes_at: Option<u64>,
    /// How many times discovery's entry modes have differed, until the
    /// survey moves onto a query (Q3).
    modes_revision: u64,
    assembled: Option<Assembled>,
    /// What this session has already worked out about one function, and the type analysis sealed from it.
    memo: Memo<Prepared, crate::SealedFunctionAnalysis>,
    /// The control for the request in hand: its cancellation, its deadline and
    /// the work it has spent. Held here so a caller can reach it while the
    /// request runs, which is the whole point of having one.
    control: crate::EngineExecutionControl,
    /// The control a caller set for the next request, which that request
    /// consumes; without one a request runs under a fresh control.
    next: Option<crate::EngineExecutionControl>,
    /// Which parameters of each callee take an address, read once per callee and revision.
    pointers: std::sync::Mutex<pointers::Pointers>,
    /// Whether control comes back from each function, derived on first use per state of the bytes.
    returns: std::sync::Mutex<returns::Returns>,
    /// What each callee's body proves, read once per callee and state of the program.
    callee_reads: crate::query::PerRevision<crate::native::CalleeRead>,
    /// The reference index, and the state of the program it was read at.
    references: Option<(Revision, std::sync::Arc<crate::query::References>)>,
    /// Discovery's walk of the whole program, and the program and state of
    /// its bytes it was walked at.
    survey: Option<((u64, u64), std::sync::Arc<requests::Survey>)>,
}

impl<S: Source + 'static> OpenProgram<S> {
    pub fn of(source: S) -> Self {
        let container = source.container();
        let slots = container
            .import_slots()
            .map(|(slot, symbol)| (slot, symbol.to_owned()))
            .collect();
        Self {
            // Read from the database by `ensure_current` alone, which is the
            // first thing every request does.
            names: Rc::new(NameDb::new()),
            imports: Rc::new(BTreeMap::new()),
            defined: definitions(container),
            extents: r2types::ProgramExtents::new(
                container
                    .sections
                    .iter()
                    .filter(|section| section.loaded)
                    .map(Section::range),
            ),
            static_data: r2types::ProgramExtents::new(
                container
                    .sections
                    .iter()
                    .filter(|section| section.holds_static_data())
                    .map(Section::range),
            ),
            code: {
                let code = container
                    .sections
                    .iter()
                    .filter(|section| section.loaded && section.is_code() && section.vsize > 0)
                    .map(Section::range)
                    .collect::<Vec<_>>();
                (!code.is_empty()).then(|| r2types::ProgramExtents::new(code))
            },
            modes: BTreeMap::new(),
            mapped: container
                .symbols
                .iter()
                .filter(|symbol| symbol.defined)
                .filter_map(|symbol| match symbol.kind {
                    SymbolKind::Mapping(Mapping::Arm) => Some((symbol.vaddr, false)),
                    SymbolKind::Mapping(Mapping::Thumb) => Some((symbol.vaddr, true)),
                    _ => None,
                })
                .collect(),
            modes_at: None,
            modes_revision: 0,
            assembled: None,
            memo: Memo::default(),
            control: crate::EngineExecutionControl::default(),
            next: None,
            pointers: std::sync::Mutex::default(),
            returns: std::sync::Mutex::default(),
            callee_reads: crate::query::PerRevision::default(),
            references: None,
            survey: None,
            db: Db::new(ProgramInputs {
                source,
                slots,
                machine: None,
                thumb_machine: None,
            }),
        }
    }

    /// What was opened.
    pub fn source(&self) -> &S {
        &self.db.inputs().source
    }

    /// What was opened, to be written to. Everything derived from it is
    /// derived again the next time it is asked for.
    pub fn source_mut(&mut self) -> &mut S {
        &mut self.db.inputs_mut().source
    }

    /// Make everything derived from the bytes current.
    ///
    /// The machine is loaded once: which instruction set a file is written in
    /// is a property of the file and no patch changes it. The names and the
    /// import stubs are read or decoded out of the bytes, so they are derived
    /// again whenever the source says it is at a different revision.
    pub fn ensure_current(&mut self) -> Result<(), String> {
        if self.db.inputs().machine.is_none() {
            let arch = self.source().container().arch.name.clone();
            let machine =
                r2sleigh_lift::embedded_machine(&arch).map_err(|error| error.to_string())?;
            // Whether any function is Thumb is discovery's answer, so the
            // decoder is loaded wherever the architecture has one.
            let thumb = r2sleigh_lift::embedded_thumb_machine(&arch)
                .transpose()
                .map_err(|error| error.to_string())?;
            let inputs = self.db.inputs_mut();
            inputs.machine = Some(machine);
            inputs.thumb_machine = thumb;
        }
        self.imports = self
            .db
            .get::<Imports>(&())
            .map_err(|cycle| format!("{cycle:?}"))?;
        self.names = self
            .db
            .get::<Names>(&())
            .map_err(|cycle| format!("{cycle:?}"))?;
        Ok(())
    }

    /// What this binary calls each address it names, as of the last
    /// `ensure_current`.
    pub fn names(&self) -> &NameDb {
        &self.names
    }

    /// Where a session starts before anything has been sought.
    ///
    /// Wherever the name table puts `entry0`, so `s entry0` and the start agree;
    /// then the declared entry, which `LC_MAIN` names `main` rather than
    /// `entry0`; then any entry; then the first code section, because an
    /// object file declares no entry at all.
    pub fn start(&self) -> Option<u64> {
        let container = self.source().container();
        let entries = &container.entries;
        let declared = entries
            .iter()
            .find(|entry| entry.kind == EntryKind::Main)
            .or_else(|| entries.first());
        self.names
            .address_of("entry0")
            .or_else(|| declared.map(|entry| entry.vaddr))
            .or_else(|| {
                container
                    .sections
                    .iter()
                    .find(|section| section.is_code() && section.vsize > 0)
                    .map(|section| section.vaddr)
            })
    }

    /// The address a flag spelling names, with `entry0` always the declared
    /// entry: Mach-O names that address `main`, and radare2 answers both.
    pub fn address_named(&mut self, spelling: &str) -> Result<Option<u64>, String> {
        if let Some(addr) = self.names.address_of(spelling) {
            return Ok(Some(addr));
        }
        // Import stubs are named only once there is a decoder to read them with.
        self.ensure_current()?;
        let declared = || {
            let entries = &self.source().container().entries;
            entries
                .iter()
                .find(|entry| entry.kind == EntryKind::Main)
                .map(|entry| entry.vaddr)
        };
        Ok(self
            .names
            .address_of(spelling)
            .or_else(|| (spelling == "entry0").then(declared).flatten()))
    }

    /// Which stub stands for which import, as of the last `ensure_current`.
    pub fn imports(&self) -> &BTreeMap<u64, naming::Stub> {
        &self.imports
    }

    /// Make current which instruction set each function is written in, which
    /// every decode reads.
    ///
    /// Discovery answers it for the whole program, so a function reached only
    /// by a call decodes the same whichever command asked first.
    fn ensure_decodable(&mut self) -> Result<(), String> {
        self.ensure_current()?;
        if self.db.inputs().thumb_machine.is_some()
            && self.modes_at != Some(self.source().byte_revision())
        {
            self.surveyed()?;
        }
        Ok(())
    }

    /// Assemble what a native request needs, once per program and machine.
    ///
    /// All of it is constant while one program is open, and rebuilding it per
    /// command cost two milliseconds -- almost all of it parsing the embedded
    /// prototype table -- on every `pdd`, `pdil`, `afl` and `ax`.
    fn ensure_assembled(&mut self, addr: u64) -> Result<(), String> {
        let machine = self
            .machine_at(addr)
            .ok_or("no Sleigh specification for this architecture")?;
        let key = (machine.arch.name.clone(), machine.compiler_spec);
        if self
            .assembled
            .as_ref()
            .is_some_and(|held| held.machine == key)
        {
            return Ok(());
        }
        let container = self.source().container();
        let bits = container.arch.bits;
        let conventions = r2abi::Conventions::for_arch(key.0.as_str(), bits)
            .ok_or_else(|| format!("no calling conventions for {} {bits}", key.0))?;
        // The system's ABI says which register it reserves for the thread
        // pointer and which control registers it makes callee-saved. A system
        // fact, so a static ELF that names no C library has it too; which
        // library's declarations apply is `platform`'s question.
        let psabi = kernel(container);
        let call_effect = conventions.default_convention().and_then(|convention| {
            crate::native::call_effect(&machine.arch, bits, psabi, convention)
        });
        let compiler = r2abi::CompilerSpec::parse(machine.compiler_spec);
        // The specification names the register; the architecture says where it
        // lives, and the lift spells writes to it in those coordinates.
        let link = compiler.return_address.as_ref().and_then(|name| {
            machine
                .arch
                .registers
                .iter()
                .find(|register| register.name.eq_ignore_ascii_case(name))
                .map(|register| r2il::Varnode {
                    space: r2il::SpaceId::Register,
                    offset: register.offset,
                    size: register.size,
                    meta: None,
                })
        });
        let mode = machine
            .arch
            .registers
            .iter()
            .find(|register| register.name == "ISAModeSwitch")
            .map(|register| r2il::Varnode {
                space: r2il::SpaceId::Register,
                offset: register.offset,
                size: register.size,
                meta: None,
            });
        // Which C library's own declarations apply is what the container
        // states of it, and nothing else: `_Exit` is each library's, and
        // `__fgets_chk` is two interfaces under one name. The program's own
        // declarations are read by address, beside these, not merged in.
        let prototypes = r2abi::Prototypes::embedded_for(platform(container));
        self.assembled = Some(Assembled {
            machine: key,
            conventions,
            call_effect,
            compiler,
            prototypes,
            link,
            mode,
        });
        Ok(())
    }

    /// Everything about the machine that does not change between functions.
    ///
    /// Assembled once and handed out, so a caller holds one description of the
    /// program rather than building its own from the parts.
    fn target(&self, addr: u64) -> Result<NativeTarget<'_>, String> {
        self.target_of(
            self.machine_at(addr)
                .ok_or("no Sleigh specification for this architecture")?,
        )
    }

    fn target_of<'a>(&'a self, machine: &'a EmbeddedMachine) -> Result<NativeTarget<'a>, String> {
        let assembled = self
            .assembled
            .as_ref()
            .ok_or("the program was not assembled for this address")?;
        Ok(NativeTarget {
            arch: &machine.arch,
            disasm: &machine.disasm,
            cpu: machine.cpu,
            convention: assembled
                .conventions
                .default_convention()
                .ok_or("the convention data names no default")?,
            call_effect: assembled.call_effect.as_ref(),
            compiler: &assembled.compiler,
            prototypes: &assembled.prototypes,
            declarations: &self.source().container().declarations,
        })
    }

    /// One function's analysis, done once per state of this program.
    ///
    /// Every tier is a rendering of this. Asking for the C and then for the
    /// ledger behind it, or for the prepared function and then for its values,
    /// used to walk and prepare the same body twice.
    fn analysed(
        &self,
        target: &NativeTarget<'_>,
        entry: u64,
    ) -> Result<std::sync::Arc<Prepared>, NativeRefusal> {
        let moved = Moved {
            written: &|since, range| self.source().written_since(since, range),
            returns: &|callee| self.comes_back(callee),
        };
        self.memo
            .analysed_since(self.revision(), entry, &moved, || {
                let recording = Recording {
                    program: self,
                    consulted: std::cell::RefCell::default(),
                };
                let analysis = crate::native::analysed(target, &recording, entry);
                analysis.map(|analysis| (analysis, recording.consulted.into_inner()))
            })
    }

    /// The control the request in hand runs under, or the last one ran under.
    pub fn control(&self) -> &crate::EngineExecutionControl {
        &self.control
    }

    /// Set the control the next request runs under; that request consumes it.
    ///
    /// A deadline, a cancellation and the work spent belong to one request,
    /// so carrying one request's control into the next would let a stop meant
    /// for one question refuse the next and add its work to the next one's.
    pub fn begin_request(&mut self, control: crate::EngineExecutionControl) {
        self.next = Some(control);
    }

    /// Start a request under the control a caller set, or a fresh one.
    fn start_request(&mut self) {
        self.control = self.next.take().unwrap_or_default();
    }

    /// The register a storage names, as this machine spells it.
    ///
    /// The shell prints what the engine proved about a value, and a value is
    /// about a storage; naming it needs the register table, which belongs to
    /// the machine and therefore here.
    pub fn spell_storage(&self, addr: u64, storage: r2ssa::CanonicalStorageId) -> Option<String> {
        let machine = self.machine_at(addr)?;
        machine
            .arch
            .registers
            .iter()
            .find(|register| {
                register.offset == storage.offset
                    && register.size == storage.size
                    && storage.space == r2ssa::CanonicalStorageSpace::Register
            })
            .map(|register| register.name.to_lowercase())
    }

    /// What the memo has been asked and what it holds.
    pub fn memo_stats(&self) -> crate::query::MemoStats {
        let (callee_hits, callees_read) = self.callee_reads.counts();
        crate::query::MemoStats {
            callee_hits,
            callees_read,
            ..self.memo.stats()
        }
    }

    /// Which state of this program every answer is about.
    pub fn revision(&self) -> Revision {
        Revision {
            program: self.source().identity(),
            bytes: self.source().byte_revision(),
            // When the table last differed, which most patches leave alone:
            // anything that read only a name stays good across them.
            names: self.db.changed_at::<Names>(&()).unwrap_or(0),
            // The entries a write can move: the import stubs, and the modes.
            entries: self.db.changed_at::<Imports>(&()).unwrap_or(0) + self.modes_revision,
        }
    }

    /// The decoder the code at this address is written in: whichever is
    /// nearest below it of a mapping symbol and a function discovery placed,
    /// the container's statement winning a tie.
    fn machine_at(&self, vaddr: u64) -> Option<&EmbeddedMachine> {
        self.machine_in(self.thumb_at(vaddr))
    }

    /// Whether the code at this address is Thumb, as `machine_at` decides it.
    fn thumb_at(&self, vaddr: u64) -> bool {
        let stated = self.mapped.range(..=vaddr).next_back();
        let derived = self.modes.range(..=vaddr).next_back();
        match (stated, derived) {
            (Some((at, thumb)), Some((from, _))) if at >= from => *thumb,
            (_, Some((_, thumb))) | (Some((_, thumb)), None) => *thumb,
            (None, None) => false,
        }
    }

    /// The decoder for one instruction set.
    fn machine_in(&self, thumb: bool) -> Option<&EmbeddedMachine> {
        match thumb {
            true => self.db.inputs().thumb_machine.as_ref(),
            false => self.db.inputs().machine.as_ref(),
        }
    }

    /// How this program spells a word in memory.
    ///
    /// The container states it, and the decoder does not: ARM BE8 puts
    /// little-endian instructions in a big-endian program, so asking the
    /// Sleigh specification gives the wrong answer on exactly the binaries
    /// that have literal pools.
    pub fn endian(&self) -> r2il::Endianness {
        match self.source().container().arch.endian {
            Endian::Little => r2il::Endianness::Little,
            Endian::Big => r2il::Endianness::Big,
        }
    }
}

impl<S: Source + 'static> Decoders for OpenProgram<S> {
    fn at(&self, vaddr: u64) -> Option<&EmbeddedMachine> {
        self.machine_at(vaddr)
    }
}

impl<S: Source + 'static> r2ssa::body::Program for OpenProgram<S> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        self.source().read(vaddr, max)
    }

    /// The segment the container states holds this address. Read from the
    /// container alone, so no write moves it and nothing need record asking.
    fn region(&self, vaddr: u64) -> Option<r2ssa::body::Region> {
        let segment = self.source().container().segment_at(vaddr)?;
        let (start, end) = segment.range();
        Some(r2ssa::body::Region {
            start,
            end,
            file_end: segment.file_end(),
            execute: segment.permissions.execute,
            write: segment.permissions.write,
        })
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        // A stub is a function of the program's as much as a body is: control
        // that reaches one has left the function it came from.
        self.imports.contains_key(&vaddr)
            || self.defined.get(&vaddr).is_some_and(|function| *function)
    }

    fn returns(&self, callee: u64) -> bool {
        self.comes_back(callee)
    }

    fn returns_through(&self, slot: u64) -> bool {
        self.returns_through_slot(slot)
    }

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        self.assembled.as_ref().and_then(|held| held.link.clone())
    }

    fn mode_register(&self) -> Option<r2il::Varnode> {
        self.assembled.as_ref().and_then(|held| held.mode.clone())
    }
}

impl<S: Source + 'static> crate::native::Program for OpenProgram<S> {
    fn control(&self) -> crate::EngineExecutionControl {
        // The token and the meter are shared, so this is the request's own
        // control rather than a copy that nothing could stop.
        self.control.clone()
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        // The plain name, with no namespace on it: this keys the prototype
        // table and spells a call, where a listing asks the same entry for
        // `sym.imp.printf`. A slot the loader fills is not in the table --
        // only a stub is an address the program transfers to -- so it is
        // asked for separately.
        self.names
            .text_at(vaddr)
            .map(str::to_owned)
            .or_else(|| self.db.inputs().slots.get(&vaddr).cloned())
    }

    fn holds_static_data(&self, vaddr: u64) -> bool {
        self.static_data.holds(vaddr)
    }

    fn loader_writes(&self) -> &[LoaderWrite] {
        &self.source().container().loader_writes
    }

    fn immutable(&self, range: &std::ops::Range<u64>) -> bool {
        self.source().container().immutable(range)
    }

    fn holds_code(&self, vaddr: u64) -> bool {
        match &self.code {
            Some(code) => code.holds(vaddr),
            None => r2ssa::body::Program::region(self, vaddr).is_some_and(|region| region.execute),
        }
    }

    fn frame_saves(&self, entry: u64) -> Vec<r2source::SourceFrameSave> {
        self.source()
            .container()
            .unwind
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
        &self.extents
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

/// The program as one derivation reads it, logging the bytes it read and each callee's return it was told.
struct Recording<'a, S: Source + 'static> {
    program: &'a OpenProgram<S>,
    consulted: std::cell::RefCell<Consulted>,
}

impl<S: Source + 'static> r2ssa::body::Program for Recording<'_, S> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let read = self.program.source().read(vaddr, max)?;
        // Only what is mapped: no write can land in the unmapped rest.
        self.consulted
            .borrow_mut()
            .read
            .push(vaddr..vaddr.saturating_add(read.len() as u64));
        Some(read)
    }

    fn region(&self, vaddr: u64) -> Option<r2ssa::body::Region> {
        r2ssa::body::Program::region(self.program, vaddr)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        r2ssa::body::Program::is_entry(self.program, vaddr)
    }

    fn returns(&self, callee: u64) -> bool {
        let answer = self.program.comes_back(callee);
        self.consulted.borrow_mut().returns.push((callee, answer));
        answer
    }

    // What a slot holds is the container's statement, fixed for the revision
    // the derivation is keyed by, so it is not a consulted answer.
    fn returns_through(&self, slot: u64) -> bool {
        self.program.returns_through_slot(slot)
    }

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        r2ssa::body::Program::return_address_register(self.program)
    }

    fn mode_register(&self) -> Option<r2il::Varnode> {
        r2ssa::body::Program::mode_register(self.program)
    }
}

impl<S: Source + 'static> crate::native::Program for Recording<'_, S> {
    fn control(&self) -> crate::EngineExecutionControl {
        crate::native::Program::control(self.program)
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        self.program.name_at(vaddr)
    }

    fn holds_static_data(&self, vaddr: u64) -> bool {
        self.program.holds_static_data(vaddr)
    }

    fn loader_writes(&self) -> &[LoaderWrite] {
        crate::native::Program::loader_writes(self.program)
    }

    fn immutable(&self, range: &std::ops::Range<u64>) -> bool {
        crate::native::Program::immutable(self.program, range)
    }

    fn holds_code(&self, vaddr: u64) -> bool {
        crate::native::Program::holds_code(self.program, vaddr)
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        self.program.extents()
    }

    fn import_at(&self, vaddr: u64) -> Option<String> {
        self.program.import_at(vaddr)
    }

    fn target_at(&self, vaddr: u64) -> Option<NativeTarget<'_>> {
        self.program.target_at(vaddr)
    }

    fn frame_saves(&self, entry: u64) -> Vec<r2source::SourceFrameSave> {
        crate::native::Program::frame_saves(self.program, entry)
    }

    /// Held per state of the program, with what deriving it read: a root that
    /// reads a held callee consulted those bytes and returns as surely as the
    /// root that derived it did, and its own memo has to know.
    fn read_callee(
        &self,
        address: u64,
        read: &mut dyn FnMut() -> crate::native::CalleeRead,
    ) -> std::sync::Arc<crate::native::CalleeRead> {
        let revision = self.program.revision();
        let cache = &self.program.callee_reads;
        if let Some((answer, consulted)) = cache.get(revision, address) {
            let mut own = self.consulted.borrow_mut();
            own.read.extend(consulted.read);
            own.returns.extend(consulted.returns);
            return answer;
        }
        let (reads, returns) = {
            let own = self.consulted.borrow();
            (own.read.len(), own.returns.len())
        };
        let answer = std::sync::Arc::new(read());
        cache.derived();
        if answer.facts.is_ok() {
            let own = self.consulted.borrow();
            let consulted = Consulted {
                read: own.read[reads..].to_vec(),
                returns: own.returns[returns..].to_vec(),
            };
            cache.hold(revision, address, std::sync::Arc::clone(&answer), consulted);
        }
        answer
    }
}

/// Which platform's declarations a program's calls are read against, as its container states it.
///
/// Mach-O is Apple's format, so it is Darwin's libSystem. An ELF is the
/// platform of the one C library its evidence names -- the dynamic linker
/// `PT_INTERP` asks for, the notes that library's start files leave -- and
/// runs on Linux as far as `EI_OSABI` says. Anything else is `Unknown`, which
/// reads only the declarations every library shares: no evidence, evidence
/// naming two libraries, an OS ABI that is not Linux's, and musl, which
/// declares nothing r2abi keeps a table for. A call then has no prototype,
/// which is visible, rather than another library's, which is wrong.
fn platform(container: &Container) -> r2abi::Platform {
    use r2abi::Platform;
    match container.format {
        Format::MachO => return Platform::Darwin,
        Format::Elf => {}
        _ => return Platform::Unknown,
    }
    let mut named = std::collections::BTreeSet::new();
    for evidence in &container.platform {
        match *evidence {
            PlatformEvidence::Interpreter(libc) | PlatformEvidence::Note(libc) => {
                named.insert(libc);
            }
            // GNU/Linux; zero, which states nothing, is never stated.
            PlatformEvidence::OsAbi(ELFOSABI_GNU) => {}
            PlatformEvidence::OsAbi(_) => return Platform::Unknown,
        }
    }
    let mut named = named.into_iter();
    match (named.next(), named.next()) {
        (Some(Libc::Glibc), None) => Platform::Linux,
        (Some(Libc::Bionic), None) => Platform::Android,
        _ => Platform::Unknown,
    }
}

/// Which kernel a program's system calls go to, as its container states it.
///
/// A kernel question, not a C library one: a static ELF names no library and
/// still traps into Linux. Mach-O runs on Darwin's. An ELF runs on Linux
/// unless its `EI_OSABI` names another system; one that states nothing is
/// Linux's convention, which is what every Linux toolchain writes.
pub(super) fn kernel(container: &Container) -> r2abi::Platform {
    use r2abi::Platform;
    match container.format {
        Format::MachO => Platform::Darwin,
        Format::Elf => {
            let other = container.platform.iter().any(
                |evidence| matches!(evidence, PlatformEvidence::OsAbi(abi) if *abi != ELFOSABI_GNU),
            );
            match other {
                true => Platform::Unknown,
                false => Platform::Linux,
            }
        }
        _ => Platform::Unknown,
    }
}

/// `EI_OSABI` for GNU/Linux, which glibc and bionic both run on.
const ELFOSABI_GNU: u8 = 3;

/// Whether a function begins at each address the binary defines.
///
/// Names live in the name table; this answers the question a walk asks of an
/// address and a name cannot. The first symbol at an address wins, so the
/// index answers the same way twice over.
fn definitions(container: &Container) -> BTreeMap<u64, bool> {
    let mut defined = BTreeMap::new();
    // The format's own entry first: a stripped binary has no symbol there.
    for entry in &container.entries {
        defined.entry(entry.vaddr).or_insert(true);
    }
    for symbol in &container.symbols {
        if !symbol.defined || symbol.name.is_empty() {
            continue;
        }
        defined
            .entry(symbol.vaddr)
            .or_insert(symbol.kind == SymbolKind::Function);
    }
    defined
}

/// What the query database reads: the source, and what no write moves -- the
/// decoders and the slots the container states the loader fills.
pub(crate) struct ProgramInputs<S> {
    pub(crate) source: S,
    /// Which import each slot the loader fills stands for. A stub's tail
    /// transfer names the slot it reads rather than any code address, so the
    /// slot has to answer for the import too; only a stub is an entry.
    slots: BTreeMap<u64, String>,
    machine: Option<EmbeddedMachine>,
    /// The same instruction set with TMode set, where the architecture has
    /// one. Which functions it decodes is what `modes` says.
    thumb_machine: Option<EmbeddedMachine>,
}

impl<S: Source + 'static> Inputs for ProgramInputs<S> {
    fn byte_revision(&self) -> u64 {
        self.source.byte_revision()
    }

    fn written_since(&self, revision: u64, range: &std::ops::Range<u64>) -> bool {
        self.source.written_since(revision, range)
    }
}

/// The source as a query reads it: every byte read is recorded against the
/// query running, so no query can read the program without depending on it.
struct Recorded<'a, S: Source + 'static> {
    db: &'a Db<ProgramInputs<S>>,
}

impl<S: Source + 'static> Source for Recorded<'_, S> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let read = self.db.inputs().source.read(vaddr, max)?;
        // Only what is mapped: no write can land in the unmapped rest.
        self.db
            .reads(vaddr..vaddr.saturating_add(read.len() as u64));
        Some(read)
    }

    fn container(&self) -> &Container {
        self.db.inputs().source.container()
    }

    fn identity(&self) -> u64 {
        self.db.inputs().source.identity()
    }

    fn byte_revision(&self) -> u64 {
        self.db.inputs().source.byte_revision()
    }

    fn written_since(&self, revision: u64, range: &std::ops::Range<u64>) -> bool {
        self.db.inputs().source.written_since(revision, range)
    }
}

/// Which stub stands for which import, by the import's own name, and how
/// large each is: stated by a Mach-O stub section, and decoded out of the
/// bytes elsewhere. `is_entry` reads it, which is what bounds every body
/// walk, so a stale table would be a body that ends in the wrong place.
struct Imports;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Imports {
    type Key = ();
    type Value = BTreeMap<u64, naming::Stub>;
    const NAME: &'static str = "imports";

    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        let machine = db
            .inputs()
            .machine
            .as_ref()
            .expect("the decoder is loaded before anything is asked");
        naming::imports(&Recorded { db }, &machine.disasm, machine.arch.alignment)
    }
}

/// What this binary calls each address it names.
struct Names;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Names {
    type Key = ();
    type Value = NameDb;
    const NAME: &'static str = "names";

    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        let source = Recorded { db };
        let imports = db.get::<Imports>(&()).expect("the imports ask for nothing");
        let mut names = naming::of(&source);
        naming::name_strings(&mut names, &source);
        naming::name_imports(&mut names, &imports);
        naming::name_slots(
            &mut names,
            &db.inputs().slots,
            &imports,
            &source.container().loader_writes,
        );
        names
    }
}
