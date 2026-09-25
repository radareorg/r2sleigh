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

pub use requests::{AnalysisRefused, FunctionListing, Rendering};

pub use source::{
    Arch, Container, Entry, EntryKind, Format, Mapping, Permissions, Relocation, Section, Segment,
    Source, Symbol, SymbolKind,
};

use std::collections::BTreeMap;

use r2sleigh_lift::EmbeddedMachine;

use crate::names::NameDb;
use crate::native::{NativeRefusal, NativeTarget, Prepared};
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
pub struct OpenProgram<S: Source> {
    source: S,
    /// What this binary calls each address it names.
    names: NameDb,
    /// Which stub stands for which import, by the import's own name.
    imports: BTreeMap<u64, String>,
    /// Which import each slot the loader fills stands for. A stub's tail
    /// transfer names the slot it reads rather than any code address, so the
    /// slot has to answer for the import too; only a stub is an entry.
    slots: BTreeMap<u64, String>,
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
    /// Which revision of the bytes the names and the imports were derived at.
    ///
    /// Both are read out of the bytes, and the imports are *decoded* from
    /// them: the table comes from lifting the stub section. A patch changes
    /// what those say, and `imports` decides `is_entry`, which is what bounds
    /// every body walk -- so a stale table is not a stale listing, it is a
    /// body that ends in the wrong place.
    derived_at: Option<u64>,
    /// How many times the rebuilt name table has actually differed.
    ///
    /// Separate from the byte revision because most patches rename nothing:
    /// anything that depended only on a name stays good across them, and one
    /// counter for both would throw that away.
    names_revision: u64,
    /// The same, for the import stubs, which are the entries a write can move.
    entries_revision: u64,
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
    machine: Option<EmbeddedMachine>,
    /// The same instruction set with TMode set, where the architecture has
    /// one. Which functions it decodes is what `modes` says.
    thumb_machine: Option<EmbeddedMachine>,
    /// Which parameters of each callee take an address, read once per callee and revision.
    pointers: std::sync::Mutex<pointers::Pointers>,
    /// Whether control comes back from each function, derived on first use per state of the bytes.
    returns: std::sync::Mutex<returns::Returns>,
    /// The reference index, and the state of the program it was read at.
    references: Option<(Revision, std::sync::Arc<crate::query::References>)>,
}

impl<S: Source> OpenProgram<S> {
    pub fn of(source: S) -> Self {
        let container = source.container();
        Self {
            // Derived by `ensure_current` alone, which is the first thing
            // every request does.
            names: NameDb::new(),
            imports: BTreeMap::new(),
            slots: container
                .relocations
                .iter()
                .map(|relocation| (relocation.vaddr, relocation.symbol.clone()))
                .collect(),
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
            source,
            // The import table needs a decoder, so nothing here is derived yet.
            derived_at: None,
            names_revision: 0,
            entries_revision: 0,
            assembled: None,
            memo: Memo::default(),
            control: crate::EngineExecutionControl::default(),
            next: None,
            machine: None,
            thumb_machine: None,
            pointers: std::sync::Mutex::default(),
            returns: std::sync::Mutex::default(),
            references: None,
        }
    }

    /// What was opened.
    pub const fn source(&self) -> &S {
        &self.source
    }

    /// What was opened, to be written to. Everything derived from it is
    /// derived again the next time it is asked for.
    pub const fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    /// Make everything derived from the bytes current.
    ///
    /// The machine is loaded once: which instruction set a file is written in
    /// is a property of the file and no patch changes it. The names and the
    /// import stubs are read or decoded out of the bytes, so they are derived
    /// again whenever the source says it is at a different revision.
    pub fn ensure_current(&mut self) -> Result<(), String> {
        if self.machine.is_none() {
            self.machine = Some(
                r2sleigh_lift::embedded_machine(&self.source.container().arch.name)
                    .map_err(|error| error.to_string())?,
            );
            // Whether any function is Thumb is discovery's answer, so the
            // decoder is loaded wherever the architecture has one.
            self.thumb_machine =
                r2sleigh_lift::embedded_thumb_machine(&self.source.container().arch.name)
                    .transpose()
                    .map_err(|error| error.to_string())?;
        }
        let revision = self.source.byte_revision();
        if self.derived_at == Some(revision) {
            return Ok(());
        }
        let machine = self.machine.as_ref().expect("the machine is loaded above");
        let format = self.source.container().format;
        let mut names = naming::of(&self.source);
        naming::name_strings(&mut names, &self.source);
        // The import stubs can only be read once there is a decoder.
        let imports = naming::imports(&self.source, &machine.disasm, machine.arch.alignment);
        naming::name_imports(&mut names, format, &imports);
        naming::name_slots(&mut names, format, &self.slots, &imports);
        // A patch that renamed nothing and moved no stub leaves everything
        // derived from those still good, so the counters move only on a
        // difference rather than on every write; the first derivation is no
        // change, since nothing was derived before it.
        let derived = self.derived_at.is_some();
        self.names_revision += u64::from(derived && names != self.names);
        self.entries_revision += u64::from(derived && imports != self.imports);
        self.names = names;
        self.imports = imports;
        self.derived_at = Some(revision);
        Ok(())
    }

    /// What this binary calls each address it names, as of the last
    /// `ensure_current`.
    pub const fn names(&self) -> &NameDb {
        &self.names
    }

    /// Where a session starts before anything has been sought.
    ///
    /// Wherever the name table puts `entry0`, so `s entry0` and the start agree;
    /// then the declared entry, which `LC_MAIN` names `main` rather than
    /// `entry0`; then any entry; then the first code section, because an
    /// object file declares no entry at all.
    pub fn start(&self) -> Option<u64> {
        let container = self.source.container();
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
                    .find(|section| section.is_code && section.vsize > 0)
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
            let entries = &self.source.container().entries;
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
    pub const fn imports(&self) -> &BTreeMap<u64, String> {
        &self.imports
    }

    /// Make current which instruction set each function is written in, which
    /// every decode reads.
    ///
    /// Discovery answers it for the whole program, so a function reached only
    /// by a call decodes the same whichever command asked first.
    fn ensure_decodable(&mut self) -> Result<(), String> {
        self.ensure_current()?;
        if self.thumb_machine.is_some() && self.modes_at != Some(self.source.byte_revision()) {
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
        let container = self.source.container();
        let bits = container.arch.bits;
        let conventions = r2abi::Conventions::for_arch(key.0.as_str(), bits)
            .ok_or_else(|| format!("no calling conventions for {} {bits}", key.0))?;
        let call_effect = conventions
            .default_convention()
            .and_then(|convention| crate::native::call_effect(&machine.arch, convention));
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
        // The format says which platform's own declarations apply: `_Exit` is
        // declared by the platform, not by the table every target shares.
        let mut prototypes = r2abi::Prototypes::embedded_for(match container.format {
            Format::Elf => r2abi::Platform::Linux,
            Format::MachO => r2abi::Platform::Darwin,
            Format::Other => r2abi::Platform::Unknown,
        });
        // What the binary's own debug information says beats the shared table:
        // the table describes what a library is expected to look like, and
        // this describes what this one is.
        prototypes.declare(container.declared.iter().cloned());
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
            written: &|since, range| self.source.written_since(since, range),
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
        self.memo.stats()
    }

    /// Which state of this program every answer is about.
    pub fn revision(&self) -> Revision {
        Revision {
            program: self.source.identity(),
            bytes: self.source.byte_revision(),
            names: self.names_revision,
            entries: self.entries_revision,
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
            true => self.thumb_machine.as_ref(),
            false => self.machine.as_ref(),
        }
    }

    /// How this program spells a word in memory.
    ///
    /// The container states it, and the decoder does not: ARM BE8 puts
    /// little-endian instructions in a big-endian program, so asking the
    /// Sleigh specification gives the wrong answer on exactly the binaries
    /// that have literal pools.
    pub fn endian(&self) -> r2il::Endianness {
        self.source.container().arch.endian
    }
}

impl<S: Source> Decoders for OpenProgram<S> {
    fn at(&self, vaddr: u64) -> Option<&EmbeddedMachine> {
        self.machine_at(vaddr)
    }
}

impl<S: Source> r2ssa::body::Program for OpenProgram<S> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        self.source.read(vaddr, max)
    }

    /// The segment the container states holds this address. Read from the
    /// container alone, so no write moves it and nothing need record asking.
    fn region(&self, vaddr: u64) -> Option<r2ssa::body::Region> {
        let segment = self.source.container().segment_at(vaddr)?;
        let (start, end) = segment.range();
        Some(r2ssa::body::Region {
            start,
            end,
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

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        self.assembled.as_ref().and_then(|held| held.link.clone())
    }

    fn mode_register(&self) -> Option<r2il::Varnode> {
        self.assembled.as_ref().and_then(|held| held.mode.clone())
    }
}

impl<S: Source> crate::native::Program for OpenProgram<S> {
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
            .or_else(|| self.slots.get(&vaddr).cloned())
    }

    fn holds_static_data(&self, vaddr: u64) -> bool {
        self.static_data.holds(vaddr)
    }

    fn loader_writes(&self, range: &std::ops::Range<u64>) -> bool {
        self.source.container().loader_writes_any(range)
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        &self.extents
    }

    fn import_at(&self, vaddr: u64) -> Option<String> {
        self.imports
            .get(&vaddr)
            .or_else(|| self.slots.get(&vaddr))
            .cloned()
    }

    fn target_at(&self, vaddr: u64) -> Option<NativeTarget<'_>> {
        self.target(vaddr).ok()
    }
}

/// The program as one derivation reads it, logging the bytes it read and each callee's return it was told.
struct Recording<'a, S: Source> {
    program: &'a OpenProgram<S>,
    consulted: std::cell::RefCell<Consulted>,
}

impl<S: Source> r2ssa::body::Program for Recording<'_, S> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        let read = self.program.source.read(vaddr, max)?;
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

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        r2ssa::body::Program::return_address_register(self.program)
    }

    fn mode_register(&self) -> Option<r2il::Varnode> {
        r2ssa::body::Program::mode_register(self.program)
    }
}

impl<S: Source> crate::native::Program for Recording<'_, S> {
    fn control(&self) -> crate::EngineExecutionControl {
        crate::native::Program::control(self.program)
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        self.program.name_at(vaddr)
    }

    fn holds_static_data(&self, vaddr: u64) -> bool {
        self.program.holds_static_data(vaddr)
    }

    fn loader_writes(&self, range: &std::ops::Range<u64>) -> bool {
        self.program.loader_writes(range)
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
}

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
