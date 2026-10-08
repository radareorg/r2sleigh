//! A program someone opened, and everything the engine derives from it.
//!
//! Whoever opened the binary hands over its bytes and what its container
//! states, through `Source`. The engine derives the rest -- the names, the
//! import stubs decoded out of their bytes, what is defined at each address --
//! and keeps it current as the bytes move. It never opens anything, so the
//! whole derivation runs just as well over a program built from byte literals.

mod analysis;
pub mod info;
pub mod naming;
mod pointers;
mod requests;
mod resolved;
mod returns;
pub mod source;
mod view;

use view::View;

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
use crate::query::Decoders;
use crate::query::db::{Db, Inputs, Query};

/// Everything a native request needs that is not the decoder itself.
struct Assembled {
    convention: &'static r2abi::CallingConvention,
    /// What the default convention says a call does; both instruction sets share one register file.
    call_effect: Option<r2source::SourceCallEffect>,
    compiler: r2sleigh_lift::profile::LanguageProfile,
    prototypes: r2abi::Prototypes,
    /// The register a call returns through, in the coordinates the lift spells.
    link: Option<r2il::Varnode>,
    /// The register a call writes the instruction set of its target to.
    mode: Option<r2il::Varnode>,
}

/// The decoders for a program's instruction sets and what a native request needs of them.
struct Machines {
    machine: EmbeddedMachine,
    /// The same instruction set with TMode set, where the architecture has
    /// one. Which functions it decodes is what `modes` says.
    thumb: Option<EmbeddedMachine>,
    assembled: Result<Assembled, String>,
}

impl Machines {
    fn load(container: &Container) -> Result<Self, String> {
        let arch = container.arch.name.clone();
        // A PE runs under the Windows toolchain, whose language may differ.
        let machine = match container.format {
            Format::Pe => r2sleigh_lift::embedded_windows_machine(&arch),
            _ => r2sleigh_lift::embedded_machine(&arch),
        }
        .map_err(|error| error.to_string())?;
        // Whether any function is Thumb is discovery's answer, so the
        // decoder is loaded wherever the architecture has one.
        let thumb = r2sleigh_lift::embedded_thumb_machine(&arch)
            .transpose()
            .map_err(|error| error.to_string())?;
        let assembled = assemble(&machine, container);
        Ok(Self {
            machine,
            thumb,
            assembled,
        })
    }
}

/// Assemble what a native request needs of the machine, once per program: constant while it is open.
fn assemble(machine: &EmbeddedMachine, container: &Container) -> Result<Assembled, String> {
    let arch = machine.arch.name.clone();
    let bits = container.arch.bits;
    // The system's ABI says which register it reserves for the thread
    // pointer and which control registers it makes callee-saved. A system
    // fact, so a static ELF that names no C library has it too; which
    // library's declarations apply is `platform`'s question.
    let psabi = kernel(container);
    let convention = r2abi::calling_convention(&arch, bits, psabi)
        .ok_or_else(|| format!("no calling convention for {arch} {bits}"))?;
    // A PE runs under the Windows toolchain's prototypes where the
    // language names one; anything else under the usual toolchain's.
    let specification = match container.format {
        Format::Pe => machine
            .windows_compiler_spec
            .unwrap_or(machine.compiler_spec),
        _ => machine.compiler_spec,
    };
    let compiler = r2sleigh_lift::profile::LanguageProfile::parse(specification)
        .map_err(|error| format!("the compiler specification does not parse: {}", error.0))?;
    let call_effect = crate::native::call_effect(
        &machine.arch,
        bits,
        psabi,
        &compiler,
        convention.variadic_count_register,
    );
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
        });
    // Which C library's own declarations apply is what the container
    // states of it, and nothing else: `_Exit` is each library's, and
    // `__fgets_chk` is two interfaces under one name. The program's own
    // declarations are read by address, beside these, not merged in.
    let prototypes = r2abi::Prototypes::embedded_for(platform(container));
    Ok(Assembled {
        convention,
        call_effect,
        compiler,
        prototypes,
        link,
        mode,
    })
}

/// One open program: its source, its decoders, and the tables read out of both.
pub struct OpenProgram<S: Source + 'static> {
    /// The source and the decoders, and every fact derived from them that has
    /// moved onto queries (doc/adr-query-database.md).
    db: Db<ProgramInputs<S>>,
    /// The control a caller set for the next request, which that request
    /// consumes; without one a request runs under a fresh control.
    next: Option<crate::EngineExecutionControl>,
}

impl<S: Source + 'static> OpenProgram<S> {
    pub fn of(source: S) -> Self {
        let container = source.container();
        let slots = container
            .import_slots()
            .map(|(slot, symbol)| (slot, symbol.to_owned()))
            .collect();
        Self {
            next: None,
            db: Db::new(ProgramInputs {
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
                control: crate::EngineExecutionControl::default(),
                source,
                slots,
                machines: std::cell::OnceCell::new(),
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

    /// Whether the program's machine loads, and why not: loaded on first use, since which instruction set a file is written in no patch changes.
    pub fn loaded(&self) -> Result<(), String> {
        self.db.inputs().machines().map(|_| ())
    }

    /// What this binary calls each address it names.
    pub fn names(&self) -> Rc<NameDb> {
        self.db
            .get::<Names>(&())
            .expect("the names ask only for the imports")
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
        // `entry0` names an entry the container states, never a stub, so no decoder is loaded to start.
        let stated = self.db.get::<StatedNames>(&());
        stated
            .expect("the stated names ask for nothing")
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
        let names = self.names();
        if let Some(addr) = names.address_of(spelling) {
            return Ok(Some(addr));
        }
        // Import stubs are named only where there is a decoder to read them with.
        self.loaded()?;
        let declared = || {
            let entries = &self.source().container().entries;
            entries
                .iter()
                .find(|entry| entry.kind == EntryKind::Main)
                .map(|entry| entry.vaddr)
        };
        Ok(names
            .address_of(spelling)
            .or_else(|| (spelling == "entry0").then(declared).flatten()))
    }

    /// Which stub stands for which import.
    pub fn imports(&self) -> Rc<BTreeMap<u64, naming::Stub>> {
        self.db
            .get::<Imports>(&())
            .expect("the imports ask for nothing")
    }

    /// Whether what a native request needs of the machine was assembled when it loaded.
    fn assembled(&self) -> Result<(), String> {
        let machines = self.db.inputs().machines()?;
        machines
            .assembled
            .as_ref()
            .map(|_| ())
            .map_err(Clone::clone)
    }

    /// Everything about the machine that does not change between functions.
    ///
    /// Assembled once and handed out, so a caller holds one description of the
    /// program rather than building its own from the parts.
    fn target(&self, addr: u64) -> Result<NativeTarget<'_>, String> {
        self.view().target(addr)
    }

    /// The program as a query reads it, over the tables this request holds.
    fn view(&self) -> View<'_, S> {
        View::new(&self.db, true)
    }

    /// Whether control comes back from a call to `callee`: false only where the program proves it never does.
    pub(super) fn comes_back(&self, callee: u64) -> bool {
        self.view().comes_back(callee)
    }
    /// One function's analysis, done once per state of what it read (the `Analysed` query).
    fn analysed(&self, entry: u64) -> Result<std::sync::Arc<Prepared>, NativeRefusal> {
        let key = (entry, self.view().thumb_at(entry));
        let analysis = self.db.get::<analysis::Analysed>(&key);
        analysis.map_or_else(
            |cycle| Err(NativeRefusal::Prepare(format!("{cycle:?}"))),
            |analysis| analysis.0.clone(),
        )
    }

    /// One function's sealed type analysis, by the same key as its analysis.
    fn sealing(&self, entry: u64) -> analysis::Sealing {
        let key = (entry, self.view().thumb_at(entry));
        let sealing = self.db.get::<analysis::Sealed>(&key);
        sealing.map_or(analysis::Sealing::Unanalysed, |sealing| (*sealing).clone())
    }

    /// The control the request in hand runs under, or the last one ran under.
    pub fn control(&self) -> &crate::EngineExecutionControl {
        &self.db.inputs().control
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
        self.db.inputs_mut().control = self.next.take().unwrap_or_default();
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

    /// What the analysis queries have computed and served.
    pub fn analysis_stats(&self) -> crate::query::AnalysisStats {
        crate::query::AnalysisStats {
            analysed: self.db.query_stats::<analysis::Analysed>(),
            sealed: self.db.query_stats::<analysis::Sealed>(),
            callee_reads: self.db.query_stats::<analysis::CalleeReads>(),
            resolved: self.db.query_stats::<resolved::Resolved>(),
            rendered: self.db.query_stats::<analysis::Rendered>(),
        }
    }

    /// The decoder the code at this address is written in: whichever is
    /// nearest below it of a mapping symbol and a function discovery placed,
    /// the container's statement winning a tie.
    fn machine_at(&self, vaddr: u64) -> Option<&EmbeddedMachine> {
        self.view().machine_at(vaddr)
    }

    /// How this program spells a word in memory.
    ///
    /// The container states it, and the decoder does not: ARM BE8 puts
    /// little-endian instructions in a big-endian program, so asking the
    /// Sleigh specification gives the wrong answer on exactly the binaries
    /// that have literal pools.
    pub fn endian(&self) -> r2il::Endianness {
        view::endian(self.source())
    }
}

impl<S: Source + 'static> Decoders for OpenProgram<S> {
    fn at(&self, vaddr: u64) -> Option<&EmbeddedMachine> {
        self.machine_at(vaddr)
    }
}

impl<S: Source + 'static> crate::body::Program for OpenProgram<S> {
    fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
        self.view().read(vaddr, max)
    }

    fn region(&self, vaddr: u64) -> Option<crate::body::Region> {
        self.view().region(vaddr)
    }

    fn is_entry(&self, vaddr: u64) -> bool {
        self.view().is_entry(vaddr)
    }

    fn returns(&self, callee: u64) -> bool {
        self.comes_back(callee)
    }

    fn returns_through(&self, slot: u64) -> bool {
        self.view().returns_through(slot)
    }

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        self.view().return_address_register()
    }

    fn mode_register(&self) -> Option<r2il::Varnode> {
        self.view().mode_register()
    }
}

impl<S: Source + 'static> crate::native::Program for OpenProgram<S> {
    fn control(&self) -> crate::EngineExecutionControl {
        // The token and the meter are shared: the request's own control, not a copy.
        self.db.inputs().control.clone()
    }

    fn name_at(&self, vaddr: u64) -> Option<String> {
        self.view().name_at(vaddr)
    }

    fn holds_static_data(&self, vaddr: u64) -> bool {
        self.view().holds_static_data(vaddr)
    }

    fn loader_writes(&self) -> &[LoaderWrite] {
        &self.source().container().loader_writes
    }

    fn immutable(&self, range: &std::ops::Range<u64>) -> bool {
        self.view().immutable(range)
    }

    fn holds_code(&self, vaddr: u64) -> bool {
        self.view().holds_code(vaddr)
    }

    fn frame_saves(&self, entry: u64) -> Vec<r2source::SourceFrameSave> {
        self.view().frame_saves(entry)
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        &self.db.inputs().extents
    }

    fn import_at(&self, vaddr: u64) -> Option<String> {
        self.view().import_at(vaddr)
    }

    fn target_at(&self, vaddr: u64) -> Option<NativeTarget<'_>> {
        self.target(vaddr).ok()
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
        Format::Pe => Platform::Windows,
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
    /// Whether the code from each ARM mapping symbol on is Thumb, as the
    /// container states it; this can switch inside one function, as a veneer
    /// does.
    mapped: BTreeMap<u64, bool>,
    /// The control of the request in hand: read by a query's work, never a dependency of its answer.
    pub(crate) control: crate::EngineExecutionControl,
    /// Which import each slot the loader fills stands for. A stub's tail
    /// transfer names the slot it reads rather than any code address, so the
    /// slot has to answer for the import too; only a stub is an entry.
    slots: BTreeMap<u64, String>,
    /// The decoders and their assembly, loaded the first time a question needs them; the container decides them, so no write moves them.
    #[cfg_attr(dylint_lib = "r2sleigh_lints", allow(cache_outside_query_database))]
    machines: std::cell::OnceCell<Result<Machines, String>>,
}

impl<S: Source> ProgramInputs<S> {
    fn machines(&self) -> Result<&Machines, String> {
        let loaded = self
            .machines
            .get_or_init(|| Machines::load(self.source.container()));
        loaded.as_ref().map_err(Clone::clone)
    }

    /// What a native request needs of the machine, where it loaded and was assembled.
    fn assembled(&self) -> Option<&Assembled> {
        self.machines().ok()?.assembled.as_ref().ok()
    }
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
        // A stub is named by decoding it, so without a decoder there is none.
        let Ok(machines) = db.inputs().machines() else {
            return BTreeMap::new();
        };
        let machine = &machines.machine;
        naming::imports(&Recorded { db }, &machine.disasm, machine.arch.alignment)
    }
}

/// What the container names: its sections, symbols and entries, read with no decoder.
struct StatedNames;

impl<S: Source + 'static> Query<ProgramInputs<S>> for StatedNames {
    type Key = ();
    type Value = NameDb;
    const NAME: &'static str = "stated-names";

    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        naming::of(&Recorded { db })
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
        let stated = db
            .get::<StatedNames>(&())
            .expect("the stated names ask for nothing");
        let mut names = NameDb::clone(&stated);
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
