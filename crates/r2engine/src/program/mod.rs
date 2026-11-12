//! A program someone opened, and everything the engine derives from it.
//!
//! Whoever opened the binary hands over its bytes and what its container
//! states, through `Source`. The engine derives the rest -- the names, the
//! import stubs decoded out of their bytes, what is defined at each address --
//! and keeps it current as the bytes move. It never opens anything, so the
//! whole derivation runs just as well over a program built from byte literals.

mod analysis;
mod fates;
pub mod info;
pub mod naming;
mod pointers;
mod reads;
mod requests;
mod resolved;
mod returns;
pub mod source;
mod starts;
mod view;

use view::View;

pub use fates::World;
pub use requests::{
    AnalysisRefused, EdgeKind, FunctionGraph, FunctionListing, GraphBlock, GraphEdge,
    RenderedResponse, Rendering, Syscall,
};

pub use source::*;

use std::collections::BTreeMap;

use crate::machine::Machine;

use std::rc::Rc;

use crate::names::NameDb;
use crate::native::{NativeRefusal, NativeTarget, Prepared, Unassembled};
use crate::query::Decoders;
use crate::query::db::{Db, Inputs, Query, Retention};

/// Everything a native request needs under one convention that is not the decoder itself.
pub(super) struct Assembled {
    convention: r2abi::ConventionId,
    /// The specification the convention reads, under its prototype.
    compiler: r2sleigh_lift::profile::LanguageProfile,
    /// The register a call returns through, in the coordinates the lift spells.
    link: Option<r2il::Varnode>,
}

/// The convention chosen for one function, and the program's own where a declaration chose
/// another (doc/adr-call-boundary.md, "S20 as built").
pub(super) struct Chosen<'a> {
    pub(super) assembled: &'a Assembled,
    pub(super) program: Option<&'a Assembled>,
}

/// The decoders for a program's instruction sets and what a native request needs of them.
struct Machines {
    machine: Machine,
    /// The same instruction set with TMode set, where the architecture has
    /// one. Which functions it decodes is what `modes` says.
    thumb: Option<Machine>,
    assembled: Result<Assembled, Unassembled>,
    /// What a Go function needs, where the container states any: Go's convention by its
    /// toolchain's version (doc/adr-language-profile.md, LP1).
    go: Option<Result<Assembled, Unassembled>>,
    /// ABI0, where the toolchain's own convention is ABIInternal: its assembly functions keep it.
    go_abi0: Option<Result<Assembled, Unassembled>>,
    /// ABIInternal refusing, for a function under it whose ABI pclntab does not state.
    go_unstated: Option<Result<Assembled, Unassembled>>,
    /// Each other convention a function's debug information states (`ms_abi`, `sysv_abi`).
    stated: BTreeMap<r2abi::ConventionId, Result<Assembled, Unassembled>>,
    /// The rows the program's C library states, and how each import binds one: read once.
    imports: crate::imports::Imports,
    /// The C data model of the architecture under that C library.
    data_model: Option<&'static r2abi::CDataModel>,
}

/// The byte orders the container states, which select the machine's language.
fn byte_order(arch: &Arch) -> r2sleigh_lift::ByteOrder {
    r2sleigh_lift::ByteOrder {
        data: view::endianness(arch.endian),
        instructions: arch.instructions.map(view::endianness),
    }
}

impl Machines {
    fn load(container: &Container) -> Result<Self, Unassembled> {
        let arch = container.arch.name.clone();
        let order = byte_order(&container.arch);
        // A PE runs under the Windows toolchain, whose language may differ.
        let windows = container.format == Format::Pe;
        let machine = r2sleigh_lift::embedded_program_machine(&arch, order, windows)
            .map(Machine::new)
            .map_err(|error| Unassembled::NoSpecification(error.to_string()))?;
        // Whether any function is Thumb is discovery's answer, so the
        // decoder is loaded wherever the architecture has one.
        let thumb = r2sleigh_lift::embedded_thumb_machine(&arch, order)
            .map(|machine| machine.map(Machine::new))
            .transpose()
            .map_err(|error| Unassembled::NoSpecification(error.to_string()))?;
        let psabi = kernel(container);
        let bits = container.arch.bits;
        let unstated = |go| Unassembled::NoConvention {
            architecture: arch.clone(),
            bits,
            go,
        };
        let assembled = r2abi::ConventionId::default_for(&arch, bits, psabi)
            .ok_or_else(|| unstated(false))
            .and_then(|id| assemble(&machine, container, id));
        let languages = &container.languages;
        let written_in_go = languages.program == SourceLanguage::Go
            || languages
                .ranges
                .iter()
                .any(|(_, language)| *language == SourceLanguage::Go);
        let convention = written_in_go
            .then(|| r2abi::ConventionId::go(&arch, bits, psabi, languages.go_version));
        let abi0 = r2abi::ConventionId::go_abi0(&arch, bits);
        let go = convention.map(|convention| {
            convention
                .ok_or_else(|| unstated(true))
                .and_then(|id| assemble(&machine, container, id))
        });
        let go_abi0 = convention
            .flatten()
            .zip(abi0)
            .filter(|(convention, abi0)| convention != abi0)
            .map(|(_, abi0)| assemble(&machine, container, abi0));
        let go_unstated = (go_abi0.is_some() && languages.go_assembly.is_none())
            .then(|| r2abi::ConventionId::go_unstated(&arch, bits))
            .flatten()
            .map(|id| assemble(&machine, container, id));
        // One pass over the declarations: O(functions).
        let default = assembled.as_ref().ok().map(|it| it.convention);
        let mut stated = BTreeMap::new();
        for (_, prototype) in container.declarations.functions() {
            if let Ok(Some(id)) = stated_convention(&arch, bits, prototype.convention)
                && Some(id) != default
            {
                (stated.entry(id)).or_insert_with(|| assemble(&machine, container, id));
            }
        }
        // The C library the container states picks the rows (`__fgets_chk` is two interfaces
        // under one name); the program's own declarations are read by address beside them.
        let library = c_library(container);
        let mut rows = r2abi::LibraryRows::embedded(library);
        // A mangled import states its parameters in its name (doc/adr-call-boundary.md, S13).
        let imports = container.symbols.iter().filter(|symbol| symbol.import);
        rows.read_mangled(imports.map(|symbol| symbol.name.as_ref()));
        let linkage = crate::imports::Linkage::of(container);
        Ok(Self {
            machine,
            thumb,
            assembled,
            go,
            go_abi0,
            go_unstated,
            stated,
            imports: crate::imports::Imports::new(rows, library, linkage),
            data_model: r2abi::CDataModel::of(&arch, bits, library),
        })
    }

    /// What a native request needs at `entry`: the convention its declaration states, else its
    /// language's (Go: ABIInternal, ABI0 where pclntab marks assembly, else refused). O(log functions).
    fn assembled_at(&self, container: &Container, entry: u64) -> Result<Chosen<'_>, Unassembled> {
        let declared = container.declarations.function_at(entry);
        let (arch, bits) = (&container.arch.name, container.arch.bits);
        let stated = declared.map_or(Ok(None), |it| stated_convention(arch, bits, it.convention));
        if let Some(id) = stated?
            && let Some(held) = self.stated.get(&id)
        {
            let program = self.assembled.as_ref().ok();
            let assembled = held.as_ref().map_err(Clone::clone)?;
            return Ok(Chosen { assembled, program });
        }
        let languages = &container.languages;
        let chosen = match (&self.go, &self.go_abi0, languages.at(entry)) {
            (Some(go), None, SourceLanguage::Go) => go,
            (Some(go), Some(abi0), SourceLanguage::Go) => match &languages.go_assembly {
                Some(assembly) if assembly.contains(&entry) => abi0,
                Some(_) => go,
                None => self.go_unstated.as_ref().unwrap_or(abi0),
            },
            _ => &self.assembled,
        };
        let assembled = chosen.as_ref().map_err(Clone::clone)?;
        Ok(Chosen {
            assembled,
            program: None,
        })
    }

    /// What a native request needs under one convention, where the program assembled it.
    fn of(&self, id: r2abi::ConventionId) -> Option<&Result<Assembled, Unassembled>> {
        let go = [&self.go, &self.go_abi0, &self.go_unstated];
        std::iter::once(&self.assembled)
            .chain(go.into_iter().flatten())
            .chain(self.stated.values())
            .find(|assembled| assembled.as_ref().is_ok_and(|it| it.convention == id))
    }
}

/// The convention a function's debug information states, `None` where it keeps the target's
/// default; a code no model here has refuses the function (doc/adr-call-boundary.md, S20).
fn stated_convention(
    arch: &str,
    bits: u32,
    stated: r2abi::StatedConvention,
) -> Result<Option<r2abi::ConventionId>, Unassembled> {
    use r2abi::{ConventionId, StatedConvention};
    match (stated, r2abi::family(arch), bits) {
        (StatedConvention::Normal | StatedConvention::Program | StatedConvention::NoCall, ..) => {
            Ok(None)
        }
        (StatedConvention::LlvmWin64, Some("x86"), 64) => Ok(Some(ConventionId::Win64)),
        (StatedConvention::LlvmX8664SysV, Some("x86"), 64) => Ok(Some(ConventionId::SysVAmd64)),
        (stated, ..) => Err(Unassembled::StatedConvention(stated)),
    }
}

/// One convention's joined model, built once per program: the container decides it, so no write
/// moves it (doc/adr-call-boundary.md, "The joined model").
pub(super) struct Convention;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Convention {
    type Key = r2abi::ConventionId;
    type Value = Result<std::sync::Arc<r2source::ConventionModel>, NativeRefusal>;
    const NAME: &'static str = "convention";
    const RETENTION: Retention = Retention::Held;

    fn compute(db: &Db<ProgramInputs<S>>, id: &r2abi::ConventionId) -> Self::Value {
        let inputs = db.inputs();
        let machines = inputs.machines().map_err(NativeRefusal::Unassembled)?;
        let assembled = machines.of(*id).ok_or(NativeRefusal::Machine(
            "the program assembled no such convention",
        ))?;
        let assembled = assembled
            .as_ref()
            .map_err(|why| NativeRefusal::Unassembled(why.clone()))?;
        let container = inputs.source.container();
        let (arch, bits) = (&machines.machine.arch, container.arch.bits);
        let library = c_library(container);
        let guards = crate::native::ContainerGuards {
            cookie: container.security_cookie,
            linked: match r2abi::guard_row(&arch.name, bits, library) {
                Some(r2abi::GuardRow::LinkedGlobal(row)) => {
                    crate::stated::linked_guard(container, row, bits / 8)
                }
                _ => None,
            },
        };
        let model = crate::native::convention_model(
            arch,
            bits,
            (kernel(container), library, guards),
            &assembled.compiler,
            id.row(),
        );
        model.map(std::sync::Arc::new)
    }
}

/// What a call from a function under one convention may run under: its model joined with every
/// other the program states, as no site states its callee's. O(stated conventions x registers).
pub(super) struct AnyCall;

impl<S: Source + 'static> Query<ProgramInputs<S>> for AnyCall {
    type Key = r2abi::ConventionId;
    type Value = Result<std::sync::Arc<r2source::ConventionModel>, NativeRefusal>;
    const NAME: &'static str = "any-call";
    const RETENTION: Retention = Retention::Held;

    fn compute(db: &Db<ProgramInputs<S>>, id: &r2abi::ConventionId) -> Self::Value {
        let held = |id: &r2abi::ConventionId| {
            let model = db.get::<Convention>(id);
            let model = model.map_err(|cycle| NativeRefusal::Prepare(format!("{cycle:?}")))?;
            (*model).clone()
        };
        let own = held(id)?;
        let machines = db.inputs().machines();
        let machines = machines.map_err(NativeRefusal::Unassembled)?;
        if machines.stated.is_empty() {
            return Ok(own);
        }
        let default = machines.assembled.as_ref().ok().map(|it| it.convention);
        let stated = machines.stated.iter();
        let stated = stated.filter_map(|(id, built)| built.is_ok().then_some(*id));
        let mut joined = own;
        for other in default.into_iter().chain(stated).filter(|it| it != id) {
            let either = joined.either(&*held(&other)?);
            joined = std::sync::Arc::new(either.map_err(|why| NativeRefusal::Machine(why.why()))?);
        }
        Ok(joined)
    }
}

/// Assemble what a native request needs of the machine under one convention, once per program:
/// constant while it is open.
fn assemble(
    machine: &Machine,
    container: &Container,
    id: r2abi::ConventionId,
) -> Result<Assembled, Unassembled> {
    let convention = id.row();
    // A convention naming its compiler runs under it; the rest under the toolchain the container
    // names: a PE under Windows', a Mach-O under Apple's where the language has one.
    let specification = match (convention.cspec.toolchain, container.format) {
        (r2abi::Toolchain::Compiler(compiler), _) => machine
            .compiler_spec_of(compiler)
            .ok_or(Unassembled::NoCompiler(compiler))?,
        (r2abi::Toolchain::Container, Format::Pe) => machine
            .compiler_spec_of("windows")
            .unwrap_or(machine.compiler_spec),
        (r2abi::Toolchain::Container, Format::MachO) => machine
            .compiler_spec_of("apple")
            .unwrap_or(machine.compiler_spec),
        (r2abi::Toolchain::Container, _) => machine.compiler_spec,
    };
    let compiler = r2sleigh_lift::profile::LanguageProfile::parse(specification)
        .map_err(|error| Unassembled::UnparsedCompiler(error.0))?;
    let compiler = match convention.cspec.prototype {
        Some(prototype) => compiler
            .under(prototype)
            .ok_or(Unassembled::NoPrototype(prototype))?,
        None => compiler,
    };
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
    Ok(Assembled {
        convention: id,
        compiler,
        link,
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
    /// Whether a function's analysis reads the program's calls to it: `aa` asks once.
    callers: World,
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
            callers: World::Open,
            db: Db::new(ProgramInputs {
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
        self.db
            .inputs()
            .machines()
            .map(|_| ())
            .map_err(|why| why.to_string())
    }

    /// What this binary calls each address it names.
    pub fn names(&self) -> Rc<NameDb> {
        self.db
            .get::<Names>(&())
            .expect("the names ask only for the imports")
    }

    /// Where a session starts: `entry0` (so `s entry0` agrees), the declared entry, any entry,
    /// the first code section (an object declares none), else the first mapped byte.
    pub fn start(&self) -> Option<u64> {
        let container = self.source().container();
        let entries = &container.entries;
        let declared = entries
            .iter()
            .find(|entry| entry.kind == EntryKind::Main)
            .or_else(|| entries.first());
        // `entry0` names an entry the container states, so the stated names answer with no decoder,
        // built and dropped here: `Names` holds the one table.
        naming::of(self.source())
            .address_of("entry0")
            .or_else(|| declared.map(|entry| entry.vaddr))
            .or_else(|| {
                container
                    .sections
                    .iter()
                    .find(|section| section.is_code() && section.vsize > 0)
                    .map(|section| section.vaddr)
            })
            .or_else(|| container.segments.first().map(|segment| segment.vaddr))
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
    pub fn imports(&self) -> Rc<naming::Linkage> {
        self.db
            .get::<Imports>(&())
            .expect("the imports ask for nothing")
    }

    /// Whether what a native request needs of the machine was assembled when it loaded.
    fn assembled(&self) -> Result<(), String> {
        let machines = self.db.inputs().machines();
        let machines = machines.map_err(|why| why.to_string())?;
        (machines.assembled.as_ref())
            .map(|_| ())
            .map_err(ToString::to_string)
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
    /// The key of one function's analysis, sealing and rendering: its entry, its mode, and
    /// whether it reads its callers.
    fn analysis_key(&self, entry: u64) -> analysis::Key {
        (entry, self.view().thumb_at(entry), self.callers)
    }

    /// One function's analysis, done once per state of what it read (the `Analysed` query).
    fn analysed(&self, entry: u64) -> Result<std::sync::Arc<Prepared>, NativeRefusal> {
        let key = self.analysis_key(entry);
        let analysis = self.db.get::<analysis::Analysed>(&key);
        analysis.map_or_else(
            |cycle| Err(NativeRefusal::Prepare(format!("{cycle:?}"))),
            |analysis| analysis.0.clone(),
        )
    }

    /// One function's sealed type analysis, by the same key as its analysis.
    fn sealing(&self, entry: u64) -> analysis::Sealing {
        let key = self.analysis_key(entry);
        let sealing = self.db.get::<analysis::Sealed>(&key);
        sealing.map_or_else(
            |cycle| analysis::Sealing::Unanalysed(NativeRefusal::Prepare(format!("{cycle:?}"))),
            |sealing| (*sealing).clone(),
        )
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
            references: self.db.query_stats::<requests::ReferenceIndex>(),
            call_boundaries: self.db.query_stats::<fates::CallBoundary>(),
            direct_sites: self.db.query_stats::<fates::DirectSites>(),
            defects: self.db.stats().defects,
        }
    }

    /// The decoder the code at this address is written in: whichever is
    /// nearest below it of a mapping symbol and a function discovery placed,
    /// the container's statement winning a tie.
    fn machine_at(&self, vaddr: u64) -> Option<&Machine> {
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
    fn at(&self, vaddr: u64) -> Option<&Machine> {
        self.machine_at(vaddr)
    }
}

impl<S: Source + 'static> crate::body::Program for OpenProgram<S> {
    fn loader_writes(&self) -> &[LoaderWrite] {
        &self.source().container().loader_writes
    }

    fn permanence(&self, range: &std::ops::Range<u64>) -> Permanence {
        self.source().container().permanence(range)
    }

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

    fn exit_premises(&self, callee: u64) -> std::collections::BTreeSet<r2source::Premise> {
        self.view().exit_premises(callee)
    }

    fn returns_through(&self, slot: u64) -> bool {
        self.view().returns_through(slot)
    }

    fn halts_on_through(&self, slot: u64) -> Option<(r2source::CanonicalStorageId, r2abi::Handle)> {
        self.view().halts_on_through(slot)
    }

    fn yields_through(&self, slot: u64) -> Option<(r2source::CanonicalStorageId, r2abi::Handle)> {
        self.view().yields_through(slot)
    }

    fn binds_handles(&self) -> bool {
        self.view().binds_handles()
    }

    fn return_address_register(&self) -> Option<r2il::Varnode> {
        self.view().return_address_register()
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

    fn holds_code(&self, vaddr: u64) -> bool {
        self.view().holds_code(vaddr)
    }

    fn frame_saves(&self, entry: u64) -> Vec<r2source::SourceFrameSave> {
        self.view().frame_saves(entry)
    }

    fn extents(&self) -> &r2types::ProgramExtents {
        &self.db.inputs().extents
    }

    fn language_at(&self, vaddr: u64) -> r2abi::statement::SourceLanguage {
        self.view().language_at(vaddr)
    }

    fn import_at(&self, vaddr: u64) -> Option<String> {
        self.view().import_at(vaddr)
    }

    fn target_at(&self, vaddr: u64) -> Option<NativeTarget<'_>> {
        self.target(vaddr).ok()
    }
}

/// The C library a program runs against, as its container states it.
///
/// Mach-O is libSystem's and a PE Microsoft's runtime. An ELF is the one library its evidence
/// names (`PT_INTERP`, the start files' notes), or glibc where nothing names one but `DT_NEEDED`
/// names `libc.so.6` with a `GLIBC_*` version need on it (a shared object has no `PT_INTERP`).
/// Two libraries named, or an OS ABI not Linux's, is `Unknown`: only portable rows apply.
fn c_library(container: &Container) -> r2abi::CLibrary {
    use r2abi::CLibrary;
    match container.format {
        Format::MachO => return CLibrary::LibSystem,
        Format::Pe => return CLibrary::Ucrt,
        Format::Elf => {}
        _ => return CLibrary::Unknown,
    }
    let mut named = std::collections::BTreeSet::new();
    for evidence in &container.platform {
        match *evidence {
            PlatformEvidence::Interpreter(libc) | PlatformEvidence::Note(libc) => {
                named.insert(libc);
            }
            // GNU/Linux; zero, which states nothing, is never stated.
            PlatformEvidence::OsAbi(ELFOSABI_GNU) => {}
            PlatformEvidence::OsAbi(_) => return CLibrary::Unknown,
        }
    }
    let mut named = named.into_iter();
    match (named.next(), named.next()) {
        (Some(Libc::Glibc), None) => CLibrary::Glibc,
        (Some(Libc::Bionic), None) => CLibrary::Bionic,
        (Some(Libc::Musl), None) => CLibrary::Musl,
        (None, _) if needs_glibc(container) => CLibrary::Glibc,
        _ => CLibrary::Unknown,
    }
}

/// `DT_NEEDED libc.so.6` and a `.gnu.version_r` need of a `GLIBC_*` node on it: musl and bionic
/// ship no such soname or node.
fn needs_glibc(container: &Container) -> bool {
    const SONAME: &str = "libc.so.6";
    let needed = container.libraries.iter().any(|library| library == SONAME);
    let versioned = container.version_needs.iter().any(|need| {
        &*need.library == SONAME && need.versions.iter().any(|v| v.starts_with("GLIBC_"))
    });
    needed && versioned
}

/// Which kernel a program's system calls go to, as its container states it.
///
/// A kernel question, not a C library one: a static ELF names no library and
/// still traps into Linux. Mach-O runs on Darwin's. An ELF runs on Linux
/// unless its `EI_OSABI` names another system; one that states nothing is
/// Linux's convention, which is what every Linux toolchain writes.
pub(super) fn kernel(container: &Container) -> r2abi::Kernel {
    use r2abi::Kernel;
    match container.format {
        Format::MachO => Kernel::Darwin,
        Format::Pe => Kernel::Windows,
        Format::Elf => {
            let other = container.platform.iter().any(
                |evidence| matches!(evidence, PlatformEvidence::OsAbi(abi) if *abi != ELFOSABI_GNU),
            );
            match other {
                true => Kernel::Unknown,
                false => Kernel::Linux,
            }
        }
        _ => Kernel::Unknown,
    }
}

/// `EI_OSABI` for GNU/Linux, which glibc and bionic both run on.
const ELFOSABI_GNU: u8 = 3;

/// What the query database reads: the source, and what no write moves -- the
/// decoders and the slots the container states the loader fills.
pub(crate) struct ProgramInputs<S> {
    pub(crate) source: S,
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
    machines: std::cell::OnceCell<Result<Machines, Unassembled>>,
}

impl<S: Source> ProgramInputs<S> {
    fn machines(&self) -> Result<&Machines, Unassembled> {
        let loaded = self
            .machines
            .get_or_init(|| Machines::load(self.source.container()));
        loaded.as_ref().map_err(Clone::clone)
    }

    /// What a native request needs of the machine, where it loaded and was assembled.
    fn assembled(&self) -> Option<&Assembled> {
        self.machines().ok()?.assembled.as_ref().ok()
    }

    /// What a native request needs for the function at `entry`.
    fn assembled_at(&self, entry: u64) -> Result<Chosen<'_>, Unassembled> {
        self.machines()?
            .assembled_at(self.source.container(), entry)
    }

    /// Whether the code from here on is Thumb, as the nearest mapping symbol at or below it states.
    fn stated_thumb(&self, vaddr: u64) -> bool {
        (self.mapped.range(..=vaddr).next_back()).is_some_and(|(_, thumb)| *thumb)
    }

    /// Whether the container states this address holds instructions: a section it says holds
    /// code, or, where it states no sections, a region it maps executable.
    fn holds_code(&self, vaddr: u64) -> bool {
        let container = self.source.container();
        match &self.code {
            Some(code) => code.holds(vaddr),
            None => {
                (container.segment_at(vaddr)).is_some_and(|segment| segment.permissions.execute)
            }
        }
    }

    /// Whether a function can begin here: code the file holds bytes for (audit W29).
    fn places_function(&self, vaddr: u64) -> bool {
        self.holds_code(vaddr) && self.source.container().file_backed(vaddr, 1) > 0
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
/// bytes elsewhere. The stated starts read it, which bound every body
/// walk, so a stale table would be a body that ends in the wrong place.
struct Imports;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Imports {
    type Key = ();
    type Value = naming::Linkage;
    const NAME: &'static str = "imports";
    const RETENTION: Retention = Retention::Held;

    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        // A stub is named by decoding it, so without a decoder there is none.
        let Ok(machines) = db.inputs().machines() else {
            return naming::Linkage::default();
        };
        let machine = &machines.machine;
        naming::imports(&Recorded { db }, &machine.disasm, machine.arch.alignment)
    }
}

/// What this binary calls each address it names.
struct Names;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Names {
    type Key = ();
    type Value = NameDb;
    const NAME: &'static str = "names";
    const RETENTION: Retention = Retention::Held;

    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        let source = Recorded { db };
        let imports = db.get::<Imports>(&()).expect("the imports ask for nothing");
        let mut names = naming::of(&source);
        naming::name_strings(&mut names, &source);
        naming::name_imports(&mut names, &imports.stubs);
        naming::name_slots(
            &mut names,
            &db.inputs().slots,
            &imports.stubs,
            &source.container().loader_writes,
        );
        names
    }
}
