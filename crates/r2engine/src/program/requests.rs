//! The questions a caller asks of an open program, each one call.
//!
//! Every command used to sequence these itself: make the tables current,
//! assemble the machine, describe the target, prepare, render. That order is
//! the engine's to keep, so a caller names what it wants and gets it.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{OpenProgram, ProgramInputs, Source, SymbolKind, View};
use crate::discovery::{Basis, Confidence, Discovered};
use crate::isolation::isolated;
use crate::native::{NativeRefusal, Prepared};
use crate::query::db::{Db, Query};
use crate::query::references::Indexing;
use crate::query::{
    Answer, Answered, Completion, Coverage, Decoders, Line, Listing, Memory, Proved, References,
    Stop, Unread, WalkedBody, Work,
};
use crate::{EngineDecompileResponse, RenderTier, SealedFunctionAnalysis};

/// One function listed block by block, and why the analysis its lines would
/// carry was refused, where it was.
pub struct FunctionListing {
    pub lines: Answer<Vec<Line>>,
    /// Where this is `Some`, the lines are the plain walk's: every block the
    /// walk reaches without the analysis, claiming only what each line and
    /// the walked def-use show.
    pub refused: Option<AnalysisRefused>,
}

/// One function as its control-flow graph: each block with its lines, and
/// where control leaves it. `agf`, and the visual mode's graph, draw this.
pub struct FunctionGraph {
    pub entry: u64,
    /// In address order; the entry block is the one starting at `entry`.
    pub blocks: Vec<GraphBlock>,
    /// As for [`FunctionListing`]: present where the blocks are the plain
    /// walk's, which follows no dispatch.
    pub refused: Option<AnalysisRefused>,
}

/// One basic block of a [`FunctionGraph`].
pub struct GraphBlock {
    pub address: u64,
    pub size: u64,
    pub lines: Vec<Line>,
    /// In the order the walk found them. Only edges to a block of this body:
    /// a branch to another function's entry is that function's, not an edge.
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphEdge {
    pub target: u64,
    pub kind: EdgeKind,
}

/// How control reaches an edge's target, read off the walk's successor kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeKind {
    /// The only way out: an unconditional branch.
    Jump,
    /// Into the next block, with no transfer.
    Fall,
    /// A conditional branch's target.
    Taken,
    /// A conditional branch's fall-through.
    NotTaken,
    /// One case of a dispatch the analysis read.
    Case,
    /// A dispatch's default.
    Default,
}

/// Each block's extent and successors, as the walk that the lines came from
/// left them, and each instruction whose dispatch the analysis read a table for.
/// A block's start, size, and where control goes from it.
type ShapeBlock = (u64, u64, Vec<(r2source::AdvisorySuccessorKind, u64)>);

struct Shape {
    blocks: Vec<ShapeBlock>,
    dispatches: std::collections::BTreeSet<u64>,
}

fn shape_of(blocks: &[crate::body::BodyBlock], dispatches: impl Iterator<Item = u64>) -> Shape {
    let blocks = blocks
        .iter()
        .map(|block| {
            let lifted = &block.lifted;
            (
                lifted.addr,
                u64::from(lifted.size),
                block.successors.clone(),
            )
        })
        .collect();
    Shape {
        blocks,
        dispatches: dispatches.collect(),
    }
}

/// The edges of one block. A direct successor beside a fall-through is a
/// conditional branch; either alone is a jump or a fall. A block ending in a
/// dispatch whose table was read goes to its arms, which are its cases.
fn edges_of(
    successors: &[(r2source::AdvisorySuccessorKind, u64)],
    dispatch: bool,
    inside: impl Fn(u64) -> bool,
) -> Vec<GraphEdge> {
    use r2source::AdvisorySuccessorKind as Kind;
    let conditional = successors.iter().any(|(kind, _)| *kind == Kind::Direct)
        && successors
            .iter()
            .any(|(kind, _)| *kind == Kind::Fallthrough);
    let mut edges = Vec::with_capacity(successors.len());
    for &(kind, target) in successors {
        let kind = match (kind, conditional) {
            (Kind::Direct, _) if dispatch => EdgeKind::Case,
            (Kind::Direct, false) => EdgeKind::Jump,
            (Kind::Direct, true) => EdgeKind::Taken,
            (Kind::Fallthrough, false) => EdgeKind::Fall,
            (Kind::Fallthrough, true) => EdgeKind::NotTaken,
            (Kind::SwitchCase, _) => EdgeKind::Case,
            (Kind::SwitchDefault, _) => EdgeKind::Default,
        };
        let edge = GraphEdge { target, kind };
        if inside(target) && !edges.contains(&edge) {
            edges.push(edge);
        }
    }
    edges
}

/// Why a function's listing carries no analysis, and what the plain walk could not follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisRefused {
    pub reason: NativeRefusal,
    /// Each indirect transfer the plain walk stopped at. The analysis is what
    /// reads a dispatch's table, so what these reach is not listed.
    pub unresolved: Vec<u64>,
}

/// A function rendered at one tier, with what of its analysis the rendering is shown with.
#[derive(Clone)]
pub struct Rendering {
    pub response: EngineDecompileResponse,
    /// The name the C defines the function under.
    pub definition: String,
    /// The callees the analysis could not read.
    pub unread: Vec<crate::native::Unread>,
}

impl Rendering {
    /// The rendering as one object a tool reads: `pddj`.
    ///
    /// `name` is the program's name for the function at `entry`.
    pub fn answer(&self, name: &str, entry: u64) -> crate::RenderedFunctionJson {
        let definition = self.definition.clone();
        crate::RenderedFunctionJson::of(&self.response, name, entry, definition)
    }
}

/// Every function discovery found, and whether each body was walked as Thumb or why it could not be walked.
#[derive(Debug)]
pub(super) struct Survey {
    functions: Vec<Discovered>,
    walked: BTreeMap<u64, Result<bool, NativeRefusal>>,
    /// Each walked body's blocks and their bytes, as the walk traced them.
    extents: BTreeMap<u64, crate::body::TraceExtent>,
    /// Each walked body's instructions that enter the supervisor, where it has any.
    supervisor: BTreeMap<u64, std::collections::BTreeSet<u64>>,
    /// Which walked bodies hold each address.
    holders: crate::discovery::Holders,
}

/// One instruction that enters the kernel, with the call it makes where the
/// body proves which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Syscall {
    pub address: u64,
    /// The number, where every path to the instruction leaves the platform's
    /// number register holding one proven value.
    pub number: Option<u64>,
    /// The kernel's name for the number, where its table gives one.
    pub name: Option<String>,
}

/// The one decoder a body was walked with, whatever the address.
struct Walked<'m>(&'m r2sleigh_lift::EmbeddedMachine);

impl Decoders for Walked<'_> {
    fn at(&self, _vaddr: u64) -> Option<&r2sleigh_lift::EmbeddedMachine> {
        Some(self.0)
    }
}

/// A body's blocks listed in address order, each one run folded across its instructions.
fn listed_by_block(answered: &Answered<'_>, blocks: &[r2il::R2ILBlock]) -> Answer<Vec<Line>> {
    let mut extents = blocks
        .iter()
        .filter(|block| block.size > 0)
        .map(|block| (block.addr, block.addr + u64::from(block.size)))
        .collect::<Vec<_>>();
    extents.sort_unstable();
    extents.dedup();
    let mut whole = Answer::complete(Vec::new());
    for (start, end) in extents {
        let listing = Listing {
            start,
            stop: Stop::At(end),
        };
        let answer = crate::query::listing(answered, listing, Work::Function);
        whole.value.extend(answer.value);
        if whole.completion == Completion::Complete {
            whole.completion = answer.completion;
        }
    }
    whole
}

impl<S: Source + 'static> OpenProgram<S> {
    /// One function's analysis, done once per state of this program.
    pub fn prepared(&mut self, entry: u64) -> Result<Arc<Prepared>, String> {
        self.start_request();
        self.prepare(entry)
    }

    /// The analysis, within a request already started.
    fn prepare(&self, entry: u64) -> Result<Arc<Prepared>, String> {
        self.loaded()?;
        self.assembled()?;
        self.analysed(entry).map_err(|refusal| refusal.to_string())
    }

    /// Read one prepared function's sealed type analysis; a refusal may be this request's stop, so it is not held.
    ///
    /// Reading is an isolation boundary: a panic in it is this function's refusal at the structuring phase.
    fn read_sealed<R>(
        &self,
        entry: u64,
        prepared: &Arc<Prepared>,
        read: impl FnOnce(&SealedFunctionAnalysis) -> R,
    ) -> Result<Result<R, Box<EngineDecompileResponse>>, String> {
        let sealed = match self.sealing(entry) {
            super::analysis::Sealing::Sealed(sealed) => sealed.0,
            super::analysis::Sealing::Refused { response, .. } => {
                return Ok(Err(Box::new((*response).clone())));
            }
            super::analysis::Sealing::Unanalysed => {
                return Err("the function has no analysis to seal".to_owned());
            }
        };
        let refused = |panicked: crate::isolation::Panicked| {
            let name = prepared.name();
            let phase = crate::EnginePhase::Structuring;
            Box::new(crate::panicked_decompile_response(name, &panicked, phase))
        };
        Ok(isolated(|| read(&sealed)).map_err(refused))
    }

    /// One function rendered at one tier.
    pub fn rendered(&mut self, entry: u64, tier: RenderTier) -> Result<Rendering, String> {
        self.start_request();
        self.loaded()?;
        self.assembled()?;
        let key = (entry, self.view().thumb_at(entry), tier);
        let render = self.db.get::<super::analysis::Rendered>(&key);
        let render = render.map_err(|cycle| format!("{cycle:?}"))?;
        let drawn = render.0.as_ref().map_err(Clone::clone)?;
        Ok(Rendering::clone(&drawn.rendering))
    }

    /// What one function is, read off the sealed analysis every rendering draws from.
    pub fn function_info(&mut self, entry: u64) -> Result<super::info::FunctionInfo, String> {
        self.start_request();
        let prepared = self.prepare(entry)?;
        let artifact = prepared.artifact().artifact();
        let noreturn = !self.comes_back(entry);
        let read = |sealed: &SealedFunctionAnalysis| {
            super::info::FunctionInfo::read(entry, artifact, sealed.facts(), noreturn)
        };
        let mut info = self
            .read_sealed(entry, &prepared, read)?
            .map_err(|refused| refused.diagnostics.route_reason.unwrap_or_default())?;
        // The frame's locals are the ones the rendering declares, so afv and pdd name the same objects (ADR frame-model).
        if let Some(locals) = self.declared_frame_locals(entry) {
            info.locals = locals;
        }
        Ok(info)
    }

    /// The frame locals the C rendering declares, at their entry-stack offsets; none where it refused.
    fn declared_frame_locals(&self, entry: u64) -> Option<Vec<super::info::Local>> {
        let key = (entry, self.view().thumb_at(entry), RenderTier::C);
        let render = self.db.get::<super::analysis::Rendered>(&key).ok()?;
        let drawn = render.0.as_ref().ok()?;
        let crate::EngineRendering::Function(rendered) = &drawn.rendering.response.output else {
            return None;
        };
        let declared = rendered
            .emission()
            .variables()
            .iter()
            .filter_map(|variable| {
                let r2dec::report::VariableLocation::Frame { offset } = variable.location else {
                    return None;
                };
                Some(super::info::Local {
                    name: variable.name.clone(),
                    base: super::info::StackBase::StackPointer,
                    offset,
                    ty: variable.ty.clone(),
                })
            });
        let mut locals: Vec<_> = declared.collect();
        locals.sort_by_key(|local| local.offset);
        Some(locals)
    }

    /// The operations Sleigh produced for one function, before any analysis.
    pub fn lifted(&mut self, entry: u64) -> Result<String, String> {
        self.start_request();
        self.loaded()?;
        self.assembled()?;
        crate::native::lifted(&self.target(entry)?, self, entry)
            .map_err(|refusal| refusal.to_string())
    }

    /// A run of instructions, each carrying what its own run of neighbours
    /// shows. Nothing is walked or prepared.
    pub fn listing(&mut self, request: Listing) -> Result<Answer<Vec<Line>>, String> {
        self.start_request();
        self.loaded()?;
        // A machine it cannot assemble still lists, with no callee parameters and nothing saying what a call clobbers.
        if let Err(reason) = self.assembled() {
            r2il::refusal_evidence!("call-effect", "{:#x}: {reason}", request.start);
        }
        Ok(crate::query::listing(
            &self.answered(None),
            request,
            Work::BlockLocal,
        ))
    }

    /// One function listed block by block, each line carrying what the
    /// analysis proved about the values it defines.
    ///
    /// By each block's own extent: sweeping from the lowest block to the
    /// highest ran through whatever lay between -- another function's bytes,
    /// or the whole gap to a cold partition placed far away. The blocks and the
    /// def-use are the walked body's, which is what the reference index reads.
    ///
    /// **The bytes never depend on the analysis succeeding.** Where the
    /// analysis refuses -- or panics, which is a refusal too -- the listing is
    /// the plain walk and says why, naming each dispatch the walk could not
    /// follow. Only a body that cannot be walked at all lists nothing, and
    /// that includes a walk that panics: every step past the tables is inside
    /// an isolation boundary, so no defect in one function's listing unwinds
    /// through the caller.
    pub fn function_listing(&mut self, entry: u64) -> Result<FunctionListing, String> {
        self.start_request();
        Ok(self.listed_body(entry)?.0)
    }

    /// One function's control-flow graph: the listing's blocks, each with its
    /// lines and its typed edges. It stands where the analysis refuses, as the
    /// listing does, and then follows no dispatch.
    ///
    /// O(body + lines): one walk, which the listing already makes.
    pub fn function_graph(&mut self, entry: u64) -> Result<FunctionGraph, String> {
        self.start_request();
        let (listing, shape) = self.listed_body(entry)?;
        let starts = shape
            .blocks
            .iter()
            .map(|(address, _, _)| *address)
            .collect::<std::collections::BTreeSet<_>>();
        let mut lines = listing.lines.value.into_iter().peekable();
        let mut blocks = Vec::with_capacity(shape.blocks.len());
        // Both are in address order, so each line is placed once.
        let Shape {
            blocks: mut walked,
            dispatches,
        } = shape;
        walked.sort_by_key(|(address, _, _)| *address);
        for (address, size, successors) in walked {
            while lines.next_if(|line| line.address < address).is_some() {}
            let mut held = Vec::new();
            while let Some(line) = lines.next_if(|line| line.address < address + size) {
                held.push(line);
            }
            let dispatch = held
                .last()
                .is_some_and(|line| dispatches.contains(&line.address));
            blocks.push(GraphBlock {
                address,
                size,
                lines: held,
                edges: edges_of(&successors, dispatch, |target| starts.contains(&target)),
            });
        }
        Ok(FunctionGraph {
            entry,
            blocks,
            refused: listing.refused,
        })
    }

    /// The listing and the shape of the body it lists, within a request already started.
    fn listed_body(&self, entry: u64) -> Result<(FunctionListing, Shape), String> {
        self.loaded()?;
        self.assembled()?;
        let target = self.target(entry)?;
        let reason = match self.analysed(entry) {
            // A defect reading what the analysis proved is an analysis defect like any other.
            Ok(prepared) => match isolated(|| self.proved_listing(&target, &prepared)) {
                Ok(listing) => {
                    let shape = shape_of(&prepared.body().blocks, prepared.dispatches());
                    return Ok((listing, shape));
                }
                Err(panicked) => NativeRefusal::from(panicked),
            },
            Err(reason) => reason,
        };
        let refused = reason.to_string();
        isolated(|| self.walked_listing(&target, entry, reason)).unwrap_or_else(|panicked| {
            Err(format!(
                "nothing is listed at {entry:#x}: the plain walk {panicked}, \
                 after the analysis was refused: {refused}"
            ))
        })
    }

    /// The listing of a function whose analysis stands, each line carrying what it proved.
    fn proved_listing(
        &self,
        target: &crate::native::NativeTarget<'_>,
        prepared: &Prepared,
    ) -> FunctionListing {
        let lifted = prepared.lifted();
        let body = WalkedBody::new(&lifted, target.arch);
        let proved = Proved::new(prepared);
        let answered = Answered {
            body: Some(&body),
            ..self.answered(Some(&proved))
        };
        FunctionListing {
            lines: listed_by_block(&answered, &lifted),
            refused: None,
        }
    }

    /// The listing of the plain walk of a function whose analysis was refused.
    ///
    /// O(body): one more walk, on the failure path only.
    fn walked_listing(
        &self,
        target: &crate::native::NativeTarget<'_>,
        entry: u64,
        reason: NativeRefusal,
    ) -> Result<(FunctionListing, Shape), String> {
        let body = crate::body::lift_body(entry, target.disasm, self, &BTreeMap::new())
            .map_err(|error| NativeRefusal::Body(error).to_string())?;
        let unresolved = body
            .unresolved
            .iter()
            .filter(|stop| stop.reason == crate::body::UnresolvedReason::IndirectBranch)
            .map(|stop| stop.addr)
            .collect();
        // The plain walk reads no table, so it follows no dispatch.
        let shape = shape_of(&body.blocks, std::iter::empty());
        let lifted = body
            .blocks
            .into_iter()
            .map(|block| block.lifted)
            .collect::<Vec<_>>();
        let walked = WalkedBody::new(&lifted, target.arch);
        let answered = Answered {
            body: Some(&walked),
            ..self.answered(None)
        };
        let listing = FunctionListing {
            lines: listed_by_block(&answered, &lifted),
            refused: Some(AnalysisRefused { reason, unresolved }),
        };
        Ok((listing, shape))
    }

    /// Every function the program has, from what the container states and
    /// what the bodies reach.
    pub fn functions(&mut self) -> Result<Vec<Discovered>, String> {
        self.start_request();
        Ok(self.surveyed()?.functions.clone())
    }

    /// The entries of every believed body whose walk decoded this address as
    /// one of its instructions, in address order: more than one where bodies
    /// share a tail, none outside every body. O(log n) once discovery has
    /// walked the program at this state of its bytes.
    pub fn functions_holding(&mut self, vaddr: u64) -> Result<Vec<u64>, String> {
        self.start_request();
        Ok(self.surveyed()?.holders.at(vaddr).to_vec())
    }

    /// Every function's basic blocks and their bytes, from the walk discovery
    /// already made, keyed by entry. A body the walk refused has none.
    ///
    /// The walk follows no dispatch table, so a jump table's arms are not
    /// counted; one resolved body for every consumer is P6.
    pub fn function_extents(&mut self) -> Result<BTreeMap<u64, crate::body::TraceExtent>, String> {
        self.start_request();
        Ok(self.surveyed()?.extents.clone())
    }

    /// Every instruction in a believed body that enters the kernel, with the
    /// call it makes: radare2's `/as`.
    ///
    /// The sites are the ones the survey's walk decoded, so an instruction is
    /// one Sleigh says enters the supervisor and lies in a body control
    /// reaches. Only a body holding one is prepared, and the number is the
    /// value the platform's number register holds there, proven or not given.
    /// A site two bodies share takes their number where they agree.
    pub fn syscalls(&mut self) -> Result<Vec<Syscall>, String> {
        self.start_request();
        let sites = self.surveyed()?.supervisor.clone();
        let container = self.source().container();
        let table = r2abi::Syscalls::for_platform(
            super::kernel(container),
            &container.arch.name,
            container.arch.bits,
        );
        let mut found = BTreeMap::<u64, Option<u64>>::new();
        for (entry, calls) in sites {
            let numbers = match &table {
                Some(table) => self.syscall_numbers(entry, table)?,
                None => BTreeMap::new(),
            };
            for site in calls {
                let number = numbers.get(&site).copied().flatten();
                // Two bodies that disagree prove neither number.
                let held = found.entry(site).or_insert(number);
                *held = held.filter(|_| *held == number);
            }
        }
        Ok(found
            .into_iter()
            .map(|(address, number)| Syscall {
                address,
                number,
                name: number
                    .zip(table.as_ref())
                    .and_then(|(number, table)| table.name(number).map(str::to_owned)),
            })
            .collect())
    }

    /// The number each supervisor call in one body proves, by instruction; a
    /// body that does not prepare proves none.
    fn syscall_numbers(
        &mut self,
        entry: u64,
        table: &r2abi::Syscalls,
    ) -> Result<BTreeMap<u64, Option<u64>>, String> {
        let Ok(prepared) = self.prepare(entry) else {
            return Ok(BTreeMap::new());
        };
        let arch = self.target(entry)?.arch;
        let Some(storage) = r2sleigh_lift::lifted_register_storage(arch, table.number_register())
        else {
            return Ok(BTreeMap::new());
        };
        Ok(prepared
            .artifact()
            .shared_artifact()
            .supervisor_calls(storage)
            .into_iter()
            .map(|call| (call.address, call.number))
            .collect())
    }

    /// Every reference the program makes, from every function discovery
    /// believes, with the coverage it was read over; read once per state of the program.
    ///
    /// Each body's blocks are listed as `pdf` lists them and the index is what
    /// those lines claim, in the instruction set discovery walked the body in.
    pub fn references(&mut self) -> Result<Answer<Arc<References>>, String> {
        self.start_request();
        // A callee's body is read in the instruction set discovery settled, so that is settled first.
        self.loaded()?;
        let index = self.db.get::<ReferenceIndex>(&());
        let index = index.map_err(|cycle| format!("{cycle:?}"))?;
        let index = index.as_ref().clone()?;
        Ok(Answer::complete(index.0))
    }

    /// Discovery over the whole program, which settles each function's instruction set and whether it returns.
    pub(super) fn surveyed(&self) -> Result<Arc<Survey>, String> {
        self.loaded()?;
        let answer = self
            .db
            .get::<SurveyQuery>(&())
            .map_err(|cycle| format!("{cycle:?}"))?;
        answer.as_ref().clone().map(|surveyed| surveyed.0)
    }

    fn answered<'a>(&'a self, proved: Option<&'a Proved<'a>>) -> Answered<'a> {
        Answered {
            decoders: self,
            memory: Memory {
                program: self,
                endian: self.endian(),
            },
            call_effect: self
                .db
                .inputs()
                .assembled()
                .and_then(|held| held.call_effect.as_ref()),
            proved,
            body: None,
            holdings: true,
            parameters: Some(self),
        }
    }
}

/// Every reference the program makes, from every function discovery believes, with the coverage it was read over.
pub(super) struct ReferenceIndex;

impl<S: Source + 'static> Query<ProgramInputs<S>> for ReferenceIndex {
    type Key = ();
    type Value = Result<super::analysis::Shared<References>, String>;
    const NAME: &'static str = "reference-index";

    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        indexed(&View::new(db, true)).map(|index| super::analysis::Shared(Arc::new(index)))
    }
}

/// Read every believed body's references.
fn indexed<S: Source + 'static>(view: &View<'_, S>) -> Result<References, String> {
    let survey = view.db.get::<SurveyQuery>(&());
    let survey = survey.map_err(|cycle| format!("{cycle:?}"))?;
    let survey = survey.as_ref().clone()?.0;
    let walked = &survey.walked;
    let mut index = Indexing::default();
    let mut coverage = Coverage::default();
    index.read_words(&view.source().container().loader_writes);
    // A program that states no function is never assembled, and has nothing to index.
    if walked.is_empty() {
        return Ok(index.finish(coverage));
    }
    let walker = super::returns::Walking::new(view.clone(), true)?;
    for (&entry, walked) in walked {
        // Each body is lifted as `pdf` walks it, one at a time: discovery kept where control goes and not what it lifted.
        let lifted = walked.clone().and_then(|thumb| {
            let target = walker.target(thumb);
            let body = crate::body::lift_body(entry, target.disasm, view, &BTreeMap::new());
            body.map(|body| (thumb, body)).map_err(NativeRefusal::Body)
        });
        let (thumb, body) = match lifted {
            Ok(lifted) => lifted,
            Err(refusal) => {
                coverage.unread.insert(entry, Unread::Refused(refusal));
                continue;
            }
        };
        if !body.unresolved.is_empty() {
            coverage.unresolved.insert(entry, body.unresolved);
        }
        let machine = walker.machine(thumb).ok_or("no machine")?;
        let decoder = (walker.target(thumb), machine);
        match claimed_by(view, decoder, body.blocks) {
            Ok(lines) => {
                coverage.read.push(entry);
                index.read(entry, lines);
            }
            Err(unread) => {
                coverage.unread.insert(entry, unread);
            }
        }
    }
    Ok(index.finish(coverage))
}

/// One body listed as the reference index reads it, or why it is unread.
fn claimed_by<S: Source + 'static>(
    view: &View<'_, S>,
    (target, machine): (
        &crate::native::NativeTarget<'_>,
        &r2sleigh_lift::EmbeddedMachine,
    ),
    blocks: Vec<crate::body::BodyBlock>,
) -> Result<Vec<Line>, Unread> {
    let lifted = blocks
        .into_iter()
        .map(|block| block.lifted)
        .collect::<Vec<_>>();
    let body = WalkedBody::new(&lifted, target.arch);
    let answered = Answered {
        decoders: &Walked(machine),
        memory: Memory {
            program: view,
            endian: super::view::endian(view.source()),
        },
        call_effect: target.call_effect,
        proved: None,
        body: Some(&body),
        holdings: false,
        parameters: Some(view),
    };
    let lines = listed_by_block(&answered, &lifted).value;
    // A number whose fate needed the def-use that did not build is unsettled, so the body is unread.
    if body.failed() {
        return Err(Unread::NoSsa);
    }
    Ok(lines)
}

/// Every function discovery finds, compared by identity: a new survey is a new answer.
#[derive(Clone)]
pub(super) struct Surveyed(Arc<Survey>);

impl PartialEq for Surveyed {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// Discovery over the whole program from what it states; its returns are deposited for `ComesBack`.
pub(super) struct SurveyQuery;

impl<S: Source + 'static> Query<ProgramInputs<S>> for SurveyQuery {
    type Key = ();
    type Value = Result<Surveyed, String>;
    const NAME: &'static str = "survey";

    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        // Discovery decides each body's instruction set itself, so it reads no modes.
        let view = View::new(db, false);
        let seeds = stated_functions(&view);
        if seeds.is_empty() {
            return Ok(Surveyed(Arc::new(Survey {
                functions: Vec::new(),
                walked: BTreeMap::new(),
                extents: BTreeMap::new(),
                supervisor: BTreeMap::new(),
                holders: crate::discovery::Holders::default(),
            })));
        }
        let walker = super::returns::Walking::new(view.clone(), true)?;
        let found = crate::discovery::functions(&view, seeds, &walker);
        db.deposit::<super::returns::ComesBack>(found.returns);
        let extents = found
            .walks
            .iter()
            .filter_map(|(entry, walk)| Some((*entry, walk.as_ref().ok()?.extent())))
            .collect();
        let supervisor = found
            .walks
            .iter()
            .filter_map(|(entry, walk)| {
                let calls = walk.as_ref().ok()?.supervisor_calls();
                (!calls.is_empty()).then(|| (*entry, calls.clone()))
            })
            .collect();
        let holders =
            crate::discovery::Holders::of(found.walks.iter().flat_map(|(entry, walk)| {
                let spans = walk.as_ref().map(|walk| walk.spans()).unwrap_or_default();
                spans.into_iter().map(move |span| (*entry, span))
            }));
        let walked = found
            .walks
            .into_iter()
            .map(|(entry, walk)| (entry, walk.map(|walk| walk.thumb)))
            .collect();
        Ok(Surveyed(Arc::new(Survey {
            functions: found.functions,
            walked,
            extents,
            supervisor,
            holders,
        })))
    }
}

/// Whether each function the survey found is Thumb; empty where the machine has one instruction set.
pub(super) struct Modes;

impl<S: Source + 'static> Query<ProgramInputs<S>> for Modes {
    type Key = ();
    type Value = BTreeMap<u64, bool>;
    const NAME: &'static str = "modes";

    fn compute(db: &Db<ProgramInputs<S>>, (): &()) -> Self::Value {
        if db
            .inputs()
            .machines()
            .map_or(true, |machines| machines.thumb.is_none())
        {
            return BTreeMap::new();
        }
        match db
            .get::<SurveyQuery>(&())
            .expect("the survey reads no modes")
            .as_ref()
        {
            Ok(surveyed) => surveyed
                .0
                .functions
                .iter()
                .map(|one| (one.address, one.thumb))
                .collect(),
            Err(_) => BTreeMap::new(),
        }
    }
}

/// Where the program states a function begins, and whether it states the code there is Thumb.
fn stated_functions<S: Source + 'static>(view: &View<'_, S>) -> Vec<(u64, Confidence, bool)> {
    let container = view.source().container();
    container
        .entries
        .iter()
        .map(|entry| (entry.vaddr, entry.thumb))
        .chain(
            container
                .symbols
                .iter()
                .filter(|symbol| symbol.defined && symbol.kind == SymbolKind::Function)
                .map(|symbol| (symbol.vaddr, symbol.thumb)),
        )
        .chain(view.imports().keys().map(|vaddr| (*vaddr, false)))
        .map(|(vaddr, thumb)| (vaddr, Confidence::of(Basis::Stated), thumb))
        .collect()
}
