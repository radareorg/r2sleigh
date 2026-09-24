//! The questions a caller asks of an open program, each one call.
//!
//! Every command used to sequence these itself: make the tables current,
//! assemble the machine, describe the target, prepare, render. That order is
//! the engine's to keep, so a caller names what it wants and gets it.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{OpenProgram, Source, SymbolKind};
use crate::discovery::{Confidence, Discovered};
use crate::native::{NativeRefusal, Prepared};
use crate::query::references::Indexing;
use crate::query::{
    Answer, Answered, Completion, Coverage, Decoders, Line, Listing, Memory, Proved, References,
    Stop, Unread, WalkedBody, Work,
};
use crate::{EngineDecompileResponse, EngineSession, RenderTier, SealedFunctionAnalysis};

/// A function rendered at one tier, and the analysis it was rendered from.
pub struct Rendering {
    pub prepared: Arc<Prepared>,
    pub response: EngineDecompileResponse,
}

/// Every function discovery found, and whether each body was walked as Thumb or why it could not be walked.
pub(super) struct Survey {
    functions: Vec<Discovered>,
    walked: BTreeMap<u64, Result<bool, NativeRefusal>>,
}

/// The one decoder a body was walked with, whatever the address.
struct Walked<'m>(&'m r2sleigh_lift::EmbeddedMachine);

impl Decoders for Walked<'_> {
    fn at(&self, _vaddr: u64) -> Option<&r2sleigh_lift::EmbeddedMachine> {
        Some(self.0)
    }
}

/// A body's blocks listed in address order, each one run folded across its instructions.
fn listed_by_block(
    answered: &Answered<'_>,
    blocks: &[r2il::R2ILBlock],
    revision: crate::query::Revision,
) -> Answer<Vec<Line>> {
    let mut extents = blocks
        .iter()
        .filter(|block| block.size > 0)
        .map(|block| (block.addr, block.addr + u64::from(block.size)))
        .collect::<Vec<_>>();
    extents.sort_unstable();
    extents.dedup();
    let mut whole = Answer::complete(Vec::new(), revision);
    for (start, end) in extents {
        let listing = Listing {
            start,
            stop: Stop::At(end),
        };
        let answer = crate::query::listing(answered, listing, Work::Function, revision);
        whole.value.extend(answer.value);
        if whole.completion == Completion::Complete {
            whole.completion = answer.completion;
        }
    }
    whole
}

impl<S: Source> OpenProgram<S> {
    /// One function's analysis, done once per state of this program.
    pub fn prepared(&mut self, entry: u64) -> Result<Arc<Prepared>, String> {
        self.start_request();
        self.prepare(entry)
    }

    /// The analysis, within a request already started.
    fn prepare(&mut self, entry: u64) -> Result<Arc<Prepared>, String> {
        self.ensure_decodable()?;
        self.ensure_assembled(entry)?;
        let target = self.target(entry)?;
        self.analysed(&target, entry)
            .map_err(|refusal| refusal.to_string())
    }

    /// Read one prepared function's sealed type analysis; a refusal may be this request's stop, so it is not held.
    fn read_sealed<R>(
        &self,
        entry: u64,
        prepared: &Arc<Prepared>,
        read: impl FnOnce(&SealedFunctionAnalysis) -> R,
    ) -> Result<Result<R, Box<EngineDecompileResponse>>, String> {
        let target = self.target(entry)?;
        let seal = || crate::native::sealed(&target, entry, prepared, &self.control);
        Ok(self.memo.read_sealed(prepared, seal, read))
    }

    /// One function rendered at one tier.
    pub fn rendered(&mut self, entry: u64, tier: RenderTier) -> Result<Rendering, String> {
        self.start_request();
        let prepared = self.prepare(entry)?;
        let render = |sealed: &_| EngineSession::new().render_sealed(sealed, tier, &self.control);
        let response = self
            .read_sealed(entry, &prepared, render)?
            .unwrap_or_else(|refused| *refused);
        Ok(Rendering { prepared, response })
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
        self.read_sealed(entry, &prepared, read)?
            .map_err(|refused| refused.diagnostics.route_reason.unwrap_or_default())
    }

    /// The operations Sleigh produced for one function, before any analysis.
    pub fn lifted(&mut self, entry: u64) -> Result<String, String> {
        self.start_request();
        self.ensure_decodable()?;
        self.ensure_assembled(entry)?;
        crate::native::lifted(&self.target(entry)?, self, entry)
            .map_err(|refusal| refusal.to_string())
    }

    /// A run of instructions, each carrying what its own run of neighbours
    /// shows. Nothing is walked or prepared.
    pub fn listing(&mut self, request: Listing) -> Result<Answer<Vec<Line>>, String> {
        self.start_request();
        self.ensure_decodable()?;
        // A machine it cannot assemble still lists, with no callee parameters and nothing saying what a call clobbers.
        if let Err(reason) = self.ensure_assembled(request.start) {
            r2il::refusal_evidence!("call-effect", "{:#x}: {reason}", request.start);
        }
        Ok(crate::query::listing(
            &self.answered(None),
            request,
            Work::BlockLocal,
            self.revision(),
        ))
    }

    /// One function listed block by block, each line carrying what the
    /// analysis proved about the values it defines.
    ///
    /// By each block's own extent: sweeping from the lowest block to the
    /// highest ran through whatever lay between -- another function's bytes,
    /// or the whole gap to a cold partition placed far away. The blocks and the
    /// def-use are the walked body's, which is what the reference index reads.
    pub fn function_listing(&mut self, entry: u64) -> Result<Answer<Vec<Line>>, String> {
        self.start_request();
        let prepared = self.prepare(entry)?;
        let target = self.target(entry)?;
        let lifted = prepared.lifted();
        let body = WalkedBody::new(&lifted, target.arch);
        let proved = Proved::new(&prepared);
        let answered = Answered {
            body: Some(&body),
            ..self.answered(Some(&proved))
        };
        Ok(listed_by_block(&answered, &lifted, self.revision()))
    }

    /// Every function the program has, from what the container states and
    /// what the bodies reach.
    pub fn functions(&mut self) -> Result<Vec<Discovered>, String> {
        self.start_request();
        Ok(self.surveyed()?.functions)
    }

    /// Every reference the program makes, from every function discovery
    /// believes, with the coverage it was read over; read once per state of the program.
    ///
    /// Each body's blocks are listed as `pdf` lists them and the index is what
    /// those lines claim, in the instruction set discovery walked the body in.
    pub fn references(&mut self) -> Result<Answer<Arc<References>>, String> {
        self.start_request();
        // A callee's body is read in the instruction set discovery settled, so that is settled first.
        self.ensure_decodable()?;
        let revision = self.revision();
        if let Some((at, held)) = &self.references
            && *at == revision
        {
            return Ok(Answer::complete(Arc::clone(held), revision));
        }
        let index = Arc::new(self.indexed(revision)?);
        self.references = Some((revision, Arc::clone(&index)));
        Ok(Answer::complete(index, revision))
    }

    /// Read every believed body's references, at one revision.
    fn indexed(&mut self, revision: crate::query::Revision) -> Result<References, String> {
        let walked = self.surveyed()?.walked;
        let mut index = Indexing::default();
        let mut coverage = Coverage::default();
        // A program that states no function is never assembled, and has nothing to index.
        if walked.is_empty() {
            return Ok(index.finish(coverage));
        }
        let program = &*self;
        let walker = super::returns::Walking::new(program, true)?;
        for (entry, walked) in walked {
            // Each body is lifted as `pdf` walks it, one at a time: discovery kept where control goes and not what it lifted.
            let lifted = walked.and_then(|thumb| {
                let target = walker.target(thumb);
                let body = r2ssa::body::lift_body(entry, target.disasm, program, &BTreeMap::new());
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
            match claimed_by(program, decoder, body.blocks, revision) {
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

    /// Discovery over the whole program, which settles each function's instruction set and whether it returns.
    pub(super) fn surveyed(&mut self) -> Result<Survey, String> {
        self.ensure_current()?;
        let seeds = self.stated_functions();
        let Some(&(first, _, _)) = seeds.first() else {
            return Ok(Survey {
                functions: Vec::new(),
                walked: BTreeMap::new(),
            });
        };
        // Both instruction sets share one convention and one compiler
        // specification, so one assembly serves either decoder.
        self.ensure_assembled(first)?;
        let program = &*self;
        let walker = super::returns::Walking::new(program, true)?;
        let found = crate::discovery::functions(program, seeds, &walker);
        let walked = found
            .walks
            .into_iter()
            .map(|(entry, walk)| (entry, walk.map(|walk| walk.thumb)))
            .collect();
        let at = (self.source.identity(), self.source.byte_revision());
        self.hold_returns(at, found.returns);
        if self.thumb_machine.is_some() {
            let modes = found
                .functions
                .iter()
                .map(|one| (one.address, one.thumb))
                .collect::<BTreeMap<_, _>>();
            self.entries_revision += u64::from(self.modes_at.is_some() && modes != self.modes);
            self.modes = modes;
            self.modes_at = Some(self.source.byte_revision());
        }
        Ok(Survey {
            functions: found.functions,
            walked,
        })
    }

    /// Where the program states a function begins, and whether it states the
    /// code there is Thumb: its entry points, the symbols it types as
    /// functions, and a linkage stub per import, which the loader's own table
    /// places.
    fn stated_functions(&self) -> Vec<(u64, Confidence, bool)> {
        let container = self.source.container();
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
            .chain(self.imports.keys().map(|vaddr| (*vaddr, false)))
            .map(|(vaddr, thumb)| (vaddr, Confidence::Stated, thumb))
            .collect()
    }

    fn answered<'a>(&'a self, proved: Option<&'a Proved<'a>>) -> Answered<'a> {
        Answered {
            decoders: self,
            memory: Memory {
                program: self,
                endian: self.endian(),
            },
            call_effect: self
                .assembled
                .as_ref()
                .and_then(|held| held.call_effect.as_ref()),
            proved,
            body: None,
            holdings: true,
            parameters: Some(self),
        }
    }
}

/// One body listed as the reference index reads it, or why it is unread.
fn claimed_by<S: Source>(
    program: &OpenProgram<S>,
    (target, machine): (
        &crate::native::NativeTarget<'_>,
        &r2sleigh_lift::EmbeddedMachine,
    ),
    blocks: Vec<r2ssa::body::BodyBlock>,
    revision: crate::query::Revision,
) -> Result<Vec<Line>, Unread> {
    let lifted = blocks
        .into_iter()
        .map(|block| block.lifted)
        .collect::<Vec<_>>();
    let body = WalkedBody::new(&lifted, target.arch);
    let answered = Answered {
        decoders: &Walked(machine),
        body: Some(&body),
        holdings: false,
        call_effect: target.call_effect,
        ..program.answered(None)
    };
    let lines = listed_by_block(&answered, &lifted, revision).value;
    // A number whose fate needed the def-use that did not build is unsettled, so the body is unread.
    if body.failed() {
        return Err(Unread::NoSsa);
    }
    Ok(lines)
}
