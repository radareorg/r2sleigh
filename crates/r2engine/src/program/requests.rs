//! The questions a caller asks of an open program, each one call.
//!
//! Every command used to sequence these itself: make the tables current,
//! assemble the machine, describe the target, prepare, render. That order is
//! the engine's to keep, so a caller names what it wants and gets it.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{OpenProgram, Source, SymbolKind};
use crate::discovery::{Confidence, Discovered};
use crate::native::{NativeRefusal, Prepared, Survey};
use crate::query::{
    Answer, Answered, Completion, Decoders, DefUse, Line, Listing, Memory, References, Stop,
    Unread, Work,
};
use crate::{EngineDecompileResponse, EngineSession, RenderTier, SealedFunctionAnalysis};

/// A function rendered at one tier, and the analysis it was rendered from.
pub struct Rendering {
    pub prepared: Arc<Prepared>,
    pub response: EngineDecompileResponse,
}

/// One walked body with the target and decoder it was lifted with, or why it could not be walked.
type Surveyed<'t, 'l> = Result<
    (
        &'t crate::native::NativeTarget<'t>,
        &'t r2sleigh_lift::EmbeddedMachine,
        &'l Survey,
    ),
    &'l NativeRefusal,
>;

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
        let read = |sealed: &SealedFunctionAnalysis| {
            super::info::FunctionInfo::read(entry, artifact, sealed.facts())
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
        let fate = DefUse::new(&lifted, target.arch);
        let answered = Answered {
            fate: Some(&fate),
            ..self.answered(Some(&prepared))
        };
        Ok(listed_by_block(&answered, &lifted, self.revision()))
    }

    /// Every function the program has, from what the container states and
    /// what the bodies reach.
    pub fn functions(&mut self) -> Result<Vec<Discovered>, String> {
        self.start_request();
        self.surveyed(|_, _, _| {})
    }

    /// Every reference the program makes, from every function discovery
    /// believes, sorted and without repeats, with the coverage it was read over.
    ///
    /// Each body's blocks are listed as `pdf` lists them and the index is what
    /// those lines claim, in the instruction set discovery walked the body in.
    pub fn references(&mut self) -> Result<Answer<References>, String> {
        self.start_request();
        // A callee's body is read in the instruction set discovery settled, so that is settled first.
        self.ensure_decodable()?;
        let revision = self.revision();
        let mut index = References::default();
        self.surveyed(|program, entry, walked| {
            let (target, machine, survey) = match walked {
                Ok(walked) => walked,
                Err(refusal) => {
                    index
                        .coverage
                        .unread
                        .insert(entry, Unread::Refused(refusal.clone()));
                    return;
                }
            };
            if !survey.unresolved.is_empty() {
                index
                    .coverage
                    .unresolved
                    .insert(entry, survey.unresolved.clone());
            }
            let fate = DefUse::new(&survey.lifted, target.arch);
            let answered = Answered {
                decoders: &Walked(machine),
                fate: Some(&fate),
                spelled: false,
                call_effect: target.call_effect,
                ..program.answered(None)
            };
            let lines = listed_by_block(&answered, &survey.lifted, revision).value;
            // A number whose fate needed the def-use that did not build is unsettled, so the body is unread.
            if fate.failed() {
                index.coverage.unread.insert(entry, Unread::NoSsa);
                return;
            }
            index.coverage.read.push(entry);
            index
                .facts
                .extend(crate::query::references::claimed_by(&lines));
        })?;
        index.coverage.read.sort_unstable();
        index.facts.sort_unstable();
        index.facts.dedup();
        Ok(Answer::complete(index, revision))
    }

    /// Discovery, handing `read` the lift of each body it walked.
    pub(super) fn surveyed(
        &mut self,
        mut read: impl FnMut(&Self, u64, Surveyed<'_, '_>),
    ) -> Result<Vec<Discovered>, String> {
        self.ensure_current()?;
        let seeds = self.stated_functions();
        let Some(&(first, _, _)) = seeds.first() else {
            return Ok(Default::default());
        };
        // Both instruction sets share one convention and one compiler
        // specification, so one assembly serves either decoder.
        self.ensure_assembled(first)?;
        let program = &*self;
        let primary = program.target_of(program.machine_in(false).ok_or("no machine")?)?;
        let thumb = match program.machine_in(true) {
            Some(machine) => Some(program.target_of(machine)?),
            None => None,
        };
        let found = crate::discovery::functions(program, seeds, |entry, in_thumb| {
            let (target, machine) = match (in_thumb, &thumb, program.machine_in(true)) {
                (true, Some(thumb), Some(machine)) => (thumb, machine),
                _ => (&primary, program.machine_in(false)?),
            };
            let survey = crate::native::surveyed(target, program, entry);
            read(
                program,
                entry,
                survey.as_ref().map(|survey| (target, machine, survey)),
            );
            let mut survey = survey.ok()?;
            let transfers = &mut survey.transfers;
            if thumb.is_some() {
                interworking(transfers);
            }
            // A handed constant is a function only where it decodes, in the
            // instruction set it is entered in.
            let entered_in = &transfers.entered_in;
            transfers.handed.retain(|address| {
                let target = match (entered_in.get(address), &thumb) {
                    (Some(true), Some(thumb)) => thumb,
                    _ => &primary,
                };
                crate::native::decodes(target.disasm, program, *address)
            });
            Some(survey.transfers)
        });
        if self.thumb_machine.is_some() {
            let modes = found
                .iter()
                .map(|one| (one.address, one.thumb))
                .collect::<BTreeMap<_, _>>();
            self.entries_revision += u64::from(self.modes_at.is_some() && modes != self.modes);
            self.modes = modes;
            self.modes_at = Some(self.source.byte_revision());
        }
        Ok(found)
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

    fn answered<'a>(&'a self, prepared: Option<&'a Prepared>) -> Answered<'a> {
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
            prepared,
            fate: None,
            spelled: true,
            parameters: Some(self),
        }
    }
}

/// A handed function pointer states its instruction set in its low bit, as
/// `bx` reads it, so the function is at the pointer with that bit clear.
fn interworking(transfers: &mut crate::discovery::Transfers) {
    for pointer in &mut transfers.handed {
        let thumb = *pointer & 1 == 1;
        *pointer &= !1;
        transfers.entered_in.insert(*pointer, thumb);
    }
}
