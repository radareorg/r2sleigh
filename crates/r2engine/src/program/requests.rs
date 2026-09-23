//! The questions a caller asks of an open program, each one call.
//!
//! Every command used to sequence these itself: make the tables current,
//! assemble the machine, describe the target, prepare, render. That order is
//! the engine's to keep, so a caller names what it wants and gets it.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::{OpenProgram, Source, SymbolKind};
use crate::discovery::{Confidence, Discovered};
use crate::native::Prepared;
use crate::query::{Answer, Answered, Completion, Line, Listing, Memory, Stop, Work};
use crate::{DataRefFact, EngineDecompileResponse, RenderTier};

/// A function rendered at one tier, and the analysis it was rendered from.
pub struct Rendering {
    pub prepared: Arc<Prepared>,
    pub response: EngineDecompileResponse,
}

/// What discovery found, and the references each body it walked makes.
type Surveyed = (Vec<Discovered>, BTreeMap<u64, Vec<DataRefFact>>);

impl<S: Source> OpenProgram<S> {
    /// One function's analysis, done once per state of this program.
    pub fn prepared(&mut self, entry: u64) -> Result<Arc<Prepared>, String> {
        self.ensure_decodable()?;
        self.ensure_assembled(entry)?;
        let target = self.target(entry)?;
        self.analysed(&target, entry)
            .map_err(|refusal| refusal.to_string())
    }

    /// One function rendered at one tier.
    pub fn rendered(&mut self, entry: u64, tier: RenderTier) -> Result<Rendering, String> {
        let prepared = self.prepared(entry)?;
        let target = self.target(entry)?;
        let response = crate::native::rendered(&target, entry, tier, &prepared, &self.control);
        Ok(Rendering { prepared, response })
    }

    /// The operations Sleigh produced for one function, before any analysis.
    pub fn lifted(&mut self, entry: u64) -> Result<String, String> {
        self.ensure_decodable()?;
        self.ensure_assembled(entry)?;
        crate::native::lifted(&self.target(entry)?, self, entry)
            .map_err(|refusal| refusal.to_string())
    }

    /// A run of instructions, each carrying what its own run of neighbours
    /// shows. Nothing is walked or prepared.
    pub fn listing(&mut self, request: Listing) -> Result<Answer<Vec<Line>>, String> {
        self.ensure_decodable()?;
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
    /// or the whole gap to a cold partition placed far away.
    pub fn function_listing(&mut self, entry: u64) -> Result<Answer<Vec<Line>>, String> {
        let prepared = self.prepared(entry)?;
        let artifact = prepared.artifact().artifact();
        let mut blocks = artifact
            .function()
            .blocks()
            .iter()
            .filter(|block| block.size > 0)
            .map(|block| (block.addr, block.addr + u64::from(block.size)))
            .collect::<Vec<_>>();
        blocks.sort_unstable();
        let answered = self.answered(Some(artifact));
        let mut whole = Answer::complete(Vec::new(), self.revision());
        for (start, end) in blocks {
            let answer = crate::query::listing(
                &answered,
                Listing {
                    start,
                    stop: Stop::At(end),
                },
                Work::Function,
                whole.revision,
            );
            whole.value.extend(answer.value);
            if whole.completion == Completion::Complete {
                whole.completion = answer.completion;
            }
        }
        Ok(whole)
    }

    /// Every function the program has, from what the container states and
    /// what the bodies reach.
    pub fn functions(&mut self) -> Result<Vec<Discovered>, String> {
        Ok(self.surveyed()?.0)
    }

    /// Every reference the program makes, from every function discovery
    /// believes, sorted and without repeats.
    ///
    /// Discovery walks every body it believes and the index wants what that
    /// same walk saw, so both come from one walk per function.
    pub fn references(&mut self) -> Result<Vec<DataRefFact>, String> {
        let (found, mut seen) = self.surveyed()?;
        let mut refs = found
            .iter()
            .filter_map(|one| seen.remove(&one.address))
            .flatten()
            .collect::<Vec<_>>();
        refs.sort_unstable();
        refs.dedup();
        Ok(refs)
    }

    /// Discovery, and the references each body it walked makes.
    pub(super) fn surveyed(&mut self) -> Result<Surveyed, String> {
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
        let mut seen = BTreeMap::new();
        let found = crate::discovery::functions(program, seeds, |entry, in_thumb| {
            let target = match (in_thumb, &thumb) {
                (true, Some(thumb)) => thumb,
                _ => &primary,
            };
            let mut survey = crate::native::surveyed(target, program, entry)?;
            seen.insert(entry, survey.data_refs);
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
            self.entries_revision += u64::from(modes != self.modes);
            self.modes = modes;
            self.modes_at = Some(self.source.byte_revision());
        }
        Ok((found, seen))
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

    fn answered<'a>(&'a self, facts: Option<&'a r2ssa::SsaArtifact>) -> Answered<'a> {
        Answered {
            decoders: self,
            memory: Memory {
                program: self,
                endian: self.endian(),
            },
            facts,
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
