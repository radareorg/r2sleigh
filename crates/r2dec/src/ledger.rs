//! What became of every obligation the source inventory recorded.
//!
//! The inventory says what a function owes. Rendering discharges some of it,
//! proves some of it needs no output, and fails at the rest. Until now those
//! three answers were counted by walking the inventory at the end and asking
//! whether anything had been proven about each entry, which meant an obligation
//! nothing had an opinion about simply did not appear in any total: a body could
//! report "34 of 43 owned, 0 unsupported" with nine effects missing and no word
//! for them.
//!
//! A ledger cannot lose one. It opens holding every obligation the inventory
//! recorded, each undecided, and the only way an entry leaves that state is for
//! a layer to say what happened to it. Closing the ledger reports all four
//! counts and they sum to the total by construction, so the gap that used to be
//! silent is now a number with a name on it.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use r2ssa::{
    SemanticObligationId, SemanticObligationInventory, SemanticObligationKind, SpelledObligation,
    SsaGraph,
};

/// Why an obligation needed no output for the rendering to be complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ElisionReason {
    /// Frame setup and teardown the rendered function does not model.
    StackFrame,
    /// A stack-protector check the compiler inserted, which passes under `Premise::UbFreeSource`.
    CompilerInserted,
    /// The exact machine control target consumed by a source-certified return.
    ///
    /// This is not the program value returned by the function. The lifted
    /// `Return` operand transports the return address, while source boundary
    /// facts separately certify any semantic return value.
    ReturnControl,
    /// A direct branch target already represented by the sealed CFG topology.
    ///
    /// The target operand is machine control, not a C expression. Conditional
    /// predicates remain ordinary exact uses and are never covered by this
    /// disposition.
    DirectControlTarget,
    /// A direct call's target operand, which the call expression renders by
    /// naming the callee.
    ///
    /// The address of a called function is not an object the program holds. It
    /// is spelled once, in the call itself, so the operand's occurrences are
    /// ordinary rendered uses while the value they name denotes nothing the
    /// function could declare. An indirect call is not covered: there the
    /// target really is a value the program computed and reads.
    DirectCallTarget,
    /// The push that carries a call's return address.
    ///
    /// The structured form spells the call, and the transfer is the call. The
    /// stack write the machine performs to record where to come back to is
    /// bookkeeping the C has no statement for, in the same way a return's own
    /// transfer is.
    CallReturnAddress,
    /// A store into a frame slot this function owns and never reads.
    ///
    /// Writing memory is an effect, but observable means observable from
    /// outside. Where the object is certified to lie wholly inside storage this
    /// function allocated, and every access to it is a write, nothing can read
    /// what was stored and no C statement has to carry it.
    DeadFrameSlotStore,
    /// A store that puts back into its object exactly what the object held.
    ///
    /// A stack probe is the case: `or qword [rsp], 0` reads the slot, leaves
    /// the value alone and writes it back, so the page is touched and memory
    /// ends as it began. The write is an assignment only when it changes what
    /// the variable holds; this one does not, and spelling `x = x` for an
    /// object nothing ever assigned would read an uninitialised variable. The
    /// read it puts back goes with it, since nothing else consumes it.
    MemoryRoundTrip,
    /// A native instruction the lifter decoded to no semantics at all.
    ///
    /// There is nothing for the rendering to emit because the instruction does
    /// nothing. A failed decode produces an `Unimplemented` operation instead,
    /// so this is a positive fact about the instruction and not a way of
    /// saying the effect is unknown.
    NoNativeSemantics,
    /// A write to the stack base that frame handling accounts for instead.
    DeadStackBase,
    /// The content an object already held when the function started.
    ///
    /// A value with no defining instruction was put there by the caller, so no
    /// statement in this function assigns it and none can be expected to. Where
    /// something reads it the read is its occurrence and this does not apply;
    /// this accounts for the entry content nothing in the function observes,
    /// which is what a register the caller happened to leave behind looks like
    /// once the merges that carried it are found to be unobserved.
    CallerSuppliedEntryValue,
    /// The register content an unknown callee left behind, that nothing reads.
    ///
    /// The convention lets the call clobber the carrier and no result
    /// certificate claims it, so no statement here assigns it; where every read
    /// of it is itself elided there is no occurrence to render.
    UnclaimedCallClobber,
}

impl std::fmt::Display for ElisionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::StackFrame => "stack-frame",
            Self::CompilerInserted => "compiler-inserted",
            Self::ReturnControl => "return-control",
            Self::DirectControlTarget => "direct-control-target",
            Self::DirectCallTarget => "direct-call-target",
            Self::CallReturnAddress => "call-return-address",
            Self::DeadFrameSlotStore => "dead-frame-slot-store",
            Self::MemoryRoundTrip => "memory-round-trip",
            Self::NoNativeSemantics => "no-native-semantics",
            Self::DeadStackBase => "dead-stack-base",
            Self::CallerSuppliedEntryValue => "caller-supplied-entry-value",
            Self::UnclaimedCallClobber => "unclaimed-call-clobber",
        })
    }
}

/// What became of one obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// Discharged by output at the obligation's own instruction.
    Rendered,
    /// Proven to need no output.
    Elided(ElisionReason),
    /// Could not be discharged. The obligation's own kind says what it was.
    Refused,
    /// Rendered as an access to a frame object whose extent is assumed (`r2ssa::ExtentAssumption`).
    Assumed,
    /// Covered by a marked gap in the output at this operation site.
    ///
    /// A gap is not a discharge and not a refusal. The renderer could not
    /// prove this cell, said so in the output where a reader and a compiler
    /// both see it, and accounted for the obligations the marker covers. The
    /// closure equation therefore still balances, while
    /// [`LedgerClosure::is_fully_proven`] is false: a gapped function is
    /// rendered, not proven.
    Gapped,
    /// No layer recorded a fate, which is a decompiler defect rather than a property of the input.
    Unattributed,
}

impl Outcome {
    /// Whether a layer has spoken about this obligation.
    pub fn is_decided(self) -> bool {
        !matches!(self, Self::Unattributed)
    }
}

/// What happened when a layer tried to record an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    /// The obligation was undecided and now holds this outcome.
    Accepted,
    /// The obligation already held exactly this outcome.
    Redundant,
    /// The obligation already held a different outcome, which is kept.
    Conflict(Outcome),
    /// No such obligation exists in the inventory this ledger was opened over.
    Unknown,
}

/// How the ledger stands, with every obligation in exactly one column.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerClosure {
    pub total: usize,
    pub rendered: usize,
    pub elided: usize,
    /// Elided as compiler-inserted, under the premise the rendering states.
    pub compiler_inserted: usize,
    /// Rendered as accesses to frame objects whose extent is assumed.
    pub assumed: usize,
    pub refused: usize,
    pub gapped: usize,
    pub unattributed: usize,
    pub conflicts: usize,
}

impl LedgerClosure {
    /// Whether every obligation has an outcome and the columns account for the total.
    pub fn is_closed(&self) -> bool {
        self.unattributed == 0 && self.accounted() == self.total
    }

    /// Whether every obligation was discharged or proven unnecessary.
    ///
    /// A closed ledger with gaps is an honest account of a function the
    /// renderer could not fully prove, which is a weaker statement than this
    /// one and must never be reported as the same thing.
    pub fn is_fully_proven(&self) -> bool {
        self.is_closed()
            && self.gapped == 0
            && self.refused == 0
            && self.assumed == 0
            && self.conflicts == 0
    }

    /// How many obligations the five columns name between them.
    pub fn accounted(&self) -> usize {
        self.rendered
            + self.elided
            + self.compiler_inserted
            + self.assumed
            + self.refused
            + self.gapped
            + self.unattributed
    }
}

/// Every obligation the inventory recorded, and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationLedger {
    outcomes: BTreeMap<SemanticObligationId, Outcome>,
    conflicts: BTreeMap<SemanticObligationId, usize>,
    /// Obligations of definitions whose values were split out of a shared
    /// variable, so that every rendered read sees the value it stands for.
    split: BTreeSet<SemanticObligationId>,
    /// Residual obligations with no site in the text, each with its named cause.
    #[serde(default)]
    /// Every obligation as it is spelled, in the order the spelling reads:
    /// by block, then by an operation's place in it. An obligation names its
    /// operation by identity, so this order is taken from the sealed
    /// function once, when the ledger opens.
    reading_order: Vec<SpelledObligation>,
}

impl ObligationLedger {
    /// Open a ledger over an inventory, with every obligation present and
    /// undecided, spelled against the graph of the function it is about.
    pub fn open(inventory: &SemanticObligationInventory, graph: &SsaGraph) -> Self {
        Self::over(inventory.obligations().keys().copied(), graph)
    }

    /// Open a ledger over a set of obligations, each undecided.
    pub fn over(ids: impl IntoIterator<Item = SemanticObligationId>, graph: &SsaGraph) -> Self {
        let outcomes = ids
            .into_iter()
            .map(|id| (id, Outcome::Unattributed))
            .collect::<BTreeMap<_, _>>();
        let mut reading_order = outcomes
            .keys()
            .map(|id| id.spelled(graph))
            .collect::<Vec<_>>();
        reading_order.sort();
        Self {
            outcomes,
            conflicts: BTreeMap::new(),
            split: BTreeSet::new(),
            reading_order,
        }
    }

    /// Every obligation, spelled, in the order the spelling reads.
    pub fn spelled(&self) -> impl Iterator<Item = &SpelledObligation> {
        self.reading_order.iter()
    }

    /// Say what became of one obligation, keeping the first answer if two disagree.
    pub fn record(&mut self, id: SemanticObligationId, outcome: Outcome) -> Record {
        let Some(slot) = self.outcomes.get_mut(&id) else {
            return Record::Unknown;
        };
        match *slot {
            Outcome::Unattributed => {
                *slot = outcome;
                Record::Accepted
            }
            existing if existing == outcome => Record::Redundant,
            existing => {
                *self.conflicts.entry(id).or_insert(0) += 1;
                Record::Conflict(existing)
            }
        }
    }

    /// Record that several incompatible occurrences answer one obligation.
    ///
    /// The obligation keeps its first outcome so the closure equation still
    /// has one owner for every source cell. The conflict is an independent
    /// admission failure, keyed by that same canonical source identity so a
    /// refusal can name where the incompatible answers occurred.
    /// Name the obligations of definitions split out of a shared variable.
    pub fn mark_split(&mut self, ids: impl IntoIterator<Item = SemanticObligationId>) {
        self.split
            .extend(ids.into_iter().filter(|id| self.outcomes.contains_key(id)));
    }

    /// How many rendered obligations the text discharges through a variable
    /// split out of a shared one: rendered, and rendered only because the
    /// reaching-values check split them.
    pub fn split_rendered(&self) -> usize {
        self.split
            .iter()
            .filter(|id| matches!(self.outcomes.get(id), Some(Outcome::Rendered)))
            .count()
    }

    pub fn record_conflict(&mut self, id: SemanticObligationId) -> Record {
        let Some(existing) = self.outcomes.get(&id).copied() else {
            return Record::Unknown;
        };
        *self.conflicts.entry(id).or_insert(0) += 1;
        Record::Conflict(existing)
    }

    /// Replace an outcome a later layer disproved, without counting it as a conflict.
    pub fn overwrite(&mut self, id: SemanticObligationId, outcome: Outcome) -> Record {
        match self.outcomes.get_mut(&id) {
            Some(slot) => {
                *slot = outcome;
                Record::Accepted
            }
            None => Record::Unknown,
        }
    }

    /// What became of one obligation, or `Unattributed` for anything this ledger does not hold.
    pub fn outcome(&self, id: &SemanticObligationId) -> Outcome {
        self.outcomes
            .get(id)
            .copied()
            .unwrap_or(Outcome::Unattributed)
    }

    /// Every obligation, in the order the spelling reads.
    pub fn entries(&self) -> impl Iterator<Item = (&SemanticObligationId, Outcome)> {
        self.reading_order
            .iter()
            .filter_map(|spelled| self.outcomes.get_key_value(&spelled.id()))
            .map(|(id, outcome)| (id, *outcome))
    }

    /// The obligations no layer spoke about, which is the list of decompiler
    /// defects, in the order the spelling reads.
    pub fn unattributed(&self) -> impl Iterator<Item = &SemanticObligationId> {
        self.entries()
            .filter(|(_, outcome)| !outcome.is_decided())
            .map(|(id, _)| id)
    }

    /// How many undecided obligations there are of each kind.
    pub fn unattributed_by_kind(&self) -> BTreeMap<SemanticObligationKind, usize> {
        let mut counts = BTreeMap::new();
        for id in self.unattributed() {
            *counts.entry(id.kind).or_insert(0usize) += 1;
        }
        counts
    }

    /// Obligations with incompatible answers, in the order the spelling
    /// reads.
    pub fn conflicts(&self) -> impl Iterator<Item = (&SemanticObligationId, usize)> {
        self.reading_order
            .iter()
            .filter_map(|spelled| self.conflicts.get_key_value(&spelled.id()))
            .map(|(id, count)| (id, *count))
    }

    /// The first obligation, in the order the spelling reads, that `wanted`
    /// accepts, spelled.
    pub fn first_spelled(
        &self,
        mut wanted: impl FnMut(&SemanticObligationId, Outcome) -> bool,
    ) -> Option<SpelledObligation> {
        self.reading_order.iter().copied().find(|spelled| {
            self.outcomes
                .get(&spelled.id())
                .is_some_and(|outcome| wanted(&spelled.id(), *outcome))
        })
    }

    /// The first conflicting obligation in the order the spelling reads.
    pub fn first_conflict_spelled(&self) -> Option<SpelledObligation> {
        self.reading_order
            .iter()
            .copied()
            .find(|spelled| self.conflicts.contains_key(&spelled.id()))
    }

    /// How many refusals there are, by the kind of obligation refused.
    pub fn refusals_by_kind(&self) -> BTreeMap<SemanticObligationKind, usize> {
        let mut counts = BTreeMap::new();
        for (id, outcome) in self.entries() {
            if outcome == Outcome::Refused {
                *counts.entry(id.kind).or_insert(0usize) += 1;
            }
        }
        counts
    }

    /// How many elisions there are, by the reason given for each.
    pub fn elisions_by_reason(&self) -> BTreeMap<ElisionReason, usize> {
        let mut counts = BTreeMap::new();
        for (_, outcome) in self.entries() {
            if let Outcome::Elided(reason) = outcome {
                *counts.entry(reason).or_insert(0usize) += 1;
            }
        }
        counts
    }

    /// The whole ledger in one line: the columns, then what is behind each.
    ///
    /// One formatter, so the debug log and whatever asks the engine read the
    /// same breakdown rather than each inventing its own spelling.
    pub fn report(&self) -> String {
        fn ranked<K: std::fmt::Display>(counts: BTreeMap<K, usize>) -> String {
            let mut entries = counts.into_iter().collect::<Vec<_>>();
            // Largest first, and by name where two tie, so the same binary
            // reports the same way twice.
            entries.sort_by(|(left_key, left), (right_key, right)| {
                right
                    .cmp(left)
                    .then_with(|| left_key.to_string().cmp(&right_key.to_string()))
            });
            entries
                .into_iter()
                .map(|(key, count)| format!("{key}={count}"))
                .collect::<Vec<_>>()
                .join(" ")
        }
        let closure = self.close();
        let mut line = format!(
            "total={} rendered={} elided={} refused={} residual={} unaccounted={} conflicts={}",
            closure.total,
            closure.rendered,
            closure.elided,
            closure.refused,
            closure.gapped,
            closure.unattributed,
            closure.conflicts,
        );
        // Only the columns that have something behind them, so a fully proven
        // function reads as one line rather than as a row of empty headings.
        let mut section = |name: &str, body: String| {
            if !body.is_empty() {
                line.push_str(&format!(" | {name}: {body}"));
            }
        };
        section("elided", ranked(self.elisions_by_reason()));
        section(
            "unaccounted-kinds",
            ranked(
                self.unattributed_by_kind()
                    .into_iter()
                    .map(|(kind, count)| (format!("{kind:?}"), count))
                    .collect(),
            ),
        );
        section(
            "refused-kinds",
            ranked(
                self.refusals_by_kind()
                    .into_iter()
                    .map(|(kind, count)| (format!("{kind:?}"), count))
                    .collect(),
            ),
        );
        section(
            "refused-ids",
            self.reading_order
                .iter()
                .filter(|spelled| self.outcomes.get(&spelled.id()) == Some(&Outcome::Refused))
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" "),
        );
        line
    }

    /// Count the ledger into its columns.
    pub fn close(&self) -> LedgerClosure {
        let mut closure = LedgerClosure {
            total: self.outcomes.len(),
            conflicts: self.conflicts.values().sum(),
            ..LedgerClosure::default()
        };
        let trace = r2il::refusal_evidence::tracing();
        for (id, outcome) in &self.outcomes {
            match outcome {
                Outcome::Rendered => closure.rendered += 1,
                Outcome::Assumed => closure.assumed += 1,
                Outcome::Elided(ElisionReason::CompilerInserted) => {
                    closure.compiler_inserted += 1;
                }
                Outcome::Elided(_) => closure.elided += 1,
                Outcome::Refused => {
                    closure.refused += 1;
                    if trace {
                        eprintln!("obligation refused {id:?} {outcome:?}");
                    }
                }
                Outcome::Gapped => {
                    closure.gapped += 1;
                    if trace {
                        eprintln!("obligation gapped {id:?} {outcome:?}");
                    }
                }
                Outcome::Unattributed => {
                    closure.unattributed += 1;
                    if trace {
                        eprintln!("obligation unattributed {id:?}");
                    }
                }
            }
        }
        closure
    }
}

/// Whether the final emission tree satisfied the source effect inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectObligationDisposition {
    Admitted,
    /// Admitted with marked gaps: every obligation is accounted, and the ones
    /// a gap covers were not discharged. The body is rendered, not proven.
    Gapped,
    Refused,
    /// The selected route never entered the native Standard renderer.
    NotRun,
}

/// Stable source-effect tuple exposed independently of binding quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectObligationAudit {
    pub disposition: EffectObligationDisposition,
    pub total: usize,
    pub rendered: usize,
    pub justified_elision: usize,
    pub refused: usize,
    /// Obligations a marked gap accounts for.
    pub gapped: usize,
    pub unaccounted: usize,
    pub conflicts: usize,
    /// First refused obligation in the order the spelling reads, for
    /// diagnostics.
    pub refused_obligation: Option<r2ssa::SpelledObligation>,
    /// First obligation with no occurrence or certificate, for diagnostics.
    pub unaccounted_obligation: Option<r2ssa::SpelledObligation>,
    /// First obligation with incompatible occurrences, for diagnostics.
    pub conflicting_obligation: Option<r2ssa::SpelledObligation>,
}

impl EffectObligationAudit {
    pub const NOT_RUN: Self = Self {
        disposition: EffectObligationDisposition::NotRun,
        total: 0,
        rendered: 0,
        justified_elision: 0,
        refused: 0,
        gapped: 0,
        unaccounted: 0,
        conflicts: 0,
        refused_obligation: None,
        unaccounted_obligation: None,
        conflicting_obligation: None,
    };

    pub fn from_ledger(ledger: &crate::ledger::ObligationLedger) -> Self {
        let closure = ledger.close();
        let admitted = closure.refused == 0
            && closure.unattributed == 0
            && closure.conflicts == 0
            && closure.is_closed();
        Self {
            disposition: match (admitted, closure.gapped) {
                (true, 0) => EffectObligationDisposition::Admitted,
                (true, _) => EffectObligationDisposition::Gapped,
                (false, _) => EffectObligationDisposition::Refused,
            },
            total: closure.total,
            rendered: closure.rendered,
            justified_elision: closure.elided + closure.compiler_inserted,
            refused: closure.refused,
            gapped: closure.gapped,
            unaccounted: closure.unattributed,
            conflicts: closure.conflicts,
            refused_obligation: ledger
                .first_spelled(|_, outcome| matches!(outcome, crate::ledger::Outcome::Refused)),
            unaccounted_obligation: ledger.first_spelled(|_, outcome| !outcome.is_decided()),
            conflicting_obligation: ledger.first_conflict_spelled(),
        }
    }

    /// Whether the body may be emitted: every obligation is accounted for,
    /// with the ones a gap covers marked in the output rather than dropped.
    pub const fn is_admitted(self) -> bool {
        matches!(
            self.disposition,
            EffectObligationDisposition::Admitted | EffectObligationDisposition::Gapped
        )
    }

    /// Whether every obligation was discharged or proven unnecessary.
    pub const fn is_fully_proven(self) -> bool {
        matches!(self.disposition, EffectObligationDisposition::Admitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2ssa::{CanonicalInstructionId, CanonicalInstructionSite, SemanticObligationComponent};

    /// A distinct obligation per `index`: the ledger reads identities, not
    /// what they stand for.
    fn obligation(index: u64, kind: SemanticObligationKind) -> SemanticObligationId {
        SemanticObligationId {
            instruction: CanonicalInstructionId {
                block_addr: 0x1000,
                site: CanonicalInstructionSite::NativeSpan {
                    instruction_addr: 0x1000 + index,
                    size: 1,
                },
            },
            kind,
            component: SemanticObligationComponent::Whole,
        }
    }

    fn ledger_of(ids: &[SemanticObligationId]) -> ObligationLedger {
        // The ids name no operation, so any function spells them the same.
        let mut block = r2il::R2ILBlock::new(0x1000, 4);
        block.push(r2il::R2ILOp::Return {
            target: r2il::Varnode::register(0, 8),
        });
        let artifact =
            r2ssa::SsaArtifact::raw(&[block], None).expect("an artifact to spell against");
        ObligationLedger::over(ids.iter().copied(), artifact.graph())
    }

    #[test]
    fn an_obligation_nothing_speaks_about_stays_visible() {
        let spoken = obligation(0, SemanticObligationKind::ObservableMemoryRead);
        let silent = obligation(1, SemanticObligationKind::LiveValueProducer);
        let mut ledger = ledger_of(&[spoken, silent]);

        ledger.record(spoken, Outcome::Rendered);

        let closure = ledger.close();
        assert_eq!(closure.total, 2);
        assert_eq!(closure.rendered, 1);
        assert_eq!(closure.unattributed, 1);
        assert!(!closure.is_closed());
        assert_eq!(ledger.unattributed().count(), 1);
    }

    #[test]
    fn the_columns_always_account_for_the_total() {
        let ids = [
            obligation(0, SemanticObligationKind::ObservableMemoryRead),
            obligation(1, SemanticObligationKind::ObservableMemoryWrite),
            obligation(2, SemanticObligationKind::Trap),
            obligation(3, SemanticObligationKind::LiveValueProducer),
        ];
        let mut ledger = ledger_of(&ids);

        ledger.record(ids[0], Outcome::Rendered);
        ledger.record(ids[1], Outcome::Elided(ElisionReason::StackFrame));
        ledger.record(ids[2], Outcome::Refused);

        let closure = ledger.close();
        assert_eq!(closure.accounted(), closure.total);
        assert_eq!(
            (closure.rendered, closure.elided, closure.refused),
            (1, 1, 1)
        );
        assert_eq!(closure.unattributed, 1);
    }

    #[test]
    fn a_gapped_obligation_closes_the_ledger_without_proving_it() {
        // A marked gap accounts for its cell: the closure equation balances
        // and nothing is left unattributed, but the function is not proven.
        let ids = [
            obligation(0, SemanticObligationKind::ObservableMemoryRead),
            obligation(1, SemanticObligationKind::Trap),
        ];
        let mut ledger = ledger_of(&ids);
        ledger.record(ids[0], Outcome::Rendered);
        ledger.record(ids[1], Outcome::Gapped);

        let closure = ledger.close();
        assert_eq!(closure.gapped, 1);
        assert_eq!(closure.accounted(), closure.total);
        assert!(closure.is_closed());
        assert!(!closure.is_fully_proven());
        assert_eq!(closure.refused, 0);
    }

    #[test]
    fn a_ledger_with_no_gaps_and_no_refusals_is_fully_proven() {
        let ids = [obligation(0, SemanticObligationKind::LiveValueProducer)];
        let mut ledger = ledger_of(&ids);
        ledger.record(ids[0], Outcome::Elided(ElisionReason::StackFrame));
        assert!(ledger.close().is_fully_proven());
    }

    #[test]
    fn a_second_answer_that_disagrees_is_reported_rather_than_applied() {
        let id = obligation(0, SemanticObligationKind::LiveValueProducer);
        let mut ledger = ledger_of(&[id]);
        let rendered = Outcome::Rendered;

        assert_eq!(ledger.record(id, rendered), Record::Accepted);
        assert_eq!(ledger.record(id, rendered), Record::Redundant);
        assert_eq!(
            ledger.record(id, Outcome::Elided(ElisionReason::StackFrame)),
            Record::Conflict(rendered)
        );

        assert_eq!(ledger.outcome(&id), rendered);
        assert_eq!(ledger.close().conflicts, 1);
    }

    #[test]
    fn taking_back_a_disproven_claim_is_not_a_conflict() {
        let id = obligation(0, SemanticObligationKind::LiveValueProducer);
        let mut ledger = ledger_of(&[id]);
        ledger.record(id, Outcome::Rendered);

        let refused = Outcome::Refused;
        assert_eq!(ledger.overwrite(id, refused), Record::Accepted);

        assert_eq!(ledger.outcome(&id), refused);
        let closure = ledger.close();
        assert_eq!((closure.refused, closure.conflicts), (1, 0));
    }

    #[test]
    fn an_obligation_the_inventory_never_held_is_not_invented() {
        let held = obligation(0, SemanticObligationKind::LiveValueProducer);
        let foreign = obligation(9, SemanticObligationKind::Call);
        let mut ledger = ledger_of(&[held]);

        assert_eq!(ledger.record(foreign, Outcome::Rendered,), Record::Unknown);
        assert_eq!(ledger.close().total, 1);
    }
}
