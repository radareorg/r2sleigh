//! Reading a run of instructions out of the program.
//!
//! The decoder is asked again at every line. ARM states the instruction set
//! per function, in the low bit of the symbol that names it, so a listing that
//! crosses a boundary and kept the decoder it started with decodes the rest of
//! itself wrongly.

use r2sleigh_lift::Continuation;

use super::records::{
    Answered, Instruction, Line, Listing, Register, Registers, Semantics, Stop, Unexpressed,
    Unlifted,
};
use super::{Answer, Completion, Work};

/// Sleigh fetches a whole window whatever the instruction needs.
const DECODE_WINDOW: usize = 16;

/// Decode a run of instructions, saying as much about each as `work` allows.
///
/// A line keeps the decoder context the line before it left, as the walk does; a run's first line starts afresh.
pub fn listing(answered: &Answered<'_>, request: Listing, work: Work) -> Answer<Vec<Line>> {
    let run = annotated(answered, request, work);
    Answer {
        value: run.lines,
        completion: run.completion,
    }
}

/// A run read and annotated as a listing of it says.
fn annotated(answered: &Answered<'_>, request: Listing, work: Work) -> Run {
    let mut run = Run::read(answered, request, work);
    let mut beyond = Lookahead {
        answered,
        next: run.next,
        context: run.context,
        open: run.completion == Completion::Complete,
        tail: Vec::new(),
    };
    let lifted = super::annotate::Run {
        lifts: &run.lifts,
        windows: &run.windows,
    };
    super::annotate::over_run(answered, work, &lifted, &mut beyond, &mut run.lines);
    run
}

/// A run of instructions, each with what its operations read, write and are, read and annotated
/// as a listing at `work` reads it, so `ao` and `pd` say the same of one address.
pub fn instructions(
    answered: &Answered<'_>,
    request: Listing,
    work: Work,
) -> Answer<Vec<Instruction>> {
    let run = annotated(answered, request, work.max(Work::InstructionLocal));
    let value = run
        .lines
        .into_iter()
        .zip(run.lifts.into_iter().zip(run.windows))
        .map(|(line, (lift, window))| {
            let machine = answered.decoders.at(line.address);
            let semantics = match (lift.zip(machine), &line.syntax, window) {
                (Some((lift, machine)), ..) => Ok(stated(&lift, machine)),
                (None, None, _) => Err(Unlifted::Undecoded),
                (None, Some(_), None) => Err(Unlifted::UnstatedField),
                (None, Some(_), Some(_)) => Err(Unlifted::NotLifted),
            };
            Instruction { line, semantics }
        })
        .collect();
    Answer {
        value,
        completion: run.completion,
    }
}

/// What one lifted instruction reads, writes and is, named by the lift.
fn stated(lift: &r2il::R2ILBlock, machine: &crate::machine::Machine) -> Semantics {
    let named = |ranges: Vec<r2il::Varnode>| {
        r2il::join_tiles(ranges, |whole| machine.disasm.declares_register(whole))
            .into_iter()
            .map(|storage| Register {
                name: machine.disasm.register_listed(&storage),
                storage,
            })
            .collect()
    };
    Semantics {
        registers: r2il::register_accesses(&lift.ops, |vn| machine.disasm.hides_register(vn))
            .map(|accesses| Registers {
                reads: named(accesses.reads),
                writes: named(accesses.writes),
            })
            .ok_or(Unexpressed::Unimplemented),
        operations: crate::native::spelled_operations(&machine.arch, &lift.ops),
    }
}

/// The lines of one run, before anything is said about them.
struct Run {
    lines: Vec<Line>,
    /// The lift of each line, kept until the run has been read: whether an
    /// instruction's own result is an address or a step towards one is a fact
    /// about what the next instruction does with it.
    lifts: Vec<Option<r2il::R2ILBlock>>,
    /// The bytes each line decoded from, which lifting again a page further on reads too.
    windows: Vec<Option<Vec<u8>>>,
    completion: Completion,
    /// Where reading stopped.
    next: u64,
    /// Where the last line left the decoder's context.
    context: Option<Continuation>,
}

impl Run {
    fn read(answered: &Answered<'_>, request: Listing, work: Work) -> Self {
        let mut run = Self {
            lines: Vec::new(),
            lifts: Vec::new(),
            windows: Vec::new(),
            completion: Completion::Complete,
            next: request.start,
            context: None,
        };
        while match request.stop {
            Stop::After(count) => run.lines.len() < count,
            Stop::At(end) => run.next < end,
        } {
            // Every listed line is spelled, so a line Sleigh spells but cannot lift is still listed whole.
            let Some(one) = decoded(answered, run.next, true, run.context) else {
                run.completion = Completion::Unmapped { at: run.next };
                break;
            };
            run.lines.push(one.line);
            // A decode-only request lifts only to commit the context the next line reads.
            run.lifts.push(one.lift.filter(|_| work > Work::Decode));
            run.windows.push(one.window);
            run.next = one.next;
            run.context = one.context;
        }
        run
    }
}

/// One instruction read at an address, and where the next one begins.
struct Decoded {
    line: Line,
    lift: Option<r2il::R2ILBlock>,
    /// The decode window it was read from, where it decoded.
    window: Option<Vec<u8>>,
    next: u64,
    /// Where it left the decoder's context, for the line after it.
    context: Option<Continuation>,
}

/// Read the instruction at `pc`, spelled and lifted from one parse or only lifted; `None` where the program maps nothing to read.
fn decoded(
    answered: &Answered<'_>,
    pc: u64,
    spell: bool,
    after: Option<Continuation>,
) -> Option<Decoded> {
    let machine = answered.decoders.at(pc)?;
    let window = answered.memory.program.read(pc, DECODE_WINDOW)?;
    // Bytes that do not decode are stepped over by the width this machine
    // addresses instructions at. Stepping one byte puts the next
    // instruction at an odd address on ARM, where none can begin.
    let step = u64::from(machine.arch.alignment.max(1));
    let available = window.len();
    // The bytes the loader leaves: a field it writes decodes as the value it writes.
    let endian = machine.disasm.arch_spec().memory_endianness;
    let program = answered.memory.program;
    let code = crate::stated::code(program.loader_writes(), pc, window, endian);
    let mut fetch = code.bytes.clone();
    fetch.resize(DECODE_WINDOW, 0);

    // The window is the decoder's, not the instruction's: Sleigh reads the
    // whole of it whatever the instruction needs, and handing it only the
    // bytes the instruction occupies fails the decode just performed.
    let (syntax, lift, context) = match spell {
        // A line Sleigh spells is listed whole, lifted or not.
        true => machine.disasm.decode(&fetch, pc, after).map_or_else(
            |_| (None, None, None),
            |one| (Some(one.syntax), one.lifted.ok(), one.continuation),
        ),
        false => machine.disasm.lift_after(&fetch, pc, after).map_or_else(
            |_| (None, None, None),
            |one| (None, Some(one.block), Some(one.continuation)),
        ),
    };
    let size = match (&syntax, &lift) {
        (Some(syntax), _) => syntax.size,
        (None, Some(lift)) => usize::try_from(lift.size).unwrap_or(0),
        (None, None) => 0,
    };
    // A field whose value the container does not state is listed as encoded, and nothing is read from it (audit W5).
    let stated = !code.unstated(&(pc..pc + size as u64));
    let lift = lift.filter(|_| stated);
    let flow = lift.as_ref().map(r2sleigh_lift::flow::of);
    if size == 0 || size > available {
        let stepped = usize::try_from(step).map_or(1, |step| step.clamp(1, available.max(1)));
        return Some(Decoded {
            line: Line {
                address: pc,
                bytes: fetch[..stepped].to_vec(),
                syntax: None,
                flow: None,
                annotations: Vec::new(),
            },
            lift: None,
            window: None,
            next: pc + step,
            context: None,
        });
    }
    Some(Decoded {
        line: Line {
            address: pc,
            bytes: fetch[..size].to_vec(),
            syntax,
            flow,
            annotations: Vec::new(),
        },
        lift,
        window: stated.then_some(fetch),
        next: pc + size as u64,
        context,
    })
}

/// Lift a run's decoded lines as one straight line, `offset` further on than they are.
pub(super) fn lift_run(
    answered: &Answered<'_>,
    lines: &[Line],
    windows: &[Option<Vec<u8>>],
    offset: u64,
) -> Vec<Option<r2il::R2ILBlock>> {
    let mut context = None;
    lines
        .iter()
        .zip(windows)
        .map(|(line, window)| {
            let lifted = answered
                .decoders
                .at(line.address)
                .zip(window.as_deref())
                .and_then(|(machine, window)| {
                    let at = line.address.wrapping_add(offset);
                    machine.disasm.lift_after(window, at, context).ok()
                });
            context = lifted.as_ref().map(|one| one.continuation);
            lifted.map(|one| one.block)
        })
        .collect()
}

/// The instructions after the run's last line, lifted only when a line asks.
///
/// Where a listing stops is the reader's choice, not the program's: where a number the last line computes goes is read past it.
pub(super) struct Lookahead<'r, 'a> {
    answered: &'r Answered<'a>,
    next: u64,
    /// Where the last instruction read left the decoder's context.
    context: Option<Continuation>,
    open: bool,
    tail: Vec<Option<r2il::R2ILBlock>>,
}

impl Lookahead<'_, '_> {
    /// The lift of the `index`th instruction past the run, or `None` where the program stops being one straight line of code.
    pub(super) fn at(&mut self, index: usize) -> Option<Option<&r2il::R2ILBlock>> {
        while self.open && self.tail.len() <= index {
            // Another function's entry is not where this one's value goes.
            let one = (!self.answered.memory.program.is_entry(self.next))
                .then(|| decoded(self.answered, self.next, false, self.context))
                .flatten();
            let Some(one) = one else {
                self.open = false;
                break;
            };
            self.next = one.next;
            self.context = one.context;
            self.tail.push(one.lift);
        }
        self.tail.get(index).map(Option::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::Program;
    use crate::machine::Machine;
    use crate::query::records::{AnnotationKind, Decoders, Memory, WalkedBody};
    use r2il::Endianness;
    use r2sleigh_lift::embedded_machine;
    use r2source::confidence::Basis;

    /// A flat run of bytes mapped at one address and nothing else.
    struct Mapped {
        base: u64,
        bytes: Vec<u8>,
        extents: r2types::ProgramExtents,
    }

    impl Mapped {
        fn new(base: u64, bytes: Vec<u8>) -> Self {
            let end = base + bytes.len() as u64;
            Self {
                base,
                bytes,
                extents: r2types::ProgramExtents::new([(base, end)]),
            }
        }
    }

    impl Program for Mapped {
        fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
            let offset = usize::try_from(vaddr.checked_sub(self.base)?).ok()?;
            let rest = self.bytes.get(offset..).filter(|rest| !rest.is_empty())?;
            Some(rest[..max.min(rest.len())].to_vec())
        }

        /// The one run of bytes is code.
        fn region(&self, vaddr: u64) -> Option<crate::body::Region> {
            let end = self.base + self.bytes.len() as u64;
            (self.base..end)
                .contains(&vaddr)
                .then_some(crate::body::Region {
                    start: self.base,
                    end,
                    file_end: end,
                    execute: true,
                    write: false,
                })
        }

        fn is_entry(&self, _vaddr: u64) -> bool {
            false
        }
    }

    /// The one run of bytes is the one section the program loads.
    impl crate::native::Program for Mapped {
        fn name_at(&self, _vaddr: u64) -> Option<String> {
            None
        }

        fn holds_static_data(&self, _vaddr: u64) -> bool {
            false
        }

        fn extents(&self) -> &r2types::ProgramExtents {
            &self.extents
        }

        fn import_at(&self, _vaddr: u64) -> Option<String> {
            None
        }
    }

    /// One decoder, whatever the address.
    struct Everywhere(Machine);

    impl Decoders for Everywhere {
        fn at(&self, _vaddr: u64) -> Option<&Machine> {
            Some(&self.0)
        }
    }

    const BASE: u64 = 0x1000;

    fn answer(bytes: &[u8], count: usize, work: Work) -> Answer<Vec<Line>> {
        let machine = Everywhere(Machine::new(
            embedded_machine("x86-64").expect("x86-64 is compiled in"),
        ));
        let program = Mapped::new(BASE, bytes.to_vec());
        let answered = Answered {
            decoders: &machine,
            memory: Memory {
                program: &program,
                endian: Endianness::Little,
            },
            call_effect: None,
            proved: None,
            body: None,
            holdings: true,
            parameters: None,
        };
        listing(
            &answered,
            Listing {
                start: BASE,
                stop: Stop::After(count),
            },
            work,
        )
    }

    /// ARM below the boundary, Thumb at it and above.
    struct Boundary {
        arm: Machine,
        thumb: Machine,
        at: u64,
    }

    impl Decoders for Boundary {
        fn at(&self, vaddr: u64) -> Option<&Machine> {
            Some(match vaddr < self.at {
                true => &self.arm,
                false => &self.thumb,
            })
        }
    }

    #[test]
    fn a_listing_that_crosses_an_instruction_set_asks_again() {
        // `mov r0, #0` in ARM, then `movs r0, #0` in Thumb. Decoding the
        // second with the ARM machine reads four bytes and spells something
        // else, which is what one decoder chosen at the start would do.
        let mut bytes = vec![0x00, 0x00, 0xa0, 0xe3, 0x00, 0x20];
        bytes.resize(32, 0);
        let decoders = Boundary {
            arm: Machine::new(embedded_machine("arm").expect("ARM is compiled in")),
            thumb: Machine::new(embedded_machine("arm-thumb").expect("Thumb is compiled in")),
            at: BASE + 4,
        };
        let answered = Answered {
            decoders: &decoders,
            memory: Memory {
                program: &Mapped::new(BASE, bytes),
                endian: Endianness::Little,
            },
            call_effect: None,
            proved: None,
            body: None,
            holdings: true,
            parameters: None,
        };
        let answer = listing(
            &answered,
            Listing {
                start: BASE,
                stop: Stop::After(2),
            },
            Work::Decode,
        );
        assert_eq!(answer.value[0].bytes.len(), 4);
        assert_eq!(answer.value[1].address, BASE + 4);
        assert_eq!(answer.value[1].bytes.len(), 2);
    }

    #[test]
    fn every_line_is_lifted_as_the_body_walk_lifts_it() {
        // cmp r0, #0; it eq; moveq r0, #1; bx lr -- the `it` predicates the move.
        let mut bytes = vec![0x00, 0x28, 0x08, 0xbf, 0x01, 0x20, 0x70, 0x47];
        bytes.resize(32, 0);
        let program = Mapped::new(BASE, bytes);
        let thumb = Everywhere(Machine::new(
            embedded_machine("arm-thumb").expect("Thumb is compiled in"),
        ));
        let body = crate::body::lift_body(BASE, &thumb.0.disasm, &program, &Default::default())
            .expect("the body walks");
        let mut walked = std::collections::BTreeMap::<u64, Vec<r2il::R2ILOp>>::new();
        for lifted in body.blocks.iter().map(|block| &block.lifted) {
            for (index, op) in lifted.ops.iter().enumerate() {
                let at = lifted.instruction_of(index);
                walked
                    .entry(at.expect("stamped"))
                    .or_default()
                    .push(op.clone());
            }
        }
        // A spelled run reads the context the walk's lift-only decode read.
        let answered = Answered {
            decoders: &thumb,
            memory: Memory {
                program: &program,
                endian: Endianness::Little,
            },
            proved: None,
            body: None,
            holdings: true,
            call_effect: None,
            parameters: None,
        };
        let request = Listing {
            start: BASE,
            stop: Stop::After(4),
        };
        let run = Run::read(&answered, request, Work::InstructionLocal);
        for (line, lift) in run.lines.iter().zip(&run.lifts) {
            let listed: &Vec<r2il::R2ILOp> = &lift.as_ref().expect("each lifts").ops;
            assert_eq!(
                Some(listed),
                walked.get(&line.address),
                "{:#x}",
                line.address
            );
        }
    }

    #[test]
    fn a_run_of_instructions_comes_back_as_records() {
        // push rbp; mov rbp, rsp; ret
        let answer = answer(&[0x55, 0x48, 0x89, 0xe5, 0xc3], 3, Work::Decode);
        assert!(answer.is_complete());
        let spelled: Vec<String> = answer
            .value
            .iter()
            .map(|line| line.syntax.as_ref().expect("each decoded").text())
            .collect();
        assert_eq!(spelled, ["push rbp", "mov rbp, rsp", "ret"]);
        assert_eq!(answer.value[1].address, BASE + 1);
        assert_eq!(answer.value[1].bytes, [0x48, 0x89, 0xe5]);
    }

    #[test]
    fn decoding_alone_claims_nothing_about_an_address() {
        let answer = answer(&[0xe8, 0x0b, 0, 0, 0], 1, Work::Decode);
        assert!(answer.value[0].annotations.is_empty());
    }

    #[test]
    fn lifting_one_instruction_says_where_a_call_goes() {
        let answer = answer(&[0xe8, 0x0b, 0, 0, 0], 1, Work::InstructionLocal);
        let line = &answer.value[0];
        let call = line
            .annotations
            .iter()
            .find(|annotation| matches!(annotation.kind, AnnotationKind::Target { call: true, .. }))
            .expect("a direct call encodes its target");
        assert_eq!(call.kind.address(), Some(BASE + 0x10));
        assert_eq!(call.support, Basis::Decoded);
        let body = &line.syntax.as_ref().expect("decoded").body;
        let span = call.operand.expect("one operand spells that address");
        assert_eq!(&body[span.start..span.end], "0x1010");
    }

    #[test]
    fn a_jump_says_where_it_goes_and_that_it_is_no_call() {
        // jmp 0x1010; je 0x1010
        let answer = answer(&[0xeb, 0x0e, 0x74, 0x0c], 2, Work::InstructionLocal);
        for line in &answer.value {
            assert!(line.annotations.iter().any(|annotation| annotation.kind
                == AnnotationKind::Target {
                    address: BASE + 0x10,
                    call: false,
                }));
        }
    }

    #[test]
    fn an_absolute_memory_operand_is_the_read_it_performs() {
        // mov rax, qword [0x1234]
        let answer = answer(
            &[0x48, 0x8b, 0x04, 0x25, 0x34, 0x12, 0x00, 0x00],
            1,
            Work::InstructionLocal,
        );
        let read = answer.value[0]
            .annotations
            .iter()
            .find(|annotation| matches!(annotation.kind, AnnotationKind::Reads { .. }))
            .expect("the operand names the address it reads");
        assert_eq!(
            read.kind,
            AnnotationKind::Reads {
                address: 0x1234,
                width: 8,
            }
        );
    }

    #[test]
    fn an_absolute_memory_destination_is_the_write_it_performs() {
        // mov dword [0x1234], eax
        let answer = answer(
            &[0x89, 0x04, 0x25, 0x34, 0x12, 0x00, 0x00],
            1,
            Work::InstructionLocal,
        );
        assert!(answer.value[0].annotations.iter().any(|annotation| {
            annotation.kind
                == AnnotationKind::Writes {
                    address: 0x1234,
                    width: 4,
                }
                && annotation.support == Basis::Decoded
        }));
    }

    #[test]
    fn what_this_revision_holds_at_a_read_is_said_beside_the_read() {
        // mov rax, qword [0x1234], with a word actually mapped there.
        let mut bytes = vec![0x48, 0x8b, 0x04, 0x25, 0x34, 0x12, 0x00, 0x00];
        bytes.resize(0x234, 0);
        bytes.extend_from_slice(&0xdead_beefu64.to_le_bytes());
        let answer = answer(&bytes, 1, Work::InstructionLocal);
        assert!(answer.value[0].annotations.iter().any(|annotation| {
            annotation.kind
                == AnnotationKind::Holds {
                    address: 0x1234,
                    width: 8,
                    value: 0xdead_beef,
                }
        }));
    }

    #[test]
    fn a_read_of_what_is_not_mapped_claims_no_value() {
        let answer = answer(
            &[0x48, 0x8b, 0x04, 0x25, 0x34, 0x12, 0x00, 0x00],
            1,
            Work::InstructionLocal,
        );
        assert!(
            !answer.value[0]
                .annotations
                .iter()
                .any(|annotation| matches!(annotation.kind, AnnotationKind::Holds { .. }))
        );
    }

    fn computes(line: &Line) -> Option<u64> {
        line.annotations
            .iter()
            .find_map(|annotation| match annotation.kind {
                AnnotationKind::Computes { value } => Some(value),
                _ => None,
            })
    }

    /// `lea rax, [rip + 0x10]`, which computes where the program itself is.
    const LEA: [u8; 7] = [0x48, 0x8d, 0x05, 0x10, 0x00, 0x00, 0x00];
    /// What that `lea` computes at `BASE`, inside what `mapped` maps.
    const LEA_VALUE: u64 = BASE + 7 + 0x10;

    /// The bytes, padded so the numbers these tests compute are addresses the program maps.
    fn mapped(bytes: &[u8]) -> Vec<u8> {
        let mut bytes = bytes.to_vec();
        bytes.resize(0x40, 0xcc);
        bytes
    }

    fn after_lea(rest: &[u8]) -> Vec<u8> {
        mapped(&LEA.iter().chain(rest).copied().collect::<Vec<_>>())
    }

    #[test]
    fn a_formed_address_is_claimed_before_a_transfer() {
        // lea rax, [rip + 0x10]; ret -- the instruction forms the address whatever the caller does with it.
        let answer = answer(&after_lea(&[0xc3]), 2, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), Some(LEA_VALUE));
    }

    #[test]
    fn a_formed_address_is_claimed_where_the_run_ends() {
        // lea rax, [rip + 0x10], and nothing listed after it.
        let answer = answer(&after_lea(&[0xc3]), 1, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), Some(LEA_VALUE));
    }

    #[test]
    fn a_formed_address_stands_when_something_builds_on_it() {
        // lea; add bl, ah; mov eax, 5 -- the add reads the address's second byte, and the lea still forms it.
        let bytes = after_lea(&[0x00, 0xe3, 0xb8, 0x05, 0x00, 0x00, 0x00]);
        let answer = answer(&bytes, 3, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), Some(LEA_VALUE));
    }

    #[test]
    fn a_number_copied_and_then_overwritten_everywhere_is_its_result() {
        // lea; mov ecx, eax; cmp ecx, 1; mov eax, 5; mov ecx, 6
        let bytes = after_lea(&[
            0x89, 0xc1, 0x83, 0xf9, 0x01, 0xb8, 0x05, 0x00, 0x00, 0x00, 0xb9, 0x06, 0x00, 0x00,
            0x00,
        ]);
        let answer = answer(&bytes, 5, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), Some(LEA_VALUE));
    }

    #[test]
    fn a_number_overwritten_before_any_read_is_still_its_result() {
        // lea; mov eax, 5; mov ebx, eax -- the read is of the 5
        let bytes = after_lea(&[0xb8, 0x05, 0x00, 0x00, 0x00, 0x89, 0xc3]);
        let answer = answer(&bytes, 3, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), Some(LEA_VALUE));
    }

    #[test]
    fn a_formed_address_stands_when_it_is_partly_overwritten_and_built_on() {
        // lea; mov al, 5; add ebx, eax
        let answer = answer(&after_lea(&[0xb0, 0x05, 0x01, 0xc3]), 3, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), Some(LEA_VALUE));
    }

    #[test]
    fn two_addresses_a_subtraction_differences_are_each_formed() {
        // lea rdi, [rip + 0x10]; lea rsi, [rip + 0x09]; sub rsi, rdi -- ada_test_dwarf's register_tm_clones.
        let bytes = mapped(&[
            0x48, 0x8d, 0x3d, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x35, 0x09, 0x00, 0x00, 0x00,
            0x48, 0x29, 0xfe,
        ]);
        let answer = answer(&bytes, 3, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), Some(BASE + 7 + 0x10));
        assert_eq!(computes(&answer.value[1]), Some(BASE + 14 + 0x09));
    }

    #[test]
    fn a_table_base_an_indexed_call_reads_through_is_formed() {
        // lea r15, [rip + 0x20]; call [r15 + rbx*8] -- __libc_csu_init.
        let bytes = mapped(&[
            0x4c, 0x8d, 0x3d, 0x20, 0x00, 0x00, 0x00, 0x41, 0xff, 0x14, 0xdf,
        ]);
        let answer = answer(&bytes, 2, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), Some(BASE + 7 + 0x20));
    }

    #[test]
    fn a_number_that_stays_put_when_the_program_moves_is_no_address() {
        // mov eax, 0x1017; mov eax, 5; mov ebx, eax -- the number the `lea` above
        // computes, mapped and a result alike, but lifted a page on it is still 0x1017.
        let bytes = mapped(&[
            0xb8, 0x17, 0x10, 0x00, 0x00, 0xb8, 0x05, 0x00, 0x00, 0x00, 0x89, 0xc3,
        ]);
        let answer = answer(&bytes, 3, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), None);
    }

    /// What each line of AArch64 code at `BASE` claims, listed in one run at `work` inside the body walked from `BASE`.
    fn aarch64_claims(code: &[u8], work: Work) -> Vec<Vec<AnnotationKind>> {
        let machine = Everywhere(Machine::new(
            embedded_machine("aarch64").expect("AArch64 is compiled in"),
        ));
        // Mapped far enough that the page and the address in it are the program's.
        let mut image = code.to_vec();
        image.resize(0x1100, 0);
        let program = Mapped::new(BASE, image);
        let walked = crate::body::lift_body(BASE, &machine.0.disasm, &program, &Default::default());
        let blocks = walked.expect("it walks").blocks.into_iter();
        let blocks = blocks.map(|block| block.lifted).collect::<Vec<_>>();
        let body = WalkedBody::new(&blocks, machine.0.tables());
        let answered = Answered {
            decoders: &machine,
            memory: Memory {
                program: &program,
                endian: Endianness::Little,
            },
            proved: None,
            body: Some(&body),
            holdings: true,
            call_effect: None,
            parameters: None,
        };
        let request = Listing {
            start: BASE,
            stop: Stop::At(BASE + code.len() as u64),
        };
        let lines = listing(&answered, request, work).value;
        let kinds = |line: &Line| {
            line.annotations
                .iter()
                .map(|one| one.kind.clone())
                .collect()
        };
        lines.iter().map(kinds).collect()
    }

    #[test]
    fn a_page_is_claimed_where_formed_and_its_address_where_the_block_carries_it_on() {
        // adrp x0, 0x2000; add x0, x0, #0x50; ldr x0, [x0]; ret
        let code = [
            0x00, 0x00, 0x00, 0xb0, 0x00, 0x40, 0x01, 0x91, 0x00, 0x00, 0x40, 0xf9, 0xc0, 0x03,
            0x5f, 0xd6,
        ];
        // A run entered anywhere knows nothing of `x0` at the add: the page is claimed where `adrp` forms it, the rest unknown.
        let run = aarch64_claims(&code, Work::BlockLocal);
        assert_eq!(run[0], [AnnotationKind::Computes { value: 0x2000 }]);
        assert!(run[1..].iter().all(Vec::is_empty), "{run:?}");
        // A block carries the page into the add, whose sum moves a page with the program and is read through.
        let block = aarch64_claims(&code, Work::Function);
        let address = 0x2050;
        assert_eq!(block[0], [AnnotationKind::Computes { value: 0x2000 }]);
        assert_eq!(block[1], [AnnotationKind::Computes { value: address }]);
        assert!(
            block[2].contains(&AnnotationKind::Reads { address, width: 8 }),
            "{block:?}"
        );
    }

    #[test]
    fn a_function_run_folds_nothing_into_a_block_another_path_enters() {
        // cbz x1, L; adrp x0, 0x2000; L: add x0, x0, #0x50; ldr x0, [x0]; ret
        let code = [
            0x41, 0x00, 0x00, 0xb4, 0x00, 0x00, 0x00, 0xb0, 0x00, 0x40, 0x01, 0x91, 0x00, 0x00,
            0x40, 0xf9, 0xc0, 0x03, 0x5f, 0xd6,
        ];
        // One run over every block: L is entered from the cbz with `x0` as the caller left it, so nothing at L names the page's address.
        let lines = aarch64_claims(&code, Work::Function);
        assert_eq!(lines.len(), 5, "{lines:?}");
        assert!(lines[2..].iter().all(Vec::is_empty), "{lines:?}");
    }

    #[test]
    fn a_function_run_folds_nothing_into_a_line_past_the_body() {
        // adrp x0, 0x2000; ret; add x0, x0, #0x50; ldr x0, [x0] -- the walk ends at the ret, so the body is one block.
        let code = [
            0x00, 0x00, 0x00, 0xb0, 0xc0, 0x03, 0x5f, 0xd6, 0x00, 0x40, 0x01, 0x91, 0x00, 0x00,
            0x40, 0xf9,
        ];
        // The run lists past the ret, and no path of the body reaches what it lists there.
        let lines = aarch64_claims(&code, Work::Function);
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[2..].iter().all(Vec::is_empty), "{lines:?}");
    }

    #[test]
    fn a_conditional_load_reads_the_address_it_names() {
        // ldreq r3, [pc, 0x10] -- lifted as a guarded load, which reads when the condition holds.
        let mut bytes = vec![0x10, 0x30, 0x9f, 0x05];
        bytes.resize(0x40, 0);
        let machine = Everywhere(Machine::new(
            embedded_machine("arm").expect("ARM is compiled in"),
        ));
        let program = Mapped::new(BASE, bytes);
        let answered = Answered {
            decoders: &machine,
            memory: Memory {
                program: &program,
                endian: Endianness::Little,
            },
            proved: None,
            body: None,
            holdings: true,
            call_effect: None,
            parameters: None,
        };
        let request = Listing {
            start: BASE,
            stop: Stop::After(1),
        };
        let line = &listing(&answered, request, Work::InstructionLocal).value[0];
        assert!(
            line.annotations.iter().any(|annotation| annotation.kind
                == AnnotationKind::Reads {
                    address: BASE + 8 + 0x10,
                    width: 4,
                }),
            "{:?}",
            line.annotations
        );
    }

    #[test]
    fn bytes_that_are_not_an_instruction_are_one_byte_and_no_spelling() {
        // 0x06 encodes nothing in long mode; the `ret` after it still decodes.
        let answer = answer(&[0x06, 0xc3], 2, Work::Decode);
        assert!(!answer.value[0].decoded());
        assert_eq!(answer.value[0].bytes, [0x06]);
        assert_eq!(answer.value[1].address, BASE + 1);
        assert_eq!(
            answer.value[1].syntax.as_ref().expect("decoded").text(),
            "ret"
        );
    }

    #[test]
    fn an_instruction_cut_off_by_the_end_of_what_is_mapped_is_not_one() {
        // 48 8b begins `mov rax, [rax]`, whose third byte is not mapped; the
        // zero padding the decoder is handed must not complete it.
        let answer = answer(&[0x48, 0x8b], 1, Work::Decode);
        assert!(!answer.value[0].decoded());
        assert_eq!(answer.value[0].bytes, [0x48]);
    }

    #[test]
    fn reading_past_what_is_mapped_says_so_rather_than_inventing_lines() {
        let answer = answer(&[0xc3], 4, Work::Decode);
        assert_eq!(answer.value.len(), 1);
        assert_eq!(answer.completion, Completion::Unmapped { at: BASE + 1 });
    }
}
