//! Reading a run of instructions out of the program.
//!
//! The decoder is asked again at every line. ARM states the instruction set
//! per function, in the low bit of the symbol that names it, so a listing that
//! crosses a boundary and kept the decoder it started with decodes the rest of
//! itself wrongly.

use super::records::{Answered, Line, Listing, Stop};
use super::{Answer, Completion, Revision, Work};

/// Sleigh fetches a whole window whatever the instruction needs.
const DECODE_WINDOW: usize = 16;

/// Decode a run of instructions, saying as much about each as `work` allows.
pub fn listing(
    answered: &Answered<'_>,
    request: Listing,
    work: Work,
    revision: Revision,
) -> Answer<Vec<Line>> {
    let mut lines = Vec::new();
    // The lift of each line, kept until the run has been read: whether an
    // instruction's own result is an address or a step towards one is a fact
    // about what the next instruction does with it.
    let mut lifts: Vec<Option<r2il::R2ILBlock>> = Vec::new();
    let mut pc = request.start;
    let mut completion = Completion::Complete;

    while match request.stop {
        Stop::After(count) => lines.len() < count,
        Stop::At(end) => pc < end,
    } {
        let Some(one) = decoded(answered, pc, work) else {
            completion = Completion::Unmapped { at: pc };
            break;
        };
        lines.push(one.line);
        lifts.push(one.lift);
        pc = one.next;
    }

    let mut beyond = Lookahead {
        answered,
        work,
        next: pc,
        open: completion == Completion::Complete,
        tail: Vec::new(),
    };
    super::annotate::over_run(answered, work, &lifts, &mut beyond, &mut lines);
    Answer {
        value: lines,
        revision,
        completion,
    }
}

/// One instruction read at an address, and where the next one begins.
struct Decoded {
    line: Line,
    lift: Option<r2il::R2ILBlock>,
    next: u64,
}

/// Read and spell the instruction at `pc`; `None` where the program maps nothing to read.
fn decoded(answered: &Answered<'_>, pc: u64, work: Work) -> Option<Decoded> {
    let machine = answered.decoders.at(pc)?;
    let window = answered.memory.program.read(pc, DECODE_WINDOW)?;
    // Bytes that do not decode are stepped over by the width this machine
    // addresses instructions at. Stepping one byte puts the next
    // instruction at an odd address on ARM, where none can begin.
    let step = u64::from(machine.arch.alignment.max(1));
    let available = window.len();
    let mut fetch = window;
    fetch.resize(DECODE_WINDOW, 0);

    let decoded = machine
        .disasm
        .disasm_syntax(&fetch, pc)
        .ok()
        .filter(|syntax| syntax.size != 0 && syntax.size <= available);
    let Some(syntax) = decoded else {
        return Some(Decoded {
            line: Line {
                address: pc,
                bytes: fetch[..1].to_vec(),
                syntax: None,
                annotations: Vec::new(),
            },
            lift: None,
            next: pc + step,
        });
    };
    let size = syntax.size;
    // The window is the decoder's, not the instruction's: Sleigh reads the
    // whole of it whatever the instruction needs, and handing it only the
    // bytes the instruction occupies fails the decode just performed.
    let lift = match work {
        Work::Decode => None,
        _ => machine.disasm.lift(&fetch, pc).ok(),
    };
    Some(Decoded {
        line: Line {
            address: pc,
            bytes: fetch[..size].to_vec(),
            syntax: Some(syntax),
            annotations: Vec::new(),
        },
        lift,
        next: pc + size as u64,
    })
}

/// The instructions after the run's last line, lifted only when a line asks.
///
/// Where a listing stops is the reader's choice, not the program's: whether a
/// number the last line computes is a step is decided by what follows it.
pub(super) struct Lookahead<'r, 'a> {
    answered: &'r Answered<'a>,
    work: Work,
    next: u64,
    open: bool,
    tail: Vec<Option<r2il::R2ILBlock>>,
}

impl Lookahead<'_, '_> {
    /// The lift of the `index`th instruction past the run, or `None` where the program stops being one straight line of code.
    pub(super) fn at(&mut self, index: usize) -> Option<Option<&r2il::R2ILBlock>> {
        while self.open && self.tail.len() <= index {
            // Another function's entry is not where this one's value goes.
            let one = (!self.answered.memory.program.is_entry(self.next))
                .then(|| decoded(self.answered, self.next, self.work))
                .flatten();
            let Some(one) = one else {
                self.open = false;
                break;
            };
            self.next = one.next;
            self.tail.push(one.lift);
        }
        self.tail.get(index).map(Option::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Support;
    use crate::query::records::{AnnotationKind, Decoders, Memory};
    use r2il::Endianness;
    use r2sleigh_lift::{EmbeddedMachine, embedded_machine};
    use r2ssa::body::Program;

    /// A flat run of bytes mapped at one address and nothing else.
    struct Mapped {
        base: u64,
        bytes: Vec<u8>,
    }

    impl Program for Mapped {
        fn read(&self, vaddr: u64, max: usize) -> Option<Vec<u8>> {
            let offset = usize::try_from(vaddr.checked_sub(self.base)?).ok()?;
            let rest = self.bytes.get(offset..).filter(|rest| !rest.is_empty())?;
            Some(rest[..max.min(rest.len())].to_vec())
        }

        fn is_entry(&self, _vaddr: u64) -> bool {
            false
        }
    }

    /// One decoder, whatever the address.
    struct Everywhere(EmbeddedMachine);

    impl Decoders for Everywhere {
        fn at(&self, _vaddr: u64) -> Option<&EmbeddedMachine> {
            Some(&self.0)
        }
    }

    const BASE: u64 = 0x1000;

    fn answer(bytes: &[u8], count: usize, work: Work) -> Answer<Vec<Line>> {
        let machine = Everywhere(embedded_machine("x86-64").expect("x86-64 is compiled in"));
        let program = Mapped {
            base: BASE,
            bytes: bytes.to_vec(),
        };
        let answered = Answered {
            decoders: &machine,
            memory: Memory {
                program: &program,
                endian: Endianness::Little,
            },
            facts: None,
        };
        listing(
            &answered,
            Listing {
                start: BASE,
                stop: Stop::After(count),
            },
            work,
            Revision::default(),
        )
    }

    /// ARM below the boundary, Thumb at it and above.
    struct Boundary {
        arm: EmbeddedMachine,
        thumb: EmbeddedMachine,
        at: u64,
    }

    impl Decoders for Boundary {
        fn at(&self, vaddr: u64) -> Option<&EmbeddedMachine> {
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
            arm: embedded_machine("arm").expect("ARM is compiled in"),
            thumb: embedded_machine("arm-thumb").expect("Thumb is compiled in"),
            at: BASE + 4,
        };
        let answered = Answered {
            decoders: &decoders,
            memory: Memory {
                program: &Mapped { base: BASE, bytes },
                endian: Endianness::Little,
            },
            facts: None,
        };
        let answer = listing(
            &answered,
            Listing {
                start: BASE,
                stop: Stop::After(2),
            },
            Work::Decode,
            Revision::default(),
        );
        assert_eq!(answer.value[0].bytes.len(), 4);
        assert_eq!(answer.value[1].address, BASE + 4);
        assert_eq!(answer.value[1].bytes.len(), 2);
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
        assert_eq!(call.kind.address(), BASE + 0x10);
        assert_eq!(call.support, Support::Decoded);
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
                && annotation.support == Support::Decoded
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

    #[test]
    fn a_transfer_before_any_read_or_overwrite_settles_nothing() {
        // mov eax, 0x1234; ret -- the caller may read it, and the run cannot see the caller.
        let answer = answer(&[0xb8, 0x34, 0x12, 0x00, 0x00, 0xc3], 2, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), None);
    }

    #[test]
    fn a_run_that_ends_before_any_read_or_overwrite_settles_nothing() {
        // mov eax, 0x1234, and nothing listed after it.
        let answer = answer(&[0xb8, 0x34, 0x12, 0x00, 0x00, 0xc3], 1, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), None);
    }

    #[test]
    fn a_number_built_on_by_any_byte_is_a_step_not_a_result() {
        // mov eax, 0x1234; add bl, ah; mov eax, 5 -- `ah` is the second byte of `rax`, so
        // the add builds on the value even though no read starts where it does.
        let answer = answer(
            &[
                0xb8, 0x34, 0x12, 0x00, 0x00, 0x00, 0xe3, 0xb8, 0x05, 0x00, 0x00, 0x00,
            ],
            3,
            Work::BlockLocal,
        );
        assert_eq!(computes(&answer.value[0]), None);
    }

    #[test]
    fn a_number_copied_and_then_overwritten_everywhere_is_its_result() {
        // mov eax, 0x1234; mov ecx, eax; cmp ecx, 1; mov eax, 5; mov ecx, 6
        let answer = answer(
            &[
                0xb8, 0x34, 0x12, 0x00, 0x00, 0x89, 0xc1, 0x83, 0xf9, 0x01, 0xb8, 0x05, 0x00, 0x00,
                0x00, 0xb9, 0x06, 0x00, 0x00, 0x00,
            ],
            5,
            Work::BlockLocal,
        );
        assert_eq!(computes(&answer.value[0]), Some(0x1234));
    }

    #[test]
    fn a_number_overwritten_before_any_read_is_still_its_result() {
        // mov eax, 0x1234; mov eax, 5; mov ebx, eax -- the read is of the 5
        let answer = answer(
            &[
                0xb8, 0x34, 0x12, 0x00, 0x00, 0xb8, 0x05, 0x00, 0x00, 0x00, 0x89, 0xc3,
            ],
            3,
            Work::BlockLocal,
        );
        assert_eq!(computes(&answer.value[0]), Some(0x1234));
    }

    #[test]
    fn a_number_partly_overwritten_and_then_built_on_is_a_step() {
        // mov eax, 0x1234; mov al, 5; add ebx, eax -- `al` leaves the rest
        // of the number standing, and the add builds on it.
        let answer = answer(
            &[0xb8, 0x34, 0x12, 0x00, 0x00, 0xb0, 0x05, 0x01, 0xc3],
            3,
            Work::BlockLocal,
        );
        assert_eq!(computes(&answer.value[0]), None);
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
