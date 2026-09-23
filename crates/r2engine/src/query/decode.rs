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
    // The bytes each line decoded from, which lifting again a page further on reads too.
    let mut windows: Vec<Option<Vec<u8>>> = Vec::new();
    let mut straight = Straight::default();
    let mut pc = request.start;
    let mut completion = Completion::Complete;

    while match request.stop {
        Stop::After(count) => lines.len() < count,
        Stop::At(end) => pc < end,
    } {
        let Some(one) = decoded(answered, pc, answered.spelled, &mut straight) else {
            completion = Completion::Unmapped { at: pc };
            break;
        };
        lines.push(one.line);
        lifts.push(one.lift);
        windows.push(one.window);
        pc = one.next;
    }
    // Spelling starts the decoder afresh at every line, so a spelled run is lifted in a pass of its own.
    if answered.spelled && work > Work::Decode {
        lifts = lift_run(answered, &lines, &windows, 0);
    }

    let mut beyond = Lookahead {
        answered,
        next: pc,
        open: completion == Completion::Complete,
        straight: Straight::default(),
        tail: Vec::new(),
    };
    let run = super::annotate::Run {
        lifts: &lifts,
        windows: &windows,
    };
    super::annotate::over_run(answered, work, &run, &mut beyond, &mut lines);
    Answer {
        value: lines,
        revision,
        completion,
    }
}

/// One instruction read at an address, and where the next one begins.
struct Decoded {
    line: Line,
    /// Its lift, where the line was read without being spelled.
    lift: Option<r2il::R2ILBlock>,
    /// The decode window it was read from, where it decoded.
    window: Option<Vec<u8>>,
    next: u64,
}

/// Read the instruction at `pc`, spelled or lifted; `None` where the program maps nothing to read.
fn decoded(
    answered: &Answered<'_>,
    pc: u64,
    spell: bool,
    straight: &mut Straight,
) -> Option<Decoded> {
    let machine = answered.decoders.at(pc)?;
    let window = answered.memory.program.read(pc, DECODE_WINDOW)?;
    // Bytes that do not decode are stepped over by the width this machine
    // addresses instructions at. Stepping one byte puts the next
    // instruction at an odd address on ARM, where none can begin.
    let step = u64::from(machine.arch.alignment.max(1));
    let available = window.len();
    let mut fetch = window;
    fetch.resize(DECODE_WINDOW, 0);

    // The window is the decoder's, not the instruction's: Sleigh reads the
    // whole of it whatever the instruction needs, and handing it only the
    // bytes the instruction occupies fails the decode just performed.
    let (syntax, lift) = match spell {
        true => (machine.disasm.disasm_syntax(&fetch, pc).ok(), None),
        false => (None, straight.lift(machine, &fetch, pc)),
    };
    let size = match (&syntax, &lift) {
        (Some(syntax), _) => syntax.size,
        (None, Some(lift)) => usize::try_from(lift.size).unwrap_or(0),
        (None, None) => 0,
    };
    if size == 0 || size > available {
        straight.end = None;
        return Some(Decoded {
            line: Line {
                address: pc,
                bytes: fetch[..1].to_vec(),
                syntax: None,
                annotations: Vec::new(),
            },
            lift: None,
            window: None,
            next: pc + step,
        });
    }
    Some(Decoded {
        line: Line {
            address: pc,
            bytes: fetch[..size].to_vec(),
            syntax,
            annotations: Vec::new(),
        },
        lift,
        window: Some(fetch),
        next: pc + size as u64,
    })
}

/// Where the last lift of one straight line ended, and on which decoder.
///
/// A lift that follows on keeps the decoder's context, as the walk's does, so
/// Thumb's `it` reaches the instructions it predicates; one that does not
/// starts afresh, which also drops whatever Sleigh cached by address for a
/// lift at an address the bytes are not at.
#[derive(Default)]
struct Straight {
    end: Option<(*const r2sleigh_lift::EmbeddedMachine, u64)>,
}

impl Straight {
    fn lift(
        &mut self,
        machine: &r2sleigh_lift::EmbeddedMachine,
        window: &[u8],
        at: u64,
    ) -> Option<r2il::R2ILBlock> {
        let lifted = match self.end == Some((std::ptr::from_ref(machine), at)) {
            true => machine.disasm.lift_continuing(window, at),
            false => machine.disasm.lift(window, at),
        }
        .ok();
        self.end = lifted.as_ref().map(|one| {
            (
                std::ptr::from_ref(machine),
                at.wrapping_add(u64::from(one.size)),
            )
        });
        lifted
    }
}

/// Lift a run's decoded lines as one straight line, `offset` further on than they are.
pub(super) fn lift_run(
    answered: &Answered<'_>,
    lines: &[Line],
    windows: &[Option<Vec<u8>>],
    offset: u64,
) -> Vec<Option<r2il::R2ILBlock>> {
    let mut straight = Straight::default();
    lines
        .iter()
        .zip(windows)
        .map(|(line, window)| {
            let (Some(machine), Some(window)) =
                (answered.decoders.at(line.address), window.as_deref())
            else {
                straight.end = None;
                return None;
            };
            straight.lift(machine, window, line.address.wrapping_add(offset))
        })
        .collect()
}

/// The instructions after the run's last line, lifted only when a line asks.
///
/// Where a listing stops is the reader's choice, not the program's: whether a
/// number the last line computes is a step is decided by what follows it.
pub(super) struct Lookahead<'r, 'a> {
    answered: &'r Answered<'a>,
    next: u64,
    open: bool,
    straight: Straight,
    tail: Vec<Option<r2il::R2ILBlock>>,
}

impl Lookahead<'_, '_> {
    /// The lift of the `index`th instruction past the run, or `None` where the program stops being one straight line of code.
    pub(super) fn at(&mut self, index: usize) -> Option<Option<&r2il::R2ILBlock>> {
        while self.open && self.tail.len() <= index {
            // Another function's entry is not where this one's value goes.
            let one = (!self.answered.memory.program.is_entry(self.next))
                .then(|| decoded(self.answered, self.next, false, &mut self.straight))
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
    struct Everywhere(EmbeddedMachine);

    impl Decoders for Everywhere {
        fn at(&self, _vaddr: u64) -> Option<&EmbeddedMachine> {
            Some(&self.0)
        }
    }

    const BASE: u64 = 0x1000;

    fn answer(bytes: &[u8], count: usize, work: Work) -> Answer<Vec<Line>> {
        let machine = Everywhere(embedded_machine("x86-64").expect("x86-64 is compiled in"));
        let program = Mapped::new(BASE, bytes.to_vec());
        let answered = Answered {
            decoders: &machine,
            memory: Memory {
                program: &program,
                endian: Endianness::Little,
            },
            facts: None,
            fate: None,
            spelled: true,
            clobbered: &[],
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
                program: &Mapped::new(BASE, bytes),
                endian: Endianness::Little,
            },
            facts: None,
            fate: None,
            spelled: true,
            clobbered: &[],
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
    fn a_transfer_before_any_read_or_overwrite_settles_nothing() {
        // lea rax, [rip + 0x1234]; ret -- the caller may read it, and the run cannot see the caller.
        let answer = answer(&after_lea(&[0xc3]), 2, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), None);
    }

    #[test]
    fn a_run_that_ends_before_any_read_or_overwrite_settles_nothing() {
        // lea rax, [rip + 0x1234], and nothing listed after it.
        let answer = answer(&after_lea(&[0xc3]), 1, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), None);
    }

    #[test]
    fn a_number_built_on_by_any_byte_is_a_step_not_a_result() {
        // lea; add bl, ah; mov eax, 5 -- `ah` is the second byte of `rax`, so
        // the add builds on the value even though no read starts where it does.
        let bytes = after_lea(&[0x00, 0xe3, 0xb8, 0x05, 0x00, 0x00, 0x00]);
        let answer = answer(&bytes, 3, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), None);
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
    fn a_number_partly_overwritten_and_then_built_on_is_a_step() {
        // lea; mov al, 5; add ebx, eax -- `al` leaves the rest of the number
        // standing, and the add builds on it.
        let answer = answer(&after_lea(&[0xb0, 0x05, 0x01, 0xc3]), 3, Work::BlockLocal);
        assert_eq!(computes(&answer.value[0]), None);
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

    #[test]
    fn a_page_and_its_offset_are_one_address_only_where_the_block_carries_one_into_the_other() {
        // adrp x0, 0x2000; add x0, x0, #0x50; ldr x0, [x0]; ret
        let bytes = [
            0x00, 0x00, 0x00, 0xb0, 0x00, 0x40, 0x01, 0x91, 0x00, 0x00, 0x40, 0xf9, 0xc0, 0x03,
            0x5f, 0xd6,
        ];
        let machine = Everywhere(embedded_machine("aarch64").expect("AArch64 is compiled in"));
        // Mapped far enough that the page and the address in it are the program's.
        let mut image = bytes.to_vec();
        image.resize(0x1100, 0);
        let program = Mapped::new(BASE, image);
        let answered = Answered {
            decoders: &machine,
            memory: Memory {
                program: &program,
                endian: Endianness::Little,
            },
            facts: None,
            fate: None,
            spelled: true,
            clobbered: &[],
        };
        let listed = |work| {
            let request = Listing {
                start: BASE,
                stop: Stop::After(4),
            };
            listing(&answered, request, work, Revision::default()).value
        };
        let claims = |lines: &[Line]| {
            lines
                .iter()
                .map(|line| {
                    let kinds = line.annotations.iter().map(|annotation| annotation.kind);
                    kinds.collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        // A run entered anywhere knows nothing of `x0` at the add: the page is a step, the rest unknown.
        let run = claims(&listed(Work::BlockLocal));
        assert!(run.iter().all(Vec::is_empty), "{run:?}");
        // A block carries the page into the add, whose sum moves a page with the program and is read through.
        let block = claims(&listed(Work::Function));
        let address = 0x2050;
        assert_eq!(block[0], []);
        assert_eq!(block[1], [AnnotationKind::Computes { value: address }]);
        assert!(
            block[2].contains(&AnnotationKind::Reads { address, width: 8 }),
            "{block:?}"
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
