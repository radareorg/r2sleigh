//! Reading a run of instructions out of the program.
//!
//! The decoder is asked again at every line. ARM states the instruction set
//! per function, in the low bit of the symbol that names it, so a listing that
//! crosses a boundary and kept the decoder it started with decodes the rest of
//! itself wrongly.

use super::records::{Decoders, Line, Listing, Memory};
use super::{Answer, Completion, Revision, Work};

/// Sleigh fetches a whole window whatever the instruction needs.
const DECODE_WINDOW: usize = 16;

/// Decode a run of instructions, saying as much about each as `work` allows.
pub fn listing(
    decoders: &dyn Decoders,
    memory: &Memory<'_>,
    request: Listing,
    work: Work,
    revision: Revision,
) -> Answer<Vec<Line>> {
    let mut lines = Vec::with_capacity(request.count);
    // The lift of each line, kept until the run has been read: whether an
    // instruction's own result is an address or a step towards one is a fact
    // about what the next instruction does with it.
    let mut lifts: Vec<Option<r2il::R2ILBlock>> = Vec::with_capacity(request.count);
    let mut pc = request.start;
    let mut completion = Completion::Complete;

    for _ in 0..request.count {
        let (Some(machine), Some(window)) =
            (decoders.at(pc), memory.program.read(pc, DECODE_WINDOW))
        else {
            completion = Completion::Unmapped { at: pc };
            break;
        };
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
            lines.push(Line {
                address: pc,
                bytes: fetch[..1].to_vec(),
                syntax: None,
                annotations: Vec::new(),
            });
            lifts.push(None);
            pc += step;
            continue;
        };

        let size = syntax.size;
        lines.push(Line {
            address: pc,
            bytes: fetch[..size].to_vec(),
            syntax: Some(syntax),
            annotations: Vec::new(),
        });
        // The window is the decoder's, not the instruction's: Sleigh reads the
        // whole of it whatever the instruction needs, and handing it only the
        // bytes the instruction occupies fails the decode just performed.
        lifts.push(match work {
            Work::Decode => None,
            _ => machine.disasm.lift(&fetch, pc).ok(),
        });
        pc += size as u64;
    }

    super::annotate::over_run(memory, work, &lifts, &mut lines);
    Answer {
        value: lines,
        revision,
        completion,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Support;
    use crate::query::records::AnnotationKind;
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
        let memory = Memory {
            program: &program,
            endian: Endianness::Little,
        };
        listing(
            &machine,
            &memory,
            Listing { start: BASE, count },
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
        let memory = Memory {
            program: &Mapped { base: BASE, bytes },
            endian: Endianness::Little,
        };
        let answer = listing(
            &decoders,
            &memory,
            Listing {
                start: BASE,
                count: 2,
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
    fn reading_past_what_is_mapped_says_so_rather_than_inventing_lines() {
        let answer = answer(&[0xc3], 4, Work::Decode);
        assert_eq!(answer.value.len(), 1);
        assert_eq!(answer.completion, Completion::Unmapped { at: BASE + 1 });
    }
}
