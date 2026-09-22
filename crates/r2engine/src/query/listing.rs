//! A listing, as records rather than as lines of text.
//!
//! The shell used to build each line by rewriting the decoder's prose seven
//! times and then substituting a name wherever a hexadecimal run happened to
//! equal an address it knew. Both halves of that are answered here instead:
//! the decoder says how the instruction is spelled and where each number in it
//! is written, and the lift says which of those numbers the instruction
//! actually uses as an address. What is left for a caller is column layout.

use r2il::{Endianness, R2ILOp, SpaceId, Varnode};
use r2sleigh_lift::{EmbeddedMachine, NumberSpan, Syntax};
use r2ssa::body::Program;
use r2ssa::origin::{BlockOrigins, ValueOrigin, encoded_target};

use super::{Answer, Completion, Revision, Support, Work};

/// Sleigh fetches a whole window whatever the instruction needs.
const DECODE_WINDOW: usize = 16;

/// Which decoder the code at an address is written in.
///
/// ARM states the instruction set per function, in the low bit of the symbol
/// that names it, so a program has no one decoder and a listing that crosses a
/// boundary decodes the rest of itself wrongly unless it asks again at every
/// line.
pub trait Decoders {
    fn at(&self, vaddr: u64) -> Option<&EmbeddedMachine>;
}

/// The program's own memory, and how it spells a word in it.
///
/// The endianness is the container's and not the decoder's. ARM BE8 is the
/// case that forces them apart: instructions are little-endian there while
/// data is big, so asking the Sleigh specification which way a pool word reads
/// gives the wrong answer on exactly the binaries that have pool words.
pub struct Memory<'a> {
    pub program: &'a dyn Program,
    pub endian: Endianness,
}

impl Memory<'_> {
    /// The value this revision holds at an address, where it holds one.
    fn word(&self, address: u64, width: u32) -> Option<u64> {
        let width = usize::try_from(width)
            .ok()
            .filter(|width| (1..=8).contains(width))?;
        let read = self
            .program
            .read(address, width)
            .filter(|read| read.len() == width)?;
        let mut bytes = [0u8; 8];
        bytes[..width].copy_from_slice(&read);
        Some(match self.endian {
            Endianness::Little => u64::from_le_bytes(bytes),
            Endianness::Big => u64::from_be_bytes(bytes) >> (8 * (8 - width as u32)),
            // Nothing says which way a word reads here, so nothing is claimed.
            Endianness::Mixed | Endianness::Custom => return None,
        })
    }
}

/// A run of instructions, asked for by where it starts and how many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listing {
    pub start: u64,
    pub count: usize,
}

/// One line of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub address: u64,
    /// The bytes this line accounts for: the whole instruction, or the single
    /// byte that did not begin one.
    pub bytes: Vec<u8>,
    /// How the decoder spells it. Absent where the bytes are not an instruction.
    pub syntax: Option<Syntax>,
    pub annotations: Vec<Annotation>,
}

impl Line {
    /// Whether the bytes decoded at all.
    pub fn decoded(&self) -> bool {
        self.syntax.is_some()
    }
}

/// Something the engine can say about one instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    pub kind: AnnotationKind,
    pub support: Support,
    /// Which number in the operand body this is about, where exactly one of
    /// them spells it. Two operands holding the same value leave this empty
    /// rather than guessing which was meant.
    pub operand: Option<NumberSpan>,
}

/// What one annotation claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationKind {
    /// The instruction encodes a transfer of control to this address.
    Target { address: u64, call: bool },
    /// The instruction reads this many bytes at this address.
    Reads { address: u64, width: u32 },
    /// The instruction writes this many bytes at this address.
    Writes { address: u64, width: u32 },
    /// The revision this answer names holds this value at that address.
    ///
    /// Not "the load returns it". Nothing here says the bytes will still be
    /// these when the instruction runs, and saying so would be the one claim
    /// a listing cannot support.
    Holds {
        address: u64,
        width: u32,
        value: u64,
    },
}

impl AnnotationKind {
    /// The address this claim is about.
    pub fn address(self) -> u64 {
        match self {
            Self::Target { address, .. }
            | Self::Reads { address, .. }
            | Self::Writes { address, .. }
            | Self::Holds { address, .. } => address,
        }
    }
}

/// Decode a run of instructions, saying as much about each as `work` allows.
pub fn listing(
    decoders: &dyn Decoders,
    memory: &Memory<'_>,
    request: Listing,
    work: Work,
    revision: Revision,
) -> Answer<Vec<Line>> {
    let mut lines = Vec::with_capacity(request.count);
    let mut pc = request.start;

    for _ in 0..request.count {
        let (Some(machine), Some(window)) =
            (decoders.at(pc), memory.program.read(pc, DECODE_WINDOW))
        else {
            return Answer {
                value: lines,
                revision,
                completion: Completion::Unmapped { at: pc },
            };
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
            pc += step;
            continue;
        };

        let size = syntax.size;
        let annotations = match work {
            Work::Decode => Vec::new(),
            _ => instruction_local(machine, memory, &fetch, pc, &syntax),
        };
        lines.push(Line {
            address: pc,
            bytes: fetch[..size].to_vec(),
            syntax: Some(syntax),
            annotations,
        });
        pc += size as u64;
    }
    Answer::complete(lines, revision)
}

/// What one instruction's own lift says about the addresses it touches.
///
/// Lifting is the whole point: a number in the operands is an address because
/// the instruction transfers to it or reads it, not because it looks like one.
/// The window is the decoder's, not the instruction's: Sleigh reads the whole
/// of it whatever the instruction needs, and handing it only the bytes the
/// instruction occupies fails the decode it just performed.
fn instruction_local(
    machine: &EmbeddedMachine,
    memory: &Memory<'_>,
    window: &[u8],
    address: u64,
    syntax: &Syntax,
) -> Vec<Annotation> {
    let Ok(block) = machine.disasm.lift(window, address) else {
        return Vec::new();
    };
    let mut origins = BlockOrigins::default();
    let mut kinds: Vec<AnnotationKind> = Vec::new();
    for op in &block.ops {
        for kind in touched(&origins, op) {
            if !kinds.contains(&kind) {
                kinds.push(kind);
            }
        }
        origins.step(op);
    }
    // What a read finds there is a fact about this revision, so it is said
    // beside the read rather than folded into it.
    for index in 0..kinds.len() {
        let AnnotationKind::Reads { address, width } = kinds[index] else {
            continue;
        };
        let Some(value) = memory.word(address, width) else {
            continue;
        };
        kinds.push(AnnotationKind::Holds {
            address,
            width,
            value,
        });
    }
    kinds
        .into_iter()
        .map(|kind| Annotation {
            kind,
            support: Support::Folded,
            operand: sole_operand(syntax, kind.address()),
        })
        .collect()
}

/// The addresses one operation names, as far as the block so far shows.
fn touched(origins: &BlockOrigins, op: &R2ILOp) -> Vec<AnnotationKind> {
    let folded = |addr: &Varnode| origins.of(addr).and_then(ValueOrigin::constant);
    let mut found = Vec::new();
    match op {
        R2ILOp::Branch { target } | R2ILOp::CBranch { target, .. } => found.extend(
            encoded_target(target).map(|address| AnnotationKind::Target {
                address,
                call: false,
            }),
        ),
        R2ILOp::Call { target } => {
            found.extend(
                encoded_target(target).map(|address| AnnotationKind::Target {
                    address,
                    call: true,
                }),
            )
        }
        R2ILOp::Load {
            dst,
            space: SpaceId::Ram,
            addr,
        } => found.extend(folded(addr).map(|address| AnnotationKind::Reads {
            address,
            width: dst.size,
        })),
        R2ILOp::Store {
            space: SpaceId::Ram,
            addr,
            val,
        } => found.extend(folded(addr).map(|address| AnnotationKind::Writes {
            address,
            width: val.size,
        })),
        _ => {}
    }
    found
}

/// The one number in the operands that spells this address, where there is one.
fn sole_operand(syntax: &Syntax, address: u64) -> Option<NumberSpan> {
    let mut spelling = syntax
        .numbers
        .iter()
        .filter(|number| number.value == i128::from(address));
    let found = spelling.next()?;
    spelling.next().is_none().then_some(*found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2sleigh_lift::embedded_machine;

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
        assert_eq!(call.support, Support::Folded);
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
