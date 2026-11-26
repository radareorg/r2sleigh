//! A function's lift run on one recorded entry state: what `r2il::eval` makes of the body `pdd`
//! reads, for the run refuter to set beside the machine's own run (ROADMAP D467).

use std::collections::BTreeMap;

use r2il::eval::{AccessKind, Flow, State, Stop, TransferKind};

use crate::program::{OpenProgram, Source};
use crate::query::records::Decoders;

/// Operations and string elements one replay may execute: a leaf the refuter records runs far
/// fewer, so a run that spends them all is refused, never cut short.
pub const REPLAY_BUDGET: u64 = 1 << 22;

/// One recorded entry state of the function at `entry`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayRequest {
    /// The function's address in the file, as `afl` lists it.
    pub entry: u64,
    /// The machine's address of the image's first byte less the file's: a PIE's load bias.
    pub bias: u64,
    /// Each register the machine held at the entry, by the name the specification gives it.
    pub registers: BTreeMap<String, u128>,
    /// Bytes of memory the machine held at the entry, by the machine's address.
    pub cells: BTreeMap<u64, u8>,
    /// The registers whose values at the return the response states.
    pub results: Vec<String>,
}

/// What the lift did from that state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayResponse {
    /// Each asked register's value at the stop, where every byte of it is known.
    pub results: BTreeMap<String, u128>,
    /// Each address the run wrote, once, in address order, at its widest write's width with the
    /// bytes it holds at the stop; an address in the image is the file's.
    pub writes: Vec<ReplayWrite>,
    pub stop: ReplayStop,
    /// Instructions the run executed.
    pub instructions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayWrite {
    pub address: u64,
    pub bytes: Vec<u8>,
}

/// Why no run was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayRefusal {
    /// The program did not load, as its loader says.
    Unloaded(String),
    /// No decoder holds the entry.
    NoDecoder { entry: u64 },
    /// The specification names no register by this name.
    UnnamedRegister(String),
    /// The register cannot hold the value recorded for it.
    Unheld { register: String, value: u128 },
    /// The entry's body could not be walked.
    Body(crate::body::BodyError),
    /// The program states no byte order the evaluator reads.
    Unordered,
}

/// Why the run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayStop {
    /// A return, to the address the machine named.
    Returned { to: u64 },
    /// A transfer to an instruction the lifted body does not hold.
    LeftBody { at: u64, to: u64 },
    /// A read of a byte the recording does not hold, at the machine's address: a recording adds it.
    Unrecorded { address: u64 },
    /// A read of a register the recording does not state.
    Unstated { at: u64, offset: u64 },
    /// An operation the evaluator does not execute.
    Unmodelled { at: u64 },
    /// A division by zero or another operation with no value.
    Undefined { at: u64 },
    /// The run spent [`REPLAY_BUDGET`].
    Exhausted,
}

/// Run the lift at `request.entry` from the recorded state until it returns; an image address reads
/// the recording at the address plus the bias, any other as is. `O(executed operations)`.
pub fn replay<S: Source + 'static>(
    program: &OpenProgram<S>,
    request: &ReplayRequest,
) -> Result<ReplayResponse, ReplayRefusal> {
    program.loaded().map_err(ReplayRefusal::Unloaded)?;
    let endian = program.endian();
    let image = image_range(program.source().container());
    let machine = Decoders::at(program, request.entry).ok_or(ReplayRefusal::NoDecoder {
        entry: request.entry,
    })?;
    let registers = (machine.arch.registers.iter())
        .map(|register| (register.name.as_str(), (register.offset, register.size)))
        .collect::<BTreeMap<_, _>>();
    let named = |name: &str| {
        (registers.get(name).copied())
            .ok_or_else(|| ReplayRefusal::UnnamedRegister(name.to_owned()))
    };
    // The body `pdd` reads, each instruction with its own lift (no dispatch: the refuter's leaves hold none).
    let (_, decoded) =
        crate::body::listed_body(request.entry, &machine.disasm, program, &BTreeMap::new())
            .map_err(ReplayRefusal::Body)?;
    let instructions = (decoded.iter())
        .map(|one| {
            (
                one.lift.addr,
                (one.lift.ops.as_slice(), u64::from(one.lift.size)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let bias = request.bias;
    let machine_address = |address: u64| match image.contains(&address) {
        true => address.wrapping_add(bias),
        false => address,
    };
    let cells = &request.cells;
    let mapped = |address: u64| cells.get(&machine_address(address)).copied();
    let mut state = State::new(endian, mapped, REPLAY_BUDGET).ok_or(ReplayRefusal::Unordered)?;
    for (name, value) in &request.registers {
        let (offset, size) = named(name)?;
        (state.set_register(offset, size, *value)).map_err(|_| ReplayRefusal::Unheld {
            register: name.clone(),
            value: *value,
        })?;
    }
    let (stop, executed, writes) = run(&instructions, &mut state, request.entry, &machine_address);
    let results = (request.results.iter())
        .filter_map(|name| {
            let (offset, size) = registers.get(name.as_str())?;
            Some((name.clone(), state.register(*offset, *size)?))
        })
        .collect();
    let mut widest = BTreeMap::<u64, u32>::new();
    for access in writes {
        let width = widest.entry(access.address).or_default();
        *width = (*width).max(access.width);
    }
    let writes = (widest.into_iter())
        .map(|(address, width)| {
            let bytes = (0..u64::from(width))
                .filter_map(|at| state.load(address.wrapping_add(at), 1).ok())
                .map(|byte| byte as u8)
                .collect();
            ReplayWrite { address, bytes }
        })
        .collect();
    Ok(ReplayResponse {
        results,
        writes,
        stop,
        instructions: executed,
    })
}

/// Step the lift from `entry` until a return, a transfer out of the body or a stop: the stop, the
/// instructions executed and the writes in order. `O(executed operations)`.
fn run<M: r2il::eval::Mapped>(
    instructions: &BTreeMap<u64, (&[r2il::R2ILOp], u64)>,
    state: &mut State<M>,
    entry: u64,
    machine_address: &dyn Fn(u64) -> u64,
) -> (ReplayStop, u64, Vec<r2il::eval::Access>) {
    let mut pc = entry;
    let mut executed = 0u64;
    let mut writes = Vec::new();
    let stop = loop {
        let Some((ops, size)) = instructions.get(&pc) else {
            break ReplayStop::LeftBody { at: pc, to: pc };
        };
        let flow = r2il::eval::run(ops, state);
        state.end_instruction();
        executed += 1;
        let accesses = state.take_accesses().into_iter();
        writes.extend(accesses.filter(|access| access.kind == AccessKind::Write));
        pc = match flow {
            Flow::Next => pc + size,
            Flow::Transfer(transfer) => match transfer.kind {
                TransferKind::Return => break ReplayStop::Returned { to: transfer.to },
                TransferKind::Jump if instructions.contains_key(&transfer.to) => transfer.to,
                TransferKind::Jump | TransferKind::Call => {
                    break ReplayStop::LeftBody {
                        at: pc,
                        to: transfer.to,
                    };
                }
            },
            Flow::Stop(stop) => break stopped(stop, pc, machine_address),
        };
    };
    (stop, executed, writes)
}

/// The file addresses the image's segments span.
fn image_range(container: &r2abi::statement::Container) -> std::ops::Range<u64> {
    let segments = container
        .segments
        .iter()
        .filter(|segment| segment.vsize > 0);
    let spans = segments.map(|segment| (segment.vaddr, segment.vaddr + segment.vsize));
    let (start, end) = spans.fold((u64::MAX, 0), |(lo, hi), (start, end)| {
        (lo.min(start), hi.max(end))
    });
    start.min(end)..end
}

fn stopped(stop: Stop, at: u64, machine_address: &dyn Fn(u64) -> u64) -> ReplayStop {
    match stop {
        Stop::Unmapped { address } => ReplayStop::Unrecorded {
            address: machine_address(address),
        },
        Stop::Unwritten {
            space: r2il::SpaceId::Register,
            offset,
        } => ReplayStop::Unstated { at, offset },
        Stop::Unwritten { .. } => ReplayStop::Unmodelled { at },
        Stop::Unmodelled => ReplayStop::Unmodelled { at },
        Stop::Undefined => ReplayStop::Undefined { at },
        Stop::Exhausted => ReplayStop::Exhausted,
    }
}
