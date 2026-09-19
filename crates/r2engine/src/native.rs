//! Decompiling a function with no radare2 anywhere.
//!
//! This is the whole native route in one place: walk the body out of the
//! program's bytes, state the machine from the convention data and the
//! compiler specification, mint a capture, and hand it to the same trusted
//! lift and the same request the plugin uses. Nothing downstream of the
//! capture is new, and nothing here formats anything.
//!
//! The callees a function calls directly are walked too, one level deep, and
//! their bodies are what say what each call takes and returns. Deeper than one
//! level is what an interprocedural fixpoint is for, and this is not one.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use r2abi::{CompilerSpec, Convention, Prototypes};
use r2il::ArchSpec;
use r2sleigh_lift::Disassembler;
use r2source::{
    CanonicalStorageId, CanonicalStorageSpace, SourceConventionSlots, SourceDataObject,
    SourceEndianness, SourceMachineRoles, SourceRoleRegisterNames, SourceStackAllocationContract,
    SourceStackGrowth,
    native::{NativeBlock, NativeCall, NativeFunction, NativeMachine},
};
use r2ssa::body::{BodyError, lift_body};
use r2ssa::{CalleePreservedCarriers, SummaryArgumentReach, TrustedSsaArtifact};

use crate::{
    CalleeFacts, EngineDecompileResponse, EngineFunctionDecompileRequestInput, EngineFunctionInput,
    EngineFunctionInputQuality, EngineSession,
};

/// The program being analysed, as the engine needs to see it.
///
/// Two questions and no cursor: what byte lives at an address, and what the
/// program calls one. Whoever opened the binary answers them.
pub trait Program: r2ssa::body::Program {
    /// What the program calls this address, where it names it at all.
    fn name_at(&self, vaddr: u64) -> Option<String>;

    /// The import this address stands for, where the binary says it is one.
    ///
    /// Asked of the binary rather than guessed from a name: a program that
    /// defines its own `strlen` carries a body there, and rendering that
    /// against the library's declaration would be a claim it never made.
    fn import_at(&self, vaddr: u64) -> Option<String>;
}

/// Everything about the machine that does not change between functions.
pub struct NativeTarget<'a> {
    pub arch: &'a ArchSpec,
    pub disasm: &'a Disassembler,
    /// The convention every function is assumed to use, which is the one the
    /// data declares as the default until something says otherwise.
    pub convention: &'a Convention,
    pub compiler: &'a CompilerSpec,
    /// What the library functions this program calls take and return. An
    /// import has no body to read an interface off, so without this a call to
    /// one renders with no arguments at all.
    pub prototypes: &'a Prototypes,
}

/// Why a native decompile could not be attempted.
///
/// These are all refusals to start. Once the request is built, a function the
/// engine cannot prove comes back as a rendered refusal rather than as an
/// error here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeRefusal {
    Body(BodyError),
    /// The compiler specification named no stack pointer, so nothing can say
    /// where the frame is.
    NoStackPointer,
    /// A register the machine data names is not one this architecture has.
    UnknownRegister(String),
    /// The carriers or the convention slots are not a machine this engine can
    /// describe.
    Machine(&'static str),
    Capture(r2source::SnapshotValidationError),
    Lift(String),
    Prepare(String),
}

impl std::fmt::Display for NativeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Body(error) => write!(f, "{error}"),
            Self::NoStackPointer => write!(f, "the compiler specification names no stack pointer"),
            Self::UnknownRegister(name) => write!(f, "this architecture has no register {name}"),
            Self::Machine(what) => write!(f, "the machine cannot be described: {what}"),
            Self::Capture(error) => write!(f, "{error}"),
            Self::Lift(error) | Self::Prepare(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for NativeRefusal {}

/// Decompile the function at `entry`.
pub fn decompile(
    target: &NativeTarget<'_>,
    program: &dyn Program,
    entry: u64,
) -> Result<EngineDecompileResponse, NativeRefusal> {
    let native = Native {
        target,
        program,
        machine: machine(target)?,
        control: crate::EngineExecutionControl::default().ssa_execution_control(),
    };
    let root = native.walk(entry)?;
    let ptr_bits = crate::engine_effective_ptr_bits(target.arch);

    // What a call takes and returns is a fact about the callee's body, so the
    // bodies it calls are walked first and the root is prepared against them.
    // A callee that cannot be walked leaves its call unproven rather than
    // failing the root.
    let mut callees = Callees::default();
    // An import has no body here to read an interface off, so its declared
    // prototype is placed in the convention's own slots and stands in for one,
    // and the same declaration states the C signature the call renders with.
    let mut declared = Vec::new();
    // A tail jump reaches another function exactly as a call does; the only
    // difference is that its result is this function's own.
    let targets: Vec<u64> = root
        .body
        .calls
        .iter()
        .chain(root.body.tail_calls.iter())
        .copied()
        .collect();
    for address in &targets {
        let Some(name) = native.program.import_at(*address) else {
            continue;
        };
        let Some(prototype) = target.prototypes.get(&name) else {
            continue;
        };
        let Some(interface) = declared_interface(prototype, &native.machine, ptr_bits) else {
            continue;
        };
        if let Some(signature) = function_type(prototype, ptr_bits)
            && let Some(declaration) = r2types::SourceOwnedCalleeSignature::declared(
                *address,
                interface.clone(),
                signature,
                ptr_bits,
            )
        {
            declared.push(declaration);
        }
        callees.interfaces.insert(*address, interface);
    }
    let mut facts = Vec::new();
    // A stub is not a body: walking one recovers an interface with no
    // parameters, which would displace the declaration that has them.
    let bodies: Vec<u64> = targets
        .iter()
        .copied()
        .filter(|address| *address != entry && !callees.interfaces.contains_key(address))
        .collect();
    for address in &bodies {
        let Ok(walked) = native.walk(*address) else {
            continue;
        };
        let Ok(artifact) = native.prepare(&walked, &Callees::default()) else {
            continue;
        };
        // The interface is what the callee's body proves about its boundary,
        // and a callee whose whole preparation cannot be certified still
        // proved that much. Taking it keeps the call rendered as a call.
        if let Some(interface) = artifact
            .shared_artifact()
            .machine_context()
            .function_interface()
        {
            callees.interfaces.insert(*address, interface.clone());
        }
        let Some(derived) = CalleeFacts::derive(&artifact, ptr_bits) else {
            continue;
        };
        callees.record(*address, &derived);
        facts.push(derived);
    }

    let first = native.prepare(&root, &callees)?;
    // A second capture states what the first proved. Preparation recovers the
    // interface off the instructions and proves which frame slots home which
    // parameter; declaring those turns the spill into the parameter again,
    // which is the whole difference between reading a frame and reading a
    // program. Text the body points at is harvested the same way, because
    // aarch64 forms an address from a page and an offset and the constant the
    // literal lives at appears only once those are folded.
    let restated = native.restated(&first);
    let folded = native.folded_literals(&first, &root);
    let artifact = match restated.is_none() && folded.is_empty() {
        true => first,
        false => native.prepare_restated(&root, &callees, folded, restated)?,
    };
    let block_count = artifact.source_block_count();
    let signatures = declared_signatures(target, &root, ptr_bits);
    let input = EngineFunctionDecompileRequestInput::single_function(
        EngineFunctionInput {
            function_name: root.name,
            function_addr: entry,
            // The artifact owns the lift and the request reads it from there.
            blocks: Vec::new(),
            arch: Some(target.arch.clone()),
            semantic_metadata_enabled: true,
            source_snapshot: None,
        },
        Some(ptr_bits),
        signatures,
    )
    .with_input_quality(EngineFunctionInputQuality::complete(block_count))
    .with_trusted_ssa(artifact)
    .with_callee_facts(facts)
    .with_declared_signatures(declared);

    Ok(EngineSession::new().decompile_function_from_input(input))
}

/// The declared interfaces of the library functions this body calls.
///
/// Keyed by name, because that is what an import is: the body is elsewhere and
/// only the name reaches the program.
fn declared_signatures(
    target: &NativeTarget<'_>,
    root: &Walked,
    ptr_bits: u32,
) -> r2types::ParsedExternalContext {
    let mut context = r2types::ParsedExternalContext::default();
    for name in &root.callee_names {
        let Some(prototype) = target.prototypes.get(name) else {
            continue;
        };
        let Some(signature) = function_type(prototype, ptr_bits) else {
            continue;
        };
        context
            .known_function_signatures
            .insert(name.clone(), signature);
    }
    context
}

/// A declared prototype, placed in the convention's slots and typed.
///
/// The prototype says how many arguments there are and what they are; the
/// convention says where they arrive. Neither alone describes the call, and
/// nothing here proves anything about the callee's body, which is why this is
/// only reached for a function whose body the program does not carry.
fn declared_interface(
    prototype: &r2abi::Prototype,
    machine: &NativeMachine,
    ptr_bits: u32,
) -> Option<r2source::SourceFunctionInterface> {
    let slots = machine.slots.argument_slots();
    if prototype.parameters.len() > slots.len() {
        r2il::refusal_evidence!(
            "declared-interface",
            "{} declares {} parameters and the convention has {} registers",
            prototype.name,
            prototype.parameters.len(),
            slots.len()
        );
        return None;
    }
    let parameters = prototype
        .parameters
        .iter()
        .enumerate()
        .map(|(index, _)| r2source::SourceAbiParameterSpec::new(index as u32, slots[index]))
        .collect::<Vec<_>>();
    let returns = match (prototype.returns.as_str(), machine.slots.result_slot()) {
        ("void" | "", _) | (_, None) => r2source::SourceFunctionReturn::Void,
        (_, Some(storage)) => r2source::SourceFunctionReturn::Register { storage },
    };

    // The declared types, as the graph the interface carries. A spelling this
    // build cannot place leaves the prototype untyped rather than half-typed.
    let mut graph = DeclaredTypes::default();
    let parameter_values = prototype
        .parameters
        .iter()
        .map(|spelling| graph.value(spelling, ptr_bits))
        .collect::<Vec<_>>();
    let return_value = match returns {
        r2source::SourceFunctionReturn::Void => None,
        _ => graph.value(&prototype.returns, ptr_bits),
    };
    let typed = parameter_values.iter().all(Option::is_some)
        && matches!(returns, r2source::SourceFunctionReturn::Void) == return_value.is_none();
    let type_graph = typed
        .then(|| r2source::SourceTypeGraph::new(graph.types.clone(), []).ok())
        .flatten();

    let revision = format!("declared:{}", prototype.name);
    let interface = match &type_graph {
        Some(_) => r2source::SourceFunctionInterface::new_exact_with_logical_types(
            revision.into_bytes(),
            machine.slots.calling_convention(),
            parameters,
            returns,
            Vec::new(),
            parameter_values,
            return_value,
            type_graph,
        ),
        None => r2source::SourceFunctionInterface::new_exact(
            revision.into_bytes(),
            machine.slots.calling_convention(),
            parameters,
            returns,
            Vec::new(),
        ),
    };

    interface
        .ok()
        .and_then(|interface| {
            let roles = machine.roles;
            interface
                .with_return_address_storage(roles.return_address_storage()?)
                .ok()?
                .with_stack_pointer_storage(roles.stack_pointer_storage()?)
                .ok()
        })
        // The types are radare2's declarations, which is exactly what this flag
        // says: the prototype was read rather than recovered.
        .map(r2source::SourceFunctionInterface::with_prototype_from_source_types)
        .or_else(|| {
            r2il::refusal_evidence!(
                "declared-interface",
                "{} could not be stated in this machine's carriers",
                prototype.name
            );
            None
        })
}

/// One interface again, with stack slots it did not have.
///
/// There is no builder that adds them, so the interface is rebuilt from what
/// it says about itself. The order matters: a return mechanism validates
/// against the carriers, and a carrier refuses to move once a mechanism is
/// bound, so the carriers go on first.
fn restate(
    interface: &r2source::SourceFunctionInterface,
    slots: Vec<r2source::SourceStackSlotSpec>,
    target: &NativeTarget<'_>,
) -> Option<r2source::SourceFunctionInterface> {
    let mut restated = r2source::SourceFunctionInterface::new_exact_with_logical_types(
        interface.revision_identity().to_vec(),
        interface.calling_convention(),
        interface.parameters().to_vec(),
        interface.return_kind(),
        slots,
        interface.parameter_logical_values().to_vec(),
        interface.return_logical_value(),
        interface.type_graph().cloned(),
    )
    .ok()?
    .with_role_register_names(interface.role_register_names())
    // What a call leaves standing is the specification's statement, not
    // something the recovered interface could know. Without it every function
    // that calls loses every fact about its own frame, and its dead spills
    // render as variables assigned from values nothing wrote.
    .with_preserved_call_carriers(
        preserves(target, interface.stack_pointer_storage()),
        preserves(target, interface.frame_pointer_storage()),
    );
    if let Some(storage) = interface.return_address_storage() {
        restated = restated.with_return_address_storage(storage).ok()?;
    }
    if let Some(storage) = interface.stack_pointer_storage() {
        restated = restated.with_stack_pointer_storage(storage).ok()?;
    }
    if let Some(storage) = interface.frame_pointer_storage() {
        restated = restated.with_frame_pointer_storage(storage).ok()?;
    }
    if let Some(mechanism) = interface.return_mechanism() {
        restated = restated
            .with_exact_stacked_return(
                mechanism.stack_offset(),
                mechanism.slot_size_bytes(),
                mechanism.stack_pointer_delta_bytes(),
                mechanism.address_size_bytes(),
            )
            .ok()?;
    }
    if interface.prototype_from_source_types() {
        restated = restated.with_prototype_from_source_types();
    }
    Some(restated)
}

/// Whether a call leaves one carrier as it found it.
///
/// A carrier the interface does not name is not disturbed by a call either,
/// because there is nothing there to disturb.
fn preserves(target: &NativeTarget<'_>, storage: Option<r2source::CanonicalStorageId>) -> bool {
    let Some(storage) = storage else {
        return true;
    };
    target
        .arch
        .registers
        .iter()
        .filter(|register| register.offset == storage.offset && register.size == storage.size)
        .any(|register| target.compiler.preserves(&register.name))
}

/// The types one declared prototype needs, interned as it is read.
#[derive(Default)]
struct DeclaredTypes {
    types: Vec<r2source::SourceType>,
}

impl DeclaredTypes {
    /// The logical value one C spelling stands for.
    fn value(&mut self, spelling: &str, ptr_bits: u32) -> Option<r2source::SourceLogicalValue> {
        let parsed = r2types::parse_c_type_like(spelling, ptr_bits)?;
        let id = self.intern(&parsed, ptr_bits)?;
        let bits = self.types[id as usize].size_bits();
        Some(r2source::SourceLogicalValue::new(
            id,
            r2source::SourceCarrierProjection::new(r2source::SourceCarrierKind::Full, 0, bits),
        ))
    }

    fn intern(&mut self, parsed: &r2types::CTypeLike, ptr_bits: u32) -> Option<u32> {
        use r2source::SourceTypeKind as Kind;
        use r2types::{CTypeLike, Signedness};

        let (kind, bits) = match parsed {
            CTypeLike::Void => (Kind::Void, 0),
            CTypeLike::Bool => (Kind::UnsignedInteger, 8),
            CTypeLike::Int { bits, signedness } => match signedness {
                Signedness::Signed => (Kind::SignedInteger, *bits),
                _ => (Kind::UnsignedInteger, *bits),
            },
            CTypeLike::Float(bits) => (Kind::Float, *bits),
            CTypeLike::Pointer(target) => {
                let target_type_id = self.intern(target, ptr_bits)?;
                (Kind::Pointer { target_type_id }, ptr_bits)
            }
            // An aggregate needs a layout this declaration does not carry.
            _ => return None,
        };
        let id = u32::try_from(self.types.len()).ok()?;
        self.types.push(r2source::SourceType::new(
            id,
            kind,
            u64::from(bits),
            u64::from(bits.max(8)),
        ));
        Some(id)
    }
}

/// One declared prototype as the type layer states it.
///
/// A spelling this build cannot parse leaves the whole prototype out rather
/// than contributing a parameter list with a hole in it.
fn function_type(prototype: &r2abi::Prototype, ptr_bits: u32) -> Option<r2types::FunctionType> {
    let mut params = Vec::with_capacity(prototype.parameters.len());
    for spelling in &prototype.parameters {
        params.push(r2types::parse_c_type_like(spelling, ptr_bits)?);
    }
    Some(r2types::FunctionType {
        return_type: r2types::parse_c_type_like(&prototype.returns, ptr_bits)?,
        params,
        variadic: prototype.variadic,
    })
}

/// What the bodies a function calls say about their own boundaries.
#[derive(Default)]
struct Callees {
    interfaces: BTreeMap<u64, r2source::SourceFunctionInterface>,
    preserved: CalleePreservedCarriers,
    /// What each callee reaches through each pointer it is handed, which is
    /// what makes the bytes one callee covers one object in the caller.
    reach: BTreeMap<u64, BTreeMap<usize, SummaryArgumentReach>>,
}

impl Callees {
    fn record(&mut self, address: u64, facts: &CalleeFacts) {
        self.interfaces.insert(address, facts.interface().clone());
        self.preserved
            .insert(address, facts.preserved_carriers().clone());
        let reach = facts.argument_touch_reach();
        if !reach.is_empty() {
            self.reach.insert(address, reach);
        }
    }
}

/// One function walked out of the program.
struct Walked {
    name: String,
    body: r2ssa::body::Body,
    /// What each function this one calls is called.
    callee_names: Vec<String>,
}

/// One program, one machine, and the walk over it.
struct Native<'a> {
    target: &'a NativeTarget<'a>,
    program: &'a dyn Program,
    machine: NativeMachine,
    /// Cancellation and the work meter, shared by the root and its callees.
    control: r2ssa::SsaExecutionControl,
}

impl Native<'_> {
    fn walk(&self, entry: u64) -> Result<Walked, NativeRefusal> {
        let body =
            lift_body(entry, self.target.disasm, self.program).map_err(NativeRefusal::Body)?;
        let callee_names = body
            .calls
            .iter()
            .filter_map(|address| self.program.name_at(*address))
            .collect();
        Ok(Walked {
            name: self
                .program
                .name_at(entry)
                .unwrap_or_else(|| format!("fcn.{entry:x}")),
            body,
            callee_names,
        })
    }

    /// The text a prepared body points at.
    ///
    /// A machine does not always write an address down: aarch64 forms one from
    /// a page and an offset, so the constant a string lives at exists only
    /// once the two are folded. Preparation folds them, and this asks it
    /// rather than re-scanning the operations that could not know.
    fn folded_literals(
        &self,
        artifact: &TrustedSsaArtifact,
        walked: &Walked,
    ) -> Vec<(u64, String)> {
        let prepared = artifact.shared_artifact();
        let already = self
            .literals(&walked.body)
            .into_iter()
            .map(|(address, _)| address)
            .collect::<BTreeSet<_>>();
        let mut found = BTreeMap::new();
        for value in prepared.value_ids() {
            let Some(address) = prepared.folded_value(value) else {
                continue;
            };
            if address == 0 || already.contains(&address) {
                continue;
            }
            if let Some(text) = self.text_at(address) {
                found.insert(address, text);
            }
        }
        found.into_iter().collect()
    }

    /// Capture what was walked and prepare it for the engine.
    fn prepare(
        &self,
        walked: &Walked,
        callees: &Callees,
    ) -> Result<Arc<TrustedSsaArtifact>, NativeRefusal> {
        self.prepare_with_literals(walked, callees, Vec::new())
    }

    /// The interface the first pass recovered, restated with the frame slots
    /// it proved.
    ///
    /// `None` where the body proves no slot, which is every function that
    /// keeps its arguments in registers.
    fn restated(&self, artifact: &TrustedSsaArtifact) -> Option<r2source::SourceFunctionInterface> {
        let prepared = artifact.shared_artifact();
        let prepared = prepared.as_ref();
        let interface = prepared.machine_context().function_interface()?;
        let base_storage = prepared.machine_context().stack_pointer_carrier()?;
        let proved = r2ssa::recover_interface::recovered_stack_slots(prepared);
        if proved.is_empty() {
            return None;
        }

        let slots = proved
            .iter()
            .filter_map(|slot| {
                let parameter = match slot.parameter {
                    None => {
                        return Some(r2source::SourceStackSlotSpec::new_local(
                            r2source::StackAddressBase::StackPointer,
                            base_storage,
                            slot.offset,
                            slot.size_bytes,
                        ));
                    }
                    Some(index) => index,
                };
                // A home names the register its parameter arrived in, and the
                // constructor refuses any other.
                let home = interface
                    .parameters()
                    .get(parameter as usize)?
                    .register_storage()?;
                Some(r2source::SourceStackSlotSpec::new_parameter_home(
                    r2source::StackAddressBase::StackPointer,
                    base_storage,
                    slot.offset,
                    slot.size_bytes,
                    parameter,
                    home,
                ))
            })
            .collect::<Vec<_>>();

        restate(interface, slots, self.target)
    }

    fn prepare_with_literals(
        &self,
        walked: &Walked,
        callees: &Callees,
        extra_literals: Vec<(u64, String)>,
    ) -> Result<Arc<TrustedSsaArtifact>, NativeRefusal> {
        self.prepare_restated(walked, callees, extra_literals, None)
    }

    fn prepare_restated(
        &self,
        walked: &Walked,
        callees: &Callees,
        extra_literals: Vec<(u64, String)>,
        interface: Option<r2source::SourceFunctionInterface>,
    ) -> Result<Arc<TrustedSsaArtifact>, NativeRefusal> {
        let function = NativeFunction {
            address: walked.body.entry,
            name: walked.name.clone(),
            blocks: walked
                .body
                .blocks
                .iter()
                .map(|block| NativeBlock {
                    address: block.lifted.addr,
                    bytes: block.bytes.clone(),
                    successors: block.successors.clone(),
                })
                .collect(),
            calls: call_sites(&walked.body, self.program),
            string_literals: {
                let mut literals = self.literals(&walked.body);
                literals.extend(extra_literals);
                literals.sort_by_key(|(address, _)| *address);
                literals.dedup_by_key(|(address, _)| *address);
                literals
            },
            data_symbols: self.data_symbols(&walked.body),
            parameter_names: (0..interface.as_ref().map_or(0, |i| i.parameters().len()))
                .map(|index| format!("arg{index}"))
                .collect(),
            interface,
            loader_role: None,
        };

        let snapshot =
            r2source::native::capture(&self.machine, function).map_err(NativeRefusal::Capture)?;
        let lifted = Disassembler::lift_owned_function(snapshot)
            .map_err(|error| NativeRefusal::Lift(error.to_string()))?;
        let artifact = TrustedSsaArtifact::prepare_with_callee_interfaces(
            lifted,
            &self.control,
            &callees.interfaces,
            &callees.preserved,
            &callees.reach,
        )
        .map_err(|error| NativeRefusal::Prepare(format!("{error:?}")))?;
        Ok(Arc::new(artifact))
    }
}

/// The longest text a capture will read out of one address.
///
/// Long enough for any format string or message a program renders, and short
/// enough that a constant landing in a run of printable bytes cannot pull the
/// whole section in behind it.
const LITERAL_LIMIT: usize = 4096;

/// Where each direct call is made and what it reaches.
///
/// The walk collects call targets without saying which instruction made each
/// one, so the instruction is found by looking for the call operation in the
/// block that carries it.
fn call_sites(body: &r2ssa::body::Body, program: &dyn Program) -> Vec<NativeCall> {
    let mut sites = Vec::new();
    for block in &body.blocks {
        for (index, op) in block.lifted.ops.iter().enumerate() {
            let Some((target, transfer)) = transfer(op, body) else {
                continue;
            };
            let Some(instruction) = block
                .lifted
                .op_metadata(index)
                .and_then(|metadata| metadata.instruction_addr)
            else {
                continue;
            };
            sites.push(NativeCall {
                instruction,
                target,
                name: program.name_at(target),
                transfer,
                linkage: match program.import_at(target) {
                    Some(_) => r2source::AdvisoryCalleeLinkage::Imported,
                    None => r2source::AdvisoryCalleeLinkage::Internal,
                },
            });
        }
    }
    sites
}

/// How one operation reaches another function, where it reaches one at all.
///
/// A call comes back and a tail jump does not, and which this is a fact about
/// the body rather than about the callee: the walk decided it when it stopped
/// at the target's entry.
fn transfer(
    op: &r2il::R2ILOp,
    body: &r2ssa::body::Body,
) -> Option<(u64, r2source::AdvisoryCallTransfer)> {
    match op {
        r2il::R2ILOp::Call { target } => {
            Some((target.offset, r2source::AdvisoryCallTransfer::Call))
        }
        r2il::R2ILOp::Branch { target } if body.tail_calls.contains(&target.offset) => {
            Some((target.offset, r2source::AdvisoryCallTransfer::TailJump))
        }
        _ => None,
    }
}

impl Native<'_> {
    /// The text this body points at.
    ///
    /// A constant the code computes with is not a pointer, and nothing here
    /// claims it is: the address has to hold a run of printable bytes ending
    /// in a terminator for it to be read as text at all.
    fn literals(&self, body: &r2ssa::body::Body) -> Vec<(u64, String)> {
        referenced(body)
            .into_iter()
            .filter_map(|address| Some((address, self.text_at(address)?)))
            .collect()
    }

    /// The named program data this body points at.
    fn data_symbols(&self, body: &r2ssa::body::Body) -> Vec<SourceDataObject> {
        referenced(body)
            .into_iter()
            .filter(|address| !body.calls.contains(address))
            .filter_map(|address| {
                let name = self.program.name_at(address)?;
                Some(SourceDataObject::new(address, name, None::<String>))
            })
            .collect()
    }

    /// The text at an address, where there is text there.
    fn text_at(&self, address: u64) -> Option<String> {
        let bytes = self.program.read(address, LITERAL_LIMIT)?;
        // A run of printable bytes that never terminates is not text, and
        // neither is an empty one. One character is: a program that points at
        // `"x"` points at a string.
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .filter(|end| *end > 0)?;
        let text = std::str::from_utf8(&bytes[..end]).ok()?;
        text.chars()
            .all(|c| !c.is_control() || c == '\n' || c == '\t')
            .then(|| text.to_owned())
    }
}

/// Every address this body names as a constant.
fn referenced(body: &r2ssa::body::Body) -> BTreeSet<u64> {
    let mut addresses = BTreeSet::new();
    for block in &body.blocks {
        for op in &block.lifted.ops {
            for varnode in op.inputs() {
                // Whether a constant is an address is decided by what is
                // there, not by how large it is: a binary linked low puts its
                // strings at four-digit addresses.
                if matches!(varnode.space, r2il::SpaceId::Ram | r2il::SpaceId::Const)
                    && varnode.offset != 0
                {
                    addresses.insert(varnode.offset);
                }
            }
        }
    }
    addresses
}

/// State the machine from the convention data and the compiler specification.
fn machine(target: &NativeTarget<'_>) -> Result<NativeMachine, NativeRefusal> {
    let (family, bits, endianness) = profile(target.arch)?;
    // A machine that leaves the return address in a register says so; one that
    // pushes it names a stack location, and then the carrier the return reads
    // is the program counter.
    let return_address_name = target
        .compiler
        .return_address
        .as_deref()
        .unwrap_or_else(|| target.disasm.program_counter());
    let return_address = storage(target.arch, return_address_name)?;
    let stack_pointer_name = target
        .compiler
        .stack_pointer
        .as_deref()
        .ok_or(NativeRefusal::NoStackPointer)?;
    let stack_pointer = storage(target.arch, stack_pointer_name)?;

    // Which way the stack grows is a fact about the machine, so it comes from
    // the compiler specification; how far past the stack pointer a leaf may
    // write is a fact about the ABI, so the red zone comes from the convention.
    let growth = match target.compiler.stack_growth {
        r2abi::StackAllocation::Lower => SourceStackGrowth::LowerAddresses,
        r2abi::StackAllocation::Higher => SourceStackGrowth::HigherAddresses,
    };
    let redzone = u32::try_from(target.convention.redzone_bytes).unwrap_or(0);
    let roles = SourceMachineRoles::new(Some(return_address), Some(stack_pointer))
        .and_then(|roles| {
            roles.with_stack_allocation_contract(
                SourceStackAllocationContract::with_implicit_active_sp_bytes(growth, redzone),
            )
        })
        .map_err(|_| NativeRefusal::Machine("the carriers are not register storages"))?
        // The names, not only the storages: the trusted lift restates every
        // carrier in its own architecture's numbering, and it looks the
        // carriers up by name to do it.
        .with_role_register_names(SourceRoleRegisterNames::new(
            Some(return_address_name),
            Some(stack_pointer_name),
            None,
        ));

    let mut argument_slots = Vec::with_capacity(target.convention.args.len());
    for slot in &target.convention.args {
        argument_slots.push(storage(target.arch, slot.name())?);
    }
    let result_slot = match target.convention.return_register() {
        Some(slot) => Some(storage(target.arch, slot.name())?),
        None => None,
    };
    // Where a seventh argument goes is stated by neither file directly: it is
    // arithmetic over the shadow space and the return-address slot. Until that
    // is derived, a function with more arguments than registers refuses rather
    // than being given a placement nothing proved.
    let slots = SourceConventionSlots::new(&target.convention.name, argument_slots, result_slot)
        .map_err(|_| NativeRefusal::Machine("the convention names one register twice"))?;

    Ok(NativeMachine {
        arch_id: family.to_owned(),
        cpu_id: family.to_owned(),
        bits,
        endianness,
        roles,
        slots,
    })
}

/// The machine tuple the trusted lift selects a Sleigh profile by.
fn profile(arch: &ArchSpec) -> Result<(&'static str, u32, SourceEndianness), NativeRefusal> {
    let bits = crate::engine_effective_ptr_bits(arch);
    let family = r2abi::family(&arch.name).ok_or(NativeRefusal::Machine(
        "no trusted profile for this machine",
    ))?;
    let endianness = match arch.memory_endianness {
        r2il::Endianness::Little => SourceEndianness::Little,
        r2il::Endianness::Big => SourceEndianness::Big,
        // A capture states one endianness, and a machine that switches or
        // spells its own is not one the trusted profiles cover.
        _ => {
            return Err(NativeRefusal::Machine(
                "this machine's byte order is not one a capture can state",
            ));
        }
    };
    Ok((family, bits, endianness))
}

/// The canonical storage one register name stands for.
///
/// The convention data spells registers in lower case and Sleigh spells them
/// in upper, so the match ignores case rather than either side converting.
fn storage(arch: &ArchSpec, name: &str) -> Result<CanonicalStorageId, NativeRefusal> {
    arch.registers
        .iter()
        .find(|register| register.name.eq_ignore_ascii_case(name))
        .map(|register| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: register.offset,
            size: register.size,
        })
        .ok_or_else(|| NativeRefusal::UnknownRegister(name.to_owned()))
}
