//! A capture the engine makes for itself, from the program's own bytes.
//!
//! Every snapshot until now arrived over the wire from radare2's side of the
//! bridge, which is why the mint is private: source authority must not be
//! assembled from detached pieces by code outside this crate. That rule is
//! about *where* a capture is assembled, not about *who* discovered the
//! bytes, so a capture the engine performs itself belongs here, beside the
//! wire decoder, and is minted by the same constructor under the same
//! validation.
//!
//! What a native capture deliberately does not carry is a function interface.
//! Nothing here recovers a prototype, and there is no radare2 to have one:
//! the convention slots and the machine roles are stated, and the artifact
//! builder reads the ABI off the instructions, which is the path it already
//! takes for any capture whose source had no prototype either.

use crate::{
    AdvisoryCallSite, AdvisoryCallTransfer, AdvisoryCalleeLinkage, AdvisorySuccessor,
    AdvisorySuccessorKind, CapturedSourceFields, DiagnosticIdentity, FunctionIdentity,
    FunctionPresentation, MachineProfile, OwnedFunctionBlock, OwnedFunctionImage,
    OwnedFunctionSnapshot, SnapshotValidationError, SourceConventionSlots, SourceDataObject,
    SourceEndianness, SourceLoaderRole, SourceMachineRoles,
};

/// The machine every function in one capture session runs on.
#[derive(Debug, Clone)]
pub struct NativeMachine {
    pub arch_id: String,
    pub cpu_id: String,
    pub bits: u32,
    pub endianness: SourceEndianness,
    pub roles: SourceMachineRoles,
    pub slots: SourceConventionSlots,
}

/// One basic block, as bytes and where control goes from it.
///
/// Bytes rather than lifted operations, because the trusted lift is what turns
/// a captured block into operations and it must be the only thing that does.
#[derive(Debug, Clone)]
pub struct NativeBlock {
    pub address: u64,
    pub bytes: Vec<u8>,
    /// Where control continues, and how. A target outside this function's own
    /// blocks is marked external by the capture rather than by the caller.
    pub successors: Vec<(AdvisorySuccessorKind, u64)>,
}

/// One direct call the body makes.
#[derive(Debug, Clone)]
pub struct NativeCall {
    pub instruction: u64,
    pub target: u64,
    /// What the program calls the target. Presentation only: it spells the
    /// call in rendered output and is evidence about nothing.
    pub name: Option<String>,
}

/// One function, as the engine walked it out of the image.
#[derive(Debug, Clone)]
pub struct NativeFunction {
    pub address: u64,
    pub name: String,
    pub blocks: Vec<NativeBlock>,
    pub calls: Vec<NativeCall>,
    /// Text the body points at, with the address it lives at.
    pub string_literals: Vec<(u64, String)>,
    /// Program data the body points at, named.
    pub data_symbols: Vec<SourceDataObject>,
    pub loader_role: Option<SourceLoaderRole>,
}

/// Mint a snapshot from a capture the engine made itself.
pub fn capture(
    machine: &NativeMachine,
    function: NativeFunction,
) -> Result<OwnedFunctionSnapshot, SnapshotValidationError> {
    let own_blocks: Vec<u64> = function.blocks.iter().map(|block| block.address).collect();
    let total_source_bytes = function
        .blocks
        .iter()
        .map(|block| block.bytes.len())
        .sum::<usize>();
    let identity = revision_identity(function.address, &function.blocks);
    // Where control leaves the function is not stated twice: it is every
    // successor that lands outside the blocks this walk kept.
    let mut external_exits: Vec<u64> = function
        .blocks
        .iter()
        .flat_map(|block| block.successors.iter())
        .map(|(_, target)| *target)
        .filter(|target| !own_blocks.contains(target))
        .collect();
    external_exits.sort_unstable();
    external_exits.dedup();

    let blocks = function
        .blocks
        .iter()
        .map(|block| OwnedFunctionBlock {
            address: block.address,
            bytes: block.bytes.as_slice().into(),
            successors: block
                .successors
                .iter()
                .map(|(kind, target)| AdvisorySuccessor {
                    kind: *kind,
                    target: *target,
                    case_value: None,
                    external: !own_blocks.contains(target),
                })
                .collect(),
            // A switch needs a value domain to resolve, and this walk refuses
            // an indirect branch rather than guessing one.
            switch_instruction: None,
        })
        .collect::<Vec<_>>();

    let advisory_calls = function
        .calls
        .iter()
        .map(|call| AdvisoryCallSite {
            instruction_address: call.instruction,
            target_address: call.target,
            transfer: AdvisoryCallTransfer::Call,
            target_name: call.name.clone(),
            linkage: AdvisoryCalleeLinkage::Internal,
            prototype: None,
        })
        .collect::<Vec<_>>();

    OwnedFunctionSnapshot::from_captured_parts(
        MachineProfile {
            arch_id: machine.arch_id.as_str().into(),
            cpu_id: machine.cpu_id.as_str().into(),
            bits: machine.bits,
            endianness: machine.endianness,
        },
        FunctionIdentity {
            address: function.address,
            loader_role: function.loader_role,
        },
        FunctionPresentation {
            display_name: function.name.as_str().into(),
            // Names for parameters this capture does not claim to have.
            parameter_names: Box::from([]),
            stack_slot_names: Box::from([]),
            signature: None,
            callee_signatures: Box::from([]),
        },
        OwnedFunctionImage {
            entry_address: function.address,
            blocks: blocks.into_boxed_slice(),
            external_exits: external_exits.into_boxed_slice(),
            string_literals: function.string_literals.into_boxed_slice(),
            data_symbols: function.data_symbols.into_boxed_slice(),
            // A table of code pointers is found by proving what indexes it,
            // which needs the value domain this walk does not have.
            code_pointer_tables: Box::from([]),
            total_source_bytes,
        },
        advisory_calls.into_boxed_slice(),
        identity,
        None,
        machine.roles,
        machine.slots.clone(),
        CapturedSourceFields {
            // The walk bounds the function: every block it kept, it decoded.
            bounded_function_image: true,
            function_interface: false,
            exact_function_types: false,
            exact_stack_slot_roles: false,
            // These say what the *interface* carried, and this capture carries
            // no interface. The same carriers are stated in the machine roles.
            return_address_storage: false,
            stack_pointer_storage: false,
            frame_pointer_storage: false,
            return_mechanism: false,
            stack_allocation_contract: machine.roles.stack_allocation_contract().is_some(),
        },
        DiagnosticIdentity(0),
    )
}

/// An identity for what was captured, from what was captured.
///
/// Two captures of the same bytes at the same address are the same revision,
/// which is what a consumer correlating an interface against a call site
/// needs, and different bytes are a different revision even at one address.
/// FNV-1a because it must be identical on every machine and every run, which
/// a randomly seeded hash is not.
fn revision_identity(address: u64, blocks: &[NativeBlock]) -> Box<[u8]> {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |byte: u8| {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    };
    for byte in address.to_le_bytes() {
        eat(byte);
    }
    for block in blocks {
        for byte in block.address.to_le_bytes() {
            eat(byte);
        }
        for byte in &block.bytes {
            eat(*byte);
        }
    }
    let mut identity = Vec::with_capacity(7 + 8);
    identity.extend_from_slice(b"native:");
    identity.extend_from_slice(&hash.to_le_bytes());
    identity.into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanonicalStorageId, CanonicalStorageSpace};

    fn storage(offset: u64, size: u32) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        }
    }

    fn machine() -> NativeMachine {
        let roles = SourceMachineRoles::new(Some(storage(0x288, 8)), Some(storage(0x20, 8)))
            .expect("machine roles");
        let slots = SourceConventionSlots::new("amd64", [storage(0x38, 8)], Some(storage(0x0, 8)))
            .expect("convention slots");
        NativeMachine {
            arch_id: "x86".to_owned(),
            cpu_id: "x86-64".to_owned(),
            bits: 64,
            endianness: SourceEndianness::Little,
            roles,
            slots,
        }
    }

    fn function() -> NativeFunction {
        NativeFunction {
            address: 0x1000,
            name: "fcn.1000".to_owned(),
            blocks: vec![
                NativeBlock {
                    address: 0x1000,
                    bytes: vec![0x48, 0x89, 0xf8, 0xc3],
                    successors: vec![(AdvisorySuccessorKind::Direct, 0x1004)],
                },
                NativeBlock {
                    address: 0x1004,
                    bytes: vec![0xc3],
                    successors: Vec::new(),
                },
            ],
            calls: Vec::new(),
            string_literals: Vec::new(),
            data_symbols: Vec::new(),
            loader_role: None,
        }
    }

    #[test]
    fn a_native_capture_mints_a_snapshot() {
        let snapshot = capture(&machine(), function()).expect("snapshot");
        assert_eq!(snapshot.function().address(), 0x1000);
        assert_eq!(snapshot.presentation().display_name(), "fcn.1000");
        assert_eq!(snapshot.image().blocks().len(), 2);
        assert_eq!(snapshot.image().total_source_bytes(), 5);
        // No prototype is claimed; the artifact builder reads the ABI off the
        // instructions instead.
        assert!(snapshot.function_interface().is_none());
        assert_eq!(snapshot.convention_slots().calling_convention(), "amd64");
    }

    #[test]
    fn the_same_bytes_are_the_same_revision_and_other_bytes_are_not() {
        let first = capture(&machine(), function()).expect("snapshot");
        let again = capture(&machine(), function()).expect("snapshot");
        assert_eq!(
            first.source_revision_identity(),
            again.source_revision_identity()
        );

        let mut changed = function();
        changed.blocks[0].bytes[0] = 0x90;
        let other = capture(&machine(), changed).expect("snapshot");
        assert_ne!(
            first.source_revision_identity(),
            other.source_revision_identity()
        );
    }

    #[test]
    fn a_successor_outside_the_function_is_external() {
        let mut leaving = function();
        leaving.blocks[1]
            .successors
            .push((AdvisorySuccessorKind::Direct, 0x2000));
        let snapshot = capture(&machine(), leaving).expect("snapshot");
        let successor = snapshot.image().blocks()[1].successors()[0];
        assert_eq!(successor.target(), 0x2000);
        assert!(successor.is_external());
        assert_eq!(snapshot.image().external_exits(), [0x2000]);
    }
}
