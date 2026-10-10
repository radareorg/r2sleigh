//! Canonical calling-convention register facts used by SSA analyses.

use std::collections::BTreeSet;

use crate::machine_context::SourceMachineContext;
use crate::{CanonicalStorageId, CanonicalStorageSpace};

/// The convention's argument and result registers, as the source states them.
#[derive(Debug, Clone, Default)]
pub struct AbiProfile {
    args: Vec<CanonicalStorageId>,
    source_owned: bool,
}

impl AbiProfile {
    pub(crate) fn from_machine_context(context: &SourceMachineContext) -> Option<Self> {
        let memory = context.memory_model();
        let abi = context.abi_model();
        if !memory.is_available()
            || !memory.is_coherent()
            || !abi.is_available()
            || !abi.argument_placement_is_coherent()
            || !abi.return_boundary_is_coherent()
        {
            return None;
        }
        let arguments = abi
            .argument_registers()
            .iter()
            .map(|slot| (slot.index(), slot.storage()))
            .collect::<Vec<_>>();
        let returns = abi
            .return_registers()
            .iter()
            .map(|slot| slot.storage())
            .collect::<Vec<_>>();
        Self::from_canonical_storage_model(&arguments, &returns)
    }

    fn from_canonical_storage_model(
        argument_registers: &[(u32, CanonicalStorageId)],
        return_registers: &[CanonicalStorageId],
    ) -> Option<Self> {
        let register = |storage: &CanonicalStorageId| {
            storage.space == CanonicalStorageSpace::Register && storage.size != 0
        };
        let mut arguments = argument_registers.to_vec();
        arguments.sort_by_key(|(index, _)| *index);
        let mut distinct = BTreeSet::new();
        let coherent = arguments
            .iter()
            .enumerate()
            .all(|(expected, (index, storage))| {
                *index as usize == expected && register(storage) && distinct.insert(*storage)
            });
        if !coherent || !return_registers.iter().all(register) {
            return None;
        }
        Some(Self {
            args: arguments.into_iter().map(|(_, storage)| storage).collect(),
            source_owned: true,
        })
    }

    pub(crate) fn exact_argument_index_for_storage(
        &self,
        storage: CanonicalStorageId,
    ) -> Option<usize> {
        self.args.iter().position(|slot| *slot == storage)
    }

    /// The storages of the argument slots the profile names.
    pub(crate) fn argument_storages(&self) -> impl Iterator<Item = CanonicalStorageId> + '_ {
        self.args.iter().copied()
    }

    pub(crate) const fn is_source_owned(&self) -> bool {
        self.source_owned
    }

    pub fn argument_count(&self) -> usize {
        self.args.len()
    }
}

#[cfg(test)]
mod tests {
    use r2il::{AddressSpace, ArchSpec, RegisterDef};

    use super::*;
    use crate::machine_context::{
        SourceAbiParameterSpec, SourceFunctionInterface, SourceFunctionReturn, SourceMachineRoles,
    };

    const ARGUMENT: CanonicalStorageId = register_storage(0, 8);
    const RETURNED: CanonicalStorageId = register_storage(8, 8);
    const STACK_POINTER: CanonicalStorageId = register_storage(16, 8);
    const RETURN_ADDRESS: CanonicalStorageId = register_storage(24, 8);

    const fn register_storage(offset: u64, size: u32) -> CanonicalStorageId {
        CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        }
    }

    fn exact_context(argument_names: &[&str], return_names: &[&str]) -> SourceMachineContext {
        let mut arch = ArchSpec::new("x86-64");
        arch.addr_size = 8;
        arch.add_space(AddressSpace::ram(8));
        for name in argument_names {
            arch.add_register(RegisterDef::new(*name, ARGUMENT.offset, ARGUMENT.size));
        }
        for name in return_names {
            arch.add_register(RegisterDef::new(*name, RETURNED.offset, RETURNED.size));
        }
        arch.add_register(RegisterDef::new(
            "source_sp",
            STACK_POINTER.offset,
            STACK_POINTER.size,
        ));
        arch.add_register(RegisterDef::new(
            "source_ra",
            RETURN_ADDRESS.offset,
            RETURN_ADDRESS.size,
        ));
        arch.return_registers = vec![RegisterDef::new(
            return_names[0],
            RETURNED.offset,
            RETURNED.size,
        )];
        let interface = SourceFunctionInterface::new_exact(
            b"abi-storage-only-test".to_vec(),
            "test-abi",
            [SourceAbiParameterSpec::new(0, ARGUMENT)],
            SourceFunctionReturn::Register { storage: RETURNED },
            [],
        )
        .and_then(|interface| interface.with_return_address_storage(RETURN_ADDRESS))
        .and_then(|interface| interface.with_stack_pointer_storage(STACK_POINTER))
        .expect("exact interface");
        let context = SourceMachineContext::from_blocks_with_interfaces(
            &[],
            Some(&crate::Arch::from(arch.clone())),
            Some(interface),
            SourceMachineRoles::default(),
            None,
            None,
            Vec::new(),
        );
        assert!(context.abi_model().argument_placement_is_coherent());
        assert!(context.abi_model().return_boundary_is_coherent());
        context
    }

    #[test]
    fn exact_storage_model_requires_no_presentation_aliases() {
        let profile = AbiProfile::from_canonical_storage_model(&[(0, ARGUMENT)], &[RETURNED])
            .expect("canonical storage is sufficient");

        assert!(profile.is_source_owned());
        assert_eq!(profile.argument_count(), 1);
        assert_eq!(profile.exact_argument_index_for_storage(ARGUMENT), Some(0));
    }

    #[test]
    fn exact_machine_profile_ignores_multiple_presentation_aliases() {
        let context = exact_context(
            &["argument", "argument_alias", "another_argument_alias"],
            &["result", "result_alias"],
        );
        let profile = AbiProfile::from_machine_context(&context)
            .expect("presentation alias count does not affect exact ABI storage");

        assert_eq!(profile.exact_argument_index_for_storage(ARGUMENT), Some(0));
    }

    #[test]
    fn exact_machine_profile_ignores_renamed_presentation_aliases() {
        let first =
            AbiProfile::from_machine_context(&exact_context(&["first_arg"], &["first_ret"]))
                .expect("first spelling set");
        let renamed = AbiProfile::from_machine_context(&exact_context(
            &["completely_renamed_arg"],
            &["completely_renamed_ret"],
        ))
        .expect("renamed spelling set");

        for profile in [&first, &renamed] {
            assert!(profile.is_source_owned());
            assert_eq!(profile.argument_count(), 1);
            assert_eq!(profile.exact_argument_index_for_storage(ARGUMENT), Some(0));
        }
    }
}
