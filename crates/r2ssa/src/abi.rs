//! The function's own parameters as its one interface states them, read by the summaries.

use crate::CanonicalStorageId;
use crate::machine_context::SourceMachineContext;

/// A view of the function interface's parameters, where the context states a coherent one
/// (doc/adr-call-boundary.md, D165): no second list of argument registers is held.
#[derive(Debug, Clone, Copy, Default)]
pub struct Formals<'a> {
    interface: Option<&'a r2source::SourceFunctionInterface>,
}

impl<'a> Formals<'a> {
    pub(crate) fn of(context: &'a SourceMachineContext) -> Option<Self> {
        let memory = context.memory_model();
        let abi = context.abi_model();
        let coherent = memory.is_available()
            && memory.is_coherent()
            && abi.is_available()
            && abi.argument_placement_is_coherent()
            && abi.return_boundary_is_coherent();
        let interface = context.function_interface().filter(|_| coherent)?;
        Some(Self {
            interface: Some(interface),
        })
    }

    /// The parameter a register arrives as.
    pub(crate) fn exact_argument_index_for_storage(
        &self,
        storage: CanonicalStorageId,
    ) -> Option<usize> {
        (self.interface?.parameters().iter())
            .position(|parameter| parameter.register_storage() == Some(storage))
    }

    /// The registers the parameters arrive in, in parameter order.
    pub(crate) fn argument_storages(&self) -> impl Iterator<Item = CanonicalStorageId> + '_ {
        (self.interface.into_iter())
            .flat_map(|interface| interface.parameters())
            .filter_map(r2source::SourceAbiParameterSpec::register_storage)
    }

    /// Whether the source states the parameters.
    pub(crate) const fn is_source_owned(&self) -> bool {
        self.interface.is_some()
    }

    /// How many parameters arrive in registers.
    pub fn argument_count(&self) -> usize {
        self.argument_storages().count()
    }
}
