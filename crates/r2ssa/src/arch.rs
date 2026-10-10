//! An architecture with the tables every function's analysis reads, derived from it once: a
//! session holds one per architecture and each artifact shares it (ROADMAP LX1).

use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::Arc;

use r2il::{ArchSpec, RegisterProjection, RegisterProjectionQuery, RegisterStorage};

use crate::function::RegisterFamilyInfo;
use crate::machine_context::{MachineMemoryModel, MachineRegisterGeometryState};
use crate::naming::RegisterNameMap;
use crate::{CanonicalStorageId, CanonicalStorageSpace};

/// An [`ArchSpec`] and what is derived from it alone; a clone shares the tables.
#[derive(Debug, Clone)]
pub struct Arch(Arc<Tables>);

#[derive(Debug)]
struct Tables {
    spec: Arc<ArchSpec>,
    register_names: RegisterNameMap,
    register_families: RegisterFamilyInfo,
    /// Each name the file gives exactly one storage, lowercased.
    registers_by_name: BTreeMap<String, CanonicalStorageId>,
    /// The first of those names, in name order, for each storage.
    names_by_register: BTreeMap<CanonicalStorageId, String>,
    /// Each register no wider one contains, by offset.
    outermost_registers: Box<[CanonicalStorageId]>,
    tracked_entry_values: Box<[(CanonicalStorageId, u64)]>,
    geometry: MachineRegisterGeometryState,
    /// The file's projections, sorted by the storage written.
    projections: Box<[RegisterProjection]>,
    query: Option<RegisterProjectionQuery>,
    memory_model: MachineMemoryModel,
    result_slot: Option<CanonicalStorageId>,
}

impl Arch {
    pub fn new(spec: impl Into<Arc<ArchSpec>>) -> Self {
        let spec = spec.into();
        let registers_by_name = unique_register_names(&spec);
        let mut names_by_register = BTreeMap::new();
        for (name, storage) in &registers_by_name {
            names_by_register
                .entry(*storage)
                .or_insert_with(|| name.clone());
        }
        // A tracked register the architecture cannot place states nothing.
        let tracked_entry_values = spec
            .tracked_entry_values
            .iter()
            .filter_map(|tracked| {
                let name = tracked.register.trim().to_ascii_lowercase();
                Some((*registers_by_name.get(&name)?, tracked.value))
            })
            .collect();
        let (geometry, query) = match RegisterProjectionQuery::from_arch(&spec) {
            Err(_) => (MachineRegisterGeometryState::Malformed, None),
            Ok(None) => (MachineRegisterGeometryState::Unavailable, None),
            Ok(Some(query)) => (MachineRegisterGeometryState::Available, Some(query)),
        };
        let mut projections = match query {
            Some(_) => spec.register_projections.clone(),
            None => Vec::new(),
        };
        projections.sort_by_key(|projection| projection.written);
        projections.dedup_by_key(|projection| projection.written);
        let result_slot = spec.return_registers.first().map(|reg| CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset: reg.offset,
            size: reg.size,
        });
        Self(Arc::new(Tables {
            register_names: crate::naming::register_name_map(&spec),
            register_families: RegisterFamilyInfo::from_arch(&spec),
            memory_model: MachineMemoryModel::from_arch(Some(&spec)),
            outermost_registers: outermost_registers(&spec),
            registers_by_name,
            names_by_register,
            tracked_entry_values,
            geometry,
            projections: projections.into_boxed_slice(),
            query,
            result_slot,
            spec,
        }))
    }

    pub fn spec(&self) -> &ArchSpec {
        &self.0.spec
    }

    /// Whether this is built over `spec` itself, the allocation and not an equal copy.
    pub fn shares(&self, spec: &ArchSpec) -> bool {
        std::ptr::eq(&*self.0.spec, spec)
    }

    pub(crate) fn register_names(&self) -> &RegisterNameMap {
        &self.0.register_names
    }

    pub(crate) fn register_families(&self) -> &RegisterFamilyInfo {
        &self.0.register_families
    }

    /// Each name the register file gives exactly one storage, lowercased.
    pub fn registers_by_name(&self) -> &BTreeMap<String, CanonicalStorageId> {
        &self.0.registers_by_name
    }

    /// The name the file gives this storage, when it names it exactly.
    pub(crate) fn register_name(&self, storage: CanonicalStorageId) -> Option<&str> {
        self.0.names_by_register.get(&storage).map(String::as_str)
    }

    /// Whether the file names this storage exactly.
    pub(crate) fn names_register(&self, storage: CanonicalStorageId) -> bool {
        self.0.names_by_register.contains_key(&storage)
    }

    /// Each register no wider one contains, by offset: what a call may change, before its effect.
    pub(crate) fn outermost_registers(&self) -> &[CanonicalStorageId] {
        &self.0.outermost_registers
    }

    pub(crate) fn tracked_entry_values(&self) -> &[(CanonicalStorageId, u64)] {
        &self.0.tracked_entry_values
    }

    pub(crate) fn geometry(&self) -> MachineRegisterGeometryState {
        self.0.geometry
    }

    /// The projection the file declares for exactly this written storage.
    pub(crate) fn declared_projection(
        &self,
        written: RegisterStorage,
    ) -> Option<&RegisterProjection> {
        let projections = &self.0.projections;
        projections
            .binary_search_by_key(&written, |projection| projection.written)
            .ok()
            .map(|index| &projections[index])
    }

    /// The projection of a written storage the file does not declare, from its geometry.
    pub(crate) fn project(&self, written: RegisterStorage) -> Option<RegisterProjection> {
        self.0.query.as_ref().map(|query| query.project(written))
    }

    pub(crate) fn memory_model(&self) -> &MachineMemoryModel {
        &self.0.memory_model
    }

    /// Where the architecture returns a value, when it says.
    pub(crate) fn result_slot(&self) -> Option<CanonicalStorageId> {
        self.0.result_slot
    }
}

impl Deref for Arch {
    type Target = ArchSpec;

    fn deref(&self) -> &ArchSpec {
        &self.0.spec
    }
}

impl From<ArchSpec> for Arch {
    fn from(spec: ArchSpec) -> Self {
        Self::new(spec)
    }
}

impl From<Arc<ArchSpec>> for Arch {
    fn from(spec: Arc<ArchSpec>) -> Self {
        Self::new(spec)
    }
}

/// Two architectures are one when their identity and every table a function reads agree.
impl PartialEq for Arch {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
            || (self.0.spec.name == other.0.spec.name
                && self.0.spec.variant == other.0.spec.variant
                && self.0.registers_by_name == other.0.registers_by_name
                && self.0.projections == other.0.projections
                && self.0.memory_model == other.0.memory_model)
    }
}

impl Eq for Arch {}

/// Each name the file gives exactly one storage, lowercased; a name two storages share names neither.
fn unique_register_names(spec: &ArchSpec) -> BTreeMap<String, CanonicalStorageId> {
    let mut declared = BTreeMap::<String, Vec<CanonicalStorageId>>::new();
    for register in &spec.registers {
        if register.size != 0
            && register
                .offset
                .checked_add(u64::from(register.size))
                .is_some()
        {
            declared
                .entry(register.name.trim().to_ascii_lowercase())
                .or_default()
                .push(CanonicalStorageId {
                    space: CanonicalStorageSpace::Register,
                    offset: register.offset,
                    size: register.size,
                });
        }
    }
    declared
        .into_iter()
        .filter_map(|(name, storages)| match storages.as_slice() {
            [storage] => Some((name, *storage)),
            _ => None,
        })
        .collect()
}

/// Each register no wider one contains, by offset, in `O(r log r)`.
fn outermost_registers(spec: &ArchSpec) -> Box<[CanonicalStorageId]> {
    let mut registers = spec
        .registers
        .iter()
        .filter(|register| register.size != 0)
        .map(|register| (register.offset, register.size))
        .collect::<Vec<_>>();
    // Widest first at each offset, so a register is kept only when nothing kept before it reaches past its end.
    registers.sort_by(|left, right| left.0.cmp(&right.0).then(right.1.cmp(&left.1)));
    let mut outermost = Vec::new();
    let mut covered_to = 0u64;
    for (offset, size) in registers {
        let end = offset.saturating_add(u64::from(size));
        if end <= covered_to {
            continue;
        }
        covered_to = covered_to.max(end);
        outermost.push(CanonicalStorageId {
            space: CanonicalStorageSpace::Register,
            offset,
            size,
        });
    }
    outermost.into_boxed_slice()
}
