use r2il::{ArchSpec, SpaceId, Varnode, select_register_name};
use rustc_hash::FxHashMap;

pub type RegisterNameMap = FxHashMap<(u64, u32), String>;

/// Each register-space `(offset, size)` the file names, with the name it is spelled by.
pub(crate) fn register_name_map(arch: &ArchSpec) -> RegisterNameMap {
    let mut names_by_key: FxHashMap<(u64, u32), Vec<&str>> =
        FxHashMap::with_capacity_and_hasher(arch.registers.len(), Default::default());
    for reg in &arch.registers {
        names_by_key
            .entry((reg.offset, reg.size))
            .or_default()
            .push(reg.name.as_str());
    }

    names_by_key
        .into_iter()
        .filter_map(|(key, names)| select_register_name(names).map(|name| (key, name)))
        .collect()
}

/// A frame object's name where nothing declares one: where it sits from the entry stack pointer, as C spells it.
pub fn frame_object_name(entry_offset: i64) -> String {
    let side = if entry_offset < 0 { 'm' } else { 'p' };
    format!("stack_{side}{}", entry_offset.unsigned_abs())
}

/// A promoted frame slot's spelling, in the coordinate every frame object is
/// named by: where it sits relative to the frame the function was entered with.
pub fn frame_slot_name(entry_offset: i64) -> String {
    if entry_offset < 0 {
        format!("stack:m{}", entry_offset.unsigned_abs())
    } else {
        format!("stack:p{}", entry_offset.unsigned_abs())
    }
}

/// A temporary's name: the instruction it belongs to and its offset there (ROADMAP D36).
pub fn temporary_name(instruction: u64, offset: u64) -> String {
    format!("tmp:{instruction:x}:{offset:x}")
}

/// A varnode's name, read or written by `instruction`, whose own a temporary is; a register is
/// spelled by the map, or `reg:<offset>` where it has none.
pub fn varnode_to_name(
    vn: &Varnode,
    reg_names: Option<&RegisterNameMap>,
    instruction: u64,
) -> String {
    match vn.space {
        SpaceId::Register => {
            if let Some(map) = reg_names
                && let Some(name) = map.get(&(vn.offset, vn.size))
            {
                return name.clone();
            }
            format!("reg:{:x}", vn.offset)
        }
        SpaceId::Unique => temporary_name(instruction, vn.offset),
        SpaceId::Const => format!("const:{:x}", vn.offset),
        SpaceId::Ram => format!("ram:{:x}", vn.offset),
        SpaceId::Custom(id) if id == crate::slot_promotion::PROMOTED_SLOT_SPACE => {
            frame_slot_name(vn.offset as i64)
        }
        SpaceId::Custom(id) => format!("space{}:{:x}", id, vn.offset),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varnode_to_name_without_map() {
        // Register without name map falls back to hex
        let vn = Varnode {
            space: SpaceId::Register,
            offset: 0x10,
            size: 8,
        };
        assert_eq!(varnode_to_name(&vn, None, 0), "reg:10");
    }

    #[test]
    fn test_varnode_to_name_with_map() {
        // Register with name map uses named register (no prefix)
        let mut map = RegisterNameMap::default();
        map.insert((0x10, 8), "rax".to_string());

        let vn = Varnode {
            space: SpaceId::Register,
            offset: 0x10,
            size: 8,
        };
        assert_eq!(varnode_to_name(&vn, Some(&map), 0), "rax");
    }

    #[test]
    fn test_varnode_to_name_map_miss() {
        // Register not in map falls back to hex
        let mut map = RegisterNameMap::default();
        map.insert((0x20, 8), "rbx".to_string());

        let vn = Varnode {
            space: SpaceId::Register,
            offset: 0x10,
            size: 8,
        };
        assert_eq!(varnode_to_name(&vn, Some(&map), 0), "reg:10");
    }

    #[test]
    fn test_varnode_to_name_other_spaces() {
        // Test other space types
        let const_vn = Varnode {
            space: SpaceId::Const,
            offset: 0x42,
            size: 4,
        };
        assert_eq!(varnode_to_name(&const_vn, None, 0), "const:42");

        let tmp_vn = Varnode {
            space: SpaceId::Unique,
            offset: 0x1000,
            size: 8,
        };
        assert_eq!(varnode_to_name(&tmp_vn, None, 0x401334), "tmp:401334:1000");

        let ram_vn = Varnode {
            space: SpaceId::Ram,
            offset: 0x400000,
            size: 8,
        };
        assert_eq!(varnode_to_name(&ram_vn, None, 0), "ram:400000");
    }
}
