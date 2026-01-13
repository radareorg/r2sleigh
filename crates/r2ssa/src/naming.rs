use std::collections::HashMap;

use r2il::{select_register_name, ArchSpec, SpaceId, Varnode};

pub type RegisterNameMap = HashMap<(u64, u32), String>;

pub fn build_register_name_map(arch: &ArchSpec) -> RegisterNameMap {
    let mut candidates: HashMap<(u64, u32), Vec<String>> = HashMap::new();
    for reg in &arch.registers {
        let key = (reg.offset, reg.size);
        candidates.entry(key).or_default().push(reg.name.clone());
    }

    let mut map = HashMap::new();
    for (key, names) in candidates {
        if let Some(name) = select_register_name(names.iter().map(String::as_str)) {
            map.insert(key, name.to_lowercase());
        }
    }

    map
}

pub fn varnode_to_name(vn: &Varnode, reg_names: Option<&RegisterNameMap>) -> String {
    match vn.space {
        SpaceId::Register => {
            if let Some(map) = reg_names {
                if let Some(name) = map.get(&(vn.offset, vn.size)) {
                    return format!("reg:{}", name);
                }
            }
            format!("reg:{:x}", vn.offset)
        }
        SpaceId::Unique => format!("tmp:{:x}", vn.offset),
        SpaceId::Const => format!("const:{:x}", vn.offset),
        SpaceId::Ram => format!("ram:{:x}", vn.offset),
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
        assert_eq!(varnode_to_name(&vn, None), "reg:10");
    }

    #[test]
    fn test_varnode_to_name_with_map() {
        // Register with name map uses named register
        let mut map = RegisterNameMap::new();
        map.insert((0x10, 8), "rax".to_string());

        let vn = Varnode {
            space: SpaceId::Register,
            offset: 0x10,
            size: 8,
        };
        assert_eq!(varnode_to_name(&vn, Some(&map)), "reg:rax");
    }

    #[test]
    fn test_varnode_to_name_map_miss() {
        // Register not in map falls back to hex
        let mut map = RegisterNameMap::new();
        map.insert((0x20, 8), "rbx".to_string());

        let vn = Varnode {
            space: SpaceId::Register,
            offset: 0x10,
            size: 8,
        };
        assert_eq!(varnode_to_name(&vn, Some(&map)), "reg:10");
    }

    #[test]
    fn test_varnode_to_name_other_spaces() {
        // Test other space types
        let const_vn = Varnode {
            space: SpaceId::Const,
            offset: 0x42,
            size: 4,
        };
        assert_eq!(varnode_to_name(&const_vn, None), "const:42");

        let tmp_vn = Varnode {
            space: SpaceId::Unique,
            offset: 0x1000,
            size: 8,
        };
        assert_eq!(varnode_to_name(&tmp_vn, None), "tmp:1000");

        let ram_vn = Varnode {
            space: SpaceId::Ram,
            offset: 0x400000,
            size: 8,
        };
        assert_eq!(varnode_to_name(&ram_vn, None), "ram:400000");
    }
}
