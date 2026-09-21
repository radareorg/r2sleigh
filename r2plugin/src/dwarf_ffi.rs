//! The debug information, read once, for the capture that is building a
//! snapshot.
//!
//! radare2 has the binary open and parses these sections itself, and the C
//! side used to walk the entries a second time to answer two questions: which
//! register a function's frame is measured from, and where a formal sits in
//! the parameter list. Two readers of one format is one too many, so the C
//! hands over the section bytes it already has and this answers from the same
//! reader the native route uses.

use std::ffi::{CStr, c_char};

/// One debug section, as the caller already holds it.
#[repr(C)]
pub struct R2SleighDwarfSectionV2 {
    /// The section's name, as the format spells it: `.debug_info`.
    pub name: *const c_char,
    pub data: *const u8,
    pub len: usize,
}

/// Everything the debug information states, owned by the caller's handle.
pub struct R2SleighDwarfFactsV2 {
    prototypes: r2image::debug::DebugPrototypes,
}

/// The sections the reader asks for, so a caller collecting them does not
/// carry its own copy of the list.
///
/// Leaving one out is not the same as a binary that lacks it: a unit naming a
/// line program that is not there fails to parse and takes its subprograms
/// with it.
#[unsafe(no_mangle)]
pub extern "C" fn r2sleigh_dwarf_section_count_v2() -> usize {
    SECTION_NAMES.len()
}

/// The `index`th such section's name, NUL-terminated, or `NULL`.
#[unsafe(no_mangle)]
pub extern "C" fn r2sleigh_dwarf_section_name_v2(index: usize) -> *const c_char {
    SECTION_NAMES
        .get(index)
        .map_or(std::ptr::null(), |name| name.as_ptr())
}

/// The reader's list, NUL-terminated for the caller that asks across the
/// boundary. Derived from the reader rather than written out again: a name
/// here that the reader does not ask for is a section collected for nothing,
/// and one it asks for that is missing here is a unit lost.
static SECTION_NAMES: std::sync::LazyLock<Vec<std::ffi::CString>> =
    std::sync::LazyLock::new(|| {
        r2image::debug::sections()
            .map(|name| std::ffi::CString::new(name).expect("a section name has no NUL"))
            .collect()
    });

/// Read the debug information these sections carry.
///
/// # Safety
/// `sections` must point to `count` readable entries, each naming a
/// NUL-terminated string and `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn r2sleigh_dwarf_open_v2(
    sections: *const R2SleighDwarfSectionV2,
    count: usize,
    big_endian: bool,
) -> *mut R2SleighDwarfFactsV2 {
    if sections.is_null() || count == 0 {
        return std::ptr::null_mut();
    }
    let entries = unsafe { std::slice::from_raw_parts(sections, count) };
    let named = entries
        .iter()
        .filter_map(|entry| {
            if entry.name.is_null() || entry.data.is_null() || entry.len == 0 {
                return None;
            }
            let name = unsafe { CStr::from_ptr(entry.name) }.to_str().ok()?;
            let data = unsafe { std::slice::from_raw_parts(entry.data, entry.len) };
            Some((name, data))
        })
        .collect::<Vec<_>>();
    let endian = match big_endian {
        true => gimli::RunTimeEndian::Big,
        false => gimli::RunTimeEndian::Little,
    };
    let prototypes = r2image::debug::read_sections(endian, |name| {
        named
            .iter()
            .find(|(other, _)| *other == name)
            .map(|(_, data)| *data)
    });
    Box::into_raw(Box::new(R2SleighDwarfFactsV2 { prototypes }))
}

/// # Safety
/// `facts` must be a handle this module returned and not yet closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn r2sleigh_dwarf_close_v2(facts: *mut R2SleighDwarfFactsV2) {
    if !facts.is_null() {
        drop(unsafe { Box::from_raw(facts) });
    }
}

/// The register the debug information names as this function's frame base.
///
/// A base computed from the canonical frame address names no register and
/// answers with nothing, which is what most optimised code carries. The name
/// is this machine's, so the caller says which machine it is asking about.
///
/// # Safety
/// `facts` must be a live handle and `arch` a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn r2sleigh_dwarf_frame_base_register_v2(
    facts: *const R2SleighDwarfFactsV2,
    function_addr: u64,
    arch: *const c_char,
    bits: u32,
) -> *const c_char {
    if facts.is_null() || arch.is_null() {
        return std::ptr::null();
    }
    let facts = unsafe { &*facts };
    let Ok(arch) = (unsafe { CStr::from_ptr(arch) }).to_str() else {
        return std::ptr::null();
    };
    let Some(r2abi::FrameBase::Register(number)) = facts
        .prototypes
        .at(function_addr)
        .and_then(|prototype| prototype.frame_base)
    else {
        return std::ptr::null();
    };
    match r2abi::dwarf_frame_register(arch, bits, number) {
        Some((r2abi::FrameRole::FramePointer, name)) => frame_register_name(name),
        _ => std::ptr::null(),
    }
}

/// The NUL-terminated spelling of one frame register.
///
/// The table hands out `&'static str`, and C needs a terminator, so the names
/// are matched against the literals rather than a string being built and
/// leaked for every question.
fn frame_register_name(name: &str) -> *const c_char {
    let literal = match name {
        "rbp" => c"rbp",
        "ebp" => c"ebp",
        "x29" => c"x29",
        "r11" => c"r11",
        _ => return std::ptr::null(),
    };
    literal.as_ptr()
}

/// Where `name` sits in this function's formal parameter list.
///
/// This is the position the caller passes it in, not radare2's dense argument
/// index: a formal the importer could not place still occupies one. `-1` where
/// the debug information does not describe the function or does not name a
/// formal this way.
///
/// # Safety
/// `facts` must be a live handle and `name` a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn r2sleigh_dwarf_formal_ordinal_v2(
    facts: *const R2SleighDwarfFactsV2,
    function_addr: u64,
    name: *const c_char,
) -> i32 {
    if facts.is_null() || name.is_null() {
        return -1;
    }
    let facts = unsafe { &*facts };
    let Ok(name) = (unsafe { CStr::from_ptr(name) }).to_str() else {
        return -1;
    };
    // One name, one position. A repeated formal name describes nothing this
    // can certify, so it answers absent rather than picking the first.
    let Some(prototype) = facts.prototypes.at(function_addr) else {
        return -1;
    };
    let mut found = None;
    for (position, parameter) in prototype.parameters.iter().enumerate() {
        if parameter.name.as_deref() != Some(name) {
            continue;
        }
        if found.is_some() {
            return -1;
        }
        found = Some(position);
    }
    found
        .and_then(|position| i32::try_from(position).ok())
        .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    /// The same fixture the reader's own tests use, so both sides of this
    /// boundary are checked against one binary.
    const FIXTURE: &[u8] = include_bytes!("../../crates/r2image/tests/data/dwarf_prototypes.elf");

    struct Opened {
        facts: *mut R2SleighDwarfFactsV2,
        _names: Vec<CString>,
    }

    impl Drop for Opened {
        fn drop(&mut self) {
            unsafe { r2sleigh_dwarf_close_v2(self.facts) };
        }
    }

    fn open() -> Opened {
        use object::{Object as _, ObjectSection as _};
        let file = object::File::parse(FIXTURE).expect("the fixture parses");
        // Every name first: taking a pointer into a vector that is still
        // growing hands out an address the next push may move.
        let found = r2image::debug::sections()
            .filter_map(|name| {
                let data = file
                    .section_by_name(name)
                    .and_then(|section| section.data().ok())?;
                Some((CString::new(name).expect("a section name has no NUL"), data))
            })
            .collect::<Vec<_>>();
        let names = found.iter().map(|(name, _)| name.clone()).collect();
        let sections = found
            .iter()
            .map(|(name, data)| R2SleighDwarfSectionV2 {
                name: name.as_ptr(),
                data: data.as_ptr(),
                len: data.len(),
            })
            .collect::<Vec<_>>();
        let facts = unsafe { r2sleigh_dwarf_open_v2(sections.as_ptr(), sections.len(), false) };
        assert!(!facts.is_null(), "the fixture's sections read");
        Opened {
            facts,
            _names: names,
        }
    }

    #[test]
    fn a_frame_measured_from_a_register_names_it() {
        let opened = open();
        // `shifted`, which `-O0` gives an ordinary base-pointer frame.
        let arch = CString::new("x86-64").expect("arch");
        let name = unsafe {
            r2sleigh_dwarf_frame_base_register_v2(opened.facts, 0x14c0, arch.as_ptr(), 64)
        };
        assert!(!name.is_null(), "the frame base names no register");
        assert_eq!(
            unsafe { CStr::from_ptr(name) }.to_str().expect("utf-8"),
            "rbp"
        );
    }

    #[test]
    fn a_function_the_debug_information_does_not_describe_names_nothing() {
        let opened = open();
        let arch = CString::new("x86-64").expect("arch");
        let name = unsafe {
            r2sleigh_dwarf_frame_base_register_v2(opened.facts, 0xdead, arch.as_ptr(), 64)
        };
        assert!(name.is_null());
    }

    #[test]
    fn a_formal_is_found_at_the_position_the_caller_passes_it() {
        let opened = open();
        // `char *pick(char **names, int index)`.
        for (name, expected) in [("names", 0), ("index", 1), ("absent", -1)] {
            let spelling = CString::new(name).expect("name");
            assert_eq!(
                unsafe {
                    r2sleigh_dwarf_formal_ordinal_v2(opened.facts, 0x1440, spelling.as_ptr())
                },
                expected,
                "{name}"
            );
        }
    }
}
