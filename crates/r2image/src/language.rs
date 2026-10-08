//! Which language each function's source was written in, as the container states it
//! (doc/adr-language-profile.md, LP0): compile units first, then a symbol's recorded mangling.

use std::ops::Range;

use object::{Object as _, ObjectSection as _};
use r2abi::statement::{Binding, Languages, SourceLanguage, Symbol, SymbolKind};

type Slice<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

/// Every language the container states, by range, and the program's.
pub(crate) fn read(file: &object::File<'_>, symbols: &[Symbol]) -> Languages {
    // Mach-O and 32-bit PE (cdecl) decorate every name they define with one leading underscore.
    let decorated = file.format() == object::BinaryFormat::MachO
        || file.format() == object::BinaryFormat::Pe && !file.is_64();
    let mangling = |symbol: &Symbol| symbol_mangling(symbol, decorated);
    let units = compile_units(file);
    let mangled = symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Function && symbol.defined && symbol.size > 0)
        .filter_map(|symbol| {
            let language = mangling(symbol)?;
            Some((
                symbol.vaddr..symbol.vaddr.saturating_add(symbol.size),
                language,
            ))
        })
        .collect::<Vec<_>>();
    let program = program_language(file, symbols, &units, &mangled, &mangling);
    Languages {
        program,
        ranges: disjoint(units, mangled),
    }
}

/// The program's language as radare2 reads it: Go's runtime tables, then Rust, then C++, else C.
fn program_language(
    file: &object::File<'_>,
    symbols: &[Symbol],
    units: &[(Range<u64>, SourceLanguage)],
    mangled: &[(Range<u64>, SourceLanguage)],
    mangling: &dyn Fn(&Symbol) -> Option<SourceLanguage>,
) -> SourceLanguage {
    let section = |name: &str| file.section_by_name(name).is_some();
    let go = [
        "__gopclntab",
        ".gopclntab",
        "__go_buildinfo",
        ".go.buildinfo",
    ]
    .iter()
    .any(|name| section(name))
        || symbols
            .iter()
            .any(|symbol| symbol.name == "runtime.buildVersion");
    let states = |language: SourceLanguage| {
        units
            .iter()
            .chain(mangled)
            .any(|(_, stated)| *stated == language)
    };
    let rustc = file
        .section_by_name(".comment")
        .and_then(|section| section.data().ok())
        .is_some_and(|data| data.windows(5).any(|window| window == b"rustc"));
    // An Itanium name the program defines or imports, a strong import of the C++ ABI (libgcc's
    // unwinder refers to some weakly in C programs too), or the C++ runtime among its libraries.
    let cpp_symbol = symbols.iter().any(|symbol| {
        (symbol.defined || symbol.import) && mangling(symbol) == Some(SourceLanguage::Cpp)
            || symbol.import && symbol.binding != Binding::Weak && cpp_abi(&symbol.name)
    });
    // A name the program defines in Rust's mangling, whether or not its table states a size.
    let rust_symbol = symbols
        .iter()
        .any(|symbol| symbol.defined && mangling(symbol) == Some(SourceLanguage::Rust));
    let libraries = needed(file);
    let links = |stem: &str| libraries.iter().any(|library| library.contains(stem));
    let cpp_import = cpp_symbol || libraries.iter().any(|library| cpp_runtime(library));
    let named = |prefix: &str| {
        file.sections()
            .any(|section| section.name().is_ok_and(|name| name.starts_with(prefix)))
    };
    let swift = named("__swift5")
        || named("swift5_")
        || links("libswiftCore")
        || states(SourceLanguage::Swift);
    // Classes, categories or protocols: Xcode leaves `__objc_imageinfo` in C and C++ programs too.
    let objc = ["__objc_classlist", "__objc_catlist", "__objc_protolist"]
        .iter()
        .any(|name| named(name))
        || states(SourceLanguage::ObjectiveC);
    if go {
        SourceLanguage::Go
    } else if rustc || rust_symbol || states(SourceLanguage::Rust) {
        SourceLanguage::Rust
    } else if swift {
        SourceLanguage::Swift
    } else if objc {
        SourceLanguage::ObjectiveC
    } else if clr_header(file) {
        SourceLanguage::Cil
    } else if cpp_import || states(SourceLanguage::Cpp) {
        SourceLanguage::Cpp
    } else {
        SourceLanguage::C
    }
}

/// Whether a name is the C++ ABI's own: exceptions, RTTI, pure virtuals and guards, not the
/// `__cxa_atexit` and `__cxa_finalize` every C runtime imports as well.
fn cpp_abi(name: &str) -> bool {
    // A static table spells an undefined symbol with its version: `__cxa_finalize@@GLIBC_2.2.5`.
    let name = name
        .split('@')
        .next()
        .unwrap_or(name)
        .trim_start_matches('_');
    name.starts_with("gxx_personality")
        || name.starts_with("cxa_")
            && !matches!(
                name,
                "cxa_atexit" | "cxa_finalize" | "cxa_thread_atexit_impl"
            )
}

/// Whether a PE states a CLR runtime header: its code is .NET's intermediate language.
fn clr_header(file: &object::File<'_>) -> bool {
    let directory = object::pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR;
    // `IMAGE_COR20_HEADER`'s 72 bytes inside a section: a folded header's stray words are not one.
    let base = file.relative_address_base();
    let stated = |entry: Option<&object::pe::ImageDataDirectory>| {
        entry.is_some_and(|entry| {
            let start = u64::from(entry.virtual_address.get(object::LittleEndian));
            let size = u64::from(entry.size.get(object::LittleEndian));
            size >= 72
                && file.sections().any(|section| {
                    let from = section.address().saturating_sub(base);
                    from <= start && start + size <= from + section.size()
                })
        })
    };
    match file {
        object::File::Pe32(pe) => stated(pe.data_directory(directory)),
        object::File::Pe64(pe) => stated(pe.data_directory(directory)),
        _ => false,
    }
}

/// Whether a library is a C++ runtime: GNU's, LLVM's, or Microsoft's.
fn cpp_runtime(library: &str) -> bool {
    let library = library.rsplit('/').next().unwrap_or(library);
    library.starts_with("libstdc++")
        || library.starts_with("libc++")
        || library.to_ascii_lowercase().starts_with("msvcp")
}

/// The libraries the program states it needs: ELF's `DT_NEEDED`, PE's import descriptors, Mach-O's
/// dylib commands. Names only, at most `LIBRARIES` of them: a crafted table can state millions.
fn needed(file: &object::File<'_>) -> Vec<String> {
    let mut libraries = match file {
        object::File::Pe32(pe) => pe_needed(pe),
        object::File::Pe64(pe) => pe_needed(pe),
        object::File::MachO32(macho) => macho_needed(macho),
        object::File::MachO64(macho) => macho_needed(macho),
        _ => elf_needed(file),
    };
    libraries.sort_unstable();
    libraries.dedup();
    libraries
}

/// More libraries than any program links: the reading stops there.
const LIBRARIES: usize = 4096;

fn pe_needed<Pe: object::read::pe::ImageNtHeaders>(
    pe: &object::read::pe::PeFile<'_, Pe>,
) -> Vec<String> {
    let Ok(Some(table)) = pe.import_table() else {
        return Vec::new();
    };
    let Ok(mut descriptors) = table.descriptors() else {
        return Vec::new();
    };
    let mut names = Vec::new();
    while let (true, Ok(Some(descriptor))) = (names.len() < LIBRARIES, descriptors.next()) {
        if let Ok(name) = table.name(descriptor.name.get(object::LittleEndian)) {
            names.push(String::from_utf8_lossy(name).into_owned());
        }
    }
    names
}

fn macho_needed<Mach: object::read::macho::MachHeader>(
    macho: &object::read::macho::MachOFile<'_, Mach>,
) -> Vec<String> {
    let endian = macho.endian();
    let Ok(mut commands) = macho.macho_load_commands() else {
        return Vec::new();
    };
    let mut names = Vec::new();
    while let (true, Ok(Some(command))) = (names.len() < LIBRARIES, commands.next()) {
        if let Ok(Some(dylib)) = command.dylib()
            && let Ok(name) = command.string(endian, dylib.dylib.name)
        {
            names.push(String::from_utf8_lossy(name).into_owned());
        }
    }
    names
}

/// ELF's `DT_NEEDED` names, read as the loader reads them: through `PT_DYNAMIC`, the string
/// table found by `DT_STRTAB`'s address in a `PT_LOAD`, so a dump with no section headers answers.
fn elf_needed(file: &object::File<'_>) -> Vec<String> {
    let mut names = match file {
        object::File::Elf32(elf) => needed_through_dynamic(elf),
        object::File::Elf64(elf) => needed_through_dynamic(elf),
        _ => Vec::new(),
    };
    names.truncate(LIBRARIES);
    names
}

fn needed_through_dynamic<Elf: object::read::elf::FileHeader>(
    elf: &object::read::elf::ElfFile<'_, Elf>,
) -> Vec<String> {
    use object::read::elf::{Dyn as _, ProgramHeader as _};
    let (endian, data) = (elf.endian(), elf.data());
    let headers = elf.elf_program_headers();
    let Some(entries) = headers
        .iter()
        .find_map(|header| header.dynamic(endian, data).ok().flatten())
    else {
        return Vec::new();
    };
    let tagged = |tag: u32| {
        entries
            .iter()
            .filter(move |entry| entry.d_tag(endian).into() == u64::from(tag))
            .map(move |entry| entry.d_val(endian).into())
    };
    // Where `DT_STRTAB`'s address lies in the file: the `PT_LOAD` that maps it.
    let Some(strings) = tagged(object::elf::DT_STRTAB).next().and_then(|vaddr| {
        headers.iter().find_map(|header| {
            let start: u64 = header.p_vaddr(endian).into();
            let held: u64 = header.p_filesz(endian).into();
            let offset: u64 = header.p_offset(endian).into();
            (header.p_type(endian) == object::elf::PT_LOAD
                && (start..start + held).contains(&vaddr))
            .then(|| offset + (vaddr - start))
        })
    }) else {
        return Vec::new();
    };
    tagged(object::elf::DT_NEEDED)
        .filter_map(|name| {
            let start = usize::try_from(strings.checked_add(name)?).ok()?;
            let tail = data.get(start..)?;
            let end = tail.iter().position(|byte| *byte == 0)?;
            Some(String::from_utf8_lossy(&tail[..end]).into_owned())
        })
        .collect()
}

/// A symbol's mangling, its name read as the source spelled it: a decorating format adds one
/// leading underscore to every name it defines (its imports are stored without it).
fn symbol_mangling(symbol: &Symbol, decorated: bool) -> Option<SourceLanguage> {
    match decorated && symbol.defined {
        true => mangling(symbol.name.strip_prefix('_')?),
        false => mangling(&symbol.name),
    }
}

/// The language a name's mangling records: Rust's v0 or legacy scheme, else Itanium C++.
fn mangling(name: &str) -> Option<SourceLanguage> {
    let name = name.split('@').next().unwrap_or(name);
    // Swift 5's `$s`, and an Objective-C method, which its symbol spells as the message.
    if ["$s", "_$s", "$S", "_$S"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return Some(SourceLanguage::Swift);
    }
    if name.starts_with("-[") || name.starts_with("+[") {
        return Some(SourceLanguage::ObjectiveC);
    }
    if let Some(rest) = name.strip_prefix("_R") {
        // v0: an optional decimal vendor tag, then a path tag.
        let path = rest.trim_start_matches(|c: char| c.is_ascii_digit());
        return path
            .starts_with(['N', 'C', 'M', 'X', 'Y', 'I', 'B'])
            .then_some(SourceLanguage::Rust);
    }
    let rest = name.strip_prefix("_Z")?;
    // Rust's legacy scheme is Itanium's nested name ending in a 16-digit hash: `17h<hash>E`.
    let hashed = rest.starts_with('N')
        && name.len() > 20
        && name.ends_with('E')
        && name[name.len() - 20..name.len() - 1].starts_with("17h")
        && name[name.len() - 17..name.len() - 1]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
    Some(match hashed {
        true => SourceLanguage::Rust,
        false => SourceLanguage::Cpp,
    })
}

/// Each compile unit's ranges and the language it states.
fn compile_units(file: &object::File<'_>) -> Vec<(Range<u64>, SourceLanguage)> {
    let endian = match file.endianness() {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };
    let load = |id: gimli::SectionId| -> Result<Slice<'_>, ()> {
        let data = file
            .section_by_name(id.name())
            .and_then(|section| section.data().ok())
            .unwrap_or(&[]);
        Ok(gimli::EndianSlice::new(data, endian))
    };
    let Ok(dwarf) = gimli::Dwarf::load(load) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    let mut headers = dwarf.units();
    while let Ok(Some(header)) = headers.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        if let Some(language) = unit_language(&unit) {
            found.extend(unit_ranges(&dwarf, &unit).map(|range| (range, language)));
        }
    }
    found
}

/// What a compile unit's `DW_AT_language` says, where it is a language with a profile.
fn unit_language(unit: &gimli::Unit<Slice<'_>>) -> Option<SourceLanguage> {
    let mut entries = unit.entries();
    let root = entries.next_dfs().ok()??;
    let gimli::AttributeValue::Language(language) = root.attr_value(gimli::DW_AT_language)? else {
        return None;
    };
    Some(match language {
        gimli::DW_LANG_C89 | gimli::DW_LANG_C | gimli::DW_LANG_C99 | gimli::DW_LANG_C11 => {
            SourceLanguage::C
        }
        gimli::DW_LANG_C_plus_plus
        | gimli::DW_LANG_C_plus_plus_03
        | gimli::DW_LANG_C_plus_plus_11
        | gimli::DW_LANG_C_plus_plus_14
        | gimli::DW_LANG_C_plus_plus_17
        | gimli::DW_LANG_C_plus_plus_20 => SourceLanguage::Cpp,
        gimli::DW_LANG_Rust => SourceLanguage::Rust,
        gimli::DW_LANG_Go => SourceLanguage::Go,
        _ => return None,
    })
}

/// The address ranges a unit covers.
fn unit_ranges<'a>(
    dwarf: &gimli::Dwarf<Slice<'a>>,
    unit: &gimli::Unit<Slice<'a>>,
) -> impl Iterator<Item = Range<u64>> {
    let mut found = Vec::new();
    if let Ok(mut ranges) = dwarf.unit_ranges(unit) {
        while let Ok(Some(range)) = ranges.next() {
            if range.begin < range.end {
                found.push(range.begin..range.end);
            }
        }
    }
    found.into_iter()
}

/// Units first, then mangled symbols outside them; sorted by start, the later of two overlapping
/// ranges dropped.
fn disjoint(
    units: Vec<(Range<u64>, SourceLanguage)>,
    mangled: Vec<(Range<u64>, SourceLanguage)>,
) -> Vec<(Range<u64>, SourceLanguage)> {
    let mut ranges = units;
    let mut units_sorted = ranges
        .iter()
        .map(|(range, _)| range.clone())
        .collect::<Vec<_>>();
    units_sorted.sort_unstable_by_key(|range| range.start);
    let inside_unit = |range: &Range<u64>| {
        let after = units_sorted.partition_point(|unit| unit.start < range.end);
        units_sorted[..after]
            .iter()
            .any(|unit| unit.start < range.end && range.start < unit.end)
    };
    ranges.extend(mangled.into_iter().filter(|(range, _)| !inside_unit(range)));
    ranges.sort_by_key(|(range, _)| (range.start, range.end));
    let mut kept: Vec<(Range<u64>, SourceLanguage)> = Vec::with_capacity(ranges.len());
    for (range, language) in ranges {
        if kept.last().is_none_or(|(last, _)| last.end <= range.start) {
            kept.push((range, language));
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_symbol_s_mangling_states_its_language() {
        let cases = [
            (
                "_ZN4core3fmt5write17h0123456789abcdefE",
                Some(SourceLanguage::Rust),
            ),
            ("_RNvCs1234_7mycrate4main", Some(SourceLanguage::Rust)),
            ("_ZN3foo3barEv", Some(SourceLanguage::Cpp)),
            ("_Z3addii", Some(SourceLanguage::Cpp)),
            ("main", None),
            ("_main", None),
            ("_Runtime", None),
            ("$s4main3fooyyF", Some(SourceLanguage::Swift)),
            (
                "-[AppDelegate application:didFinishLaunchingWithOptions:]",
                Some(SourceLanguage::ObjectiveC),
            ),
        ];
        for (name, expected) in cases {
            assert_eq!(mangling(name), expected, "{name}");
        }
    }

    #[test]
    fn the_cxx_abi_is_cxx_s_and_not_what_c_runtimes_import() {
        for name in [
            "__cxa_pure_virtual",
            "__cxa_begin_catch",
            "__gxx_personality_v0",
        ] {
            assert!(cpp_abi(name), "{name}");
        }
        for name in [
            "__cxa_atexit",
            "__cxa_finalize",
            "__cxa_finalize@@GLIBC_2.2.5",
            "__cxa_thread_atexit_impl",
            "printf",
        ] {
            assert!(!cpp_abi(name), "{name}");
        }
    }

    /// Mach-O's `_RIM_2608` is C's `RIM_2608`; its `__ZN3foo3barEv` is C++'s `_ZN3foo3barEv`.
    #[test]
    fn a_macho_name_is_read_without_its_decoration() {
        let defined = |name: &str| Symbol {
            name: name.to_owned(),
            defined: true,
            ..Symbol::default()
        };
        assert_eq!(symbol_mangling(&defined("_RIM_2608"), true), None);
        assert_eq!(
            symbol_mangling(&defined("__ZN3foo3barEv"), true),
            Some(SourceLanguage::Cpp)
        );
        assert_eq!(
            symbol_mangling(&defined("_ZN3foo3barEv"), false),
            Some(SourceLanguage::Cpp)
        );
    }

    #[test]
    fn a_cxx_runtime_is_named_by_its_library() {
        for library in [
            "libstdc++.so.6",
            "/usr/lib/libc++.1.dylib",
            "libc++_shared.so",
            "MSVCP140.dll",
        ] {
            assert!(cpp_runtime(library), "{library}");
        }
        for library in ["libc.so.6", "libm.so.6", "libgcc_s.so.1", "libcrypto.so"] {
            assert!(!cpp_runtime(library), "{library}");
        }
    }

    #[test]
    fn a_unit_s_range_outranks_a_symbol_s_mangling() {
        let kept = disjoint(
            vec![(0x1000..0x2000, SourceLanguage::C)],
            vec![
                (0x1100..0x1200, SourceLanguage::Cpp),
                (0x3000..0x3100, SourceLanguage::Rust),
            ],
        );
        assert_eq!(
            kept,
            [
                (0x1000..0x2000, SourceLanguage::C),
                (0x3000..0x3100, SourceLanguage::Rust)
            ]
        );
        let languages = Languages {
            program: SourceLanguage::Go,
            ranges: kept,
        };
        assert_eq!(languages.at(0x1150), SourceLanguage::C);
        assert_eq!(languages.at(0x3050), SourceLanguage::Rust);
        assert_eq!(languages.at(0x5000), SourceLanguage::Go);
    }
}
