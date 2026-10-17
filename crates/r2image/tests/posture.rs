//! How an image is linked and protected, each expectation as `readelf -lW -d` and radare2's `i` state it.

use r2image::{Image, Posture, Relro};

fn posture(bytes: &[u8]) -> Posture {
    let image = Image::parse(bytes.to_vec()).expect("the fixture parses");
    image.container().posture.clone()
}

#[test]
fn a_dynamic_executable_states_its_interpreter_and_a_full_relro() {
    let posture = posture(include_bytes!("../../../tests/fixtures/rv_O0g"));
    assert_eq!(
        posture.interpreter.as_deref(),
        Some("/lib64/ld-linux-x86-64.so.2")
    );
    assert_eq!(posture.nx, Some(true));
    assert!(posture.pic);
    assert_eq!(posture.relro, Some(Relro::Full));
    assert!(!posture.statically_linked);
}

#[test]
fn a_static_executable_has_no_interpreter_and_no_relro() {
    let posture = posture(include_bytes!("../../../tests/fixtures/syscalls_static_O2"));
    assert_eq!(posture.interpreter, None);
    assert!(!posture.pic);
    assert_eq!(posture.relro, Some(Relro::No));
    assert!(posture.statically_linked);
}

/// A shared object has `PT_DYNAMIC` and no interpreter: it is not static, and nothing but another
/// image's loader relocates it.
#[test]
fn a_shared_object_is_neither_interpreted_nor_static() {
    let posture = posture(include_bytes!("../../../tests/fixtures/arm_plt_lld_be8.so"));
    assert_eq!(posture.interpreter, None);
    assert!(posture.pic);
    assert_eq!(posture.relro, Some(Relro::Partial));
    assert!(!posture.statically_linked);
}

/// Mach-O and PE state none of it in these terms: nothing is claimed.
#[test]
fn a_format_without_program_headers_states_no_posture() {
    let posture = posture(include_bytes!("../../../tests/fixtures/manual_limits_O0"));
    assert_eq!(posture, Posture::default());
}

/// Each program header of `rv_O0g` with its offset and size set to `value`: a path and a dynamic
/// section that run past the file (D18). The posture reads to the bytes held and claims no more.
#[test]
fn a_header_stating_bytes_past_the_file_reads_only_the_bytes_the_file_holds() {
    let whole = include_bytes!("../../../tests/fixtures/rv_O0g");
    let word = |at: usize| u64::from_le_bytes(whole[at..at + 8].try_into().unwrap()) as usize;
    let (table, size, count) = (
        word(0x20),
        usize::from(u16::from_le_bytes([whole[0x36], whole[0x37]])),
        usize::from(u16::from_le_bytes([whole[0x38], whole[0x39]])),
    );
    for value in [u64::MAX, u64::MAX - 7, 1 << 40, whole.len() as u64 + 1] {
        for header in 0..count {
            let mut bytes = whole.to_vec();
            let at = table + header * size;
            // `p_offset` and `p_filesz` of an ELF64 header.
            bytes[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
            bytes[at + 32..at + 40].copy_from_slice(&value.to_le_bytes());
            if let Ok(image) = Image::parse(bytes) {
                let posture = &image.container().posture;
                assert!(posture.interpreter.is_some() || posture.statically_linked);
            }
        }
    }
}
