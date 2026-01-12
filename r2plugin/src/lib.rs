//! r2sleigh radare2 plugin
//!
//! This module provides C-ABI functions for radare2 integration.
//! It allows r2 to load compiled .r2il files and use them for
//! instruction lifting and analysis.
//!
//! # C API
//!
//! ```c
//! // Load an r2il file
//! R2IL_Context* r2il_load(const char* path);
//!
//! // Free a context
//! void r2il_free(R2IL_Context* ctx);
//!
//! // Get architecture name
//! const char* r2il_arch_name(R2IL_Context* ctx);
//!
//! // Check if loaded
//! int r2il_is_loaded(R2IL_Context* ctx);
//! ```

use r2il::{serialize, ArchSpec};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::ptr;

/// Opaque context handle for C API.
pub struct R2ILContext {
    arch: Option<ArchSpec>,
    arch_name_cstr: Option<CString>,
    error: Option<CString>,
}

impl R2ILContext {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            arch: None,
            arch_name_cstr: None,
            error: None,
        }
    }

    fn with_arch(arch: ArchSpec) -> Self {
        let name = CString::new(arch.name.clone()).ok();
        Self {
            arch: Some(arch),
            arch_name_cstr: name,
            error: None,
        }
    }

    fn with_error(msg: &str) -> Self {
        Self {
            arch: None,
            arch_name_cstr: None,
            error: CString::new(msg).ok(),
        }
    }
}

/// Load an r2il file and return a context handle.
///
/// Returns NULL on failure.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_load(path: *const c_char) -> *mut R2ILContext {
    if path.is_null() {
        return ptr::null_mut();
    }

    let path_str = unsafe {
        match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return ptr::null_mut(),
        }
    };

    match serialize::load(Path::new(path_str)) {
        Ok(arch) => Box::into_raw(Box::new(R2ILContext::with_arch(arch))),
        Err(e) => Box::into_raw(Box::new(R2ILContext::with_error(&e.to_string()))),
    }
}

/// Free a context handle.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_free(ctx: *mut R2ILContext) {
    if !ctx.is_null() {
        unsafe {
            drop(Box::from_raw(ctx));
        }
    }
}

/// Check if the context has a loaded architecture.
///
/// Returns 1 if loaded, 0 otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_is_loaded(ctx: *const R2ILContext) -> i32 {
    if ctx.is_null() {
        return 0;
    }

    unsafe {
        if (*ctx).arch.is_some() {
            1
        } else {
            0
        }
    }
}

/// Get the architecture name.
///
/// Returns NULL if not loaded.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_arch_name(ctx: *const R2ILContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }

    unsafe {
        match &(*ctx).arch_name_cstr {
            Some(s) => s.as_ptr(),
            None => ptr::null(),
        }
    }
}

/// Get the last error message.
///
/// Returns NULL if no error.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_error(ctx: *const R2ILContext) -> *const c_char {
    if ctx.is_null() {
        return ptr::null();
    }

    unsafe {
        match &(*ctx).error {
            Some(s) => s.as_ptr(),
            None => ptr::null(),
        }
    }
}

/// Get the address size in bytes.
///
/// Returns 0 if not loaded.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_addr_size(ctx: *const R2ILContext) -> u32 {
    if ctx.is_null() {
        return 0;
    }

    unsafe {
        match &(*ctx).arch {
            Some(arch) => arch.addr_size,
            None => 0,
        }
    }
}

/// Check if the architecture is big-endian.
///
/// Returns 1 for big-endian, 0 for little-endian or if not loaded.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_is_big_endian(ctx: *const R2ILContext) -> i32 {
    if ctx.is_null() {
        return 0;
    }

    unsafe {
        match &(*ctx).arch {
            Some(arch) => {
                if arch.big_endian {
                    1
                } else {
                    0
                }
            }
            None => 0,
        }
    }
}

/// Get the number of registers.
///
/// Returns 0 if not loaded.
#[unsafe(no_mangle)]
pub extern "C" fn r2il_register_count(ctx: *const R2ILContext) -> usize {
    if ctx.is_null() {
        return 0;
    }

    unsafe {
        match &(*ctx).arch {
            Some(arch) => arch.registers.len(),
            None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use r2sleigh_lift::create_x86_64_spec;
    use std::ffi::CString;

    #[test]
    fn test_context_lifecycle() {
        // Create a test r2il file
        let spec = create_x86_64_spec();
        let temp_path = "/tmp/test_r2il_plugin.r2il";
        serialize::save(&spec, Path::new(temp_path)).unwrap();

        // Load via C API
        let path_cstr = CString::new(temp_path).unwrap();
        let ctx = r2il_load(path_cstr.as_ptr());
        assert!(!ctx.is_null());

        // Check it's loaded
        assert_eq!(r2il_is_loaded(ctx), 1);

        // Check arch name
        let name_ptr = r2il_arch_name(ctx);
        assert!(!name_ptr.is_null());
        let name = unsafe { CStr::from_ptr(name_ptr) };
        assert_eq!(name.to_str().unwrap(), "x86-64");

        // Check properties
        assert_eq!(r2il_addr_size(ctx), 8);
        assert_eq!(r2il_is_big_endian(ctx), 0);
        assert!(r2il_register_count(ctx) > 0);

        // Free
        r2il_free(ctx);

        // Cleanup
        std::fs::remove_file(temp_path).ok();
    }

    #[test]
    fn test_null_handling() {
        assert!(r2il_load(ptr::null()).is_null());
        assert_eq!(r2il_is_loaded(ptr::null()), 0);
        assert!(r2il_arch_name(ptr::null()).is_null());

        // Should not crash
        r2il_free(ptr::null_mut());
    }
}
