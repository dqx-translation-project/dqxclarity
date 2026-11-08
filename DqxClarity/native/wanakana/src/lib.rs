// Minimal C-ABI wrapper around wana_kana::to_romaji.
//
// Exposed surface (one function):
//   int wanakana_to_romaji(const char *input_utf8, char *out_utf8, int out_capacity_bytes);
//     - input_utf8:  null-terminated utf-8 source japanese text (kana only)
//     - out_utf8:    caller-allocated buffer
//     - out_capacity_bytes: capacity of out_utf8 in bytes (including space for the null terminator)
//   returns: number of bytes written to out_utf8 (excluding null terminator) on success;
//            -1 on bad input or buffer too small.
//
// We never allocate on the rust side that the caller needs to free. The c# side
// passes a stackalloc'd or pooled buffer; rust just writes utf-8 + null.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use wana_kana::ConvertJapanese;

#[no_mangle]
pub extern "C" fn wanakana_to_romaji(
    input_utf8: *const c_char,
    out_utf8: *mut c_char,
    out_capacity_bytes: c_int,
) -> c_int {
    if input_utf8.is_null() || out_utf8.is_null() || out_capacity_bytes <= 0 {
        return -1;
    }

    // SAFETY: caller guarantees input_utf8 is a null-terminated utf-8 string.
    let input_cstr = unsafe { CStr::from_ptr(input_utf8) };
    let input_str = match input_cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let romaji = input_str.to_romaji();
    let bytes = romaji.as_bytes();

    // need room for the null terminator
    if bytes.len() + 1 > out_capacity_bytes as usize {
        return -1;
    }

    // SAFETY: caller guarantees out_utf8 has at least out_capacity_bytes valid bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_utf8 as *mut u8, bytes.len());
        *out_utf8.add(bytes.len()) = 0;
    }

    bytes.len() as c_int
}

// Convenience entry that's a no-op if the input is empty. Mirrors the python
// `transliterate_player_name` short-circuit so the c# wrapper doesn't need
// special-casing for the empty string.
#[no_mangle]
pub extern "C" fn wanakana_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

// keep CString in scope for the linker; not actually called.
#[allow(dead_code)]
fn _unused_keep_cstring_dep() {
    let _ = CString::new("");
}
