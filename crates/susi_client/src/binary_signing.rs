/// Returns `true` if the currently running binary has a valid code signature.
///
/// | Platform | Mechanism                                    |
/// |----------|----------------------------------------------|
/// | Windows  | `WinVerifyTrust` (Authenticode, SHA-256)     |
/// | macOS    | `SecStaticCodeCheckValidity`                 |
/// | Linux    | always `true` — no standard mechanism exists |
///
/// # Startup enforcement
///
/// Enable the `require-signed-binary` Cargo feature to automatically abort
/// the process at startup if this function returns `false`.  The check runs
/// via a global constructor (before `main`), so no call site in application
/// code is needed.
///
/// ```toml
/// # Cargo.toml of the application that embeds susi_client
/// [dependencies]
/// susi_client = { path = "…", features = ["require-signed-binary"] }
/// ```
pub fn is_binary_signed() -> bool {
    #[cfg(target_os = "windows")]
    return windows::check();
    #[cfg(target_os = "macos")]
    return macos::check();
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    return true;
}

#[cfg(target_os = "windows")]
mod windows {
    use std::os::windows::ffi::OsStrExt;

    // Raw FFI declarations for WinVerifyTrust — avoids windows-sys feature complexity.
    type HWND = *mut std::ffi::c_void;
    type HANDLE = *mut std::ffi::c_void;
    type LONG = i32;
    type DWORD = u32;

    #[repr(C)]
    struct GUID {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    // {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    const WINTRUST_ACTION_GENERIC_VERIFY_V2: GUID = GUID {
        data1: 0x00aac56b,
        data2: 0xcd44,
        data3: 0x11d0,
        data4: [0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee],
    };

    const WTD_UI_NONE: DWORD = 2;
    const WTD_REVOKE_NONE: DWORD = 0;
    const WTD_CHOICE_FILE: DWORD = 1;
    const WTD_STATEACTION_VERIFY: DWORD = 1;
    const WTD_STATEACTION_CLOSE: DWORD = 2;
    const WTD_SAFER_FLAG: DWORD = 0x100;
    const ERROR_SUCCESS: LONG = 0;

    #[repr(C)]
    struct WINTRUST_FILE_INFO {
        cb_struct: DWORD,
        pcwsz_file_path: *const u16,
        h_file: HANDLE,
        pg_known_subject: *mut GUID,
    }

    #[repr(C)]
    struct WINTRUST_DATA {
        cb_struct: DWORD,
        p_policy_callback_data: *mut std::ffi::c_void,
        p_sip_client_data: *mut std::ffi::c_void,
        dw_ui_choice: DWORD,
        fdw_revocation_checks: DWORD,
        dw_union_choice: DWORD,
        p_file: *mut WINTRUST_FILE_INFO, // union field, we only use pFile
        dw_state_action: DWORD,
        h_wvt_state_data: HANDLE,
        pwsz_url_reference: *mut u16,
        dw_prov_flags: DWORD,
        dw_ui_context: DWORD,
        p_signature_settings: *mut std::ffi::c_void,
    }

    #[link(name = "wintrust")]
    extern "system" {
        fn WinVerifyTrust(hwnd: HWND, pgActionID: *mut GUID, pWVTData: *mut WINTRUST_DATA) -> LONG;
    }

    pub fn check() -> bool {
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let wide: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let mut file_info = WINTRUST_FILE_INFO {
                cb_struct: std::mem::size_of::<WINTRUST_FILE_INFO>() as DWORD,
                pcwsz_file_path: wide.as_ptr(),
                h_file: std::ptr::null_mut(),
                pg_known_subject: std::ptr::null_mut(),
            };

            let mut data = WINTRUST_DATA {
                cb_struct: std::mem::size_of::<WINTRUST_DATA>() as DWORD,
                p_policy_callback_data: std::ptr::null_mut(),
                p_sip_client_data: std::ptr::null_mut(),
                dw_ui_choice: WTD_UI_NONE,
                fdw_revocation_checks: WTD_REVOKE_NONE,
                dw_union_choice: WTD_CHOICE_FILE,
                p_file: &mut file_info,
                dw_state_action: WTD_STATEACTION_VERIFY,
                h_wvt_state_data: std::ptr::null_mut(),
                pwsz_url_reference: std::ptr::null_mut(),
                dw_prov_flags: WTD_SAFER_FLAG,
                dw_ui_context: 0,
                p_signature_settings: std::ptr::null_mut(),
            };

            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let result = WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data);

            data.dw_state_action = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data);

            result == ERROR_SUCCESS
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    type OSStatus = i32;
    const ERR_SEC_SUCCESS: OSStatus = 0;
    const KSE_CS_DEFAULT_FLAGS: u32 = 0;

    #[repr(C)]
    struct OpaqueSecStaticCode(u8);
    type SecStaticCodeRef = *mut OpaqueSecStaticCode;

    #[repr(C)]
    struct OpaqueSecRequirement(u8);
    type SecRequirementRef = *mut OpaqueSecRequirement;

    #[repr(C)]
    struct __CFURL(u8);
    type CFURLRef = *const __CFURL;

    type CFURLPathStyle = i64;

    extern "C" {
        fn SecStaticCodeCreateWithPath(
            path: CFURLRef,
            flags: u32,
            static_code: *mut SecStaticCodeRef,
        ) -> OSStatus;
        fn SecStaticCodeCheckValidity(
            static_code: SecStaticCodeRef,
            flags: u32,
            requirement: SecRequirementRef,
        ) -> OSStatus;
        fn CFRelease(cf: *const std::ffi::c_void);
        fn CFURLCreateFromFileSystemRepresentation(
            allocator: *const std::ffi::c_void,
            buffer: *const u8,
            buf_len: isize,
            is_directory: u8,
        ) -> CFURLRef;
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {}

    pub fn check() -> bool {
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return false,
        };
        let path_bytes = match exe.to_str() {
            Some(s) => s.as_bytes(),
            None => return false,
        };

        unsafe {
            let url = CFURLCreateFromFileSystemRepresentation(
                std::ptr::null(),
                path_bytes.as_ptr(),
                path_bytes.len() as isize,
                0,
            );
            if url.is_null() {
                return false;
            }

            let mut code: SecStaticCodeRef = std::ptr::null_mut();
            let status = SecStaticCodeCreateWithPath(url, KSE_CS_DEFAULT_FLAGS, &mut code);
            CFRelease(url as *const std::ffi::c_void);

            if status != ERR_SEC_SUCCESS || code.is_null() {
                return false;
            }

            let valid = SecStaticCodeCheckValidity(code, KSE_CS_DEFAULT_FLAGS, std::ptr::null_mut());
            CFRelease(code as *const std::ffi::c_void);

            valid == ERR_SEC_SUCCESS
        }
    }
}

// ---------------------------------------------------------------------------
// Startup enforcement (feature = "require-signed-binary")
// ---------------------------------------------------------------------------

/// When the `require-signed-binary` feature is enabled this constructor runs
/// before `main()` and aborts the process if [`is_binary_signed`] returns
/// `false`.
///
/// The abort is intentionally unconditional and happens before any
/// application logic, including before license file loading, so an attacker
/// cannot reach the license-bypass code path at all.
#[cfg(feature = "require-signed-binary")]
#[ctor::ctor]
fn enforce_signed_binary_at_startup() {
    if !is_binary_signed() {
        // Write directly to stderr — log infrastructure is not yet initialised
        // at constructor time.
        eprintln!(
            "[susi] FATAL: Binary signature check failed at startup. \
             This binary has not been code-signed or has been tampered with."
        );
        std::process::abort();
    }
}
