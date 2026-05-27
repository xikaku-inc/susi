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

    // ---------------------------------------------------------------------------
    // crypt32.dll FFI — certificate chain extraction from embedded Authenticode
    // ---------------------------------------------------------------------------
    type HCERTSTORE = *mut std::ffi::c_void;
    type HCRYPTMSG  = *mut std::ffi::c_void;
    #[allow(non_camel_case_types)]
    type PCCERT_CONTEXT = *const CERT_CONTEXT;

    #[repr(C)]
    struct CERT_CONTEXT {
        dw_cert_encoding_type: DWORD,
        pb_cert_encoded: *mut u8,
        cb_cert_encoded: DWORD,
        p_cert_info: *mut std::ffi::c_void,
        h_cert_store: HCERTSTORE,
    }

    const CERT_QUERY_OBJECT_FILE: DWORD = 1;
    const CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED: DWORD = 1 << 10;
    const CERT_QUERY_FORMAT_FLAG_ALL: DWORD = 0x0E;
    const CERT_CLOSE_STORE_FORCE_FLAG: DWORD = 1;

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptQueryObject(
            dw_object_type: DWORD,
            pv_object: *const std::ffi::c_void,
            dw_expected_content_type_flags: DWORD,
            dw_expected_format_type_flags: DWORD,
            dw_flags: DWORD,
            pdw_msg_and_cert_encoding_type: *mut DWORD,
            pdw_content_type: *mut DWORD,
            pdw_format_type: *mut DWORD,
            ph_cert_store: *mut HCERTSTORE,
            ph_msg: *mut HCRYPTMSG,
            ppv_context: *mut *const std::ffi::c_void,
        ) -> i32;
        fn CertEnumCertificatesInStore(
            h_cert_store: HCERTSTORE,
            pprev_cert_context: PCCERT_CONTEXT,
        ) -> PCCERT_CONTEXT;
        fn CertCloseStore(h_cert_store: HCERTSTORE, dw_flags: DWORD) -> i32;
        fn CryptMsgClose(h_crypt_msg: HCRYPTMSG) -> i32;
    }

    pub fn extract_chain() -> Vec<Vec<u8>> {
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return vec![],
        };
        let wide: Vec<u16> = exe.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

        unsafe {
            let mut cert_store: HCERTSTORE = std::ptr::null_mut();
            let mut hcrypt_msg: HCRYPTMSG = std::ptr::null_mut();
            let mut enc_type: DWORD = 0;
            let mut content_type: DWORD = 0;
            let mut format_type: DWORD = 0;
            let mut pv_context: *const std::ffi::c_void = std::ptr::null();

            let ok = CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                wide.as_ptr() as *const std::ffi::c_void,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_ALL,
                0,
                &mut enc_type,
                &mut content_type,
                &mut format_type,
                &mut cert_store,
                &mut hcrypt_msg,
                &mut pv_context,
            );

            if ok == 0 || cert_store.is_null() {
                if !hcrypt_msg.is_null() { CryptMsgClose(hcrypt_msg); }
                return vec![];
            }

            let mut certs: Vec<Vec<u8>> = Vec::new();
            let mut p_prev: PCCERT_CONTEXT = std::ptr::null();
            loop {
                let p_ctx = CertEnumCertificatesInStore(cert_store, p_prev);
                if p_ctx.is_null() { break; }
                let cb = (*p_ctx).cb_cert_encoded as usize;
                let pb = (*p_ctx).pb_cert_encoded;
                certs.push(std::slice::from_raw_parts(pb, cb).to_vec());
                p_prev = p_ctx;
                // CertEnumCertificatesInStore takes ownership of p_prev — do not
                // call CertFreeCertificateContext on intermediate pointers.
            }

            if !hcrypt_msg.is_null() { CryptMsgClose(hcrypt_msg); }
            CertCloseStore(cert_store, CERT_CLOSE_STORE_FORCE_FLAG);
            certs
        }
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

    // Additional types for certificate extraction
    #[repr(C)] struct __CFDictionary(u8);
    type CFDictionaryRef = *const __CFDictionary;
    #[repr(C)] struct __CFArray(u8);
    type CFArrayRef = *const __CFArray;
    #[repr(C)] struct __CFData(u8);
    type CFDataRef = *const __CFData;
    #[repr(C)] struct OpaqueSecCertificate(u8);
    type SecCertificateRef = *const OpaqueSecCertificate;

    // kSecCSSigningInformation = 0x00000002 — requests the certificate chain
    const K_SEC_CS_SIGNING_INFORMATION: u32 = 0x00000002;

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
        // kSecCodeInfoCertificates is a CFStringRef exported by Security.framework.
        // CFDictionary uses pointer identity for CF string keys, so it must be
        // the exact extern symbol — not a hardcoded string constant.
        static kSecCodeInfoCertificates: *const std::ffi::c_void;
        fn SecCodeCopySigningInformation(
            code: SecStaticCodeRef,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> OSStatus;
        fn CFDictionaryGetValue(
            the_dict: CFDictionaryRef,
            key: *const std::ffi::c_void,
        ) -> *const std::ffi::c_void;
        fn CFArrayGetCount(the_array: CFArrayRef) -> isize;
        fn CFArrayGetValueAtIndex(the_array: CFArrayRef, idx: isize) -> *const std::ffi::c_void;
        fn SecCertificateCopyData(certificate: SecCertificateRef) -> CFDataRef;
        fn CFDataGetBytePtr(the_data: CFDataRef) -> *const u8;
        fn CFDataGetLength(the_data: CFDataRef) -> isize;
    }

    #[link(name = "Security", kind = "framework")]
    extern "C" {}

    pub fn extract_chain() -> Vec<Vec<u8>> {
        let exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(_) => return vec![],
        };
        let path_bytes = match exe.to_str() {
            Some(s) => s.as_bytes(),
            None => return vec![],
        };

        unsafe {
            let url = CFURLCreateFromFileSystemRepresentation(
                std::ptr::null(),
                path_bytes.as_ptr(),
                path_bytes.len() as isize,
                0,
            );
            if url.is_null() { return vec![]; }

            let mut code: SecStaticCodeRef = std::ptr::null_mut();
            let status = SecStaticCodeCreateWithPath(url, KSE_CS_DEFAULT_FLAGS, &mut code);
            CFRelease(url as *const _);
            if status != ERR_SEC_SUCCESS || code.is_null() { return vec![]; }

            let mut info_dict: CFDictionaryRef = std::ptr::null();
            let status = SecCodeCopySigningInformation(
                code, K_SEC_CS_SIGNING_INFORMATION, &mut info_dict,
            );
            CFRelease(code as *const _);
            if status != ERR_SEC_SUCCESS || info_dict.is_null() { return vec![]; }

            let certs_val = CFDictionaryGetValue(info_dict, kSecCodeInfoCertificates);
            if certs_val.is_null() {
                CFRelease(info_dict as *const _);
                return vec![];
            }

            let certs_array = certs_val as CFArrayRef;
            let count = CFArrayGetCount(certs_array);
            let mut result: Vec<Vec<u8>> = Vec::with_capacity(count as usize);
            for i in 0..count {
                let cert_ref = CFArrayGetValueAtIndex(certs_array, i) as SecCertificateRef;
                if cert_ref.is_null() { continue; }
                let data_ref = SecCertificateCopyData(cert_ref);
                if data_ref.is_null() { continue; }
                let len = CFDataGetLength(data_ref) as usize;
                let ptr = CFDataGetBytePtr(data_ref);
                result.push(std::slice::from_raw_parts(ptr, len).to_vec());
                CFRelease(data_ref as *const _);
            }

            CFRelease(info_dict as *const _);
            result
        }
    }

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

/// Extract the DER-encoded certificate chain from the running binary's code
/// signature. Returns the chain leaf-first, or an empty `Vec` if the binary is
/// unsigned, on Linux, or if extraction fails for any reason.
///
/// The returned bytes are suitable for sending to the server for CA pinning
/// verification via [`crate::LicenseClient`].
pub fn extract_signing_cert_chain() -> Vec<Vec<u8>> {
    #[cfg(target_os = "windows")]
    return windows::extract_chain();
    #[cfg(target_os = "macos")]
    return macos::extract_chain();
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    return vec![];
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
