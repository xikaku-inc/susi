use sha2::{Digest, Sha256};

use crate::error::LicenseError;

/// Compute a machine fingerprint from hardware identifiers.
/// Returns a hex-encoded SHA256 hash of sorted MAC addresses + hostname.
pub fn get_machine_code() -> Result<String, LicenseError> {
    let macs = get_mac_addresses()?;
    let hostname = get_hostname()?;

    let mut components: Vec<String> = macs;
    components.sort();
    components.push(hostname);

    let combined = components.join("|");
    let hash = Sha256::digest(combined.as_bytes());
    Ok(hex::encode(hash))
}

// ---- Platform-specific implementations ----

#[cfg(target_os = "windows")]
fn get_mac_addresses() -> Result<Vec<String>, LicenseError> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let mut buf_len: u32 = 15000;
    let mut buffer: Vec<u8>;

    loop {
        buffer = vec![0u8; buf_len as usize];
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buf_len,
            )
        };
        if ret == 0 {
            break;
        }
        if ret == 111 {
            // ERROR_BUFFER_OVERFLOW, try again with larger buffer
            continue;
        }
        return Err(LicenseError::Other(format!(
            "GetAdaptersAddresses failed with error {}",
            ret
        )));
    }

    let mut macs = Vec::new();
    let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

    while !adapter.is_null() {
        let a = unsafe { &*adapter };
        let phys_len = a.PhysicalAddressLength as usize;
        if phys_len == 6 {
            let mac = &a.PhysicalAddress[..phys_len];
            // Skip all-zero MACs
            if mac.iter().any(|&b| b != 0) {
                macs.push(hex::encode(mac));
            }
        }
        adapter = a.Next;
    }

    macs.sort();
    macs.dedup();
    Ok(macs)
}

#[cfg(target_os = "windows")]
fn get_hostname() -> Result<String, LicenseError> {
    use windows::core::PWSTR;
    use windows::Win32::System::SystemInformation::{
        ComputerNamePhysicalDnsHostname, GetComputerNameExW,
    };

    let mut size: u32 = 0;
    // First call to get required buffer size
    unsafe {
        let _ = GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            PWSTR(std::ptr::null_mut()),
            &mut size,
        );
    }

    let mut buffer = vec![0u16; size as usize];
    unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
        .map_err(|e| LicenseError::Other(format!("GetComputerNameExW failed: {}", e)))?;
    }

    Ok(String::from_utf16_lossy(&buffer[..size as usize]))
}

#[cfg(target_os = "linux")]
fn get_mac_addresses() -> Result<Vec<String>, LicenseError> {
    let mut macs = Vec::new();

    let entries = std::fs::read_dir("/sys/class/net")
        .map_err(|e| LicenseError::Other(format!("Failed to read /sys/class/net: {}", e)))?;

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // Skip loopback
        if name == "lo" {
            continue;
        }
        let addr_path = entry.path().join("address");
        if let Ok(mac) = std::fs::read_to_string(&addr_path) {
            let mac = mac.trim().to_lowercase();
            // Skip all-zero MACs
            if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                // Normalize: remove colons
                let normalized: String = mac.chars().filter(|c| *c != ':').collect();
                macs.push(normalized);
            }
        }
    }

    macs.sort();
    macs.dedup();
    Ok(macs)
}

#[cfg(target_os = "linux")]
fn get_hostname() -> Result<String, LicenseError> {
    std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .or_else(|_| {
            // Fallback: use gethostname
            let mut buf = [0u8; 256];
            let result = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut i8, buf.len()) };
            if result != 0 {
                return Err(LicenseError::Other("gethostname failed".to_string()));
            }
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Ok(String::from_utf8_lossy(&buf[..len]).to_string())
        })
}

#[cfg(target_os = "macos")]
fn get_mac_addresses() -> Result<Vec<String>, LicenseError> {
    use std::ptr;

    // AF_LINK on macOS
    const AF_LINK: i32 = 18;

    // Minimal sockaddr_dl layout for reading MAC addresses
    #[repr(C)]
    struct SockaddrDl {
        sdl_len: u8,
        sdl_family: u8,
        _sdl_index: u16,
        sdl_type: u8,
        sdl_nlen: u8,
        sdl_alen: u8,
        _sdl_slen: u8,
        sdl_data: [u8; 46],
    }

    // IFT_ETHER
    const IFT_ETHER: u8 = 6;

    let mut ifap: *mut libc::ifaddrs = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(LicenseError::Other("getifaddrs failed".to_string()));
    }

    let mut macs = Vec::new();
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            let sa = unsafe { &*ifa.ifa_addr };
            if sa.sa_family as i32 == AF_LINK {
                let sdl = unsafe { &*(ifa.ifa_addr as *const SockaddrDl) };
                if sdl.sdl_type == IFT_ETHER && sdl.sdl_alen == 6 {
                    let offset = sdl.sdl_nlen as usize;
                    let mac = &sdl.sdl_data[offset..offset + 6];
                    if mac.iter().any(|&b| b != 0) {
                        macs.push(hex::encode(mac));
                    }
                }
            }
        }
        cur = ifa.ifa_next;
    }

    unsafe { libc::freeifaddrs(ifap) };
    macs.sort();
    macs.dedup();
    Ok(macs)
}

#[cfg(target_os = "macos")]
fn get_hostname() -> Result<String, LicenseError> {
    let mut buf = [0u8; 256];
    let result = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut i8, buf.len()) };
    if result != 0 {
        return Err(LicenseError::Other("gethostname failed".to_string()));
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..len]).to_string())
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn get_mac_addresses() -> Result<Vec<String>, LicenseError> {
    Err(LicenseError::Other(
        "Platform not supported for hardware fingerprinting".to_string(),
    ))
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn get_hostname() -> Result<String, LicenseError> {
    Err(LicenseError::Other(
        "Platform not supported for hardware fingerprinting".to_string(),
    ))
}

/// Compute a machine code from a user-supplied string (for manual fingerprinting).
pub fn machine_code_from_string(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}

/// Helper module for hex encoding without adding an external dependency.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_code_from_string() {
        let code = machine_code_from_string("test-machine-id");
        // SHA256 produces 64 hex characters
        assert_eq!(code.len(), 64);
        assert!(code.chars().all(|c| c.is_ascii_hexdigit()));

        // Deterministic
        let code2 = machine_code_from_string("test-machine-id");
        assert_eq!(code, code2);

        // Different input → different output
        let code3 = machine_code_from_string("other-machine");
        assert_ne!(code, code3);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_get_machine_code_windows() {
        let code = get_machine_code().unwrap();
        assert_eq!(code.len(), 64);
        assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
        // Should be deterministic on same machine
        let code2 = get_machine_code().unwrap();
        assert_eq!(code, code2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_get_machine_code_linux() {
        let code = get_machine_code().unwrap();
        assert_eq!(code.len(), 64);
        assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
        let code2 = get_machine_code().unwrap();
        assert_eq!(code, code2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_get_machine_code_macos() {
        let code = get_machine_code().unwrap();
        assert_eq!(code.len(), 64);
        assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
        let code2 = get_machine_code().unwrap();
        assert_eq!(code, code2);
    }
}
