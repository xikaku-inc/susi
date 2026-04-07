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

/// On **Windows**, MACs are taken from `MSFT_NetAdapter` in `ROOT\\StandardCimv2` with
/// `Virtual = FALSE` and `Hidden = FALSE`, matching **`Get-NetAdapter -Physical`** (default,
/// non-hidden adapters): **wired and Wi‑Fi** NICs, not virtual, including when disabled.
#[cfg(target_os = "windows")]
fn get_mac_addresses() -> Result<Vec<String>, LicenseError> {
    use std::collections::HashMap;

    use wmi::{Variant, WMIConnection};

    /// Same population as `Get-NetAdapter -Physical` (excludes hidden unless `-IncludeHidden`).
    /// `PermanentAddress` is the CIM field behind PowerShell's `MacAddress`.
    const QUERY: &str =
        "SELECT PermanentAddress FROM MSFT_NetAdapter WHERE Virtual = FALSE AND Hidden = FALSE";

    fn mac_string_from_variant(v: &Variant) -> Option<String> {
        match v {
            Variant::String(s) if !s.is_empty() => Some(s.clone()),
            Variant::Null | Variant::Empty => None,
            _ => None,
        }
    }

    /// WMI uses hyphen-separated MACs (e.g. `AA-BB-CC-DD-EE-FF`); fingerprint uses 12 hex chars.
    fn normalize_wmi_mac(s: &str) -> Option<String> {
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() != 12 || hex.chars().all(|c| c == '0') {
            return None;
        }
        Some(hex.to_lowercase())
    }

    let wmi_con = WMIConnection::with_namespace_path(r"ROOT\StandardCimv2").map_err(|e| {
        LicenseError::Other(format!("WMI connection to ROOT\\StandardCimv2: {}", e))
    })?;

    let rows: Vec<HashMap<String, Variant>> = wmi_con.raw_query(QUERY).map_err(|e| {
        LicenseError::Other(format!(
            "WMI query MSFT_NetAdapter (match Get-NetAdapter -Physical): {}",
            e
        ))
    })?;

    let mut macs = Vec::new();
    for row in rows {
        let Some(v) = row.get("PermanentAddress") else {
            continue;
        };
        let Some(raw) = mac_string_from_variant(v) else {
            continue;
        };
        if let Some(n) = normalize_wmi_mac(&raw) {
            macs.push(n);
        }
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

/// On **Linux**, **physical** interfaces only (sysfs path not under `/virtual/`): **Ethernet**
/// (`ARPHRD_ETHER`) and **Wi‑Fi** (`ARPHRD_IEEE80211`), regardless of `OPERSTATE`.
#[cfg(target_os = "linux")]
fn get_mac_addresses() -> Result<Vec<String>, LicenseError> {
    use std::path::Path;

    /// linux/uapi/linux/if_arp.h
    const ARPHRD_ETHER: u32 = 1;
    const ARPHRD_IEEE80211: u32 = 801;

    fn is_physical_wired_or_wifi_iface(name: &str) -> bool {
        if name == "lo" {
            return false;
        }
        let base = format!("/sys/class/net/{name}");
        let type_path = format!("{base}/type");
        let arp_type: u32 = match std::fs::read_to_string(&type_path) {
            Ok(s) => s.trim().parse().unwrap_or(0),
            Err(_) => return false,
        };
        if arp_type != ARPHRD_ETHER && arp_type != ARPHRD_IEEE80211 {
            return false;
        }
        match std::fs::canonicalize(Path::new(&base)) {
            Ok(p) => !p.to_string_lossy().contains("/virtual/"),
            Err(_) => false,
        }
    }

    let mut macs = Vec::new();

    let entries = std::fs::read_dir("/sys/class/net")
        .map_err(|e| LicenseError::Other(format!("Failed to read /sys/class/net: {}", e)))?;

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !is_physical_wired_or_wifi_iface(&name) {
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

/// On **macOS**, link-layer addresses where **`SIOCGIFMEDIA`** reports **`IFM_ETHER`** or
/// **`IFM_IEEE80211`** (wired or Wi‑Fi), excluding other virtual-style types when ioctl succeeds.
#[cfg(target_os = "macos")]
fn get_mac_addresses() -> Result<Vec<String>, LicenseError> {
    use std::ffi::CStr;
    use std::io;
    use std::mem;
    use std::ptr;

    // AF_LINK on macOS
    const AF_LINK: i32 = 18;

    // net/if_media.h — IFM_TYPE(x) ((x) & IFM_NMASK)
    const IFM_NMASK: i32 = 0x0000_00e0;
    const IFM_ETHER: i32 = 0x0000_0020;
    const IFM_IEEE80211: i32 = 0x0000_0080;

    // bsd/sys/sockio.h: _IOWR('i', 56, struct ifmediareq) on 64-bit Darwin
    const SIOCGIFMEDIA: libc::c_ulong = 0xc028_6938;

    #[repr(C)]
    struct Ifmediareq {
        ifm_name: [u8; libc::IFNAMSIZ],
        ifm_current: i32,
        ifm_active: i32,
        ifm_count: i32,
        ifm_ulist: *mut i32,
    }

    fn ifm_type(media_word: i32) -> i32 {
        media_word & IFM_NMASK
    }

    /// Wired Ethernet or Wi‑Fi; both use `IFT_ETHER` in `sockaddr_dl` but differ in media type.
    fn is_physical_wired_or_wifi_media(ifname: &str) -> bool {
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return false;
        }
        let mut req: Ifmediareq = unsafe { mem::zeroed() };
        let bytes = ifname.as_bytes();
        let copy_len = bytes.len().min(req.ifm_name.len() - 1);
        req.ifm_name[..copy_len].copy_from_slice(&bytes[..copy_len]);
        let r = unsafe {
            libc::ioctl(
                sock,
                SIOCGIFMEDIA as libc::c_ulong,
                &mut req as *mut Ifmediareq as *mut libc::c_void,
            )
        };
        let _ = unsafe { libc::close(sock) };
        if r < 0 {
            return false;
        }
        let t = ifm_type(req.ifm_active);
        t == IFM_ETHER || t == IFM_IEEE80211
    }

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
                    let ifname = unsafe { CStr::from_ptr(ifa.ifa_name) }
                        .to_string_lossy()
                        .into_owned();
                    if !is_physical_wired_or_wifi_media(&ifname) {
                        cur = ifa.ifa_next;
                        continue;
                    }
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
