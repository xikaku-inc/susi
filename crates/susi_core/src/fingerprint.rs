use sha2::{Digest, Sha256};

use crate::error::LicenseError;

/// Compute a machine fingerprint from hardware identifiers.
/// Returns a hex-encoded SHA256 hash of platform-specific hardware IDs.
///
/// Fails if either hardware identifier comes back empty. A partial read would
/// silently produce a *different* fingerprint from the normal one, which caused
/// ghost machine slots to pile up on the license server.
pub fn get_machine_code() -> Result<String, LicenseError> {
    let (a, b) = get_hardware_ids()?;
    machine_code_from_ids(&a, &b)
}

/// Pure core of [`get_machine_code`] — separated so it can be unit-tested
/// without access to the real hardware ID sources.
pub(crate) fn machine_code_from_ids(a: &str, b: &str) -> Result<String, LicenseError> {
    let na = normalize(a);
    let nb = normalize(b);
    if na.is_empty() || nb.is_empty() {
        return Err(LicenseError::Other(format!(
            "Hardware fingerprint incomplete (id1={} id2={}); refusing to generate an unstable machine code",
            if na.is_empty() { "empty" } else { "ok" },
            if nb.is_empty() { "empty" } else { "ok" },
        )));
    }
    let combined = format!("{}|{}", na, nb);
    let hash = Sha256::digest(combined.as_bytes());
    Ok(hex::encode(hash))
}

/// Get the machine code, preferring a previously-cached value at `cache_path`.
///
/// Behavior:
/// - If the cache file contains a valid 64-char lowercase hex code, return it.
/// - Otherwise compute a fresh code via [`get_machine_code`]. On success, write
///   it to the cache so later calls are immune to intermittent hardware ID
///   lookup failures (flaky WMI, temporary /proc reads, etc).
pub fn get_or_cache_machine_code(cache_path: &std::path::Path) -> Result<String, LicenseError> {
    if let Ok(contents) = std::fs::read_to_string(cache_path) {
        let code = contents.trim();
        if is_valid_machine_code(code) {
            return Ok(code.to_string());
        }
    }

    let code = get_machine_code()?;
    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(cache_path, &code);
    Ok(code)
}

fn is_valid_machine_code(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

fn normalize(s: &str) -> String {
    s.chars().filter(|&c| c != '-').map(|c| c.to_ascii_lowercase()).collect()
}

// ---- Platform-specific implementations ----

/// Windows: BIOS UUID + CPU ProcessorId (via WMI ROOT\CIMV2)
#[cfg(target_os = "windows")]
fn get_hardware_ids() -> Result<(String, String), LicenseError> {
    use std::collections::HashMap;
    use wmi::{Variant, WMIConnection};

    let wmi_con = WMIConnection::new()
        .map_err(|e| LicenseError::Other(format!("WMI: {}", e)))?;

    let query_first = |query: &str, prop: &str| -> String {
        wmi_con
            .raw_query(query)
            .ok()
            .and_then(|mut rows: Vec<HashMap<String, Variant>>| {
                rows.first_mut()?.remove(prop)
            })
            .and_then(|v| if let Variant::String(s) = v { Some(s) } else { None })
            .unwrap_or_default()
    };

    let bios_uuid = query_first("SELECT UUID FROM Win32_ComputerSystemProduct", "UUID");
    let processor_id = query_first("SELECT ProcessorId FROM Win32_Processor", "ProcessorId");
    Ok((bios_uuid, processor_id))
}

/// Linux: /etc/machine-id + root disk serial
#[cfg(target_os = "linux")]
fn get_hardware_ids() -> Result<(String, String), LicenseError> {
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let disk_serial = root_disk_serial();
    Ok((machine_id, disk_serial))
}

#[cfg(target_os = "linux")]
fn root_disk_serial() -> String {
    // Find the device mounted at "/"
    let root_dev = std::fs::read_to_string("/proc/mounts").ok().and_then(|s| {
        s.lines()
            .find(|l| l.split_whitespace().nth(1) == Some("/"))
            .and_then(|l| l.split_whitespace().next())
            .filter(|d| d.starts_with("/dev/"))
            .map(|d| d[5..].to_string()) // strip "/dev/"
    });

    let dev = match root_dev {
        Some(d) => d,
        None => return String::new(),
    };

    // Determine base disk name (strip partition suffix)
    // NVMe/eMMC: "nvme0n1p1" → "nvme0n1", "mmcblk0p1" → "mmcblk0"
    // SATA/SCSI: "sda1" → "sda"
    let disk = if let Some(p) = dev.rfind('p') {
        let suffix = &dev[p + 1..];
        if p > 0 && !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
            dev[..p].to_string()
        } else {
            dev.trim_end_matches(|c: char| c.is_ascii_digit()).to_string()
        }
    } else {
        dev.trim_end_matches(|c: char| c.is_ascii_digit()).to_string()
    };

    for path in &[
        format!("/sys/block/{}/device/serial", disk),
        format!("/sys/block/{}/serial", disk),
    ] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }
    String::new()
}

/// macOS: IOPlatformUUID + IOPlatformSerialNumber (via ioreg)
#[cfg(target_os = "macos")]
fn get_hardware_ids() -> Result<(String, String), LicenseError> {
    let ioreg_value = |key: &str| -> String {
        std::process::Command::new("ioreg")
            .args(["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                s.lines()
                    .find(|l| l.contains(key))
                    .and_then(|l| l.split('"').nth(3))
                    .map(|s| s.to_string())
            })
            .unwrap_or_default()
    };

    Ok((ioreg_value("IOPlatformUUID"), ioreg_value("IOPlatformSerialNumber")))
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn get_hardware_ids() -> Result<(String, String), LicenseError> {
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
        assert_eq!(code.len(), 64);
        assert!(code.chars().all(|c| c.is_ascii_hexdigit()));

        let code2 = machine_code_from_string("test-machine-id");
        assert_eq!(code, code2);

        let code3 = machine_code_from_string("other-machine");
        assert_ne!(code, code3);
    }

    #[test]
    fn test_get_machine_code_is_stable() {
        let code = get_machine_code().expect("machine code should be readable");
        assert_eq!(code.len(), 64);
        assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
        let code2 = get_machine_code().unwrap();
        assert_eq!(code, code2);
    }

    #[test]
    fn test_is_valid_machine_code() {
        assert!(is_valid_machine_code(&"0".repeat(64)));
        assert!(is_valid_machine_code(&"abcdef0123456789".repeat(4)));
        assert!(!is_valid_machine_code("short"));
        assert!(!is_valid_machine_code(&"g".repeat(64)));
        assert!(!is_valid_machine_code(&"A".repeat(64)));
    }

    #[test]
    fn test_get_or_cache_reads_existing() {
        let dir = std::env::temp_dir().join("susi_fp_test_read");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mc");
        let good = "b".repeat(64);
        std::fs::write(&path, &good).unwrap();
        let got = get_or_cache_machine_code(&path).unwrap();
        assert_eq!(got, good);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_get_or_cache_rejects_corrupt_and_writes_fresh() {
        let dir = std::env::temp_dir().join("susi_fp_test_corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mc");
        std::fs::write(&path, "garbage").unwrap();
        let got = get_or_cache_machine_code(&path).unwrap();
        assert_eq!(got.len(), 64);
        // Cache should now hold the fresh value, not "garbage".
        let reread = std::fs::read_to_string(&path).unwrap();
        assert_eq!(reread.trim(), got);
        let _ = std::fs::remove_file(&path);
    }

    // --- Regression tests for ghost-slot bug ---
    //
    // Previously `query_first` on Windows could return an empty string on a
    // transient WMI hiccup and the code silently hashed ("","") or ("x","")
    // into a *different* but valid-looking 64-hex machine code. The server
    // treats each distinct machine code as a new activation slot, so the same
    // physical laptop accumulated multiple entries and eventually hit the
    // machine limit. These tests pin the invariants that prevent that drift.

    #[test]
    fn regression_partial_hardware_id_is_refused() {
        // Simulate WMI returning one value but failing the other. The pure
        // hashing core must refuse rather than produce a "different-but-stable"
        // fingerprint.
        assert!(machine_code_from_ids("", "").is_err());
        assert!(machine_code_from_ids("", "CPUID-ABC123").is_err());
        assert!(machine_code_from_ids("BIOS-UUID-0001", "").is_err());
        // Empty after normalization (only separator chars) must also fail.
        assert!(machine_code_from_ids("---", "CPUID-ABC123").is_err());
    }

    #[test]
    fn regression_full_hardware_id_is_deterministic_and_normalized() {
        // Same inputs → same output (a machine that restarts gets the same slot).
        let a = machine_code_from_ids("BIOS-UUID-0001", "CPUID-ABC123").unwrap();
        let b = machine_code_from_ids("BIOS-UUID-0001", "CPUID-ABC123").unwrap();
        assert_eq!(a, b);

        // Normalization: dashes and case must not change the fingerprint.
        // Otherwise a WMI driver update that changes formatting would spawn a
        // ghost slot.
        let c = machine_code_from_ids("biosuuid0001", "cpuidabc123").unwrap();
        assert_eq!(a, c);
        let d = machine_code_from_ids("BIOS--UUID--0001", "CPUID-ABC-123").unwrap();
        assert_eq!(a, d);

        // Different inputs → different hash (sanity).
        let e = machine_code_from_ids("BIOS-UUID-9999", "CPUID-ABC123").unwrap();
        assert_ne!(a, e);
    }

    #[test]
    fn regression_cache_shields_from_transient_failure() {
        // Once a good fingerprint has been computed and cached, a later call
        // must reuse it even if the underlying hardware read would now fail.
        // The cache file is the only input to `get_or_cache_machine_code` when
        // a valid code is present, so this test is independent of the real
        // `get_hardware_ids`.
        let dir = std::env::temp_dir().join("susi_fp_test_transient");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mc");
        let good = "a".repeat(64);
        std::fs::write(&path, &good).unwrap();

        for _ in 0..5 {
            let got = get_or_cache_machine_code(&path).unwrap();
            assert_eq!(got, good, "cached code must be reused across calls");
        }
        let _ = std::fs::remove_file(&path);
    }
}