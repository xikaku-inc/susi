use sha2::{Digest, Sha256};

use crate::error::LicenseError;

/// Compute a machine fingerprint from hardware identifiers.
/// Returns a hex-encoded SHA256 hash of platform-specific hardware IDs.
pub fn get_machine_code() -> Result<String, LicenseError> {
    let (a, b) = get_hardware_ids()?;
    let combined = format!("{}|{}", normalize(&a), normalize(&b));
    let hash = Sha256::digest(combined.as_bytes());
    Ok(hex::encode(hash))
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
}