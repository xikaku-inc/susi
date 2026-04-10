use sha2::{Digest, Sha256};

use crate::error::LicenseError;

/// Compute a machine fingerprint from a stable OS-level identifier.
///
/// Sources per platform (all set at OS install time and survive reboots,
/// hardware swaps, VPN/Docker/Bluetooth adapter changes):
/// - Windows: `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
/// - Linux:   `/etc/machine-id` (fallback `/var/lib/dbus/machine-id`)
/// - macOS:   `IOPlatformUUID` from IOKit
///
/// Returns a hex-encoded SHA256 of the raw ID so the emitted machine code
/// is a fixed 64-character string and the underlying OS ID is not exposed.
pub fn get_machine_code() -> Result<String, LicenseError> {
    let raw = machine_uid::get()
        .map_err(|e| LicenseError::Other(format!("machine_uid error: {}", e)))?;
    let hash = Sha256::digest(raw.as_bytes());
    Ok(hex_encode(&hash))
}

/// Compute a machine code from a user-supplied string (for manual fingerprinting).
pub fn machine_code_from_string(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    hex_encode(&hash)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
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
