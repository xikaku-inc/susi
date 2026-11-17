use sha2::{Digest, Sha256};

use crate::error::LicenseError;

/// Compute a machine fingerprint from hardware identifiers.
/// Returns a hex-encoded SHA256 hash of platform-specific hardware IDs.
///
/// Fails if either hardware identifier comes back empty. A partial read would
/// silently produce a *different* fingerprint from the normal one, which caused
/// ghost machine slots to pile up on the license server.
pub fn get_machine_code() -> Result<String, LicenseError> {
    // Hardware identity cannot change mid-process; memoize the first
    // successful read so periodic license checks don't re-query WMI/proc,
    // and so a mid-run transient failure can't flip the code.
    static HW: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(code) = HW.get() {
        return Ok(code.clone());
    }
    let (a, b) = get_hardware_ids()?;
    let code = machine_code_from_ids(&a, &b)?;
    let _ = HW.set(code.clone());
    Ok(code)
}

/// Pure core of [`get_machine_code`] - separated so it can be unit-tested
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

/// Get the machine code, treating the live hardware fingerprint as
/// authoritative and `cache_path` only as a fallback for lookup failures
/// (flaky WMI, temporary /proc reads, containers without hardware identity).
///
/// The cache is never trusted over a successful hardware read - a
/// hand-edited cache file must not be able to spoof the machine code - and
/// is rewritten whenever it disagrees with the hardware value.
pub fn get_or_cache_machine_code(cache_path: &std::path::Path) -> Result<String, LicenseError> {
    resolve_machine_code(cache_path, get_machine_code)
}

/// Pure core of [`get_or_cache_machine_code`] with an injectable hardware
/// lookup so the priority rules are unit-testable.
fn resolve_machine_code(
    cache_path: &std::path::Path,
    fetch: impl FnOnce() -> Result<String, LicenseError>,
) -> Result<String, LicenseError> {
    match fetch() {
        Ok(code) => {
            let stale = std::fs::read_to_string(cache_path)
                .map(|c| c.trim() != code)
                .unwrap_or(true);
            if stale {
                if let Some(parent) = cache_path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(cache_path, &code);
            }
            Ok(code)
        }
        Err(e) => {
            if let Ok(contents) = std::fs::read_to_string(cache_path) {
                let code = contents.trim();
                if is_valid_machine_code(code) {
                    return Ok(code.to_string());
                }
            }
            Err(e)
        }
    }
}

fn is_valid_machine_code(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

fn normalize(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

// ---- Platform-specific implementations ----

/// Windows: BIOS UUID + CPU ProcessorId (via WMI ROOT\CIMV2)
#[cfg(target_os = "windows")]
fn get_hardware_ids() -> Result<(String, String), LicenseError> {
    use std::collections::HashMap;
    use wmi::{Variant, WMIConnection};

    let wmi_con = WMIConnection::new().map_err(|e| LicenseError::Other(format!("WMI: {}", e)))?;

    let query_first = |query: &str, prop: &str| -> String {
        wmi_con
            .raw_query(query)
            .ok()
            .and_then(|mut rows: Vec<HashMap<String, Variant>>| rows.first_mut()?.remove(prop))
            .and_then(|v| {
                if let Variant::String(s) = v {
                    Some(s)
                } else {
                    None
                }
            })
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

    let disk_serial = root_disk_serial(std::path::Path::new("/"));
    Ok((machine_id, disk_serial))
}

/// Stable ID of the disk holding the root filesystem. /proc, /sys and /dev are
/// read below `root`, so tests can use a fake tree.
#[cfg(target_os = "linux")]
fn root_disk_serial(root: &std::path::Path) -> String {
    let disk = match root_block_device(root) {
        Some(d) => d,
        None => return String::new(),
    };

    // /dev/disk/by-id/ contains stable udev-managed symlinks (works for direct
    // disks, NVMe, and LVM dm-uuid entries) without requiring root.
    if let Some(id) = disk_id_from_by_id(root, &disk) {
        return id;
    }

    // Sysfs serial attributes (SATA/SCSI direct path)
    for path in &[
        format!("sys/block/{}/device/serial", disk),
        format!("sys/block/{}/serial", disk),
    ] {
        if let Ok(s) = std::fs::read_to_string(root.join(path)) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }

    // NVMe: /sys/class/nvme/nvme0/serial (namespace "nvme0n1" → controller "nvme0")
    if let Some(i) = disk.strip_prefix("nvme").and_then(|rest| rest.find('n')) {
        let ctrl = &disk[..4 + i];
        if let Ok(s) = std::fs::read_to_string(root.join(format!("sys/class/nvme/{}/serial", ctrl))) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return s;
            }
        }
    }

    String::new()
}

/// Resolve the disk holding the root filesystem (e.g. "sda", "nvme0n1", "dm-0").
/// Device-mapper devices (LVM, LUKS) are followed down to the physical disk.
#[cfg(target_os = "linux")]
fn root_block_device(root: &std::path::Path) -> Option<String> {
    // The last mount on "/" is the visible one. Fields: id, parent id,
    // major:minor, root, mount point, ..., "-", fs type, source, options.
    let mountinfo = std::fs::read_to_string(root.join("proc/self/mountinfo")).ok()?;
    let line = mountinfo
        .lines()
        .filter(|l| l.split_whitespace().nth(4) == Some("/"))
        .last()?;

    // Resolve the device number first: the source can be a name without a
    // device node, such as "/dev/root" when the kernel mounts root without an
    // initramfs (e.g. on Azure VMs).
    let by_number = std::fs::canonicalize(root.join("sys/dev/block").join(line.split_whitespace().nth(2)?))
        .ok()
        .and_then(|p| Some(p.file_name()?.to_string_lossy().into_owned()));
    let mut dev = match by_number {
        Some(dev) => dev,
        // Filesystems such as btrfs report an anonymous device number.
        None => {
            let raw = line.split_once(" - ")?.1.split_whitespace().nth(1)?.strip_prefix("/dev/")?;
            match raw.strip_prefix("mapper/") {
                Some(name) => resolve_mapper_to_dm(root, name)?,
                None => raw.to_string(),
            }
        }
    };
    // Take the smallest slave name so a volume spanning several disks resolves
    // the same way on every run.
    while dev.starts_with("dm-") {
        let slave = std::fs::read_dir(root.join(format!("sys/block/{}/slaves", dev)))
            .ok()
            .and_then(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).min());
        match slave {
            Some(s) => dev = s,
            None => break,
        }
    }
    Some(whole_disk(root, &dev))
}

#[cfg(target_os = "linux")]
fn resolve_mapper_to_dm(root: &std::path::Path, mapper_name: &str) -> Option<String> {
    // /sys/block/dm-N/dm/name contains the mapper name
    if let Ok(rd) = std::fs::read_dir(root.join("sys/block")) {
        for entry in rd.flatten() {
            let bname = entry.file_name().to_string_lossy().to_string();
            if !bname.starts_with("dm-") {
                continue;
            }
            let name_path = root.join(format!("sys/block/{}/dm/name", bname));
            if let Ok(n) = std::fs::read_to_string(&name_path) {
                if n.trim() == mapper_name {
                    return Some(bname);
                }
            }
        }
    }
    None
}

/// The disk a partition belongs to, from sysfs ("sda1" → "sda", "nvme0n1p3" →
/// "nvme0n1"). Whole disks such as "nvme0n1" or "dm-0" are returned unchanged.
#[cfg(target_os = "linux")]
fn whole_disk(root: &std::path::Path, dev: &str) -> String {
    // /sys/class/block/<partition> links into the directory of its disk.
    let sys = root.join("sys/class/block").join(dev);
    if sys.join("partition").exists() {
        if let Some(disk) = std::fs::canonicalize(&sys)
            .ok()
            .as_deref()
            .and_then(std::path::Path::parent)
            .and_then(std::path::Path::file_name)
        {
            return disk.to_string_lossy().into_owned();
        }
    }
    dev.to_string()
}

/// Find a stable ID for `disk` in /dev/disk/by-id/.
/// Prefers entries that contain "serial", then world-wide IDs (wwn, NVMe
/// eui/uuid), then "dm-uuid", then any match. Ties are broken by name so the
/// result doesn't depend on directory order.
#[cfg(target_os = "linux")]
fn disk_id_from_by_id(root: &std::path::Path, disk: &str) -> Option<String> {
    // Model and serial links can carry a placeholder serial (Azure NVMe disks
    // all report "SN: 00000"), so prefer the IDs unique to the disk.
    let rank = |s: &str| -> u8 {
        if s.contains("serial") {
            0
        } else if s.starts_with("wwn-") || s.starts_with("nvme-eui.") || s.starts_with("nvme-uuid.") {
            1
        } else if s.starts_with("dm-uuid") {
            2
        } else {
            3
        }
    };
    std::fs::read_dir(root.join("dev/disk/by-id"))
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let link_name = entry.file_name().to_string_lossy().into_owned();
            let target = std::fs::read_link(entry.path()).ok()?;
            // Skip partition-specific entries (they include "-partN" suffix)
            (target.file_name()? == std::ffi::OsStr::new(disk) && !link_name.contains("-part"))
                .then_some(link_name)
        })
        .min_by_key(|s| (rank(s), s.clone()))
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

    Ok((
        ioreg_value("IOPlatformUUID"),
        ioreg_value("IOPlatformSerialNumber"),
    ))
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
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
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
        let code = get_machine_code().unwrap();
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
    fn test_resolve_falls_back_to_cache_when_hardware_fails() {
        let dir = std::env::temp_dir().join("susi_fp_test_read");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mc");
        let good = "b".repeat(64);
        std::fs::write(&path, &good).unwrap();
        let got =
            resolve_machine_code(&path, || Err(LicenseError::Other("hw unavailable".into())))
                .unwrap();
        assert_eq!(got, good);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_resolve_hardware_overrides_tampered_cache() {
        // A hand-edited cache must not spoof the machine code: a successful
        // hardware read wins and corrects the file (fusionhub #99).
        let dir = std::env::temp_dir().join("susi_fp_test_tamper");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mc");
        std::fs::write(&path, "a".repeat(64)).unwrap();
        let hw = "c".repeat(64);
        let got = resolve_machine_code(&path, || Ok(hw.clone())).unwrap();
        assert_eq!(got, hw);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), hw);
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
        // must reuse it even if the underlying hardware read now fails.
        let dir = std::env::temp_dir().join("susi_fp_test_transient");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mc");
        let good = "a".repeat(64);
        std::fs::write(&path, &good).unwrap();

        for _ in 0..5 {
            let got =
                resolve_machine_code(&path, || Err(LicenseError::Other("hw flake".into())))
                    .unwrap();
            assert_eq!(got, good, "cached code must be reused across calls");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// Fake filesystem root with the parts of /proc, /sys and /dev that the
    /// Linux disk lookup reads.
    #[cfg(target_os = "linux")]
    struct FakeRoot(std::path::PathBuf);

    #[cfg(target_os = "linux")]
    impl FakeRoot {
        /// Root filesystem mounted from device `number` ("major:minor") with the given source.
        fn new(name: &str, number: &str, source: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("susi_fp_{}_{}", name, std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let root = FakeRoot(dir);
            root.file(
                "proc/self/mountinfo",
                &format!(
                    "24 1 {} / / rw,relatime shared:1 - ext4 {} rw\n\
                     25 24 0:22 / /sys rw,nosuid shared:7 - sysfs sysfs rw\n",
                    number, source
                ),
            );
            root
        }

        fn file(&self, path: &str, contents: &str) -> &Self {
            let p = self.0.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, contents).unwrap();
            self
        }

        fn link(&self, path: &str, target: &str) -> &Self {
            let p = self.0.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, p).unwrap();
            self
        }

        /// Register a block device with device number `number` in /sys/class/block and
        /// /sys/dev/block, as a partition of `disk` if given.
        fn block(&self, name: &str, number: &str, disk: Option<&str>) -> &Self {
            let dev = match disk {
                Some(d) => format!("sys/devices/{}/{}", d, name),
                None => format!("sys/devices/{}", name),
            };
            std::fs::create_dir_all(self.0.join(&dev)).unwrap();
            if disk.is_some() {
                self.file(&format!("{}/partition", dev), "1\n");
            }
            self.link(&format!("sys/class/block/{}", name), &format!("../../../{}", dev))
                .link(&format!("sys/dev/block/{}", number), &format!("../../../{}", dev))
        }

        fn by_id(&self, name: &str, dev: &str) -> &Self {
            self.link(&format!("dev/disk/by-id/{}", name), &format!("../../{}", dev))
        }

        fn disk_id(&self) -> String {
            root_disk_serial(&self.0)
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for FakeRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_id_prefers_wwn_link_of_partitioned_sata_disk() {
        let root = FakeRoot::new("sata", "8:2", "/dev/sda2");
        root.block("sda", "8:0", None)
            .block("sda2", "8:2", Some("sda"))
            .by_id("ata-Samsung_SSD_860_S3Z9NB0K123", "sda")
            .by_id("ata-Samsung_SSD_860_S3Z9NB0K123-part2", "sda2")
            .by_id("wwn-0x5002538e40a1b2c3", "sda")
            .by_id("wwn-0x5002538e40a1b2c3-part2", "sda2");
        assert_eq!(root.disk_id(), "wwn-0x5002538e40a1b2c3");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_id_resolves_dev_root_and_skips_placeholder_serials() {
        // Layout of an Azure VM: root is mounted as "/dev/root" without a device node,
        // and every disk reports the serial "SN: 00000".
        let root = FakeRoot::new("azure", "259:1", "/dev/root");
        root.block("nvme0n1", "259:0", None)
            .block("nvme0n1p1", "259:1", Some("nvme0n1"))
            .by_id("nvme-MSFT_NVMe_Accelerator_v1.0_SN:_00000", "nvme0n1")
            .by_id("nvme-MSFT_NVMe_Accelerator_v1.0_SN:_00000-part1", "nvme0n1p1")
            .by_id("nvme-MSFT_NVMe_Accelerator_v1.0_SN:_00000_1", "nvme0n1")
            .by_id("nvme-eui.0b7bb4bc50584c62a0ca333f6cbcec01", "nvme0n1")
            .by_id("nvme-eui.0b7bb4bc50584c62a0ca333f6cbcec01-part1", "nvme0n1p1")
            .file("sys/block/nvme0n1/device/serial", "SN: 00000\n");
        assert_eq!(root.disk_id(), "nvme-eui.0b7bb4bc50584c62a0ca333f6cbcec01");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_id_follows_a_snapshot_root_to_its_disk() {
        // Layout of an AWS VM: root is a device-mapper snapshot of the EBS volume.
        let root = FakeRoot::new("aws", "252:0", "/dev/mapper/cow-root");
        root.file("sys/block/dm-0/dm/name", "cow-root\n")
            .file("sys/block/dm-0/slaves/nvme0n1p1", "")
            .block("dm-0", "252:0", None)
            .block("nvme0n1", "259:0", None)
            .block("nvme0n1p1", "259:1", Some("nvme0n1"))
            .by_id("dm-name-cow-root", "dm-0")
            .by_id("nvme-Amazon_Elastic_Block_Store_vol059e04ef34c1f365f", "nvme0n1")
            .by_id("nvme-Amazon_Elastic_Block_Store_vol059e04ef34c1f365f_1", "nvme0n1")
            .by_id("nvme-uuid.d6dd1855-3c3b-5af4-bc41-87880af0260f", "nvme0n1");
        assert_eq!(root.disk_id(), "nvme-uuid.d6dd1855-3c3b-5af4-bc41-87880af0260f");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_id_falls_back_to_the_mount_source_for_anonymous_devices() {
        // btrfs reports an anonymous device number, so the mapper name is resolved instead.
        let root = FakeRoot::new("btrfs", "0:31", "/dev/mapper/luks-root");
        root.file("sys/block/dm-0/dm/name", "luks-root\n")
            .file("sys/block/dm-0/slaves/nvme0n1p2", "")
            .block("dm-0", "253:0", None)
            .block("nvme0n1", "259:0", None)
            .block("nvme0n1p2", "259:2", Some("nvme0n1"))
            .by_id("dm-uuid-CRYPT-LUKS2-0a1b2c3d-luks-root", "dm-0")
            .by_id("nvme-Samsung_SSD_970_S467NX0M123", "nvme0n1");
        assert_eq!(root.disk_id(), "nvme-Samsung_SSD_970_S467NX0M123");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_id_matches_disk_names_ending_in_a_digit() {
        // Stripping digits used to turn "nvme0n1" into "nvme0n", so no link matched.
        let root = FakeRoot::new("nvme", "259:3", "/dev/nvme0n1p3");
        root.block("nvme0n1", "259:0", None)
            .block("nvme0n1p3", "259:3", Some("nvme0n1"))
            .by_id("nvme-Samsung_SSD_970_S467NX0M123", "nvme0n1")
            .by_id("nvme-Samsung_SSD_970_S467NX0M123-part3", "nvme0n1p3")
            .file("sys/block/nvme0n1/device/serial", "S467NX0M123\n");
        assert_eq!(root.disk_id(), "nvme-Samsung_SSD_970_S467NX0M123");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_id_follows_lvm_on_luks_to_the_physical_disk() {
        // Every dm-N used to strip to "dm-", so any dm link could be picked.
        let root = FakeRoot::new("luks", "253:1", "/dev/mapper/vgubuntu-root");
        root.file("sys/block/dm-0/dm/name", "nvme0n1p3_crypt\n")
            .file("sys/block/dm-0/slaves/nvme0n1p3", "")
            .file("sys/block/dm-1/dm/name", "vgubuntu-root\n")
            .file("sys/block/dm-1/slaves/dm-0", "")
            .file("sys/block/dm-2/dm/name", "vgubuntu-swap_1\n")
            .file("sys/block/dm-2/slaves/dm-0", "")
            .block("dm-0", "253:0", None)
            .block("dm-1", "253:1", None)
            .block("dm-2", "253:2", None)
            .block("nvme0n1", "259:0", None)
            .block("nvme0n1p3", "259:3", Some("nvme0n1"))
            .by_id("dm-uuid-CRYPT-LUKS2-0a1b2c3d-nvme0n1p3_crypt", "dm-0")
            .by_id("dm-uuid-LVM-root", "dm-1")
            .by_id("dm-uuid-LVM-swap", "dm-2")
            .by_id("nvme-Samsung_SSD_970_S467NX0M123", "nvme0n1");
        assert_eq!(root.disk_id(), "nvme-Samsung_SSD_970_S467NX0M123");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_id_uses_dm_uuid_of_a_dm_device_without_slaves() {
        let root = FakeRoot::new("dm", "253:0", "/dev/dm-0");
        root.file("sys/block/dm-0/dm/name", "root\n")
            .block("dm-0", "253:0", None)
            .by_id("dm-name-root", "dm-0")
            .by_id("dm-uuid-LVM-other", "dm-1")
            .by_id("dm-uuid-LVM-root", "dm-0");
        assert_eq!(root.disk_id(), "dm-uuid-LVM-root");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_id_falls_back_to_sysfs_serial() {
        let root = FakeRoot::new("sysfs", "8:1", "/dev/sda1");
        root.block("sda", "8:0", None)
            .block("sda1", "8:1", Some("sda"))
            .file("sys/block/sda/device/serial", "  WD-WCC4N1234567 \n");
        assert_eq!(root.disk_id(), "WD-WCC4N1234567");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_id_falls_back_to_nvme_controller_serial() {
        let root = FakeRoot::new("nvmectrl", "259:1", "/dev/nvme0n1p1");
        root.block("nvme0n1", "259:0", None)
            .block("nvme0n1p1", "259:1", Some("nvme0n1"))
            .file("sys/class/nvme/nvme0/serial", "S467NX0M123\n");
        assert_eq!(root.disk_id(), "S467NX0M123");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_disk_id_is_empty_without_any_id() {
        let root = FakeRoot::new("none", "8:1", "/dev/sda1");
        root.block("sda", "8:0", None).block("sda1", "8:1", Some("sda"));
        assert_eq!(root.disk_id(), "");
    }
}
