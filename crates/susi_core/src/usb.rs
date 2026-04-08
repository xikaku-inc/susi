use std::path::PathBuf;

use crate::error::LicenseError;

#[derive(Debug, Clone)]
pub struct UsbDevice {
    pub serial: String,
    pub mount_path: PathBuf,
    pub name: String,
}

pub fn enumerate_usb_devices() -> Result<Vec<UsbDevice>, LicenseError> {
    platform_enumerate()
}

// ---- Windows ----

#[cfg(target_os = "windows")]
fn platform_enumerate() -> Result<Vec<UsbDevice>, LicenseError> {
    use std::ffi::c_void;
    use std::mem::size_of;
    use windows::core::PCWSTR;
    use windows::Win32::Devices::DeviceAndDriverInstallation::{
        CM_Get_Device_IDW, CM_Get_Parent, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInterfaces,
        SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW, CR_SUCCESS, SP_DEVICE_INTERFACE_DATA,
        SP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVINFO_DATA, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT,
    };
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW,
        FILE_SHARE_READ, FILE_SHARE_WRITE, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
    };
    use windows::Win32::System::Ioctl::{
        GUID_DEVINTERFACE_DISK, IOCTL_STORAGE_GET_DEVICE_NUMBER, STORAGE_DEVICE_NUMBER,
        VOLUME_DISK_EXTENTS,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    const DRIVE_REMOVABLE: u32 = 2;

    /// USB instance serial from PnP (USBSTOR\...\SERIAL&0), aligned with Linux sysfs .../serial.
    unsafe fn usb_instance_serial_for_disk_number(disk_number: u32) -> Option<String> {
        let devs = SetupDiGetClassDevsW(
            Some(&GUID_DEVINTERFACE_DISK),
            PCWSTR::null(),
            None,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
        .ok()?;

        let mut if_data = SP_DEVICE_INTERFACE_DATA {
            cbSize: size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
            ..Default::default()
        };

        let mut idx = 0u32;
        let mut found_serial: Option<String> = None;

        while SetupDiEnumDeviceInterfaces(devs, None, &GUID_DEVINTERFACE_DISK, idx, &mut if_data).is_ok() {
            idx += 1;

            let mut required: u32 = 0;
            let _ = SetupDiGetDeviceInterfaceDetailW(devs, &mut if_data, None, 0, Some(&mut required), None);
            if required < size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32 {
                continue;
            }

            let mut detail_buf = vec![0u8; required as usize];
            let detail = detail_buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
            (*detail).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;

            let mut dev_info = SP_DEVINFO_DATA {
                cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };

            if SetupDiGetDeviceInterfaceDetailW(
                devs,
                &mut if_data,
                Some(detail),
                required,
                None,
                Some(&mut dev_info),
            )
            .is_err()
            {
                continue;
            }

            let path_ptr = (*detail).DevicePath.as_ptr();
            let path_len = (0..)
                .take_while(|&i| *path_ptr.add(i) != 0)
                .last()
                .map(|i| i + 1)
                .unwrap_or(0);
            if path_len == 0 {
                continue;
            }

            let h_disk = match CreateFileW(
                PCWSTR(path_ptr),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                Default::default(),
                HANDLE::default(),
            ) {
                Ok(h) => h,
                Err(_) => continue,
            };

            let mut sdn = STORAGE_DEVICE_NUMBER::default();
            let mut br = 0u32;
            let got = DeviceIoControl(
                h_disk,
                IOCTL_STORAGE_GET_DEVICE_NUMBER,
                None,
                0,
                Some(&mut sdn as *mut _ as *mut c_void),
                size_of::<STORAGE_DEVICE_NUMBER>() as u32,
                Some(&mut br),
                None,
            )
            .is_ok();
            let _ = CloseHandle(h_disk);

            if !got || sdn.DeviceNumber != disk_number {
                continue;
            }

            let mut dev_inst: u32 = dev_info.DevInst;
            for _ in 0..32 {
                if dev_inst == 0 {
                    break;
                }
                let mut inst_id = [0u16; 512];
                if CM_Get_Device_IDW(dev_inst, inst_id.as_mut_slice(), 0) != CR_SUCCESS {
                    break;
                }
                let id_end = inst_id.iter().position(|&c| c == 0).unwrap_or(inst_id.len());
                let id_wide = &inst_id[..id_end];
                let id = String::from_utf16_lossy(id_wide);
                if id.len() >= 8 && id[..8].eq_ignore_ascii_case("USBSTOR\\") {
                    if let Some(last_slash) = id.rfind('\\') {
                        let tail = &id[last_slash + 1..];
                        let ser = if let Some(amp) = tail.rfind('&') {
                            if amp > 0 {
                                &tail[..amp]
                            } else {
                                tail
                            }
                        } else {
                            tail
                        };
                        let ser = ser.trim_end_matches([' ', '\t']).to_string();
                        if !ser.is_empty() {
                            found_serial = Some(ser);
                        }
                    }
                    break;
                }
                let mut parent: u32 = 0;
                if CM_Get_Parent(&mut parent, dev_inst, 0) != CR_SUCCESS {
                    break;
                }
                dev_inst = parent;
            }
            break;
        }

        let _ = SetupDiDestroyDeviceInfoList(devs);
        found_serial
    }

    let mut drives_buf = [0u16; 512];
    let len = unsafe { GetLogicalDriveStringsW(Some(&mut drives_buf)) };
    if len == 0 {
        return Ok(Vec::new());
    }

    let mut devices = Vec::new();
    let mut offset = 0usize;

    while offset < len as usize {
        let end = drives_buf[offset..]
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(0);
        if end == 0 {
            break;
        }
        let drive_slice = &drives_buf[offset..offset + end + 1];
        offset += end + 1;

        let drive_type = unsafe { GetDriveTypeW(PCWSTR(drive_slice.as_ptr())) };
        if drive_type != DRIVE_REMOVABLE {
            continue;
        }

        let drive_letter = (drive_slice[0] as u8) as char;
        let device_path: Vec<u16> = format!("\\\\.\\{}:", drive_letter)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let h_vol = match unsafe {
            CreateFileW(
                PCWSTR(device_path.as_ptr()),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                Default::default(),
                HANDLE::default(),
            )
        } {
            Ok(h) => h,
            Err(_) => continue,
        };

        let mut ext_buf = [0u8; 512];
        let mut br = 0u32;
        let ext_ok = unsafe {
            DeviceIoControl(
                h_vol,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                None,
                0,
                Some(ext_buf.as_mut_ptr() as *mut c_void),
                ext_buf.len() as u32,
                Some(&mut br),
                None,
            )
            .is_ok()
        };
        let _ = unsafe { CloseHandle(h_vol) };

        if !ext_ok || br < size_of::<VOLUME_DISK_EXTENTS>() as u32 {
            continue;
        }

        let vde = unsafe { &*(ext_buf.as_ptr() as *const VOLUME_DISK_EXTENTS) };
        if vde.NumberOfDiskExtents < 1 {
            continue;
        }
        let disk_number = vde.Extents[0].DiskNumber;

        let Some(serial) = (unsafe { usb_instance_serial_for_disk_number(disk_number) }) else {
            continue;
        };

        let mut vol_name = [0u16; 261];
        let vol_ok = unsafe {
            GetVolumeInformationW(
                PCWSTR(drive_slice.as_ptr()),
                Some(&mut vol_name),
                None,
                None,
                None,
                None,
            )
        };

        let name = if vol_ok.is_ok() {
            let end = vol_name.iter().position(|&c| c == 0).unwrap_or(vol_name.len());
            let label = String::from_utf16_lossy(&vol_name[..end]);
            if label.is_empty() {
                "USB Drive".to_string()
            } else {
                label
            }
        } else {
            "USB Drive".to_string()
        };

        let mount_path = format!("{}:\\", drive_letter);

        devices.push(UsbDevice {
            serial,
            mount_path: PathBuf::from(mount_path),
            name,
        });
    }

    Ok(devices)
}

// ---- Linux ----

#[cfg(target_os = "linux")]
fn platform_enumerate() -> Result<Vec<UsbDevice>, LicenseError> {
    use std::collections::HashMap;

    // Parse /proc/mounts -> device -> mountpoint
    let mounts_content = std::fs::read_to_string("/proc/mounts")
        .map_err(|e| LicenseError::UsbError(format!("Failed to read /proc/mounts: {}", e)))?;

    let mut mounts: HashMap<String, String> = HashMap::new();
    for line in mounts_content.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(dev), Some(mount)) = (parts.next(), parts.next()) {
            mounts.insert(dev.to_string(), mount.to_string());
        }
    }

    let mut devices = Vec::new();

    let block_dir = match std::fs::read_dir("/sys/block") {
        Ok(d) => d,
        Err(_) => return Ok(devices),
    };

    for entry in block_dir.flatten() {
        let block_name = entry.file_name().to_string_lossy().to_string();
        if !block_name.starts_with("sd") {
            continue;
        }

        // Check removable
        let removable_path = format!("/sys/block/{}/removable", block_name);
        let removable = std::fs::read_to_string(&removable_path)
            .unwrap_or_default()
            .trim()
            .to_string();
        if removable != "1" {
            continue;
        }

        // Walk sysfs upward to find USB serial
        let device_link = format!("/sys/block/{}/device", block_name);
        let real_path = match std::fs::canonicalize(&device_link) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let mut serial = String::new();
        let mut current = real_path.as_path();
        for _ in 0..6 {
            let serial_file = current.join("serial");
            if let Ok(s) = std::fs::read_to_string(&serial_file) {
                let s = s.trim().to_string();
                if !s.is_empty() {
                    serial = s;
                    break;
                }
            }
            match current.parent() {
                Some(p) => current = p,
                None => break,
            }
        }

        if serial.is_empty() {
            continue;
        }

        // Find mount point for this device or its partitions
        let dev_path = format!("/dev/{}", block_name);
        let mut mount_path = None;

        // Try partitions first (e.g. /dev/sdb1)
        for i in 1..=9 {
            let part = format!("{}{}",dev_path, i);
            if let Some(mp) = mounts.get(&part) {
                mount_path = Some(mp.clone());
                break;
            }
        }

        // Try whole device
        if mount_path.is_none() {
            if let Some(mp) = mounts.get(&dev_path) {
                mount_path = Some(mp.clone());
            }
        }

        let mount_path = match mount_path {
            Some(mp) => mp,
            None => continue, // not mounted
        };

        // Try to get model name
        let model_path = format!("/sys/block/{}/device/model", block_name);
        let name = std::fs::read_to_string(&model_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "USB Drive".to_string());

        devices.push(UsbDevice {
            serial,
            mount_path: PathBuf::from(mount_path),
            name,
        });
    }

    Ok(devices)
}

// ---- macOS ----

#[cfg(target_os = "macos")]
fn platform_enumerate() -> Result<Vec<UsbDevice>, LicenseError> {
    use std::collections::HashMap;
    use std::ffi::{CStr, CString};
    use std::os::raw::{c_char, c_void};

    type CFTypeRef = *const c_void;
    type CFStringRef = CFTypeRef;
    type CFAllocatorRef = CFTypeRef;
    type CFMutableDictionaryRef = *mut c_void;
    type CFIndex = isize;
    type CFStringEncoding = u32;
    type IoObjectT = u32;
    type IoServiceT = IoObjectT;
    type IoIteratorT = IoObjectT;
    type KernReturn = i32;

    const K_CF_STRING_ENCODING_UTF8: CFStringEncoding = 0x0800_0100;
    const KERN_SUCCESS: KernReturn = 0;
    const IO_OBJECT_NULL: IoObjectT = 0;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFAllocatorDefault: CFAllocatorRef;
        static kCFBooleanTrue: CFTypeRef;
        fn CFStringGetCString(s: CFStringRef, buf: *mut c_char, size: CFIndex, enc: CFStringEncoding) -> bool;
        fn CFStringCreateWithCString(alloc: CFAllocatorRef, c_str: *const c_char, enc: CFStringEncoding) -> CFStringRef;
        fn CFRelease(cf: CFTypeRef);
        fn CFDictionarySetValue(dict: CFMutableDictionaryRef, key: CFTypeRef, value: CFTypeRef);
    }

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOServiceMatching(name: *const c_char) -> CFMutableDictionaryRef;
        fn IOServiceGetMatchingServices(port: u32, matching: CFMutableDictionaryRef, existing: *mut IoIteratorT) -> KernReturn;
        fn IOIteratorNext(iter: IoIteratorT) -> IoServiceT;
        fn IOObjectRelease(obj: IoObjectT) -> KernReturn;
        fn IOObjectRetain(obj: IoObjectT) -> KernReturn;
        fn IORegistryEntryCreateCFProperty(entry: IoServiceT, key: CFStringRef, alloc: CFAllocatorRef, options: u32) -> CFTypeRef;
        fn IORegistryEntryGetParentEntry(entry: IoServiceT, plane: *const c_char, parent: *mut IoServiceT) -> KernReturn;
    }

    unsafe fn cf_str(s: &str) -> CFStringRef {
        let cs = CString::new(s).unwrap();
        CFStringCreateWithCString(kCFAllocatorDefault, cs.as_ptr(), K_CF_STRING_ENCODING_UTF8)
    }

    unsafe fn cf_string_to_std(s: CFStringRef) -> Option<String> {
        if s.is_null() { return None; }
        let mut buf = [0i8; 512];
        if CFStringGetCString(s, buf.as_mut_ptr(), buf.len() as CFIndex, K_CF_STRING_ENCODING_UTF8) {
            CStr::from_ptr(buf.as_ptr()).to_str().ok().map(str::to_string)
        } else {
            None
        }
    }

    // Walk up the IOKit service plane to find "USB Serial Number" (iSerialNumber descriptor).
    // Matches the serial extracted from USBSTOR device ID on Windows.
    unsafe fn usb_serial_for_service(service: IoServiceT) -> Option<String> {
        let key = cf_str("USB Serial Number");
        let mut cur = service;
        IOObjectRetain(cur);
        let mut serial = None;
        for _ in 0..12 {
            if cur == IO_OBJECT_NULL { break; }
            let prop = IORegistryEntryCreateCFProperty(cur, key, kCFAllocatorDefault, 0);
            if !prop.is_null() {
                serial = cf_string_to_std(prop);
                CFRelease(prop);
                IOObjectRelease(cur);
                break;
            }
            let mut parent: IoServiceT = IO_OBJECT_NULL;
            let kr = IORegistryEntryGetParentEntry(cur, b"IOService\0".as_ptr() as *const c_char, &mut parent);
            IOObjectRelease(cur);
            if kr != KERN_SUCCESS { break; }
            cur = parent;
        }
        CFRelease(key);
        serial
    }

    // Build /dev/diskNsM -> mount point map via getfsstat
    let mut mount_map: HashMap<String, String> = HashMap::new();
    unsafe {
        let count = libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT);
        if count > 0 {
            let mut stats = vec![std::mem::zeroed::<libc::statfs>(); count as usize];
            let count2 = libc::getfsstat(
                stats.as_mut_ptr(),
                (count as usize * std::mem::size_of::<libc::statfs>()) as libc::c_int,
                libc::MNT_NOWAIT,
            );
            for stat in &stats[..count2.max(0) as usize] {
                let from = CStr::from_ptr(stat.f_mntfromname.as_ptr()).to_string_lossy().into_owned();
                let to = CStr::from_ptr(stat.f_mntonname.as_ptr()).to_string_lossy().into_owned();
                mount_map.insert(from, to);
            }
        }
    }

    let mut devices = Vec::new();

    unsafe {
        // IOServiceGetMatchingServices consumes one reference to `matching`, so no CFRelease after.
        let matching = IOServiceMatching(b"IOMedia\0".as_ptr() as *const c_char);
        if matching.is_null() { return Ok(devices); }

        let removable_key = cf_str("Removable");
        let whole_key = cf_str("Whole");
        CFDictionarySetValue(matching, removable_key, kCFBooleanTrue);
        CFDictionarySetValue(matching, whole_key, kCFBooleanTrue);
        CFRelease(removable_key);
        CFRelease(whole_key);

        let mut iter: IoIteratorT = IO_OBJECT_NULL;
        if IOServiceGetMatchingServices(0, matching, &mut iter) != KERN_SUCCESS {
            return Ok(devices);
        }

        let bsd_key = cf_str("BSD Name");

        loop {
            let media = IOIteratorNext(iter);
            if media == IO_OBJECT_NULL { break; }

            let bsd_prop = IORegistryEntryCreateCFProperty(media, bsd_key, kCFAllocatorDefault, 0);
            let bsd_name = cf_string_to_std(bsd_prop);
            if !bsd_prop.is_null() { CFRelease(bsd_prop); }

            let bsd_name = match bsd_name.filter(|n| !n.is_empty()) {
                Some(n) => n,
                None => { IOObjectRelease(media); continue; }
            };

            let serial = match usb_serial_for_service(media).filter(|s| !s.is_empty()) {
                Some(s) => s,
                None => { IOObjectRelease(media); continue; }
            };

            // Find mount point: try partitions diskNs1..s9, then whole disk
            let mut mount_point = None;
            for p in 1u32..=9 {
                let part = format!("/dev/{}s{}", bsd_name, p);
                if let Some(mp) = mount_map.get(&part) {
                    mount_point = Some(mp.clone());
                    break;
                }
            }
            if mount_point.is_none() {
                mount_point = mount_map.get(&format!("/dev/{}", bsd_name)).cloned();
            }

            let mount_path = match mount_point {
                Some(mp) => mp,
                None => { IOObjectRelease(media); continue; }
            };

            // Volume name = last path component (e.g. /Volumes/MY_DRIVE -> MY_DRIVE)
            let name = mount_path.rsplit('/').next().filter(|s| !s.is_empty())
                .unwrap_or("USB Drive").to_string();

            devices.push(UsbDevice {
                serial,
                mount_path: PathBuf::from(&mount_path),
                name,
            });
            IOObjectRelease(media);
        }

        CFRelease(bsd_key);
        IOObjectRelease(iter);
    }

    Ok(devices)
}

// ---- Unsupported platforms ----

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn platform_enumerate() -> Result<Vec<UsbDevice>, LicenseError> {
    Err(LicenseError::UsbError(
        "USB token enumeration not supported on this platform".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // requires physical USB device
    fn test_enumerate_usb() {
        let devices = enumerate_usb_devices().unwrap();
        println!("Found {} USB device(s):", devices.len());
        for dev in &devices {
            println!("  serial={}, mount={}, name={}", dev.serial, dev.mount_path.display(), dev.name);
        }
    }
}
