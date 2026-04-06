pub mod crypto;
#[cfg(feature = "db")]
pub mod db;
pub mod error;
pub mod features;
pub mod fingerprint;
pub mod license;
pub mod token;
pub mod usb;

pub use crypto::{generate_keypair, sign_license, verify_license};
pub use error::LicenseError;
pub use fingerprint::get_machine_code;
pub use license::{
    License, LicensePayload, MachineActivation, SignedLicense,
    DEFAULT_LEASE_DURATION_HOURS, DEFAULT_LEASE_GRACE_HOURS,
};
pub use token::{decrypt_token, encrypt_token, read_token, write_token, token_file_path};
pub use usb::{enumerate_usb_devices, UsbDevice};
