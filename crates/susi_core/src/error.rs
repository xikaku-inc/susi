use thiserror::Error;

#[derive(Debug, Error)]
pub enum LicenseError {
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),

    #[error("PKCS8 error: {0}")]
    Pkcs8Spki(#[from] rsa::pkcs8::spki::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("License expired at {0}")]
    Expired(String),

    #[error("Machine not authorized: {0}")]
    InvalidMachine(String),

    #[error("Feature not available: {0}")]
    FeatureNotAvailable(String),

    #[error("License revoked")]
    Revoked,

    #[error("Machine deactivated by administrator")]
    Deactivated,

    #[error("License not found")]
    NotFound,

    #[error("Machine limit reached (max {0})")]
    MachineLimitReached(u32),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("PEM error: {0}")]
    Pem(String),

    #[error("USB error: {0}")]
    UsbError(String),

    #[error("No USB token found")]
    UsbTokenNotFound,

    #[error("Token decryption failed: {0}")]
    TokenDecryptionFailed(String),

    #[error("Workspace graph version conflict (current={current})")]
    GraphConflict { current: u32 },

    #[error("{0}")]
    Other(String),
}
