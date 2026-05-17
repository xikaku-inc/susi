//! S3 client wrapper for workspace recordings.
//!
//! Susi never streams object bytes — it only generates presigned URLs the
//! client uses directly against S3, and handles HEAD/DELETE for finalize and
//! cleanup. The `S3Storage` is built once at startup from env vars and lives
//! on `AppState` as `Option` (so missing config degrades cleanly to a
//! 503-ish error from the recording endpoints rather than panicking).

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use aws_sdk_s3::presigning::PresigningConfig;
use aws_sdk_s3::Client;

#[derive(Clone)]
pub struct S3Storage {
    client: Client,
    bucket: String,
    region: String,
}

impl S3Storage {
    /// Build from env. Returns Ok(None) if any required var is empty so the
    /// server can start without S3 (recording endpoints then 503).
    pub async fn from_env() -> Result<Option<Self>> {
        let bucket = std::env::var("SUSI_S3_BUCKET").unwrap_or_default();
        let region = std::env::var("SUSI_S3_REGION").unwrap_or_default();
        if bucket.is_empty() || region.is_empty() {
            return Ok(None);
        }
        // AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are picked up by the SDK
        // from the default provider chain. Setting AWS_REGION explicitly
        // overrides the chain for this client.
        let region_provider = aws_config::Region::new(region.clone());
        let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;
        let client = Client::new(&cfg);
        Ok(Some(Self { client, bucket, region }))
    }

    pub fn bucket(&self) -> &str { &self.bucket }
    pub fn region(&self) -> &str { &self.region }

    /// Presigned PUT URL the client uses to upload object bytes directly.
    /// `content_type` is bound into the signature: the client MUST send the
    /// same Content-Type header on its PUT or S3 rejects it.
    pub async fn presign_put(
        &self,
        key: &str,
        content_type: &str,
        expires_in: Duration,
    ) -> Result<String> {
        let presign = PresigningConfig::expires_in(expires_in)
            .context("PresigningConfig::expires_in")?;
        let req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .presigned(presign)
            .await
            .map_err(|e| anyhow!("S3 presign_put: {}", e))?;
        Ok(req.uri().to_string())
    }

    /// Presigned GET URL for downloading the object. If `download_name` is
    /// set, S3 returns a Content-Disposition that makes browsers save-as
    /// (with that filename) instead of rendering JSON Lines inline.
    pub async fn presign_get(
        &self,
        key: &str,
        download_name: Option<&str>,
        expires_in: Duration,
    ) -> Result<String> {
        let presign = PresigningConfig::expires_in(expires_in)
            .context("PresigningConfig::expires_in")?;
        let mut builder = self.client.get_object().bucket(&self.bucket).key(key);
        if let Some(name) = download_name {
            // Quoted filename = safe with spaces / unicode after sanitize.
            builder = builder.response_content_disposition(format!(
                "attachment; filename=\"{}\"",
                name.replace('"', "")
            ));
        }
        let req = builder
            .presigned(presign)
            .await
            .map_err(|e| anyhow!("S3 presign_get: {}", e))?;
        Ok(req.uri().to_string())
    }

    /// Returns the object's content length, or None if it doesn't exist.
    pub async fn head_size(&self, key: &str) -> Result<Option<u64>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(out) => Ok(Some(out.content_length().unwrap_or(0).max(0) as u64)),
            Err(e) => {
                // 404 → object missing (upload not done). Other errors propagate.
                let svc = e.into_service_error();
                if svc.is_not_found() {
                    Ok(None)
                } else {
                    Err(anyhow!("S3 head_object: {}", svc))
                }
            }
        }
    }

    pub async fn delete_object(&self, key: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| anyhow!("S3 delete_object: {}", e))?;
        Ok(())
    }
}
