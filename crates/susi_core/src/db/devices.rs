use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Known devices (trusted-device gate for login)
    // -----------------------------------------------------------------------

    pub fn is_device_known(&self, username: &str, fingerprint: &str) -> Result<bool, LicenseError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM known_devices WHERE username = ?1 AND fingerprint = ?2",
                params![username, fingerprint],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(count > 0)
    }

    /// Insert a new trusted-device row, or refresh last_seen + label if it already exists.
    pub fn register_device(
        &self,
        username: &str,
        fingerprint: &str,
        label: &str,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO known_devices (username, fingerprint, label, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?4)
                 ON CONFLICT(username, fingerprint) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    label = CASE WHEN excluded.label != '' THEN excluded.label ELSE known_devices.label END",
                params![username, fingerprint, label, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert: {}", e)))?;
        Ok(())
    }

    pub fn touch_device(&self, username: &str, fingerprint: &str) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE known_devices SET last_seen = ?1 WHERE username = ?2 AND fingerprint = ?3",
                params![now, username, fingerprint],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(())
    }

    pub fn list_devices(&self, username: &str) -> Result<Vec<DeviceInfo>, LicenseError> {
        let mut stmt = self.conn
            .prepare("SELECT fingerprint, label, first_seen, last_seen FROM known_devices WHERE username = ?1 ORDER BY last_seen DESC")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![username], |r| {
                Ok(DeviceInfo {
                    fingerprint: r.get(0)?,
                    label: r.get(1)?,
                    first_seen: r.get(2)?,
                    last_seen: r.get(3)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn revoke_device(&self, username: &str, fingerprint: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM known_devices WHERE username = ?1 AND fingerprint = ?2",
                params![username, fingerprint],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

}
