use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // TOTP backup codes
    // -----------------------------------------------------------------------

    /// Replace the set of backup codes for a user. Atomic: wipes previous rows
    /// (used or not) before inserting the new hashes. The caller is expected
    /// to keep the raw codes only until they've been shown to the user.
    pub fn replace_backup_codes(
        &self,
        username: &str,
        hashes: &[String],
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        tx.execute(
            "DELETE FROM totp_backup_codes WHERE username = ?1",
            params![username],
        )
        .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        for h in hashes {
            tx.execute(
                "INSERT INTO totp_backup_codes (username, code_hash, created_at) VALUES (?1, ?2, ?3)",
                params![username, h, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert backup: {}", e)))?;
        }
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB commit: {}", e)))?;
        Ok(())
    }

    pub fn clear_backup_codes(&self, username: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "DELETE FROM totp_backup_codes WHERE username = ?1",
                params![username],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(())
    }

    pub fn list_unused_backup_codes(
        &self,
        username: &str,
    ) -> Result<Vec<(i64, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, code_hash FROM totp_backup_codes WHERE username = ?1 AND used_at IS NULL",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![username], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn count_unused_backup_codes(&self, username: &str) -> Result<usize, LicenseError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM totp_backup_codes WHERE username = ?1 AND used_at IS NULL",
                params![username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(n as usize)
    }

    /// Mark a backup-code row used. Returns true iff a previously-unused row
    /// was flipped - false for already-used or unknown IDs (guards against race).
    pub fn consume_backup_code(&self, id: i64) -> Result<bool, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "UPDATE totp_backup_codes SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL",
                params![now, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update: {}", e)))?;
        Ok(n > 0)
    }

}
