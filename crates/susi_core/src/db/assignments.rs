use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // License <-> user assignment
    // -----------------------------------------------------------------------

    pub fn assign_license_user(&self, license_id: &str, username: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO license_users (license_id, username, added_at) VALUES (?1, ?2, ?3)",
                params![license_id, username, Utc::now().to_rfc3339()],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert: {}", e)))?;
        Ok(())
    }

    pub fn unassign_license_user(
        &self,
        license_id: &str,
        username: &str,
    ) -> Result<bool, LicenseError> {
        let rows = self
            .conn
            .execute(
                "DELETE FROM license_users WHERE license_id = ?1 AND username = ?2",
                params![license_id, username],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(rows > 0)
    }

    pub fn list_license_users(&self, license_id: &str) -> Result<Vec<String>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT username FROM license_users WHERE license_id = ?1 ORDER BY username")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let users = stmt
            .query_map(params![license_id], |r| r.get(0))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(users)
    }

    pub fn is_license_assigned(
        &self,
        license_id: &str,
        username: &str,
    ) -> Result<bool, LicenseError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM license_users WHERE license_id = ?1 AND username = ?2",
                params![license_id, username],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(count > 0)
    }

    /// Every (username, license_key, product) assignment row. One query for
    /// the admin users list instead of a per-user lookup.
    pub fn list_all_license_assignments(
        &self,
    ) -> Result<Vec<(String, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT lu.username, l.license_key, l.product
                 FROM license_users lu JOIN licenses l ON l.id = lu.license_id
                 ORDER BY lu.username, l.product",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

}
