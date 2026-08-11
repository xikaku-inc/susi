use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Audit log
    // -----------------------------------------------------------------------

    pub fn insert_audit(
        &self,
        actor: &str,
        action: &str,
        target: &str,
        details: &str,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO audit_log (at, actor, action, target, details)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![now, actor, action, target, details],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert audit: {}", e)))?;
        Ok(())
    }

    /// Newest-first page of audit entries. `before_id` is a keyset cursor:
    /// pass the smallest id of the previous page to fetch the next one.
    pub fn list_audit(
        &self,
        limit: i64,
        before_id: Option<i64>,
    ) -> Result<Vec<AuditRow>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, at, actor, action, target, details FROM audit_log
                 WHERE (?2 IS NULL OR id < ?2)
                 ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows: Vec<AuditRow> = stmt
            .query_map(params![limit, before_id], |r| {
                Ok(AuditRow {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    target: r.get(4)?,
                    details: r.get(5)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Retention: drop audit entries older than `max_age_days`.
    pub fn purge_audit_log(&self, max_age_days: i64) -> Result<usize, LicenseError> {
        let cutoff = (Utc::now() - Duration::days(max_age_days)).to_rfc3339();
        self.conn
            .execute("DELETE FROM audit_log WHERE at < ?1", params![cutoff])
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))
    }

    /// Every audit entry a user appears in, for the subject-access export.
    pub fn list_audit_for_user(&self, username: &str) -> Result<Vec<AuditRow>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, at, actor, action, target, details FROM audit_log
                 WHERE actor = ?1 OR target = ?1 ORDER BY id",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows: Vec<AuditRow> = stmt
            .query_map(params![username], |r| {
                Ok(AuditRow {
                    id: r.get(0)?,
                    at: r.get(1)?,
                    actor: r.get(2)?,
                    action: r.get(3)?,
                    target: r.get(4)?,
                    details: r.get(5)?,
                })
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }
}
