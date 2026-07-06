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
}
