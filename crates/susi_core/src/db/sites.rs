//! Registry of the public sites this backend serves.

use rusqlite::params;

use super::LicenseDb;
use crate::error::LicenseError;

impl LicenseDb {
    /// All sites ordered by `ord`: (id, config JSON).
    pub fn list_sites(&self) -> Result<Vec<(String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, config FROM sites ORDER BY ord, id")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn sites_count(&self) -> Result<i64, LicenseError> {
        self.conn
            .query_row("SELECT COUNT(*) FROM sites", [], |r| r.get(0))
            .map_err(|e| LicenseError::Other(format!("DB sites count: {}", e)))
    }

    /// Insert or replace a site. A new site should pass `ord = None` to be
    /// appended after the existing ones; an update keeps the stored ord.
    pub fn upsert_site(&self, id: &str, ord: Option<i64>, config: &str) -> Result<(), LicenseError> {
        let ord = match ord {
            Some(o) => o,
            None => self
                .conn
                .query_row(
                    "SELECT COALESCE((SELECT ord FROM sites WHERE id = ?1),
                                     (SELECT COALESCE(MAX(ord), -1) + 1 FROM sites))",
                    params![id],
                    |r| r.get(0),
                )
                .map_err(|e| LicenseError::Other(format!("DB site ord: {}", e)))?,
        };
        self.conn
            .execute(
                "INSERT INTO sites (id, ord, config) VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET config = excluded.config",
                params![id, ord, config],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert site: {}", e)))?;
        Ok(())
    }
}
