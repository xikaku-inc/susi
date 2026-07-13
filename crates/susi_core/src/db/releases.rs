use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Releases (with workspace scoping)
    // -----------------------------------------------------------------------

    /// `kind` is 'software' for binary releases, 'docs' for doc-only
    /// collections (which live in the same table so doc_pages/doc_assets can
    /// FK on release_id, but must not surface in software release listings).
    pub fn insert_release(
        &self,
        product: &str,
        tag: &str,
        name: &str,
        body: &str,
        prerelease: bool,
        workspace_id: Option<&str>,
        kind: &str,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO releases (product, tag, name, body, prerelease, created_at, workspace_id, kind) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![product, tag, name, body, prerelease as i32, now, workspace_id, kind],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert release: {}", e)))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Promote a doc-only collection to a software release once binaries get
    /// attached to it (upload reusing an existing tag).
    pub fn set_release_kind(&self, release_id: i64, kind: &str) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "UPDATE releases SET kind = ?1 WHERE id = ?2",
                params![kind, release_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update release kind: {}", e)))?;
        Ok(())
    }

    pub fn add_release_asset(
        &self,
        release_id: i64,
        file_name: &str,
        file_size: u64,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO release_assets (release_id, file_name, file_size) VALUES (?1, ?2, ?3)
                 ON CONFLICT(release_id, file_name) DO UPDATE SET file_size = excluded.file_size",
                params![release_id, file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB insert asset: {}", e)))?;
        Ok(())
    }

    pub fn delete_release_asset(
        &self,
        release_id: i64,
        file_name: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM release_assets WHERE release_id = ?1 AND file_name = ?2",
                params![release_id, file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete asset: {}", e)))?;
        Ok(n > 0)
    }

    /// Update metadata of an existing release without touching its id (so
    /// FKs from doc_pages / release_assets remain intact).
    pub fn update_release_metadata(
        &self,
        release_id: i64,
        name: &str,
        body: &str,
        prerelease: bool,
        workspace_id: Option<&str>,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "UPDATE releases SET name = ?1, body = ?2, prerelease = ?3, workspace_id = ?4, created_at = ?5 WHERE id = ?6",
                params![name, body, prerelease as i32, workspace_id, now, release_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB update release: {}", e)))?;
        Ok(())
    }

    pub fn list_releases(
        &self,
    ) -> Result<Vec<(i64, String, String, String, bool, String, Option<String>, String)>, LicenseError>
    {
        let mut stmt = self.conn
            .prepare("SELECT id, tag, name, body, prerelease, created_at, workspace_id, product FROM releases WHERE kind = 'software' ORDER BY id DESC")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i32>(4)? != 0,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// List releases that belong to a single workspace. Global releases are
    /// excluded — those are reachable through the public/admin global release
    /// listing and don't belong on a workspace-specific surface.
    pub fn list_releases_for_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(i64, String, String, String, bool, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, tag, name, body, prerelease, created_at FROM releases
                 WHERE workspace_id = ?1 AND kind = 'software'
                 ORDER BY id DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i32>(4)? != 0,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_release_assets(&self, release_id: i64) -> Result<Vec<(String, u64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT file_name, file_size FROM release_assets WHERE release_id = ?1")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![release_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Batch variant of `get_release_assets` for list endpoints. Returns one
    /// `release_id → assets` map after a single query, eliminating the
    /// per-release N+1 in `handle_list_releases_admin` / workspace listings.
    pub fn get_assets_for_releases(
        &self,
        release_ids: &[i64],
    ) -> Result<std::collections::HashMap<i64, Vec<(String, u64)>>, LicenseError> {
        let mut out: std::collections::HashMap<i64, Vec<(String, u64)>> =
            std::collections::HashMap::with_capacity(release_ids.len());
        if release_ids.is_empty() {
            return Ok(out);
        }
        let placeholders = std::iter::repeat("?")
            .take(release_ids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT release_id, file_name, file_size FROM release_assets WHERE release_id IN ({})",
            placeholders,
        );
        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let params_iter: Vec<&dyn rusqlite::ToSql> = release_ids
            .iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();
        let rows = stmt
            .query_map(&params_iter[..], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)? as u64,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        for (rid, name, size) in rows.flatten() {
            out.entry(rid).or_default().push((name, size));
        }
        Ok(out)
    }

    pub fn get_release_by_product_tag(
        &self,
        product: &str,
        tag: &str,
    ) -> Result<Option<i64>, LicenseError> {
        match self.conn.query_row(
            "SELECT id FROM releases WHERE product = ?1 AND tag = ?2",
            params![product, tag],
            |r| r.get(0),
        ) {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    /// Reassign a release to a different workspace (or to global with `None`).
    /// Doesn't touch any other column — doc pages, assets, and software files
    /// stay attached because they FK on release_id, not on workspace_id.
    pub fn set_release_workspace(
        &self,
        release_id: i64,
        workspace_id: Option<&str>,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "UPDATE releases SET workspace_id = ?1 WHERE id = ?2",
                params![workspace_id, release_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB move release: {}", e)))?;
        Ok(())
    }

    /// Return `Some(workspace_id_or_none)` if the (product, tag) exists, else
    /// `None`. Inner `Option` is `Some(ws_id)` for workspace-scoped, `None` for
    /// global.
    pub fn get_release_workspace_id(
        &self,
        product: &str,
        tag: &str,
    ) -> Result<Option<Option<String>>, LicenseError> {
        match self.conn.query_row(
            "SELECT workspace_id FROM releases WHERE product = ?1 AND tag = ?2",
            params![product, tag],
            |r| r.get::<_, Option<String>>(0),
        ) {
            Ok(ws) => Ok(Some(ws)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn delete_release(&self, product: &str, tag: &str) -> Result<bool, LicenseError> {
        let rows = self
            .conn
            .execute(
                "DELETE FROM releases WHERE product = ?1 AND tag = ?2",
                params![product, tag],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(rows > 0)
    }

}
