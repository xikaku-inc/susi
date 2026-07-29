use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Workspace files (flat per-workspace file shares; bytes live on disk
    // under the server's data dir, rows hold metadata only)
    // -----------------------------------------------------------------------

    pub fn upsert_workspace_file(
        &self,
        workspace_id: &str,
        file_name: &str,
        file_size: u64,
        author: &str,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspace_files (workspace_id, file_name, file_size, author, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(workspace_id, file_name) DO UPDATE SET
                   file_size = excluded.file_size,
                   author = excluded.author,
                   created_at = excluded.created_at",
                params![workspace_id, file_name, file_size as i64, author, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert workspace file: {}", e)))?;
        Ok(())
    }

    pub fn workspace_file_exists(
        &self,
        workspace_id: &str,
        file_name: &str,
    ) -> Result<bool, LicenseError> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM workspace_files WHERE workspace_id = ?1 AND file_name = ?2",
                params![workspace_id, file_name],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(n > 0)
    }

    /// (file_name, file_size, author, created_at), newest first.
    pub fn list_workspace_files(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(String, u64, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT file_name, file_size, author, created_at FROM workspace_files
                 WHERE workspace_id = ?1 ORDER BY created_at DESC, file_name",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn delete_workspace_file(
        &self,
        workspace_id: &str,
        file_name: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM workspace_files WHERE workspace_id = ?1 AND file_name = ?2",
                params![workspace_id, file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete workspace file: {}", e)))?;
        Ok(n > 0)
    }

    // -----------------------------------------------------------------------
    // Workspace documentation (one flat page tree per workspace; the
    // release-tag dimension only exists for global product docs)
    // -----------------------------------------------------------------------

    pub fn upsert_ws_doc_page(
        &self,
        workspace_id: &str,
        slug: &str,
        title: &str,
        body_md: &str,
        parent_slug: Option<&str>,
        ord: i64,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO workspace_doc_pages (workspace_id, slug, title, body_md, parent_slug, ord, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(workspace_id, slug) DO UPDATE SET
                   title = excluded.title,
                   body_md = excluded.body_md,
                   parent_slug = excluded.parent_slug,
                   ord = excluded.ord,
                   updated_at = excluded.updated_at",
                params![workspace_id, slug, title, body_md, parent_slug, ord, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert ws doc page: {}", e)))?;
        let id = self
            .conn
            .query_row(
                "SELECT id FROM workspace_doc_pages WHERE workspace_id = ?1 AND slug = ?2",
                params![workspace_id, slug],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB lookup ws doc page: {}", e)))?;
        Ok(id)
    }

    /// List all pages of a workspace as (slug, title, parent_slug, ord, updated_at).
    pub fn list_ws_doc_pages(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(String, String, Option<String>, i64, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT slug, title, parent_slug, ord, updated_at FROM workspace_doc_pages
                 WHERE workspace_id = ?1 ORDER BY parent_slug NULLS FIRST, ord, title",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Fetch a single page (title, body_md, parent_slug, ord, updated_at).
    pub fn get_ws_doc_page(
        &self,
        workspace_id: &str,
        slug: &str,
    ) -> Result<Option<(String, String, Option<String>, i64, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT title, body_md, parent_slug, ord, updated_at FROM workspace_doc_pages
             WHERE workspace_id = ?1 AND slug = ?2",
            params![workspace_id, slug],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn delete_ws_doc_page(
        &self,
        workspace_id: &str,
        slug: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM workspace_doc_pages WHERE workspace_id = ?1 AND slug = ?2",
                params![workspace_id, slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    /// Rename a page's slug atomically, cascading to children whose
    /// `parent_slug` pointed at the old value. Ok(false) if the source page
    /// doesn't exist; Err on UNIQUE conflict (target slug taken).
    pub fn rename_ws_doc_page(
        &mut self,
        workspace_id: &str,
        old_slug: &str,
        new_slug: &str,
    ) -> Result<bool, LicenseError> {
        if old_slug == new_slug {
            return Ok(true);
        }
        let tx = self
            .conn
            .transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        let n = tx
            .execute(
                "UPDATE workspace_doc_pages SET slug = ?1 WHERE workspace_id = ?2 AND slug = ?3",
                params![new_slug, workspace_id, old_slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB rename: {}", e)))?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE workspace_doc_pages SET parent_slug = ?1 WHERE workspace_id = ?2 AND parent_slug = ?3",
            params![new_slug, workspace_id, old_slug],
        )
        .map_err(|e| LicenseError::Other(format!("DB rename cascade: {}", e)))?;
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok(true)
    }

    pub fn upsert_ws_doc_asset(
        &self,
        workspace_id: &str,
        file_name: &str,
        file_size: u64,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO workspace_doc_assets (workspace_id, file_name, file_size)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(workspace_id, file_name) DO UPDATE SET
                   file_size = excluded.file_size",
                params![workspace_id, file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert ws doc asset: {}", e)))?;
        Ok(())
    }

    pub fn list_ws_doc_assets(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<(String, u64)>, LicenseError> {
        let mut stmt = self.conn
            .prepare("SELECT file_name, file_size FROM workspace_doc_assets WHERE workspace_id = ?1 ORDER BY file_name")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![workspace_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn delete_ws_doc_asset(
        &self,
        workspace_id: &str,
        file_name: &str,
    ) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM workspace_doc_assets WHERE workspace_id = ?1 AND file_name = ?2",
                params![workspace_id, file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    // -----------------------------------------------------------------------
    // One-time migration of workspace-scoped releases (retired concept) into
    // workspace files + workspace docs. The server orchestrates the disk
    // moves; these helpers do the row moves.
    // -----------------------------------------------------------------------

    /// Releases still carrying a workspace scope, newest first (so slug/file
    /// collisions resolve to the newest content). Returns
    /// (id, tag, product, workspace_id, created_at). Empty once the
    /// `workspace_id` column is gone or no scoped rows remain.
    pub fn list_workspace_scoped_releases(
        &self,
    ) -> Result<Vec<(i64, String, String, String, String)>, LicenseError> {
        let has_col: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('releases') WHERE name = 'workspace_id'",
                [],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB pragma: {}", e)))?;
        if has_col == 0 {
            return Ok(Vec::new());
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, tag, product, workspace_id, created_at FROM releases
                 WHERE workspace_id IS NOT NULL ORDER BY id DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Move one release's doc pages + doc asset rows into the workspace-scoped
    /// tables. Existing workspace slugs/file names win (INSERT OR IGNORE), so
    /// calling for releases newest-first keeps the newest content. Returns the
    /// asset file names of the release so the caller can copy the files on disk.
    pub fn migrate_release_docs_to_workspace(
        &self,
        release_id: i64,
        workspace_id: &str,
    ) -> Result<Vec<String>, LicenseError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO workspace_doc_pages
                   (workspace_id, slug, title, body_md, parent_slug, ord, updated_at)
                 SELECT ?1, slug, title, body_md, parent_slug, ord, updated_at
                 FROM doc_pages WHERE release_id = ?2",
                params![workspace_id, release_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB migrate ws doc pages: {}", e)))?;
        self.conn
            .execute(
                "INSERT OR IGNORE INTO workspace_doc_assets (workspace_id, file_name, file_size)
                 SELECT ?1, file_name, file_size FROM doc_assets WHERE release_id = ?2",
                params![workspace_id, release_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB migrate ws doc assets: {}", e)))?;
        let mut stmt = self
            .conn
            .prepare("SELECT file_name FROM doc_assets WHERE release_id = ?1")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let names = stmt
            .query_map(params![release_id], |r| r.get::<_, String>(0))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(names)
    }

    /// Preserve the original release date on a migrated file row.
    pub fn migrate_workspace_file_row(
        &self,
        workspace_id: &str,
        file_name: &str,
        file_size: u64,
        created_at: &str,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO workspace_files (workspace_id, file_name, file_size, author, created_at)
                 VALUES (?1, ?2, ?3, '', ?4)",
                params![workspace_id, file_name, file_size as i64, created_at],
            )
            .map_err(|e| LicenseError::Other(format!("DB migrate ws file: {}", e)))?;
        Ok(())
    }

    /// Delete a migrated release row; doc_pages / doc_assets / release_assets
    /// cascade via their FKs.
    pub fn delete_release_by_id(&self, release_id: i64) -> Result<(), LicenseError> {
        self.conn
            .execute("DELETE FROM releases WHERE id = ?1", params![release_id])
            .map_err(|e| LicenseError::Other(format!("DB delete release: {}", e)))?;
        Ok(())
    }
}
