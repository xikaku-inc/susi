use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Documentation pages (per-release knowledge base)
    // -----------------------------------------------------------------------

    /// Upsert a single page authored via the editor. Always marks the row as
    /// `origin='user'` - even if a prior pipeline run had planted the slug.
    /// Manual edits imply ownership: next pipeline run will skip it.
    pub fn upsert_doc_page(
        &self,
        release_id: i64,
        slug: &str,
        title: &str,
        body_md: &str,
        parent_slug: Option<&str>,
        ord: i64,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO doc_pages (release_id, slug, title, body_md, parent_slug, ord, updated_at, origin)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'user')
                 ON CONFLICT(release_id, slug) DO UPDATE SET
                   title = excluded.title,
                   body_md = excluded.body_md,
                   parent_slug = excluded.parent_slug,
                   ord = excluded.ord,
                   updated_at = excluded.updated_at,
                   origin = 'user'",
                params![release_id, slug, title, body_md, parent_slug, ord, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert doc page: {}", e)))?;
        let id = self
            .conn
            .query_row(
                "SELECT id FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
                params![release_id, slug],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB lookup doc page: {}", e)))?;
        Ok(id)
    }

    /// List all pages of a release as (slug, title, parent_slug, ord, updated_at).
    pub fn list_doc_pages(
        &self,
        release_id: i64,
    ) -> Result<Vec<(String, String, Option<String>, i64, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT slug, title, parent_slug, ord, updated_at FROM doc_pages
                 WHERE release_id = ?1 ORDER BY parent_slug NULLS FIRST, ord, title",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![release_id], |r| {
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
    pub fn get_doc_page(
        &self,
        release_id: i64,
        slug: &str,
    ) -> Result<Option<(String, String, Option<String>, i64, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT title, body_md, parent_slug, ord, updated_at FROM doc_pages
             WHERE release_id = ?1 AND slug = ?2",
            params![release_id, slug],
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

    pub fn delete_doc_page(&self, release_id: i64, slug: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
                params![release_id, slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    /// Rename a page's slug atomically. Cascades to any child pages whose
    /// `parent_slug` pointed at the old value. Returns Ok(false) if the source
    /// page doesn't exist; Err on UNIQUE conflict (target slug already taken).
    pub fn rename_doc_page(
        &mut self,
        release_id: i64,
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
                "UPDATE doc_pages SET slug = ?1 WHERE release_id = ?2 AND slug = ?3",
                params![new_slug, release_id, old_slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB rename: {}", e)))?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE doc_pages SET parent_slug = ?1 WHERE release_id = ?2 AND parent_slug = ?3",
            params![new_slug, release_id, old_slug],
        )
        .map_err(|e| LicenseError::Other(format!("DB rename cascade: {}", e)))?;
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok(true)
    }

    /// Bulk-upsert pages originating from the auto-generated pipeline. Within
    /// a single transaction: for each slug, if an existing row is
    /// `origin='user'` (i.e. the user has taken ownership via the editor) the
    /// page is left untouched and its slug is returned in the skipped list.
    /// Everything else is inserted or refreshed as `origin='pipeline'`.
    /// Returns (written_count, skipped_user_slugs).
    pub fn upsert_doc_pages(
        &mut self,
        release_id: i64,
        pages: &[(String, String, String, Option<String>, i64)],
    ) -> Result<(usize, Vec<String>), LicenseError> {
        let now = Utc::now().to_rfc3339();
        let tx = self
            .conn
            .transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        let mut written = 0usize;
        let mut skipped: Vec<String> = Vec::new();
        for (slug, title, body_md, parent_slug, ord) in pages {
            let existing_origin: Option<String> = tx
                .query_row(
                    "SELECT origin FROM doc_pages WHERE release_id = ?1 AND slug = ?2",
                    params![release_id, slug],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| LicenseError::Other(format!("DB origin probe {}: {}", slug, e)))?;
            if existing_origin.as_deref() == Some("user") {
                skipped.push(slug.clone());
                continue;
            }
            tx.execute(
                "INSERT INTO doc_pages (release_id, slug, title, body_md, parent_slug, ord, updated_at, origin)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pipeline')
                 ON CONFLICT(release_id, slug) DO UPDATE SET
                   title = excluded.title,
                   body_md = excluded.body_md,
                   parent_slug = excluded.parent_slug,
                   ord = excluded.ord,
                   updated_at = excluded.updated_at,
                   origin = 'pipeline'",
                params![release_id, slug, title, body_md, parent_slug.as_deref(), ord, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert page {}: {}", slug, e)))?;
            written += 1;
        }
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB commit: {}", e)))?;
        Ok((written, skipped))
    }

    /// Upsert an asset uploaded via the editor - always marks origin='user',
    /// including when overwriting a prior pipeline-planted row.
    pub fn upsert_doc_asset(
        &self,
        release_id: i64,
        file_name: &str,
        file_size: u64,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO doc_assets (release_id, file_name, file_size, origin)
                 VALUES (?1, ?2, ?3, 'user')
                 ON CONFLICT(release_id, file_name) DO UPDATE SET
                   file_size = excluded.file_size,
                   origin = 'user'",
                params![release_id, file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert asset: {}", e)))?;
        Ok(())
    }

    /// Pipeline-side asset upsert. Skips rows whose existing origin='user' so
    /// hand-uploaded assets aren't clobbered. Returns true if written.
    pub fn upsert_doc_asset_pipeline(
        &self,
        release_id: i64,
        file_name: &str,
        file_size: u64,
    ) -> Result<bool, LicenseError> {
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT origin FROM doc_assets WHERE release_id = ?1 AND file_name = ?2",
                params![release_id, file_name],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB asset origin probe: {}", e)))?;
        if existing.as_deref() == Some("user") {
            return Ok(false);
        }
        self.conn
            .execute(
                "INSERT INTO doc_assets (release_id, file_name, file_size, origin)
                 VALUES (?1, ?2, ?3, 'pipeline')
                 ON CONFLICT(release_id, file_name) DO UPDATE SET
                   file_size = excluded.file_size,
                   origin = 'pipeline'",
                params![release_id, file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert asset: {}", e)))?;
        Ok(true)
    }

    pub fn list_doc_assets(&self, release_id: i64) -> Result<Vec<(String, u64)>, LicenseError> {
        let mut stmt = self.conn
            .prepare("SELECT file_name, file_size FROM doc_assets WHERE release_id = ?1 ORDER BY file_name")
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

    pub fn delete_doc_asset(&self, release_id: i64, file_name: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM doc_assets WHERE release_id = ?1 AND file_name = ?2",
                params![release_id, file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    /// Releases of one product that contain at least one doc page (newest
    /// first). Returns (id, tag, name, created_at, page_count).
    pub fn list_doc_releases(
        &self,
        product: &str,
    ) -> Result<Vec<(i64, String, String, String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT r.id, r.tag, r.name, r.created_at, COUNT(p.id)
                 FROM releases r
                 INNER JOIN doc_pages p ON p.release_id = r.id
                 WHERE r.workspace_id IS NULL AND r.product = ?1
                 GROUP BY r.id
                 ORDER BY r.id DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![product], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Ensure a release row exists for the given tag under the default product
    /// - used by bulk doc import when the docs ship before the binary release.
    /// Returns the release id.
    pub fn ensure_release(&self, tag: &str, name: &str) -> Result<i64, LicenseError> {
        Ok(self.ensure_release_created(tag, name)?.0)
    }

    /// Same as `ensure_release` but also signals whether the row was created
    /// (true) or already existed (false). Callers use the boolean to trigger
    /// one-shot seeding (e.g. copying hand-authored doc pages forward).
    pub fn ensure_release_created(
        &self,
        tag: &str,
        name: &str,
    ) -> Result<(i64, bool), LicenseError> {
        self.ensure_release_created_for(DEFAULT_PRODUCT, tag, name)
    }

    /// Product-aware variant.
    pub fn ensure_release_created_for(
        &self,
        product: &str,
        tag: &str,
        name: &str,
    ) -> Result<(i64, bool), LicenseError> {
        if let Some(id) = self.get_release_by_product_tag(product, tag)? {
            return Ok((id, false));
        }
        // Only doc handlers create releases through here, so a fresh row is a
        // doc-only collection. A later binary upload promotes it to 'software'.
        let id = self.insert_release(product, tag, name, "", false, "docs")?;
        Ok((id, true))
    }

    /// Return (id, tag) of the most recent release that has at least one
    /// `origin='user'` doc page, excluding a given release id. Restricted to
    /// the same product so user docs never seed across products.
    pub fn latest_prior_release_with_user_docs(
        &self,
        exclude_id: i64,
        product: &str,
    ) -> Result<Option<(i64, String)>, LicenseError> {
        self.conn
            .query_row(
                "SELECT r.id, r.tag FROM releases r
                 WHERE r.id != ?1
                   AND r.product = ?2
                   AND EXISTS (
                       SELECT 1 FROM doc_pages p
                       WHERE p.release_id = r.id AND p.origin = 'user'
                   )
                 ORDER BY r.id DESC LIMIT 1",
                params![exclude_id, product],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB prior release: {}", e)))
    }

    /// Clone all `origin='user'` doc pages from `src_release_id` into
    /// `dst_release_id`. Slugs that already exist in the destination are left
    /// untouched (which shouldn't happen for a freshly created release, but
    /// makes the helper idempotent). Returns the number of pages inserted.
    pub fn copy_user_doc_pages(
        &mut self,
        src_release_id: i64,
        dst_release_id: i64,
    ) -> Result<usize, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let n = self
            .conn
            .execute(
                "INSERT OR IGNORE INTO doc_pages
                   (release_id, slug, title, body_md, parent_slug, ord, updated_at, origin)
                 SELECT ?1, slug, title, body_md, parent_slug, ord, ?2, 'user'
                 FROM doc_pages
                 WHERE release_id = ?3 AND origin = 'user'",
                params![dst_release_id, now, src_release_id],
            )
            .map_err(|e| LicenseError::Other(format!("DB copy user pages: {}", e)))?;
        Ok(n)
    }

    /// Clone `origin='user'` asset rows between releases. Returns the list of
    /// file names so the caller can copy the backing files on disk (the DB
    /// only knows about metadata).
    pub fn copy_user_doc_asset_rows(
        &self,
        src_release_id: i64,
        dst_release_id: i64,
    ) -> Result<Vec<String>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT file_name, file_size FROM doc_assets
                 WHERE release_id = ?1 AND origin = 'user'",
            )
            .map_err(|e| LicenseError::Other(format!("DB prep: {}", e)))?;
        let rows: Vec<(String, i64)> = stmt
            .query_map(params![src_release_id], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        let mut copied = Vec::with_capacity(rows.len());
        for (name, size) in rows {
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO doc_assets (release_id, file_name, file_size, origin)
                     VALUES (?1, ?2, ?3, 'user')",
                    params![dst_release_id, name, size],
                )
                .map_err(|e| LicenseError::Other(format!("DB insert asset: {}", e)))?;
            copied.push(name);
        }
        Ok(copied)
    }

}
