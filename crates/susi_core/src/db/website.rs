use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Website pages / assets (single-site public page store, no releases)
    // -----------------------------------------------------------------------

    /// Upsert a website page. When the row already exists and its content
    /// actually differs from the incoming state, the prior state is captured
    /// into `website_page_revisions` so edits are recoverable.
    pub fn upsert_website_page(
        &mut self,
        slug: &str,
        title: &str,
        body_md: &str,
        parent_slug: Option<&str>,
        ord: i64,
        meta_description: &str,
        author: Option<&str>,
    ) -> Result<i64, LicenseError> {
        let now = Utc::now().to_rfc3339();
        let tx = self
            .conn
            .transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;

        // Capture prior state as a revision if this is an update-with-change.
        let prior: Option<(String, String, Option<String>, i64)> = tx
            .query_row(
                "SELECT title, body_md, parent_slug, ord FROM website_pages WHERE slug = ?1",
                params![slug],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB read prior: {}", e)))?;
        if let Some((p_title, p_body, p_parent, p_ord)) = &prior {
            let unchanged = p_title == title
                && p_body == body_md
                && p_parent.as_deref() == parent_slug
                && *p_ord == ord;
            if !unchanged {
                tx.execute(
                    "INSERT INTO website_page_revisions
                       (slug, title, body_md, parent_slug, ord, captured_at, author)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![slug, p_title, p_body, p_parent, p_ord, now, author],
                )
                .map_err(|e| LicenseError::Other(format!("DB snapshot: {}", e)))?;
            }
        }

        tx.execute(
            "INSERT INTO website_pages (slug, title, body_md, parent_slug, ord, updated_at, meta_description)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(slug) DO UPDATE SET
               title = excluded.title,
               body_md = excluded.body_md,
               parent_slug = excluded.parent_slug,
               ord = excluded.ord,
               updated_at = excluded.updated_at,
               meta_description = excluded.meta_description",
            params![slug, title, body_md, parent_slug, ord, now, meta_description],
        )
        .map_err(|e| LicenseError::Other(format!("DB upsert website page: {}", e)))?;
        let id = tx
            .query_row(
                "SELECT id FROM website_pages WHERE slug = ?1",
                params![slug],
                |r| r.get::<_, i64>(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB lookup website page: {}", e)))?;
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok(id)
    }

    /// List revisions for a page, newest first. Body omitted for list brevity.
    pub fn list_page_revisions(
        &self,
        slug: &str,
    ) -> Result<Vec<(i64, String, Option<String>, String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, captured_at, author, title, LENGTH(body_md)
                 FROM website_page_revisions
                 WHERE slug = ?1
                 ORDER BY captured_at DESC, id DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![slug], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Fetch full content of a specific revision by id.
    pub fn get_page_revision(
        &self,
        slug: &str,
        revision_id: i64,
    ) -> Result<Option<(String, String, Option<String>, i64, String, Option<String>)>, LicenseError>
    {
        self.conn
            .query_row(
                "SELECT title, body_md, parent_slug, ord, captured_at, author
                 FROM website_page_revisions
                 WHERE slug = ?1 AND id = ?2",
                params![slug, revision_id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    /// Assets with usage: (file_name, file_size, usage_count, pages_csv, products_csv).
    /// A page is counted if its body contains the literal filename substring;
    /// products_csv lists shop SKUs whose image_asset is this file.
    pub fn list_website_assets_with_usage(
        &self,
    ) -> Result<Vec<(String, i64, i64, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT a.file_name, a.file_size,
                        (SELECT COUNT(*) FROM website_pages p
                           WHERE p.body_md LIKE '%' || a.file_name || '%') AS usage_count,
                        COALESCE(
                          (SELECT GROUP_CONCAT(p.slug, ',') FROM website_pages p
                             WHERE p.body_md LIKE '%' || a.file_name || '%'),
                          ''
                        ) AS pages_csv,
                        COALESCE(
                          (SELECT GROUP_CONCAT(s.sku, ',') FROM shop_products s
                             WHERE s.image_asset = a.file_name),
                          ''
                        ) AS products_csv
                 FROM website_assets a
                 ORDER BY a.file_name",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Rename an asset file_name and rewrite every markdown reference in page
    /// bodies in the same transaction. Returns (renamed, pages_updated).
    pub fn rename_website_asset(
        &mut self,
        old_name: &str,
        new_name: &str,
    ) -> Result<(bool, usize), LicenseError> {
        if old_name == new_name {
            return Ok((true, 0));
        }
        let tx = self
            .conn
            .transaction()
            .map_err(|e| LicenseError::Other(format!("DB tx: {}", e)))?;
        // Reject if target already exists (would collide on UNIQUE).
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM website_assets WHERE file_name = ?1",
                params![new_name],
                |_| Ok(true),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB check: {}", e)))?
            .unwrap_or(false);
        if exists {
            return Err(LicenseError::Other("target filename already exists".into()));
        }
        let n_assets = tx
            .execute(
                "UPDATE website_assets SET file_name = ?1 WHERE file_name = ?2",
                params![new_name, old_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB rename asset: {}", e)))?;
        if n_assets == 0 {
            return Ok((false, 0));
        }
        // Rewrite markdown: match both `](old)` and `](old){...}` forms.
        let paren_old = format!("]({})", old_name);
        let paren_new = format!("]({})", new_name);
        let brace_old = format!("]({}){{", old_name);
        let brace_new = format!("]({}){{", new_name);
        let n_pages = tx
            .execute(
                "UPDATE website_pages
             SET body_md = REPLACE(REPLACE(body_md, ?1, ?2), ?3, ?4)
             WHERE body_md LIKE '%' || ?5 || '%'",
                params![brace_old, brace_new, paren_old, paren_new, old_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB rewrite body_md: {}", e)))?;
        tx.execute(
            "UPDATE shop_products SET image_asset = ?1 WHERE image_asset = ?2",
            params![new_name, old_name],
        )
        .map_err(|e| LicenseError::Other(format!("DB rewrite product image: {}", e)))?;
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok((true, n_pages))
    }

    pub fn list_website_pages(
        &self,
    ) -> Result<Vec<(String, String, Option<String>, i64, String, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT slug, title, parent_slug, ord, updated_at, meta_description FROM website_pages
                 ORDER BY parent_slug NULLS FIRST, ord, title",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn get_website_page(
        &self,
        slug: &str,
    ) -> Result<Option<(String, String, Option<String>, i64, String, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT title, body_md, parent_slug, ord, updated_at, meta_description FROM website_pages
             WHERE slug = ?1",
            params![slug],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            },
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    pub fn delete_website_page(&self, slug: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute("DELETE FROM website_pages WHERE slug = ?1", params![slug])
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    /// Rename a website page slug, cascading `parent_slug` references.
    /// Returns Ok(false) if the source slug doesn't exist; Err on UNIQUE conflict.
    pub fn rename_website_page(
        &mut self,
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
                "UPDATE website_pages SET slug = ?1 WHERE slug = ?2",
                params![new_slug, old_slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB rename: {}", e)))?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE website_pages SET parent_slug = ?1 WHERE parent_slug = ?2",
            params![new_slug, old_slug],
        )
        .map_err(|e| LicenseError::Other(format!("DB rename cascade: {}", e)))?;
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok(true)
    }

    pub fn upsert_website_asset(
        &self,
        file_name: &str,
        file_size: u64,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO website_assets (file_name, file_size)
                 VALUES (?1, ?2)
                 ON CONFLICT(file_name) DO UPDATE SET file_size = excluded.file_size",
                params![file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert website asset: {}", e)))?;
        Ok(())
    }

    /// Returns true if a website asset with the given file name is recorded.
    /// Used by shop product upsert to validate `image_asset` references a
    /// real upload before saving.
    pub fn website_asset_exists(&self, file_name: &str) -> Result<bool, LicenseError> {
        match self.conn.query_row(
            "SELECT 1 FROM website_assets WHERE file_name = ?1",
            params![file_name],
            |_| Ok(()),
        ) {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(LicenseError::Other(format!("DB asset exists: {}", e))),
        }
    }

    pub fn list_website_assets(&self) -> Result<Vec<(String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT file_name, file_size FROM website_assets ORDER BY file_name")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn delete_website_asset(&self, file_name: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM website_assets WHERE file_name = ?1",
                params![file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete website asset: {}", e)))?;
        Ok(n > 0)
    }

}
