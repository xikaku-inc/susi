use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Website pages / assets (per-site public page store, no releases)
    // -----------------------------------------------------------------------

    /// Upsert a website page. When the row already exists and its content
    /// actually differs from the incoming state, the prior state is captured
    /// into `website_page_revisions` so edits are recoverable.
    pub fn upsert_website_page(
        &mut self,
        site: &str,
        lang: &str,
        slug: &str,
        title: &str,
        body_md: &str,
        parent_slug: Option<&str>,
        ord: i64,
        meta_description: &str,
        page_kind: &str,
        published_at: &str,
        author_username: &str,
        redirect_to: &str,
        translation_of: &str,
        og_image: &str,
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
                "SELECT title, body_md, parent_slug, ord FROM website_pages WHERE site = ?1 AND lang = ?2 AND slug = ?3",
                params![site, lang, slug],
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
                       (site, lang, slug, title, body_md, parent_slug, ord, captured_at, author)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![site, lang, slug, p_title, p_body, p_parent, p_ord, now, author],
                )
                .map_err(|e| LicenseError::Other(format!("DB snapshot: {}", e)))?;
            }
        }

        tx.execute(
            "INSERT INTO website_pages (site, lang, slug, title, body_md, parent_slug, ord, updated_at, meta_description, page_kind, published_at, author_username, redirect_to, translation_of, og_image)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(site, lang, slug) DO UPDATE SET
               title = excluded.title,
               body_md = excluded.body_md,
               parent_slug = excluded.parent_slug,
               ord = excluded.ord,
               updated_at = excluded.updated_at,
               meta_description = excluded.meta_description,
               page_kind = excluded.page_kind,
               published_at = excluded.published_at,
               author_username = excluded.author_username,
               redirect_to = excluded.redirect_to,
               translation_of = excluded.translation_of,
               og_image = excluded.og_image",
            params![site, lang, slug, title, body_md, parent_slug, ord, now, meta_description, page_kind, published_at, author_username, redirect_to, translation_of, og_image],
        )
        .map_err(|e| LicenseError::Other(format!("DB upsert website page: {}", e)))?;
        let id = tx
            .query_row(
                "SELECT id FROM website_pages WHERE site = ?1 AND lang = ?2 AND slug = ?3",
                params![site, lang, slug],
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
        site: &str,
        lang: &str,
        slug: &str,
    ) -> Result<Vec<(i64, String, Option<String>, String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, captured_at, author, title, LENGTH(body_md)
                 FROM website_page_revisions
                 WHERE site = ?1 AND lang = ?2 AND slug = ?3
                 ORDER BY captured_at DESC, id DESC",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![site, lang, slug], |r| {
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
        site: &str,
        lang: &str,
        slug: &str,
        revision_id: i64,
    ) -> Result<Option<(String, String, Option<String>, i64, String, Option<String>)>, LicenseError>
    {
        self.conn
            .query_row(
                "SELECT title, body_md, parent_slug, ord, captured_at, author
                 FROM website_page_revisions
                 WHERE site = ?1 AND lang = ?2 AND slug = ?3 AND id = ?4",
                params![site, lang, slug, revision_id],
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
        site: &str,
    ) -> Result<Vec<(String, i64, i64, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT a.file_name, a.file_size,
                        (SELECT COUNT(*) FROM website_pages p
                           WHERE p.site = a.site AND p.body_md LIKE '%' || a.file_name || '%') AS usage_count,
                        COALESCE(
                          (SELECT GROUP_CONCAT(p.slug, ',') FROM website_pages p
                             WHERE p.site = a.site AND p.body_md LIKE '%' || a.file_name || '%'),
                          ''
                        ) AS pages_csv,
                        COALESCE(
                          (SELECT GROUP_CONCAT(s.sku, ',') FROM shop_products s
                             WHERE s.site = a.site AND s.image_asset = a.file_name),
                          ''
                        ) AS products_csv
                 FROM website_assets a
                 WHERE a.site = ?1
                 ORDER BY a.file_name",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![site], |r| {
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
        site: &str,
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
                "SELECT 1 FROM website_assets WHERE site = ?1 AND file_name = ?2",
                params![site, new_name],
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
                "UPDATE website_assets SET file_name = ?1 WHERE site = ?2 AND file_name = ?3",
                params![new_name, site, old_name],
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
             WHERE site = ?5 AND body_md LIKE '%' || ?6 || '%'",
                params![brace_old, brace_new, paren_old, paren_new, site, old_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB rewrite body_md: {}", e)))?;
        tx.execute(
            "UPDATE shop_products SET image_asset = ?1 WHERE site = ?3 AND image_asset = ?2",
            params![new_name, old_name, site],
        )
        .map_err(|e| LicenseError::Other(format!("DB rewrite product image: {}", e)))?;
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok((true, n_pages))
    }

    /// All languages; the two trailing fields are (lang, translation_of).
    pub fn list_website_pages(
        &self,
        site: &str,
    ) -> Result<Vec<(String, String, Option<String>, i64, String, String, bool, String, String, String, String, String, String)>, LicenseError> {
        let mut stmt = self.conn
            .prepare(
                "SELECT slug, title, parent_slug, ord, updated_at, meta_description, hidden, page_kind, published_at, author_username, redirect_to, lang, translation_of FROM website_pages
                 WHERE site = ?1
                 ORDER BY parent_slug NULLS FIRST, ord, title",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![site], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)? != 0,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, String>(12)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// The two trailing fields are (translation_of, og_image).
    pub fn get_website_page(
        &self,
        site: &str,
        lang: &str,
        slug: &str,
    ) -> Result<Option<(String, String, Option<String>, i64, String, String, bool, String, String, String, String, String, String)>, LicenseError> {
        match self.conn.query_row(
            "SELECT title, body_md, parent_slug, ord, updated_at, meta_description, hidden, page_kind, published_at, author_username, redirect_to, translation_of, og_image FROM website_pages
             WHERE site = ?1 AND lang = ?2 AND slug = ?3",
            params![site, lang, slug],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)? != 0,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, String>(12)?,
                ))
            },
        ) {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB query: {}", e))),
        }
    }

    // -----------------------------------------------------------------------
    // Path-level 301 redirects
    // -----------------------------------------------------------------------

    pub fn upsert_site_redirect(
        &self,
        site: &str,
        from_path: &str,
        to_path: &str,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO site_redirects (site, from_path, to_path, updated_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(site, from_path) DO UPDATE SET
                   to_path = excluded.to_path,
                   updated_at = excluded.updated_at",
                params![site, from_path, to_path, Utc::now().to_rfc3339()],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert redirect: {}", e)))?;
        Ok(())
    }

    pub fn get_site_redirect(&self, site: &str, from_path: &str) -> Result<Option<String>, LicenseError> {
        match self.conn.query_row(
            "SELECT to_path FROM site_redirects WHERE site = ?1 AND from_path = ?2",
            params![site, from_path],
            |r| r.get::<_, String>(0),
        ) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LicenseError::Other(format!("DB get redirect: {}", e))),
        }
    }

    pub fn list_site_redirects(
        &self,
        site: &str,
    ) -> Result<Vec<(i64, String, String, String)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, from_path, to_path, updated_at FROM site_redirects
                 WHERE site = ?1 ORDER BY from_path",
            )
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![site], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn delete_site_redirect(&self, site: &str, id: i64) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM site_redirects WHERE site = ?1 AND id = ?2",
                params![site, id],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete redirect: {}", e)))?;
        Ok(n > 0)
    }

    /// Set the hidden flag on a page. Returns false if the slug doesn't exist.
    pub fn set_website_page_hidden(&self, site: &str, lang: &str, slug: &str, hidden: bool) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "UPDATE website_pages SET hidden = ?1 WHERE site = ?2 AND lang = ?3 AND slug = ?4",
                params![hidden as i64, site, lang, slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB set hidden: {}", e)))?;
        Ok(n > 0)
    }

    pub fn delete_website_page(&self, site: &str, lang: &str, slug: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM website_pages WHERE site = ?1 AND lang = ?2 AND slug = ?3",
                params![site, lang, slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete: {}", e)))?;
        Ok(n > 0)
    }

    /// Rename a website page slug, cascading `parent_slug` references within
    /// its language and `translation_of` links from other languages when the
    /// renamed page is in the default language.
    /// Returns Ok(false) if the source slug doesn't exist; Err on UNIQUE conflict.
    pub fn rename_website_page(
        &mut self,
        site: &str,
        lang: &str,
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
                "UPDATE website_pages SET slug = ?1 WHERE site = ?2 AND lang = ?3 AND slug = ?4",
                params![new_slug, site, lang, old_slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB rename: {}", e)))?;
        if n == 0 {
            return Ok(false);
        }
        tx.execute(
            "UPDATE website_pages SET parent_slug = ?1 WHERE site = ?2 AND lang = ?3 AND parent_slug = ?4",
            params![new_slug, site, lang, old_slug],
        )
        .map_err(|e| LicenseError::Other(format!("DB rename cascade: {}", e)))?;
        if lang.is_empty() {
            tx.execute(
                "UPDATE website_pages SET translation_of = ?1 WHERE site = ?2 AND translation_of = ?3",
                params![new_slug, site, old_slug],
            )
            .map_err(|e| LicenseError::Other(format!("DB rename translation links: {}", e)))?;
        }
        tx.commit()
            .map_err(|e| LicenseError::Other(format!("DB tx commit: {}", e)))?;
        Ok(true)
    }

    pub fn upsert_website_asset(
        &self,
        site: &str,
        file_name: &str,
        file_size: u64,
    ) -> Result<(), LicenseError> {
        self.conn
            .execute(
                "INSERT INTO website_assets (site, file_name, file_size)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(site, file_name) DO UPDATE SET file_size = excluded.file_size",
                params![site, file_name, file_size as i64],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert website asset: {}", e)))?;
        Ok(())
    }

    /// Returns true if a website asset with the given file name is recorded.
    /// Used by shop product upsert to validate `image_asset` references a
    /// real upload before saving.
    pub fn website_asset_exists(&self, site: &str, file_name: &str) -> Result<bool, LicenseError> {
        match self.conn.query_row(
            "SELECT 1 FROM website_assets WHERE site = ?1 AND file_name = ?2",
            params![site, file_name],
            |_| Ok(()),
        ) {
            Ok(_) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(LicenseError::Other(format!("DB asset exists: {}", e))),
        }
    }

    pub fn list_website_assets(&self, site: &str) -> Result<Vec<(String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT file_name, file_size FROM website_assets WHERE site = ?1 ORDER BY file_name")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map(params![site], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn delete_website_asset(&self, site: &str, file_name: &str) -> Result<bool, LicenseError> {
        let n = self
            .conn
            .execute(
                "DELETE FROM website_assets WHERE site = ?1 AND file_name = ?2",
                params![site, file_name],
            )
            .map_err(|e| LicenseError::Other(format!("DB delete website asset: {}", e)))?;
        Ok(n > 0)
    }

}
