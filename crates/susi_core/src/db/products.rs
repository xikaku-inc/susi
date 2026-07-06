use super::*;

impl LicenseDb {
    // -----------------------------------------------------------------------
    // Products (catalog dimension that scopes releases + docs)
    // -----------------------------------------------------------------------

    /// All products, ordered for display. Returns (slug, name, description, ord).
    pub fn list_release_products(
        &self,
    ) -> Result<Vec<(String, String, String, i64)>, LicenseError> {
        let mut stmt = self
            .conn
            .prepare("SELECT slug, name, description, ord FROM products ORDER BY ord, name")
            .map_err(|e| LicenseError::Other(format!("DB prepare: {}", e)))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    pub fn product_exists(&self, slug: &str) -> Result<bool, LicenseError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM products WHERE slug = ?1",
                params![slug],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))?;
        Ok(count > 0)
    }

    /// Display name for a release-product slug, if the product exists.
    pub fn get_product_name(&self, slug: &str) -> Result<Option<String>, LicenseError> {
        self.conn
            .query_row(
                "SELECT name FROM products WHERE slug = ?1",
                params![slug],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    /// Insert or update a product. Slug is the immutable key.
    pub fn upsert_release_product(
        &self,
        slug: &str,
        name: &str,
        description: &str,
        ord: i64,
    ) -> Result<(), LicenseError> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO products (slug, name, description, ord, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(slug) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    ord = excluded.ord",
                params![slug, name, description, ord, now],
            )
            .map_err(|e| LicenseError::Other(format!("DB upsert product: {}", e)))?;
        Ok(())
    }

    /// Count releases attached to a product — callers reject deletion of a
    /// product that still owns releases.
    pub fn count_releases_for_product(&self, slug: &str) -> Result<i64, LicenseError> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM releases WHERE product = ?1",
                params![slug],
                |r| r.get(0),
            )
            .map_err(|e| LicenseError::Other(format!("DB query: {}", e)))
    }

    pub fn delete_release_product(&self, slug: &str) -> Result<bool, LicenseError> {
        let rows = self
            .conn
            .execute("DELETE FROM products WHERE slug = ?1", params![slug])
            .map_err(|e| LicenseError::Other(format!("DB delete product: {}", e)))?;
        Ok(rows > 0)
    }

}
