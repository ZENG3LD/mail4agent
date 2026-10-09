//! Media repository for attachments. Blobs are opaque bytes: in E2E rooms
//! clients upload AES-CTR ciphertext (Matrix encrypted attachments), so the
//! server stores ciphertext only. They follow the ciphertext-pump rule: kept
//! for a TTL (see [`purge_expired`]) and then deleted. Plaintext uploads for
//! public channels use the same table and the same TTL for now; a separate
//! persistent public-media store is a named seam, not built.

use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

/// Largest accepted upload.
pub const MAX_UPLOAD_BYTES: usize = 25 * 1024 * 1024;

/// DDL (own table, outside the event tables).
pub fn create_media_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS media (
            media_id      TEXT PRIMARY KEY,
            owner_user_id INTEGER NOT NULL,
            content_type  TEXT NOT NULL,
            filename      TEXT,
            created_ms    INTEGER NOT NULL,
            data          BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_media_created ON media(created_ms);",
    )
}

/// A fetched blob.
pub struct Blob {
    /// MIME type given at upload.
    pub content_type: String,
    /// Optional upload filename.
    pub filename: Option<String>,
    /// Bytes.
    pub data: Vec<u8>,
}

/// Stores a blob and returns its media id (24 url-safe chars).
pub fn put(conn: &Connection, owner: i64, content_type: &str, filename: Option<&str>, data: &[u8], now_ms: i64) -> rusqlite::Result<String> {
    let mut raw = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut raw);
    let id = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw);
    conn.execute(
        "INSERT INTO media (media_id, owner_user_id, content_type, filename, created_ms, data) VALUES (?1,?2,?3,?4,?5,?6)",
        params![id, owner, content_type, filename, now_ms, data],
    )?;
    Ok(id)
}

/// Fetches a blob.
pub fn get(conn: &Connection, media_id: &str) -> rusqlite::Result<Option<Blob>> {
    conn.query_row("SELECT content_type, filename, data FROM media WHERE media_id = ?1", params![media_id], |r| {
        Ok(Blob { content_type: r.get(0)?, filename: r.get(1)?, data: r.get(2)? })
    })
    .optional()
}

/// Deletes blobs older than `ttl_ms`. Returns how many.
pub fn purge_expired(conn: &Connection, now_ms: i64, ttl_ms: i64) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM media WHERE created_ms < ?1", params![now_ms - ttl_ms])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_and_ttl() {
        let c = Connection::open_in_memory().unwrap();
        create_media_schema(&c).unwrap();
        let id = put(&c, 1, "application/octet-stream", Some("a.bin"), &[1, 2, 3], 1_000).unwrap();
        assert_eq!(get(&c, &id).unwrap().unwrap().data, vec![1, 2, 3]);
        assert_eq!(purge_expired(&c, 1_500, 1_000).unwrap(), 0);
        assert_eq!(purge_expired(&c, 5_000, 1_000).unwrap(), 1);
        assert!(get(&c, &id).unwrap().is_none());
    }
}
