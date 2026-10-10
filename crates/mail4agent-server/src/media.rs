//! Media repository for attachments. Blobs are opaque bytes: in E2E rooms
//! clients upload AES-CTR ciphertext (Matrix encrypted attachments), so the
//! server stores ciphertext only. They follow the ciphertext-pump rule: kept
//! for a TTL (see [`purge_expired`]) and then deleted. Plaintext uploads for
//! public channels use the same table and the same TTL for now; a separate
//! persistent public-media store is a named seam, not built.

use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};

/// Default largest accepted upload (and largest remote file fetched). Env: `M4A_MEDIA_MAX_BYTES`.
pub const MAX_UPLOAD_BYTES: usize = 25 * 1024 * 1024;

fn env_num(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

/// Largest upload / remote file in bytes (`M4A_MEDIA_MAX_BYTES`).
pub fn max_bytes() -> usize {
    env_num("M4A_MEDIA_MAX_BYTES", MAX_UPLOAD_BYTES as u64) as usize
}

/// Is media federation (serving peers, fetching remote media) on? Cargo feature `media-federation`
/// (default) and `M4A_MEDIA_FEDERATION` not `off`.
pub fn federation_enabled() -> bool {
    cfg!(feature = "media-federation") && std::env::var("M4A_MEDIA_FEDERATION").map(|v| v != "off").unwrap_or(true)
}

/// How long a cached remote file is kept, ms (`M4A_MEDIA_REMOTE_TTL_SECS`, default 7 days).
pub fn remote_ttl_ms() -> i64 {
    env_num("M4A_MEDIA_REMOTE_TTL_SECS", 7 * 24 * 3600) as i64 * 1000
}

/// Cap on all cached remote bytes (`M4A_MEDIA_REMOTE_CACHE_BYTES`, default 512 MiB); oldest go first.
pub fn remote_cache_cap() -> i64 {
    env_num("M4A_MEDIA_REMOTE_CACHE_BYTES", 512 * 1024 * 1024) as i64
}

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
        CREATE INDEX IF NOT EXISTS idx_media_created ON media(created_ms);
        CREATE TABLE IF NOT EXISTS media_pending (
            media_id   TEXT PRIMARY KEY,
            owner_user_id INTEGER NOT NULL,
            expires_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS remote_media (
            server       TEXT NOT NULL,
            media_id     TEXT NOT NULL,
            content_type TEXT NOT NULL,
            filename     TEXT,
            fetched_ms   INTEGER NOT NULL,
            size         INTEGER NOT NULL,
            data         BLOB NOT NULL,
            PRIMARY KEY (server, media_id)
        );",
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

/// A cached copy of another server's file, if still fresh.
pub fn get_remote(conn: &Connection, server: &str, media_id: &str, now_ms: i64) -> rusqlite::Result<Option<Blob>> {
    conn.query_row(
        "SELECT content_type, filename, data FROM remote_media WHERE server = ?1 AND media_id = ?2 AND fetched_ms > ?3",
        params![server, media_id, now_ms - remote_ttl_ms()],
        |r| Ok(Blob { content_type: r.get(0)?, filename: r.get(1)?, data: r.get(2)? }),
    )
    .optional()
}

/// Caches another server's file; drops expired copies, then the oldest while over the cap.
pub fn put_remote(conn: &Connection, server: &str, media_id: &str, blob: &Blob, now_ms: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM remote_media WHERE fetched_ms <= ?1", [now_ms - remote_ttl_ms()])?;
    conn.execute(
        "INSERT OR REPLACE INTO remote_media (server, media_id, content_type, filename, fetched_ms, size, data) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![server, media_id, blob.content_type, blob.filename, now_ms, blob.data.len() as i64, blob.data],
    )?;
    loop {
        let total: i64 = conn.query_row("SELECT COALESCE(SUM(size), 0) FROM remote_media", [], |r| r.get(0))?;
        if total <= remote_cache_cap() {
            return Ok(());
        }
        let gone = conn.execute(
            "DELETE FROM remote_media WHERE (server, media_id) = (SELECT server, media_id FROM remote_media WHERE NOT (server = ?1 AND media_id = ?2) ORDER BY fetched_ms LIMIT 1)",
            params![server, media_id],
        )?;
        if gone == 0 {
            return Ok(());
        }
    }
}

/// Reserves a media id for a later `PUT` (`POST /media/v1/create`).
pub fn create_pending(conn: &Connection, owner: i64, now_ms: i64) -> rusqlite::Result<Option<(String, i64)>> {
    conn.execute("DELETE FROM media_pending WHERE expires_ms < ?1", [now_ms])?;
    let open: i64 = conn.query_row("SELECT COUNT(*) FROM media_pending WHERE owner_user_id = ?1", [owner], |r| r.get(0))?;
    if open >= 10 {
        return Ok(None);
    }
    let mut raw = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut raw);
    let id = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw);
    let expires = now_ms + 24 * 3600 * 1000;
    conn.execute("INSERT INTO media_pending (media_id, owner_user_id, expires_ms) VALUES (?1,?2,?3)", params![id, owner, expires])?;
    Ok(Some((id, expires)))
}

/// Fills a reserved id. `Ok(false)`: not reserved by this user (or expired); `Err(Constraint)` if filled already.
pub fn put_reserved(conn: &Connection, owner: i64, media_id: &str, content_type: &str, filename: Option<&str>, data: &[u8], now_ms: i64) -> rusqlite::Result<bool> {
    let n = conn.execute("DELETE FROM media_pending WHERE media_id = ?1 AND owner_user_id = ?2 AND expires_ms >= ?3", params![media_id, owner, now_ms])?;
    if n == 0 {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO media (media_id, owner_user_id, content_type, filename, created_ms, data) VALUES (?1,?2,?3,?4,?5,?6)",
        params![media_id, owner, content_type, filename, now_ms, data],
    )?;
    Ok(true)
}

/// Is a reservation open (the id was handed out and not yet filled)?
pub fn is_pending(conn: &Connection, media_id: &str, now_ms: i64) -> bool {
    conn.query_row("SELECT 1 FROM media_pending WHERE media_id = ?1 AND expires_ms >= ?2", params![media_id, now_ms], |_| Ok(())).is_ok()
}

/// `multipart/mixed` answer of the federation media endpoints: a JSON part `{}`, then the file.
pub fn multipart_body(blob: &Blob) -> (String, Vec<u8>) {
    let mut raw = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut raw);
    let boundary: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{boundary}\r\nContent-Type: application/json\r\n\r\n{{}}\r\n--{boundary}\r\nContent-Type: {}\r\n", blob.content_type).as_bytes());
    if let Some(f) = &blob.filename {
        body.extend_from_slice(format!("Content-Disposition: attachment; filename=\"{}\"\r\n", f.replace(['"', '\\', '\r', '\n'], "_")).as_bytes());
    }
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(&blob.data);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (format!("multipart/mixed; boundary={boundary}"), body)
}

/// What the second part of a federation media answer holds.
pub enum Part {
    /// The file itself.
    Data(Blob),
    /// The file lives elsewhere: fetch it from this URL.
    Redirect(String),
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() || from > hay.len() - needle.len() {
        return None;
    }
    (from..=hay.len() - needle.len()).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Parses a `multipart/mixed` federation media answer (JSON part, then data or `Location`).
pub fn parse_multipart(content_type: &str, body: &[u8]) -> Option<Part> {
    let b = content_type.split(';').filter_map(|p| p.trim().strip_prefix("boundary=")).next()?.trim_matches('"');
    let delim = format!("--{b}").into_bytes();
    let first = find(body, &delim, 0)? + delim.len();
    let h1_end = find(body, b"\r\n\r\n", first)? + 4;
    let next = find(body, &[b"\r\n".as_slice(), &delim].concat(), h1_end)? + 2 + delim.len();
    let h2_end = find(body, b"\r\n\r\n", next)? + 4;
    let headers = std::str::from_utf8(&body[next..h2_end]).ok()?;
    let end = find(body, &[b"\r\n".as_slice(), &delim].concat(), h2_end)?;
    let mut content_type = "application/octet-stream".to_string();
    let (mut filename, mut location) = (None, None);
    for line in headers.split("\r\n") {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "content-type" if !v.is_empty() && v.len() <= 128 => content_type = v.to_string(),
            "location" => location = Some(v.to_string()),
            "content-disposition" => {
                filename = v.split(';').filter_map(|p| p.trim().strip_prefix("filename=")).next().map(|f| f.trim_matches('"').to_string());
            }
            _ => {}
        }
    }
    if let Some(l) = location {
        return Some(Part::Redirect(l));
    }
    Some(Part::Data(Blob { content_type, filename, data: body[h2_end..end].to_vec() }))
}

/// A thumbnail of an image, or `None` when it is not a decodable image (ciphertext, other files)
/// or the feature is off; callers then serve the original. Never enlarges.
#[cfg(feature = "media-thumbnails")]
pub fn thumbnail(data: &[u8], width: u32, height: u32, crop: bool) -> Option<(Vec<u8>, &'static str)> {
    use image::{ImageFormat, ImageReader};
    let reader = ImageReader::new(std::io::Cursor::new(data)).with_guessed_format().ok()?;
    let fmt = reader.format()?;
    let (w, h) = reader.into_dimensions().ok()?;
    if u64::from(w) * u64::from(h) > 40_000_000 || (w <= width && h <= height) {
        return None;
    }
    let img = image::load_from_memory_with_format(data, fmt).ok()?;
    let out = if crop { img.resize_to_fill(width, height, image::imageops::FilterType::Triangle) } else { img.resize(width, height, image::imageops::FilterType::Triangle) };
    let (format, mime) = if fmt == ImageFormat::Jpeg { (ImageFormat::Jpeg, "image/jpeg") } else { (ImageFormat::Png, "image/png") };
    let mut buf = std::io::Cursor::new(Vec::new());
    if format == ImageFormat::Jpeg { out.to_rgb8().write_to(&mut buf, format).ok()?; } else { out.write_to(&mut buf, format).ok()?; }
    Some((buf.into_inner(), mime))
}

#[cfg(not(feature = "media-thumbnails"))]
pub fn thumbnail(_data: &[u8], _width: u32, _height: u32, _crop: bool) -> Option<(Vec<u8>, &'static str)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_round_trips_and_a_location_part_is_a_redirect() {
        let blob = Blob { content_type: "text/plain".into(), filename: Some("a.txt".into()), data: b"hello\r\n--x not a boundary".to_vec() };
        let (ct, body) = multipart_body(&blob);
        let Some(Part::Data(got)) = parse_multipart(&ct, &body) else { panic!("data part") };
        assert_eq!((got.content_type.as_str(), got.filename.as_deref(), got.data), ("text/plain", Some("a.txt"), blob.data));
        let redirect = b"--B\r\nContent-Type: application/json\r\n\r\n{}\r\n--B\r\nLocation: https://cdn.example/x\r\n\r\n\r\n--B--\r\n";
        assert!(matches!(parse_multipart("multipart/mixed; boundary=B", redirect), Some(Part::Redirect(u)) if u == "https://cdn.example/x"));
        assert!(parse_multipart("multipart/mixed; boundary=B", b"junk").is_none());
    }

    #[test]
    fn remote_cache_expires_and_evicts_the_oldest_over_the_cap() {
        let c = Connection::open_in_memory().unwrap();
        create_media_schema(&c).unwrap();
        let blob = |n: usize| Blob { content_type: "a/b".into(), filename: None, data: vec![0; n] };
        std::env::set_var("M4A_MEDIA_REMOTE_CACHE_BYTES", "100");
        put_remote(&c, "s", "one", &blob(60), 1_000).unwrap();
        put_remote(&c, "s", "two", &blob(60), 2_000).unwrap();
        std::env::remove_var("M4A_MEDIA_REMOTE_CACHE_BYTES");
        assert!(get_remote(&c, "s", "one", 3_000).unwrap().is_none(), "oldest evicted");
        assert!(get_remote(&c, "s", "two", 3_000).unwrap().is_some());
        assert!(get_remote(&c, "s", "two", 2_000 + remote_ttl_ms() + 1).unwrap().is_none(), "expired");
    }

    #[cfg(feature = "media-thumbnails")]
    #[test]
    fn images_are_scaled_or_cropped_and_other_bytes_are_left_alone() {
        let img = image::RgbImage::from_fn(100, 60, |x, y| image::Rgb([x as u8, y as u8, 7]));
        let mut png = std::io::Cursor::new(Vec::new());
        img.write_to(&mut png, image::ImageFormat::Png).unwrap();
        let png = png.into_inner();
        let (bytes, mime) = thumbnail(&png, 32, 32, false).unwrap();
        let t = image::load_from_memory(&bytes).unwrap();
        assert_eq!((mime, t.width(), t.height()), ("image/png", 32, 19));
        let (bytes, _) = thumbnail(&png, 32, 32, true).unwrap();
        let t = image::load_from_memory(&bytes).unwrap();
        assert_eq!((t.width(), t.height()), (32, 32));
        assert!(thumbnail(&png, 200, 200, false).is_none(), "never enlarged");
        assert!(thumbnail(b"ciphertext, not an image", 32, 32, false).is_none());
    }

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
