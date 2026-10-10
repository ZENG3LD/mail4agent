//! The media repository's client routes: upload (direct, or reserve-then-PUT), download,
//! thumbnails, config, a URL-preview stub, in the legacy `/media/v3` and the authenticated
//! `/client/v1/media` (spec v1.11) forms. Files of other servers are fetched through the
//! federation media endpoints (`media-federation` feature, `M4A_MEDIA_FEDERATION=off` to disable)
//! and cached with a TTL and a size cap; see [`crate::media`] for the knobs.
//!
//! Uploads are opaque bytes: ciphertext attachments of E2E rooms are never interpreted. The
//! thumbnailer only acts when the bytes decode as an image, so ciphertext falls through to the
//! original. `preview_url` answers `{}` on purpose: the server never fetches arbitrary URLs for a
//! client (SSRF); a deployment that wants previews puts a preview service in front.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::{json, Value};

use super::{resolve_caller, with_conn_pub, Homeserver};
use crate::error::MatrixError;
use crate::media::{self, Blob, Part};

pub(super) fn routes() -> Router<Arc<Homeserver>> {
    let uploads = Router::new()
        .route("/media/v3/upload", post(upload))
        .route("/media/v3/upload/{server}/{media_id}", put(upload_reserved))
        .layer(DefaultBodyLimit::max(media::max_bytes()));
    Router::new()
        .route("/media/v1/create", post(create))
        .route("/media/v3/config", get(config))
        .route("/client/v1/media/config", get(config))
        .route("/media/v3/download/{server}/{media_id}", get(download))
        .route("/media/v3/download/{server}/{media_id}/{filename}", get(download_named))
        .route("/client/v1/media/download/{server}/{media_id}", get(download))
        .route("/client/v1/media/download/{server}/{media_id}/{filename}", get(download_named))
        .route("/media/v3/thumbnail/{server}/{media_id}", get(thumbnail))
        .route("/client/v1/media/thumbnail/{server}/{media_id}", get(thumbnail))
        .route("/media/v3/preview_url", get(preview))
        .route("/client/v1/media/preview_url", get(preview))
        .merge(uploads)
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

async fn config(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Ok(Json(json!({ "m.upload.size": media::max_bytes() })))
}

async fn preview(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Ok(Json(json!({})))
}

#[derive(serde::Deserialize)]
struct UploadQuery {
    filename: Option<String>,
}

fn content_type_of(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 128)
        .unwrap_or("application/octet-stream")
        .to_string()
}

fn too_large() -> MatrixError {
    MatrixError::new(413, "M_TOO_LARGE", "upload exceeds the size limit")
}

async fn upload(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Query(q): Query<UploadQuery>, body: Bytes) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    state.check_policy(&caller, crate::policy::Action::UploadMedia, None)?;
    if body.is_empty() {
        return Err(MatrixError::invalid_param("empty upload"));
    }
    if body.len() > media::max_bytes() {
        return Err(too_large());
    }
    let content_type = content_type_of(&headers);
    let id = with_conn_pub(&state, move |conn| Ok(media::put(conn, caller.user_id, &content_type, q.filename.as_deref(), &body, now_ms())?)).await?;
    Ok(Json(json!({ "content_uri": format!("mxc://{}/{}", crate::store::matrix_server_name(), id) })))
}

/// `POST /media/v1/create`: hand out an `mxc` URI now, accept the bytes later.
async fn create(State(state): State<Arc<Homeserver>>, headers: HeaderMap) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    state.check_policy(&caller, crate::policy::Action::UploadMedia, None)?;
    let made = with_conn_pub(&state, move |conn| Ok(media::create_pending(conn, caller.user_id, now_ms())?)).await?;
    let (id, expires) = made.ok_or_else(|| MatrixError::limit_exceeded(60_000))?;
    Ok(Json(json!({ "content_uri": format!("mxc://{}/{}", crate::store::matrix_server_name(), id), "unused_expires_at": expires })))
}

async fn upload_reserved(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path((server, media_id)): Path<(String, String)>, Query(q): Query<UploadQuery>, body: Bytes) -> Result<Json<Value>, MatrixError> {
    let caller = resolve_caller(&state, &headers, None).await?;
    if !crate::store::is_local_server_name(&server) {
        return Err(MatrixError::not_found("media is not local"));
    }
    if body.is_empty() {
        return Err(MatrixError::invalid_param("empty upload"));
    }
    if body.len() > media::max_bytes() {
        return Err(too_large());
    }
    let content_type = content_type_of(&headers);
    let r = with_conn_pub(&state, move |conn| {
        match media::put_reserved(conn, caller.user_id, &media_id, &content_type, q.filename.as_deref(), &body, now_ms()) {
            Ok(true) => Ok(()),
            Ok(false) => Err(MatrixError::forbidden("this media id was not reserved by you, or the reservation expired")),
            Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == rusqlite::ErrorCode::ConstraintViolation => Err(MatrixError::new(409, "M_CANNOT_OVERWRITE_MEDIA", "that media already has content")),
            Err(e) => Err(e.into()),
        }
    })
    .await;
    r.map(|()| Json(json!({})))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A local blob, or a remote one from cache / the origin server.
async fn resolve_blob(state: &Arc<Homeserver>, server: &str, media_id: &str) -> Result<Blob, MatrixError> {
    if !valid_id(media_id) {
        return Err(MatrixError::not_found("no such media"));
    }
    if crate::store::is_local_server_name(server) {
        let id = media_id.to_string();
        let now = now_ms();
        if let Some(b) = with_conn_pub(state, {
            let id = id.clone();
            move |conn| Ok(media::get(conn, &id)?)
        })
        .await?
        {
            return Ok(b);
        }
        let pending = with_conn_pub(state, move |conn| Ok(media::is_pending(conn, &id, now))).await?;
        return Err(if pending { MatrixError::new(504, "M_NOT_YET_UPLOADED", "the content has not been uploaded yet") } else { MatrixError::not_found("no such media") });
    }
    if !media::federation_enabled() {
        return Err(MatrixError::not_found("media of other servers is not served here"));
    }
    if server.len() > 255 || !server.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']')) {
        return Err(MatrixError::not_found("no such media"));
    }
    let (s, i) = (server.to_string(), media_id.to_string());
    if let Some(b) = with_conn_pub(state, move |conn| Ok(media::get_remote(conn, &s, &i, now_ms())?)).await? {
        return Ok(b);
    }
    let blob = fetch_remote(state, server, media_id).await?;
    let (s, i) = (server.to_string(), media_id.to_string());
    let copy = Blob { content_type: blob.content_type.clone(), filename: blob.filename.clone(), data: blob.data.clone() };
    with_conn_pub(state, move |conn| Ok(media::put_remote(conn, &s, &i, &copy, now_ms())?)).await?;
    Ok(blob)
}

/// Fetches one file from `server` over federation (`GET /federation/v1/media/download`).
async fn fetch_remote(state: &Arc<Homeserver>, server: &str, media_id: &str) -> Result<Blob, MatrixError> {
    let max = media::max_bytes();
    let resp = super::fed_net::fed_request_raw(state, server, &format!("/federation/v1/media/download/{}?timeout_ms=20000", crate::federation::enc(media_id)), max + 64 * 1024).await.map_err(|_| MatrixError::not_found("that server's media could not be fetched"))?;
    if resp.status == 404 {
        return Err(MatrixError::not_found("the origin server does not have that media"));
    }
    if resp.status != 200 {
        return Err(MatrixError::unknown(format!("{server} answered {} for that media", resp.status)));
    }
    let ct = resp.content_type.unwrap_or_default();
    let bad = || MatrixError::unknown("the origin server's media answer is malformed");
    let blob = match media::parse_multipart(&ct, &resp.body).ok_or_else(bad)? {
        Part::Data(b) => b,
        Part::Redirect(url) => follow_redirect(&url, max).await?,
    };
    if blob.data.len() > max {
        return Err(MatrixError::new(502, "M_TOO_LARGE", "the remote file exceeds the size limit"));
    }
    Ok(blob)
}

/// A media answer may point at a CDN. Only https, and never an address on a private network.
async fn follow_redirect(url: &str, max: usize) -> Result<Blob, MatrixError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| MatrixError::unknown("bad media redirect"))?;
    let allow_http = std::env::var("M4A_MEDIA_REDIRECT_INSECURE").map(|v| v == "1").unwrap_or(false);
    if parsed.scheme() != "https" && !(allow_http && parsed.scheme() == "http") {
        return Err(MatrixError::unknown("the media redirect is not https"));
    }
    let host = parsed.host_str().unwrap_or_default().to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    if !allow_http {
        let addrs = tokio::net::lookup_host((host.as_str(), port)).await.map_err(|_| MatrixError::unknown("media redirect host does not resolve"))?;
        for a in addrs {
            let ip = a.ip();
            let private = match ip {
                std::net::IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast(),
                std::net::IpAddr::V6(v) => v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
            };
            if private {
                return Err(MatrixError::unknown("the media redirect points into a private network"));
            }
        }
    }
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(30)).build().map_err(|_| MatrixError::internal())?;
    let mut resp = client.get(parsed).send().await.map_err(|_| MatrixError::unknown("could not fetch the media redirect"))?;
    if !resp.status().is_success() {
        return Err(MatrixError::unknown("the media redirect did not serve the file"));
    }
    let content_type = resp.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).filter(|v| v.len() <= 128).unwrap_or("application/octet-stream").to_string();
    let mut data = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| MatrixError::unknown("media redirect broke off"))? {
        if data.len() + chunk.len() > max {
            return Err(MatrixError::new(502, "M_TOO_LARGE", "the remote file exceeds the size limit"));
        }
        data.extend_from_slice(&chunk);
    }
    Ok(Blob { content_type, filename: None, data })
}

fn respond(blob: Blob, name: Option<String>, content_type: Option<&str>, data: Option<Vec<u8>>) -> Response {
    let mut resp = (StatusCode::OK, data.unwrap_or(blob.data)).into_response();
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(content_type.unwrap_or(&blob.content_type)) {
        h.insert(header::CONTENT_TYPE, v);
    }
    // Always a download, never inline-rendered by the browser; nosniff.
    let fname = name.or(blob.filename).unwrap_or_else(|| "file".into()).replace(['"', '\\', '\r', '\n'], "_");
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{fname}\"")) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("sandbox; default-src 'none'"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("cross-origin"));
    resp
}

async fn download(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path((server, media_id)): Path<(String, String)>) -> Result<Response, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Ok(respond(resolve_blob(&state, &server, &media_id).await?, None, None, None))
}

async fn download_named(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path((server, media_id, name)): Path<(String, String, String)>) -> Result<Response, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    Ok(respond(resolve_blob(&state, &server, &media_id).await?, Some(name), None, None))
}

async fn thumbnail(State(state): State<Arc<Homeserver>>, headers: HeaderMap, Path((server, media_id)): Path<(String, String)>, Query(q): Query<HashMap<String, String>>) -> Result<Response, MatrixError> {
    resolve_caller(&state, &headers, None).await?;
    let num = |k: &str| q.get(k).and_then(|v| v.parse::<u32>().ok()).filter(|n| (1..=2048).contains(n));
    let (Some(w), Some(h)) = (num("width"), num("height")) else { return Err(MatrixError::invalid_param("width and height are required (1..2048)")) };
    let crop = match q.get("method").map(String::as_str) {
        None | Some("scale") => false,
        Some("crop") => true,
        Some(_) => return Err(MatrixError::invalid_param("method must be crop or scale")),
    };
    let blob = resolve_blob(&state, &server, &media_id).await?;
    let data = blob.data.clone();
    let thumb = tokio::task::spawn_blocking(move || media::thumbnail(&data, w, h, crop)).await.ok().flatten();
    Ok(match thumb {
        Some((bytes, mime)) => respond(blob, None, Some(mime), Some(bytes)),
        None => respond(blob, None, None, None),
    })
}
