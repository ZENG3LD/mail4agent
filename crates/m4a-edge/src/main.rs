//! `m4a-edge`: the public-facing role. Listens on loopback (a TLS proxy such as
//! Caddy sits in front), forwards to the core over the private tunnel.
//!
//! Flags: `--bind 127.0.0.1:18741`, `--core-url http://<core-wg-ip>:8741`.
//! Env: `M4A_EDGE_SECRET` (shared with the core, at least 32 characters), `M4A_CORE_URL`, `M4A_EDGE_BIND` (loopback only).

use std::net::SocketAddr;

fn main() {
    if let Err(e) = run() {
        eprintln!("m4a-edge: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut bind = std::env::var("M4A_EDGE_BIND").unwrap_or_else(|_| "127.0.0.1:18741".to_string());
    let mut core_url = std::env::var("M4A_CORE_URL").unwrap_or_default();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--bind" => bind = args.next().ok_or("--bind needs ip:port")?,
            "--core-url" => core_url = args.next().ok_or("--core-url needs a URL")?,
            _ => return Err(format!("unknown argument {a}; usage: m4a-edge --bind 127.0.0.1:18741 --core-url http://<core-wg-ip>:8741")),
        }
    }
    let secret = std::env::var("M4A_EDGE_SECRET").map_err(|_| "M4A_EDGE_SECRET is required")?;
    if secret.len() < 32 {
        return Err("M4A_EDGE_SECRET must be at least 32 characters".into());
    }
    if core_url.is_empty() {
        return Err("--core-url (or M4A_CORE_URL) is required".into());
    }
    let addr: SocketAddr = bind.parse().map_err(|_| format!("bad bind {bind}"))?;
    if !addr.ip().is_loopback() {
        return Err("the edge listens on loopback only; a TLS proxy faces the internet".into());
    }
    let app = m4a_edge::edge_router(m4a_edge::EdgeConfig { core_url, secret });
    let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let l = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("bind {addr}: {e}"))?;
        println!("m4a-edge listening {addr}");
        axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await.map_err(|e| e.to_string())
    })
}
