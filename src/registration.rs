//! Builds the `nemo_service::manifest::ServiceManifest` mail4agent asserts
//! about itself via `PUT /registry/mail4agent` (see `crate::main`'s call to
//! `nemo_service::register::spawn`). `endpoints` is the list `crate::main`
//! recorded while building the real router via `nemo_service::router::DocRouter`
//! -- there is exactly one place a route is described. Replaces the
//! hand-written `.nemo-service.toml`, deleted in the same commit as this
//! module.

use nemo_service::manifest::{Dependencies, Endpoint, HealthInfo, Links, ServiceManifest, ServiceMeta};

/// `mail4agent/CLAUDE.md`'s own first line, plus what it deliberately does
/// not know.
const SERVICE_DESCRIPTION: &str = "A mailbox for agent sessions: addresses, messages, threads and acknowledgements, over HTTP and MCP. Knows about participants and rooms; nothing about tasks, runs or workspaces.";

/// Where an authorised caller finds a bearer for this mailbox. Unlike most
/// nemo services there is no single fixed key: every participant mints and
/// holds its OWN secret via `POST /admin/participant` (or `.../rotate`),
/// and any of them authenticates `/mail/*` and `/mcp`. This names the one
/// fixed exception -- the bootstrap operator's secret, written once on
/// first start (`crate::bootstrap`) -- which is also the only credential
/// that can mint every other participant's own secret in the first place.
const KEY_REF: &str = "~/.mail4agent/operator-key.raw (bootstrap operator only -- every other participant authenticates with its own secret, minted via POST /admin/participant)";

/// Build the manifest mail4agent asserts about itself. `endpoints` is the
/// list `crate::main` recorded while building the real router -- passed in
/// rather than rebuilt here so there is exactly one place a route is
/// described. `port` is the bind port actually in `mail4agent.toml` (or its
/// default), read back rather than hardcoded so `links.local_url` can never
/// drift from what the daemon actually bound to.
pub fn service_manifest(endpoints: Vec<Endpoint>, port: u16) -> ServiceManifest {
    ServiceManifest {
        service: ServiceMeta {
            name: "mail4agent".to_string(),
            kind: "service".to_string(),
            display_name: Some("mail4agent".to_string()),
            description: Some(SERVICE_DESCRIPTION.to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            key_ref: Some(KEY_REF.to_string()),
        },
        links: Links {
            public_url: None,
            local_url: Some(format!("http://127.0.0.1:{port}")),
            admin_url: None,
            docs: Some("mail4agent/CLAUDE.md".to_string()),
            repo: Some("mail4agent".to_string()),
        },
        endpoints,
        manage_actions: Vec::new(),
        dependencies: Dependencies { upstream: Vec::new(), downstream: vec!["gate4agent".to_string()], external: Vec::new() },
        health: Some(HealthInfo { endpoint: "/health".to_string(), expected_status: 200, interval_secs: 30 }),
    }
}
