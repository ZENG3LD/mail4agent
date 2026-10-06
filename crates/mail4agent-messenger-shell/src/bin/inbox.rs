//! `m4a-inbox`: the hook side of the provider wake chains.
//!
//! Runs inside the provider session (as a hook or by the agent). The local
//! client queues letters into the session inbox; this command registers
//! the session and hands letters to the session in the vendor's hook
//! format.
//!
//! ```text
//! m4a-inbox register [--provider P] [--session ID] [--nick N] [--cwd DIR]
//!                    [--headless] [--pid N] [--arm FORMAT]... [--hook-stdin]
//! m4a-inbox wait  --format claude-rewake [--session ID] [--hook-stdin] [--timeout SECS]
//! m4a-inbox drain --format claude-stop|codex-stop|kimi-stop|cursor-stop|grok-stop|text
//!                 [--session ID] [--hook-stdin]
//! m4a-inbox unregister [--session ID] [--hook-stdin]
//! m4a-inbox hooks --provider P      # prints the hook config to install
//! ```
//!
//! `--hook-stdin` reads the hook's JSON payload (`session_id`,
//! `conversation_id`, `thread_id`, `cwd`). Inbox: `M4A_INBOX_DIR`, else
//! `<M4A_STORE_ROOT>/inbox/<session>`. Exit codes follow the hook
//! contract of the chosen format (2 = wake / continue with stderr).

use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use mail4agent_messenger_shell::provider::chain::{detect_provider, detect_session_id};
use mail4agent_messenger_shell::provider::hook::HookFlavor;
use mail4agent_messenger_shell::provider::{inbox, registry};
use mail4agent_messenger_shell::{
    load_env_file_named, nick_from_display_name, ProviderKind, SessionRecord, INBOX_DIR_ENV,
    STORE_ROOT_ENV,
};

#[derive(Default)]
struct Args {
    command: String,
    provider: Option<String>,
    session: Option<String>,
    nick: Option<String>,
    cwd: Option<PathBuf>,
    headless: bool,
    pid: Option<u32>,
    arm: Vec<String>,
    hook_stdin: bool,
    format: Option<String>,
    timeout: Option<u64>,
}

fn parse() -> Args {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    args.command = it.next().unwrap_or_default();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--provider" => args.provider = it.next(),
            "--session" => args.session = it.next(),
            "--nick" => args.nick = it.next(),
            "--cwd" => args.cwd = it.next().map(PathBuf::from),
            "--headless" => args.headless = true,
            "--pid" => args.pid = it.next().and_then(|v| v.parse().ok()),
            "--arm" => args.arm.extend(it.next()),
            "--hook-stdin" => args.hook_stdin = true,
            "--format" => args.format = it.next(),
            "--timeout" => args.timeout = it.next().and_then(|v| v.parse().ok()),
            other => fail(&format!("unknown argument {other}")),
        }
    }
    args
}

fn fail(msg: &str) -> ! {
    eprintln!("m4a-inbox: {msg}");
    std::process::exit(64);
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

struct Ctx {
    provider: Option<ProviderKind>,
    session: String,
    cwd: Option<PathBuf>,
    store_root: Option<PathBuf>,
    inbox: PathBuf,
    title: Option<String>,
}

fn context(args: &Args) -> Ctx {
    let payload: serde_json::Value = if args.hook_stdin {
        let mut text = String::new();
        let _ = std::io::stdin().read_to_string(&mut text);
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
    } else {
        serde_json::Value::Null
    };
    let provider = args
        .provider
        .as_deref()
        .map(|p| ProviderKind::parse(p).unwrap_or_else(|| fail("unknown provider")))
        .or_else(|| detect_provider(env));
    let session = args
        .session
        .clone()
        .or_else(|| {
            ["session_id", "conversation_id", "thread_id", "sessionId"]
                .iter()
                .find_map(|key| payload[*key].as_str().map(str::to_string))
        })
        .or_else(|| provider.and_then(|p| detect_session_id(p, env)))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| fail("no session id (use --session or --hook-stdin)"));
    let cwd = args
        .cwd
        .clone()
        .or_else(|| payload["cwd"].as_str().map(PathBuf::from))
        .or_else(|| payload["workspace_roots"][0].as_str().map(PathBuf::from))
        .or_else(|| std::env::current_dir().ok());
    let store_root = env(STORE_ROOT_ENV).map(PathBuf::from);
    let inbox = env(INBOX_DIR_ENV)
        .map(PathBuf::from)
        .or_else(|| {
            store_root
                .as_deref()
                .map(|root| registry::inbox_dir(root, &session))
        })
        .unwrap_or_else(|| fail("set M4A_STORE_ROOT or M4A_INBOX_DIR"));
    let title = payload["session_title"].as_str().map(str::to_string);
    Ctx {
        provider,
        session,
        cwd,
        store_root,
        inbox,
        title,
    }
}

fn flavor(args: &Args) -> Option<HookFlavor> {
    let format = args
        .format
        .as_deref()
        .unwrap_or_else(|| fail("--format is required"));
    if format == "text" {
        return None;
    }
    Some(HookFlavor::parse(format).unwrap_or_else(|| fail("unknown --format")))
}

fn emit(flavor: Option<HookFlavor>, prompts: &[String]) -> ! {
    match flavor {
        None => {
            for prompt in prompts {
                println!("{prompt}\n");
            }
            std::process::exit(0);
        }
        Some(flavor) => match flavor.render(prompts) {
            None => std::process::exit(0),
            Some((out, err, code)) => {
                if !out.is_empty() {
                    println!("{out}");
                }
                if !err.is_empty() {
                    eprintln!("{err}");
                }
                std::process::exit(code);
            }
        },
    }
}

fn main() {
    load_env_file_named("node-client.env");
    let args = parse();
    match args.command.as_str() {
        "register" => {
            let ctx = context(&args);
            let provider = ctx
                .provider
                .unwrap_or_else(|| fail("no provider (use --provider or M4A_PROVIDER)"));
            let root = ctx
                .store_root
                .clone()
                .unwrap_or_else(|| fail("M4A_STORE_ROOT is required"));
            let nick = args
                .nick
                .clone()
                .or_else(|| env("M4A_NICK"))
                .or_else(|| {
                    ctx.title
                        .as_deref()
                        .and_then(|t| nick_from_display_name(t).ok())
                })
                .or_else(|| {
                    ctx.cwd
                        .as_deref()
                        .and_then(|cwd| cwd.file_name())
                        .and_then(|name| nick_from_display_name(&name.to_string_lossy()).ok())
                })
                .unwrap_or_else(|| fail("no nick (use --nick or M4A_NICK)"));
            let record = SessionRecord {
                provider: provider.id().to_string(),
                surface: if env("CLAUDE_CODE_REMOTE").is_some() {
                    "web"
                } else {
                    "local"
                }
                .to_string(),
                session_id: ctx.session.clone(),
                nick,
                cwd: ctx.cwd.clone(),
                headless: args.headless,
                pid: args.pid,
            };
            if let Err(err) = registry::register(&root, &record) {
                fail(&format!("register: {}", err.kind()));
            }
            for format in &args.arm {
                let flavor =
                    HookFlavor::parse(format).unwrap_or_else(|| fail("unknown --arm format"));
                if let Err(err) = inbox::arm(&ctx.inbox, &flavor.consumer()) {
                    fail(&err.to_string());
                }
            }
        }
        "unregister" => {
            let ctx = context(&args);
            if let Some(root) = ctx.store_root.as_deref() {
                registry::unregister(root, &ctx.session);
            }
            for flavor in HookFlavor::ALL {
                inbox::disarm(&ctx.inbox, &flavor.consumer());
            }
        }
        "drain" => {
            let ctx = context(&args);
            let flavor = flavor(&args);
            if let Some(flavor) = flavor.filter(|f| !f.wakes_idle()) {
                let _ = inbox::arm(&ctx.inbox, &flavor.consumer());
            }
            let prompts: Vec<String> = inbox::drain(&ctx.inbox)
                .into_iter()
                .map(|e| e.letter.prompt)
                .collect();
            emit(flavor, &prompts);
        }
        "wait" => {
            let ctx = context(&args);
            let flavor = flavor(&args).unwrap_or(HookFlavor::ClaudeRewake);
            let name = flavor.consumer();
            // One waiter per session: a second asyncRewake run leaves.
            if inbox::is_live(&ctx.inbox, &name) {
                std::process::exit(0);
            }
            let presence = inbox::Presence::announce(&ctx.inbox, &name)
                .unwrap_or_else(|err| fail(&err.to_string()));
            let deadline = args
                .timeout
                .map(|s| Instant::now() + Duration::from_secs(s));
            let mut beat = Instant::now();
            loop {
                if inbox::pending(&ctx.inbox) > 0 {
                    let prompts: Vec<String> = inbox::drain(&ctx.inbox)
                        .into_iter()
                        .map(|e| e.letter.prompt)
                        .collect();
                    if !prompts.is_empty() {
                        drop(presence);
                        emit(Some(flavor), &prompts);
                    }
                }
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    drop(presence);
                    std::process::exit(0);
                }
                if beat.elapsed() >= inbox::HEARTBEAT {
                    presence.beat();
                    beat = Instant::now();
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        "hooks" => {
            let provider = args
                .provider
                .as_deref()
                .and_then(ProviderKind::parse)
                .unwrap_or_else(|| fail("--provider is required"));
            println!("{}", hook_config(provider));
        }
        _ => fail("usage: m4a-inbox register|unregister|drain|wait|hooks ..."),
    }
}

/// Hook config to install for `provider` (no secrets, no paths beyond the
/// command name; `M4A_STORE_ROOT` comes from `node-client.env`).
fn hook_config(provider: ProviderKind) -> String {
    let p = provider.id();
    let value = match provider {
        ProviderKind::ClaudeCode => serde_json::json!({"hooks": {
            "SessionStart": [{"hooks": [{"type": "command", "command": format!("m4a-inbox register --provider {p} --hook-stdin --arm claude-stop")}]}],
            "Stop": [{"hooks": [
                {"type": "command", "command": "m4a-inbox drain --format claude-stop --hook-stdin"},
                {"type": "command", "command": "m4a-inbox wait --format claude-rewake --hook-stdin", "asyncRewake": true, "timeout": 86400}
            ]}],
            "SessionEnd": [{"hooks": [{"type": "command", "command": "m4a-inbox unregister --hook-stdin"}]}]
        }}),
        ProviderKind::Codex => serde_json::json!({"hooks": {
            "SessionStart": [{"hooks": [{"type": "command", "command": format!("m4a-inbox register --provider {p} --hook-stdin --arm codex-stop")}]}],
            "Stop": [{"hooks": [{"type": "command", "command": "m4a-inbox drain --format codex-stop --hook-stdin"}]}]
        }}),
        ProviderKind::Cursor => serde_json::json!({"version": 1, "hooks": {
            "sessionStart": [{"command": format!("m4a-inbox register --provider {p} --hook-stdin --arm cursor-stop")}],
            "stop": [{"command": "m4a-inbox drain --format cursor-stop --hook-stdin"}]
        }}),
        ProviderKind::KimiCode => {
            return "# ~/.kimi-code/config.toml\n[[hooks]]\nevent = \"SessionStart\"\ncommand = \"m4a-inbox register --provider kimi --hook-stdin --arm kimi-stop\"\n\n[[hooks]]\nevent = \"Stop\"\ncommand = \"m4a-inbox drain --format kimi-stop --hook-stdin\"\n".to_string();
        }
        ProviderKind::Grok => serde_json::json!({"hooks": {
            "Stop": [{"hooks": [{"type": "command", "command": "m4a-inbox drain --format grok-stop --hook-stdin"}]}]
        }}),
    };
    serde_json::to_string_pretty(&value).unwrap_or_default()
}
