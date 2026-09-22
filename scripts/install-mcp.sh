#!/usr/bin/env bash
# Register the running mail4agent daemon as an MCP server in each agent CLI's
# config. Idempotent: re-running replaces the mail4agent entry in place.
#
# Each CLI carries its own per-client bearer token — mail4agent attests the
# caller from the connection, the token only names the account. A fresh token
# per client is generated here unless one is supplied.
#
# Usage:
#   scripts/install-mcp.sh [--url URL] [--clients claude,codex,grok,kimi]
# Env overrides for the token of each client (else a random 32-byte hex is made):
#   M4A_TOKEN_CLAUDE  M4A_TOKEN_CODEX  M4A_TOKEN_GROK  M4A_TOKEN_KIMI
set -euo pipefail

URL="${M4A_URL:-http://127.0.0.1:18301/mcp}"
CLIENTS="claude,codex,grok,kimi"
while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --clients) CLIENTS="$2"; shift 2 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

gen_token() { openssl rand -hex 32 2>/dev/null || python -c "import secrets;print(secrets.token_hex(32))"; }

python="$(command -v python3 || command -v python)"
[ -n "$python" ] || { echo "python required (JSON/TOML edits)" >&2; exit 1; }

# python helper: idempotent upsert of one MCP entry into a JSON or TOML config.
upsert() { "$python" - "$@" <<'PY'
import json, sys, os, re
kind, path, url, token = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
os.makedirs(os.path.dirname(path), exist_ok=True)

if kind == "json-claude":
    # ~/.claude.json: mcpServers live under a per-project or top block; we edit
    # the first object that already has "mcpServers", else the top level.
    doc = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
    def find(d):
        if isinstance(d, dict):
            if "mcpServers" in d and isinstance(d["mcpServers"], dict): return d["mcpServers"]
            for v in d.values():
                r = find(v)
                if r is not None: return r
        return None
    servers = find(doc)
    if servers is None:
        servers = doc.setdefault("mcpServers", {})
    servers["mail4agent"] = {"type":"http","url":url,"headers":{"Authorization":f"Bearer {token}"}}
    json.dump(doc, open(path,"w",encoding="utf-8"), indent=2, ensure_ascii=False)

elif kind == "json-kimi":
    doc = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
    servers = doc.setdefault("mcpServers", doc.get("mcpServers") or {})
    servers["mail4agent"] = {"type":"http","url":url,"headers":{"Authorization":f"Bearer {token}"}}
    json.dump(doc, open(path,"w",encoding="utf-8"), indent=2, ensure_ascii=False)

elif kind in ("toml-grok","toml-codex"):
    txt = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
    # strip any existing mail4agent tables (header + its body up to next table/EOF)
    txt = re.sub(r'(?ms)^\[mcp_servers\.mail4agent(?:\.[^\]]+)?\]\s*\n(?:(?!^\[).*\n?)*', '', txt)
    txt = txt.rstrip() + "\n\n"
    if kind == "toml-grok":
        txt += ("[mcp_servers.mail4agent]\n"
                f'url = "{url}"\nenabled = true\n\n'
                "[mcp_servers.mail4agent.headers]\n"
                f'Authorization = "Bearer {token}"\n')
    else:  # codex reads the token from an env var, not the file
        txt += ("[mcp_servers.mail4agent]\n"
                f'url = "{url}"\n'
                'bearer_token_env_var = "MAIL4AGENT_CODEX_TOKEN"\nenabled = true\n')
    open(path,"w",encoding="utf-8").write(txt)
print(f"  {kind:12s} {path}")
PY
}

IFS=',' read -ra list <<< "$CLIENTS"
for c in "${list[@]}"; do
  case "$c" in
    claude) t="${M4A_TOKEN_CLAUDE:-$(gen_token)}"; upsert json-claude "$HOME/.claude.json" "$URL" "$t" ;;
    kimi)   t="${M4A_TOKEN_KIMI:-$(gen_token)}";   upsert json-kimi   "$HOME/.kimi-code/mcp.json" "$URL" "$t" ;;
    grok)   t="${M4A_TOKEN_GROK:-$(gen_token)}";   upsert toml-grok   "$HOME/.grok/config.toml" "$URL" "$t" ;;
    codex)  t="${M4A_TOKEN_CODEX:-$(gen_token)}";  upsert toml-codex  "$HOME/.codex/config.toml" "$URL" "$t"
            echo "  codex: set env MAIL4AGENT_CODEX_TOKEN=$t (its config reads the token from there)" ;;
    *) echo "unknown client: $c" >&2; exit 2 ;;
  esac
done

echo "mail4agent registered at $URL. Each client must have a participant with the matching token (admin/participant)."
