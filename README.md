# mcp-secret-scrub

> `mcp-name: io.github.sudo-ai-git/mcp-secret-scrub`

**Deterministic, no-LLM MCP server that scrubs secrets from text, logs, and
transcripts before they enter agent context — and never leaks the value.**

No LLM. No network. Pure structural detection. MIT. Crown-jewel-free.

---

## The problem it solves

Before you hand raw text to an agent (or store it, or pass it to a tool), you
often don't know whether it contains a live secret. Platform scrubbers miss
patterns all the time — a private key, an `nvapi-` token, a `github_pat_`
token, an `api_key=` assignment mid-log. If that text reaches an LLM context
or a persisted transcript, the secret is effectively exfiltrated.

This server answers, deterministically:
> *Which secrets are in this text, and can you redact them safely before it
> goes anywhere?*

## Detection coverage (deterministic profiles)

| family | examples |
|---|---|
| **AI provider keys** | `sk-proj-…`, `sk-ant-api…`, `sk-or-v1-…`, `sk-…`, `nvapi-…` |
| **Cloud / GitHub** | `AKIA…`, `aws_secret_access_key=`, `ghp_…`, `gho_…`, `ghu_…`, `ghs_…`, `ghr_…`, `github_pat_…` |
| **Identity / auth** | JWTs (`eyJ…`), PEM private keys, `Bearer …`, `Basic …`, OAuth client secrets |
| **Assignments** | `api_key=`, `token=`, `secret=`, `password=`, `client_secret=`, `webhook_secret=` |
| **Endpoints / DSNs** | Discord webhooks, Slack `xox…`, SQL/Redis/Mongo/AMQP connection strings |

The scan **never returns the secret value** — only its type, count, and
position. That is a hard safety contract, enforced by test.

## Tools (MCP)

| tool | purpose |
|---|---|
| `scrub_text(text, mode, keep_label)` | redact / mask / hash secrets; returns scrubbed text (never the value) |
| `scan_text(text)` | detect which secret types are present (no mutation) |
| `report_full(text)` | scan + redact in one call, scrubbed preview + findings |
| `secret_profiles()` | list all supported detection profiles |

Modes:
- **`redact`** (default) → `[REDACTED:TYPE]`
- **`mask`** → shows first 4 + last 2 chars
- **`hash`** → deterministic SHA-256 prefix (reproducible across calls)

## Quick start (stdio)

```bash
pip install mcp-secret-scrub
mcp-secret-scrub          # stdio (default)
```

Or via uv/pipx for an installable console entry:
```bash
pipx install mcp-secret-scrub
```

MCP client config:
```json
{ "mcpServers": {
    "secret-scrub": { "command": "mcp-secret-scrub" }
}}
```

## Streamable HTTP (remote / Smithery-publishable)

```bash
python3 mcp_server.py --http --port 8138   # serves on http://<host>:8138/mcp/
```

## Determinism & safety guarantees

- **Deterministic**: same input → identical output in every mode, every call.
- **Never leaks**: `scan_text` and `scrub_text` never emit the original token;
  `_deterministic_hash` is SHA-256 (no salt) so output is reproducible.
- **No LLM, no network**: pure regex + reachable structure detection.
- **Input-safe**: non-string input returns a clean error, not a traceback.

## Verification

- `python3 test_detector.py` — 14/14 core checks (detection, redaction,
  determinism, no-leak contract, benign/unicode/empty input, bad-mode)
- `python3 test_e2e.py` — drives the real MCP stdio transport and asserts
  the secret does NOT cross the wire

## License & provenance

MIT. Part of the sudo-ai-git deterministic no-LLM agent-trust MCP family
(`mcp-skill-sec` · `mcp-verify-claim` · `mcp-benchmark-hygiene` ·
`mcp-secret-scrub`).
