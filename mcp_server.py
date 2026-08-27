#!/usr/bin/env python3
"""mcp-secret-scrub — deterministic, no-LLM MCP server that scrubs secrets
from arbitrary text/logs/transcripts before they enter agent context.

The agent-trust family (skill-sec / verify-claim / benchmark-hygiene /
secret-scrub) all share one contract: deterministic, verifiable, no LLM.
This server answers: "before I hand this text to an agent (or store it),
which secrets are in it, and can you redact them safely?"

No network. No LLM. Pure regex + structure detection. MIT. Crown-jewel-free.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Secret detection profiles
# ---------------------------------------------------------------------------
# Each entry: (label, compiled regex, has_group_to_keep)
# The regex captures the FULL secret. Some patterns need a key token kept
# (e.g. `aws_access_key_id=` -> keep the label, scrub the value).
_PROFILES: List[Tuple[str, str, bool]] = [
    # --- cloud provider keys ---
    ("AWS_ACCESS_KEY_ID", r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b", False),
    ("AWS_SECRET", r"(?:aws_secret_access_key|secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*\S+", True),
    # --- GitHub ---
    ("GITHUB_PAT", r"\bghp_[A-Za-z0-9]{36}\b", False),
    ("GITHUB_OAUTH", r"\bgho_[A-Za-z0-9]{36}\b", False),
    ("GITHUB_USER_TOKEN", r"\bghu_[A-Za-z0-9]{36}\b", False),
    ("GITHUB_APP_TOKEN", r"\bghs_[A-Za-z0-9]{36}\b", False),
    ("GITHUB_FINE_GRAINED", r"\bgithub_pat_[A-Za-z0-9_]{80,}\b", False),
    ("GITHUB_REFRESH", r"\bghr_[A-Za-z0-9]{36}\b", False),
    # --- AI provider keys ---
    ("OPENAI_KEY", r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b", False),       # legacy sk-proj has this marker
    ("OPENAI_PROJECT_KEY", r"\bsk-proj-[A-Za-z0-9_\-]{30,}\b", False),
    ("ANTHROPIC_KEY", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", False),
    ("OPENROUTER_KEY", r"\bsk-or-v1-[A-Za-z0-9_\-]{30,}\b", False),
    ("DEEPSEEK_KEY", r"\bsk-[A-Za-z0-9]{20,}\b", False),
    ("GENERIC_LLM_KEY", r"\bsk-[A-Za-z0-9]{25,}\b", False),
    ("NVIDIA_NIM", r"\bnvapi-[A-Za-z0-9_\-]{20,}\b", False),
    ("ANTHROPIC_CONSOLE", r"\b[A-Za-z0-9]{40}(?::[A-Za-z0-9]{40})\b", False),        # anthropic console key
    ("MISTRAL_KEY", r"\b[A-Za-z0-9]{32,}\.[A-Za-z0-9]{32,}\b", False),              # mistral sk-.internal
    # --- identity / auth ---
    ("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", False),
    ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", False),
    ("BEARER_TOKEN", r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b", False),
    ("BASIC_AUTH", r"\bBasic\s+[A-Za-z0-9+/]+={0,2}\b", False),
    # --- explicit assignments (keep label) ---
    ("API_KEY_ASSIGN", r"\b(?:api[_-]?key|apikey|API_?KEY|token|TOKEN|secret|SECRET|password|PASSWORD|passwd|client_secret|webhook_secret)\b\s*[=:]?\s*[\'\"`]?\s*([A-Za-z0-9_\-\.]{16,})\b", True),
    ("WEBHOOK_URL", r"https://discord(?:app)?\.com/api/webhooks/[A-Za-z0-9_\-]+/[A-Za-z0-9_\-]+", False),
    ("SLACK_LEGACY_TOKEN", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b", False),
    ("CONNECTION_STRING", r"\b(?:mongodb(?:\+srv)?://|postgres(?:ql)?://|mysql://|redis://|amqp://)[^\s>\"']+", False),
    # --- Firebase / project ids that decode to secrets ---
    ("GCP_SA_KEY", r"-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----", False),
]

# High-entropy generic token detector (as a fallback label, low priority to
# avoid false positives on normal opaque identifiers)
_HIGH_ENTROPY = re.compile(r"[\w\-]{32,}")


@dataclass
class Profile:
    label: str
    rx: re.Pattern
    keep_label: bool


def _build_profiles() -> List[Profile]:
    out = []
    for label, pat, keep in _PROFILES:
        try:
            out.append(Profile(label, re.compile(pat), keep))
        except re.error:
            # A malformed pattern is a hard failure — never silently drop a
            # security check.
            raise ValueError(f"secret-scrub: malformed pattern for {label}")
    return out


_PROFILE_LIST = _build_profiles()


def _deterministic_hash(token: str, length: int = 16) -> str:
    """Deterministic, non-reversible replacement digest (sha256, no salt —
    collision-gated by length; attacker with the original can re-derive, but
    that's expected for scrubbing that must stay reproducible)."""
    return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()[:length]


# ---------------------------------------------------------------------------
# Core API (deterministic, no LLM)
# ---------------------------------------------------------------------------

def scan_text(text: str) -> Dict[str, object]:
    """Detect secrets present in `text`. Returns per-type counts + the list of
    types found. NEVER returns the secret value itself.
    """
    if not isinstance(text, str):
        return {"ok": False, "error": "input must be a string", "findings": [], "total": 0}
    findings: List[Dict[str, object]] = []
    seen: List[str] = []
    for prof in _PROFILE_LIST:
        m = prof.rx.search(text)
        if m:
            token = m.group(1) if prof.keep_label and m.lastindex else m.group(0)
            # dedupe identical token strings across profiles (JWT vs Bearer)
            if token in seen:
                continue
            seen.append(token)
            findings.append({
                "type": prof.label,
                "count": len(prof.rx.findall(text)),
                "pos": m.start(),
                "token_length": len(token),
            })
    return {"ok": True, "findings": findings, "total": len(findings), "types": [f["type"] for f in findings]}


def scrub_text(text: str, mode: str = "redact", keep_label: bool = False) -> Dict[str, object]:
    """Scrub secrets from `text`. mode: redact | mask | hash.
    Returns scrubbed text + a report of what was removed (type + count, never
    the value). keep_label retains the surrounding key (`api_key=***`).
    """
    mode = mode.lower()
    if mode not in ("redact", "mask", "hash"):
        return {"ok": False, "error": f"unknown mode '{mode}' (use redact|mask|hash)", "scrubbed": text, "types_scrubbed": []}
    if not isinstance(text, str):
        return {"ok": False, "error": "input must be a string", "scrubbed": None, "types_scrubbed": []}

    scrubbed = text
    replaced_types: List[str] = []
    for prof in _PROFILE_LIST:
        if not prof.rx.search(text):
            continue
        def _repl(match: re.Match, _p=prof, _mode=mode) -> str:
            token = match.group(1) if _p.keep_label and match.lastindex else match.group(0)
            if _mode == "redact":
                r = f"[REDACTED:{_p.label}]"
            elif _mode == "mask":
                r = token[:4] + "…" + token[-2:] if len(token) > 8 else "[REDACTED…]"
            else:  # hash
                r = f"[HASH:{_deterministic_hash(token)}]"
            if _p.keep_label and match.lastindex:
                return match.group(0).replace(token, r)
            return r
        scrubbed = prof.rx.sub(_repl, scrubbed)
        replaced_types.append(prof.label)
    return {
        "ok": True,
        "scrubbed": scrubbed,
        "types_scrubbed": sorted(set(replaced_types)),
        "count": len(replaced_types),
        "mode": mode,
    }


def report_full(text: str) -> Dict[str, object]:
    """scan + scrub summary in one call. Safe default: redact mode."""
    scan = scan_text(text)
    scrub = scrub_text(text, "redact", keep_label=True)
    return {
        "ok": True,
        "scan": scan,
        "scrubbed": scrub["scrubbed"],
        "types": scan["types"],
        "count": scan["total"],
        "advice": "Found secrets above; use scrub before logging/storing/agent-context injection.",
        "preview_scrubbed": scrub["scrubbed"][:400],
    }


# ---------------------------------------------------------------------------
# MCP server wiring — FastMCP (matches the proven skill-sec / verify-claim /
# benchmark-hygiene family; auto-builds proper Tool objects for stdio + HTTP).
# ---------------------------------------------------------------------------
try:
    from mcp.server.fastmcp import FastMCP
except Exception:
    FastMCP = None


def _register_tools(mcp) -> None:
    """Register the four MCP tools on a FastMCP instance (shared stdio + HTTP).
    Wrappers call the _impl cores below, not themselves (no recursion)."""

    @mcp.tool()
    def scrub_text(text: str, mode: str = "redact", keep_label: bool = True) -> Dict[str, object]:
        """Detect and redact/mask/hash secrets in text before it enters agent
        context or logs. Returns scrubbed text — never the secret value."""
        return _scrub_text_impl(text, mode, keep_label)

    @mcp.tool()
    def scan_text(text: str) -> Dict[str, object]:
        """Detect which secret types are present in text WITHOUT modifying it.
        Returns types + counts, never the values."""
        return _scan_text_impl(text)

    @mcp.tool()
    def report_full(text: str) -> Dict[str, object]:
        """scan + redact in one call: scrubbed preview + findings report."""
        return _report_full_impl(text)

    @mcp.tool()
    def secret_profiles() -> Dict[str, object]:
        """List all supported secret detection profiles (type labels)."""
        return {"ok": True, "profiles": [p.label for p in _PROFILE_LIST]}


def build_app():
    """Build the FastMCP app with tools registered (shared by stdio + HTTP)."""
    if FastMCP is None:
        raise RuntimeError("mcp package not installed ('pip install mcp')")
    mcp = FastMCP("mcp-secret-scrub")
    _register_tools(mcp)
    return mcp


def _main() -> None:
    """Console-script entry point (also used by `python3 mcp_server.py`)."""
    import argparse
    p = argparse.ArgumentParser(description="mcp-secret-scrub MCP server")
    p.add_argument("--http", action="store_true",
                   help="serve over Streamable HTTP (default: stdio)")
    p.add_argument("--host", default="0.0.0.0", help="HTTP bind host")
    p.add_argument("--port", type=int, default=8138, help="HTTP port")
    args = p.parse_args()

    mcp = build_app()
    if args.http:
        import uvicorn
        app = mcp.streamable_http_app()
        print(f"[mcp-secret-scrub] serving Streamable HTTP on {args.host}:{args.port}", flush=True)
        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    else:
        mcp.run()  # stdio (default)


# ── renames: MCP tool wrappers shadow module fns; impls live under _impl
_scan_text_impl = scan_text
_scrub_text_impl = scrub_text
_report_full_impl = report_full

main_entry = _main  # console-script entry point


if __name__ == "__main__":
    _main()

