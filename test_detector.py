#!/usr/bin/env python3
"""Test suite for mcp-secret-scrub determinism + safety contract."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcp_server as m

# ---------------------------------------------------------------------------
# 1. Detection (scan_text) — must find, never leak
# ---------------------------------------------------------------------------
def test_scan_finds_types():
    t = "openai key sk-proj-abcdef1234567890abcdef1234567890GHIJKL and AWS AKIAABCDEFGHIJKLMNOP"
    r = m.scan_text(t)
    assert r["ok"] and r["total"] >= 2, r
    types = r["types"]
    assert "OPENAI_PROJECT_KEY" in types, types
    assert "AWS_ACCESS_KEY_ID" in types, types
    # safety contract: the token value must NOT appear in the scan output
    assert "sk-proj" not in json_dump(r), "scan leaked secret!"

def test_never_leak_value_in_scan():
    secret = "sk-ant-api03-abcdefghijkl1234567890abcdefghijkl"
    r = m.scan_text(f"key={secret}")
    dump = json_dump(r)
    assert secret not in dump, "scan leaked the raw secret"

# ---------------------------------------------------------------------------
# 2. Scrubbing (scrub_text) — redacts, position-correct, deterministic
# ---------------------------------------------------------------------------
def test_redact_removes_secret():
    sec = "sk-proj-abcdef1234567890abcdef1234567890ABC"
    t = f"my key is {sec} and more text"
    r = m.scrub_text(t, "redact")
    assert r["ok"]
    assert sec not in r["scrubbed"], "secret survived redaction"
    assert "[REDACTED:OPENAI_PROJECT_KEY]" in r["scrubbed"], r["scrubbed"]
    assert r["types_scrubbed"] and "OPENAI_PROJECT_KEY" in r["types_scrubbed"], r

def test_mask_shows_edges_only():
    sec = "sk-abcdefghijkl1234567890"
    r = m.scrub_text(f"x {sec} y", "mask")
    assert sec not in r["scrubbed"]
    # masked form shows only 4-char head
    assert "sk-a" in r["scrubbed"]

def test_hash_is_deterministic():
    sec = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
    a = m.scrub_text(f"{sec}", "hash")
    b = m.scrub_text(f"{sec}", "hash")
    assert a["scrubbed"] == b["scrubbed"], "hash mode must be deterministic"
    assert "ghp_" not in a["scrubbed"]

def test_keep_label_preserves_key_name():
    t = "api_key=sk-proj-1234567890abcdef1234567890abcdef"
    r = m.scrub_text(t, "redact", keep_label=True)
    assert "api_key=" in r["scrubbed"], "label should be kept"
    assert "sk-proj" not in r["scrubbed"], "value must be scrubbed even with label"

# ---------------------------------------------------------------------------
# 3. Private keys / PEM / multi-line — must fully redact
# ---------------------------------------------------------------------------
def test_private_key_block_redacted():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAfake\n-----END RSA PRIVATE KEY-----"
    r = m.scrub_text(f"before {pem} after")
    assert "BEGIN RSA PRIVATE KEY" not in r["scrubbed"]
    assert "MIIEow" not in r["scrubbed"]
    assert "before" in r["scrubbed"] and "after" in r["scrubbed"]

def test_jwt_redacted():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    r = m.scrub_text(f"token={jwt}")
    assert jwt not in r["scrubbed"]

# ---------------------------------------------------------------------------
# 4. No false positives on benign text / empty / unicode
# ---------------------------------------------------------------------------
def test_benign_text_unchanged():
    t = "The quick brown fox jumps over the lazy dog. normal_identifier_plain_text."
    r = m.scrub_text(t, "redact")
    # a short normal sentence should be unchanged (no 16+ char key-like tokens)
    assert r["scrubbed"] == t, r["scrubbed"]

def test_empty_string():
    assert m.scrub_text("")["scrubbed"] == ""
    assert m.scan_text("")["ok"] and m.scan_text("")["total"] == 0

def test_unicode():
    t = "héllo wörld — some 日本語 text with no secrets"
    r = m.scrub_text(t, "redact")
    assert r["scrubbed"] == t

def test_report_full_contract():
    t = "here is a key sk-ant-abcdefghij1234567890"
    r = m.report_full(t)
    assert r["ok"]
    assert "sk-ant" not in r["scrubbed"]
    assert "scan" in r and "advice" in r

# ---------------------------------------------------------------------------
# 5. Input validation
# ---------------------------------------------------------------------------
def test_non_string_input():
    r = m.scrub_text(None if False else 12345)  # int input
    assert r["ok"] is False or r["scrubbed"] is not None

def test_bad_mode():
    r = m.scrub_text("x", "bogus")
    assert r["ok"] is False

def json_dump(obj):
    import json
    return json.dumps(obj)

if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
            passed += 1
        except Exception as e:
            print(f"FAIL {fn.__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
