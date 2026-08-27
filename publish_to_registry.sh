#!/usr/bin/env bash
# Publish mcp-secret-scrub: PyPI upload + Official MCP Registry.
# USAGE: ./publish_to_registry.sh <pypi-api-token>
# Registry publish (step 3) MUST be: login github --token <PAT> && publish in ONE command
# (mcp-publisher issues a 5-minute JWT — a stale token 401s).
set -euo pipefail
TOKEN="${1:?Usage: $0 <pypi-api-token>}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="$TOKEN"

echo "==> 1/3 Building package..."
cd "$ROOT"
rm -rf dist build *.egg-info
python3 -m build

echo "==> 2/3 Uploading sdist+wheel to PyPI..."
python3 -m twine upload dist/*

echo "==> 3/3 Registry (run IMMEDIATELY after a fresh login):"
echo "       mcp-publisher login github --token <PAT>"
echo "       mcp-publisher publish server.json"
echo "  Verify: GET https://registry.modelcontextprotocol.io/v0.1/servers/io.github.sudo-ai-git%2Fmcp-secret-scrub/versions/1.0.0"
