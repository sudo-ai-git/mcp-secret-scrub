#!/usr/bin/env python3
"""E2E test: drive the real mcp-secret-scrub stdio server through an MCP
client, assert secrets scrub end-to-end over the wire, and confirm the leaked
values never appear in tool output."""
import asyncio, json, os, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def main():
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        print("SKIP: mcp package not installed")
        return 0

    server_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcp_server.py")
    params = StdioServerParameters(command=sys.executable, args=[server_path])

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print("tools:", names)
            assert set(["scrub_text", "scan_text", "report_full", "secret_profiles"]).issubset(names), names

            # scrub over the wire
            secret = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl123456"
            res = await session.call_tool("scrub_text", {"text": f"leak={secret} other", "mode": "redact"})
            out = ""
            for c in res.content:
                out += getattr(c, "text", "")
            print("scrub result:", out[:120])
            assert secret not in out, "SECRET LEAKED over wire!"
            assert "REDACTED" in out

            # scan over the wire
            res = await session.call_tool("scan_text", {"text": f"x {secret} y"})
            out = "".join(getattr(c, "text", "") for c in res.content)
            data = json.loads(out)
            assert data["ok"] and data["total"] >= 1, data
            assert "sk-proj" not in out, "scan leaked value"
            print("scan ok, types:", data["types"])

            # profiles
            res = await session.call_tool("secret_profiles", {})
            out = "".join(getattr(c, "text", "") for c in res.content)
            print("profiles:", json.loads(out)["ok"])
    print("E2E PASS")
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
