"""End-to-end smoke test: launches server.py over stdio as a real MCP client
and exercises the tool surface (read-only + wiring; no live rpc_call payloads)."""

from __future__ import annotations

import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TARGET_DLL = r"C:\Windows\System32\ssdpsrv.dll"  # CVE-2025-48815 target

PASS, FAIL = 0, 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    mark = "PASS" if cond else "FAIL"
    if cond:
        PASS += 1
    else:
        FAIL += 1
    print(f"[{mark}] {name}" + (f"  -> {detail[:200]}" if detail and not cond else ""))


async def call_json(session: ClientSession, name: str, args: dict | None = None):
    res = await session.call_tool(name, args or {})
    texts = [c.text for c in res.content if hasattr(c, "text")]
    try:
        return json.loads(texts[0]) if texts else {}
    except (ValueError, IndexError):
        return {"_raw": texts[0] if texts else ""}


async def main() -> int:
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(ROOT, "server.py")], cwd=ROOT)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            names = {t.name for t in tools.tools}
            print("tools:", len(names))
            check("tool count >= 14", len(names) >= 14, f"got {len(names)}")

            # 1. parse
            r = await call_json(session, "rpc_parse", {"file_path": TARGET_DLL})
            check("rpc_parse ok", r.get("ok") is True or ("servers" in r), json.dumps(r)[:200])
            servers = r.get("servers", [])
            check("rpc_parse found ssdpsrv interface", len(servers) >= 1, json.dumps(r)[:200])
            key = servers[0]["key"] if servers else ""
            ifid = servers[0].get("interface_id", "") if servers else ""

            # 2. state
            r2 = await call_json(session, "rpc_state")
            check("rpc_state lists cached server", any(s.get("key") == key for s in r2.get("servers", [])), json.dumps(r2)[:200])

            # 3. get_interface
            r3 = await call_json(session, "rpc_get_interface", {"server_key": key})
            check("rpc_get_interface procedures", r3.get("procedure_count", 0) >= 10, json.dumps(r3)[:200])
            ctx_params = [
                p
                for proc in r3.get("procedures", [])
                for p in proc.get("params", [])
                if p.get("is_context_handle")
            ]
            check("rpc_get_interface sees context handles", len(ctx_params) > 0, f"ctx={len(ctx_params)}")

            # 4. query endpoints (global, limited)
            r4 = await call_json(session, "rpc_query_endpoints", {"limit": 10})
            check("rpc_query_endpoints returns entries", r4.get("total", 0) > 0, json.dumps(r4)[:200])

            # 5. EPM filter by interface id
            if ifid:
                r4b = await call_json(session, "rpc_query_endpoints", {"interface_id": ifid, "limit": 10})
                check("rpc_query_endpoints filtered call clean", r4b.get("ok", True) or "error" in r4b, json.dumps(r4b)[:200])

            # 6. context-handle methodology scan
            r6 = await call_json(session, "rpc_scan_context_handles", {"paths": [TARGET_DLL]})
            check("rpc_scan_context_handles finds ssdpsrv ctx surface", r6.get("finding_count", 0) >= 1, json.dumps(r6)[:300])
            if r6.get("findings"):
                f0 = r6["findings"][0]
                check("scan reports non-strict/producer data", ("non_strict_count" in f0 and "producer_procs" in f0), json.dumps(f0)[:200])

            # 7. decode flags
            r7 = await call_json(session, "rpc_decode_flags", {"flags": 145})  # 0x91
            setflags = [f["flag"] for f in r7.get("flags", []) if f["set"]]
            check("rpc_decode_flags 0x91", "RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH" in "".join(setflags), json.dumps(r7)[:200])

            # 8. connect wiring (expect success OR clean structured error; SSDPSRV often stopped)
            r8 = await call_json(session, "rpc_connect", {"session": "s1", "server_key": key})
            connected = r8.get("session") == "s1" or r8.get("ok", False)
            check("rpc_connect responds (connect or clean error)", "error" in r8 or connected, json.dumps(r8)[:300])
            if "error" in r8:
                print("      connect error (acceptable if service stopped):", str(r8["error"])[:140])

            # 9. methods + bogus call prove invocation plumbing without touching real RPC
            if "error" not in r8:
                r9 = await call_json(session, "rpc_methods", {"session": "s1"})
                check("rpc_methods lists methods", r9.get("count", 0) > 0, json.dumps(r9)[:200])
                r10 = await call_json(session, "rpc_call", {"session": "s1", "method": "DefinitelyNotAMethod"})
                check("rpc_call bogus method -> structured error", "error" in r10 and "method not found" in str(r10.get("error", "")), json.dumps(r10)[:200])
                r11 = await call_json(session, "rpc_disconnect", {"session": "s1"})
                check("rpc_disconnect", r11.get("disconnected") == "s1", json.dumps(r11)[:200])
            else:
                r10 = await call_json(session, "rpc_call", {"session": "nonexistent", "method": "x"})
                check("rpc_call unknown session -> structured error", "error" in r10, json.dumps(r10)[:200])

            # 10. interface security (best-effort fields)
            r12 = await call_json(session, "rpc_interface_security", {"server_key": key})
            check("rpc_interface_security responds", "interface_id" in r12 or "error" in r12, json.dumps(r12)[:200])

            # 11. running servers wiring (own PID should be parseable, maybe 0 servers)
            r13 = await call_json(session, "rpc_running_servers", {"process_id": os.getpid()})
            check("rpc_running_servers clean", "servers" in r13 or "error" in r13, json.dumps(r13)[:200])

    print(f"\n== {PASS} passed, {FAIL} failed ==")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
