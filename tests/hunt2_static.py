"""Hunt phase 2A (static): deep-dive the HIGH candidate and map the hijack surface.

1. Parse srvsvc.dll WITH symbols -> real procedure names for interface 98716d03
   (and 4b324fc8 for reference), build the context-handle producer/consumer map.
2. Export client source, locate FC_BIND_CONTEXT markers per handle group.
3. For hijackable services: list static_endpoints (fixed ALPC names = squat candidates).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
S32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
SYM = "srv*" + os.path.join(tempfile.gettempdir(), "rpcmcp_symbols") + "*https://msdl.microsoft.com/download/symbols"

report: dict = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%S")}


async def call(session: ClientSession, tool: str, args: dict | None = None):
    res = await session.call_tool(tool, args or {})
    texts = [c.text for c in res.content if hasattr(c, "text")]
    try:
        return json.loads(texts[0]) if texts else {}
    except (ValueError, IndexError):
        return {}


async def main() -> int:
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(ROOT, "server.py")], cwd=ROOT)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("== A. srvsvc with symbols (network to MS symbol server) ==")
            t0 = time.time()
            pr = await call(session, "rpc_parse", {"file_path": os.path.join(S32, "srvsvc.dll"), "symbol_path": SYM})
            print(f"   parse done in {time.time()-t0:.0f}s, servers={pr.get('count')}")
            targets = {}
            for s in pr.get("servers", []):
                iid = s.get("interface_id", "")
                print(f"   - {s.get('key')}: {iid} v{s.get('version')} procs={s.get('procedure_count')} svc={s.get('service')}")
                if iid.startswith("98716d03") or iid.startswith("4b324fc8"):
                    targets[iid[:8]] = s["key"]

            deep = {}
            for tag, key in targets.items():
                gi = await call(session, "rpc_get_interface", {"server_key": key})
                procs = gi.get("procedures") or []
                ctx_map = []
                for p in procs:
                    ctx_params = [pp for pp in (p.get("params") or []) if pp.get("is_context_handle")]
                    if ctx_params:
                        ctx_map.append(
                            {
                                "proc": p.get("name"),
                                "proc_num": p.get("proc_num"),
                                "ctx": [
                                    {
                                        "param": c.get("name"),
                                        "dir": c.get("direction"),
                                        "strict": c.get("strict_context"),
                                    }
                                    for c in ctx_params
                                ],
                            }
                        )
                deep[tag] = {
                    "key": key,
                    "interface_id": gi.get("interface_id"),
                    "procs_total": gi.get("procedure_count"),
                    "ctx_procs": ctx_map,
                }
                print(f"\n   == {tag} {gi.get('interface_id')} ({gi.get('procedure_count')} procs) ==")
                for c in ctx_map:
                    desc = ", ".join(f"{x['param']}:{x['dir']}{'/strict' if x['strict'] else '/NONSTRICT'}" for x in c["ctx"])
                    print(f"   {c['proc_num']:>3} {c['proc']:<40} {desc}")

                fc = await call(session, "rpc_format_client", {"server_key": key})
                saved = fc.get("saved_to", "")
                body = fc.get("preview", "")
                if saved and os.path.isfile(saved):
                    body = open(saved, encoding="utf-8", errors="replace").read()
                binds = re.findall(r"FC_BIND_\w+|BIND_CONTEXT|CONTEXT_HANDLE", body)
                deep[tag]["format_client"] = {
                    "saved_to": saved,
                    "length": fc.get("length"),
                    "bind_markers": {m: binds.count(m) for m in set(binds)},
                }

            report["srvsvc_deep"] = deep

            print("\n== B. hijackable services: static endpoints (fixed-name squat candidates) ==")
            hj = await call(session, "rpc_find_hijackable", {"max_services": 25})
            static_eps = []
            for f in hj.get("findings", []):
                mod = f.get("module", "")
                if mod and os.path.isfile(mod):
                    pm = await call(session, "rpc_parse", {"file_path": mod})
                    for s in pm.get("servers", []):
                        for ep in s.get("static_endpoints", []):
                            if "LRPC-" not in ep:
                                static_eps.append(
                                    {
                                        "service": f.get("service"),
                                        "start": f.get("start_mode"),
                                        "interface": s.get("interface_id"),
                                        "static_endpoint": ep,
                                        "procedures": s.get("procedure_count"),
                                        "key": s.get("key"),
                                    }
                                )
            report["static_endpoints"] = static_eps
            for e in static_eps:
                print(f"   - {e['service']} ({e['start']}): {e['static_endpoint']} if={e['interface'][:13]} procs={e['procedures']}")

    report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    out = os.path.join(ROOT, "output", "hunt2_static.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=1, default=str)
    print(f"\nreport -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
