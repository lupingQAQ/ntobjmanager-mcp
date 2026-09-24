"""Hunt phase 2B (wide scan): sweep 51 known RPC-hosting modules, flag non-strict
multi-handle interfaces, then dump details of every HIGH candidate for UUID identification."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LIST = os.path.join(tempfile.gettempdir(), "rpcmcp_scan_list.txt")

report: dict = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%S")}


async def call(session: ClientSession, tool: str, args: dict | None = None):
    res = await session.call_tool(tool, args or {})
    texts = [c.text for c in res.content if hasattr(c, "text")]
    try:
        return json.loads(texts[0]) if texts else {}
    except (ValueError, IndexError):
        return {}


async def main() -> int:
    files = [ln.strip() for ln in open(LIST) if ln.strip()]
    print(f"scanning {len(files)} files")
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(ROOT, "server.py")], cwd=ROOT)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            t0 = time.time()
            sc = await call(session, "rpc_scan_context_handles", {"paths": files})
            print(f"scan done in {time.time()-t0:.0f}s findings={sc.get('finding_count')} errors={len(sc.get('errors', []))}")
            report["scan_summary"] = {k: sc.get(k) for k in ("files_scanned", "finding_count", "errors")}
            highs = [f for f in (sc.get("findings") or []) if "HIGH" in str(f.get("verdict", ""))]
            print(f"HIGH candidates: {len(highs)}")
            details = []
            for f in highs:
                d = dict(f)
                pr = await call(session, "rpc_parse", {"file_path": f["file"]})
                match = [s for s in pr.get("servers", []) if s.get("interface_id") == f["interface_id"]]
                if match:
                    gi = await call(session, "rpc_get_interface", {"server_key": match[0]["key"]})
                    procs = []
                    for p in gi.get("procedures", []):
                        ctx = [pp for pp in (p.get("params") or []) if pp.get("is_context_handle")]
                        if ctx:
                            procs.append(
                                {
                                    "proc": p.get("name"),
                                    "num": p.get("proc_num"),
                                    "ctx": [f"{c.get('name')}:{c.get('direction')}{'/S' if c.get('strict_context') else '/N'}" for c in ctx],
                                    "other_params": [
                                        f"{pp.get('name')}:{pp.get('ndr_type')}" for pp in (p.get("params") or []) if not pp.get("is_context_handle")
                                    ][:6],
                                }
                            )
                    d["detail_key"] = match[0]["key"]
                    d["service"] = gi.get("service")
                    d["ctx_procs"] = procs
                details.append(d)
                print(f"\n== {os.path.basename(f['file'])} {f['interface_id']} svc={d.get('service')} ==")
                for p in d.get("ctx_procs", []):
                    print(f"   {p['num']:>3} {p['proc']:<36} {', '.join(p['ctx'])}  others={p['other_params'][:3]}")
            report["high_details"] = details

    out = os.path.join(ROOT, "output", "hunt2_wide.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=1, default=str)
    print(f"\nreport -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
