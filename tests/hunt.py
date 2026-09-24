"""Hunting round: use the MCP itself (real stdio client) to survey local RPC attack surface.

SAFE-ONLY policy on this machine: enumeration, parsing, EPM cross-checks, dry-run plans,
one known-harmless live call target (ssdpsrv Proc0 context-handle open, proven stable).
No rpc_fuzz execution, no blind method invocation, no alpc squatting against real services.
Output: output/hunt_report.json + console summary + list of MCP defects observed.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
S32 = r"C:\Windows\System32"

CANDIDATE_DLLS = [
    "efssvc.dll", "ssdpsrv.dll", "winhttp.dll", "schedsvc.dll", "srvsvc.dll",
    "wkssvc.dll", "dhcpcsvc.dll", "dhcpcsvc6.dll", "rasmans.dll", "dnsapi.dll",
    "mpssvc.dll", "cryptsvc.dll? no",
]
CANDIDATE_DLLS = [d.strip() for d in CANDIDATE_DLLS if "?" not in d]

report: dict = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
defects: list[str] = []


def defect(msg: str) -> None:
    defects.append(msg)
    print("MCP-DEFECT:", msg)


async def call(session: ClientSession, tool: str, args: dict | None = None):
    res = await session.call_tool(tool, args or {})
    texts = [c.text for c in res.content if hasattr(c, "text")]
    try:
        return json.loads(texts[0]) if texts else {}
    except (ValueError, IndexError):
        defect(f"tool {tool} returned unparseable output: {(texts[0] if texts else '')[:120]!r}")
        return {}


async def main() -> int:
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(ROOT, "server.py")], cwd=ROOT)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            print("== 1. hijackable services (EPM poisoning surface) ==")
            t0 = time.time()
            hj = await call(session, "rpc_find_hijackable", {"max_services": 25})
            report["hijackable"] = hj
            print(f"   candidates={hj.get('non_running_candidates')} modules={hj.get('modules_checked')} "
                  f"hijackable={hj.get('hijackable_services')} ({time.time()-t0:.0f}s)")
            for f in (hj.get("findings") or [])[:8]:
                ifaces = ", ".join(i.get("interface_id", "")[:13] for i in (f.get("unregistered_interfaces") or [])[:3])
                print(f"   - {f.get('service')}: {f.get('start_mode')}/{f.get('delayed')} via {f.get('via')} ifaces[{ifaces}]")

            print("== 2. context-handle type-confusion candidates ==")
            paths = [os.path.join(S32, d) for d in CANDIDATE_DLLS]
            existing = [p for p in paths if os.path.isfile(p)]
            print(f"   scanning {len(existing)} files")
            sc = await call(session, "rpc_scan_context_handles", {"paths": existing})
            report["context_handle_scan"] = sc
            print(f"   findings={sc.get('finding_count')} errors={len(sc.get('errors', []))}")
            for f in (sc.get("findings") or [])[:10]:
                print(f"   - {os.path.basename(f.get('file',''))} {f.get('interface_id','')[:13]} svc={f.get('service')} "
                      f"ctx={f.get('ctx_param_count')} non_strict={f.get('non_strict_count')} groups={len(f.get('distinct_groups', {}))} [{f.get('verdict')}]")

            print("== 3. inventory slice (parse + EPM cross-check) ==")
            inv = await call(session, "rpc_inventory", {"paths": existing[:8], "limit": 8})
            report["inventory"] = {k: inv.get(k) for k in ("files", "interfaces", "epm_registered", "epm_unregistered_or_unknown", "saved_to")}
            print(f"   {inv.get('interfaces')} interfaces, {inv.get('epm_registered')} EPM-registered -> {inv.get('saved_to')}")

            print("== 4. accessible scheduled tasks (Dark Elevator chain) ==")
            tk = await call(session, "rpc_accessible_tasks", {})
            report["accessible_tasks"] = tk
            print(f"   count={tk.get('count')}")
            for t in (tk.get("tasks") or [])[:6]:
                print(f"   - {t}")

            print("== 5. ETW unreachable-client probe (expected: needs admin) ==")
            etw = await call(session, "rpc_etw_unreachable", {"duration_sec": 4, "trigger_script": "gpupdate /force"})
            report["etw"] = {k: etw.get(k) for k in ("admin", "hit_count", "events_scanned", "error", "hint")}
            print(f"   admin={etw.get('admin')} error={str(etw.get('error'))[:90]!r}")

            print("== 6. deep dive: safest live interface (ssdpsrv, CVE-2025-48815 pattern) ==")
            deep: dict = {}
            pr = await call(session, "rpc_parse", {"file_path": os.path.join(S32, "ssdpsrv.dll")})
            key = (pr.get("servers") or [{}])[0].get("key", "")
            deep["parse"] = {"key": key, "ifid": (pr.get("servers") or [{}])[0].get("interface_id")}
            gi = await call(session, "rpc_get_interface", {"server_key": key})
            ctx_procs = [p for p in (gi.get("procedures") or []) if any(pp.get("is_context_handle") for pp in (p.get("params") or []))]
            deep["ctx_procedures"] = [p.get("name") for p in ctx_procs][:15]
            print(f"   ctx-handle procs: {deep['ctx_procedures'][:8]}")
            cn = await call(session, "rpc_connect", {"session": "hunt1", "server_key": key})
            if "error" not in cn:
                mm = await call(session, "rpc_methods", {"session": "hunt1"})
                mapped = sum(1 for m in (mm.get("methods") or []) if m.get("opnum") is not None)
                deep["methods"] = {"count": mm.get("count"), "opnum_mapped": mapped}
                fz = await call(session, "rpc_fuzz", {"session": "hunt1", "dry_run": True, "max_procs": 30})
                deep["fuzz_plan"] = {"planned": fz.get("planned"), "primitive_only": sum(1 for p in (fz.get("plan") or []) if p.get("primitive_only"))}
                st = await call(session, "rpc_call", {"session": "hunt1", "method": "Proc0", "args_json": "[]", "store_as": "h1"})
                deep["proc0"] = {"stored_as": st.get("stored_as"), "handle": st.get("result")}
                vv = await call(session, "rpc_vars", {"session": "hunt1"})
                deep["vars"] = vv.get("vars")
                await call(session, "rpc_disconnect", {"session": "hunt1"})
                print(f"   methods={deep['methods']} fuzz_plan={deep['fuzz_plan']}")
                print(f"   Proc0 handle: {str(st.get('result'))[:100]}")
            else:
                defect(f"connect to previously-working ssdpsrv failed: {str(cn.get('error'))[:120]}")
            report["deep_dive"] = deep

    report["mcp_defects_observed"] = defects
    report["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    out = os.path.join(ROOT, "output", "hunt_report.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=1, default=str)
    print(f"\nreport -> {out}")
    print("defects:", len(defects))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
