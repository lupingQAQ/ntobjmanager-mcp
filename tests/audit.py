"""Audit suite: hunt bugs, gaps and rough edges in the NtObjectManager MCP.

Sections:
  A. protocol/schema shape        E. state persistence stress
  B. input-validation errors      F. concurrency (engine lock)
  C. hostile path escaping        G. argument marshaling edge cases
  D. non-PE / empty-RPC handling  H. live: find_hijackable, etw, security
  I. engine timeout robustness (direct, isolated instance)
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TARGET_DLL = r"C:\Windows\System32\ssdpsrv.dll"

FINDINGS: list[str] = []


def note(msg: str) -> None:
    FINDINGS.append(msg)
    print("FINDING:", msg)


def check(name: str, cond: bool, detail: str = "") -> bool:
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"  detail: {detail[:250]}" if not cond else ""))
    return cond


async def call(session: ClientSession, tool: str, args: dict | None = None):
    res = await session.call_tool(tool, args or {})
    texts = [c.text for c in res.content if hasattr(c, "text")]
    try:
        return json.loads(texts[0]) if texts else {}
    except (ValueError, IndexError):
        return {"_raw": texts[0] if texts else "", "_unparseable": True}


async def section_a(session: ClientSession) -> None:
    print("\n=== A. protocol/schema ===")
    tools = await session.list_tools()
    names = sorted(t.name for t in tools.tools)
    check("22 tools present", len(names) == 22, f"got {len(names)}: {names}")
    bad_schema = [t.name for t in tools.tools if not (getattr(t, "input_schema", None) or getattr(t, "inputSchema", None))]
    check("every tool has inputSchema", not bad_schema, str(bad_schema))
    no_desc = [t.name for t in tools.tools if not (t.description or "").strip()]
    check("every tool has description", not no_desc, str(no_desc))


async def section_b(session: ClientSession) -> None:
    print("\n=== B. input-validation errors ===")
    r = await call(session, "rpc_parse", {"file_path": r"C:\no\such\file.dll"})
    check("parse missing file -> clean error", r.get("ok") is False and "not found" in str(r.get("error", "")), json.dumps(r))
    r = await call(session, "rpc_get_interface", {"server_key": "nope_9"})
    check("get_interface bad key -> error", "error" in r and "rpc_state" in str(r.get("error", "")), json.dumps(r))
    r = await call(session, "rpc_connect", {"session": "x", "server_key": "nope_9"})
    check("connect bad key -> error", "error" in r, json.dumps(r))
    r = await call(session, "rpc_methods", {"session": "ghost"})
    check("methods bad session -> error", "error" in r, json.dumps(r))
    r = await call(session, "rpc_call", {"session": "ghost", "method": "m"})
    check("call bad session -> error", "error" in r, json.dumps(r))
    r = await call(session, "rpc_call", {"session": "s", "method": "m", "args_json": "{not json"})
    check("call invalid args_json -> python-side error", r.get("ok") is False, json.dumps(r))
    r = await call(session, "rpc_call", {"session": "s", "method": "m", "args_json": '{"a":1}'})
    check("call non-array args_json rejected", r.get("ok") is False, json.dumps(r))
    r = await call(session, "rpc_query_endpoints", {"find_alpc_port": True})
    check("endpoints find_alpc w/o ifid -> error", r.get("ok") is False, json.dumps(r))
    r = await call(session, "rpc_query_endpoints", {"interface_id": "not-a-guid"})
    check("endpoints bad guid -> structured error", "error" in r, json.dumps(r))
    r = await call(session, "rpc_etw_unreachable", {"duration_sec": 0})
    check("etw duration 0 rejected", r.get("ok") is False, json.dumps(r))
    r = await call(session, "rpc_etw_unreachable", {"duration_sec": 999})
    check("etw duration 999 rejected", r.get("ok") is False, json.dumps(r))
    r = await call(session, "rpc_scan_context_handles", {"paths": []})
    check("scan empty paths -> error", r.get("ok") is False, json.dumps(r))
    r = await call(session, "rpc_running_servers", {})
    check("running_servers no args -> error", r.get("ok") is False, json.dumps(r))


async def section_c(session: ClientSession, tmpdir: str) -> str:
    print("\n=== C. hostile path escaping ===")
    hostile = os.path.join(tmpdir, "o'brien `tick` 中文 拷贝.dll")
    shutil.copy(TARGET_DLL, hostile)
    r = await call(session, "rpc_parse", {"file_path": hostile})
    ok = r.get("count", 0) >= 1 or r.get("ok") is True
    check("parse hostile filename (quote/space/unicode)", ok, json.dumps(r)[:300])
    if not ok and "_unparseable" in r:
        note(f"hostile filename breaks protocol output: {json.dumps(r)[:200]}")
    return r.get("servers", [{}])[0].get("key", "h0") if r.get("servers") else "h0"


async def section_d(session: ClientSession, tmpdir: str) -> None:
    print("\n=== D. non-PE / empty-RPC handling ===")
    txt = os.path.join(tmpdir, "plain.txt")
    with open(txt, "w") as f:
        f.write("MZ not really a PE" * 100)
    r = await call(session, "rpc_parse", {"file_path": txt})
    check("parse non-PE -> structured error", ("error" in r) or r.get("count", -1) == 0, json.dumps(r)[:250])
    if r.get("_unparseable"):
        note(f"non-PE file produced unparseable output (wrapper protocol leak): {r.get('_raw','')[:150]}")
    # a real DLL with no RPC servers: gdiplus? use notepad.exe copy
    np = os.path.join(tmpdir, "notepad.exe")
    shutil.copy(r"C:\Windows\System32\notepad.exe", np)
    r = await call(session, "rpc_parse", {"file_path": np})
    check("parse no-RPC PE -> count 0 or clean", r.get("count", -1) == 0 or "error" in r, json.dumps(r)[:200])


async def section_e(session: ClientSession, key: str) -> None:
    print("\n=== E. state persistence stress ===")
    r = await call(session, "rpc_connect", {"session": "audit1", "server_key": key})
    if "error" in r:
        print("      connect failed (service state dependent):", str(r.get("error"))[:120], "- stress via methods skipped")
        return
    alive = True
    for i in range(5):
        s1 = await call(session, "rpc_state")
        s2 = await call(session, "rpc_methods", {"session": "audit1"})
        s3 = await call(session, "rpc_query_endpoints", {"limit": 3})
        if not any(s.get("session") == "audit1" for s in s1.get("sessions", [])) or s2.get("count", 0) == 0:
            alive = False
            print(f"      round {i}: state={json.dumps(s1)[:150]} methods={json.dumps(s2)[:150]}")
            break
    check("session survives 5 interleaved call rounds", alive)
    bogus = await call(session, "rpc_call", {"session": "audit1", "method": "ZzNope", "args_json": '[1,"a",true,{"__ps__":"2+2"}]'})
    check("call w/ __ps__ escape + bogus method -> structured error", "method not found" in str(bogus.get("error", "")), json.dumps(bogus)[:250])
    still = await call(session, "rpc_methods", {"session": "audit1"})
    check("session survives failed call", still.get("count", 0) > 0, json.dumps(still)[:150])
    d = await call(session, "rpc_disconnect", {"session": "audit1"})
    check("disconnect audit1", d.get("disconnected") == "audit1", json.dumps(d))


async def section_f(session: ClientSession) -> None:
    print("\n=== F. concurrency ===")

    async def one(i: int):
        return await call(session, "rpc_state")

    results = await asyncio.gather(*[one(i) for i in range(6)], return_exceptions=True)
    bad = [r for r in results if isinstance(r, Exception) or r.get("_unparseable")]
    check("6 parallel rpc_state all clean", not bad, str(bad)[:200])


async def section_g(session: ClientSession, key: str) -> None:
    print("\n=== G. arg marshaling ===")
    r = await call(session, "rpc_connect", {"session": "g1", "server_key": key})
    if "error" in r:
        print("      (connect unavailable, skipping G live checks)")
        return
    m = await call(session, "rpc_methods", {"session": "g1"})
    zero_arg = None
    two_arg = None
    for meth in m.get("methods", []):
        n = len(meth.get("params", []))
        if n == 0 and zero_arg is None:
            zero_arg = meth["name"]
        if n >= 2 and two_arg is None:
            two_arg = meth["name"]
    if zero_arg:
        rr = await call(session, "rpc_call", {"session": "g1", "method": zero_arg, "args_json": "[]"})
        check(f"call 0-arg method {zero_arg} -> structured (live RPC)", "error" in rr or "result" in rr, json.dumps(rr)[:250])
        if "error" not in rr:
            print("      zero-arg call result_type:", rr.get("result_type"), "result:", str(rr.get("result"))[:120])
    else:
        print("      no 0-arg method found (skipped)")
    if two_arg:
        rr = await call(session, "rpc_call", {"session": "g1", "method": two_arg, "args_json": "[]"})
        check(f"call {two_arg} with WRONG arg count -> structured error", "error" in rr, json.dumps(rr)[:250])
        if rr.get("_unparseable"):
            note(f"wrong-arg-count response broke JSON protocol: {rr.get('_raw','')[:150]}")
    rr = await call(session, "rpc_call", {"session": "g1", "method": "ZzNope", "args_json": '[{"__ps__":"$null"}]'})
    check("null __ps__ arg tolerated", "error" in rr, json.dumps(rr)[:200])
    await call(session, "rpc_disconnect", {"session": "g1"})


async def section_h(session: ClientSession, key: str) -> None:
    print("\n=== H. live: untested tools ===")
    r = await call(session, "rpc_find_hijackable", {"max_services": 5})
    check("find_hijackable runs clean", r.get("ok") is True and "modules_checked" in r, json.dumps(r)[:300])
    print("      hijackable summary:", {k: r.get(k) for k in ("non_running_candidates", "modules_checked", "hijackable_services")})
    r = await call(session, "rpc_interface_security", {"server_key": key})
    check("interface_security shape", "alpc_security_descriptor_sddl" in r or "error" in r, json.dumps(r)[:200])
    print("      sddl:", str(r.get("alpc_security_descriptor_sddl"))[:150], "| alpc_port:", r.get("alpc_port"), "| alpc_error:", str(r.get("alpc_error"))[:80])
    if r.get("alpc_port") and not r.get("alpc_security_descriptor_sddl"):
        note(f"ALPC SDDL extraction returned empty for live port {r.get('alpc_port')}: {r.get('alpc_error')}")
    r = await call(session, "rpc_etw_unreachable", {"duration_sec": 3})
    shape_ok = "hit_count" in r or "error" in r
    check("etw_unreachable responds", shape_ok, json.dumps(r)[:250])
    print("      etw:", {k: r.get(k) for k in ("admin", "events_scanned", "hit_count", "error")})
    if r.get("admin") is False and "error" not in r and r.get("events_scanned", 0) == 0:
        note("etw_unreachable returns ok-shaped result with 0 events when logman fails as non-admin (silent failure)")


async def section_j(session: ClientSession) -> None:
    print("\n=== J. NEW TOOLS (P1-P3) ===")
    r = await call(session, "rpc_alpc_squat", {"port_name": "mcp_audit_squat_test", "duration_sec": 2})
    check("alpc_squat runs and cleans up", "squatted_port" in r or "error" in r, json.dumps(r)[:200])
    if "error" in r:
        print("      squat error:", str(r.get("error"))[:140])
    r = await call(session, "rpc_alpc_squat", {"port_name": "bad/port\\name", "duration_sec": 2})
    check("alpc_squat rejects path-like names", r.get("ok") is False, json.dumps(r))
    r = await call(session, "rpc_format_client", {"server_key": "@@audit-key@@"})
    check("format_client bad key -> error", "error" in r, json.dumps(r)[:150])
    r = await call(session, "rpc_new_struct", {"session": "ghost", "type_name": "X", "store_as": "v"})
    check("new_struct bad session -> error", "error" in r, json.dumps(r)[:150])
    r = await call(session, "rpc_accessible_tasks", {})
    check("accessible_tasks responds", "count" in r or "error" in r, json.dumps(r)[:200])
    if "count" in r:
        print("      accessible tasks:", r.get("count"))
    r = await call(session, "rpc_clear_cache", {})
    check("clear_cache responds", "cleared" in r, json.dumps(r)[:150])
    rp = await call(session, "rpc_parse", {"file_path": TARGET_DLL})
    key = (rp.get("servers") or [{}])[0].get("key", "")
    rc = await call(session, "rpc_connect", {"session": "audit_new", "server_key": key})
    if "error" not in rc:
        rm = await call(session, "rpc_methods", {"session": "audit_new"})
        with_opnum = [m for m in rm.get("methods", []) if m.get("opnum") is not None]
        check("rpc_methods includes opnum mapping", len(with_opnum) >= 5, f"{len(with_opnum)}/{rm.get('count')}")
        rf = await call(session, "rpc_fuzz", {"session": "audit_new", "dry_run": True, "max_procs": 10})
        check("rpc_fuzz dry_run plans only", rf.get("dry_run") is True and rf.get("executed") == 0 and rf.get("planned", 0) > 0, json.dumps(rf)[:250])
        fc = await call(session, "rpc_format_client", {"server_key": key})
        check("format_client saves source", fc.get("length", 0) > 5000 and os.path.isfile(fc.get("saved_to", "")), json.dumps(fc)[:200])
        rv = await call(session, "rpc_vars", {"session": "audit_new"})
        check("rpc_vars lists (empty ok)", "vars" in rv, json.dumps(rv)[:150])
        rns = await call(session, "rpc_new_struct", {"session": "audit_new", "type_name": "NotARealType", "store_as": "x"})
        check("new_struct unknown type -> error", "not found" in str(rns.get("error", "")), json.dumps(rns)[:200])
        await call(session, "rpc_disconnect", {"session": "audit_new"})
    else:
        print("      connect unavailable; skipping opnum/fuzz/format live checks:", str(rc.get("error"))[:100])
    audit_log = os.path.join(ROOT, "output", "mcp_audit.log")
    check("audit log written by tool wrapper", os.path.isfile(audit_log) and os.path.getsize(audit_log) > 0, audit_log)


async def section_timeout() -> None:
    print("\n=== I. engine timeout robustness (isolated instance) ===")
    import snippets as S
    from ps_engine import EngineTimeoutError, PowerShellEngine

    eng = PowerShellEngine(init_script=S.INIT)
    check("isolated engine init", eng.init_result.get("ready") is True, json.dumps(eng.init_result))
    try:
        eng.execute("Start-Sleep -Seconds 8", timeout=1.5)
        check("timeout raises EngineTimeoutError", False, "no exception raised")
    except EngineTimeoutError:
        check("timeout raises EngineTimeoutError", True)
    check("engine marked dead after timeout", not eng.alive)
    eng2 = PowerShellEngine(init_script=S.INIT)
    r = eng2.call_json(S.STATE, timeout=30)
    check("fresh engine works after old one died", "servers" in r, json.dumps(r)[:150])
    try:
        eng2.proc.kill()
    except OSError:
        pass


async def main() -> int:
    tmpdir = tempfile.mkdtemp(prefix="mcp_audit_")
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(ROOT, "server.py")], cwd=ROOT)
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await section_a(session)
                await section_b(session)
                hkey = await section_c(session, tmpdir)
                await section_d(session, tmpdir)
                # ensure main target parsed for E/G/H
                r = await call(session, "rpc_parse", {"file_path": TARGET_DLL})
                key = (r.get("servers") or [{}])[0].get("key", hkey)
                await section_e(session, key)
                await section_f(session)
                await section_g(session, key)
                await section_h(session, key)
                await section_j(session)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    await section_timeout()
    print("\n===== AUDIT FINDINGS (" + str(len(FINDINGS)) + ") =====")
    for f in FINDINGS:
        print(" -", f)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
