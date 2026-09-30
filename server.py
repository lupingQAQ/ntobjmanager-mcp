"""NtObjectManager MCP server.

Stateful Windows RPC research MCP over James Forshaw's NtObjectManager /
NtCoreLib. Two tool families:

1. Stateful core: parse -> inspect -> connect -> call, with RPC client
   objects kept alive in a persistent PowerShell session between tool calls.
2. Fixed methodology tools distilled from 2024-2026 public CVE research:
   - rpc_scan_context_handles  (context-handle type confusion, CVE-2025-48815 pattern)
   - rpc_inventory             (MS-RPC-Fuzzer phase 1 / Get-RpcServerData, CVE-2025-26651 pattern)
   - rpc_find_hijackable       (EPM poisoning / RPC-Racer, CVE-2025-49760/59200/59230 pattern)
   - rpc_etw_unreachable       (PhantomRPC, Kaspersky 2026 pattern)
   - rpc_interface_security    (MS-NRPC null session, Securelist 2025 pattern)
   - rpc_decode_flags          (interface flag bitmask decoding)

WARNING: research tool only. rpc_call can invoke arbitrary RPC methods on
this host and may crash services. Prefer an isolated VM.
"""

from __future__ import annotations

import base64
import functools
import glob as _glob
import json
import os
import re
import subprocess
import threading
import time
import urllib.request
from typing import Any, Optional

try:  # mcp 2.x renamed FastMCP -> MCPServer
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP

import snippets as S
from ps_engine import EngineDeadError, PowerShellEngine

mcp = FastMCP("ntobjectmanager-rpc")

_HERE = os.path.dirname(os.path.abspath(__file__))
_ENGINE: Optional[PowerShellEngine] = None
_ENGINE_LOCK = threading.Lock()
_AUDIT_LOCK = threading.Lock()


def _audit(tool_name: str, detail: str) -> None:
    out_dir = os.path.join(_HERE, "output")
    try:
        os.makedirs(out_dir, exist_ok=True)
        line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {tool_name} {detail[:300]}\n"
        with _AUDIT_LOCK, open(os.path.join(out_dir, "mcp_audit.log"), "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def tool(fn):
    """Register a tool and append every call to output/mcp_audit.log."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        sig = {}
        try:
            sig = {k: v for k, v in kwargs.items() if k in fn.__code__.co_varnames}
        except Exception:
            pass
        _audit(fn.__name__, json.dumps(sig, ensure_ascii=False, default=str))
        return fn(*args, **kwargs)

    return mcp.tool()(wrapper)

RPC_IF_FLAGS: dict[int, str] = {
    0x0001: "RPC_IF_AUTOLISTEN",
    0x0008: "RPC_IF_ALLOW_SECURE_ONLY (deprecated)",
    0x0010: "RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH",
    0x0020: "RPC_IF_ALLOW_LOCAL_ONLY",
    0x0040: "RPC_IF_SEC_CACHE_PER_PROC",
    0x0080: "RPC_IF_SEC_NO_CACHE",
}


def _engine() -> PowerShellEngine:
    global _ENGINE
    with _ENGINE_LOCK:
        if _ENGINE is None or not _ENGINE.alive:
            _ENGINE = PowerShellEngine(init_script=S.INIT)
        return _ENGINE


def _ready_error() -> Optional[dict[str, Any]]:
    eng = _engine()
    init = eng.init_result if eng.init_result else {}
    if not init.get("ready", False):
        return {
            "ok": False,
            "error": init.get("error", "NtObjectManager not available"),
            "hint": "Install-Module NtObjectManager -Scope CurrentUser",
        }
    return None


def _run(template: str, timeout: float = 120.0, **tokens: str) -> dict[str, Any]:
    err = _ready_error()
    if err:
        return err
    script = S.render(template, **tokens)
    try:
        return _engine().call_json(script, timeout=timeout)
    except EngineDeadError:
        return {"ok": False, "error": "engine died; state lost - retry the call to restart"}


def _prefix_for(path: str) -> str:
    base = os.path.splitext(os.path.basename(path))[0]
    return re.sub(r"[^A-Za-z0-9_-]", "_", base)[:24] or "srv"


# ===========================================================================
# Core stateful tools
# ===========================================================================


@tool
def rpc_parse(file_path: str, symbol_path: Optional[str] = None) -> dict:
    """Parse a PE file (DLL/EXE) for embedded RPC servers and cache them for later tools.

    Each found interface gets a stable key (<filebase>_N) usable in rpc_get_interface /
    rpc_connect. Optionally pass symbol_path like 'srv*C:\\symbols*https://msdl.microsoft.com/download/symbols'
    to resolve real procedure names (slow on first use, downloads from MS symbol server).
    This is the Get-RpcServer entry point used across PetitPotam-class research.
    """
    if not os.path.isfile(file_path):
        return {"ok": False, "error": f"file not found: {file_path}"}
    timeout = 600.0 if symbol_path else 120.0
    return _run(
        S.PARSE,
        timeout=timeout,
        PATH=S.ps_str(file_path),
        PREFIX=S.ps_str(_prefix_for(file_path)),
        SYMBOLPATH=S.ps_str(symbol_path),
    )


@tool
def rpc_state() -> dict:
    """List all cached parsed RPC servers and live connected client sessions."""
    return _run(S.STATE, timeout=60)


@tool
def rpc_get_interface(server_key: str) -> dict:
    """Show full detail (procedures, parameters, NDR types, context handles, strictness)
    for one cached RPC interface. Context-handle params are flagged so you can spot
    producer/consumer pairs for type-confusion research."""
    return _run(S.GET_INTERFACE, timeout=60, KEY=S.ps_str(server_key))


@tool
def rpc_query_endpoints(
    interface_id: Optional[str] = None,
    search_binding: Optional[str] = None,
    find_alpc_port: bool = False,
    limit: int = 50,
) -> dict:
    """Query the RPC endpoint mapper (EPM). No args = all local registrations.
    interface_id filters one interface; search_binding like 'ncacn_ip_tcp:10.0.0.5'
    queries a REMOTE host's EPM (recon of remotely exposed RPC, cf. rpcdump).
    find_alpc_port brute-forces ALPC ports for an interface (slow)."""
    if find_alpc_port and not interface_id:
        return {"ok": False, "error": "find_alpc_port requires interface_id"}
    return _run(
        S.QUERY_ENDPOINTS,
        timeout=300.0 if find_alpc_port else 60.0,
        IFID=S.ps_str(interface_id),
        SEARCHBIND=S.ps_str(search_binding),
        FINDALPC=S.ps_bool(find_alpc_port),
        LIMIT=str(int(limit)),
    )


@tool
def rpc_running_servers(process_id: Optional[int] = None, service_name: Optional[str] = None) -> dict:
    """Enumerate RPC servers in a RUNNING process (by PID) or registered Windows service
    (by service name) by parsing its loaded modules. Results are cached like rpc_parse.
    This is the runtime-discovery complement to file parsing (tiraniddo methodology)."""
    if process_id is None and not service_name:
        return {"ok": False, "error": "provide process_id or service_name"}
    return _run(
        S.RUNNING_SERVERS,
        timeout=180,
        PID=str(int(process_id)) if process_id is not None else "0",
        SVCNAME=S.ps_str(service_name if service_name else ""),
    )


@tool
def rpc_connect(
    session: str,
    server_key: str,
    string_binding: Optional[str] = None,
    authentication_level: Optional[str] = None,
    authentication_type: Optional[str] = None,
    find_alpc_port: bool = False,
) -> dict:
    """Create and CONNECT a stateful RPC client for a cached interface. The client stays
    alive across tool calls under the session name (this is the core stateful feature).

    string_binding like 'ncalrpc:[LSMApi]', 'ncacn_np:[\\pipe\\LSM_API_service]' or
    'ncacn_ip_tcp:host'; omit it to auto-discover via EPM. authentication_level e.g.
    'PacketPrivacy', authentication_type e.g. 'WinNT' (needed for many named-pipe
    servers, cf. CVE-2025-26651 LSM writeup). Then use rpc_methods + rpc_call."""
    return _run(
        S.CONNECT,
        timeout=600.0 if find_alpc_port else 180.0,
        SESSION=S.ps_str(session),
        KEY=S.ps_str(server_key),
        BINDING=S.ps_str(string_binding),
        AUTHLEVEL=S.ps_str(authentication_level),
        AUTHTYPE=S.ps_str(authentication_type),
        FINDALPC=S.ps_bool(find_alpc_port),
    )


@tool
def rpc_methods(session: str) -> dict:
    """List callable methods (name, params, return type) of a connected RPC client session."""
    return _run(S.METHODS, timeout=60, SESSION=S.ps_str(session))


@tool
def rpc_call(
    session: str,
    method: str,
    args_json: str = "[]",
    store_as: Optional[str] = None,
) -> dict:
    """Invoke a method on a connected session. args_json is a JSON array of arguments:
    primitives (numbers/strings/bools) bind directly; {"__ps__": "<PowerShell expression>"}
    evaluates arbitrary expressions (for complex NDR structs); {"__var__": "name"} passes a
    PREVIOUSLY STORED result object as-is (no serialization round-trip).

    store_as="name" keeps the raw returned object in the session so later calls can pass it
    via {"__var__": "name"} - this is how you chain producer/consumer context handles for
    type-confusion testing (CVE-2025-48815 methodology). Stored vars appear in rpc_state.
    DANGEROUS: can crash services; prefer an isolated VM."""
    try:
        parsed = json.loads(args_json)
        if not isinstance(parsed, list):
            return {"ok": False, "error": "args_json must be a JSON array"}
    except ValueError as e:
        return {"ok": False, "error": f"invalid args_json: {e}"}
    return _run(
        S.CALL,
        timeout=180,
        SESSION=S.ps_str(session),
        METHOD=S.ps_str(method),
        ARGS=S.ps_str(args_json),
        STOREAS=S.ps_str(store_as),
    )


@tool
def rpc_disconnect(session: str) -> dict:
    """Disconnect and drop a client session."""
    return _run(S.DISCONNECT, timeout=60, SESSION=S.ps_str(session))


# ===========================================================================
# Fixed methodology tools (2024-2026 public CVE research)
# ===========================================================================


@tool
def rpc_scan_context_handles(paths: list[str], min_named_groups: int = 1) -> dict:
    """[CVE-2025-48815 pattern, whereisk0shl 2026] Scan PE files for interfaces whose
    procedures exchange MULTIPLE context handles - the classic type-confusion attack
    surface (pass one interface's context handle where another type is expected;
    runtime only auto-validates *strict* handles). Reports per-interface context-handle
    params with direction and strictness, flags non-strict producers/consumers."""
    if not paths:
        return {"ok": False, "error": "paths (list of file paths/globs) required"}
    files: list[str] = []
    for p in paths:
        if any(c in p for c in "*?"):
            files.extend(sorted(_glob.glob(p)))
        elif os.path.isfile(p):
            files.append(p)
    files = sorted(set(files))
    findings: list[dict] = []
    errors: list[dict] = []
    for f in files[:200]:
        res = _run(S.CTX_SCAN, timeout=90, PATH=S.ps_str(f))
        if not res.get("ok", False):
            errors.append({"file": f, "error": res.get("error", "unknown")})
            continue
        for iface in res.get("interfaces", []):
            params = iface.get("context_handle_params", []) or []
            if not params:
                continue
            named: dict[str, dict] = {}
            n_non_strict = sum(1 for r in params if not r.get("strict"))
            producers = sorted({r["proc"] for r in params if r["direction"] in ("out", "inout")})
            consumers = sorted({r["proc"] for r in params if r["direction"] in ("in", "inout")})
            for r in params:
                g = named.setdefault(r["param"], {"strict": r.get("strict"), "procs": []})
                if r["proc"] not in g["procs"]:
                    g["procs"].append(r["proc"])
            named_groups = {k: v for k, v in named.items() if k != "unnamed"}
            if len(named_groups) >= max(1, min_named_groups) or len(named) > 1:
                findings.append(
                    {
                        "file": iface.get("file"),
                        "interface_id": iface.get("interface_id"),
                        "version": iface.get("version"),
                        "service": iface.get("service"),
                        "service_running": iface.get("service_running"),
                        "ctx_param_count": len(params),
                        "distinct_groups": named,
                        "non_strict_count": n_non_strict,
                        "producer_procs": producers,
                        "consumer_procs": consumers,
                        "verdict": (
                            "HIGH interest: multiple context-handle groups and non-strict handles present"
                            if (len(named) > 1 and n_non_strict > 0)
                            else "review: context handles present"
                        ),
                    }
                )
    findings.sort(key=lambda x: (-x["ctx_param_count"], x.get("file") or ""))
    return {
        "ok": True,
        "files_scanned": len(files),
        "errors": errors[:10],
        "finding_count": len(findings),
        "findings": findings[:40],
        "methodology_note": "Re-scope like ssdpsrv (CVE-2025-48815): non-strict (BIND_CONTEXT, format 0x70) handles are not type-checked by rpcrt4 while strict (SUPPLEMENT, 0x75) are. CAUTION: groups are keyed by parameter NAME (positional when symbols are unavailable) - a 'multiple groups' verdict does NOT prove distinct handle TYPES (e.g. XactSrv in srvsvc.dll routes one printer handle type through several procs and still flags HIGH). Confirm type identity via RE of dispatch functions or public protocol docs before concluding type confusion. Next step: rpc_parse + rpc_connect, produce a handle via a producer proc, feed it to a consumer expecting another type. Use symbol_path in rpc_parse for real param names.",
    }


@tool
def rpc_inventory(paths: list[str], limit: int = 40, with_endpoints: bool = True) -> dict:
    """[MS-RPC-Fuzzer phase-1 / Get-RpcServerData, CVE-2025-26651 pattern] Batch-parse
    files (globs ok, default a System32 slice) and cross-check every interface against
    the EPM: which are registered/reachable right now. Produces an attack-surface
    inventory JSON saved to ./output/ and cached servers you can rpc_connect directly."""
    if not paths:
        paths = [r"C:\Windows\System32\*.dll"]
    files: list[str] = []
    for p in paths:
        hits = sorted(_glob.glob(p)) if any(c in p for c in "*?") else [p]
        files.extend(h for h in hits if h.lower().endswith((".dll", ".exe")) and os.path.isfile(h))
    files = sorted(set(files))[: max(1, limit)]
    entries: list[dict] = []
    errors: list[dict] = []
    t0 = time.time()
    for f in files:
        res = _run(S.PARSE, timeout=90, PATH=S.ps_str(f), PREFIX=S.ps_str(_prefix_for(f)), SYMBOLPATH="$null")
        if not res.get("ok", False):
            errors.append({"file": f, "error": str(res.get("error", "unknown"))[:200]})
            continue
        for srv in res.get("servers", []):
            entry = dict(srv)
            entry["epm_registered"] = None
            if with_endpoints:
                epm = _run(S.EPM_REGISTERED, timeout=45, IFID=S.ps_str(srv["interface_id"]))
                if epm.get("ok", False):
                    entry["epm_registered"] = (epm.get("count", 0) or 0) > 0
                    entry["epm_bindings"] = epm.get("bindings", [])[:4]
            entries.append(entry)
    out_dir = os.path.join(_HERE, "output")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"inventory_{time.strftime('%Y%m%d_%H%M%S')}.json")
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "files_requested": len(files),
        "interfaces": entries,
        "errors": errors,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=1)
    registered = sum(1 for e in entries if e.get("epm_registered"))
    return {
        "ok": True,
        "files": len(files),
        "interfaces": len(entries),
        "epm_registered": registered,
        "epm_unregistered_or_unknown": len(entries) - registered,
        "errors": errors[:10],
        "duration_sec": round(time.time() - t0, 1),
        "saved_to": out_path,
        "sample": entries[:10],
        "note": "Servers are cached; keys are in each entry's 'key' field - feed them to rpc_connect.",
    }


@tool
def rpc_find_hijackable(max_services: int = 30, include_delayed_auto: bool = True) -> dict:
    """[EPM poisoning / RPC-Racer, SafeBreach CVE-2025-49760 + CVE-2025-59200/59230 pattern]
    Find RPC attack-surface of services that are NOT currently running (Manual or
    Delayed-Autostart): their interfaces are unregistered in the EPM, so a low-privileged
    process can register a rogue server and capture privileged clients that race for the
    endpoint after service start. Per-service this resolves svchost ServiceDlls, parses
    interfaces and checks live EPM registration."""
    res = _run(S.SERVICES_LIST, timeout=90)
    if not res.get("ok", False):
        return res
    services = res.get("services", []) or []
    candidates: list[dict] = []
    for s in services:
        if s.get("start") == "Manual":
            candidates.append(dict(s, delayed=False))
        elif s.get("start") == "Auto" and include_delayed_auto:
            candidates.append(dict(s, delayed=None))  # resolved via registry below
    if not candidates:
        return {"ok": True, "candidates": 0, "note": "no non-running Manual/Delayed services found"}
    names = [c["name"] for c in candidates][:500]
    reg = _run(S.SERVICE_REGISTRY, timeout=90, NAMES=S.ps_str(json.dumps(names)))
    reg_map = {r["name"]: r for r in (reg.get("services", []) or [])} if reg.get("ok", False) else {}
    final: list[dict] = []
    for c in candidates:
        r = reg_map.get(c["name"], {})
        if c.get("delayed") is None:
            if not r.get("delayed_autostart"):
                continue
            c["delayed"] = True
        path = os.path.expandvars((c.get("path") or "").strip().strip('"').split(" -")[0].split(" /")[0])
        low = path.lower()
        if low.endswith("svchost.exe"):
            dll = r.get("service_dll")
            if not dll:
                continue
            c["module"] = dll
            c["via"] = "svchost ServiceDll"
        else:
            if not low.endswith((".exe", ".dll")):
                continue
            c["module"] = path
            c["via"] = "service binary"
        final.append(c)
    findings: list[dict] = []
    checked = 0
    for c in final:
        if checked >= max_services:
            break
        mod = c.get("module") or ""
        if not os.path.isfile(mod):
            continue
        checked += 1
        pres = _run(S.PARSE, timeout=90, PATH=S.ps_str(mod), PREFIX=S.ps_str(_prefix_for(mod)), SYMBOLPATH="$null")
        if not pres.get("ok", False):
            continue
        ifaces = pres.get("servers", []) or []
        if not ifaces:
            continue
        unreg: list[dict] = []
        for srv in ifaces[:8]:
            epm = _run(S.EPM_REGISTERED, timeout=45, IFID=S.ps_str(srv["interface_id"]))
            if epm.get("ok", False) and (epm.get("count", 0) or 0) == 0:
                unreg.append({"key": srv.get("key"), "interface_id": srv.get("interface_id"), "procedure_count": srv.get("procedure_count")})
        if unreg:
            findings.append(
                {
                    "service": c["name"],
                    "display": c.get("display"),
                    "start_mode": c.get("start"),
                    "delayed": c.get("delayed"),
                    "module": mod,
                    "via": c.get("via"),
                    "unregistered_interfaces": unreg,
                }
            )
    return {
        "ok": True,
        "non_running_candidates": len(final),
        "modules_checked": checked,
        "hijackable_services": len(findings),
        "findings": findings[:30],
        "note": "Each finding = service with RPC interfaces currently absent from the EPM. RPC-Racer pattern: register the interface (needs a rogue RPC server / NtObjectManager RpcServer hosting), trigger/start the service, capture the privileged client. Microsoft's partial fix (security QOS check on specific clients) does NOT cover untouched interfaces.",
    }


@tool
def rpc_interface_security(server_key: str) -> dict:
    """[MS-NRPC null-session methodology, Securelist 2025] Security posture of a cached
    interface: running state, EPM registration, and (best effort) the ALPC port's
    security descriptor SDDL - look for anonymous/EVERYONE ACEs which allow unauthenticated
    access even under the 'Authenticated' RPC policy. Flags need RE: decode them with
    rpc_decode_flags after reading the RpcServerRegisterIf3 call."""
    return _run(S.INTERFACE_SECURITY, timeout=120, KEY=S.ps_str(server_key))


@tool
def rpc_etw_unreachable(
    duration_sec: int = 10,
    status_regex: str = "(?i)6d1",
    max_results: int = 20,
    trigger_script: Optional[str] = None,
) -> dict:
    """[PhantomRPC methodology, Kaspersky 2026] Run an ETW trace of the Microsoft-Windows-RPC
    provider and report RPC calls whose stop event Status matches status_regex (default
    targets RPC_S_SERVER_UNAVAILABLE / 0x6D1): clients trying to reach servers that are
    not running - each is a candidate for rogue-server substitution privilege escalation.
    trigger_script (PowerShell) executes DURING the trace window to provoke RPC activity
    (e.g. 'gpupdate /force', netsh tweaks, service starts - the PhantomRPC workflow).
    Needs admin; EXPERIMENTAL property-name mapping."""
    if duration_sec < 1 or duration_sec > 300:
        return {"ok": False, "error": "duration_sec must be within 1..300"}
    trace_name = f"mcp_rpc_{int(time.time())}"
    return _run(
        S.ETW_UNREACHABLE,
        timeout=float(duration_sec + 120),
        NAME=S.ps_str(trace_name),
        DUR=str(int(duration_sec)),
        STATUSREGEX=S.ps_str(status_regex),
        MAXRES=str(int(max_results)),
        TRIGGER=S.ps_str(trigger_script),
    )


@tool
def rpc_decode_flags(flags: int) -> dict:
    """Decode an RPC interface registration flags bitmask (value read from RE of
    RpcServerRegisterIf2/3 calls or RpcView). Includes security interpretation of each
    flag (e.g. ALLOW_CALLBACKS_WITH_NO_AUTH bypasses the 'Authenticated only' policy)."""
    value = int(flags) & 0xFFFFFFFF
    matched = [
        {"bit": f"0x{bit:04X}", "flag": name, "set": bool(value & bit)}
        for bit, name in sorted(RPC_IF_FLAGS.items())
    ]
    unknown = value & ~0xF9  # bits outside the known set (0x01|0x08|0x10|0x20|0x40|0x80)
    notes = []
    if value & 0x0010:
        notes.append("RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH: interface reachable even against the Restrict Unauthenticated RPC Clients=Authenticated policy (null-session research vector).")
    if value & 0x0020:
        notes.append("RPC_IF_ALLOW_LOCAL_ONLY: remote clients rejected - local-only attack surface.")
    if value & 0x0008:
        notes.append("RPC_IF_ALLOW_SECURE_ONLY: deprecated, requires authenticated clients.")
    if value & 0x0001:
        notes.append("RPC_IF_AUTOLISTEN: runtime listens automatically.")
    return {
        "ok": True,
        "input": f"0x{value:08X}",
        "flags": matched,
        "unknown_bits": f"0x{unknown:08X}" if unknown else None,
        "security_notes": notes,
    }


# ===========================================================================
# Feature completion (P1-P3)
# ===========================================================================


@tool
def rpc_alpc_squat(port_name: str, duration_sec: int = 10) -> dict:
    """[RPC-Racer attack-side primitive, SafeBreach methodology] Create an ALPC port with the
    given name (fixed endpoint of a target RPC interface) and CAPTURE clients that connect
    during the window - proves a race is winnable after rpc_find_hijackable flags a service.
    Raw ALPC only: clients connect but cannot complete the RPC handshake (no server builder
    in NtObjectManager 2.0.1; weaponize with RPC-Racer for full rogue-server scenarios)."""
    if duration_sec < 1 or duration_sec > 120:
        return {"ok": False, "error": "duration_sec must be within 1..120"}
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", port_name):
        return {"ok": False, "error": "port_name must be a simple name (no paths)"}
    return _run(S.ALPC_SQUAT, timeout=float(duration_sec + 90), NAME=S.ps_str(port_name), DUR=str(int(duration_sec)))


@tool
def rpc_format_client(server_key: str, out_path: Optional[str] = None) -> dict:
    """Export the generated C# client source (Format-RpcClient) for offline auditing -
    grep for FC_BINDING_CONTEXT patterns, review NDR marshalling, build standalone clients
    (whereisk0shl CVE-2025-48815 writeup workflow). Defaults to ./client_<key>.cs."""
    if out_path and not os.path.isabs(out_path):
        return {"ok": False, "error": "out_path must be absolute"}
    return _run(S.FORMAT_CLIENT, timeout=90, KEY=S.ps_str(server_key), OUTPATH=S.ps_str(out_path))


@tool
def rpc_fuzz(session: str, max_procs: int = 25, dry_run: bool = True) -> dict:
    """[MS-RPC-Fuzzer phase-2 lite, CVE-2025-26651 pattern] Plan (dry_run=True, SAFE) or execute
    primitive-only calls with default values against a connected session, classifying results
    ok / access_denied / error. dry_run=False ACTUALLY INVOKES RPC METHODS and can crash
    services - isolated VM only. Complex-parameter procs are listed for manual __ps__/struct
    work instead of being blindly called."""
    return _run(
        S.FUZZ,
        timeout=240,
        SESSION=S.ps_str(session),
        DRYRUN=S.ps_bool(dry_run),
        MAXPROCS=str(int(max_procs)),
    )


@tool
def rpc_new_struct(session: str, type_name: str, store_as: str, fields_json: str = "{}") -> dict:
    """Build an instance of an NDR complex type from the generated client assembly (type names
    appear in rpc_methods params, e.g. NdrStructure_xxx) and store it as a session var for
    {"__var__"} passing. fields_json maps field/property names to primitive values."""
    try:
        parsed = json.loads(fields_json)
        if not isinstance(parsed, dict):
            return {"ok": False, "error": "fields_json must be a JSON object"}
    except ValueError as e:
        return {"ok": False, "error": f"invalid fields_json: {e}"}
    return _run(
        S.NEW_STRUCT,
        timeout=90,
        SESSION=S.ps_str(session),
        TYPE=S.ps_str(type_name),
        FIELDS=S.ps_str(fields_json),
        STOREAS=S.ps_str(store_as),
    )


@tool
def rpc_accessible_tasks() -> dict:
    """[Forshaw COM/privilege-esc methodology, cf. CVE-2026-66804 'Dark Elevator' pattern]
    List scheduled tasks accessible to the current user (Get-AccessibleScheduledTask) -
    user-startable tasks that run as SYSTEM are the classic delivery vehicle for
    dangling-COM / EPM-poisoning chains."""
    return _run(S.ACCESSIBLE_TASKS, timeout=120)


@tool
def rpc_vars(session: str, clear: bool = False) -> dict:
    """List (or clear) stored session variables created via store_as / rpc_new_struct."""
    return _run(S.VARS, timeout=60, SESSION=S.ps_str(session), CLEAR=S.ps_bool(clear))


@tool
def rpc_clear_cache() -> dict:
    """Drop all cached parsed servers (eviction cap is 150; connected sessions keep their
    clients and stay usable)."""
    return _run(S.CLEAR_CACHE, timeout=60)


# ===========================================================================
# VM bridge: execute PowerShell inside a VMware guest via a persistent
# HTTP listener (vm_listener.ps1), so host-driven hunts can run probes in
# the isolated VM at ~100ms/call instead of ~20s vmrun round trips.
# ===========================================================================

# VM definitions come from the environment - no lab host, path, credential or IP
# is baked into the source. Set RPCMCP_VMS to a JSON object shaped like:
#   {"<name>": {"vmx": "<guest.vmx>", "user": "<user>", "pass": "<pass>", "ip": "<optional>"}}
# Optional: RPCMCP_VM_DEFAULT (default VM name), RPCMCP_VMRUN (vmrun path).
try:
    import local_config as _local_config
except ImportError:
    _local_config = None

try:
    _VMS: dict[str, dict[str, str]] = json.loads(os.environ.get("RPCMCP_VMS", "") or "{}")
    if not isinstance(_VMS, dict):
        _VMS = {}
except ValueError:
    _VMS = {}
if not _VMS and _local_config is not None:
    _VMS = getattr(_local_config, "VMS", {}) or {}
_DEFAULT_VM = (
    os.environ.get("RPCMCP_VM_DEFAULT", "")
    or (getattr(_local_config, "DEFAULT_VM", "") if _local_config else "")
    or next(iter(_VMS), "")
)
_VMRUN = (
    os.environ.get("RPCMCP_VMRUN", "")
    or (getattr(_local_config, "VMRUN", "") if _local_config else "")
    or "vmrun"
)
_BRIDGE_PORT = 8765
_BRIDGE_TOKEN = "rpcmcp-bridge"
_vm_ip_cache: dict[str, str] = {}


def _vm_ip(vm: str) -> Optional[str]:
    if vm in _vm_ip_cache:
        return _vm_ip_cache[vm]
    info = _VMS.get(vm, {})
    if info.get("ip"):
        _vm_ip_cache[vm] = info["ip"]
        return info["ip"]
    vmx = info.get("vmx")
    if not vmx:
        return None
    try:
        out = subprocess.run(
            [_VMRUN, "-T", "ws", "getGuestIPAddress", vmx],
            capture_output=True, text=True, timeout=60,
        )
        ip = out.stdout.strip()
        if ip:
            _vm_ip_cache[vm] = ip
            return ip
    except Exception:
        pass
    return None


def _vm_post(ps: str, timeout: float = 180.0, vm: str = _DEFAULT_VM) -> dict:
    ip = _vm_ip(vm)
    if ip:
        try:
            body = json.dumps({"ps": ps}).encode("utf-8")
            req = urllib.request.Request(
                f"http://{ip}:{_BRIDGE_PORT}/rpcmcp/",
                data=body,
                headers={"Content-Type": "application/json", "X-Token": _BRIDGE_TOKEN},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="replace"))
            out = payload.get("output", "")
            try:
                val = json.loads(out) if out else None
            except ValueError:
                val = out
            return {
                "ok": True, "vm": vm, "via": "http", "result": val,
                "stateful": True,
                "note": "persistent guest engine: variables / connected RPC clients survive across rpc_vm_exec calls",
            }
        except Exception:
            pass
    return _vm_post_via_vmrun(ps, timeout, vm)


_VM_RUN_LOCK = threading.Lock()
_VM_TASK_SEQ = 0


def _vm_post_via_vmrun(ps: str, timeout: float = 180.0, vm: str = _DEFAULT_VM) -> dict:
    """Fallback bridge transport: file-copy the script in via vmrun, run, copy result out.
    No guest networking required (uses the VMware Tools channel). ~6-8s per call."""
    global _VM_TASK_SEQ
    info = _VMS.get(vm, {})
    vmx = info.get("vmx")
    auth = ["-gu", info.get("user", "Administrator"), "-gp", info.get("pass", "")]
    if not vmx:
        return {"ok": False, "error": f"unknown vm {vm!r} (known: {sorted(_VMS)})"}
    with _VM_RUN_LOCK:
        _VM_TASK_SEQ += 1
        task = f"task_{int(time.time())}_{_VM_TASK_SEQ}"
        here = os.path.dirname(os.path.abspath(__file__))
        local_ps = os.path.join(here, "output", f"vm_{task}.ps1")
        local_out = os.path.join(here, "output", f"vm_{task}.out")
        os.makedirs(os.path.dirname(local_ps), exist_ok=True)
        wrapper = (
            "Import-Module NtObjectManager -ErrorAction SilentlyContinue\n"
            "$userPs = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
            + base64.b64encode(ps.encode("utf-8")).decode("ascii")
            + "'))\n"
            "try {\n"
            "$r = Invoke-Expression $userPs\n"
            "} catch { $r = '__ERROR__ ' + $_.Exception.Message }\n"
            "if ($null -ne $r -and \"$r\" -ne '') { $r | Out-File C:\\rpcmcp\\last.out -Encoding utf8 } "
            "else { 'null' | Out-File C:\\rpcmcp\\last.out -Encoding utf8 }\n"
        )
        with open(local_ps, "w", encoding="utf-8-sig") as fh:
            fh.write(wrapper)
        try:
            r1 = subprocess.run([_VMRUN, "-T", "ws", *auth, "CopyFileFromHostToGuest", vmx, local_ps, rf"C:\rpcmcp\run.ps1"],
                                capture_output=True, timeout=240)
            if r1.returncode != 0:
                return {"ok": False, "error": f"copy-in failed: {r1.stderr.decode(errors='replace')[:200]}"}
            r2 = subprocess.run([_VMRUN, "-T", "ws", *auth, "runProgramInGuest", vmx,
                                 r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                 "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", r"C:\rpcmcp\run.ps1"],
                                capture_output=True, timeout=max(120, timeout))
            if r2.returncode != 0 and b"Error" in r2.stderr:
                return {"ok": False, "error": f"guest run failed: {r2.stderr.decode(errors='replace')[:200]}"}
            subprocess.run([_VMRUN, "-T", "ws", *auth, "CopyFileFromGuestToHost", vmx, r"C:\rpcmcp\last.out", local_out],
                           capture_output=True, timeout=240)
            if not os.path.isfile(local_out):
                return {"ok": False, "error": "copy-out failed (output missing)"}
            out = open(local_out, encoding="utf-8-sig", errors="replace").read().strip()
            if out.startswith("__ERROR__"):
                return {"ok": False, "vm": vm, "via": "vmrun", "error": out[len("__ERROR__"):].strip()}
            try:
                val = json.loads(out)
            except ValueError:
                val = out
            return {
                "ok": True, "vm": vm, "via": "vmrun", "result": val,
                "stateful": False,
                "hint": "vmrun fallback spawns a fresh guest shell per call - state does NOT persist across calls. "
                        "Run rpc_vm_start_listener (needs admin in the guest) to use the persistent HTTP engine.",
            }
        except Exception as e:
            return {"ok": False, "error": f"vmrun bridge failed: {e}"}


@tool
def rpc_vm_exec(ps: str, timeout: int = 180, vm: str = "") -> dict:
    """Run arbitrary PowerShell INSIDE a lab VM and return its output. The target VM
    is chosen by name (see RPCMCP_VMS / RPCMCP_VM_DEFAULT). Write the PS to emit JSON
    (ConvertTo-Json) for structured results.

    Stateful: when the HTTP bridge is live (rpc_vm_start_listener) the guest keeps ONE
    persistent runspace, so variables / connected RPC clients survive across calls.
    The vmrun file-copy fallback is stateless (fresh guest shell per call). The
    response carries a `stateful` flag so you can tell which transport was used."""
    return _vm_post(ps, timeout=min(max(timeout, 5), 900), vm=vm or _DEFAULT_VM)


@tool
def rpc_vm_start_listener(vm: str = "") -> dict:
    """Deploy/start the PowerShell HTTP bridge listener inside a VM (idempotent):
    copies vm_listener.ps1 via vmrun, adds URLACL + firewall rule, starts listener.
    The listener keeps ONE persistent guest runspace, so rpc_vm_exec state (variables,
    connected RPC clients) survives across calls. If an OLDER listener is already
    running it is NOT replaced - stop it first (rpc_vm_exec a Stop-Process over
    CommandLine matching *vm_listener.ps1*), then call this again to redeploy."""
    name = vm or _DEFAULT_VM
    info = _VMS.get(name)
    if not info:
        return {"ok": False, "error": f"unknown vm {name!r} (known: {sorted(_VMS)})"}
    vmx = info["vmx"]
    here = os.path.dirname(os.path.abspath(__file__))
    listener = os.path.join(here, "vm_listener.ps1")
    if not os.path.isfile(listener):
        return {"ok": False, "error": f"vm_listener.ps1 missing next to server.py: {listener}"}
    auth = ["-gu", info["user"], "-gp", info["pass"]]
    powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    bootstrap = (
        "$running = @(Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | "
        "Where-Object { $_.CommandLine -like '*vm_listener.ps1*' })\r\n"
        "if (-not (Test-Path C:\\rpcmcp)) { New-Item -ItemType Directory C:\\rpcmcp -Force | Out-Null }\r\n"
        "netsh http add urlacl url=http://+:8765/rpcmcp/ user=Everyone 2>$null | Out-Null\r\n"
        "netsh advfirewall firewall delete rule name=RpcMcpBridge 2>$null | Out-Null\r\n"
        "netsh advfirewall firewall add rule name=RpcMcpBridge dir=in action=allow protocol=TCP localport=8765 | Out-Null\r\n"
        "if ($running.Count) { $status = 'already-running' } else {\r\n"
        "  Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\\rpcmcp\\vm_listener.ps1' -WindowStyle Hidden\r\n"
        "  $status = 'started'\r\n"
        "}\r\n"
        "$status | Out-File C:\\rpcmcp\\boot.status -Encoding ascii\r\n"
    )
    out_dir = os.path.join(here, "output")
    os.makedirs(out_dir, exist_ok=True)
    local_boot = os.path.join(out_dir, "vm_bootstrap.ps1")
    local_status = os.path.join(out_dir, "vm_boot.status")
    with open(local_boot, "w", encoding="utf-8-sig") as fh:
        fh.write(bootstrap)
    try:
        for local_path, guest_path in ((listener, r"C:\rpcmcp\vm_listener.ps1"), (local_boot, r"C:\rpcmcp\bootstrap.ps1")):
            cp = subprocess.run([_VMRUN, "-T", "ws", *auth, "CopyFileFromHostToGuest", vmx, local_path, guest_path],
                                capture_output=True, timeout=300)
            if cp.returncode != 0:
                return {"ok": False, "error": f"copy-in failed for {os.path.basename(local_path)}: {cp.stderr.decode(errors='replace')[:200]}"}
        subprocess.run([_VMRUN, "-T", "ws", *auth, "runProgramInGuest", vmx,
                        powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", r"C:\rpcmcp\bootstrap.ps1"],
                       capture_output=True, timeout=300)
        subprocess.run([_VMRUN, "-T", "ws", *auth, "CopyFileFromGuestToHost", vmx, r"C:\rpcmcp\boot.status", local_status],
                       capture_output=True, timeout=300)
        status = ""
        if os.path.isfile(local_status):
            with open(local_status, encoding="utf-8-sig", errors="replace") as fh:
                status = fh.read().strip()
        return {"ok": True, "vm": name, "status": status or "started"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


try:
    import local_tools as _local_tools

    class _LocalNS:
        pass

    _ns = _LocalNS()
    _ns.tool = tool
    _ns.run = _run
    _ns.snippets = S
    _ns.prefix_for = _prefix_for
    _ns.scan_context_handles = rpc_scan_context_handles
    _local_tools.register(_ns)
except ImportError:
    pass


if __name__ == "__main__":
    mcp.run(transport="stdio")
