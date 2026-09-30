# 🛰️ NtObjectManager-MCP

### Stateful Windows RPC Research MCP — 2024–2026 CVE methodologies as one-click tools

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/windows-server/administration/windows-commands/powershell)
[![MCP](https://img.shields.io/badge/MCP-24%20tools-purple)](https://modelcontextprotocol.io)

🌐 **[中文版](README.zh-CN.md)**

---

## What is NtObjectManager-MCP?

A Model Context Protocol server that gives an AI agent **live, stateful access to Windows
RPC attack-surface research**, built on James Forshaw's
[NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager) (NtCoreLib).

Three things a generic PowerShell MCP cannot do — and the reason this exists:

1. **Stateful RPC connections** — a persistent PowerShell engine keeps parsed
   `RpcServer` objects and *connected RPC clients* alive across tool calls:
   `rpc_connect` once, `rpc_call` many times (auth handshakes, context-handle
   chains, session variables survive).
2. **CVE methodology as fixed tools** — the standard hunting workflows from
   2024–2026 public research are one-click, not prompt-engineering.
3. **Stateful execution inside a lab VM** — the same one-engine principle applied
   in the guest: `rpc_vm_exec` keeps variables and connected RPC clients alive
   across calls through a single persistent guest runspace, never a fresh shell
   per call (the vmrun fallback is reported as `stateful: false`).

```
┌────────────────────────────────────────────────────────────────────┐
│  AI Agent (Claude Code / OpenCode / any MCP client)                │
│      │  MCP (stdio, 24 tools)                                      │
│      ▼                                                             │
│  server.py ── snippets.py (PS templates, @@TOKEN@@ + ps_str escape)│
│      │                                                             │
│      ▼                                                             │
│  ps_engine.py ── persistent powershell.exe (base64 + __MCP_DONE__) │
│      │            state: $RPCMCP = @{ Servers; Clients; vars }     │
│      ▼                                                             │
│  NtObjectManager / NtCoreLib  ──►  RPC runtime (ALPC / pipe / TCP) │
└────────────────────────────────────────────────────────────────────┘
```

## Tool Matrix (24)

### Core stateful pipeline

| Tool | Purpose |
|------|---------|
| `rpc_parse(file, symbol_path?)` | Parse a PE for RPC servers, cache (keys `file_N`) |
| `rpc_state()` | Cached servers + live sessions |
| `rpc_get_interface(key)` | Procedures, NDR params, context handles, strictness |
| `rpc_query_endpoints(ifid?, search_binding?, find_alpc_port?)` | EPM query (local **or remote**) |
| `rpc_running_servers(pid?/service?)` | Live process/service enumeration |
| `rpc_connect(session, key, binding?, auth?)` | Generate + **connect** client (stateful) |
| `rpc_methods(session)` | Signatures **with opnum mapping** |
| `rpc_call(session, method, args_json, store_as?)` | Reflection invoke; `{"__var__"}` passes stored objects |
| `rpc_disconnect(session)` | Drop session |

### VM lab bridge (stateful guest execution)

| Tool | Purpose |
|------|---------|
| `rpc_vm_exec(ps, timeout?, vm?)` | Run PowerShell inside a lab VM; state survives across calls (persistent guest runspace) |
| `rpc_vm_start_listener(vm?)` | Deploy/start the persistent guest HTTP engine (`vm_listener.ps1`) |

### 2024–2026 CVE methodology tools

| Tool | Methodology source |
|------|-------------------|
| `rpc_scan_context_handles(paths)` | Context-handle type confusion — CVE-2025-48815 pattern (whereisk0shl 2026) |
| `rpc_inventory(paths?, limit?)` | Attack-surface inventory + EPM cross-check — MS-RPC-Fuzzer phase 1 (CVE-2025-26651) |
| `rpc_fuzz(session, dry_run=True)` | Primitive-only default-value fuzzing with ok/denied/error classification — **dry-run by default** |
| `rpc_find_hijackable()` | Unregistered interfaces of stopped services — EPM poisoning / RPC-Racer (CVE-2025-49760/59200/59230) |
| `rpc_etw_unreachable(duration, trigger_script?)` | Clients calling dead servers — PhantomRPC (Kaspersky 2026), admin required |
| `rpc_interface_security(key)` | ALPC SD / anonymous-ACE audit — MS-NRPC null session (SafeBreach/Securelist 2025) |
| `rpc_decode_flags(flags)` | `RpcServerRegisterIf3` flag bitmask decoding |
| `rpc_format_client(key)` | Export generated C# client source (offline grep workflow) |
| `rpc_new_struct(session, type, store_as)` | Build NDR complex types as session vars |
| `rpc_alpc_squat(name, duration)` | ALPC port squat + connection capture (race validation primitive) |
| `rpc_accessible_tasks()` | User-startable tasks (Dark-Elevator chain material, CVE-2026-66804 pattern) |
| `rpc_vars` / `rpc_clear_cache` | Session-variable and cache management (eviction cap 150) |

Every tool call is appended to `output/mcp_audit.log`.

## Field-Tested (real machine, full hunting round)

| Candidate | Result |
|-----------|--------|
| `srvsvc.dll 98716d03…` flagged HIGH | Identified as **XactSrv** (XsOpenPrinter/XsClosePrinter/XsAddJob/XsScheduleJob) — single printer-handle type; live probe: non-admin connect OK but `XsOpenPrinter` → **ACCESS_DENIED** (authorization gate works). Scanner false-positive mode documented |
| `ssdpsrv.dll` (CVE-2025-48815 original) | All 20 context handles **strict** — patched state on current builds |
| 51-module sweep | 31 findings, 6 HIGH, all "one producer → many consumers"; NDR layer cannot prove multi-*type* handles (needs RE) |
| EPM hijack surface | 10 stopped services with unregistered interfaces (AppIDSvc, ClipSVC, dcsvc…) |
| Task chains | 44 user-startable SYSTEM tasks inventoried |
| **Verdict** | No confirmable exploitable vuln on the tested host — with per-step evidence |

## 🚀 Quick Start

```powershell
# 1) Prerequisites (one-time)
Install-Module NtObjectManager -Scope CurrentUser -Force
pip install -r requirements.txt            # mcp>=1.2.0 (1.x / 2.x compatible)

# 2) Verify — three suites, all green
python tests\smoke_test.py                 # 17 checks (live MCP stdio round-trip)
python tests\var_test.py                   # 10 checks (store_as / __var__ mechanics)
python tests\audit.py                      # 43 checks (edge cases, hostile paths, concurrency)

# 3) Run the server
python server.py                           # stdio MCP
```

**Claude Code:**

```bash
claude mcp add ntobjectmanager-rpc -- python C:\path\to\ntobjmanager-mcp\server.py
```

**Any MCP client** (e.g. OpenCode `opencode.json`):

```json
{
  "mcp": {
    "ntobjectmanager-rpc": {
      "type": "local",
      "command": ["python", "C:\\path\\to\\ntobjmanager-mcp\\server.py"],
      "enabled": true
    }
  }
}
```

## Example: context-handle type confusion (CVE-2025-48815 pattern)

```
1. rpc_parse  C:\Windows\System32\target.dll  [symbol_path optional]
2. rpc_scan_context_handles ["C:\\Windows\\System32\\target.dll"]
3. rpc_get_interface target_0                 → producer ([out] ctx) / consumer ([in] ctx) pairs
4. rpc_connect s1 target_0                    → auto-discovers binding via EPM
5. rpc_methods s1                            → opnum-mapped signatures
6. rpc_call s1 XsOpenPrinter-like args store_as="h"   → keep the raw handle object
7. rpc_call s1 XsClosePrinter-like [{"__var__":"h"}] → feed it to the other type
```

`store_as` / `{"__var__"}` is the core chain primitive: RPC return objects flow
between calls **without serialization round-trips**, which is exactly what
producer→consumer handle-confusion testing needs.

## 📁 Project Structure

```
ntobjmanager-mcp/
├── server.py            # 24 MCP tools + audit logging wrapper
├── snippets.py          # PowerShell templates (@@TOKEN@@ render + ps_str escaping)
├── ps_engine.py         # Persistent engine: base64 cmds + __MCP_DONE__ markers, timeouts
├── wrapper.ps1          # PS-side loop (state lives in $RPCMCP)
├── vm_listener.ps1      # Persistent guest HTTP bridge (stateful VM exec)
├── tests/
│   ├── smoke_test.py    # 17 checks — live stdio end-to-end
│   ├── var_test.py      # 10 checks — store_as/__var__ object passing
│   ├── audit.py         # 43 checks — hostile inputs, concurrency, engine kill/restart
│   ├── hunt.py          # Full dogfood hunting round (safe policy)
│   ├── hunt2_static.py  # Deep-dive: symbols + producer/consumer map
│   ├── hunt2_wide.py    # 51-module sweep
│   └── hunt2_probe.py   # Safe runtime probes (exposure / task cross-ref)
├── ARCHITECTURE.md      # Engine protocol + design decisions
├── CHANGELOG.md         # Decision history (R1–R13)
├── SECURITY.md          # Authorized-use policy + MSRC disclosure
├── CONTRIBUTING.md      # Development invariants
└── LICENSE              # MIT
```

## 🛡️ Honest Capability Boundaries

| Claim | Status |
|-------|--------|
| Stateful clients across tool calls | Yes — persistent engine + `$RPCMCP` |
| Stateful execution inside a lab VM | Yes — one persistent guest runspace (`rpc_vm_exec`); the vmrun fallback is stateless |
| Context-handle chaining (producer → consumer) | Yes — `store_as` / `__var__` raw-object passing |
| Auto-confirm type confusion | **No** — NDR cannot prove distinct handle *types*; verify via RE (see XactSrv case) |
| Full rogue-RPC hosting | **No** — NtObjectManager 2.0.1 ships no server builder; `rpc_alpc_squat` covers race-capture only |
| ETW tracing / ALPC SDDL | Requires **admin** (logman / SeDebugPrivilege) |
| Symbol-resolved procedure names | Environment-dependent (symsrv chain); heuristic fallback names otherwise |
| Runs anywhere but Windows PS 5.1 | Not yet (pwsh 7 untested) |

## 📖 Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — engine protocol, state model, design decisions
- [CHANGELOG.md](CHANGELOG.md) — R1–R13 decision history incl. two PS 5.1 marshaling bugs
- [SECURITY.md](SECURITY.md) — authorized use, VM isolation, MSRC disclosure
- [CONTRIBUTING.md](CONTRIBUTING.md) — development invariants and test requirements

## ⚠️ Disclaimer

For **lawful security research, education, and authorized testing only**.
`rpc_call` invokes real RPC methods and can crash services — run it against an
**isolated VM**, never a production or daily-driver host. Vulnerabilities found
through this tool must follow responsible disclosure (MSRC).

## 📄 License

[MIT](LICENSE) — Copyright (c) 2026 ntobjmanager-mcp Contributors
