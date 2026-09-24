"""Verify rpc_call store_as / __var__ object-passing mechanics without touching real RPC.

A DateTime object stands in for a generated client (same reflection path in CALL):
  1. ToOADate() -> double, stored as var 'days'
  2. AddDays({"__var__":"days"}) -> DateTime one day later  => object flowed var->arg
  3. unknown __var__ -> structured error
  4. rpc_methods IsSpecialName filter -> no get_/set_ accessors listed
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import snippets as S
from ps_engine import PowerShellEngine

FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global FAIL
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"  detail: {detail[:250]}" if not cond else ""))
    if not cond:
        FAIL += 1


eng = PowerShellEngine(init_script=S.INIT)
check("engine init ready", eng.init_result.get("ready") is True)

# fake session with a DateTime 'client' + vars container, mirroring CONNECT's structure
r = eng.execute(
    r"$RPCMCP.Clients['t1'] = @{ client = [datetime]::Now; key = 'k'; interface = 'i'; binding = 'b'; connected_at = 'now'; vars = @{} }; 'ok'",
    timeout=30,
)
check("fake session installed", r.get("ok") is True and "ok" in r.get("output", ""), str(r))

base = float(eng.execute("[datetime]::Now.ToOADate()", timeout=30)["output"])
print(f"      baseline OADate = {base}")

r1 = eng.call_json(
    S.render(S.CALL, SESSION="'t1'", METHOD="'ToOADate'", ARGS="'[]'", STOREAS="'days'"),
    timeout=60,
)
check("call ToOADate + store_as='days'", r1.get("stored_as") == "days", json.dumps(r1)[:200])
val = r1.get("result")
check("stored value serializes to the OADate double", isinstance(val, (int, float)) and abs(float(val) - base) < 0.01, f"got {val!r}")

r2 = eng.call_json(
    S.render(S.CALL, SESSION="'t1'", METHOD="'AddDays'", ARGS='\'[{"__var__":"days"}]\'', STOREAS="$null"),
    timeout=60,
)
check("AddDays(__var__ days) invoked via reflection", "error" not in r2, json.dumps(r2)[:250])
if "error" not in r2:
    import re as _re

    stored_days_span_126_years = 2100
    m = _re.search(r"(\d{4})", str(r2.get("result", "")))
    year = int(m.group(1)) if m else 0
    check(
        "__var__ object flowed into method (date advanced ~126y)",
        year > stored_days_span_126_years,
        f"result={r2.get('result')!r}",
    )

r3 = eng.call_json(
    S.render(S.CALL, SESSION="'t1'", METHOD="'AddDays'", ARGS='\'[{"__var__":"nope"}]\'', STOREAS="$null"),
    timeout=60,
)
check("unknown __var__ -> structured error", "unknown stored var" in str(r3.get("error", "")), json.dumps(r3)[:200])

r4 = eng.call_json(S.render(S.METHODS, SESSION="'t1'"), timeout=60)
names = [m.get("name") for m in r4.get("methods", [])]
check("rpc_methods excludes property accessors (get_/set_)", not any(str(n).startswith(("get_", "set_")) for n in names), str(names[:15]))
check("rpc_methods still lists real methods", any(n in names for n in ("ToOADate", "AddDays", "ToFileTime")), str(names[:15]))

st = eng.call_json(S.STATE, timeout=30)
sess = [s for s in st.get("sessions", []) if s.get("session") == "t1"]
check("rpc_state exposes session vars", sess and "days" in (sess[0].get("vars") or []), json.dumps(st)[:200])

try:
    eng.proc.kill()
except OSError:
    pass
print(f"\n== {'ALL PASS' if FAIL == 0 else str(FAIL) + ' FAILED'} ==")
sys.exit(1 if FAIL else 0)
