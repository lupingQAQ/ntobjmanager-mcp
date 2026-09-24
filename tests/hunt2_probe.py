"""Hunt phase 2C (safe probes, fixed): XactSrv exposure + SYSTEM-task cross-reference."""

from __future__ import annotations

import csv
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server as M

out: dict = {}

print("== A. XactSrv exposure probe (non-admin user) ==")
pr = M.rpc_parse(file_path=r"C:\Windows\System32\srvsvc.dll")
tgt = [s for s in pr.get("servers", []) if s.get("interface_id", "").startswith("98716d03")]
key = tgt[0]["key"]
cn = M.rpc_connect(session="xact", server_key=key)
if "error" in cn:
    out["connect"] = cn
    print("connect failed:", cn.get("error"))
else:
    mm = M.rpc_methods(session="xact")
    by_opnum = {m["opnum"]: m for m in mm.get("methods", []) if m.get("opnum") is not None}
    open_m = by_opnum.get(0)
    close_m = by_opnum.get(1)
    print(f"open(opnum0)={open_m['name'] if open_m else None}  close(opnum1)={close_m['name'] if close_m else None}")

    ns = M.rpc_new_struct(session="xact", type_name="Struct_0", store_as="pname", fields_json="{}")
    print(f"Struct_0 built: {json.dumps(ns)[:200]}")
    args = [{"__var__": "pname"}, 0] if "error" not in ns else ["", 0]
    r0 = M.rpc_call(session="xact", method=open_m["name"], args_json=json.dumps(args), store_as="xh")
    print(f"XsOpenPrinter(<empty name>): {json.dumps(r0)[:400]}")
    out["open"] = r0
    if r0.get("stored_as") and close_m:
        r1 = M.rpc_call(session="xact", method=close_m["name"], args_json=json.dumps([{"__var__": "xh"}, 0]), store_as="cl")
        print(f"XsClosePrinter(handle): {json.dumps(r1)[:300]}")
        out["close"] = r1
    M.rpc_disconnect(session="xact")

print("\n== B. accessible tasks x SYSTEM-run cross-reference ==")
res = subprocess.run(
    ["schtasks", "/query", "/fo", "csv", "/v"],
    capture_output=True, text=True, encoding="mbcs", errors="replace", check=False,
)
rows = list(csv.reader(res.stdout.splitlines()))
if not rows:
    print("schtasks returned nothing:", res.stderr[:200])
else:
    hdr = rows[0]
    idx = {h.strip(): i for i, h in enumerate(hdr)}
    name_i = idx.get("TaskName", 1)
    run_i = idx.get("Run As User", len(hdr) - 1)
    act_i = idx.get("Task To Run", len(hdr) - 1)
    svc_users = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
    system_tasks = []
    for r in rows[1:]:
        if len(r) > max(name_i, run_i) and r[run_i].strip().upper() in svc_users:
            system_tasks.append(
                {"name": r[name_i].strip().lstrip("\\"), "run_as": r[run_i].strip(), "action": r[act_i].strip()[:140] if len(r) > act_i else ""}
            )
    print(f"service-run tasks total: {len(system_tasks)}")
    acc = M.rpc_accessible_tasks()
    acc_names = {t.get("Name", "").lstrip("\\").lower() for t in acc.get("tasks", [])}
    both = [t for t in system_tasks if t["name"].lower() in acc_names]
    out["user_accessible_service_tasks"] = both
    print(f"user-accessible AND service-run: {len(both)}")
    for t in both[:20]:
        print(f"   - {t['name']}  run_as={t['run_as']}  action={t['action'][:90]}")

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs(os.path.join(root, "output"), exist_ok=True)
with open(os.path.join(root, "output", "hunt2_probe.json"), "w", encoding="utf-8") as fh:
    json.dump(out, fh, ensure_ascii=False, indent=1, default=str)
print("\nreport -> output/hunt2_probe.json")
