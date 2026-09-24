"""Persistent PowerShell engine for the NtObjectManager MCP server.

Keeps one powershell.exe process alive for the whole MCP session so that
state (parsed RpcServer objects, connected RPC clients) survives across
tool calls. Commands are base64-encoded scripts; results come back over
stdout terminated by a marker line; non-terminating errors go to stderr.
"""

from __future__ import annotations

import base64
import os
import queue
import subprocess
import threading
import time
from typing import Any, Optional

MARKER_DONE = "__MCP_DONE__"
MARKER_ERR_PREFIX = "__MCP_ERR__"


class EngineError(RuntimeError):
    pass


class EngineDeadError(EngineError):
    pass


class EngineTimeoutError(EngineError):
    pass


class PowerShellEngine:
    """One long-lived powershell.exe process with marker-framed commands."""

    def __init__(self, ps_exe: Optional[str] = None, init_script: str = "") -> None:
        self._here = os.path.dirname(os.path.abspath(__file__))
        wrapper = os.path.join(self._here, "wrapper.ps1")
        exe = ps_exe or "powershell.exe"
        self.proc = subprocess.Popen(
            [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-STA", "-File", wrapper],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=self._here,
        )
        self._out_q: "queue.Queue[Optional[str]]" = queue.Queue()
        self._err_q: "queue.Queue[str]" = queue.Queue()
        self._alive = True
        self._lock = threading.Lock()
        self.last_stderr: list[str] = []
        self._readers = [
            threading.Thread(target=self._read_stdout, daemon=True),
            threading.Thread(target=self._read_stderr, daemon=True),
        ]
        for t in self._readers:
            t.start()
        self.init_result: dict[str, Any] = {}
        if init_script:
            self.init_result = self.call_json(init_script, timeout=180) or {}

    # ------------------------------------------------------------------ io

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._out_q.put(line.rstrip("\r\n"))
        self._alive = False
        self._out_q.put(None)

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self._err_q.put(line.rstrip("\r\n"))

    def _drain_stderr(self) -> list[str]:
        out: list[str] = []
        while True:
            try:
                out.append(self._err_q.get_nowait())
            except queue.Empty:
                return out

    # -------------------------------------------------------------- execute

    def execute(self, script: str, timeout: float = 120.0) -> dict[str, Any]:
        """Run one PowerShell script; return {ok, output, error, stderr}."""
        with self._lock:
            if not self._alive:
                raise EngineDeadError("PowerShell engine process is dead")
            assert self.proc.stdin is not None
            cmd = base64.b64encode(script.encode("utf-8")).decode("ascii")
            self.proc.stdin.write(cmd + "\n")
            self.proc.stdin.flush()

            lines: list[str] = []
            error: Optional[str] = None
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._kill()
                    raise EngineTimeoutError(
                        f"PowerShell command exceeded {timeout:.0f}s; engine was killed and all "
                        "state (parsed servers, sessions) is lost. Recreate state with rpc_parse."
                    )
                try:
                    line = self._out_q.get(timeout=min(remaining, 0.5))
                except queue.Empty:
                    if not self._alive:
                        raise EngineDeadError("PowerShell engine exited unexpectedly")
                    continue
                if line is None:
                    raise EngineDeadError("PowerShell engine exited unexpectedly")
                if line == MARKER_DONE:
                    break
                if line.startswith(MARKER_ERR_PREFIX):
                    error = line[len(MARKER_ERR_PREFIX):].strip()
                    continue
                lines.append(line)
            stderr_tail = self._drain_stderr()
            self.last_stderr = stderr_tail[-20:]
            return {
                "ok": error is None,
                "output": "\n".join(lines).strip(),
                "error": error,
                "stderr": stderr_tail,
            }

    def call_json(self, script: str, timeout: float = 120.0) -> dict[str, Any]:
        """Run a script that is expected to emit one JSON object."""
        res = self.execute(script, timeout=timeout)
        if not res["ok"]:
            return {"ok": False, "error": res["error"] or "unknown PowerShell error", "stderr": res["stderr"][-5:]}
        raw = res["output"]
        if not raw:
            return {"ok": True, "result": None}
        import json

        try:
            parsed = json.loads(raw)
        except ValueError:
            return {"ok": False, "error": f"non-JSON output from PowerShell: {raw[:400]!r}"}
        if isinstance(parsed, dict):
            parsed.setdefault("ok", True)
            if res["stderr"]:
                parsed.setdefault("stderr_tail", res["stderr"][-3:])
            return parsed
        return {"ok": True, "result": parsed}

    # -------------------------------------------------------------- lifecycle

    def _kill(self) -> None:
        try:
            self.proc.kill()
        except OSError:
            pass
        self._alive = False

    @property
    def alive(self) -> bool:
        return self._alive
