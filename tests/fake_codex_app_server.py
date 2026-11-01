"""FAKE Codex App Server for protocol tests of ``CodexAppServerClient`` / ``CodexAppServerAdapter``. NOT Codex.

It speaks just enough of the App Server's JSON-RPC over stdio (one JSON object per line, no ``jsonrpc`` member) to
exercise the client: ``initialize``, ``account/read``, ``thread/start``, ``thread/resume``, ``turn/start``,
``turn/interrupt``, ``mcpServerStatus/list`` and ``mcpServer/tool/call``. Nothing here is evidence about the real
server; the real one is run separately, with its own version, by the scenario scripts.

The client gives its child only ``PATH``, ``HOME``, ``CODEX_HOME`` and ``LANG``, so the behaviour is read from
``$CODEX_HOME/fake.json``: ``{"log": <JSON-lines file>, "account": "none"|"chatgpt", "turn": "complete"|"fail"|
"hang"|"approval", "cwd": <what thread/start answers instead of the requested cwd>, "omit_cwd": true,
"resume_lands_on": <thread id answered to thread/resume instead of the requested one>, "linger": <seconds the fake
stays alive after its stdin closed, like a server that outlives its Consumer>, "orphan": true (it starts a helper in
its own session that closing the server's process group does not reach)}``. Every request the fake receives is
appended to ``log``; the first entry carries the fake's own PID.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SETTINGS = json.loads((Path(os.environ["CODEX_HOME"]) / "fake.json").read_text(encoding="utf-8"))
LOG = SETTINGS.get("log")
ACCOUNT = SETTINGS.get("account", "none")
TURN = SETTINGS.get("turn", "complete")


def send(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def log(entry: dict[str, Any]) -> None:
    if LOG:
        with open(LOG, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")


def complete(thread_id: str, turn_id: str, status: str) -> None:
    send({"method": "turn/completed", "params": {"threadId": thread_id, "turn": {"id": turn_id, "status": status}}})


def thread_answer(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """What a real server answers to thread/start|resume: the thread and the directory it is bound to."""
    thread_id = params.get("threadId") or "thr-fake-1"
    if method == "thread/resume" and SETTINGS.get("resume_lands_on"):
        thread_id = SETTINGS["resume_lands_on"]
    answer: dict[str, Any] = {"thread": {"id": thread_id, "sessionId": f"sess-{thread_id}"}, "sandbox": params.get("sandbox"),
                              "approvalPolicy": params.get("approvalPolicy")}
    if not SETTINGS.get("omit_cwd"):
        cwd = SETTINGS.get("cwd") or params.get("cwd")
        answer["cwd"] = cwd
        answer["thread"]["cwd"] = cwd
    return answer


def main() -> int:
    log({"argv": sys.argv[1:], "codex_home": os.environ.get("CODEX_HOME"), "home": os.environ.get("HOME"), "pid": os.getpid()})
    if SETTINGS.get("orphan"):  # a helper in its own session: closing the server's process group does not reach it
        orphan = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(120)"], start_new_session=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        log({"orphan_pid": orphan.pid})
    for raw in sys.stdin:
        message = json.loads(raw)
        method, request_id, params = message.get("method"), message.get("id"), message.get("params") or {}
        if method is None:  # a reply to something the fake asked
            log({"reply_to_server_request": message})
            continue
        log({"method": method, "params": params})
        if request_id is None:
            continue
        if method == "initialize":
            send({"id": request_id, "result": {"userAgent": "fake-codex/0"}})
        elif method == "account/read":
            account = None if ACCOUNT == "none" else {"type": "chatgpt", "email": "fake@example.invalid", "planType": "plus"}
            send({"id": request_id, "result": {"account": account, "requiresOpenaiAuth": account is None}})
        elif method in ("thread/start", "thread/resume"):
            send({"id": request_id, "result": thread_answer(method, params)})
        elif method == "mcpServerStatus/list":
            send({"id": request_id, "result": {"data": [{"name": params.get("serverName"), "runtimeStatus": "connected", "tools": ["fake_tool"]}]}})
        elif method == "mcpServer/tool/call":
            send({"id": request_id, "result": {"content": [{"type": "text", "text": json.dumps({"echo": params.get("arguments")})}], "isError": False}})
        elif method == "turn/start":
            send({"id": request_id, "result": {"turn": {"id": "turn-fake-1", "status": "inProgress"}}})
            thread_id = params["threadId"]
            if TURN == "complete":
                complete(thread_id, "turn-fake-1", "completed")
            elif TURN == "fail":
                complete(thread_id, "turn-fake-1", "failed")
            elif TURN == "approval":
                send({"id": 900, "method": "item/commandExecution/requestApproval", "params": {"command": "rm -rf /"}})
                time.sleep(0.3)
                complete(thread_id, "turn-fake-1", "completed")
        elif method == "turn/interrupt":
            send({"id": request_id, "result": {}})
            complete(params["threadId"], params["turnId"], "interrupted")
        else:
            send({"id": request_id, "error": {"code": -32601, "message": f"unknown method {method}"}})
    if SETTINGS.get("linger"):
        time.sleep(float(SETTINGS["linger"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
