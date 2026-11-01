"""TEST STAND-IN authority for the Consumer's tests and scenario worlds. Not product, not an issuer, not a grant.

It checks only what the version-2 port carries: the binding digest can be recomputed from the request and the
authority reference starts with ``grant-``. It holds no policy, reads no OwnerScope and proves nothing about a real
authority; the real adapter (``local-owner-authority-r1``) needs a scope that is expired and is not touched here.

When ``log`` is given, every question is appended to that JSON-lines file with one ``O_APPEND`` write, so a
scenario can show that each effect of each process passed the port.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from universal_agent_middleware.task_continuity import compute_binding_digest
from universal_agent_middleware.task_control import AuthorityDecision, AuthorityRequest


class StandInAuthority:
    request_version = 2

    def __init__(self, log: str | None = None) -> None:
        self._log = Path(log) if log else None

    def verify(self, request: AuthorityRequest) -> AuthorityDecision:
        if request.request_version >= 2 and request.binding_digest != compute_binding_digest(request):
            decision = AuthorityDecision(False, "BINDING_NOT_VERIFIABLE")
        elif not request.authority_ref.startswith("grant-"):
            decision = AuthorityDecision(False, "REFERENCE_NOT_VALID")
        else:
            decision = AuthorityDecision(True, "TEST_STAND_IN")
        self._record(request, decision)
        return decision

    def _record(self, request: AuthorityRequest, decision: AuthorityDecision) -> None:
        if self._log is None:
            return
        line = json.dumps({
            "pid": os.getpid(), "effect": request.effect, "principal": request.principal,
            "delivery_id": request.delivery_id, "attempt_ref": request.attempt_ref,
            "business_task_ref": request.business_task_ref, "allowed": decision.allowed, "reason": decision.reason,
        }, sort_keys=True) + "\n"
        descriptor = os.open(self._log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(descriptor, line.encode("utf-8"))
        finally:
            os.close(descriptor)


def stand_in_authority(log: str | None = None) -> StandInAuthority:
    """The factory the Consumer's ``--authority-factory`` names."""
    return StandInAuthority(log)
