from __future__ import annotations

import hmac
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .errors import UAMError
from .gateway import MiddlewareGateway
from .mcp import MCPDispatcher, MCP_PROTOCOL_VERSION
from .openapi import schema as openapi_schema


class UAMHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address,
        handler,
        *,
        gateway: MiddlewareGateway,
        bearer_token: str,
        allowed_origins: set[str] | None = None,
    ):
        super().__init__(address, handler)
        self.gateway = gateway
        self.bearer_token = bearer_token
        self.allowed_origins = allowed_origins or set()
        self.mcp = MCPDispatcher(gateway)


class Handler(BaseHTTPRequestHandler):
    server: UAMHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, payload: dict[str, Any], *, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        expected = f"Bearer {self.server.bearer_token}"
        actual = self.headers.get("Authorization", "")
        return bool(self.server.bearer_token) and hmac.compare_digest(actual, expected)

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
        return False

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 1_000_000:
            raise UAMError("request body too large")
        raw = self.rfile.read(length)
        data = json.loads(raw or b"{}")
        if not isinstance(data, dict):
            raise UAMError("JSON body must be an object")
        return data

    @staticmethod
    def _one(qs: dict[str, list[str]], name: str, default: str | None = None) -> str | None:
        values = qs.get(name)
        return values[0] if values else default

    def _validate_mcp_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if origin and origin not in self.server.allowed_origins:
            self._json(HTTPStatus.FORBIDDEN, {"error": "invalid_origin"})
            return False
        return True

    def _mcp_header_error(
        self,
        request_id: str | int | None,
        message: str,
        code: int = -32020,
        data: Any = None,
    ) -> None:
        self._json(
            HTTPStatus.BAD_REQUEST,
            self.server.mcp.error(request_id, code, message, data),
        )

    def _validate_mcp_headers(self, body: dict[str, Any]) -> bool:
        request_id = body.get("id") if isinstance(body.get("id"), (str, int)) else None
        requested_version = self.headers.get("MCP-Protocol-Version")
        if requested_version != MCP_PROTOCOL_VERSION:
            self._mcp_header_error(
                request_id,
                "unsupported MCP-Protocol-Version",
                -32022,
                {
                    "supported": [MCP_PROTOCOL_VERSION],
                    "requested": requested_version,
                },
            )
            return False
        method = body.get("method")
        if self.headers.get("Mcp-Method") != method:
            self._mcp_header_error(request_id, "Mcp-Method does not match request body")
            return False
        expected_name = None
        params = body.get("params")
        if isinstance(params, dict) and method == "tools/call":
            expected_name = params.get("name")
        actual_name = self.headers.get("Mcp-Name")
        if expected_name is not None and actual_name != expected_name:
            self._mcp_header_error(request_id, "Mcp-Name does not match request body")
            return False
        if expected_name is None and actual_name:
            self._mcp_header_error(request_id, "unexpected Mcp-Name header")
            return False
        accept = self.headers.get("Accept", "")
        if "application/json" not in accept or "text/event-stream" not in accept:
            self._mcp_header_error(request_id, "Accept must include application/json and text/event-stream")
            return False
        return True

    def _validate_mcp_content_type(self) -> bool:
        media_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "unsupported_media_type"})
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/livez":
            return self._json(HTTPStatus.OK, {"status": "alive"})
        if parsed.path == "/readyz":
            try:
                g = self.server.gateway
                audit = g.audit.verify()
                if (not audit["valid"] or (audit["records"] and audit.get("schema_version") != 2)
                        or (g.audit.freeze_file and g.audit.freeze_file.exists())):
                    return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"status": "frozen"})
                g.registry.list()
                return self._json(HTTPStatus.OK, {"status": "ready"})
            except Exception:
                return self._json(
                    HTTPStatus.SERVICE_UNAVAILABLE, {"status": "not_ready"},
                )
        if parsed.path == "/status":
            import time
            try:
                g = self.server.gateway
                audit = g.audit.verify()
                if (not audit["valid"] or (audit["records"] and audit.get("schema_version") != 2)
                        or (g.audit.freeze_file and g.audit.freeze_file.exists())):
                    return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"status": "frozen"})
                ws = g.registry.list()
                import universal_agent_middleware
                return self._json(HTTPStatus.OK, {
                    "status": "ok",
                    "version": universal_agent_middleware.__version__,
                    "workspace_count": len(ws),
                    "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
            except Exception:
                return self._json(HTTPStatus.SERVICE_UNAVAILABLE, {
                    "status": "degraded",
                    "error": "health check failed",
                })
        if parsed.path == "/health":
            return self._json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "product": "universal-agent-middleware",
                    "mode": "target-workspace-read-only",
                    "protocols": ["http-openapi", f"mcp-{MCP_PROTOCOL_VERSION}"],
                },
            )
        if parsed.path == "/openapi.json":
            return self._json(HTTPStatus.OK, openapi_schema())
        if parsed.path == "/mcp":
            if not self._require_auth():
                return
            if not self._validate_mcp_origin():
                return
            self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if not self._require_auth():
            return
        qs = parse_qs(parsed.query)
        try:
            g = self.server.gateway
            if parsed.path == "/v1/workspaces":
                result = g.list_workspaces()
            elif parsed.path == "/v1/tree":
                result = g.tree(
                    self._one(qs, "workspace_id") or "",
                    self._one(qs, "path", ".") or ".",
                    int(self._one(qs, "depth", "3") or 3),
                )
            elif parsed.path == "/v1/git/status":
                result = g.git_status(self._one(qs, "workspace_id") or "")
            elif parsed.path == "/v1/git/diff":
                result = g.git_diff(
                    self._one(qs, "workspace_id") or "", self._one(qs, "path")
                )
            elif parsed.path == "/v1/git/log":
                result = g.git_log(
                    self._one(qs, "workspace_id") or "",
                    int(self._one(qs, "limit", "20") or 20),
                )
            elif parsed.path.startswith("/v1/contracts/"):
                result = g.get_contract(parsed.path.rsplit("/", 1)[-1])
            elif parsed.path.startswith("/v1/results/"):
                result = g.get_executor_result(parsed.path.rsplit("/", 1)[-1])
            elif parsed.path == "/v1/audit/verify":
                result = g.audit.verify()
            else:
                return self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            self._json(HTTPStatus.OK, result)
        except (UAMError, ValueError, json.JSONDecodeError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": type(exc).__name__, "message": str(exc)},
            )
        except Exception:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if not self._require_auth():
            return
        try:
            if parsed.path == "/mcp" and not self._validate_mcp_content_type():
                return
            body = self._body()
            if parsed.path == "/mcp":
                if not self._validate_mcp_origin():
                    return
                if not self._validate_mcp_headers(body):
                    return
                response = self.server.mcp.dispatch(body)
                error_code = response.get("error", {}).get("code")
                status = (
                    HTTPStatus.BAD_REQUEST
                    if error_code in {-32020, -32021, -32022}
                    else HTTPStatus.OK
                )
                return self._json(status, response)
            g = self.server.gateway
            if parsed.path == "/v1/read":
                result = g.read_file(
                    body.get("workspace_id", ""),
                    body.get("path", ""),
                    int(body.get("start_line", 1)),
                    body.get("end_line"),
                )
            elif parsed.path == "/v1/search":
                result = g.search(
                    body.get("workspace_id", ""),
                    body.get("query", ""),
                    body.get("path", "."),
                    int(body.get("max_results", 100)),
                )
            elif parsed.path == "/v1/contracts":
                result = g.create_contract(body)
            elif parsed.path == "/v1/results":
                result = g.record_executor_result(body)
            else:
                return self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            self._json(HTTPStatus.OK, result)
        except (UAMError, ValueError, json.JSONDecodeError) as exc:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {"error": type(exc).__name__, "message": str(exc)},
            )
        except Exception:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
