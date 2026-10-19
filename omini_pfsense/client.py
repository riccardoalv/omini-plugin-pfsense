"""Client for the pfSense REST API package v2 (https://pfrest.org/), on the
SDK's HTTP client: timeouts, retries, and errors that name the privilege a
refused endpoint needs.

Every request is authenticated with the ``X-API-Key`` header. Answers come in
an envelope ``{code, status, response_id, message, data}``; the client returns
``data``. Reads are ``GET``; the changes Omini applies use ``POST`` (create),
``PATCH`` (change) and ``DELETE`` (with the object's ``id`` in the query).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from omini_sdk import PluginError
from omini_sdk.http import Client as HttpClient
from omini_sdk.http import Forbidden, NotFound, Unavailable

__all__ = ["Client", "Forbidden", "NotFound", "privilege"]


def privilege(method: str, path: str) -> str:
    """The package's name for the privilege of an endpoint and method."""
    return f"REST API - {path} {method}"


class Client(HttpClient):
    def __init__(
        self,
        url: str,
        key: str,
        verify_tls: bool = False,
        timeout: float = 15,
        transport: httpx.BaseTransport | None = None,
        sleep: Any = None,
    ):
        super().__init__(
            url,
            name="pfSense",
            verify_tls=verify_tls,
            timeout=timeout,
            headers={"X-API-Key": key},
            user_agent="omini-plugin-pfsense",
            unauthorized=(
                "pfSense rejected the API key (check the key, and that 'API Key' is one of the "
                "authentication methods in System → REST API → Settings)"
            ),
            forbidden_hint=privilege,
            transport=transport,
            sleep=sleep,
        )

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:  # type: ignore[override]
        return self.request("GET", path, params=params)

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:  # type: ignore[override]
        return self.request("POST", path, json=body or {})

    def patch(self, path: str, body: dict[str, Any]) -> Any:  # type: ignore[override]
        return self.request("PATCH", path, json=body)

    def delete(self, path: str, params: dict[str, Any]) -> Any:  # type: ignore[override]
        return self.request("DELETE", path, params=params)

    def request(self, method: str, path: str, **kw: Any) -> Any:
        body = super().request(method, path, **kw)
        if not isinstance(body, dict) or "data" not in body:
            raise PluginError(f"{self.base} gave an unexpected answer for {path}")
        return body["data"]

    def json(self, r: httpx.Response, path: str = "") -> Any:
        try:
            return r.json() if r.content else None
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise PluginError(
                f"{self.base} did not answer with JSON: is it pfSense with the REST API package?"
            ) from e

    def check(self, r: httpx.Response, method: str, path: str) -> None:
        """As the SDK's, and: a method the package does not have yet (405 for
        a change) or a package that is not installed, e.g. WireGuard (424),
        is NotFound; a change the firewall failed (5xx) says why."""
        status = r.status_code
        where = {"status": status, "method": method, "resource": path}
        if status == 424 or (status == 405 and method != "GET"):
            raise NotFound(f"pfSense has no {path}", **where)
        if status >= 500 and status != 503 and method != "GET":
            raise Unavailable(f"pfSense refused {method} {path}: {self.detail(r)}", **where)
        super().check(r, method, path)
