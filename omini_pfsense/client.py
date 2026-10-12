"""Minimal client for the pfSense REST API package v2 (https://pfrest.org/).

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


class Forbidden(Exception):
    """The API user lacks the privilege for an endpoint (403)."""

    def __init__(self, path: str, method: str = "GET"):
        super().__init__(path)
        self.path, self.method = path, method

    @property
    def privilege(self) -> str:
        """The package's name for the missing privilege."""
        return f"REST API - {self.path} {self.method}"


class NotFound(Exception):
    """The endpoint does not exist on this package version (404, or 405 for a
    method it does not have yet), the object asked for does not exist (404), or
    it needs a package that is not installed, e.g. WireGuard (424)."""


class Client:
    def __init__(
        self,
        url: str,
        key: str,
        verify_tls: bool = False,
        timeout: float = 10,
        transport: httpx.BaseTransport | None = None,
    ):
        url = url.strip().rstrip("/")
        if not url.startswith(("https://", "http://")):
            url = "https://" + url
        self.base = url
        self.http = httpx.Client(
            base_url=url,
            verify=verify_tls,
            timeout=timeout,
            headers={
                "Accept": "application/json",
                "User-Agent": "omini-plugin-pfsense",
                "X-API-Key": key,
            },
            transport=transport,
        )

    def close(self) -> None:
        self.http.close()

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return self.request("POST", path, body=body or {})

    def patch(self, path: str, body: dict[str, Any]) -> Any:
        return self.request("PATCH", path, body=body)

    def delete(self, path: str, params: dict[str, Any]) -> Any:
        return self.request("DELETE", path, params=params)

    def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        try:
            r = self.http.request(method, path, params=params, json=body)
        except httpx.ConnectError as e:
            raise PluginError(f"cannot connect to {self.base}: {e}") from e
        except httpx.TimeoutException as e:
            raise PluginError(f"{self.base} did not answer in time") from e
        except httpx.HTTPError as e:
            raise PluginError(f"request to {self.base} failed: {e}") from e
        if r.status_code == 401:
            raise PluginError(
                "pfSense rejected the API key (check the key, and that 'API Key' is one of the "
                "authentication methods in System → REST API → Settings)"
            )
        if r.status_code == 403:
            raise Forbidden(path, method)
        if r.status_code in (404, 424) or (r.status_code == 405 and method != "GET"):
            raise NotFound(path)
        if r.status_code >= 400:
            if method != "GET":
                # A refused change: pfSense says why (a field it does not accept…).
                raise PluginError(f"pfSense refused {method} {path}: {message(r)}")
            raise PluginError(f"pfSense answered {r.status_code} for {path}")
        try:
            body = r.json()
        except json.JSONDecodeError as e:
            raise PluginError(
                f"{self.base} did not answer with JSON: is it pfSense with the REST API package?"
            ) from e
        if not isinstance(body, dict) or "data" not in body:
            raise PluginError(f"{self.base} gave an unexpected answer for {path}")
        return body["data"]


def message(r: httpx.Response) -> str:
    """The package's own words for an error (its envelope's message)."""
    try:
        body = r.json()
    except json.JSONDecodeError:
        return f"HTTP {r.status_code}"
    msg = body.get("message") if isinstance(body, dict) else None
    return str(msg).strip() if msg else f"HTTP {r.status_code}"
