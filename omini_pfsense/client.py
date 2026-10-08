"""Minimal client for the pfSense REST API package v2 (https://pfrest.org/).

Every request is a GET authenticated with the ``X-API-Key`` header. Answers
come in an envelope ``{code, status, response_id, message, data}``; the
client returns ``data``.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from omini_sdk import PluginError


class Forbidden(Exception):
    """The API user lacks the privilege for an endpoint (403)."""


class NotFound(Exception):
    """The endpoint does not exist on this package version (404), or needs a
    package that is not installed, e.g. WireGuard (424)."""


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
        try:
            r = self.http.get(path, params=params)
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
            raise Forbidden(path)
        if r.status_code in (404, 424):
            raise NotFound(path)
        if r.status_code >= 400:
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
