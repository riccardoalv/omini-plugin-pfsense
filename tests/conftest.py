import json
import types
from functools import partial
from pathlib import Path

import httpx
import pytest

import omini_pfsense.collect as collect_module
from omini_pfsense.client import Client

FIXTURES = Path(__file__).parent / "fixtures"

# 60 s after the phone's last WireGuard handshake in the fixtures.
NOW = 1791374400


def error(code: int, status: str, response_id: str, message: str) -> httpx.Response:
    """An error in the REST API's envelope."""
    body = {"code": code, "status": status, "response_id": response_id, "message": message}
    return httpx.Response(code, json={**body, "data": [], "_links": {}})


class FakePfSense:
    """Answers like pfSense Plus 24.03 with the REST API package v2, from the
    JSON files in fixtures/ (shaped like the package's OpenAPI schema)."""

    def __init__(self):
        self.routes = {}
        self.forbidden = set()
        self.missing_package = set()
        self.calls = []
        self.key = "0123456789abcdef"
        for f in FIXTURES.glob("*.json"):
            self.routes["/api/v2/" + f.stem.replace("__", "/")] = json.loads(f.read_text())

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append((request.method, request.url.path))
        if request.headers.get("x-api-key") != self.key:
            return error(401, "unauthorized", "AUTH_AUTHENTICATION_FAILED", "Authentication failed")
        path = request.url.path
        if any(path.startswith(p) for p in self.forbidden):
            return error(403, "forbidden", "AUTH_INSUFFICIENT_PRIVILEGES", "Not authorized")
        if any(path.startswith(p) for p in self.missing_package):
            return error(424, "failed dependency", "MODEL_MISSING_REQUIRED_PACKAGE", "Missing")
        if path not in self.routes:
            return error(404, "not found", "ENDPOINT_NOT_FOUND", "Endpoint not found")
        return httpx.Response(200, json=self.routes[path])


@pytest.fixture
def pfsense(monkeypatch):
    fake = FakePfSense()
    monkeypatch.setattr(
        collect_module, "Client", partial(Client, transport=httpx.MockTransport(fake.handler))
    )
    monkeypatch.setattr(collect_module, "time", types.SimpleNamespace(time=lambda: NOW))
    return fake


@pytest.fixture
def cfg():
    from omini_sdk import Config

    return Config({"url": "https://192.168.1.1", "api_key": "0123456789abcdef"})
