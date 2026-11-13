import base64
import json

import pytest
import requests
from requests.adapters import BaseAdapter

from pyngen import Ngen

BASE = "https://ngen.test"


class FakeAdapter(BaseAdapter):
    """Answers from a {(METHOD, path): handler} table and records every request."""

    def __init__(self, routes):
        super().__init__()
        self.routes = routes
        self.calls = []

    def send(self, request, **kwargs):
        self.calls.append(request)
        path = requests.utils.urlparse(request.url).path
        handler = self.routes.get((request.method, path))
        if handler is None:
            status, body = 404, {"detail": "not found"}
        else:
            status, body = handler(request)
        if isinstance(body, Exception):
            raise body
        response = requests.Response()
        response.status_code = status
        response.url = request.url
        response.request = request
        if isinstance(body, bytes):
            response._content = body
        else:
            response._content = b"" if body is None else json.dumps(body).encode()
        return response

    def close(self):
        pass

    def paths(self):
        return [(c.method, requests.utils.urlparse(c.url).path) for c in self.calls]


def make_client(routes, **kwargs):
    kwargs.setdefault("token", "secret")
    ngen = Ngen(BASE, **kwargs)
    adapter = FakeAdapter(routes)
    ngen.session.mount(BASE, adapter)
    return ngen, adapter


def jwt(exp):
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return f"h.{payload}.s"


def paginated(items):
    return lambda r: (200, {"results": items, "next": None})


@pytest.fixture
def client():
    """``client(routes, **ngen_kwargs) -> (ngen, adapter)`` with a fake server."""
    return make_client


@pytest.fixture
def fake_server(monkeypatch):
    """
    ``fake_server(routes) -> adapter``: every Session created from now on
    (CLI, PyNgen, from_env...) answers from ``routes``.
    """
    def install(routes):
        adapter = FakeAdapter(routes)
        real = requests.Session

        class FakeSession(real):
            def __init__(self):
                super().__init__()
                self.mount(BASE, adapter)

        monkeypatch.setattr(requests, "Session", FakeSession)
        return adapter

    return install
