import ipaddress
import itertools
import json

import pytest
import requests

from pyngen.resources import address_filter
from pyngen.seed import DOMAIN, RANGES, clean, seed
from conftest import BASE, make_client

pytest.importorskip("faker")

CATALOGS = {
    "/api/taxonomy/": [{"url": f"{BASE}/api/taxonomy/1/", "slug": "malware", "active": True}],
    "/api/administration/feed/": [{"url": f"{BASE}/api/administration/feed/1/", "active": True}],
    "/api/administration/priority/": [{"url": f"{BASE}/api/administration/priority/1/"}],
    "/api/administration/tlp/": [{"url": f"{BASE}/api/administration/tlp/1/"}],
    "/api/state/": [{"url": f"{BASE}/api/state/1/", "active": True}],
}


class FakeNgen:
    """Keeps what is POSTed and answers lists from it, unfiltered except for a few keys."""

    def __init__(self):
        self.store = {}
        self.ids = itertools.count(1)
        self.deleted = []

    def routes(self):
        routes = {("GET", path): self.catalog(items) for path, items in CATALOGS.items()}
        for name in ("entity", "contact", "network", "event", "case"):
            path = f"/api/{name}/"
            self.store[path] = []
            routes[("POST", path)] = self.create(path)
            routes[("GET", path)] = self.list(path)
        return routes

    def catalog(self, items):
        return lambda r: (200, {"results": items, "next": None})

    def create(self, path):
        def handler(request):
            if "json" in request.headers.get("Content-Type", ""):
                fields = json.loads(request.body)
            else:  # multipart: only what the tests look at
                body = request.body.decode(errors="ignore")
                fields = {"address_value": body.split('name="address_value"\r\n\r\n')[1].split("\r\n")[0]}
                fields["tags"] = ["seed"] if 'name="tags"\r\n\r\nseed' in body else []
                fields["evidence"] = 'name="evidence"' in body
            item = {**fields, "url": f"{BASE}{path}{next(self.ids)}/", "case": None}
            if "address_value" in fields:  # Ngen answers with the parsed address
                item.update(address_filter(fields["address_value"]))
            self.store[path].append(item)
            return 201, item

        return handler

    def list(self, path):
        def handler(request):
            query = requests.utils.urlparse(request.url).query
            items = self.store[path]
            if "network_entity=" in query:
                entity = int(query.split("network_entity=")[1].split("&")[0])
                items = [i for i in items if i.get("network_entity", "").endswith(f"/{entity}/")]
            return 200, {"results": items, "next": None}

        return handler


def test_seed_stays_in_reserved_space_and_clean_removes_it():
    fake = FakeNgen()
    ngen, adapter = make_client(fake.routes())

    def delete(request):
        fake.deleted.append(request.url)
        return 204, None

    result = seed(ngen, entities=2, networks=5, events=20, cases=4, seed=1, log=lambda m: None)
    assert (len(result.entities), len(result.networks), len(result.events)) == (2, 10, 20)
    assert len(result.cases) == 4

    for contact in result.contacts:
        assert contact["username"].endswith(f".{DOMAIN}")
    for item in result.networks + result.events:
        address = item["address_value"]
        try:
            ip = ipaddress.ip_network(address)
        except ValueError:
            assert address.endswith(f".{DOMAIN}")
        else:
            assert any(ip.subnet_of(r) for r in RANGES)
    assert all(e["tags"] == ["seed"] and e["evidence"] for e in result.events)
    assert all(c["tags"] == ["seed"] and 1 <= len(c["events"]) <= 3 for c in result.cases)

    for item in result.entities + result.contacts + result.networks + result.events + result.cases:
        adapter.routes[("DELETE", requests.utils.urlparse(item["url"]).path)] = delete
    # Look-alikes that Ngen's suffix/substring filters would also return must survive
    fake.store["/api/event/"].append({"url": f"{BASE}/api/event/9001/", "domain": f"not{DOMAIN}", "tags": [], "case": None})
    fake.store["/api/event/"].append({"url": f"{BASE}/api/event/9002/", "domain": f"www.{DOMAIN}", "tags": [], "case": None})
    fake.store["/api/contact/"].append({"url": f"{BASE}/api/contact/9001/", "username": f"x@team.{DOMAIN}.org"})
    for path in ("/api/event/9001/", "/api/event/9002/", "/api/contact/9001/"):
        adapter.routes[("DELETE", path)] = delete
    clean(ngen, log=lambda m: None)
    created = {i["url"] for i in result.entities + result.contacts + result.networks + result.events + result.cases}
    assert set(fake.deleted) == created


def test_same_seed_same_data():
    def run():
        ngen, _ = make_client(FakeNgen().routes())
        result = seed(ngen, entities=1, networks=3, events=5, cases=1, seed=7, log=lambda m: None)
        return [c["name"] for c in result.contacts]

    assert run() == run()
