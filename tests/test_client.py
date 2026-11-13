import json
import time

import pytest
import requests

from conftest import BASE, jwt, paginated
from pyngen import Ngen, NgenAPIError, NgenConfigError, NgenNotFoundError, NgenValidationError, report


def test_token_header_and_pagination(client):
    pages = {
        "1": {"results": [{"id": 1}], "next": f"{BASE}/api/network/?page=2"},
        "2": {"results": [{"id": 2}], "next": None},
    }

    def networks(req):
        return 200, pages["2" if "page=2" in req.url else "1"]

    ngen, adapter = client({("GET", "/api/network/"): networks})
    assert [n["id"] for n in ngen.networks.list()] == [1, 2]
    assert adapter.calls[0].headers["Authorization"] == "Token secret"
    assert adapter.calls[0].headers["User-Agent"].startswith("pyngen/")
    assert "page_size=100" in adapter.calls[0].url


def test_url_validation():
    with pytest.raises(NgenConfigError):
        Ngen("ngen.test", token="x")
    with pytest.raises(NgenConfigError):
        Ngen(BASE)


def test_by_slug_is_exact(client):
    ngen, _ = client({("GET", "/api/taxonomy/"): paginated([{"slug": "nessus_report_old"}, {"slug": "nessus_report"}])})
    assert ngen.taxonomies.by_slug("nessus_report")["slug"] == "nessus_report"
    with pytest.raises(NgenNotFoundError):
        ngen.taxonomies.by_slug("nessus")


def test_errors_are_typed(client):
    ngen, _ = client({("POST", "/api/event/"): lambda r: (400, {"feed": ["invalid"]})})
    with pytest.raises(NgenValidationError) as e:
        ngen.events.create(address_value="10.0.0.1", feed="nope")
    assert e.value.body == {"feed": ["invalid"]}


def test_non_json_answer_is_an_api_error(client):
    ngen, _ = client({("GET", "/api/version/"): lambda r: (200, b"<html>login</html>")})
    with pytest.raises(NgenAPIError):
        ngen.version()


def test_json_drops_none(client):
    ngen, adapter = client({("POST", "/api/event/"): lambda r: (201, {"url": "u"})})
    ngen.events.create(address_value="10.0.0.1", priority=None, tags=[])
    assert json.loads(adapter.calls[0].body) == {"address_value": "10.0.0.1", "tags": []}


def test_multipart_drops_none_and_encodes_bools(client, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    ngen, adapter = client({("POST", "/api/event/"): lambda r: (201, {"url": "u"})})
    ngen.events.create(address_value="10.0.0.1", avoid_auto_merge=True, notes=None, evidence=[f])
    body = adapter.calls[0].body
    assert b'name="avoid_auto_merge"\r\n\r\ntrue' in body
    assert b'name="notes"' not in body
    assert b'filename="a.txt"' in body


def test_evidence_accepts_single_path_and_text(client, tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("x")
    ngen, adapter = client({("POST", "/api/event/"): lambda r: (201, {"url": "u"})})
    ngen.events.create(address_value="10.0.0.1", evidence=str(f))
    assert b'filename="a.txt"' in adapter.calls[0].body
    ngen.events.create(address_value="10.0.0.1", evidence=("t.txt", "texto"))
    assert b'filename="t.txt"\r\n\r\ntexto' in adapter.calls[1].body


def test_jwt_logs_in_renews_and_logs_out(client):
    login = {"access": jwt(time.time() + 300), "refresh": jwt(time.time() + 3600)}
    ngen, adapter = client(
        {
            ("POST", "/api/token/"): lambda r: (200, login),
            ("POST", "/api/token/refresh/"): lambda r: (200, {"access": jwt(time.time() + 300)}),
            ("POST", "/api/logout/"): lambda r: (205, None),
            ("GET", "/api/version/"): lambda r: (200, {"version": "2.5"}),
        },
        token=None,
        username="u",
        password="p",
    )
    assert ngen.version() == {"version": "2.5"}
    ngen.auth.access = jwt(time.time() - 1)  # access expires, refresh is still valid
    ngen.version()
    ngen.logout()
    assert [p for _, p in adapter.paths()] == [
        "/api/token/", "/api/version/", "/api/token/refresh/", "/api/version/", "/api/logout/"
    ]
    assert adapter.calls[-2].headers["Authorization"].startswith("Bearer ")
    assert ngen.auth.access is None


def test_bad_jwt_is_treated_as_expired():
    from pyngen.auth import _jwt_exp

    assert _jwt_exp("garbage") == 0


def test_from_env_reads_env_then_config_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("NGEN_URL", raising=False)
    monkeypatch.delenv("NGEN_TOKEN", raising=False)
    monkeypatch.setenv("NGEN_CONFIG_DIR", str(tmp_path))
    with pytest.raises(NgenConfigError):
        Ngen.from_env()
    (tmp_path / "url").write_text(BASE + "\n")
    (tmp_path / "apikey").write_text("fromfile\n")
    assert Ngen.from_env().auth.token == "fromfile"
    monkeypatch.setenv("NGEN_TOKEN", "fromenv")
    monkeypatch.setenv("NGEN_VERIFY", "false")
    ngen = Ngen.from_env()
    assert ngen.auth.token == "fromenv" and ngen.verify is False


TAXONOMY = {"url": f"{BASE}/api/taxonomy/7/", "slug": "vuln_scan"}


def report_routes(events, case_blocked=False, patch_status=(200, {"url": f"{BASE}/api/event/5/"})):
    return {
        ("GET", "/api/taxonomy/"): paginated([TAXONOMY]),
        ("GET", "/api/event/"): paginated(events),
        ("GET", "/api/case/3/"): lambda r: (200, {"blocked": case_blocked}),
        ("POST", "/api/event/"): lambda r: (201, {"url": f"{BASE}/api/event/99/"}),
        ("PATCH", "/api/event/5/"): lambda r: patch_status,
        ("DELETE", "/api/evidence/1/"): lambda r: (204, None),
    }


EXISTING = {
    "url": f"{BASE}/api/event/5/",
    "taxonomy": TAXONOMY["url"],
    "case": f"{BASE}/api/case/3/",
    "evidence": [f"{BASE}/api/evidence/1/"],
}


def test_report_updates_open_event(client, tmp_path):
    f = tmp_path / "r.html"
    f.write_text("x")
    ngen, adapter = client(report_routes([EXISTING]))
    result = report(ngen, "10.0.0.1", "vuln_scan", "nessus", [f])
    assert result.action == "updated"
    assert ("DELETE", "/api/evidence/1/") in adapter.paths()
    assert ("PATCH", "/api/event/5/") in adapter.paths()
    assert "cidr=10.0.0.1%2F32" in adapter.calls[1].url
    assert "parent__isnull=True" in adapter.calls[1].url


def test_report_creates_when_case_closed_with_defaults(client, tmp_path):
    f = tmp_path / "r.html"
    f.write_text("x")
    ngen, adapter = client(report_routes([EXISTING], case_blocked=True))
    assert report(ngen, "10.0.0.1", "vuln_scan", "nessus", [f], tags=["scan"]).action == "created"
    body = adapter.calls[-1].body
    assert b'name="priority"\r\n\r\nmedium' in body
    assert b'name="tlp"\r\n\r\namber' in body
    assert b'name="tags"\r\n\r\nscan' in body
    assert b'name="avoid_auto_merge"\r\n\r\ntrue' in body


def test_report_zips_multiple_files(client, tmp_path):
    a, b = tmp_path / "r.html", tmp_path / "r.txt"
    a.write_text("x")
    b.write_text("y")
    ngen, adapter = client(report_routes([]))
    report(ngen, "10.0.0.1", "vuln_scan", "nessus", [a, b])
    assert b'filename="10.0.0.1.zip"' in adapter.calls[-1].body


def test_report_keep_evidence_duplicate_is_unchanged(client, tmp_path):
    f = tmp_path / "r.html"
    f.write_text("x")
    dup = (400, {"file": ["already exists"]})
    ngen, adapter = client(report_routes([EXISTING], patch_status=dup))
    result = report(ngen, "10.0.0.1", "vuln_scan", "nessus", [f], replace_evidence=False)
    assert result.action == "unchanged"
    assert ("DELETE", "/api/evidence/1/") not in adapter.paths()
    with pytest.raises(NgenValidationError):
        report(ngen, "10.0.0.1", "vuln_scan", "nessus", [f])


NETWORKS = [
    {"url": f"{BASE}/api/network/1/", "cidr": "0.0.0.0/0", "network_entity": None, "type": "internal"},
    {"url": f"{BASE}/api/network/3/", "cidr": "10.0.0.0/24", "network_entity": None, "type": "internal"},
    {"url": f"{BASE}/api/network/2/", "cidr": "10.0.0.0/8",
     "network_entity": f"{BASE}/api/entity/4/", "type": "internal"},
]
CONTACTS = {"2": [{"username": "abuse@example.org", "type": "email", "role": "abuse"}]}


def lookup_routes():
    def contacts(req):
        query = requests.utils.urlparse(req.url).query
        network_id = query.split("network_id=")[1].split("&")[0]
        return 200, {"results": CONTACTS.get(network_id, []), "next": None}

    return {
        ("GET", "/api/network/"): paginated(NETWORKS),
        ("GET", "/api/contact/"): contacts,
        ("GET", "/api/entity/4/"): lambda r: (200, {"url": f"{BASE}/api/entity/4/", "name": "UNLP"}),
    }


def test_networks_containing_most_specific_first(client):
    ngen, adapter = client(lookup_routes())
    networks = ngen.networks.containing("10.0.0.1")
    assert [n["cidr"] for n in networks] == ["10.0.0.0/24", "10.0.0.0/8", "0.0.0.0/0"]
    assert "supernet_of=10.0.0.1" in adapter.calls[0].url


def test_lookup_inherits_contacts_and_entity_from_parent(client):
    ngen, adapter = client(lookup_routes())
    result = ngen.lookup("10.0.0.1", type="email")
    assert result.network["cidr"] == "10.0.0.0/24"
    assert result.entity["name"] == "UNLP"
    assert result.contacts_from["cidr"] == "10.0.0.0/8"
    assert [c["username"] for c in result.contacts] == ["abuse@example.org"]
    assert "type=email" in adapter.calls[-1].url
    assert ngen.contacts.for_address("10.0.0.1") == result.contacts


def test_lookup_without_network(client):
    ngen, _ = client({("GET", "/api/network/"): paginated([])})
    result = ngen.lookup("192.0.2.1")
    assert (result.network, result.entity, result.contacts) == (None, None, [])
