"""The pyngen 1.x interface must keep working on top of the new client."""

import json

import pytest
import requests

from conftest import BASE, paginated
from pyngen import NgenAPIError, NgenAuthError, NgenValidationError, PyNgen
from pyngen.ngen_exceptions import *  # noqa: F403
from pyngen.ngen_exceptions import (
    NewEventFieldError,
    NewEventTypeFieldError,
    NewIncidentTypeDeactivatedError,
    NgenError,
    SchemeNotSettedError,
    UnauthorizedNgenError,
    UnexpectedError,
)

ROOT = {("GET", "/api/"): lambda r: (200, {"event": f"{BASE}/api/event/"})}
EVENT = {"url": f"{BASE}/api/event/9/", "address_value": "10.0.0.1"}


def legacy(fake_server, routes=None, **kwargs):
    adapter = fake_server({**ROOT, **(routes or {})})
    return PyNgen(BASE, "KEY", **kwargs), adapter


def test_init_checks_url_and_keeps_attributes(fake_server):
    ngen, adapter = legacy(fake_server, timeout=7)
    assert adapter.paths() == [("GET", "/api/")]
    assert adapter.calls[0].headers["Authorization"] == "Token KEY"
    assert (ngen.hostname, ngen.port, ngen.scheme, ngen.timeout) == ("ngen.test", 443, "https", 7)
    assert ngen.ngen.timeout == 7


def test_init_without_scheme():
    with pytest.raises(SchemeNotSettedError) as e:
        PyNgen("ngen.test", "KEY")
    assert "http/https" in e.value.detail
    assert isinstance(e.value, NgenError)


def test_bad_apikey(fake_server):
    fake_server({("GET", "/api/"): lambda r: (401, {"detail": "Invalid token."})})
    with pytest.raises(UnauthorizedNgenError) as e:
        PyNgen(BASE, "bad")
    assert str(e.value) == "Invalid Api Key"
    assert isinstance(e.value, NgenAuthError)


def test_new_event_json_payload_and_return_shape(fake_server):
    ngen, adapter = legacy(fake_server, {("POST", "/api/event/"): lambda r: (201, EVENT)})
    res = ngen.newEvent("10.0.0.1", "shodan", "open_dns", notes="n", date="2026-01-01T00:00:00Z", raw="{}")
    assert res == {"status_code": 201, "data": EVENT}
    assert json.loads(adapter.calls[-1].body) == {
        "address_value": "10.0.0.1",
        "notes": "n",
        "priority": "medium",
        "tlp": "amber",
        "taxonomy": "open_dns",
        "feed": "shodan",
        "artifacts": [],
        "date": "2026-01-01T00:00:00Z",
        "raw": "{}",
    }
    assert ngen.newIncident is not None


def test_new_event_with_evidence_is_multipart(fake_server, tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.log"
    a.write_text("A")
    b.write_text("B")
    ngen, adapter = legacy(fake_server, {("POST", "/api/event/"): lambda r: (201, EVENT)})
    ngen.newEvent("10.0.0.1", "shodan", "open_dns", evidence_text="texto", evidence_file=f"{a}, {b}")
    body = adapter.calls[-1].body
    assert body.count(b'name="evidence"') == 3
    assert b'filename="a.txt"' in body and b'filename="b.log"' in body
    assert b'filename="evidence.txt"\r\nContent-Type: text/plain' in body
    assert b'name="priority"\r\n\r\nmedium' in body
    assert b'name="notes"' not in body
    with pytest.raises(FileNotFoundError):
        ngen.newEvent("10.0.0.1", "shodan", "open_dns", evidence_file="/nope.txt")


def test_new_event_errors_map_to_legacy_classes(fake_server):
    answers = {}
    ngen, _ = legacy(fake_server, {("POST", "/api/event/"): lambda r: answers["next"]})

    answers["next"] = (400, {"feed": ["nope is not a valid slug for Feed."]})
    with pytest.raises(NewEventFieldError) as e:
        ngen.newEvent("10.0.0.1", "nope", "open_dns")
    assert e.value.msg == {"feed": ["nope is not a valid slug for Feed."]}
    assert e.value.data["feed"] == "nope"
    assert "Data sent" in e.value.detail
    assert isinstance(e.value, NgenValidationError) and e.value.status_code == 400

    answers["next"] = (400, {"taxonomy": ["zzz is not a valid slug for Taxonomy."]})
    with pytest.raises(NewEventTypeFieldError):
        ngen.newEvent("10.0.0.1", "shodan", "zzz")

    answers["next"] = (400, {"taxonomy": ["Taxonomy zzz is deactivated."]})
    with pytest.raises(NewIncidentTypeDeactivatedError):
        ngen.newEvent("10.0.0.1", "shodan", "zzz")

    answers["next"] = (500, b"boom")
    with pytest.raises(UnexpectedError) as e:
        ngen.newEvent("10.0.0.1", "shodan", "open_dns")
    assert e.value.code == 500 and "boom" in e.value.msg and "Error Code 500" in e.value.detail
    assert isinstance(e.value, NgenAPIError)


def test_new_event_retries_on_read_timeout(fake_server):
    attempts = []

    def flaky(request):
        attempts.append(1)
        if len(attempts) == 1:
            return 0, requests.exceptions.ReadTimeout("slow")
        return 201, EVENT

    ngen, _ = legacy(fake_server, {("POST", "/api/event/"): flaky})
    with pytest.raises(requests.exceptions.ReadTimeout):
        ngen.newEvent("10.0.0.1", "shodan", "open_dns")
    assert ngen.newEvent("10.0.0.1", "shodan", "open_dns", retries=2)["status_code"] == 201


FEEDS = [
    {"url": f"{BASE}/api/administration/feed/1/", "slug": "shodan", "name": "Shodan", "active": True},
    {"url": f"{BASE}/api/administration/feed/2/", "slug": "old", "name": "Old", "active": False},
]


def test_catalog_methods(fake_server):
    pages = {
        "1": {"results": FEEDS[:1], "next": f"{BASE}/api/administration/feed/?page=2"},
        "2": {"results": FEEDS[1:], "next": None},
    }
    ngen, adapter = legacy(fake_server, {
        ("GET", "/api/administration/feed/"): lambda r: (200, pages["2" if "page=2" in r.url else "1"]),
        ("PATCH", "/api/administration/feed/1/"): lambda r: (200, {**FEEDS[0], "name": "S"}),
        ("POST", "/api/administration/feed/"): lambda r: (201, {"slug": "nuevo"}),
        ("GET", "/api/taxonomy/"): paginated([{"slug": "open_dns", "active": True}]),
        ("POST", "/api/taxonomy/"): lambda r: (201, {"slug": "otro"}),
        ("GET", "/api/administration/priority/"): paginated([{"slug": "medium", "name": "Medium"}]),
        ("GET", "/api/administration/tlp/"): paginated([{"slug": "amber"}]),
    })
    assert ngen.getFeeds() == {"status_code": 200, "data": FEEDS}  # raw answer, as in 1.x
    assert ngen.getFeeds(field="slug") == ["shodan", "old"]
    assert ngen.getActiveFeeds(field="slug") == ["shodan"]
    assert ngen.getFeed("shodan") == FEEDS[0] and ngen.getFeed("zzz") is None
    assert ngen._getFeedFor("old")["slug"] == "old"
    assert ngen.editFeed("shodan", name="S")["name"] == "S"
    assert ngen.newFeed("Nuevo") == "nuevo"
    assert ngen.getEventTypes(field="slug") == ["open_dns"]
    assert ngen.getActiveEventTypes() == [{"slug": "open_dns", "active": True}]
    assert ngen._getTaxonomyFor("open_dns")["slug"] == "open_dns"
    assert ngen.newEventType("Otro") == "otro"
    assert json.loads(adapter.calls[-1].body) == {"name": "Otro", "type": "incident"}
    assert ngen._getPriorityFor("medium")["name"] == "Medium"
    assert ngen._getTLPFor("amber")["slug"] == "amber"


def test_event_methods_use_event_endpoint(fake_server):
    ngen, adapter = legacy(fake_server, {
        ("GET", "/api/event/9/"): lambda r: (200, EVENT),
        ("PATCH", "/api/event/9/"): lambda r: (200, {**EVENT, "notes": "x"}),
        ("GET", "/api/event/"): paginated([EVENT]),
    })
    assert ngen.getEvent(9) == EVENT
    assert ngen.editEvent(9, notes="x")["notes"] == "x"
    assert json.loads(adapter.calls[-1].body) == {"notes": "x"}
    assert ngen.getEvents() == [EVENT]
    assert ngen._action("/api/event/", "GET")["data"] == [EVENT]
    assert ngen._action("api/event/", "GET")["status_code"] == 200  # no leading slash, as getEvents did


def test_csv_reports_group_by_address(fake_server):
    sent = []

    def create(request):
        body = request.body.decode()
        address = body.split('name="address_value"\r\n\r\n')[1].split("\r\n")[0]
        evidence = body.split('filename="evidence.txt"')[1].split("\r\n\r\n", 1)[1].split("\r\n--")[0]
        sent.append((address, evidence))
        return 201, EVENT

    ngen, _ = legacy(fake_server, {("POST", "/api/event/"): create})
    text = "ip;port\n10.0.0.1;22\n10.0.0.2;80\n10.0.0.1;443\n"
    results = ngen.reportFromCSVText(text, "shodan", "open_port", "ip")
    assert len(results) == 2 and results[0]["status_code"] == 201
    assert sent[0] == ("10.0.0.1", "ip,port\r\n10.0.0.1,22\r\n10.0.0.1,443\r\n")
    assert sent[1][0] == "10.0.0.2"

    sent.clear()
    raw = "# scanner v1\nip|port\n10.0.0.1|22\n# comment\n10.0.0.3|25\n"
    ngen.reportFromMalformedCSV(raw, "shodan", "open_port", 1, 2, 2, 0, "|", comment="#")
    assert sent == [("10.0.0.1", "ip|port\n10.0.0.1,22"), ("10.0.0.3", "ip|port\n10.0.0.3,25")]


def test_report_from_path(fake_server, tmp_path):
    ngen, adapter = legacy(fake_server, {("POST", "/api/event/"): lambda r: (201, EVENT)})
    path = tmp_path / "r.csv"
    path.write_text("ip,port\n10.0.0.1,22\n")
    assert len(ngen.reportFromPathCSV(str(path), "shodan", "open_port", "ip")) == 1


def test_new_client_is_reachable(fake_server):
    ngen, _ = legacy(fake_server, {("GET", "/api/event/"): paginated([EVENT])})
    assert list(ngen.events.list()) == [EVENT]
    assert ngen.ngen.base_url == BASE


def test_star_import_exports_every_legacy_name():
    import pyngen

    for name in ("NgenError", "UnauthorizedNgenError", "UnexpectedError", "SchemeNotSettedError",
                 "NewEventFieldError", "NewEventTypeFieldError", "NewEventTypeDeactivatedError",
                 "NewEventError", "NewIncidentTypeDeactivatedError"):
        assert name in globals(), name
        assert getattr(pyngen, name) is globals()[name]
