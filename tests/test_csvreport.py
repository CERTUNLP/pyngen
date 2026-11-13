import pytest
import io

from conftest import BASE, paginated
from pyngen.csvreport import group_lines, group_rows, report_csv, sniff_delimiter


def test_group_rows_detects_delimiter_and_skips_empty():
    text = "ip\tport\n10.0.0.1\t22\n\t80\n10.0.0.1\t443\n"
    groups = group_rows(io.StringIO(text), "ip")
    assert list(groups) == ["10.0.0.1"]
    assert groups["10.0.0.1"] == "ip,port\r\n10.0.0.1,22\r\n10.0.0.1,443\r\n"
    assert sniff_delimiter("a;b\n1;2\n") == ";"
    assert sniff_delimiter("nodelimiter", default="|") == "|"


def test_group_lines_header_and_comments():
    raw = b"h1\r\nip;x\r\n1.1.1.1;a\r\n#c\r\n1.1.1.1;b\r\n2.2.2.2;c"
    groups = group_lines(raw, 1, 2, 2, 0, ";", comment="#")
    # the header lines are kept as they are, like pyngen 1.x did
    assert groups == {"1.1.1.1": "ip;x\n1.1.1.1,a\n1.1.1.1,b", "2.2.2.2": "ip;x\n2.2.2.2,c"}


def test_report_csv_creates_one_event_per_address(client, tmp_path):
    created = []
    ngen, adapter = client({("POST", "/api/event/"): lambda r: (201, {"url": "u"})})
    path = tmp_path / "scan.csv"
    path.write_text("ip,port\n10.0.0.1,22\n10.0.0.2,80\n")
    results = report_csv(ngen, path, "open_port", "nmap", "ip", notes="scan")
    assert [r.action for r in results] == ["created", "created"]
    body = adapter.calls[0].body
    assert b'name="address_value"\r\n\r\n10.0.0.1' in body
    assert b'filename="evidence.csv"' in body
    assert b'name="priority"\r\n\r\nmedium' in body and b'name="notes"\r\n\r\nscan' in body


def test_report_csv_reuse_open(client):
    taxonomy = {"url": f"{BASE}/api/taxonomy/1/", "slug": "open_port"}
    event = {"url": f"{BASE}/api/event/5/", "taxonomy": taxonomy["url"], "case": None, "evidence": []}
    ngen, adapter = client({
        ("GET", "/api/taxonomy/"): paginated([taxonomy]),
        ("GET", "/api/event/"): lambda r: (200, {"results": [event] if "10.0.0.1" in r.url else [], "next": None}),
        ("PATCH", "/api/event/5/"): lambda r: (200, event),
        ("POST", "/api/event/"): lambda r: (201, {"url": "new"}),
    })
    results = report_csv(ngen, "ip,port\n10.0.0.1,22\n10.0.0.2,80\n", "open_port", "nmap", "ip", reuse_open=True)
    assert [r.action for r in results] == ["updated", "created"]


def test_group_rows_rejects_a_missing_address_header():
    with pytest.raises(ValueError, match="'host' not found"):
        group_rows("ip,port\n10.0.0.1,22\n", "host")
    assert group_rows("", "ip") == {}
