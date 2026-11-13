import json

from click.testing import CliRunner

from conftest import BASE, paginated
from pyngen import legacy_cli
from pyngen.cli import cli

EVENT = {"url": f"{BASE}/api/event/9/", "address_value": "10.0.0.1"}


def run(args, env=None):
    env = {"NGEN_URL": BASE, "NGEN_TOKEN": "secret", **(env or {})}
    return CliRunner().invoke(cli, args, env=env, catch_exceptions=False)


def test_version_and_list(fake_server):
    adapter = fake_server({
        ("GET", "/api/version/"): lambda r: (200, {"version": "v2.6.1"}),
        ("GET", "/api/event/"): paginated([EVENT, EVENT]),
    })
    assert json.loads(run(["version"]).output)["version"] == "v2.6.1"
    out = run(["list", "event", "cidr=10.0.0.1/32", "--limit", "1"])
    assert len(json.loads(out.output)) == 1
    assert "cidr=10.0.0.1%2F32" in adapter.calls[-1].url
    assert adapter.calls[-1].headers["Authorization"] == "Token secret"


def test_create_patch_delete_any_resource(fake_server, tmp_path):
    adapter = fake_server({
        ("POST", "/api/playbook/"): lambda r: (201, {"url": "p"}),
        ("PATCH", "/api/event/9/"): lambda r: (200, EVENT),
        ("DELETE", "/api/event/9/"): lambda r: (204, None),
    })
    run(["create", "playbook", "name=pb", "tags:=[\"a\"]", "active:=true"])
    assert json.loads(adapter.calls[-1].body) == {"name": "pb", "tags": ["a"], "active": True}
    f = tmp_path / "e.txt"
    f.write_text("x")
    run(["patch", "event", "9", "notes=n", "-e", str(f)])
    assert b'filename="e.txt"' in adapter.calls[-1].body
    assert run(["delete", "event", "9"]).exit_code == 0
    assert adapter.paths()[-1] == ("DELETE", "/api/event/9/")


def test_report_and_report_csv(fake_server, tmp_path):
    taxonomy = {"url": f"{BASE}/api/taxonomy/1/", "slug": "vuln"}
    adapter = fake_server({
        ("GET", "/api/taxonomy/"): paginated([taxonomy]),
        ("GET", "/api/event/"): paginated([]),
        ("POST", "/api/event/"): lambda r: (201, EVENT),
    })
    f = tmp_path / "r.html"
    f.write_text("x")
    out = run(["report", "10.0.0.1", "--taxonomy", "vuln", "--feed", "nessus", "-e", str(f), "--tag", "t"])
    assert out.output.startswith("created: ")
    assert b'name="tlp"\r\n\r\namber' in adapter.calls[-1].body
    csv = tmp_path / "s.csv"
    csv.write_text("ip,port\n10.0.0.1,22\n10.0.0.2,80\n")
    out = run(["report-csv", str(csv), "--taxonomy", "vuln", "--feed", "nmap", "--address-header", "ip"])
    assert out.output.count("created: ") == 2


def test_errors_are_shown_not_raised(fake_server):
    fake_server({("GET", "/api/version/"): lambda r: (401, {"detail": "Invalid token."})})
    out = CliRunner().invoke(cli, ["version"], env={"NGEN_URL": BASE, "NGEN_TOKEN": "bad"})
    assert out.exit_code != 0
    assert "401" in out.output
    out = CliRunner().invoke(cli, ["version"], env={"NGEN_URL": "", "NGEN_TOKEN": "", "NGEN_CONFIG_DIR": "/nonexistent"})
    assert "missing --url" in out.output


def test_init_then_config_fallback(fake_server, tmp_path, monkeypatch):
    monkeypatch.setenv("NGEN_CONFIG_DIR", str(tmp_path))
    adapter = fake_server({
        ("GET", "/api/"): lambda r: (200, {}),
        ("GET", "/api/version/"): lambda r: (200, {"version": "v2"}),
    })
    out = CliRunner().invoke(cli, ["init", "--url", BASE, "--token", "saved"], env={"NGEN_URL": "", "NGEN_TOKEN": ""})
    assert out.exit_code == 0, out.output
    assert (tmp_path / "apikey").read_text() == "saved"
    out = CliRunner().invoke(cli, ["version"], env={"NGEN_URL": "", "NGEN_TOKEN": ""})
    assert "v2" in out.output
    assert adapter.calls[-1].headers["Authorization"] == "Token saved"


def test_legacy_ngen_command(fake_server, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NGEN_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("NGEN_URL", raising=False)
    monkeypatch.delenv("NGEN_TOKEN", raising=False)
    adapter = fake_server({
        ("GET", "/api/"): lambda r: (200, {}),
        ("POST", "/api/event/"): lambda r: (201, EVENT),
    })
    legacy_cli.main(["init", "-apikey", "KEY", "-url", BASE])
    assert (tmp_path / "url").read_text() == BASE
    legacy_cli.main(["newevent", "-feed", "shodan", "-type", "open_dns", "-address", "10.0.0.1",
                     "-evidenceText", "ev", "-notes", "n"])
    assert "Added event" in capsys.readouterr().out
    body = adapter.calls[-1].body
    assert b'name="taxonomy"\r\n\r\nopen_dns' in body and b'filename="evidence.txt"' in body
    csv = tmp_path / "r.csv"
    csv.write_text("ip,port\n10.0.0.1,22\n10.0.0.2,80\n")
    legacy_cli.main(["reportcsv", "-feed", "shodan", "-type", "open_port", "-path", str(csv), "-addressheader", "ip"])
    assert "Added 2 events" in capsys.readouterr().out


def test_init_honours_insecure_and_timeout(fake_server, tmp_path, monkeypatch):
    monkeypatch.setenv("NGEN_CONFIG_DIR", str(tmp_path))
    adapter = fake_server({("GET", "/api/"): lambda r: (200, {})})
    out = CliRunner().invoke(cli, ["--insecure", "--timeout", "3", "init", "--url", BASE, "--token", "t"],
                             env={"NGEN_URL": "", "NGEN_TOKEN": ""})
    assert out.exit_code == 0, out.output
    assert adapter.kwargs[-1]["verify"] is False and adapter.kwargs[-1]["timeout"] == 3


def test_patch_can_clear_a_field_with_json_null(fake_server):
    adapter = fake_server({("PATCH", "/api/event/9/"): lambda r: (200, EVENT)})
    run(["patch", "event", "9", "case:=null"])
    assert json.loads(adapter.calls[-1].body) == {"case": None}


def test_list_limit_does_not_fetch_the_next_page(fake_server):
    pages = {
        "1": {"results": [EVENT] * 100, "next": f"{BASE}/api/event/?page=2"},
        "2": {"results": [EVENT], "next": None},
    }
    adapter = fake_server({("GET", "/api/event/"): lambda r: (200, pages["2" if "page=2" in r.url else "1"])})
    assert len(json.loads(run(["list", "event", "--limit", "100"]).output)) == 100
    assert len(adapter.calls) == 1


def test_legacy_init_honours_ngen_verify(fake_server, tmp_path, monkeypatch):
    monkeypatch.setenv("NGEN_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("NGEN_VERIFY", "false")
    adapter = fake_server({("GET", "/api/"): lambda r: (200, {})})
    legacy_cli.main(["init", "-apikey", "KEY", "-url", BASE])
    assert adapter.kwargs[-1]["verify"] is False
