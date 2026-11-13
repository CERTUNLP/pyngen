# pyngen

Python client and CLI for the [Ngen](https://github.com/CERTUNLP/ngen) REST API.

```bash
pip install pyngen
```

Version 2 is a new client for Ngen 2 that keeps the pyngen 1.x interface
(`PyNgen`, `pyngen.ngen_exceptions`, the `ngen` command) working on top of
it. Existing scripts and IntelMQ bots need no changes; see
[Legacy interface](#legacy-interface-pyngen-1x) and the
[CHANGELOG](CHANGELOG.md).

## Authentication

Either an API key (from `/api/token/simple/` or the Ngen admin) or a username and
password. With username/password the client logs in with JWT and renews the token
on its own.

```python
from pyngen import Ngen

ngen = Ngen("https://ngen.example.org", token="...")
ngen = Ngen("https://ngen.example.org", username="scanner", password="...")
ngen = Ngen.from_env()  # NGEN_URL + NGEN_TOKEN (or NGEN_USERNAME/NGEN_PASSWORD), else ~/.ngen
```

TLS certificates are verified by default. Pass `verify=False` (or `NGEN_VERIFY=false`)
only for test instances. `ngen.session` is the underlying `requests.Session`,
so proxies and extra headers go there (`ngen.session.proxies = {...}`).
Set the `pyngen` logger to `DEBUG` to see every request.

## Resources

Every resource has `list(**filters)`, `first(**filters)`, `get(id_or_url)`,
`create(**fields)`, `update(id_or_url, **fields)` (PUT), `patch(id_or_url, **fields)`,
`delete(id_or_url)` and `by_slug(slug)`. `list` follows pagination for you and the
filters are the query params Ngen accepts.

| Attribute | Endpoint |
|---|---|
| `events`, `cases` | `/api/event/`, `/api/case/` |
| `evidence`, `artifacts` | `/api/evidence/`, `/api/artifact/` |
| `networks`, `entities`, `contacts` | `/api/network/`, `/api/entity/`, `/api/contact/` |
| `taxonomies`, `feeds`, `priorities`, `tlps`, `states`, `tags`, `users` | catalog endpoints |

Any other endpoint: `ngen.resource("playbook").list()`.

Event fields `taxonomy`, `feed`, `priority` and `tlp` (and case `state`) take a
slug or a URL. Case and contact `priority`/`tlp` need a URL, for example
`ngen.priorities.by_slug("high")["url"]`. Ngen requires `priority` and `tlp` on
every event, and `artifacts=[]` when there is no evidence (JSON request).

```python
event = ngen.events.create(
    address_value="192.0.2.10",
    taxonomy="vulnerability",
    feed="nessus",
    priority="high",
    tlp="amber",
    evidence=["report.html"],      # paths, or (name, bytes) tuples
)

for event in ngen.events.for_address("192.0.2.10"):
    print(event["url"], event["case"])

open_cases = [c for c in ngen.cases.for_address("192.0.2.0/24") if ngen.cases.is_open(c)]
```

Errors raise `NgenValidationError` (400, field errors in `.body`), `NgenAuthError`
(401/403), `NgenNotFoundError` (404) or `NgenAPIError`. All derive from `NgenError`.

A taxonomy slug Ngen does not know is **created** by Ngen (setting
`TAXONOMY_ALLOW_AUTO_CREATE`, on by default) rather than rejected. Check it
first with `ngen.taxonomies.by_slug(slug)` when typos matter.

## Reporting from scanners

`report()` keeps one event per address and taxonomy while its case is open: it
replaces the evidence of that event, or creates a new event when there is none or
its case was closed. Several files go in one zip, since Ngen notifies once per
evidence. `priority` and `tlp` default to `medium` and `amber`.

```python
from pyngen import report

result = report(ngen, "192.0.2.10", taxonomy="vulnerability", feed="nessus",
                evidence=["192.0.2.10.html", "192.0.2.10.txt"])
print(result.action, result.event["url"])  # "created", "updated" or "unchanged"
```

`report_csv()` creates one event per address found in a CSV file, with the rows
of that address as evidence (what `reportFromPathCSV` did in 1.x):

```python
from pyngen import report_csv

for result in report_csv(ngen, "scan.csv", taxonomy="open_port", feed="nmap", address_header="ip"):
    print(result.action, result.event["address_value"])
```

With `reuse_open=True` each address goes through `report()` instead.

## Who is behind an address

`lookup()` gives the network, entity and contacts of an IP, CIDR or domain, with
the same rules Ngen uses to notify an event: the most specific network that
contains the address wins, and when it has no contacts of its own they come from
the closest parent network that has some.

```python
info = ngen.lookup("192.0.2.10")
print(info.network["cidr"], info.entity and info.entity["name"])
print([n["cidr"] for n in info.networks])  # every containing network, most specific first
print(info.contacts_from["cidr"], [c["username"] for c in info.contacts])

ngen.lookup("192.0.2.10", type="email", role="abuse")  # filter the contacts
ngen.networks.containing("www.example.org")             # networks only
ngen.contacts.for_address("192.0.2.10")                 # contacts only
ngen.contacts.for_network(info.network)                 # a network's own, no inheritance
```

## CLI

```bash
pyngen init                                 # asks URL and API key, saves them in ~/.ngen
# or: export NGEN_URL=https://ngen.example.org NGEN_TOKEN=...
# or: export NGEN_USERNAME=... NGEN_PASSWORD=...

pyngen version
pyngen list event cidr=192.0.2.10/32 --limit 5
pyngen get case 42
pyngen create event address_value=192.0.2.10 taxonomy=malware feed=shodan priority=high tlp=amber -e report.txt
pyngen patch event 42 notes="checked" tags:='["seen"]'    # key:=json for lists and booleans
pyngen delete event 42
pyngen report 192.0.2.10 --taxonomy vulnerability --feed nessus -e report.html -e report.txt
pyngen report-csv scan.csv --taxonomy open_port --feed nmap --address-header ip
pyngen lookup 192.0.2.10                    # network, entity and contacts
pyngen lookup example.org --role abuse --json
pyngen seed --yes
```

`pyngen --help` and `pyngen <command> --help` list every option. Any resource
name works with `list`, `get`, `create`, `patch` and `delete`, not only the ones
with a shortcut.

## Legacy interface (pyngen 1.x)

Everything below keeps working and is implemented on top of `Ngen`:

```python
from pyngen import PyNgen
from pyngen.ngen_exceptions import NewEventFieldError, UnauthorizedNgenError

ngen = PyNgen("https://ngen.example.org", "API_KEY", timeout=10)
res = ngen.newEvent("192.0.2.10", "shodan", "open_dns", evidence_text="...", notes="...")
res["status_code"], res["data"]["url"]
ngen.newEvent("192.0.2.10", "shodan", "open_dns", evidence_file="a.txt,b.txt", date="2026-01-01T00:00:00Z")
ngen.reportFromPathCSV("scan.csv", "nmap", "open_port", "ip")
ngen.events.list()          # the new client is also reachable from the old object
```

```bash
ngen init -apikey KEY -url https://ngen.example.org
ngen newevent -feed shodan -type open_dns -address 192.0.2.10 -evidenceText "..." [-evidenceFile a.txt,b.txt]
ngen reportcsv -feed nmap -type open_port -path scan.csv -addressheader ip
```

Equivalences, for new code:

| pyngen 1.x | pyngen 2 |
|---|---|
| `PyNgen(url, apikey, timeout=5)` | `Ngen(url, token=apikey, timeout=30)` |
| `newEvent(addr, feed, tax, evidence_text=t)` → `{"status_code", "data"}` | `ngen.events.create(address_value=addr, feed=feed, taxonomy=tax, priority="medium", tlp="amber", evidence=[("evidence.txt", t)])` → event |
| `evidence_file="a,b"` | `evidence=["a", "b"]` |
| `reportFromPathCSV(path, feed, tax, header)` | `report_csv(ngen, path, tax, feed, header)` |
| `_getFeedFor(slug)` | `ngen.feeds.by_slug(slug)` |
| `getFeeds()["data"]` | `list(ngen.feeds.list())` |
| `_action(path, method, jsondata)` | `ngen.request(method, path, json=...)` |
| `UnauthorizedNgenError`, `UnexpectedError`, `NewEventFieldError`, `SchemeNotSettedError` | `NgenAuthError`, `NgenAPIError`, `NgenValidationError`, `NgenConfigError` (the old ones subclass these) |

One difference: a 400 now raises `NewEventFieldError` (as 1.x intended) where
1.x against Ngen 2 raised `UnexpectedError`. Both are `NgenError`.

## Test data

`pyngen seed` fills an instance with fake data so you can try Ngen out. It needs
the `seed` extra (Faker):

```bash
pip install "pyngen[seed]"
pyngen seed                                     # defaults below
pyngen seed --events 200 --cases 30 --seed 42   # same seed, same data
pyngen seed --clean                             # delete what seed created
```

| Option | Default | |
|---|---|---|
| `--entities` | 3 | Entities to create |
| `--networks` | 20 | Networks per entity, each with its own contact |
| `--events` | 100 | Events, each with an evidence file |
| `--cases` | 20 | Cases, grouping 1 to 3 events each |
| `--seed` | random | Random seed, for repeatable data |
| `--clean` | | Delete the seeded data instead |
| `--yes` | | Do not ask for confirmation |

Everything stays in reserved space (RFC 5737 ranges and `.seed.example`
domains), so no real host or mailbox is touched, but use it on test instances
only. `--clean` removes the data of every seed run and leaves your own alone.

From Python:

```python
from pyngen.seed import seed, clean

result = seed(ngen, entities=1, networks=5, events=20, cases=5, seed=42)
clean(ngen)
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

The tests run against a fake server. To try a real one, start Ngen with its
Docker Compose and point `NGEN_URL`/`NGEN_TOKEN` at it.

## License

GPL-3.0, like Ngen.
