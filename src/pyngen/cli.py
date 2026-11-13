import dataclasses
import json

import click

from . import config
from .client import Ngen
from .csvreport import report_csv
from .exceptions import NgenError
from .report import DEFAULT_PRIORITY, DEFAULT_TLP, report as report_evidence

RESOURCES = {
    "event": "events",
    "case": "cases",
    "evidence": "evidence",
    "artifact": "artifacts",
    "network": "networks",
    "entity": "entities",
    "contact": "contacts",
    "taxonomy": "taxonomies",
    "feed": "feeds",
    "priority": "priorities",
    "tlp": "tlps",
    "state": "states",
    "tag": "tags",
    "user": "users",
}


def _echo(data):
    click.echo(json.dumps(data, indent=2, ensure_ascii=False))


def _fields(pairs):
    """``key=value`` pairs to a dict. ``key:=json`` parses the value as JSON (lists, booleans)."""
    fields = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep:
            raise click.BadParameter(f"expected key=value, got {pair!r}")
        if key.endswith(":"):
            key = key[:-1]
            try:
                value = json.loads(value)
            except ValueError:
                raise click.BadParameter(f"{key}: {value!r} is not JSON")
        fields[key] = value
    return fields


def _resource(ngen, name):
    return getattr(ngen, RESOURCES[name]) if name in RESOURCES else ngen.resource(name)


class _Group(click.Group):
    """Shows pyngen errors the way click shows usage errors, with exit code 1."""

    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except NgenError as e:
            raise click.ClickException(str(e)) from None


@click.group(cls=_Group)
@click.option("--url", envvar="NGEN_URL", help="Ngen base URL. [env: NGEN_URL, or ~/.ngen/url]")
@click.option("--token", envvar="NGEN_TOKEN", help="API key. [env: NGEN_TOKEN, or ~/.ngen/apikey]")
@click.option("--username", envvar="NGEN_USERNAME", help="[env: NGEN_USERNAME]")
@click.option("--password", envvar="NGEN_PASSWORD", help="[env: NGEN_PASSWORD]")
@click.option("--insecure", is_flag=True, help="Skip TLS certificate verification.")
@click.option("--timeout", type=int, default=30, show_default=True)
@click.pass_context
def cli(ctx, url, token, username, password, insecure, timeout):
    """Command line client for the Ngen REST API."""

    # Built lazily so --help works without credentials
    def make():
        settings = config.load()
        base = url or settings["url"]
        if not base:
            raise click.UsageError("missing --url, NGEN_URL or ~/.ngen/url (run: pyngen init)")
        key = token or (settings["token"] if not (username or password) else None)
        return Ngen(
            base, token=key, username=username, password=password,
            verify=not insecure and settings["verify"], timeout=timeout,
        )

    ctx.obj = make


@cli.command()
@click.option("--url", "init_url", prompt="Ngen URL", help="Ngen base URL.")
@click.option("--token", "init_token", prompt="API key", hide_input=True, help="API key.")
def init(init_url, init_token):
    """Check an API key and save it with the URL in ~/.ngen for later runs."""
    Ngen(init_url, token=init_token).request("GET", "/api/")
    click.echo(f"Saved in {config.save(init_url, init_token)}")


@cli.command()
@click.pass_obj
def version(make):
    """Show the server version."""
    _echo(make().version())


@cli.command("list")
@click.argument("resource")
@click.argument("filters", nargs=-1)
@click.option("--limit", type=int, help="Stop after N results.")
@click.pass_obj
def list_(make, resource, filters, limit):
    """List RESOURCE, with optional key=value filters (e.g. event cidr=10.0.0.1/32)."""
    items = _resource(make(), resource).list(**_fields(filters))
    result = []
    for item in items:
        if limit is not None and len(result) >= limit:
            break
        result.append(item)
    _echo(result)


@cli.command()
@click.argument("resource")
@click.argument("id_or_url")
@click.pass_obj
def get(make, resource, id_or_url):
    """Show one RESOURCE by id or URL."""
    _echo(_resource(make(), resource).get(id_or_url))


@cli.command()
@click.argument("resource")
@click.argument("fields", nargs=-1)
@click.option("-e", "--evidence", multiple=True, type=click.Path(exists=True, dir_okay=False),
              help="Evidence file (event and case only), repeatable.")
@click.pass_obj
def create(make, resource, fields, evidence):
    """Create a RESOURCE from key=value fields (key:=json for lists and booleans)."""
    data = _fields(fields)
    if evidence:
        data["evidence"] = list(evidence)
    _echo(_resource(make(), resource).create(**data))


@cli.command()
@click.argument("resource")
@click.argument("id_or_url")
@click.argument("fields", nargs=-1)
@click.option("-e", "--evidence", multiple=True, type=click.Path(exists=True, dir_okay=False),
              help="Evidence file to add (event and case only), repeatable.")
@click.pass_obj
def patch(make, resource, id_or_url, fields, evidence):
    """Change fields of one RESOURCE (key=value, or key:=json)."""
    data = _fields(fields)
    if evidence:
        data["evidence"] = list(evidence)
    _echo(_resource(make(), resource).patch(id_or_url, **data))


@cli.command()
@click.argument("resource")
@click.argument("id_or_url")
@click.pass_obj
def delete(make, resource, id_or_url):
    """Delete one RESOURCE by id or URL."""
    _resource(make(), resource).delete(id_or_url)


@cli.command()
@click.argument("address")
@click.option("--taxonomy", required=True, help="Taxonomy slug.")
@click.option("--feed", required=True, help="Feed slug.")
@click.option("--priority", default=DEFAULT_PRIORITY, show_default=True, help="Priority slug.")
@click.option("--tlp", default=DEFAULT_TLP, show_default=True, help="TLP slug.")
@click.option("--notes")
@click.option("--tag", "tags", multiple=True, help="Tag for a new event, repeatable.")
@click.option("-e", "--evidence", "evidence", multiple=True, required=True,
              type=click.Path(exists=True, dir_okay=False), help="Evidence file, repeatable.")
@click.option("--keep-evidence", is_flag=True, help="Do not delete the previous evidence.")
@click.pass_obj
def report(make, address, taxonomy, feed, priority, tlp, notes, tags, evidence, keep_evidence):
    """Report evidence for ADDRESS, reusing its open event if there is one."""
    result = report_evidence(
        make(), address, taxonomy, feed, list(evidence),
        priority=priority, tlp=tlp, notes=notes, tags=list(tags) or None,
        replace_evidence=not keep_evidence,
    )
    click.echo(f"{result.action}: {result.event.get('url')}")


@cli.command("report-csv")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--taxonomy", required=True, help="Taxonomy slug.")
@click.option("--feed", required=True, help="Feed slug.")
@click.option("--address-header", required=True, help="Column that holds the IP or domain.")
@click.option("--delimiter", help="CSV delimiter (autodetected if omitted).")
@click.option("--priority", default=DEFAULT_PRIORITY, show_default=True)
@click.option("--tlp", default=DEFAULT_TLP, show_default=True)
@click.option("--notes")
@click.option("--reuse-open", is_flag=True, help="Replace the evidence of an open event instead of creating one.")
@click.pass_obj
def report_csv_(make, path, taxonomy, feed, address_header, delimiter, priority, tlp, notes, reuse_open):
    """One event per address in a CSV file, with its rows as evidence."""
    results = report_csv(
        make(), path, taxonomy, feed, address_header, delimiter=delimiter,
        priority=priority, tlp=tlp, notes=notes, reuse_open=reuse_open,
    )
    for result in results:
        click.echo(f"{result.action}: {result.event.get('address_value')} {result.event.get('url')}")


def _address(network):
    return network.get("cidr") or network.get("domain")


@cli.command()
@click.argument("address")
@click.option("--type", "type_", help="Only contacts of this type (email, telegram, phone, uri).")
@click.option("--role", help="Only contacts with this role (abuse, technical, noc...).")
@click.option("--json", "as_json", is_flag=True, help="Print the full objects as JSON.")
@click.pass_obj
def lookup(make, address, type_, role, as_json):
    """Show the network, entity and contacts of ADDRESS (IP, CIDR or domain)."""
    filters = {k: v for k, v in {"type": type_, "role": role}.items() if v}
    result = make().lookup(address, **filters)
    if as_json:
        _echo(dataclasses.asdict(result))
        return
    if not result.network:
        click.echo(f"{address}: no network contains it")
        return
    network = result.network
    click.echo(f"network:  {_address(network)} ({network.get('type')})  {network['url']}")
    for parent in result.networks[1:]:
        click.echo(f"parent:   {_address(parent)}  {parent['url']}")
    entity = result.entity
    click.echo(f"entity:   {entity['name']}  {entity['url']}" if entity else "entity:   -")
    if not result.contacts:
        click.echo("contacts: -")
        return
    click.echo(f"contacts: (from {_address(result.contacts_from)})")
    for contact in result.contacts:
        click.echo(f"  {contact['username']}  {contact.get('name')}  {contact.get('type')}/{contact.get('role')}")


@cli.command()
@click.option("--entities", default=3, show_default=True)
@click.option("--networks", default=20, show_default=True, help="Networks (and contacts) per entity.")
@click.option("--events", default=100, show_default=True)
@click.option("--cases", default=20, show_default=True)
@click.option("--seed", "seed_value", type=int, help="Random seed, for repeatable data.")
@click.option("--clean", is_flag=True, help="Delete the seeded data instead.")
@click.option("--yes", is_flag=True, help="Do not ask for confirmation.")
@click.pass_obj
def seed(make, entities, networks, events, cases, seed_value, clean, yes):
    """Fill the instance with fake data to try Ngen out (needs pyngen[seed])."""
    from . import seed as seeding

    ngen = make()
    action = "Delete the seeded data from" if clean else "Write fake data to"
    if not yes:
        click.confirm(f"{action} {ngen.base_url}?", abort=True)
    if clean:
        seeding.clean(ngen, log=click.echo)
        return
    result = seeding.seed(ngen, entities, networks, events, cases, seed=seed_value, log=click.echo)
    click.echo(
        f"Created {len(result.entities)} entities, {len(result.contacts)} contacts, "
        f"{len(result.networks)} networks, {len(result.events)} events and {len(result.cases)} cases"
    )


def main():
    cli()
