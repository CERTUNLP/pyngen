"""
Fill an Ngen instance with fake data to try it out.

Creates entities, contacts, networks, events (with evidence) and cases using
only what the instance already has (taxonomies, feeds, priorities, TLPs and
states), so it works on a fresh install. Needs the ``seed`` extra (Faker).

Everything stays in reserved address space, because Ngen notifies the
contacts of the networks by email: IPs come from the documentation ranges
(RFC 5737) and domains end in ``.seed.example`` (RFC 2606), so no real
host or mailbox is ever touched. ``clean()`` removes what ``seed()`` made.
"""

import ipaddress
import random
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .exceptions import NgenAPIError, NgenNotFoundError
from .resources import id_from_url

TAG = "seed"
DOMAIN = "seed.example"
ENTITY_MARK = "[seed"
ENTITY_RE = re.compile(r"\[seed [0-9a-f]{6}\]$")
RANGES = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
SUBNET_PREFIX = 28
ROLES = ["technical", "administrative", "abuse", "notifications", "noc"]


@dataclass
class SeedResult:
    entities: list = field(default_factory=list)
    contacts: list = field(default_factory=list)
    networks: list = field(default_factory=list)
    events: list = field(default_factory=list)
    cases: list = field(default_factory=list)


def _faker(seed):
    try:
        from faker import Faker
    except ImportError:
        raise ImportError("seeding needs Faker: pip install 'pyngen[seed]'") from None
    fake = Faker()
    fake.seed_instance(seed)
    return fake


def _slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _catalog(resource, **filters):
    items = [i for i in resource.list(**filters) if i.get("active", True)]
    if not items:
        raise NgenNotFoundError(404, resource.client.url(resource.path), "nothing to choose from")
    return items


def _free_subnets(ngen):
    """Documentation /28s that no network of the instance uses yet."""
    used = set()
    for net in RANGES:
        for network in ngen.networks.list(is_subnet_of=str(net)):
            if network.get("cidr"):
                used.add(ipaddress.ip_network(network["cidr"]))
    return [
        subnet
        for net in RANGES
        for subnet in net.subnets(new_prefix=SUBNET_PREFIX)
        if not any(subnet.overlaps(u) for u in used)
    ]


def _event_address(rng, network):
    if network.get("cidr"):
        hosts = list(ipaddress.ip_network(network["cidr"]).hosts())
        return str(rng.choice(hosts))
    return rng.choice(["", "www.", "mail.", "vpn."]) + network["domain"]


def _evidence(fake, address):
    lines = [f"{fake.date_time_this_month().isoformat()} {address} {fake.sentence()}" for _ in range(5)]
    return (f"{address}.log", "\n".join(lines).encode())


def seed(ngen, entities=3, networks=20, events=100, cases=20, seed=None, log=print):
    """
    Create fake data in ``ngen`` and return what was created.

    ``networks`` is per entity and each network gets its own contact. Events
    fall inside those networks; ``cases`` groups 1 to 3 of the events that
    Ngen did not put in a case on its own. Same ``seed``, same data.
    """
    counts = {"entities": entities, "networks": networks, "events": events, "cases": cases}
    for name, value in counts.items():
        if not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
    if events and not (entities and networks):
        raise ValueError("events need at least one entity with one network")
    if cases and not events:
        raise ValueError("cases need at least one event")

    fake = _faker(seed)
    rng = random.Random(seed)
    run = secrets.token_hex(3)  # keeps slugs and domains unique across runs
    result = SeedResult()

    taxonomies = _catalog(ngen.taxonomies, alias_of__isnull=True)
    feeds = _catalog(ngen.feeds)
    priorities = _catalog(ngen.priorities)
    tlps = _catalog(ngen.tlps)
    states = _catalog(ngen.states)
    # Ngen mails the contacts whose priority severity is >= the event's and, when
    # none qualifies, the contacts of the parent networks (which may be real):
    # the least severe priority makes the seeded contact qualify for everything
    contact_priority = max(priorities, key=lambda p: p.get("severity", 0))
    subnets = _free_subnets(ngen)
    rng.shuffle(subnets)

    log(f"Creating {entities} entities with {networks} networks each...")
    for _ in range(entities):
        company = fake.unique.company()
        entity = ngen.entities.create(name=f"{company} {ENTITY_MARK} {run}]")
        result.entities.append(entity)
        base = f"{_slug(company)}.{run}.{DOMAIN}"
        network_type = rng.choice(["internal", "internal", "external"])

        for n in range(networks):
            domain = f"n{n}.{base}"
            first, last = fake.unique.first_name(), fake.last_name()
            contact = ngen.contacts.create(
                name=f"{first} {last}",
                username=f"{_slug(first)}.{_slug(last)}@{domain}",
                type="email",
                role=rng.choice(ROLES),
                priority=contact_priority["url"],
                networks=[],  # required, linked from the network below
            )
            result.contacts.append(contact)

            use_ip = subnets and rng.random() < 0.5
            network = ngen.networks.create(
                type=network_type,
                address_value=str(subnets.pop()) if use_ip else domain,
                contacts=[contact["url"]],
                network_entity=entity["url"],
            )
            result.networks.append(network)

    log(f"Creating {events} events...")
    now = datetime.now(timezone.utc)
    for _ in range(events):
        address = _event_address(rng, rng.choice(result.networks))
        event = ngen.events.create(
            address_value=address,
            taxonomy=rng.choice(taxonomies)["url"],
            feed=rng.choice(feeds)["url"],
            priority=rng.choice(priorities)["url"],
            tlp=rng.choice(tlps)["url"],
            date=(now - timedelta(minutes=rng.randrange(60 * 24 * 30))).isoformat(),
            notes=fake.sentence(),
            tags=[TAG],
            evidence=[_evidence(fake, address)],
        )
        result.events.append(event)

    log(f"Creating {cases} cases...")
    loose = [e for e in result.events if not e.get("case") and not e.get("parent")]
    rng.shuffle(loose)
    for _ in range(cases):
        group = [loose.pop() for _ in range(min(rng.randint(1, 3), len(loose)))]
        if not group:
            log("No events left without a case")
            break
        try:
            case = ngen.cases.create(
                name=fake.catch_phrase(),
                events=[e["url"] for e in group],
                state=rng.choice(states)["url"],
                priority=rng.choice(priorities)["url"],
                tlp=rng.choice(tlps)["url"],
                date=now.isoformat(),
                tags=[TAG],
                artifacts=[],  # required on create
            )
        except NgenAPIError as e:
            # An event may have been merged or put in a case since it was created
            log(f"Skipped a case: {e}")
            continue
        result.cases.append(case)

    return result


def _seeded_domain(name):
    """``name`` is ``seed.example`` or a subdomain of it (not ``notseed.example``)."""
    name = (name or "").lower().rstrip(".")
    return name == DOMAIN or name.endswith("." + DOMAIN)


def _delete_all(resource, urls, log, name):
    deleted = 0
    for url in urls:
        try:
            resource.delete(url)
            deleted += 1
        except NgenNotFoundError:
            pass
        except NgenAPIError as e:
            log(f"Could not delete {url}: {e}")
    log(f"Deleted {deleted} {name}")
    return deleted


def clean(ngen, log=print):
    """Delete everything ``seed()`` created, on any run."""
    events, cases = {}, {}
    for net in RANGES:
        for event in ngen.events.list(is_subnet_of=str(net)):
            # Shared ranges: only events tagged by seed()
            if TAG in (event.get("tags") or []):
                events[event["url"]] = event
        for case in ngen.cases.list(event_cidr=str(net)):
            cases[case["url"]] = case
    for event in ngen.events.list(is_subdomain_of=DOMAIN):
        # Ngen matches by suffix, so check the domain boundary and the tag ourselves
        if TAG in (event.get("tags") or []) and _seeded_domain(event.get("domain")):
            events[event["url"]] = event
    for case in ngen.cases.list(event_domain=DOMAIN):
        cases[case["url"]] = case

    # Deleting a case deletes its events, so a case only goes when every event
    # in it is a seeded one: cases Ngen opened on its own for seeded events are
    # included, a seeded case an analyst added real events to is kept
    seeded_cases = []
    for url, case in cases.items():
        case_events = set(case.get("events") or [])
        if case_events <= events.keys() and (case_events or TAG in (case.get("tags") or [])):
            seeded_cases.append(url)

    # name__icontains is a substring match: check the full "[seed xxxxxx]" marker
    seeded_entities = [
        e for e in ngen.entities.list(name__icontains=ENTITY_MARK) if ENTITY_RE.search(e.get("name") or "")
    ]
    networks = [
        n["url"]
        for entity in seeded_entities
        for n in ngen.networks.list(network_entity=id_from_url(entity["url"]))
    ]
    contacts = [
        c["url"]
        for c in ngen.contacts.list(username__icontains=f".{DOMAIN}")
        if _seeded_domain(c.get("username", "").rpartition("@")[2])
    ]

    # Events first: a case can't be deleted while it holds events
    _delete_all(ngen.events, events, log, "events")
    _delete_all(ngen.cases, seeded_cases, log, "cases")
    _delete_all(ngen.networks, networks, log, "networks")
    _delete_all(ngen.contacts, contacts, log, "contacts")
    _delete_all(ngen.entities, [e["url"] for e in seeded_entities], log, "entities")
