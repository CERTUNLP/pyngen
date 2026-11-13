"""
Who is behind an address: its network, entity and contacts.

Follows the rules Ngen uses to notify an event: the most specific network that
contains the address wins, and its contacts are inherited from the closest
parent network when it has none of its own.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LookupResult:
    address: str
    network: Optional[dict] = None  # most specific network containing the address
    networks: list = field(default_factory=list)  # every containing network, most specific first
    entity: Optional[dict] = None
    contacts: list = field(default_factory=list)
    contacts_from: Optional[dict] = None  # network the contacts belong to


def lookup(ngen, address, **contact_filters):
    """
    Network, entity and contacts of ``address`` (IP, CIDR or domain).

    The entity is the one of the most specific network that has an entity.
    ``contact_filters`` narrow the contacts, e.g. ``type="email"`` or
    ``role="abuse"``, before falling back to the parent networks.
    """
    networks = ngen.networks.containing(address)
    result = LookupResult(address, networks[0] if networks else None, networks)

    entity_url = next((n["network_entity"] for n in networks if n.get("network_entity")), None)
    if entity_url:
        result.entity = ngen.entities.get(entity_url)

    result.contacts_from, result.contacts = ngen.contacts.inherited(networks, **contact_filters)
    return result
