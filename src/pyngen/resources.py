import io
import ipaddress
import os
import zipfile

from .exceptions import NgenNotFoundError


def address_filter(address):
    """Filter params that match an address exactly: ``cidr`` for IPs, ``domain`` otherwise."""
    try:
        return {"cidr": str(ipaddress.ip_network(address, strict=False))}
    except ValueError:
        return {"domain": address}


def id_from_url(url):
    return int(str(url).rstrip("/").rsplit("/", 1)[-1])


def evidence_files(evidence, zip_name=None):
    """
    Build the multipart ``files`` list for the ``evidence`` field.

    ``evidence`` is a path, a ``(filename, content)`` tuple (``content`` being
    bytes, text or a file object) or a list of those. With ``zip_name`` and
    more than one file everything goes in a single zip: Ngen notifies once per
    evidence, so bundling avoids one email per file.
    """
    if isinstance(evidence, (str, os.PathLike, tuple)):
        evidence = [evidence]

    items = []
    for item in evidence:
        if isinstance(item, (str, os.PathLike)):
            with open(item, "rb") as f:
                items.append((os.path.basename(item), f.read()))
        else:
            name, content = item
            if hasattr(content, "read"):
                content = content.read()
            if isinstance(content, str):
                content = content.encode()
            items.append((name, content))

    if zip_name and len(items) > 1:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in items:
                zf.writestr(name, content)
        return [("evidence", (zip_name, buffer.getvalue(), "application/zip"))]

    return [("evidence", (name, content)) for name, content in items]


class Resource:
    """CRUD over one Ngen endpoint, for example ``/api/network/``."""

    def __init__(self, client, path):
        self.client = client
        self.path = f"/api/{path.strip('/')}/"

    def _url(self, id_or_url):
        if isinstance(id_or_url, str) and id_or_url.startswith(("http://", "https://")):
            return id_or_url
        return f"{self.path}{id_or_url}/"

    def list(self, **filters):
        """Iterate every result, following pagination. ``filters`` go as query params."""
        return self.client.paginate(self.path, params=filters)

    def first(self, **filters):
        return next(iter(self.list(**filters)), None)

    def get(self, id_or_url):
        return self.client.request("GET", self._url(id_or_url))

    def create(self, **fields):
        return self.client.request("POST", self.path, json=fields)

    def update(self, id_or_url, **fields):
        """Full update (PUT): send every required field."""
        return self.client.request("PUT", self._url(id_or_url), json=fields)

    def patch(self, id_or_url, **fields):
        return self.client.request("PATCH", self._url(id_or_url), json=fields)

    def delete(self, id_or_url):
        return self.client.request("DELETE", self._url(id_or_url))

    def by_slug(self, slug):
        """Exact slug lookup. Raises NgenNotFoundError when nothing matches."""
        for item in self.list(slug__icontains=slug):
            if item.get("slug") == slug:
                return item
        raise NgenNotFoundError(404, self.client.url(self.path), f"slug {slug!r}")


class EvidenceResource(Resource):
    """Events and cases: create and patch can attach evidence files."""

    def create(self, evidence=None, zip_name=None, **fields):
        if not evidence:
            return super().create(**fields)
        return self.client.request(
            "POST", self.path, data=fields, files=evidence_files(evidence, zip_name)
        )

    def patch(self, id_or_url, evidence=None, zip_name=None, **fields):
        if not evidence:
            return super().patch(id_or_url, **fields)
        return self.client.request(
            "PATCH",
            self._url(id_or_url),
            data=fields,
            files=evidence_files(evidence, zip_name),
        )


class EventResource(EvidenceResource):
    def for_address(self, address, **filters):
        """Events whose address is exactly ``address`` (IP, CIDR or domain)."""
        return self.list(**address_filter(address), **filters)


class CaseResource(EvidenceResource):
    def for_address(self, address, **filters):
        """Cases with an event inside ``address`` (subnets and subdomains included)."""
        key = "event_cidr" if "cidr" in address_filter(address) else "event_domain"
        return self.list(**{key: address}, **filters)

    def is_open(self, case):
        """``case`` is a dict or a URL/id. Closed cases are ``blocked`` in Ngen."""
        if not isinstance(case, dict):
            case = self.get(case)
        return not case.get("blocked", False)


def _specificity(network):
    # Only one family matches an address, so prefix length and domain length never mix
    if network.get("cidr"):
        return ipaddress.ip_network(network["cidr"]).prefixlen
    return len(network.get("domain") or "")


class NetworkResource(Resource):
    def containing(self, address, **filters):
        """Networks that contain ``address`` (IP, CIDR or domain), most specific first."""
        networks = list(self.list(supernet_of=address, **filters))
        return sorted(networks, key=_specificity, reverse=True)

    def for_address(self, address, **filters):
        """The most specific network containing ``address``, or None."""
        return next(iter(self.containing(address, **filters)), None)


class ContactResource(Resource):
    def for_network(self, network, **filters):
        """Contacts assigned to ``network`` (a dict or a URL/id), without inheritance."""
        if isinstance(network, dict):
            network = network["url"]
        if isinstance(network, str):
            network = id_from_url(network)
        return self.list(network_id=network, **filters)

    def inherited(self, networks, **filters):
        """
        ``(network, contacts)`` for the first of ``networks`` with contacts, or
        ``(None, [])``. Ngen notifies the contacts of the most specific network
        and falls back to the closest parent that has some.
        """
        for network in networks:
            contacts = list(self.for_network(network, **filters))
            if contacts:
                return network, contacts
        return None, []

    def for_address(self, address, **filters):
        """Contacts Ngen would notify for ``address``. ``filters`` like ``type="email"``."""
        return self.inherited(self.client.networks.containing(address), **filters)[1]
