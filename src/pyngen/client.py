import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import config
from .auth import JWTAuth, TokenAuth
from .exceptions import (
    NgenAPIError,
    NgenAuthError,
    NgenConfigError,
    NgenNotFoundError,
    NgenValidationError,
)
from .resources import CaseResource, ContactResource, EventResource, NetworkResource, Resource

log = logging.getLogger("pyngen")

_ERRORS = {
    400: NgenValidationError,
    401: NgenAuthError,
    403: NgenAuthError,
    404: NgenNotFoundError,
}


def _form_value(value):
    # multipart has no JSON types: DRF parses "true"/"false" for booleans
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _version():
    try:
        from importlib.metadata import version

        return version("pyngen")
    except Exception:  # not installed, running from a checkout
        return "dev"


class Ngen:
    """
    Ngen REST API client.

    Authenticate with an API key (``token``) or with ``username`` and
    ``password`` (JWT, renewed automatically)::

        ngen = Ngen("https://ngen.example.org", token="...")
        ngen = Ngen.from_env()  # NGEN_URL, NGEN_TOKEN or NGEN_USERNAME/NGEN_PASSWORD, or ~/.ngen
    """

    def __init__(
        self,
        url,
        token=None,
        username=None,
        password=None,
        verify=True,
        timeout=30,
        retries=3,
        page_size=100,
    ):
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            raise NgenConfigError(f"url must start with http:// or https://: {url!r}")
        self.base_url = url.rstrip("/")
        self.verify = verify
        self.timeout = timeout
        self.page_size = page_size

        self.session = requests.Session()
        # Retry only idempotent methods (urllib3 default) so a POST never duplicates an event
        retry = Retry(
            total=retries, backoff_factor=0.5, status_forcelist=(502, 503, 504),
            raise_on_status=False,  # hand the last 5xx to send() so it becomes an NgenAPIError
        )
        self.session.mount("http://", HTTPAdapter(max_retries=retry))
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.headers["Accept"] = "application/json"
        self.session.headers["User-Agent"] = f"pyngen/{_version()}"
        self.session.verify = verify

        if token:
            self.auth = TokenAuth(token)
        elif username and password:
            self.auth = JWTAuth(self, username, password)
        else:
            raise NgenConfigError("pass token, or username and password")

        self.events = EventResource(self, "event")
        self.cases = CaseResource(self, "case")
        self.evidence = Resource(self, "evidence")
        self.artifacts = Resource(self, "artifact")
        self.networks = NetworkResource(self, "network")
        self.entities = Resource(self, "entity")
        self.contacts = ContactResource(self, "contact")
        self.taxonomies = Resource(self, "taxonomy")
        self.feeds = Resource(self, "administration/feed")
        self.priorities = Resource(self, "administration/priority")
        self.tlps = Resource(self, "administration/tlp")
        self.states = Resource(self, "state")
        self.tags = Resource(self, "tag")
        self.users = Resource(self, "user")

    @classmethod
    def from_env(cls, **kwargs):
        """
        Build from ``NGEN_URL``, ``NGEN_TOKEN``, ``NGEN_USERNAME``, ``NGEN_PASSWORD``
        and ``NGEN_VERIFY``, falling back to ``~/.ngen/url`` and ``~/.ngen/apikey``
        (what ``ngen init`` writes). Keyword arguments override both.
        """
        settings = config.load()
        configured_url = settings.pop("url")
        url = kwargs.pop("url", None) or configured_url
        if not url:
            raise NgenConfigError("NGEN_URL is not set and there is no ~/.ngen/url")
        if (kwargs.get("username") or kwargs.get("password")) and "token" not in kwargs:
            settings["token"] = None  # explicit JWT credentials win over a saved API key
        settings.update(kwargs)
        return cls(url, **settings)

    def resource(self, path):
        """Any endpoint without a shortcut, for example ``ngen.resource("playbook")``."""
        return Resource(self, path)

    def url(self, path):
        if path.startswith(("http://", "https://")):
            return path
        return self.base_url + "/" + path.lstrip("/")

    def send(self, method, path, params=None, json=None, data=None, files=None):
        """
        Send a request and return the :class:`requests.Response`.

        On POST, ``None`` values are dropped from ``json`` so the server
        applies its defaults; on PUT/PATCH they are sent as ``null`` to clear
        the field. Multipart ``data`` never carries ``None``. Raises a typed
        :class:`NgenAPIError` on 4xx/5xx.
        """
        if isinstance(json, dict) and method.upper() == "POST":
            json = {k: v for k, v in json.items() if v is not None}
        if data is not None:
            data = {k: _form_value(v) for k, v in data.items() if v is not None}
        url = self.url(path)
        log.debug("%s %s params=%s", method, url, params)
        response = self.session.request(
            method,
            url,
            params=params,
            json=json,
            data=data,
            files=files,
            auth=self.auth,
            timeout=self.timeout,
            verify=self.verify,
        )
        log.debug("%s %s -> %s", method, url, response.status_code)
        if response.status_code >= 400:
            try:
                body = response.json()
            except ValueError:
                body = response.text
            error = _ERRORS.get(response.status_code, NgenAPIError)
            raise error(response.status_code, response.url, body)
        return response

    def decode(self, response):
        """JSON body of ``response``, ``None`` when empty. Not JSON -> NgenAPIError."""
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            raise NgenAPIError(
                response.status_code, response.url, f"not JSON: {response.text[:200]!r}"
            ) from None

    def request(self, method, path, params=None, json=None, data=None, files=None):
        """Send a request and return the decoded JSON body (None when empty)."""
        return self.decode(self.send(method, path, params=params, json=json, data=data, files=files))

    def paginate(self, path, params=None):
        params = {"page_size": self.page_size, **(params or {})}
        page = self.request("GET", path, params=params)
        while True:
            # Endpoints without pagination answer with a plain list
            if isinstance(page, list):
                yield from page
                return
            yield from page.get("results", [])
            if not page.get("next"):
                return
            page = self.request("GET", page["next"])

    def lookup(self, address, **contact_filters):
        """Network, entity and contacts of ``address``: see :func:`pyngen.lookup.lookup`."""
        from .lookup import lookup

        return lookup(self, address, **contact_filters)

    def version(self):
        """``/api/version/``: version, commit, branch and environment of the server."""
        return self.request("GET", "/api/version/")

    def logout(self):
        if isinstance(self.auth, JWTAuth):
            self.auth.logout()
