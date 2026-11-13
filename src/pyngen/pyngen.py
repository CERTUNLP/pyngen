"""
The pyngen 1.x interface, on top of :class:`pyngen.Ngen`.

Kept so that code written for pyngen 1.x keeps working unchanged::

    from pyngen import PyNgen
    ngen = PyNgen("https://ngen.example.org", "API_KEY")
    ngen.newEvent("192.0.2.10", "shodan", "open_dns", evidence_text="...")

Methods return what they did in 1.x (``{"status_code": ..., "data": ...}``)
and raise the exceptions of :mod:`pyngen.ngen_exceptions`. The pyngen 2
client is available as ``.ngen`` and unknown attributes are delegated to it,
so ``PyNgen(...).events.list()`` works too. New code should use
:class:`pyngen.Ngen` directly.
"""

import logging
import mimetypes
import os
import re
from contextlib import contextmanager
from urllib.parse import urlparse

import requests

from .client import Ngen
from .csvreport import group_lines, group_rows
from .exceptions import NgenAPIError, NgenAuthError, NgenError, NgenValidationError
from .ngen_exceptions import (
    NewEventFieldError,
    NewEventTypeDeactivatedError,
    NewEventTypeFieldError,
    SchemeNotSettedError,
    UnauthorizedNgenError,
    UnexpectedError,
)
from .resources import evidence_files

DEFAULT_PRIORITY = "medium"
DEFAULT_TLP = "amber"


class PyNgen:
    def __init__(self, url, apikey, debug=False, timeout=5, verify=True, retries=3):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise SchemeNotSettedError("Please set http/https")
        self.scheme = parsed.scheme
        self.hostname = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.path = parsed.path.rstrip("/")
        self.apikey = apikey
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        if debug:
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(
                logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            )
            root = logging.getLogger("pyngen")
            root.setLevel(logging.DEBUG)
            root.addHandler(handler)

        self.ngen = Ngen(url, token=apikey, timeout=timeout, verify=verify, retries=retries)
        self.checkUrl()

    def __getattr__(self, name):
        # Anything that is not 1.x API comes from the pyngen 2 client (events, cases, lookup...)
        if name == "ngen":
            raise AttributeError(name)
        return getattr(self.ngen, name)

    # ==============================================
    # Errors: pyngen 2 exceptions -> pyngen 1.x ones
    # ==============================================

    @contextmanager
    def _legacy_errors(self, data=None):
        try:
            yield
        except NgenAuthError as e:
            if e.status_code == 401:
                raise UnauthorizedNgenError(e.status_code, e.url, e.body) from None
            raise UnexpectedError(e.status_code, e.body, e.url) from None
        except NgenValidationError as e:
            body = e.body
            if isinstance(body, dict) and ("taxonomy" in body or "type" in body):
                text = str(body).lower()
                if "deactivated" in text or "inactive" in text or "not active" in text:
                    raise NewEventTypeDeactivatedError(data, body, e.url) from None
                raise NewEventTypeFieldError(data, body, e.url) from None
            raise NewEventFieldError(data, body, e.url) from None
        except NgenAPIError as e:
            raise UnexpectedError(e.status_code, e.body, e.url) from None

    # ==============================================
    # Generic REST access
    # ==============================================

    def _completeUrl(self, action):
        return self.ngen.url(action)

    def _action(self, action, method, jsondata=None, files=None, retries=1, data=None):
        """
        ``{"status_code": ..., "data": ...}`` for one request. GET lists are
        fully paginated. ``retries`` repeats the request on a read timeout
        (careful with POST: the first attempt may have gone through).
        """
        if jsondata is None:
            jsondata = data
        attempts = max(int(retries), 1)
        for attempt in range(attempts):
            try:
                with self._legacy_errors(jsondata):
                    if files:
                        response = self.ngen.send(method, action, data=jsondata, files=files)
                        result = self.ngen.decode(response)
                    elif method == "GET":
                        response = self.ngen.send(
                            method, action, params={"page_size": self.ngen.page_size}
                        )
                        result = self.ngen.decode(response)
                        if isinstance(result, dict) and "results" in result:
                            page, result = result, list(result["results"])
                            while page.get("next"):
                                page = self.ngen.request("GET", page["next"])
                                result.extend(page.get("results", []))
                    else:
                        response = self.ngen.send(method, action, json=jsondata)
                        result = self.ngen.decode(response)
                break
            except requests.exceptions.ReadTimeout:
                if attempt >= attempts - 1:
                    raise
        return {"status_code": response.status_code, "data": "" if result is None else result}

    def checkUrl(self):
        return self._action("/api/", "GET")

    def getVersion(self):
        """Version string of the server, or ``"unknown"`` when it cannot be read."""
        try:
            return self.ngen.version().get("version", "unknown")
        except NgenError:
            return "unknown"

    def isSupportedVersion(self):
        return self._isSupportedVersion(self.getVersion())

    def _isSupportedVersion(self, version):
        return str(version).lstrip("v").startswith("2")

    # ==============================================
    # Helpers
    # ==============================================

    def _getNames(self, col):
        return [elem["name"] for elem in col]

    def _getSlugs(self, col):
        return [elem["slug"] for elem in col]

    def _isActive(self, elem):
        return elem.get("active", elem.get("is_active", True))

    def _selectField(self, data, field):
        if field is not None:
            return [elem[field] for elem in data]
        return data

    def _getSlugFor(self, name):
        return re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")

    def _openFile(self, evidence_path):
        mimetype = mimetypes.guess_type(evidence_path)[0] or "application/octet-stream"
        with open(evidence_path, "rb") as f:
            data = f.read()
        return {"evidence_file": ("evidence.txt", data, mimetype, {"Expires": "0"})}

    # ==============================================
    # FEEDS
    # ==============================================

    def _getFeeds(self):
        return self._action("/api/administration/feed/", "GET")

    def _getFeedFor(self, slug):
        return [e for e in self._getFeeds()["data"] if e["slug"] == slug][0]

    def getFeeds(self, field=None):
        """
        Get all feeds. Without ``field`` this is the raw ``{"status_code", "data"}``
        answer (as in 1.x); with ``field`` a list of that field (``slug``, ``name``...).
        """
        data = self._getFeeds()
        if field is None:
            return data
        return self._selectField(data["data"], field)

    def getActiveFeeds(self, field=None):
        data = [elem for elem in self._getFeeds()["data"] if self._isActive(elem)]
        return self._selectField(data, field)

    def getFeed(self, slug):
        for feed in self._getFeeds()["data"]:
            if feed["slug"] == slug:
                return feed
        return None

    def newFeed(self, name, **kargs):
        """Create a feed and return its slug."""
        data = {"name": name, **kargs}
        return self._action("/api/administration/feed/", "POST", jsondata=data)["data"]["slug"]

    def editFeed(self, slug, **kargs):
        feed = self._getFeedFor(slug)
        return self._action(feed["url"], "PATCH", jsondata=kargs)["data"]

    # ==============================================
    # TAXONOMY (event types)
    # ==============================================

    def _getEventTaxonomy(self):
        return self._action("/api/taxonomy/", "GET")

    def _getTaxonomyFor(self, slug):
        return [e for e in self._getEventTaxonomy()["data"] if e["slug"] == slug][0]

    def getEventTypes(self, field=None):
        data = self._getEventTaxonomy()
        if field is None:
            return data
        return self._selectField(data["data"], field)

    def getActiveEventTypes(self, field=None):
        data = [elem for elem in self._getEventTaxonomy()["data"] if self._isActive(elem)]
        return self._selectField(data, field)

    def newEventType(self, name, slug=None, type="incident", **kargs):
        """Create a taxonomy and return its slug (Ngen derives it from ``name``)."""
        data = {"name": name, "type": type, **kargs}
        return self._action("/api/taxonomy/", "POST", jsondata=data)["data"]["slug"]

    def editEventType(self, slug, **kargs):
        taxonomy = self._getTaxonomyFor(slug)
        return self._action(taxonomy["url"], "PATCH", jsondata=kargs)["data"]

    # ==============================================
    # TLP / PRIORITY
    # ==============================================

    def _getTLPFor(self, slug):
        return [
            e for e in self._action("/api/administration/tlp/", "GET")["data"] if e["slug"] == slug
        ][0]

    def _getPriorityFor(self, slug):
        return [
            e
            for e in self._action("/api/administration/priority/", "GET")["data"]
            if e.get("slug") == slug or e["name"].lower().replace(" ", "_") == slug
        ][0]

    # ==============================================
    # ENTITIES (formerly academic units)
    # ==============================================

    def getAcademicUnit(self):
        return self._action("/api/entity/", "GET")["data"]

    # ==============================================
    # EVENTS
    # ==============================================

    def getEvents(self):
        return self._action("/api/event/", "GET")["data"]

    def getEvent(self, id):
        res = self._action(f"/api/event/{id}/", "GET")
        if res["status_code"] == 200:
            return res["data"]
        return None

    def editEvent(self, id, **kargs):
        return self._action(f"/api/event/{id}/", "PATCH", jsondata=kargs)["data"]

    def newEvent(
        self,
        address,
        event_feed,
        event_taxonomy,
        notes=None,
        evidence_text=None,
        evidence_file=None,
        create_type=False,
        retries=1,
        date=None,
        priority=DEFAULT_PRIORITY,
        tlp=DEFAULT_TLP,
        **kargs,
    ):
        """
        Create an event and return ``{"status_code": 201, "data": event}``.

        ``event_feed`` and ``event_taxonomy`` are slugs (or URLs).
        ``evidence_file`` is a path, several paths separated by commas, or a
        list of paths; ``evidence_text`` is uploaded as ``evidence.txt``.
        Extra keyword arguments go into the payload as they are.
        ``create_type`` is accepted for compatibility: Ngen now creates
        unknown taxonomies on its own when ``TAXONOMY_ALLOW_AUTO_CREATE`` is on.
        """
        report = {
            "address_value": address,
            "notes": notes,
            "priority": priority,
            "tlp": tlp,
            "taxonomy": event_taxonomy,
            "feed": event_feed,
            "artifacts": [],
        }
        if date:
            report["date"] = date
        report.update(kargs)

        files = []
        if evidence_file:
            if isinstance(evidence_file, (list, tuple)):
                paths = [str(p) for p in evidence_file]
            else:
                paths = [p.strip() for p in str(evidence_file).split(",") if p.strip()]
            for path in paths:
                if not os.path.exists(path):
                    raise FileNotFoundError(f"File not found: {path}")
            files.extend(evidence_files(paths))
        if evidence_text:
            files.append(
                ("evidence", ("evidence.txt", evidence_text, "text/plain", {"Expires": "0"}))
            )

        return self._action("/api/event/", "POST", jsondata=report, files=files or None, retries=retries)

    newIncident = newEvent

    def newEvents(self, events=()):
        """Create several events; each item is a dict of ``newEvent`` arguments."""
        return [self.newEvent(**event) for event in events]

    # ==============================================
    # CSV reports: one event per address
    # ==============================================

    def _reportGroups(self, groups, event_feed, event_taxonomy):
        results = []
        for address, evidence in groups.items():
            self.logger.debug("reporting %s", address)
            results.append(
                self.newEvent(address, event_feed, event_taxonomy, evidence_text=evidence)
            )
        return results

    def reportFromFileCSV(self, csv_file, event_feed, event_taxonomy, address_header, delimiter=None):
        groups = group_rows(csv_file, address_header, delimiter)
        return self._reportGroups(groups, event_feed, event_taxonomy)

    def reportFromPathCSV(self, csv_path, event_feed, event_taxonomy, address_header, delimiter=None):
        with open(csv_path, newline="") as csv_file:
            return self.reportFromFileCSV(
                csv_file, event_feed, event_taxonomy, address_header, delimiter=delimiter
            )

    def reportFromCSVText(self, csv_text, event_feed, event_taxonomy, address_header, delimiter=None):
        return self.reportFromFileCSV(
            csv_text, event_feed, event_taxonomy, address_header, delimiter=delimiter
        )

    def reportFromMalformedCSV(
        self,
        csv_text,
        event_feed,
        event_taxonomy,
        header_pos_start,
        header_pos_end,
        evidence_pos_start,
        address_pos,
        delimiter,
        delimiter_desired=",",
        line_delimiter=None,
        comment=None,
    ):
        groups = group_lines(
            csv_text,
            header_pos_start,
            header_pos_end,
            evidence_pos_start,
            address_pos,
            delimiter,
            delimiter_desired=delimiter_desired,
            line_delimiter=line_delimiter,
            comment=comment,
        )
        return self._reportGroups(groups, event_feed, event_taxonomy)
