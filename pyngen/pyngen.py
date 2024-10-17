# encoding: utf8
import requests
import logging
import csv
import _csv
import json
import socket
import filemime
import re
import tempfile
import os
from io import StringIO
from slugify import slugify
from urllib.parse import urlsplit, urlparse
from .ngen_exceptions import *
from .lib import *


class PyNgen:

    def __init__(self, url, apikey, debug=False, timeout=5):
        url = urlparse(url)
        if url.scheme == "http":
            self.port = 80
            self.scheme = url.scheme
        elif url.scheme == "https":
            self.port = 443
            self.scheme = url.scheme
        else:
            raise (SchemeNotSettedError("Please set http/https"))
        if url.port != None:
            self.port = url.port
        self.apikey = apikey
        self.hostname = url.hostname
        self.path = url.path if not url.path.endswith("/") else url.path[:-1]
        self.logger = logging.getLogger(__name__)
        self.timeout = timeout
        if debug:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
        # check URL
        # check apikey
        # self.logger.info(self._completeUrl("/api"))
        self.checkUrl()

    # GENERICS
    def _getNames(self, col):
        return [elem["name"] for elem in col]

    def _getSlugs(self, col):
        return [elem["slug"] for elem in col]

    def _isActive(self, elem):
        return elem["is_active"]

    def getVersion(self):
        # TODO PYNGEN GET VERSION
        return "1.0"

    def isSupportedVersion(self):
        return self._isSupportedVersion(self.getVersion())

    def _isSupportedVersion(self, version):
        # TODO : Completar supporteds de alguna manera.
        supporteds = ["1.0", "1.1"]
        return version in supporteds

    # ==============================================
    # FEEDS
    # ==============================================

    def _getFeeds(self):
        return self._action("/api/administration/feed/", "GET")

    def _getFeedFor(self, slug):
        return [
            e
            for e in self._action("/api/administration/feed/", "GET")["data"]
            if e["slug"] == slug
        ][0]

    def _selectField(self, data, field):
        if field != None:
            return [elem[field] for elem in data]
        else:
            return data

    def getFeeds(self, field=None):
        """
        Get All feeds.
        Optional send field: id, slug, name, etc.
        """
        data = self._getFeeds()
        return self._selectField(data, field)

    def getActiveFeeds(self, field=None):
        """
        Get All active feeds.
        Optional send field "argument" with: id, slug, name, etc.
        """
        data = [elem for elem in self._getFeeds() if self._isActive(elem)]
        return self._selectField(data, field)

    def newFeed(self, name):
        """
        Creates a new feed with name.
        Keyword arguments:
            name: Name for the feed.
        """
        data = {"name": name}
        return self._action("/api/feed", "POST", data=data)["data"][0]["slug"]

    def getFeed(self, slug):
        """
        Return a feed vía slug name.
        Get all slugs with getFeeds(field="slug")
        """
        feeds = self.getFeeds()
        for i in feeds:
            if i["slug"] == slug:
                return i

    def editFeed(self, slug, **kargs):
        """
        Edit a feed vía slug name.
        Get all slugs with getFeeds(field="slug")
        **kargs keys: name, slug.
        """
        res = self._action("/api/feeds/{}".format(slug), "PATCH", data=kargs)
        return res["data"]

    #        return self._action("api/feeds", "POST",data=data)['data']

    # ==============================================
    # INCIDENT TAXONOMY
    # ==============================================

    def _getEventTaxonomy(self):
        return self._action("/api/taxonomy", "GET")

    def _getTaxonomyFor(self, slug):
        return [
            e
            for e in self._action("/api/taxonomy/", "GET")["data"]
            if e["slug"] == slug
        ][0]

    def getEventTypes(self, field=None):
        data = self._getEventTaxonomy()
        return self._selectField(data, field)

    def getActiveEventTypes(self, field=None):
        data = [elem for elem in self._getEventTaxonomy() if self._isActive(elem)]
        return self._selectField(data, field)

    def _getSlugFor(self, name):
        return slugify(name, separator="_")

    def newEventType(self, name, slug=None):
        """
        Creates a new Event type with name.
        Keyword arguments:
            name: Name for the feed.
        Returns:
            Slug name
        """
        data = {"name": name}
        return self._action("/api/taxonomy", "POST", data=data)["data"][0]["slug"]

    def editEventType(self, slug, **kargs):
        """
        Edit a event type vía slug name.
        Get all slugs with getEventTaxonomy(field="slug")
        **kargs keys: name, slug.
        """
        res = self._action("/api/taxonomy/{}".format(slug), "PATCH", data=kargs)
        return res["data"]

    # ==============================================
    # INCIDENT TLP
    # ==============================================

    def _getTLPFor(self, slug):
        return [
            e
            for e in self._action("/api/administration/tlp/", "GET")["data"]
            if e["slug"] == slug
        ][0]

    # ==============================================
    # INCIDENT PRIORITY
    # ==============================================

    # TODO : Cambiar name por slug cuando ngen priority lo tenga
    def _getPriorityFor(self, slug):
        return [
            e
            for e in self._action("/api/administration/priority/", "GET")["data"]
            if e["name"].lower().replace(" ", "_") == slug
        ][0]

    # ==============================================
    # INCIDENTS
    # ==============================================

    def getEvents(self):
        return self._action("api/internals", "GET")["data"]

    # ==============================================
    # EX network_entity
    # ==============================================
    # Academic Unit cambió el nombre, migrar a "networksalgo(nomeacuerdo)"

    def getAcademicUnit(self):
        self._action("network_entity", "GET")

    # ==============================================
    # Check login
    # ==============================================
    # Debería chequear contra la versión de NGEN, no contra network_entity
    # luego de eso chequear compatibilidad de versiones API/ngen

    def checkUrl(self):
        return self._action("/api/", "GET")

    def _openFile(self, evidence_path):
        fm = filemime.filemime()
        mimetype = fm.load_file(evidence_path, mimeType=True)
        if type(mimetype) == bytes:
            mimetype = mimetype.decode("utf-8")
        data = open(evidence_path, "r").read()

        files = {"evidence_file": ("evidence.txt", data, mimetype, {"Expires": "0"})}
        return files

    def reportFromFileCSV(
        self, csv_file, event_feed, event_taxonomy, address_header, delimiter=None
    ):
        self.logger.debug(
            "In reportFromFileCSV: {} {} {}".format(
                event_feed, event_taxonomy, address_header
            )
        )
        if not delimiter:
            try:
                dialect = csv.Sniffer().sniff(csv_file.read(), delimiters="\t;, :")
                csv_file.seek(0)
                delimiter = dialect.delimiter
                self.logger.info("using autodetect delimiter: {}".format(delimiter))
            except _csv.Error:
                delimiter = ","
                self.logger.warn(
                    "autodetect delimiter failed. using default delimiter ','"
                )

        reader = csv.DictReader(csv_file, delimiter=delimiter)

        # =Group by IP=
        reports = {}
        for row in reader:
            self.logger.debug(row)
            reports.setdefault(row[address_header], []).append(row)

        self.logger.debug(reports)
        for address, evidence in reports.items():
            # evidence = '\n'.join(lines)
            evfile = StringIO()
            evidencecsv = csv.DictWriter(evfile, sorted(evidence[0].keys()))
            evidencecsv.writeheader()
            evidencecsv.writerows(evidence)
            evidence = evfile.getvalue()
            self.logger.debug(address)
            self.logger.debug(evidence)
            self.newEvent(address, event_feed, event_taxonomy, evidence_text=evidence)

    def reportFromPathCSV(
        self, csv_path, event_feed, event_taxonomy, address_header, delimiter=None
    ):
        with open(csv_path, newline="") as csv_file:
            self.reportFromFileCSV(
                csv_file,
                event_feed,
                event_taxonomy,
                address_header,
                delimiter=delimiter,
            )

    def reportFromCSVText(
        self, csv_text, event_feed, event_taxonomy, address_header, delimiter=None
    ):
        self.logger.debug("Converting to StringIO: {}".format(csv_text))
        self.reportFromFileCSV(
            StringIO(csv_text),
            event_feed,
            event_taxonomy,
            address_header,
            delimiter=delimiter,
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
        # TODO: revisar que todos los feeds y tipos de eventes existan
        if type(csv_text) == bytes:
            csv_text = csv_text.decode("utf-8")

        if not line_delimiter:
            if "\r\n" in csv_text:
                line_delimiter = "\r\n"
            else:
                line_delimiter = "\n"

        new_data = csv_text.strip().split(line_delimiter)
        header = new_data[header_pos_start:header_pos_end]

        reports = new_data[evidence_pos_start:]
        lines = [item.replace(delimiter, delimiter_desired) for item in reports]

        # remove comments:
        if comment:
            lines = [item for item in lines if not item.startswith(comment)]

        self.logger.debug("lines: {}".format(lines))

        # GROUP LINES BY IP
        hosts = {}
        for line in lines:
            # Separo evidencias por hosts
            l = line.split(delimiter_desired)
            address = l[address_pos]
            if address in hosts:
                hosts[address].append(line)
            else:
                hosts[address] = [line]

        # REPORTAR
        for address, evidence in hosts.items():
            parsed_evidence = "{}\n{}".format("\n".join(header), "\n".join(evidence))
            self.newEvent(
                address, event_feed, event_taxonomy, evidence_text=parsed_evidence
            )

    # get event by id

    def getEvent(self, id):
        res = self._action("/api/{}".format(id), "GET")
        if res["status_code"] == 200:
            return res["data"]

    def editEvent(self, id, **kargs):
        self.logger.debug(kargs, type(kargs))
        report = dict()
        report.update(kargs)
        res = self._action("/api/{}".format(id), "PATCH", data=kargs)
        return res["data"]

    def _parseError(self, response):
        if response.code == 400:
            msg = json.loads(response.msg)
            ans = "Errors in newEvent.\n"
            if "errors" in msg["errors"]["children"]["feed"].keys():
                feeds = self.getActiveFeeds(field="slug")
                ans += "INVALID FEED slug, the valids are: {}\n".format(
                    ", ".join(feeds)
                )
            if "errors" in msg["errors"]["children"]["type"].keys():
                types = self.getActiveEventTypes(field="slug")
                ans += "INVALID INCIDENT TYPE slug, the valids are: {}\n".format(
                    ", ".join(types)
                )
            if (
                not "errors" in msg["errors"]["children"]["type"].keys()
                and not "errors" in msg["errors"]["children"]["feed"].keys()
            ):
                return response.msg
            return ans

    # generate new report in Ngen.
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
        **kargs,
    ):
        """Qué debería pasar"""
        url_taxonomy = event_taxonomy  # self._getTaxonomyFor(event_taxonomy)['url']
        url_feed = event_feed  # self._getFeedFor(event_feed)['url']
        report = {
            "address_value": address,
            # 'cidr': address,
            # 'domain': 'string', # TODO
            # 'date': '2022-12-07T10:24:54.649Z',
            # 'evidence_file_path': 'string',
            "notes": notes,
            "priority": "medium",
            "tlp": "amber",
            "taxonomy": url_taxonomy,
            "feed": url_feed,
            "artifacts": [],
        }
        report.update(kargs)

        files = []
        if evidence_file:
            for f in evidence_file.split(","):
                if not os.path.exists(f):
                    raise Exception("File not found: {}".format(f))
                files.append(("evidence", (os.path.basename(f), open(f, "rb"))))

        if evidence_text:
            files.append(
                (
                    "evidence",
                    ("evidence.txt", evidence_text, "text/plain", {"Expires": "0"}),
                )
            )

        # response = self._action("/api/event/", "POST", jsondata=report, retries=1)
        response = self._action(
            "/api/event/", "POST", jsondata=report, files=files, retries=1
        )
        return response

    # Bulk insert
    def newEvents(self):
        # To Do
        pass

    def _completeUrl(self, action):
        return "{}://{}:{}{}{}".format(
            self.scheme, self.hostname, self.port, self.path, action
        )
        # TODO: sacar el limit cuando cambie la API

    def _req(self, action, method, jsondata=None, files=None):
        headers = {
            "Authorization": f"Token {self.apikey}",
            # "Content-Type": "application/json",
        }
        session = retry_session(retries=3)
        kwargs = {"headers": headers, "timeout": self.timeout}

        if method == "POST":
            if files:
                kwargs["data"] = jsondata
                kwargs["files"] = files
            else:
                kwargs["json"] = jsondata
        elif method == "PATCH":
            kwargs["json"] = jsondata

        page = 1
        results = []
        res = session.request(
            method,
            self._completeUrl(action),
            params={"page_size": 150, "page": page},
            **kwargs,
        )
        rj = res.json()

        if "results" in rj:
            results.extend(rj["results"])
            while "results" in rj and rj["next"]:
                page += 1
                res = session.request(
                    method,
                    self._completeUrl(action),
                    params={"page_size": 150, "page": page},
                    **kwargs,
                )
                rj = res.json()
                results.extend(rj["results"])
        else:
            results = rj

        # TODO: hacer mas lindo esto
        # r = res.json()
        # r = results
        # r['']

        return session, res, results

    #   Generic action for REST interface
    def _action(self, action, method, jsondata=None, files=None, retries=1):
        for i in range(retries):
            try:
                s, r, res = self._req(action, method, jsondata=jsondata, files=files)
                break
            except requests.exceptions.ReadTimeout as e:
                if i >= retries - 1:
                    raise e

        # self.logger.debug("URL: {}\n\nMETHOD: {}\n\nREQ HEADERS: {}\n\nREQ BODY: {}\n\nRES TEXT: {}\n\nRES HEADERS: {}\n\njsondata: {}\n\nfiles: {}\n\nresponse: {}\n\n".format(
        # r.url, method, r.request.headers, r.request.body, r.text, r.headers, jsondata, str(files)[:200], r))
        if r.status_code == 401:
            raise UnauthorizedNgenError()
        # elif r.status_code == 404:
        #     raise NotFoundError()
        elif r.status_code == 400:
            try:
                rjsondata = json.loads(r.text)
            except:
                raise Exception(
                    "Response code 400. Cannot parse response from Ngen as json: {}".format(
                        r.text
                    )
                )

            if not "errors" in rjsondata:
                raise UnexpectedError(
                    r.status_code,
                    "Unexpected response (errors not in response). {}".format(
                        rjsondata
                    ),
                )
            elif not "fields" in rjsondata["errors"]:
                raise UnexpectedError(
                    r.status_code,
                    "Unexpected response (fields not in errors). {}".format(rjsondata),
                )
            elif "type" in rjsondata["errors"]["fields"]:
                if "is deactivated" in rjsondata["errors"]["fields"]["type"].lower():
                    self.logger.debug("Event type already exists but is deactivated.")
                    raise NewEventTypeDeactivatedError(jsondata, rjsondata)
                else:
                    self.logger.debug("Event type does not exists.")
                    raise NewEventTypeFieldError(jsondata, rjsondata)

            raise NewEventFieldError(jsondata, rjsondata)
        # Temporal
        # ==========
        elif r.status_code == 204:
            return {"status_code": r.status_code, "data": r.text}
        # =========
        elif not r.status_code in [200, 201, 204]:
            raise UnexpectedError(r.status_code, r.text)

        return {"status_code": r.status_code, "data": res}
