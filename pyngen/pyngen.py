# encoding: utf8
import requests
import logging
import csv
import json
import socket
import magic
import re
import tempfile
import os
from io import StringIO
from urllib.parse import urlsplit, urlparse
from .NgenExceptions import *


class PyNgen():

    def __init__(self, url, apikey, incident_format="json"):
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
        self.path = url.path
        self.incident_format = incident_format
        self.logger = logging.getLogger(__name__)
        # check URL
        # check apikey
        # self.logger.info(self._completeUrl("/incidents"))
        self.checkUrl()

    # GENERICS
    def _getNames(self, col):
        return [elem['name'] for elem in col]

    def _getSlugs(self, col):
        return [elem['slug'] for elem in col]

    def _isActive(self, elem):
        return elem['is_active']

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
        return self._action("/incidents/feeds", "GET")['data']

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
        return self._action("/incidents/feeds", "POST", data=data)["data"][0]["slug"]

    def getFeed(self, slug):
        """
        Return a feed vía slug name.
        Get all slugs with getFeeds(field="slug")
        """
        feeds = self.getFeeds()
        for i in feeds:
            if (i["slug"] == slug):
                return i

    def editFeed(self, slug, **kargs):
        """
        Edit a feed vía slug name.
        Get all slugs with getFeeds(field="slug")
        **kargs keys: name, slug.
        """
        res = self._action(
            "/incidents/feeds/{}".format(slug), "PATCH", data=kargs)
        return res["data"]
#        return self._action("incidents/feeds", "POST",data=data)["data"]

    # ==============================================
    # INCIDENT TYPES
    # ==============================================

    def _getIncidentTypes(self):
        return self._action("/incidents/incident/types", "GET")['data']

    def getIncidentTypes(self, field=None):
        data = self._getIncidentTypes()
        return self._selectField(data, field)

    def getActiveIncidentTypes(self, field=None):
        data = [elem for elem in self._getIncidentTypes()
                if self._isActive(elem)]
        return self._selectField(data, field)

    def newIncidentType(self, name):
        """
        Creates a new Incident type with name.
        Keyword arguments:
            name: Name for the feed.
        Returns:
            Slug name
        """
        data = {"name": name}
        return self._action("/incidents/types", "POST", data=data)["data"][0]["slug"]

    def editIncidentType(self, slug, **kargs):
        """
        Edit a incident type vía slug name.
        Get all slugs with getIncidentTypes(field="slug")
        **kargs keys: name, slug.
        """
        res = self._action(
            "/incidents/types/{}".format(slug), "PATCH", data=kargs)
        return res["data"]

    # ==============================================
    # INCIDENTS
    # ==============================================

    def getIncidents(self):
        return self._action("incidents/internals", "GET")['data']

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
        # Acá debería ir get_status ó get_version
        self.getActiveFeeds()
        # To Do

    def _openFile(self, evidence_path):
        mime = magic.Magic(mime=True)
        mimetype = mime.from_file(evidence_path)
        if type(mimetype) == bytes:
            mimetype = mimetype.decode('utf-8')
        data = open(evidence_path, "r").read()

        files = {'evidence_file': (
            "evidence.txt", data, mimetype, {'Expires': '0'})}
        return files

    def reportFromFileCSV(self, csv_file, incident_feed, incident_type, address_header, delimiter=','):
        self.logger.debug("In reportFromFileCSV: {} {} {}".format(
            incident_feed, incident_type, address_header))
        reader = csv.DictReader(csv_file, delimiter=delimiter)
        # =Group by IP=
        reports = {}
        for row in reader:
            self.logger.debug(row)
            reports.setdefault(row[address_header], []).append(row)

        self.logger.debug(reports)
        for address, evidence in reports.items():
            #evidence = '\n'.join(lines)
            evfile = StringIO()
            evidencecsv = csv.DictWriter(evfile, sorted(evidence[0].keys()))
            evidencecsv.writeheader()
            evidencecsv.writerows(evidence)
            evidence = evfile.getvalue()
            self.logger.debug(address)
            self.logger.debug(evidence)
            self.newIncident(address, incident_feed,
                             incident_type, evidence_text=evidence)

    def reportFromPathCSV(self, csv_path, incident_feed, incident_type, address_header, delimiter=','):
        with open(csv_path, newline='') as csv_file:
            self.reportFromFileCSV(
                csv_file, incident_feed, incident_type, address_header, delimiter=delimiter)

    def reportFromCSVText(self, csv_text, incident_feed, incident_type, address_header):
        self.logger.debug("Converting to StringIO: {}".format(csv_text))
        self.reportFromFileCSV(StringIO(csv_text),
                               incident_feed, incident_type, address_header)

    def reportFromMalformedCSV(self, csv_text, incident_feed, incident_type, header_pos_start, header_pos_end, evidence_pos_start, address_pos, delimiter, delimiter_desired=',', line_delimiter=None, comment=None):
        # TODO: revisar que todos los feeds y tipos de incidentes existan
        if type(csv_text) == bytes:
            csv_text = csv_text.decode('utf-8')

        if not line_delimiter:
            if '\r\n' in csv_text:
                line_delimiter = '\r\n'
            else:
                line_delimiter = '\n'

        new_data = csv_text.strip().split(line_delimiter)
        header = new_data[header_pos_start:header_pos_end]

        reports = new_data[evidence_pos_start:]
        lines = [item.replace(delimiter, delimiter_desired)
                 for item in reports]

        # remove comments:
        if comment:
            lines = [
                item for item in lines if not item.startswith(comment)]

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
            parsed_evidence = "{}\n{}".format(
                '\n'.join(header), '\n'.join(evidence))
            self.newIncident(address, incident_feed, incident_type,
                             evidence_text=parsed_evidence)

    # get incident by id

    def getIncident(self, id):
        res = self._action("/incidents/{}".format(id), "GET")
        if res["status_code"] == 200:
            return res["data"]

    def editIncident(self, id, **kargs):
        self.logger.debug(kargs, type(kargs))
        report = dict()
        report.update(kargs)
        res = self._action("/incidents/{}".format(id), "PATCH", data=kargs)
        return res["data"]

    def _parseError(self, response):
        if (response.code == 400):
            msg = json.loads(response.msg)
            ans = "Errors in newIncident.\n"
            if ("errors" in msg["errors"]["children"]["feed"].keys()):
                feeds = self.getActiveFeeds(field="slug")
                ans += "INVALID FEED slug, the valids are: {}\n".format(
                    ", ".join(feeds))
            if ("errors" in msg["errors"]["children"]["type"].keys()):
                types = self.getActiveIncidentTypes(field="slug")
                ans += "INVALID INCIDENT TYPE slug, the valids are: {}\n".format(
                    ", ".join(types))
            if (not "errors" in msg["errors"]["children"]["type"].keys() and not "errors" in msg["errors"]["children"]["feed"].keys()):
                return response.msg
            return ans

    # generate new report in Ngen.

    def newIncident(self, address, incident_feed, incident_type, evidence_text=None, evidence_file=None, **kargs):
        """Qué debería pasar"""
        report = dict(
            type=incident_type,
            address=address,
            feed=incident_feed
        )
        report.update(kargs)

        files = None
        if evidence_file:
            files = self._openFile(evidence_file)
        elif evidence_text:
            files = {'evidence_file': (
                "evidence.txt", evidence_text, 'text/plain', {'Expires': '0'})}

        try:
            response = self._action(
                "/incidents", "POST", data=report, files=files)
            return response["data"][0]["id"]
        except UnexpectedError as e:
            raise NewIncidentFieldError(e.msg)

    # Bulk insert

    def newIncidents(self):
        # To Do
        pass

    def _completeUrl(self, action):
        return "{}://{}:{}{}{}.{}?apikey={}".format(self.scheme, self.hostname, self.port, self.path, action, self.incident_format, self.apikey)
        # TODO: sacar el limit cuando cambie la API

    #   Generic action for REST interface
    def _action(self, action, method, data=None, files=None):
        headers = {}
        if method == "POST":
            r = requests.post(self._completeUrl(
                action), headers=headers, files=files, data=data)
        elif method == "PATCH":
            r = requests.request(method, self._completeUrl(
                action), headers=headers, data=data)
        else:
            r = (requests.request(method, self._completeUrl(
                action), headers=headers, files=files))

        self.logger.debug("URL: {}\n\nMETHOD: {}\n\nREQ HEADERS: {}\n\nREQ BODY: {}\n\nRES TEXT: {}\n\nRES HEADERS: {}\n\ndata: {}\n\nfiles: {}\n\nresponse: {}\n\n".format(
            r.url, method, r.request.headers, r.request.body, r.text, r.headers, data, str(files)[:200], r))
        if r.status_code == 401:
            raise UnauthorizedNgenError()
        elif r.status_code == 404:
            raise NotFoundError()
        # Temporal
        # ==========
        elif r.status_code == 204:
            return {"status_code": r.status_code, "data": r.text}
        # =========
        elif not r.status_code in [200, 201, 204]:
            raise UnexpectedError(r.status_code, r.text)

        data = json.loads(r.text)
        return {"status_code": r.status_code, "data": data}
