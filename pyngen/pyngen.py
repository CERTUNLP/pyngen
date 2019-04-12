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
from urllib.parse import urlsplit, urlparse
from .NgenExceptions import *

class PyNgen():

    def __init__(self, url, api_key, port=443, scheme="https", path="app_dev.php/api", format="json", debug=False):
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
        self.debug= debug
        self.api_key = api_key
        self.hostname = url.hostname
        self.path = path
        self.format = format
        self.logger = logging.getLogger(__name__)
        # check URL
        # check api_key
        # print (self._completeUrl("/incidents"))
        self.checkUrl()

    # GENERICS
    def _getNames(self, col):
        return [elem['name'] for elem in col]

    def _getSlugs(self, col):
        return [elem['slug'] for elem in col]

    def _isActive(self, elem):
        return elem['is_active']

    def getVersion(self):
        #TODO PYNGEN GET VERSION
        return "1.0"

    def isSupportedVersion(self):
        return self._isSupportedVersion(self.getVersion())

    def _isSupportedVersion(self, version):
        #TODO : Completar supporteds de alguna manera.
        supporteds=["1.0","1.1"]
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


    def newFeed(self,name):
        """
        Creates a new feed with name.
        Keyword arguments:
            name: Name for the feed.
        """
        data={"name":name}
        return self._action("/incidents/feeds", "POST",data=data)["data"][0]["slug"]

    def getFeed(self, slug):
        """
        Return a feed vía slug name.
        Get all slugs with getFeeds(field="slug")
        """
        feeds=self.getFeeds()
        for i in feeds:
            if (i["slug"]==slug):
                return i

    def editFeed(self, slug, **kargs):
        """
        Edit a feed vía slug name.
        Get all slugs with getFeeds(field="slug")
        **kargs keys: name, slug.
        """
        res=self._action("/incidents/feeds/{}".format(slug),"PATCH",data=kargs)
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

    def newIncidentType(self,name):
        """
        Creates a new Incident type with name.
        Keyword arguments:
            name: Name for the feed.
        Returns:
            Slug name
        """
        data={"name":name}
        return self._action("/incidents/types", "POST",data=data)["data"][0]["slug"]

    def editIncidentType(self, slug, **kargs):
        """
        Edit a incident type vía slug name.
        Get all slugs with getIncidentTypes(field="slug")
        **kargs keys: name, slug.
        """
        res=self._action("/incidents/types/{}".format(slug),"PATCH",data=kargs)
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
        #Acá debería ir get_status ó get_version
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

    def reportFromFileCSV(self, csv_path, feed, type, ip_header, delimiter=',',  is_domain=False):
        with open(csv_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile, delimiter=delimiter)

            # =Group by IP=
            reports = {}
            for row in reader:
                if not row[ip_header] in reports.keys():
                    reports[row[ip_header]] = []
                reports[row[ip_header]].append(row)
            # ==============

        # import pprint
        # pprint.pprint (reports)

        # =Convert evidence to csv and report=
        for ip, dicts in reports.items():
            keys = reports[ip][0].keys()
            with tempfile.NamedTemporaryFile("w", delete=False) as output_file:
                path = output_file.name
                dict_writer = csv.DictWriter(output_file, keys)
                dict_writer.writeheader()
                dict_writer.writerows(reports[ip])
            self.reportFromFile(ip, feed, type, path)
            os.remove(path)
        # =========

    def reportFromCSV(self, incident_type, feed, text_file, header_pos_start, header_pos_end, evidence_pos_start, ip_pos, separtor, separator_desired=',', line_separator=None, is_domain=False, comment=None):
        # TODO: revisar que todos los feeds y tipos de incidentes existan
        if type(text_file) == bytes:
            text_file = text_file.decode('utf-8')

        if not line_separator:
            if '\r\n' in text_file:
                line_separator = '\r\n'
            else:
                line_separator = '\n'

        new_data = text_file.strip().split(line_separator)
        header = new_data[header_pos_start:header_pos_end]

        reports = new_data[evidence_pos_start:]
        lines = [item.replace(separtor, separator_desired)
                 for item in reports]

        # remove comments:
        if comment:
            lines = [
                item for item in lines if not item.startswith(comment)]

        self.logger.info("lines: {}".format(lines))

        # GROUP LINES BY IP
        hosts = {}
        for line in lines:
            # Separo evidencias por hosts
            l = line.split(separator_desired)
            if is_domain:
                domain = urlsplit(l[ip_pos]).hostname
                ip = socket.gethostbyname(domain)
            else:
                net_cleaned = re.sub(r'[^0-9./]', "", l[ip_pos])
                net = net_cleaned.split('/')
                ip = net[0]
            if ip in hosts:
                hosts[ip].append(line)
            else:
                hosts[ip] = [line]

        # REPORTAR
        for ip, evidence in hosts.items():
            parsed_evidence = "{}\n{}".format(
                '\n'.join(header), '\n'.join(evidence))
            self.newIncident(ip, feed, incident_type, evidence=parsed_evidence)


    # get incident by id
    def getIncident(self, id):
        res=self._action("/incidents/{}".format(id),"GET")
        if res["status_code"]==200:
            return res["data"]


    def editIncident (self,id,**kargs):
        print (kargs,type(kargs))
        report = dict()
        report.update(kargs)
        res=self._action("/incidents/{}".format(id),"PATCH",data=kargs)
        return res["data"]

    def _parseError(self, response):
        if (response.code == 400):
            msg = json.loads(response.msg)
            ans = "Errors in newIncident.\n"
            if ("errors" in msg["errors"]["children"]["feed"].keys()):
                feeds = self.getActiveFeeds(field="slug")
                ans += "INVALID FEED slug, the valids are: {}\n".format(", ".join(feeds))
            if ("errors" in msg["errors"]["children"]["type"].keys()):
                types = self.getActiveIncidentTypes(field="slug")
                ans += "INVALID INCIDENT TYPE slug, the valids are: {}\n".format(", ".join(types))
            if (not "errors" in msg["errors"]["children"]["type"].keys() and not "errors" in msg["errors"]["children"]["feed"].keys()):
                return response.msg
            return ans



    # generate new report in Ngen.
    def newIncident(self, address, incident_feed, incident_type, evidence=None, evidence_file=None, **kargs):
        """Qué debería pasar"""
        report = dict(
            type=incident_type,
            address=address,
            feed=incident_feed
        )
        report.update(kargs)

        files=None
        if "evidence_file" in kargs.keys():
            files = self._openFile(evidence_file)
        elif "evidence" in kargs.keys():
            files = {'evidence_file': (
                "evidence.txt", kargs["evidence"], 'text/plain', {'Expires': '0'})}

        fail=False
        try:
            response = self._action("/incidents", "POST", data=report, files=files)
            return response["data"][0]["id"]
        except UnexpectedError as e:
            raise NewIncidentFieldError(e.msg)


    # Bulk insert
    def newIncidents(self):
        # To Do
        pass

    def _completeUrl(self, action):
        return "{}://{}:{}/{}{}.{}?apikey={}".format(self.scheme, self.hostname, self.port, self.path, action, self.format, self.api_key)
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

        if self.debug:
            print("URL: {}\n\nMETHOD: {}\n\nREQ HEADERS: {}\n\nREQ BODY: {}\n\nRES TEXT: {}\n\nRES HEADERS: {}\n\ndata: {}\n\nresponse: {}\n\n".format(
               r.url, method, r.request.headers, r.request.body, r.text, r.headers, data, r))
        if r.status_code == 401:
            raise UnauthorizedNgenError()
        elif r.status_code == 404:
            raise NotFoundError()
        # Temporal
        #==========
        elif r.status_code == 204:
            return {"status_code": r.status_code, "data": r.text}
        #=========
        elif not r.status_code in [200, 201, 204]:
            raise UnexpectedError(r.status_code, r.text)

        data=json.loads(r.text)
        return {"status_code": r.status_code, "data": data}
