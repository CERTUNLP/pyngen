PyNgen
======

Cli and python library for using Ngen.

Installation
------------

```bash
pip3 install pyngen
```

Usage Python Module
-------------------

```python
from pyngen import PyNgen

#Create object PyNgen
ngen = PyNgen("ngen.example.com", "apiKey", port=443, scheme="https", path="api")

#Minimum data required.
#Add a new Incident for IP "163.10.0.2" for feed "shodan" and Type "open_dns"
incident_id = ngen.newIncident("163.10.0.2","shodan","open_dns")

#more data
another_incident_id = ngen.newIncident("163.10.0.3","shodan","open_dns", evidence="")
```


Usage CLI
---------

```bash
ngen init -key <apikey>  -url http://<ngenurl>/api
```

```bash
ngen newincident -feed shodan -ip 163.10.0.2 -type open_dns
```
