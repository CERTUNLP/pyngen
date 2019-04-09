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

#Add a new Incident for IP "163.10.0.2" for feed "shodan" and Type "open_dns"
incident_id = ngen.newIncident("163.10.0.2","shodan","open_dns")
```


Usage CLI
---------

//In process
