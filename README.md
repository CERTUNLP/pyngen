PyNgen
======

Cli and python library for using Ngen.


Instalation
-----------
```bash
pip3 install pyngen
```

Usage Python Module
-------------------

```python
from pyngen import PyNgen

#Create object PyNgen
pyngen = PyNgen("<urlNgen", "ApiKey", port=443, scheme="https", path="api")

#Add a new Incident in ip "163.10.0.2" for feed "shodan" and Type "open_dns"
id = ngen.newIncident("163.10.0.2","shodan","open_dns")
```


Usage CLI
---------

 //To Do
