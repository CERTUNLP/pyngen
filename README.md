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
ngen = PyNgen("https://ngen.example.com/", "YOUR_API_KEY")

#Minimum data required.
#Add a new Incident for IP "163.10.0.2" for feed "shodan" and Type "open_dns"
incident_id = ngen.newEvent("163.10.0.2", "shodan", "open_dns")

#upload with txt evidence
another_incident_id = ngen.newEvent("163.0.0.99","another_feed","another_incident_type", evidence_text="text_evidence", notes="Notes for this incident", impact="low", urgency="medium")

```


Usage CLI
---------

```bash
ngen init -apikey <apikey>  -url https://<ngenurl>/
```

```bash
ngen newevent -feed shodan -address 163.10.0.2 -type open_dns
ngen newevent -feed shodan -type spam -address 192.168.0.11 -evidenceFile /tmp/test.txt,/tmp/test2.txt -evidenceText "evidence example text"
```

```bash
ngen reportcsv -feed external_report -type miner -path path/to/file.csv  -addressheader ip
```

