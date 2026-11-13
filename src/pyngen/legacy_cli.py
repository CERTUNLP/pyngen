"""
The ``ngen`` command of pyngen 1.x: ``init``, ``newevent`` and ``reportcsv``,
with the same single-dash options. Credentials live in ``~/.ngen/``, which
the ``pyngen`` command also reads. New scripts should use ``pyngen``.
"""

import sys
from argparse import ArgumentParser, RawTextHelpFormatter

from . import config
from .ngen_exceptions import NewEventFieldError, NgenError, UnauthorizedNgenError
from .pyngen import PyNgen

EPILOG = """
EXAMPLES:
%(prog)s init -apikey 0123456789abcdef -url https://ngen.example.com
%(prog)s newevent -feed external_report -type malware -address ip.or.domain.com
%(prog)s reportcsv -feed external_report -type miner -path path/to/file.csv -addressheader ip"""


def build_parser(argv):
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter, epilog=EPILOG)
    parser.add_argument(
        "revs", metavar="action", choices=["newevent", "init", "reportcsv"],
        help="Set action: %(choices)s",
    )
    needs_event = "newevent" in argv or "reportcsv" in argv

    newevent = parser.add_argument_group("newevent arguments")
    newevent.add_argument("-feed", dest="feed", help="Select feed slug", required=needs_event)
    newevent.add_argument("-type", dest="type", help="Select type slug", required=needs_event)
    newevent.add_argument("-notes", dest="notes", help="Notes for event", default=None)
    newevent.add_argument("-address", dest="address", help="IP or Domain", required="newevent" in argv)
    newevent.add_argument("-evidenceFile", dest="evidenceFile", help="Path(s) of evidence, comma separated", default=None)
    newevent.add_argument("-evidenceText", dest="evidenceText", help="Text to send as evidence", default=None)
    newevent.add_argument("-priority", dest="priority", help="Priority slug (default medium)", default="medium")
    newevent.add_argument("-tlp", dest="tlp", help="TLP slug (default amber)", default="amber")

    init = parser.add_argument_group("init arguments")
    init.add_argument("-apikey", dest="apikey", help="Set API KEY for init", required="init" in argv)
    init.add_argument("-url", dest="url", help="Set Ngen URL for init", required="init" in argv)

    csv = parser.add_argument_group("reportcsv arguments")
    csv.add_argument("-path", dest="pathcsv", help="Set Path of CSV file", required="reportcsv" in argv)
    csv.add_argument("-addressheader", dest="address_header", help="Set CSV Address field", required="reportcsv" in argv)
    csv.add_argument("-delimiter", dest="delimiter", help="(Optional) Set delimiter for CSV. For TAB use $'\\t'", default=None)
    return parser


def inits(url, apikey):
    """Validate the credentials and store them in ~/.ngen."""
    url, apikey = url.strip(), apikey.strip()
    try:
        PyNgen(url, apikey)
    except UnauthorizedNgenError as e:
        sys.exit(f"Error: {e.detail}")
    directory = config.save(url, apikey)
    print(f"Saved url and apikey in {directory}")


def getpyngen():
    settings = config.load()
    if not settings["url"] or not settings["token"]:
        print("Please use init first")
        sys.exit(2)
    return PyNgen(settings["url"], settings["token"], verify=settings["verify"])


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    args = build_parser(argv).parse_args(argv)
    try:
        if args.revs == "init":
            inits(args.url, args.apikey)
        elif args.revs == "newevent":
            ngen = getpyngen()
            try:
                res = ngen.newEvent(
                    args.address, args.feed, args.type,
                    evidence_text=args.evidenceText, evidence_file=args.evidenceFile,
                    notes=args.notes, priority=args.priority, tlp=args.tlp,
                )
                print(f"Added event: {res}")
            except NewEventFieldError as e:
                print(f"Error creating event: \n{e.detail}")
                sys.exit(2)
        elif args.revs == "reportcsv":
            ngen = getpyngen()
            results = ngen.reportFromPathCSV(
                args.pathcsv, args.feed, args.type, args.address_header, delimiter=args.delimiter
            )
            print(f"Added {len(results)} events")
    except NgenError as e:
        print(f"Error: {e.detail}")
        sys.exit(1)


if __name__ == "__main__":
    main()
