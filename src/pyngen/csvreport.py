"""
Report every address found in a CSV, one event per address.

Rows are grouped by the column that holds the address and each group is sent
as the evidence of its event, as a CSV with the same header. This is what
pyngen 1.x ``reportFrom*CSV`` did; :func:`report_csv` adds the option to reuse
the open event of each address like :func:`pyngen.report.report`.
"""

import csv
import io
import os

from .report import DEFAULT_PRIORITY, DEFAULT_TLP, ReportResult, report


def sniff_delimiter(sample, default=","):
    """Delimiter of ``sample`` among tab, ``;``, ``,``, space and ``:``."""
    try:
        return csv.Sniffer().sniff(sample, delimiters="\t;, :").delimiter
    except csv.Error:
        return default


def group_rows(csv_file, address_header, delimiter=None):
    """
    ``{address: csv_text}`` from a file object (or text): the rows of each
    address, written back as CSV with a sorted header.
    """
    if isinstance(csv_file, str):
        csv_file = io.StringIO(csv_file)
    if not delimiter:
        delimiter = sniff_delimiter(csv_file.read())
        csv_file.seek(0)

    reader = csv.DictReader(csv_file, delimiter=delimiter)
    if reader.fieldnames is None:  # empty input
        return {}
    if address_header not in reader.fieldnames:
        raise ValueError(
            f"column {address_header!r} not found in the CSV header: {', '.join(reader.fieldnames)}"
        )

    groups = {}
    for row in reader:
        address = (row.get(address_header) or "").strip()
        if not address:
            continue
        groups.setdefault(address, []).append(row)

    evidence = {}
    for address, rows in groups.items():
        out = io.StringIO()
        writer = csv.DictWriter(out, sorted(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
        evidence[address] = out.getvalue()
    return evidence


def group_lines(
    text,
    header_pos_start,
    header_pos_end,
    evidence_pos_start,
    address_pos,
    delimiter,
    delimiter_desired=",",
    line_delimiter=None,
    comment=None,
):
    """
    ``{address: text}`` for files that are not quite CSV: ``text`` is split in
    lines, ``header_pos_start:header_pos_end`` are the header lines, the data
    starts at ``evidence_pos_start`` and the address is column
    ``address_pos`` after splitting by ``delimiter``. Lines starting with
    ``comment`` are dropped. The evidence is the header plus the lines of the
    address, with ``delimiter`` replaced by ``delimiter_desired``.
    """
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    if not line_delimiter:
        line_delimiter = "\r\n" if "\r\n" in text else "\n"

    lines = text.strip().split(line_delimiter)
    header = lines[header_pos_start:header_pos_end]
    data = [line.replace(delimiter, delimiter_desired) for line in lines[evidence_pos_start:]]
    if comment:
        data = [line for line in data if not line.startswith(comment)]

    groups = {}
    for line in data:
        address = line.split(delimiter_desired)[address_pos]
        groups.setdefault(address, []).append(line)

    return {
        address: "\n".join(header + rows) for address, rows in groups.items()
    }


def report_csv(
    ngen,
    source,
    taxonomy,
    feed,
    address_header,
    delimiter=None,
    priority=None,
    tlp=None,
    notes=None,
    tags=None,
    reuse_open=False,
    evidence_name="evidence.csv",
):
    """
    One event per address in ``source`` (a path, a file object or CSV text).

    With ``reuse_open`` each address goes through :func:`pyngen.report.report`,
    so an open event gets its evidence replaced instead of a new event being
    created. Returns a list of :class:`ReportResult`.
    """
    if isinstance(source, (str, os.PathLike)) and os.path.exists(source):
        with open(source, newline="") as f:
            groups = group_rows(f, address_header, delimiter)
    else:
        groups = group_rows(source, address_header, delimiter)

    results = []
    for address, text in groups.items():
        evidence = [(evidence_name, text.encode())]
        if reuse_open:
            results.append(
                report(ngen, address, taxonomy, feed, evidence, priority=priority, tlp=tlp,
                       notes=notes, tags=tags)
            )
        else:
            event = ngen.events.create(
                address_value=address,
                taxonomy=taxonomy,
                feed=feed,
                priority=priority or DEFAULT_PRIORITY,
                tlp=tlp or DEFAULT_TLP,
                notes=notes,
                tags=tags,
                evidence=evidence,
            )
            results.append(ReportResult("created", event))
    return results
