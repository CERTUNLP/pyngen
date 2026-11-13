"""
Report evidence for an address, reusing the open event when there is one.

Meant for periodic scanners (Nessus, OpenVAS, nuclei...): each run sends the
latest report for a host and Ngen keeps a single event per host and taxonomy
until its case is closed.
"""

from dataclasses import dataclass

from .exceptions import NgenNotFoundError, NgenValidationError
from .resources import evidence_files

# Ngen (2.6) requires priority and tlp on every event; these match what pyngen 1.x sent
DEFAULT_PRIORITY = "medium"
DEFAULT_TLP = "amber"


@dataclass
class ReportResult:
    action: str  # "created", "updated" or "unchanged"
    event: dict


def _matches_taxonomy(event, taxonomy):
    # initial_taxonomy_slug keeps matching after an analyst reclassifies the event
    return event.get("taxonomy") == taxonomy["url"] or (
        event.get("initial_taxonomy_slug") == taxonomy["slug"]
    )


def _taxonomy(ngen, taxonomy):
    if isinstance(taxonomy, dict):
        return taxonomy
    if "://" in taxonomy:
        return ngen.taxonomies.get(taxonomy)
    return ngen.taxonomies.by_slug(taxonomy)


def find_open_event(ngen, address, taxonomy):
    """
    Newest event for ``address`` with ``taxonomy`` (a slug, URL or taxonomy
    dict) whose case is still open. Events already in a case win over loose
    ones. Events merged into another one (``parent``) are skipped.
    """
    taxonomy = _taxonomy(ngen, taxonomy)

    events = [
        e
        for e in ngen.events.for_address(address, parent__isnull=True)
        if _matches_taxonomy(e, taxonomy)
    ]
    events.sort(key=lambda e: (bool(e.get("case")), e.get("modified") or ""), reverse=True)

    for event in events:
        if not event.get("case") or ngen.cases.is_open(event["case"]):
            return event
    return None


def _duplicate_evidence(error):
    """
    ``error`` is Ngen rejecting a file the event already holds (one copy of
    each file per event, unique on the content hash). Other ``file`` errors
    (an invalid upload) are not duplicates.
    """
    if not isinstance(error.body, dict) or "file" not in error.body:
        return False
    messages = error.body["file"]
    if not isinstance(messages, list):
        messages = [messages]
    detail = str(error.body.get("_detail") or "")
    # Django's unique message is localized ("already exists", "Ya existe"); the
    # database detail is not
    return "unique constraint" in detail or any("exist" in str(m).lower() for m in messages)


def report(
    ngen,
    address,
    taxonomy,
    feed,
    evidence,
    priority=None,
    tlp=None,
    notes=None,
    tags=None,
    replace_evidence=True,
    zip_name=None,
):
    """
    Attach ``evidence`` to the open event for ``address``/``taxonomy``, or
    create a new event if there is none (or its case is closed).

    ``taxonomy``, ``feed``, ``priority`` and ``tlp`` are slugs or URLs;
    ``priority`` and ``tlp`` default to ``medium`` and ``amber`` since Ngen
    requires them. With ``replace_evidence`` the previous evidence of the
    event is deleted once the new one is uploaded, so it only holds the
    latest report; without it, sending a file the event already has gives
    ``action == "unchanged"``. Several files are zipped into ``zip_name``
    (default ``<address>.zip``) because Ngen notifies once per evidence.
    """
    zip_name = zip_name or f"{address}.zip"
    # Read the files now: a missing or unreadable one fails before anything is touched
    loaded = [(name, content) for _, (name, content, *_) in evidence_files(evidence)]
    if not loaded:
        # with nothing to upload, replacing would only delete the previous evidence
        raise ValueError("report() needs at least one evidence file")
    taxonomy_obj = _taxonomy(ngen, taxonomy)
    event = find_open_event(ngen, address, taxonomy_obj)

    if event is None:
        created = ngen.events.create(
            address_value=address,
            taxonomy=taxonomy_obj["url"],
            feed=feed,
            priority=priority or DEFAULT_PRIORITY,
            tlp=tlp or DEFAULT_TLP,
            notes=notes,
            tags=tags,
            avoid_auto_merge=True,
            evidence=loaded,
            zip_name=zip_name,
        )
        return ReportResult("created", created)

    previous = list(event.get("evidence") or [])

    def upload():
        return ngen.events.patch(event["url"], evidence=loaded, zip_name=zip_name)

    try:
        updated = upload()
    except NgenValidationError as e:
        if not _duplicate_evidence(e):
            raise
        if not replace_evidence:
            return ReportResult("unchanged", event)
        # The event already holds this file: drop the previous set and upload again
        _delete_evidence(ngen, previous)
        return ReportResult("updated", upload())

    if replace_evidence:
        _delete_evidence(ngen, previous)
        # the PATCH answer was built before the deletion
        updated["evidence"] = [u for u in updated.get("evidence") or [] if u not in previous]
    return ReportResult("updated", updated)


def _delete_evidence(ngen, urls):
    for url in urls:
        try:
            ngen.evidence.delete(url)
        except NgenNotFoundError:
            pass
