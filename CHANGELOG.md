# Changelog

## 2.0.0

New client for Ngen 2 (`pyngen.Ngen`), with the pyngen 1.x interface kept on
top of it. Code written for 1.x keeps working: `from pyngen import PyNgen`,
`pyngen.ngen_exceptions`, `pyngen.lib.retry_session` and the `ngen` command.

### Added

- `Ngen` client: API key or username/password (JWT, renewed on its own),
  automatic pagination, typed errors (`NgenValidationError` with the field
  errors in `.body`, `NgenAuthError`, `NgenNotFoundError`, `NgenAPIError`),
  retries of idempotent requests only, `Ngen.from_env()` (environment
  variables, then `~/.ngen`), `ngen.session` for proxies and other
  `requests` settings, debug logging under the `pyngen` logger.
- Resources: `events`, `cases`, `evidence`, `artifacts`, `networks`,
  `entities`, `contacts`, `taxonomies`, `feeds`, `priorities`, `tlps`,
  `states`, `tags`, `users`, and `ngen.resource("...")` for the rest. Each
  one has `list`, `first`, `get`, `create`, `update`, `patch`, `delete` and
  `by_slug`; events and cases accept `evidence=[...]` files.
- `report()`: one event per address and taxonomy while its case is open.
  The new evidence is uploaded before the previous one is deleted, and the
  files are read before anything is touched.
- `lookup()`: network, entity and contacts of an address, with the
  inheritance rules Ngen uses to notify.
- `report_csv()`: one event per address found in a CSV.
- `pyngen` command: `init`, `version`, `list`, `get`, `create`, `patch`,
  `delete`, `report`, `report-csv`, `lookup`, `seed`.
- `pyngen seed`: fake data for test instances (`pip install "pyngen[seed]"`).

### Changed

- Packaging: `pyproject.toml`, `src/` layout, Python 3.9+. Dependencies are
  `requests` and `click` only (`filemime` and `python-slugify` dropped).
- `PyNgen` is now a facade over `Ngen`. Differences from 1.x:
  - A 400 from Ngen raises `NewEventFieldError` (or `NewEventTypeFieldError`
    when the error is about the taxonomy) with the field errors in `.msg`.
    In 1.x against Ngen 2 it raised `UnexpectedError`, because the error
    format it parsed was the one of Ngen 1. Both are subclasses of
    `NgenError`, so `except NgenError` and `except Exception` are unaffected.
  - `newEvent()` accepts `date`, `priority` and `tlp` (defaults `medium`
    and `amber`, as before). A missing evidence file raises
    `FileNotFoundError` instead of a bare `Exception`.
  - `getEvent`, `editEvent`, `getEvents`, `getFeeds(field=...)`,
    `getActiveFeeds`, `getFeed`, `getActiveEventTypes`, `newFeed`,
    `newEventType`, `editFeed` and `editEventType` work again (they used
    Ngen 1 URLs). `getFeeds()` and `getEventTypes()` without `field` still
    return the raw `{"status_code", "data"}` answer.
  - `getVersion()` returns the server version instead of `"1.0"`.
  - `newIncident` and the `NewIncident*Error` names are back as aliases.
  - Attributes that are not 1.x API are delegated to the `Ngen` client, so
    `PyNgen(...).events.list()` works.
- `ngen` command: `newevent` accepts `-priority` and `-tlp`; `reportcsv`
  prints how many events it created. Credentials still live in `~/.ngen/`
  and the `pyngen` command reads them too.

### Notes for Ngen 2.6

- `POST /api/event/` requires `priority` and `tlp`; `report()`, `report_csv()`
  and both commands default them to `medium` and `amber`.
- An unknown taxonomy slug is created by Ngen (`TAXONOMY_ALLOW_AUTO_CREATE`)
  instead of being rejected: check the slug first if typos matter.
- Only event `feed`, `tlp`, `priority`, `taxonomy` and case `state` accept
  slugs; case and contact `priority`/`tlp` need URLs (`ngen.priorities.by_slug("high")["url"]`).
