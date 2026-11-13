from .client import Ngen
from .exceptions import (
    NgenAPIError,
    NgenAuthError,
    NgenConfigError,
    NgenError,
    NgenNotFoundError,
    NgenValidationError,
)
from .lookup import LookupResult, lookup
from .report import ReportResult, find_open_event, report
from .csvreport import report_csv

# pyngen 1.x interface
from .pyngen import PyNgen
from .ngen_exceptions import *  # noqa: F401,F403
from . import ngen_exceptions as _legacy

try:
    from importlib.metadata import version as _version

    __version__ = _version("pyngen")
except Exception:  # running from a checkout
    __version__ = "2.0.0"

__all__ = [
    "Ngen",
    "PyNgen",
    "NgenAPIError",
    "NgenAuthError",
    "NgenConfigError",
    "NgenError",
    "NgenNotFoundError",
    "NgenValidationError",
    "LookupResult",
    "ReportResult",
    "find_open_event",
    "lookup",
    "report",
    "report_csv",
] + _legacy.__all__
