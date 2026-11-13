"""
Exceptions of pyngen 1.x, kept so that ``from pyngen.ngen_exceptions import *``
and ``except UnexpectedError`` keep working.

Every one of them is also a subclass of the pyngen 2 exceptions in
:mod:`pyngen.exceptions`, so ``except NgenAPIError`` catches them too. They are
raised by :class:`pyngen.PyNgen`; the :class:`pyngen.Ngen` client raises the
new ones directly.
"""

from .exceptions import (
    NgenAPIError,
    NgenAuthError,
    NgenConfigError,
    NgenError,
    NgenValidationError,
)

__all__ = [
    "NgenError",
    "UnauthorizedNgenError",
    "UnexpectedError",
    "SchemeNotSettedError",
    "NewEventError",
    "NewEventFieldError",
    "NewEventTypeFieldError",
    "NewEventTypeDeactivatedError",
    "NewIncidentError",
    "NewIncidentFieldError",
    "NewIncidentTypeFieldError",
    "NewIncidentTypeDeactivatedError",
]


class _LegacyDetail:
    """``str(e)`` and ``repr(e)`` give ``e.detail``, like pyngen 1.x did."""

    def __str__(self):
        return self.detail

    def __repr__(self):
        return self.detail


class UnauthorizedNgenError(_LegacyDetail, NgenAuthError):
    detail = "Invalid Api Key"

    def __init__(self, status_code=401, url="", body=None):
        NgenAuthError.__init__(self, status_code, url, body)


class UnexpectedError(_LegacyDetail, NgenAPIError):
    _detail = "\n\n - Error Code {}\n - Error Message:\n{}"

    def __init__(self, code, msg, url=""):
        self.code = code
        self.msg = msg
        NgenAPIError.__init__(self, code, url, msg)

    @property
    def detail(self):
        return self._detail.format(self.code, self.msg)


class SchemeNotSettedError(_LegacyDetail, NgenConfigError):
    _detail = "\n\n - Error Message:\n{}"

    def __init__(self, msg):
        self.msg = msg
        NgenConfigError.__init__(self, msg)

    @property
    def detail(self):
        return self._detail.format(self.msg)


class NewEventFieldError(_LegacyDetail, NgenValidationError):
    """400 from Ngen. ``msg`` is the ``{field: [errors]}`` body, ``data`` what was sent."""

    _detail = "\n\n - Event field error. Error Message:\n{}\n - Data sent:\n{}"

    def __init__(self, data, msg, url=""):
        self.data = data
        self.msg = msg
        NgenValidationError.__init__(self, 400, url, msg)

    @property
    def detail(self):
        return self._detail.format(self.msg, self.data)


class NewEventTypeFieldError(NewEventFieldError):
    """The 400 is about the taxonomy (event type)."""

    _detail = "\n\n - Event type field error. Error Message:\n{}\n - Data sent:\n{}"


class NewEventTypeDeactivatedError(NewEventFieldError):
    """The taxonomy exists but is not active."""

    _detail = "\n\n - Event type is deactivated. Error Message:\n{}\n - Data sent:\n{}"


class NewEventError(_LegacyDetail, NgenError):
    _detail = "Error Message:\n{}"

    def __init__(self, msg):
        self.msg = msg
        NgenError.__init__(self, msg)

    @property
    def detail(self):
        return self._detail.format(self.msg)


# Names from before events were called events
NewIncidentError = NewEventError
NewIncidentFieldError = NewEventFieldError
NewIncidentTypeFieldError = NewEventTypeFieldError
NewIncidentTypeDeactivatedError = NewEventTypeDeactivatedError
