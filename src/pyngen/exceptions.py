class NgenError(Exception):
    """Base class for every pyngen error."""

    @property
    def detail(self):
        """Message of the error. Kept for code written against pyngen 1.x."""
        return str(self)


class NgenConfigError(NgenError):
    """The client was built with missing or invalid settings."""


class NgenAPIError(NgenError):
    """Ngen answered with an unexpected HTTP status, or with a body that is not JSON."""

    def __init__(self, status_code, url, body=None):
        self.status_code = status_code
        self.url = url
        self.body = body
        super().__init__(f"{status_code} for {url}: {body!r}")


class NgenAuthError(NgenAPIError):
    """401/403: bad credentials, expired token or missing permission."""


class NgenNotFoundError(NgenAPIError):
    """404, or a lookup (for example by slug) that matched nothing."""


class NgenValidationError(NgenAPIError):
    """400: Ngen rejected the payload. ``body`` holds the field errors."""
