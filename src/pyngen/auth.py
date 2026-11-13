import base64
import json
import time

from requests.auth import AuthBase

from .exceptions import NgenAuthError


class TokenAuth(AuthBase):
    """API key from ``/api/token/simple/`` (DRF TokenAuthentication)."""

    def __init__(self, token):
        self.token = token

    def __call__(self, request):
        request.headers["Authorization"] = f"Token {self.token}"
        return request


def _jwt_exp(token):
    """Read the ``exp`` claim without verifying the signature. 0 when unreadable."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return int(json.loads(base64.urlsafe_b64decode(payload))["exp"])
    except (IndexError, KeyError, ValueError, TypeError):
        return 0


class JWTAuth(AuthBase):
    """
    Username/password login against ``/api/token/``.

    Keeps the access token in memory and renews it before it expires, first
    with the refresh token and, if that one expired too, logging in again.
    """

    def __init__(self, client, username, password, leeway=30):
        self.client = client
        self.username = username
        self.password = password
        self.leeway = leeway
        self.access = None
        self.refresh = None

    def _expired(self, token):
        return token is None or _jwt_exp(token) - self.leeway < time.time()

    def _post(self, path, payload):
        response = self.client.session.post(
            self.client.url(path),
            json=payload,
            timeout=self.client.timeout,
            verify=self.client.verify,
        )
        if response.status_code != 200:
            raise NgenAuthError(response.status_code, response.url, response.text)
        return response.json()

    def login(self):
        data = self._post("/api/token/", {"username": self.username, "password": self.password})
        self.access, self.refresh = data["access"], data["refresh"]

    def _renew(self):
        data = self._post("/api/token/refresh/", {"refresh": self.refresh})
        self.access = data["access"]
        # Ngen rotates refresh tokens
        self.refresh = data.get("refresh", self.refresh)

    def token(self):
        if not self._expired(self.access):
            return self.access
        if not self._expired(self.refresh):
            try:
                self._renew()
                return self.access
            except NgenAuthError:
                pass
        self.login()
        return self.access

    def logout(self):
        """Blacklist the refresh token. Does not log in again just to log out."""
        if self.refresh and not self._expired(self.access):
            self.client.session.post(
                self.client.url("/api/logout/"),
                json={"refresh": self.refresh},
                headers={"Authorization": f"Bearer {self.access}"},
                timeout=self.client.timeout,
                verify=self.client.verify,
            )
        self.access = self.refresh = None

    def __call__(self, request):
        request.headers["Authorization"] = f"Bearer {self.token()}"
        return request
