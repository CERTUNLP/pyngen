"""
Where the CLIs and ``Ngen.from_env()`` find the server and the credentials.

Environment variables win: ``NGEN_URL``, ``NGEN_TOKEN`` (or ``NGEN_USERNAME``
and ``NGEN_PASSWORD``) and ``NGEN_VERIFY``. Without them, the files that
``ngen init`` / ``pyngen init`` write in ``~/.ngen/`` (``url`` and ``apikey``)
are used, like pyngen 1.x did.
"""

import os

CONFIG_DIR = "~/.ngen"


def config_dir():
    return os.path.expanduser(os.environ.get("NGEN_CONFIG_DIR", CONFIG_DIR))


def _read(name):
    try:
        with open(os.path.join(config_dir(), name)) as f:
            return f.read().strip() or None
    except OSError:
        return None


def load():
    """``{"url", "token", "username", "password", "verify"}`` from env, then ``~/.ngen``."""
    verify = os.environ.get("NGEN_VERIFY", "true").strip().lower() not in ("0", "false", "no")
    username, password = os.environ.get("NGEN_USERNAME"), os.environ.get("NGEN_PASSWORD")
    token = os.environ.get("NGEN_TOKEN")
    if not token and not (username and password):
        token = _read("apikey")  # the saved key only when nothing in the environment says otherwise
    return {
        "url": os.environ.get("NGEN_URL") or _read("url"),
        "token": token,
        "username": username,
        "password": password,
        "verify": verify,
    }


def save(url, token):
    """Write ``url`` and ``apikey`` under ``~/.ngen`` with owner-only permissions."""
    directory = config_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    for name, value in (("url", url.strip()), ("apikey", token.strip())):
        path = os.path.join(directory, name)
        with open(path, "w") as f:
            f.write(value)
        os.chmod(path, 0o600)
    return directory
