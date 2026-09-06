"""One shared TLS context for every outbound HTTPS client.

httpx2 verifies against the operating system's trust store through
``truststore`` by default. truststore reconfigures its underlying OpenSSL
context on *every* handshake and, as of 0.10.4, serializes that only on the
synchronous ``wrap_socket`` path. Async clients take ``wrap_bio``, which is
not serialized, and anyio runs ``wrap_bio`` on a worker thread for any
context that is not a plain ``ssl.SSLContext``. The audit opens ~23 probe
connections at once, so on Linux many threads reload the CA store into one
OpenSSL context concurrently, and OpenSSL 3.0 corrupts its heap: ``double
free or corruption (fasttop)``, exit 134/139 mid-audit, seen in CI on
2026-09-05 and 2026-09-06 and reproduced with a 48-connection stress loop.
Upstream: sethmlarson/truststore#209 (the missing lock on ``wrap_bio``).

The fix keeps the trust behavior and removes the race:

- Linux: truststore's backend is OpenSSL's own verification against the
  default paths (plus a few known bundle locations), so a stdlib context
  built once is the same trust store without the per-handshake reload. It
  is a bare ``SSLContext(PROTOCOL_TLS_CLIENT)`` like truststore's, not
  ``create_default_context()``, which on Python 3.13+ also turns on
  ``VERIFY_X509_STRICT`` and ``VERIFY_X509_PARTIAL_CHAIN`` and would reject
  chains truststore accepts. A plain ``ssl.SSLContext`` also keeps anyio off
  worker threads.
- Emscripten (Pyodide): the lockfile swaps in httpx2's browser fetch
  backend, with no truststore, anyio, or working ``ssl``; httpx2's default
  ``verify=True`` is returned untouched.
- macOS and Windows: truststore verifies through the native APIs, which a
  stdlib context cannot do, so it stays, with ``wrap_bio`` serialized the
  way upstream serializes ``wrap_socket``.
- ``SSL_CERT_FILE`` / ``SSL_CERT_DIR`` keep the precedence httpx2 gives them.

Every ``httpx2.AsyncClient`` in the engine passes ``verify=client_ssl_context()``;
a test walks the package tree to enforce that.
"""

from __future__ import annotations

import functools
import os
from pathlib import Path
import re
import ssl
import sys
import threading
from typing import Any

# The bundle locations truststore's OpenSSL backend falls back to when the
# compiled-in default paths hold no certificates (truststore/_openssl.py).
CA_BUNDLE_CANDIDATES: tuple[str, ...] = (
    "/etc/ssl/cert.pem",  # Alpine, Arch, Fedora 34-42, OpenWRT, RHEL 9-10, BSD
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  # Fedora 43+, RHEL 11+
    "/etc/pki/tls/cert.pem",  # Fedora <= 34, RHEL <= 9, CentOS <= 9
    "/etc/ssl/certs/ca-certificates.crt",  # Debian, Ubuntu (ca-certificates)
    "/etc/ssl/ca-bundle.pem",  # SUSE
)

_HASHED_CERT_FILENAME = re.compile(r"^[0-9a-fA-F]{8}\.[0-9]$")

NATIVE_TRUST_PLATFORMS: frozenset[str] = frozenset({"darwin", "win32"})
"""Platforms where truststore verifies through an OS API rather than OpenSSL."""


def _capath_holds_certs(capath: str) -> bool:
    directory = Path(capath)
    if not directory.is_dir():
        return False
    return any(_HASHED_CERT_FILENAME.match(entry.name) for entry in directory.iterdir())


def _openssl_default_context() -> ssl.SSLContext:
    """Build a stdlib context trusting what truststore's OpenSSL backend would trust.

    Same construction as truststore: a bare client context (``CERT_REQUIRED``
    and hostname checking are its defaults) with the default paths loaded
    once. ``create_default_context()`` is deliberately not used; its extra
    verification flags would change which server chains pass.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    defaults = ssl.get_default_verify_paths()
    if defaults.cafile or (defaults.capath and _capath_holds_certs(defaults.capath)):
        context.set_default_verify_paths()
        return context
    for cafile in CA_BUNDLE_CANDIDATES:
        if Path(cafile).is_file():
            context.load_verify_locations(cafile=cafile)
            break
    return context


def _serialized_truststore_context() -> ssl.SSLContext:
    """Truststore's native-API context with ``wrap_bio`` serialized (upstream only serializes ``wrap_socket``)."""
    import truststore

    class SerializedTruststoreContext(truststore.SSLContext):
        def __init__(self, protocol: int) -> None:
            super().__init__(protocol)
            self._wrap_bio_lock = threading.Lock()

        def wrap_bio(self, *args: Any, **kwargs: Any) -> ssl.SSLObject:
            with self._wrap_bio_lock:
                return super().wrap_bio(*args, **kwargs)

    return SerializedTruststoreContext(ssl.PROTOCOL_TLS_CLIENT)


@functools.cache
def client_ssl_context() -> ssl.SSLContext | bool:
    """Return the process-wide client TLS context: built once, safe under concurrent handshakes.

    ``True`` on Emscripten, where httpx2 runs on the browser's fetch and its
    own default is the only working option.
    """
    if sys.platform == "emscripten":
        return True
    cafile = os.environ.get("SSL_CERT_FILE")
    if cafile:
        return ssl.create_default_context(cafile=cafile)
    capath = os.environ.get("SSL_CERT_DIR")
    if capath:
        return ssl.create_default_context(capath=capath)
    if sys.platform in NATIVE_TRUST_PLATFORMS:
        return _serialized_truststore_context()
    return _openssl_default_context()
