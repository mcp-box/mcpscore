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
  way upstream serializes ``wrap_socket``. The same lock covers
  ``set_alpn_protocols``, the one other mutation the HTTP stack makes per
  connection (httpcore2 calls it before every TLS start, from the event
  loop thread, while a worker may be inside ``wrap_bio``).
- ``SSL_CERT_FILE`` / ``SSL_CERT_DIR`` keep the precedence httpx2 gives them,
  and like httpx2 they are consulted only when ``trust_env`` is on.

Every outbound client in the engine is built by :func:`async_client`, which
passes the context for the target *and* for an HTTPS proxy taken from the
environment: httpx2 builds environment proxies with no context of their
own, and httpcore2 then falls back to a fresh truststore context for the
TLS connection to the proxy. A test walks the package tree to enforce that
nothing constructs ``httpx2.AsyncClient`` directly.
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

import httpx2
from httpx2._utils import get_environment_proxies  # the helper httpx2 itself maps env proxies with

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


def _openssl_default_context(trust_env: bool) -> ssl.SSLContext:
    """Build a stdlib context trusting what truststore's OpenSSL backend would trust.

    Same construction as truststore: a bare client context (``CERT_REQUIRED``
    and hostname checking are its defaults) with the default paths loaded
    once. ``create_default_context()`` is deliberately not used; its extra
    verification flags would change which server chains pass.

    With ``trust_env`` off, OpenSSL's *compiled-in* locations are loaded by
    name: both ``get_default_verify_paths().cafile``/``capath`` and
    ``set_default_verify_paths()`` honor ``SSL_CERT_FILE``/``SSL_CERT_DIR``,
    which is exactly what that flag promises to ignore.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    defaults = ssl.get_default_verify_paths()
    if trust_env:
        if defaults.cafile or (defaults.capath and _capath_holds_certs(defaults.capath)):
            context.set_default_verify_paths()
            return context
    else:
        cafile = (
            defaults.openssl_cafile if defaults.openssl_cafile and Path(defaults.openssl_cafile).is_file() else None
        )
        capath = (
            defaults.openssl_capath
            if defaults.openssl_capath and _capath_holds_certs(defaults.openssl_capath)
            else None
        )
        if cafile or capath:
            context.load_verify_locations(cafile=cafile, capath=capath)
            return context
    for candidate in CA_BUNDLE_CANDIDATES:
        if Path(candidate).is_file():
            context.load_verify_locations(cafile=candidate)
            break
    return context


def _serialized_truststore_context() -> ssl.SSLContext:
    """Build truststore's native-API context with its per-connection mutations serialized.

    Upstream serializes only ``wrap_socket``. ``wrap_bio`` (which anyio runs
    on worker threads) and ``set_alpn_protocols`` (which httpcore2 calls
    before every TLS start) both touch the one underlying OpenSSL context,
    so they share a lock here.
    """
    import truststore

    class SerializedTruststoreContext(truststore.SSLContext):
        def __init__(self, protocol: int) -> None:
            super().__init__(protocol)
            self._context_lock = threading.Lock()

        def wrap_bio(self, *args: Any, **kwargs: Any) -> ssl.SSLObject:
            with self._context_lock:
                return super().wrap_bio(*args, **kwargs)

        def set_alpn_protocols(self, alpn_protocols: Any) -> None:
            with self._context_lock:
                super().set_alpn_protocols(alpn_protocols)

    return SerializedTruststoreContext(ssl.PROTOCOL_TLS_CLIENT)


def client_ssl_context(trust_env: bool = True) -> ssl.SSLContext | bool:
    """Return the process-wide client TLS context: built once, safe under concurrent handshakes.

    ``trust_env`` mirrors httpx2's: only when it is on do ``SSL_CERT_FILE``
    and ``SSL_CERT_DIR`` select the bundle. ``True`` on Emscripten, where
    httpx2 runs on the browser's fetch and its own default is the only
    working option.
    """
    return _build_client_ssl_context(bool(trust_env))


@functools.cache
def _build_client_ssl_context(trust_env: bool) -> ssl.SSLContext | bool:
    if sys.platform == "emscripten":
        return True
    if trust_env:
        cafile = os.environ.get("SSL_CERT_FILE")
        if cafile:
            return ssl.create_default_context(cafile=cafile)
        capath = os.environ.get("SSL_CERT_DIR")
        if capath:
            return ssl.create_default_context(capath=capath)
    if sys.platform in NATIVE_TRUST_PLATFORMS:
        return _serialized_truststore_context()
    return _openssl_default_context(trust_env)


_TRANSPORT_OPTIONS = ("limits", "http1", "http2")
"""Client options httpx2 forwards to the transports it builds for environment proxies."""


def _environment_proxy_mounts(context: ssl.SSLContext, client_kwargs: dict[str, Any]) -> dict[str, Any]:
    """Mirror httpx2's environment proxy map, giving an HTTPS proxy the shared context.

    ``None`` keeps httpx2's meaning: the pattern (a ``NO_PROXY`` entry) uses
    the client's own transport. A proxy reached over plain HTTP gets no
    context, which httpcore2 requires for that scheme. The transport-level
    options the client was given travel along, as httpx2 would forward them.
    """
    transport_options = {name: client_kwargs[name] for name in _TRANSPORT_OPTIONS if name in client_kwargs}
    mounts: dict[str, Any] = {}
    for pattern, url in get_environment_proxies().items():
        if url is None:
            mounts[pattern] = None
            continue
        proxy_context = context if httpx2.URL(url).scheme == "https" else None
        mounts[pattern] = httpx2.AsyncHTTPTransport(
            verify=context, proxy=httpx2.Proxy(url=url, ssl_context=proxy_context), **transport_options
        )
    return mounts


def async_client(**kwargs: Any) -> httpx2.AsyncClient:
    """Build an ``httpx2.AsyncClient`` on the shared context, proxies included.

    Accepts the client's own keyword arguments. ``verify=True`` (the default)
    becomes the shared context; ``verify=False`` or a caller's own context is
    passed through untouched, and then the environment proxies are httpx2's
    business too, since the proxy hop must follow the caller's policy. A
    caller-supplied ``transport`` is left entirely alone, as httpx2 ignores
    ``verify`` and environment proxies for it; ``proxy``, ``mounts``, or
    ``trust_env=False`` keep the shared context but leave proxies to httpx2.
    """
    if "cert" in kwargs:
        # httpx2 would load_cert_chain() the credential into whatever `verify`
        # holds: on the shared context that leaks it into every later client
        # and mutates the context mid-handshake. httpx2 deprecates `cert=`
        # for the same reason; the caller's own context is the way.
        raise TypeError(
            "async_client() does not accept cert=; load the chain into your own context and pass it as verify="
        )
    # Build the shared context only where httpx2 would build its own: the
    # default `verify=True` on a client without a caller-supplied transport.
    # `verify=False`, a caller's context, or a custom transport never touch
    # it, so a bad SSL_CERT_FILE cannot fail a client that does not verify.
    if kwargs.get("verify", True) is True and kwargs.get("transport") is None:
        trust_env = bool(kwargs.get("trust_env", True))
        shared = client_ssl_context(trust_env)
        kwargs["verify"] = shared
        if isinstance(shared, ssl.SSLContext) and trust_env and "proxy" not in kwargs and "mounts" not in kwargs:
            kwargs["mounts"] = _environment_proxy_mounts(shared, kwargs)
    return httpx2.AsyncClient(**kwargs)
