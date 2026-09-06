"""The shared client TLS context: trust behavior preserved, per-handshake races removed."""

from __future__ import annotations

import ast
from pathlib import Path
import ssl
import sys

import pytest

from mcpscore import tls

ENGINE_DIR = Path(__file__).parent.parent / "mcpscore"


@pytest.fixture(autouse=True)
def fresh_context(monkeypatch: pytest.MonkeyPatch):
    """Each test builds its own context: clear the cache and the env overrides."""
    tls.client_ssl_context.cache_clear()
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    yield
    tls.client_ssl_context.cache_clear()


class TestOpenSSLPlatforms:
    """Linux and friends: a plain stdlib context, so anyio never threads wrap_bio and nothing reloads the store."""

    def test_is_a_plain_stdlib_context_that_verifies(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(sys, "platform", "linux")

        context = tls.client_ssl_context()

        assert type(context) is ssl.SSLContext
        assert context.verify_mode is ssl.CERT_REQUIRED
        assert context.check_hostname is True

    def test_keeps_truststore_verification_policy_not_the_stricter_default(self, monkeypatch: pytest.MonkeyPatch):
        # create_default_context() adds VERIFY_X509_STRICT and PARTIAL_CHAIN on
        # 3.13+; truststore starts from a bare client context, and so do we.
        monkeypatch.setattr(sys, "platform", "linux")

        context = tls.client_ssl_context()

        assert context.verify_flags == ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).verify_flags
        assert not context.verify_flags & ssl.VERIFY_X509_STRICT

    def test_loads_the_default_paths_once_when_they_hold_certs(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setattr(sys, "platform", "linux")
        bundle = tmp_path / "bundle.pem"
        bundle.write_text("", encoding="utf-8")
        paths = ssl.DefaultVerifyPaths(str(bundle), None, "SSL_CERT_FILE", str(bundle), "SSL_CERT_DIR", None)
        monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: paths)
        calls: list[str] = []
        monkeypatch.setattr(ssl.SSLContext, "set_default_verify_paths", lambda _self: calls.append("defaults"))
        monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", lambda _self, **_kw: calls.append("candidate"))

        tls.client_ssl_context()

        assert calls == ["defaults"]

    def test_a_missing_capath_directory_does_not_count(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        assert tls._capath_holds_certs(str(tmp_path / "absent")) is False

    def test_no_bundle_at_all_still_yields_a_verifying_context(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setattr(sys, "platform", "linux")
        empty = ssl.DefaultVerifyPaths(None, None, "SSL_CERT_FILE", None, "SSL_CERT_DIR", None)
        monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: empty)
        monkeypatch.setattr(tls, "CA_BUNDLE_CANDIDATES", (str(tmp_path / "missing.pem"),))
        loaded: list[str] = []
        monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", lambda _self, **_kw: loaded.append("called"))

        context = tls.client_ssl_context()

        assert loaded == []
        assert context.verify_mode is ssl.CERT_REQUIRED

    def test_built_once_per_process(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(sys, "platform", "linux")

        assert tls.client_ssl_context() is tls.client_ssl_context()

    def test_falls_back_to_a_known_bundle_when_default_paths_are_empty(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        monkeypatch.setattr(sys, "platform", "linux")
        empty = ssl.DefaultVerifyPaths(None, None, "SSL_CERT_FILE", None, "SSL_CERT_DIR", str(tmp_path / "nope"))
        monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: empty)
        bundle = tmp_path / "cert.pem"
        bundle.write_text("", encoding="utf-8")
        monkeypatch.setattr(tls, "CA_BUNDLE_CANDIDATES", (str(tmp_path / "missing.pem"), str(bundle)))
        loaded: list[str] = []
        monkeypatch.setattr(
            ssl.SSLContext, "load_verify_locations", lambda _self, cafile=None, **_: loaded.append(cafile)
        )

        tls.client_ssl_context()

        assert loaded == [str(bundle)]

    def test_hashed_capath_counts_as_default_paths(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setattr(sys, "platform", "linux")
        (tmp_path / "5ed36f99.0").write_text("", encoding="utf-8")
        paths = ssl.DefaultVerifyPaths(None, str(tmp_path), "SSL_CERT_FILE", None, "SSL_CERT_DIR", str(tmp_path))
        monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: paths)
        loaded: list[str] = []
        monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", lambda _self, **_kw: loaded.append("called"))

        tls.client_ssl_context()

        assert loaded == []


class TestEmscripten:
    """Pyodide gets httpx2's browser fetch backend: no ssl module worth touching, keep httpx2's default."""

    def test_returns_httpx2_default_without_building_a_context(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(sys, "platform", "emscripten")

        def boom(*_args, **_kwargs):
            raise AssertionError("ssl must not be touched on emscripten")

        monkeypatch.setattr(ssl, "SSLContext", boom)
        monkeypatch.setattr(ssl, "create_default_context", boom)

        assert tls.client_ssl_context() is True


class TestEnvironmentOverrides:
    """SSL_CERT_FILE and SSL_CERT_DIR keep the precedence httpx2 gives them, on every platform."""

    @pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
    def test_ssl_cert_file_wins(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, platform: str):
        monkeypatch.setattr(sys, "platform", platform)
        bundle = tmp_path / "corp.pem"
        bundle.write_text("", encoding="utf-8")
        monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
        seen: dict = {}

        def capture(**kwargs):
            # Not the real builder: with sys.platform patched it would try the
            # Windows certificate stores on whatever OS runs the tests.
            seen.update(kwargs)
            return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        monkeypatch.setattr(ssl, "create_default_context", capture)

        context = tls.client_ssl_context()

        assert seen == {"cafile": str(bundle)}
        assert type(context) is ssl.SSLContext

    def test_ssl_cert_dir_when_no_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
        seen: dict = {}
        monkeypatch.setattr(
            ssl, "create_default_context", lambda **kw: (seen.update(kw), ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))[1]
        )

        tls.client_ssl_context()

        assert seen == {"capath": str(tmp_path)}


class TestNativeTrustPlatforms:
    """macOS and Windows keep truststore's OS verification, with wrap_bio serialized like upstream's wrap_socket."""

    @pytest.mark.parametrize("platform", ["darwin", "win32"])
    def test_is_truststore_with_a_serialized_wrap_bio(self, monkeypatch: pytest.MonkeyPatch, platform: str):
        truststore = pytest.importorskip("truststore")
        monkeypatch.setattr(sys, "platform", platform)

        context = tls.client_ssl_context()

        assert isinstance(context, truststore.SSLContext)
        assert type(context) is not truststore.SSLContext
        held: list[str] = []

        def fake_wrap_bio(self, *_args, **_kwargs):
            held.append(f"wrap_bio:{self._context_lock.locked()}")
            return "ssl-object"

        def fake_set_alpn(self, protocols):
            held.append(f"alpn:{self._context_lock.locked()}:{protocols}")

        monkeypatch.setattr(truststore.SSLContext, "wrap_bio", fake_wrap_bio)
        monkeypatch.setattr(truststore.SSLContext, "set_alpn_protocols", fake_set_alpn)

        assert context.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="example.com") == "ssl-object"
        # httpcore2 does this before every TLS start, on the event loop thread.
        context.set_alpn_protocols(["http/1.1"])
        assert held == ["wrap_bio:True", "alpn:True:['http/1.1']"]
        assert context._context_lock.locked() is False


def _uses_shared_context(value: ast.expr) -> bool:
    """Accept only a bare ``client_ssl_context()`` call: ``verify=True`` is httpx2's truststore default again."""
    if not isinstance(value, ast.Call) or value.args or value.keywords:
        return False
    func = value.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
    return name == "client_ssl_context"


def clients_without_shared_context(source: str, label: str = "<source>") -> list[str]:
    """List every ``AsyncClient(...)`` call in ``source`` whose ``verify`` is not ``client_ssl_context()``."""
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != "AsyncClient":
            continue
        verify = next((kw.value for kw in node.keywords if kw.arg == "verify"), None)
        if verify is None or not _uses_shared_context(verify):
            offenders.append(f"{label}:{node.lineno}")
    return offenders


class TestEveryClientUsesIt:
    """A new httpx2 client that forgets verify= silently reintroduces the race; this finds it."""

    def test_every_async_client_in_the_engine_passes_the_shared_context(self):
        offenders: list[str] = []
        for module in sorted(ENGINE_DIR.rglob("*.py")):
            offenders += clients_without_shared_context(
                module.read_text(encoding="utf-8"), str(module.relative_to(ENGINE_DIR))
            )
        assert offenders == [], f"httpx2.AsyncClient without verify=client_ssl_context(): {offenders}"

    @pytest.mark.parametrize(
        "snippet",
        [
            "httpx2.AsyncClient()",
            "httpx2.AsyncClient(verify=True)",
            "httpx2.AsyncClient(verify=ssl.create_default_context())",
            "httpx2.AsyncClient(verify=client_ssl_context(strict=True))",
            "AsyncClient(verify=other())",
        ],
    )
    def test_guard_rejects_anything_but_the_shared_context(self, snippet: str):
        assert clients_without_shared_context(snippet) == ["<source>:1"]

    @pytest.mark.parametrize(
        "snippet",
        [
            "httpx2.AsyncClient(verify=client_ssl_context())",
            "AsyncClient(timeout=1, verify=tls.client_ssl_context())",
            "httpx2.Client()",  # not an AsyncClient: out of scope
        ],
    )
    def test_guard_accepts_the_shared_context(self, snippet: str):
        assert clients_without_shared_context(snippet) == []
