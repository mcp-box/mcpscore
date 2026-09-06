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
        held: list[bool] = []

        def fake_wrap_bio(self, *_args, **_kwargs):
            held.append(self._wrap_bio_lock.locked())
            return "ssl-object"

        monkeypatch.setattr(truststore.SSLContext, "wrap_bio", fake_wrap_bio)

        assert context.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="example.com") == "ssl-object"
        assert held == [True]
        assert context._wrap_bio_lock.locked() is False


class TestEveryClientUsesIt:
    """A new httpx2 client that forgets verify= silently reintroduces the race; this finds it."""

    def test_every_async_client_in_the_engine_passes_the_shared_context(self):
        offenders: list[str] = []
        for module in sorted(ENGINE_DIR.glob("*.py")):
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                if name != "AsyncClient":
                    continue
                keywords = {kw.arg for kw in node.keywords}
                if "verify" not in keywords:
                    offenders.append(f"{module.name}:{node.lineno}")
        assert offenders == [], f"httpx2.AsyncClient without verify=client_ssl_context(): {offenders}"
