"""The shared client TLS context: trust behavior preserved, per-handshake races removed."""

from __future__ import annotations

import ast
from pathlib import Path
import ssl
import sys
import threading

import httpx2
import pytest

from mcpscore import tls

ENGINE_DIR = Path(__file__).parent.parent / "mcpscore"


@pytest.fixture(autouse=True)
def fresh_context(monkeypatch: pytest.MonkeyPatch):
    """Each test builds its own context: clear the cache and the env overrides."""
    tls._build_client_ssl_context.cache_clear()
    monkeypatch.delenv("SSL_CERT_FILE", raising=False)
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    yield
    tls._build_client_ssl_context.cache_clear()


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

    @pytest.mark.parametrize("platform", ["linux", "darwin"])
    def test_trust_env_off_ignores_the_environment(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, platform: str
    ):
        monkeypatch.setattr(sys, "platform", platform)
        monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "corp.pem"))
        monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))

        env_builds: list[dict] = []
        monkeypatch.setattr(
            ssl,
            "create_default_context",
            lambda **kw: (env_builds.append(kw), ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))[1],
        )

        context = tls.client_ssl_context(trust_env=False)

        assert env_builds == []  # the environment bundle was never consulted
        if platform == "linux":
            assert type(context) is ssl.SSLContext
        else:
            assert type(context) is not ssl.SSLContext  # truststore's native verification stays
        assert tls.client_ssl_context(trust_env=False) is context
        # Cached separately from the environment-aware context.
        assert tls.client_ssl_context(trust_env=True) is not context
        assert env_builds == [{"cafile": str(tmp_path / "corp.pem")}]

    @pytest.mark.parametrize("compiled_in", ["cafile", "capath"])
    def test_trust_env_off_loads_only_the_compiled_in_openssl_locations(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, compiled_in: str
    ):
        # get_default_verify_paths().cafile and set_default_verify_paths() both
        # resolve SSL_CERT_FILE; with trust_env off, only the compiled-in
        # openssl_cafile / openssl_capath may be loaded, and by name.
        monkeypatch.setattr(sys, "platform", "linux")
        env_bundle = tmp_path / "env.pem"
        env_bundle.write_text("", encoding="utf-8")
        monkeypatch.setenv("SSL_CERT_FILE", str(env_bundle))
        builtin_file = tmp_path / "builtin.pem"
        builtin_file.write_text("", encoding="utf-8")
        builtin_dir = tmp_path / "certs"
        builtin_dir.mkdir()
        (builtin_dir / "5ed36f99.0").write_text("", encoding="utf-8")
        paths = ssl.DefaultVerifyPaths(
            cafile=str(env_bundle),
            capath=None,
            openssl_cafile_env="SSL_CERT_FILE",
            openssl_cafile=str(builtin_file) if compiled_in == "cafile" else str(tmp_path / "absent.pem"),
            openssl_capath_env="SSL_CERT_DIR",
            openssl_capath=str(builtin_dir) if compiled_in == "capath" else str(tmp_path / "absent"),
        )
        monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: paths)
        calls: list[tuple[str, object]] = []
        monkeypatch.setattr(ssl.SSLContext, "set_default_verify_paths", lambda _self: calls.append(("defaults", None)))
        monkeypatch.setattr(
            ssl.SSLContext,
            "load_verify_locations",
            lambda _self, cafile=None, capath=None, **_kw: calls.append(("load", (cafile, capath))),
        )

        tls.client_ssl_context(trust_env=False)

        expected = (str(builtin_file), None) if compiled_in == "cafile" else (None, str(builtin_dir))
        assert calls == [("load", expected)]

    def test_trust_env_off_falls_back_to_a_known_bundle(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setattr(sys, "platform", "linux")
        absent = str(tmp_path / "absent")
        paths = ssl.DefaultVerifyPaths(None, None, "SSL_CERT_FILE", absent, "SSL_CERT_DIR", absent)
        monkeypatch.setattr(ssl, "get_default_verify_paths", lambda: paths)
        bundle = tmp_path / "cert.pem"
        bundle.write_text("", encoding="utf-8")
        monkeypatch.setattr(tls, "CA_BUNDLE_CANDIDATES", (str(bundle),))
        loaded: list[str | None] = []
        monkeypatch.setattr(
            ssl.SSLContext, "load_verify_locations", lambda _self, cafile=None, **_kw: loaded.append(cafile)
        )

        tls.client_ssl_context(trust_env=False)

        assert loaded == [str(bundle)]

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


class TestSerializationUnderContention:
    """Two threads, deterministic: the second mutation cannot enter while the first holds the context."""

    def test_set_alpn_protocols_waits_for_an_in_flight_wrap_bio(self, monkeypatch: pytest.MonkeyPatch):
        truststore = pytest.importorskip("truststore")
        monkeypatch.setattr(sys, "platform", "darwin")
        context = tls.client_ssl_context()
        wrap_entered = threading.Event()
        release_wrap = threading.Event()
        alpn_entered = threading.Event()

        def blocking_wrap_bio(self, *_args, **_kwargs):
            wrap_entered.set()
            assert release_wrap.wait(5), "test harness never released wrap_bio"
            return "ssl-object"

        def fake_set_alpn(self, _protocols):
            alpn_entered.set()

        monkeypatch.setattr(truststore.SSLContext, "wrap_bio", blocking_wrap_bio)
        monkeypatch.setattr(truststore.SSLContext, "set_alpn_protocols", fake_set_alpn)

        wrapper = threading.Thread(target=context.wrap_bio, args=(ssl.MemoryBIO(), ssl.MemoryBIO()))
        wrapper.start()
        assert wrap_entered.wait(5)
        alpn = threading.Thread(target=context.set_alpn_protocols, args=(["http/1.1"],))
        alpn.start()

        # wrap_bio is parked inside the lock: the ALPN mutation must not get in.
        assert alpn_entered.wait(0.3) is False

        release_wrap.set()
        wrapper.join(5)
        alpn.join(5)
        assert alpn_entered.is_set()
        assert context._context_lock.locked() is False


class TestAsyncClientFactory:
    """Every engine client comes from async_client(), which also covers the proxy hop."""

    @pytest.fixture(autouse=True)
    def no_environment_proxies(self, monkeypatch: pytest.MonkeyPatch):
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
            monkeypatch.delenv(name, raising=False)
            monkeypatch.delenv(name.lower(), raising=False)

    def test_passes_the_shared_context_as_verify(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(sys, "platform", "linux")
        seen: dict = {}
        monkeypatch.setattr(httpx2, "AsyncClient", lambda **kw: seen.update(kw) or "client")

        assert tls.async_client(timeout=3.0) == "client"

        assert seen["verify"] is tls.client_ssl_context()
        assert seen["timeout"] == 3.0
        assert seen["mounts"] == {}

    def test_an_https_proxy_from_the_environment_gets_the_shared_context(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example:8443")
        monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:3128")
        monkeypatch.setenv("NO_PROXY", "localhost")
        context = tls.client_ssl_context()
        limits = httpx2.Limits(max_connections=7)

        client = tls.async_client(limits=limits)

        # httpx2 keeps mounted transports keyed by URL pattern; the proxy pool
        # sits on each transport. Private attributes, but they are the only
        # place the proxy's TLS context can be observed.
        mounts = {str(pattern.pattern): transport for pattern, transport in client._mounts.items()}
        https_pool = mounts["https://"]._pool
        http_pool = mounts["http://"]._pool
        assert type(https_pool).__name__ == "AsyncHTTPProxy"
        assert https_pool._proxy_ssl_context is context
        assert https_pool._ssl_context is context
        assert https_pool._max_connections == 7
        assert http_pool._proxy_ssl_context is None  # plain-HTTP proxy hop: no TLS to the proxy
        assert mounts["all://localhost"] is None  # NO_PROXY entry keeps the client's own transport

    def test_a_proxy_transport_without_limits_uses_httpx2_defaults(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example:8443")

        client = tls.async_client()

        mounts = {str(pattern.pattern): transport for pattern, transport in client._mounts.items()}
        assert mounts["https://"]._pool._max_connections == httpx2.AsyncHTTPTransport()._pool._max_connections

    @pytest.mark.parametrize("kwargs", [{"proxy": "http://p.example:1"}, {"mounts": {}}, {"trust_env": False}])
    def test_leaves_explicit_proxy_configuration_alone(self, monkeypatch: pytest.MonkeyPatch, kwargs: dict):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example:8443")
        seen: dict = {}
        monkeypatch.setattr(httpx2, "AsyncClient", lambda **kw: seen.update(kw) or "client")

        tls.async_client(**kwargs)

        assert seen["verify"] is tls.client_ssl_context(kwargs.get("trust_env", True))
        assert ("mounts" in seen) == ("mounts" in kwargs)

    def test_explicit_verify_true_is_the_shared_context(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(sys, "platform", "linux")
        seen: dict = {}
        monkeypatch.setattr(httpx2, "AsyncClient", lambda **kw: seen.update(kw) or "client")

        tls.async_client(verify=True)

        assert seen["verify"] is tls.client_ssl_context()

    @pytest.mark.parametrize("verify", [False, "own-context"])
    def test_a_callers_own_verify_passes_through_and_proxies_follow_it(self, monkeypatch: pytest.MonkeyPatch, verify):
        # verify=False or a private CA context is the caller's policy; the proxy
        # hop must not be verified against the shared context behind their back.
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example:8443")
        own = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) if verify == "own-context" else verify
        seen: dict = {}
        monkeypatch.setattr(httpx2, "AsyncClient", lambda **kw: seen.update(kw) or "client")

        tls.async_client(verify=own)

        assert seen["verify"] is own
        assert "mounts" not in seen

    def test_http_version_options_reach_the_proxy_transports(self, monkeypatch: pytest.MonkeyPatch):
        # Captured at the transport constructor: enabling HTTP/2 for real needs
        # the optional h2 package, and what matters here is the forwarding.
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example:8443")
        built: list[dict] = []
        monkeypatch.setattr(httpx2, "AsyncHTTPTransport", lambda **kw: built.append(kw) or "transport")
        monkeypatch.setattr(httpx2, "AsyncClient", lambda **_kw: "client")

        tls.async_client(http1=False, http2=True, limits=httpx2.Limits(max_connections=3))

        assert len(built) == 1
        assert built[0]["http1"] is False
        assert built[0]["http2"] is True
        assert built[0]["limits"].max_connections == 3
        assert built[0]["verify"] is tls.client_ssl_context()

    def test_cert_is_rejected_so_the_shared_context_never_carries_a_credential(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ):
        monkeypatch.setattr(sys, "platform", "linux")
        before = tls.client_ssl_context()

        with pytest.raises(TypeError, match="cert="):
            tls.async_client(cert=str(tmp_path / "client.pem"))

        assert tls.client_ssl_context() is before

    def test_emscripten_builds_no_mounts(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(sys, "platform", "emscripten")
        monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example:8443")
        seen: dict = {}
        monkeypatch.setattr(httpx2, "AsyncClient", lambda **kw: seen.update(kw) or "client")

        tls.async_client()

        assert seen == {"verify": True}


def direct_async_client_calls(source: str, label: str = "<source>") -> list[str]:
    """List every ``AsyncClient(...)`` construction in ``source``: engine code must use ``async_client()`` instead."""
    offenders: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name == "AsyncClient":
            offenders.append(f"{label}:{node.lineno}")
    return offenders


class TestEveryClientUsesTheFactory:
    """A new httpx2 client built directly silently reintroduces the race; this finds it."""

    def test_only_the_factory_constructs_async_clients(self):
        offenders: list[str] = []
        for module in sorted(ENGINE_DIR.rglob("*.py")):
            label = str(module.relative_to(ENGINE_DIR))
            if label == "tls.py":
                continue
            offenders += direct_async_client_calls(module.read_text(encoding="utf-8"), label)
        assert offenders == [], f"httpx2.AsyncClient built outside tls.async_client(): {offenders}"

    @pytest.mark.parametrize(
        "snippet",
        [
            "httpx2.AsyncClient()",
            "httpx2.AsyncClient(verify=True)",
            "httpx2.AsyncClient(verify=client_ssl_context())",
            "AsyncClient(verify=other())",
        ],
    )
    def test_guard_rejects_direct_construction(self, snippet: str):
        assert direct_async_client_calls(snippet) == ["<source>:1"]

    @pytest.mark.parametrize("snippet", ["async_client(timeout=1)", "tls.async_client()", "httpx2.Client()"])
    def test_guard_accepts_the_factory(self, snippet: str):
        assert direct_async_client_calls(snippet) == []
