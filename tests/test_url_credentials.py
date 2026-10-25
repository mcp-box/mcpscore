"""Which query parameters count as credentials, and how a URL looks without them."""

import pytest

from mcpscore.url_credentials import credential_query_params, without_credential_params


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("token=abc", ["token"]),
        ("Access-Token=abc", ["Access-Token"]),
        ("apiKey=abc", ["apiKey"]),
        ("API_KEY=abc", ["API_KEY"]),
        ("serviceAPIKey=abc", ["serviceAPIKey"]),
        ("serviceAPIToken=rdme_abc", ["serviceAPIToken"]),
        ("client_secret=abc", ["client_secret"]),
        ("password=", ["password"]),
        ("demo_token=public", ["demo_token"]),
        ("stripe_api_key=abc", ["stripe_api_key"]),
        ("key=rdme_abc", ["key"]),
        ("sig=8f3a9c1e8f3a9c1e8f3a9c1e", ["sig"]),
        ("sig=4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8=", ["sig"]),
        ("session_key=eyJhbGciOiJIUzI1NiJ9.e30.abc123", ["session_key"]),
        ("token=a&token=b&transport=sse", ["token"]),
    ],
)
def test_credentials_are_found(query: str, expected: list[str]):
    assert credential_query_params(query) == expected


@pytest.mark.parametrize(
    "query",
    [
        None,
        "",
        "transport=sse",
        "key=getting-started",
        "sort_key=created_at",
        "auth=required",
        "author=jane&keyword=docs&design=dark&compass=north&passage=1",
        "session=abcdefghijklmnopqrstuvwxyz",  # long but no digits: a word, not a secret
        "toolsets=core,code-exec&omit_tools=search_logs",
        "tokens=10",
    ],
)
def test_ordinary_parameters_are_not_credentials(query: str | None):
    assert credential_query_params(query) == []


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://x.readme.io/mcp?token=rdme_abc", "https://x.readme.io/mcp"),
        ("https://example.com/mcp?transport=sse&api-key=abc", "https://example.com/mcp?transport=sse"),
        ("https://example.com/mcp?key=getting-started&key2=x", "https://example.com/mcp?key=getting-started&key2=x"),
        ("https://example.com:8443/v1/mcp?sig=ghp_abc#part", "https://example.com:8443/v1/mcp#part"),
        ("https://example.com/mcp", "https://example.com/mcp"),
        # Kept parameters stay byte for byte as sent.
        ("https://example.com/mcp?a=x%20y&flag&b=%FF&token=t", "https://example.com/mcp?a=x%20y&flag&b=%FF"),
        ("https://example.com/mcp?a=x+y", "https://example.com/mcp?a=x+y"),
        ("https://example.com/mcp?api%5Fkey=abc&q=1", "https://example.com/mcp?q=1"),
    ],
)
def test_without_credential_params_keeps_everything_else(url: str, expected: str):
    assert without_credential_params(url) == expected
