"""Same-origin redirect policy for the engine's own HTTP requests.

Since mcp 2.2.0 the SDK's HTTP transports follow a redirect only while it
stays on the endpoint's origin: same scheme, host and port, or ``http`` to
``https`` on the same host with default ports, keeping the request method (a
307/308). Anything else is refused and the message fails with ``Redirect to
<url> not followed``. The probes and the OAuth bootstrap request send raw
HTTP outside the SDK, and until this module they followed every redirect the
way httpx2 does, so one audit applied two policies to one endpoint: the
session refused a redirect the probes then followed, judging an origin the
user never named and carrying caller headers there.

:func:`send_within_origin` is the one rule for both. It follows the hops the
SDK follows (a trailing-slash normalisation, an https upgrade), up to the
client's ``max_redirects``, and hands any other redirect response back
unfollowed for the caller to treat as the non-success it is. The client's
own ``follow_redirects`` setting is deliberately not consulted, as in the
SDK, so a caller-injected client cannot widen the policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx2

REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})
"""HTTP statuses whose ``Location`` a client may follow."""

REFUSED_OFF_ORIGIN = "another origin"
"""Refusal reason: the target is not on the endpoint's origin. A property of the URL, whatever the request."""

REFUSED_CREDENTIALS = "the target URL introduces credentials"
"""Refusal reason: the target carries userinfo the endpoint did not. A property of the URL, whatever the request."""


def _redirected_method(status: int, method: str) -> str:
    """Return the method httpx2 would send to the redirect target (``AsyncClient._redirect_method``).

    A 303 turns anything but HEAD into a GET; a 302 does the same except for
    HEAD and QUERY; a 301 turns only a POST into a GET; 307/308 keep the
    method. Mirrored here so a hand-built response classifies the way a
    client-built one does.
    """
    if status == 303 and method != "HEAD":
        return "GET"
    if status == 302 and method not in ("HEAD", "QUERY"):
        return "GET"
    if status == 301 and method == "POST":
        return "GET"
    return method


def within_origin(sent: httpx2.URL, location: httpx2.URL) -> bool:
    """Whether ``location`` is on ``sent``'s origin, or its https upgrade on the default ports.

    httpx2 normalises a scheme's default port to ``None`` and lower-cases the
    host, so tuple comparison is exact. The upgrade rule is the one httpx2
    itself uses to decide a redirect has not left the origin, and the one the
    MCP SDK adopted.
    """
    if (sent.scheme, sent.host, sent.port) == (location.scheme, location.host, location.port):
        return True
    return (
        sent.host == location.host
        and sent.scheme == "http"
        and sent.port is None
        and location.scheme == "https"
        and location.port is None
    )


def redirect_target(response: httpx2.Response) -> httpx2.URL | None:
    """Return the absolute ``Location`` of a redirect response, else ``None``.

    A redirect status without a ``Location`` is not a redirect anyone can
    follow and reports ``None`` too.
    """
    if response.status_code not in REDIRECT_STATUSES:
        return None
    location = response.headers.get("location")
    if not location:
        return None
    return response.request.url.join(location)


@dataclass(frozen=True)
class RefusedRedirect:
    """A redirect the same-origin policy left unfollowed, and why."""

    target: str
    """Absolute URL the server redirected to, without userinfo, query or fragment (see :func:`unfollowed_redirect`)."""
    why: str
    """Short reason for the refusal, phrased to sit in a message: "another origin"."""


def _refusal(response: httpx2.Response, target: httpx2.URL) -> str | None:
    """Return why the policy refuses ``response``'s redirect to ``target``, or ``None`` if it follows it.

    Followed only when the target stays within the origin of the request just
    sent, introduces no userinfo (which httpx2 would send as Basic auth;
    userinfo the endpoint URL already carries and a relative ``Location``
    inherits unchanged is fine, as in the SDK), and the redirect keeps the
    method (httpx2 turns a POST into a body-less GET for 301/302/303, which
    would drop the message; see :func:`_redirected_method`). The reasons that
    hold for any request come first, so an off-origin 303 is reported as
    off-origin: a caller can then tell a refusal a differently-shaped request
    would share from one it would not.
    """
    sent = response.request
    if not within_origin(sent.url, target):
        return REFUSED_OFF_ORIGIN
    if target.userinfo and target.userinfo != sent.url.userinfo:
        return REFUSED_CREDENTIALS
    redirected = _redirected_method(response.status_code, sent.method)
    if redirected != sent.method:
        return f"the {sent.method} would become a {redirected}"
    return None


def unfollowed_redirect(response: httpx2.Response) -> RefusedRedirect | None:
    """Return the redirect the policy leaves unfollowed, with its reason, else ``None``.

    ``None`` for a non-redirect, and for a redirect the policy would have
    followed (same origin, same method): such a response reached the caller
    only past the redirect budget, and is a plain HTTP status to it.

    The target is for a message or a log line, so it is reported the way the
    SDK reports its own: without userinfo, query or fragment, which can carry
    credentials or state (a relative ``Location`` inherits the endpoint's
    userinfo, and a signed URL carries its token in the query).
    """
    target = redirect_target(response)
    if target is None:
        return None
    why = _refusal(response, target)
    if why is None:
        return None
    return RefusedRedirect(str(target.copy_with(userinfo=b"", query=None, fragment=None)), why)


async def send_within_origin(
    client: httpx2.AsyncClient, request: httpx2.Request, **send_kwargs: Any
) -> httpx2.Response:
    """``client.send(request)``, following redirects only while they stay within the request's origin.

    A redirect the policy accepts is followed, at most ``client.max_redirects``
    times, on the request httpx2 itself built for it (``response.next_request``,
    which carries the body of a 307/308 and applies httpx2's own header
    rules). Any other redirect, or one past that budget, is returned as is,
    the way httpx2 hands one back with ``follow_redirects`` off. Requests an
    ``httpx2.Auth`` flow makes during the send are not followed either.
    """
    followed = 0
    while True:
        response = await client.send(request, follow_redirects=False, **send_kwargs)
        target = redirect_target(response)
        next_request = response.next_request
        if target is None or next_request is None or _refusal(response, target) is not None:
            return response
        if followed == client.max_redirects:
            return response
        # Release the redirect's connection to the pool, as httpx2 does when it follows.
        await response.aclose()
        request = next_request
        followed += 1
