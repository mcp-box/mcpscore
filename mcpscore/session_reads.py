"""Bound how much of an answer body the MCP SDK session reads.

The SDK reads a JSON answer whole (``response.aread()``), with content
decoding on. :func:`cap_body`, run from a response event hook, swaps the body
for one that decodes as it goes and stops past a byte limit, so neither a large
body nor a small compressed one that inflates can exhaust memory. SSE bodies
are left alone: the SDK already limits each event's size.
"""

from collections.abc import AsyncIterator, Callable

import httpx2

SESSION_READ_LIMIT = 8 * 1024 * 1024
"""Decoded bytes of one session answer read before giving up. Room for a large catalog page."""


class AnswerOverLimitError(httpx2.StreamError):
    """An answer body grew past the read limit and was not read.

    A ``StreamError``, so the SDK resolves the call with an error instead of
    tearing the session down; the client's own record says why.
    """

    def __init__(self, limit: int) -> None:
        super().__init__(f"answer body over the {limit}-byte read limit; not read")


class _CappedBody(httpx2.AsyncByteStream):
    """Yield a response's decoded body, raising ``AnswerOverLimitError`` past ``limit`` bytes."""

    def __init__(self, source: httpx2.Response, limit: int, on_cap: Callable[[], None]) -> None:
        super().__init__()
        # A view over the original headers and stream, so httpx2's own decoders inflate in bounded pieces.
        self._decoded = httpx2.Response(
            source.status_code, headers=httpx2.Headers(source.headers), stream=source.stream, request=source.request
        )
        self._limit = limit
        self._on_cap = on_cap

    async def __aiter__(self) -> AsyncIterator[bytes]:
        read = 0
        async for chunk in self._decoded.aiter_bytes():
            read += len(chunk)
            if read > self._limit:
                self._on_cap()
                raise AnswerOverLimitError(self._limit)
            yield chunk

    async def aclose(self) -> None:
        await self._decoded.aclose()


def cap_body(response: httpx2.Response, on_cap: Callable[[], None], limit: int = SESSION_READ_LIMIT) -> None:
    """Make a non-SSE response's body stop after ``limit`` decoded bytes, calling ``on_cap`` when it does.

    Call before anything reads the body. The body is handed on already decoded,
    so the ``Content-Encoding`` header is dropped to keep httpx2 from decoding it twice.
    """
    if "text/event-stream" in response.headers.get("content-type", "").lower():
        return
    response.stream = _CappedBody(response, limit, on_cap)
    response.headers.pop("content-encoding", None)
