"""HTTP statuses that refuse a request for want of capacity, not because of what it asked."""

from __future__ import annotations

THROTTLED_STATUSES = frozenset({408, 429, 503})
"""A timeout (408), a rate limit (429) or an unavailable server (503).

An answer with one of these says nothing about how the server handles the request, so it is never judged. Other 5xx
statuses are not in the set: a 500 on bad input can be a real server bug.
"""
