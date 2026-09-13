"""Remove sensitive probe evidence from report copies without changing observations."""

from typing import Any
from urllib.parse import urlsplit, urlunsplit


def report_evidence(value: Any, *, key: str = "") -> Any:
    """Copy evidence, masking session/challenge values and credential-bearing URL parts.

    This is deliberately not a general-purpose secret detector. Raw response bodies
    belong in ProbeResult.payload, and publisher input must not be interpolated into
    diagnostic prose. Rules continue to judge the original observations.
    """
    if key in {"response_session_id", "www_authenticate"}:
        return None if value is None else "[redacted]"
    if key in {"error", "error_message", "auth_server_metadata_error"} and value is not None:
        return "[error details omitted]"
    if isinstance(value, dict):
        return {
            k: "[exception details omitted]" if k == "reason" and "exception" in value else report_evidence(v, key=k)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [report_evidence(item, key=key) for item in value]
    if key != "spec" and isinstance(value, str) and value.startswith(("https://", "http://")):
        try:
            parts = urlsplit(value)
        except ValueError:
            return "[invalid URL omitted]"
        return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, "", ""))
    return value
