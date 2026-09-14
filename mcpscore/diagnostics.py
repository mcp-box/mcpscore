"""Build bounded validation evidence and escaped human-readable previews."""

import json
from typing import Any

from pydantic import ValidationError


def validation_diagnostics(error: ValidationError, *, prefix: tuple[str | int, ...] = ()) -> dict[str, Any]:
    """Preserve validation locations and types, omitting inputs and overlong paths."""
    issues: list[dict[str, Any]] = []
    for item in error.errors(include_input=False, include_context=False, include_url=False)[:20]:
        parts = (*prefix, *item["loc"])
        path = "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)
        issue: dict[str, Any] = {
            "reason": item["type"],
            "expected": {
                "list_type": "an array",
                "string_type": "a string",
                "dict_type": "an object",
                "missing": "a required field",
            }.get(item["type"], "the declared catalog field type"),
        }
        if len(path) <= 255:
            issue["path"] = path
        else:
            issue["path_omitted"] = True
        issues.append(issue)
    return {
        "outcome": "invalid_response",
        "issues": issues,
        "issues_total": error.error_count(),
        "issues_omitted": max(0, error.error_count() - 20),
    }


_ENTITY_LABELS = {
    "tool": "Tool",
    "resource": "Resource",
    "resource_template": "Resource template",
    "prompt": "Prompt",
    "server": "Server",
    "catalog": "Catalog",
    "response": "Response",
}


def entity_label(kind: str | None) -> str:
    """Return a human-readable label shared by messages and CLI evidence."""
    return _ENTITY_LABELS.get(kind, "Catalog item") if kind is not None else "Catalog item"


def quoted_preview(value: str, limit: int = 60) -> str:
    """Quote at most ``limit`` source code points, preserving printable Unicode.

    Keep the full original value in existing details. This is a display bound,
    not redaction: only identity fields intended for humans should use it.
    """
    parts: list[str] = []
    for character in value[:limit]:
        # JSON handles quotes, backslashes and ASCII controls. Force escapes
        # for other nonprinting characters too (C1 controls, line separators,
        # bidi controls and surrogates), without obscuring CJK text or emoji.
        escaped = json.dumps(character, ensure_ascii=not character.isprintable())[1:-1]
        parts.append(escaped)
    return '"' + "".join(parts) + '"' + (" [truncated]" if len(value) > limit else "")
