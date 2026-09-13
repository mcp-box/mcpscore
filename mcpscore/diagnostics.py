"""Build bounded validation diagnostics without copying server response values."""

import json
from typing import Any

from pydantic import ValidationError


def validation_diagnostics(error: ValidationError, *, prefix: tuple[str | int, ...] = ()) -> dict[str, Any]:
    """Preserve validation locations and types, omitting inputs and overlong paths."""
    issues: list[dict[str, Any]] = []
    for item in error.errors(include_input=False, include_context=False, include_url=False)[:20]:
        path = "/" + "/".join(
            json.dumps(str(part), ensure_ascii=False)[1:-1].replace("~", "~0").replace("/", "~1")
            for part in (*prefix, *item["loc"])
        )
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
