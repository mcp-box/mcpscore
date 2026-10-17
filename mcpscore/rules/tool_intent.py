"""Read what a tool says it does from its name and description, conservatively.

Used to check behavior annotations against the tool's own words. A tool is
classified only when its leading verb is unambiguous; anything else is
"unknown", because a false accusation of inconsistency is worse than a miss.
"""

from enum import StrEnum
import re

from mcp_types import Tool


class ToolIntent(StrEnum):
    READ = "read"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


_DESTRUCTIVE_VERBS = frozenset({"delete", "destroy", "erase"})
# Destructive only as a name verb ("drop_table"); in prose "drop a file in" or "wipe the filters" is milder.
_DESTRUCTIVE_NAME_ONLY = frozenset({"drop", "wipe"})
_READ_VERBS = frozenset(
    {
        "count",
        "describe",
        "fetch",
        "find",
        "get",
        "list",
        "lookup",
        "query",
        "read",
        "retrieve",
        "search",
        "show",
        "view",
    }
)
# Any of these in a read-named tool means it may also change something ("get_or_create").
_CHANGE_WORDS = frozenset(
    {
        "add",
        "apply",
        "approve",
        "archive",
        "assign",
        "cancel",
        "clear",
        "close",
        "copy",
        "create",
        "disable",
        "edit",
        "enable",
        "end",
        "execute",
        "generate",
        "hide",
        "import",
        "insert",
        "invite",
        "merge",
        "modify",
        "move",
        "post",
        "publish",
        "put",
        "reject",
        "remove",
        "rename",
        "replace",
        "reset",
        "restore",
        "run",
        "save",
        "send",
        "set",
        "start",
        "stop",
        "submit",
        "sync",
        "update",
        "upload",
        "upsert",
        "write",
    }
    | _DESTRUCTIVE_VERBS
    | _DESTRUCTIVE_NAME_ONLY
)
_ALL_VERBS = _READ_VERBS | _CHANGE_WORDS
_LEAD_ADVERBS = frozenset({"permanently", "irreversibly", "completely", "safely"})
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SEPARATORS = re.compile(r"[^A-Za-z0-9]+")
_WORD = re.compile(r"[A-Za-z]+")


def _name_tokens(name: str) -> list[str]:
    return [token.lower() for token in _SEPARATORS.split(_CAMEL_BOUNDARY.sub(" ", name)) if token]


def _base_verb(word: str) -> str:
    """Map "deletes"/"lists"/"retrieves" to the verb; leave other words alone."""
    for suffix in ("es", "s"):
        stem = word[: -len(suffix)]
        if word.endswith(suffix) and stem in _ALL_VERBS:
            return stem
    return word


def _name_verb(name: str) -> str | None:
    # The verb leads the name, or follows one namespace token ("github_delete_repo").
    for token in _name_tokens(name)[:2]:
        if token in _ALL_VERBS:
            return token
    return None


def _description_verb(description: str | None) -> str | None:
    words = [word.lower() for word in _WORD.findall(description or "")[:3]]
    while words and words[0] in _LEAD_ADVERBS:
        words.pop(0)
    if not words:
        return None
    verb = _base_verb(words[0])
    return verb if verb in _ALL_VERBS else None


def tool_intent(tool: Tool) -> ToolIntent:
    """Classify a tool as clearly reading, clearly destructive, or unknown.

    A description that opens with a verb decides; the name decides otherwise. "delete_person_preview"
    described as "Create a non-mutating snapshot" is not a delete.
    """
    name_verb = _name_verb(tool.name)
    description_verb = _description_verb(tool.description)
    if description_verb is not None:
        destructive = description_verb in _DESTRUCTIVE_VERBS
    else:
        destructive = name_verb in _DESTRUCTIVE_VERBS | _DESTRUCTIVE_NAME_ONLY
    if destructive:
        return ToolIntent.DESTRUCTIVE
    if name_verb in _READ_VERBS:
        changes = set(_name_tokens(tool.name)) & _CHANGE_WORDS
        if not changes and description_verb not in _CHANGE_WORDS:
            return ToolIntent.READ
    return ToolIntent.UNKNOWN
