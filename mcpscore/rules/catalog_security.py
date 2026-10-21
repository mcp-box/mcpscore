"""Security rules over the text a server publishes in its catalog.

Every string a server lists (instructions, names, titles, descriptions,
schemas, URIs) reaches the model's context before any tool runs. These rules
read only collected catalog data: no probe, no ``tools/call``. Evidence names
the location and the matched class, never the matched string, so a report
never repeats a secret or an injected instruction.
"""

from abc import abstractmethod
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from html import unescape as html_unescape
from html.parser import HTMLParser
import re
from typing import Any, ClassVar
from urllib.parse import unquote

from markdown_it import MarkdownIt
from markdown_it.token import Token
from mcp_types import Icon

from .base import SKIP_REASON_INSUFFICIENT_DATA, AuditData, BaseRule, RuleResult, RuleSeverity
from .catalog_diagnostics import catalog_result, field_issue, pointer_token
from .registry import register_rule

_LISTINGS = ("tools", "prompts", "resources", "resource_templates")


@dataclass(frozen=True)
class CatalogText:
    """One publisher-controlled string and where it sits in the catalog."""

    kind: str
    index: int | None
    path: str
    text: str
    in_key: bool = False
    """The text is an object key; ``path`` then points at the object, so a key is never echoed."""


def _schema_strings(value: Any, pointer: str) -> Iterator[tuple[str, str, bool]]:
    """Yield every string in a JSON schema with its JSON Pointer and whether it is a key."""
    if isinstance(value, str):
        yield pointer, value, False
    elif isinstance(value, dict):
        for key, item in value.items():
            yield pointer, str(key), True
            yield from _schema_strings(item, f"{pointer}/{pointer_token(str(key))}")
    elif isinstance(value, list):
        for position, item in enumerate(value):
            yield from _schema_strings(item, f"{pointer}/{position}")


def _icon_texts(kind: str, index: int | None, base: str, icons: list[Icon] | None) -> Iterator[CatalogText]:
    """Yield each icon's strings; a ``data:`` URI is an encoded image, not text, and is skipped."""
    for position, icon in enumerate(icons or []):
        path = f"{base}/{position}"
        if icon.src and not icon.src.lower().startswith("data:"):
            yield CatalogText(kind, index, f"{path}/src", icon.src)
        if icon.mime_type:
            yield CatalogText(kind, index, f"{path}/mimeType", icon.mime_type)
        for size_position, size in enumerate(icon.sizes or []):
            if size:
                yield CatalogText(kind, index, f"{path}/sizes/{size_position}", size)


def _json_texts(kind: str, index: int | None, root: str, value: Any) -> Iterator[CatalogText]:
    """Yield every non-empty string key and value of a JSON document such as a schema or ``_meta``."""
    for path, text, in_key in _schema_strings(value, root):
        if text:
            yield CatalogText(kind, index, path, text, in_key)


def catalog_texts(audit_data: AuditData) -> Iterator[CatalogText]:
    """Yield every publisher-controlled string the audit collected."""

    def entries(kind: str, index: int | None, fields: dict[str, object]) -> Iterator[CatalogText]:
        for path, value in fields.items():
            if isinstance(value, str) and value:
                yield CatalogText(kind, index, path, value)

    if audit_data.instructions:
        yield CatalogText("server", None, "/instructions", audit_data.instructions)
    info = audit_data.server_info
    if info is not None:
        yield from entries(
            "server",
            None,
            {
                "/serverInfo/name": info.name,
                "/serverInfo/title": info.title,
                "/serverInfo/version": info.version,
                "/serverInfo/description": info.description,
                "/serverInfo/websiteUrl": info.website_url,
            },
        )
        yield from _icon_texts("server", None, "/serverInfo/icons", info.icons)
    for index, tool in enumerate(audit_data.tools or []):
        annotations_title = tool.annotations.title if tool.annotations else None
        fields = {"/name": tool.name, "/title": tool.title, "/description": tool.description}
        yield from entries("tool", index, {**fields, "/annotations/title": annotations_title})
        yield from _icon_texts("tool", index, "/icons", tool.icons)
        for root, document in (("/inputSchema", tool.input_schema), ("/outputSchema", tool.output_schema)):
            yield from _json_texts("tool", index, root, document)
        yield from _json_texts("tool", index, "/_meta", tool.meta)
    for index, prompt in enumerate(audit_data.prompts or []):
        yield from entries(
            "prompt", index, {"/name": prompt.name, "/title": prompt.title, "/description": prompt.description}
        )
        yield from _icon_texts("prompt", index, "/icons", prompt.icons)
        for position, argument in enumerate(prompt.arguments or []):
            base = f"/arguments/{position}"
            yield from entries(
                "prompt",
                index,
                {
                    f"{base}/name": argument.name,
                    f"{base}/title": argument.title,
                    f"{base}/description": argument.description,
                },
            )
        yield from _json_texts("prompt", index, "/_meta", prompt.meta)
    resources = [("/uri", item, item.uri) for item in audit_data.resources or []]
    templates = [("/uriTemplate", item, item.uri_template) for item in audit_data.resource_templates or []]
    for kind, items in (("resource", resources), ("resource_template", templates)):
        for index, (uri_path, item, uri) in enumerate(items):
            last_modified = item.annotations.last_modified if item.annotations else None
            yield from entries(
                kind,
                index,
                {
                    uri_path: uri,
                    "/name": item.name,
                    "/title": item.title,
                    "/description": item.description,
                    "/mimeType": item.mime_type,
                    "/annotations/lastModified": last_modified,
                },
            )
            yield from _icon_texts(kind, index, "/icons", item.icons)
            yield from _json_texts(kind, index, "/_meta", item.meta)


def _publishable_path(path: str) -> tuple[str, bool]:
    """Cut *path* above the first segment that is itself a finding, so evidence never echoes it."""
    segments = path.split("/")
    for position, segment in enumerate(segments[1:], start=1):
        text = segment.replace("~1", "/").replace("~0", "~")
        if (
            hidden_unicode_classes(text)
            or secret_classes(text)
            or injection_classes(text)
            or exfiltration_link_classes(text)
        ):
            return "/".join(segments[:position]), True
    return path, False


class CatalogSecurityRule(BaseRule):
    """Base for rules that scan every collected catalog string.

    Subclasses return the matched classes for one string; the base turns
    matches into bounded, location-only evidence.
    """

    group_name = "security"
    group_order = 3
    issue_reason: ClassVar[str]
    expected: ClassVar[str]
    passed_message: ClassVar[str]
    failure_label: ClassVar[str]
    fix: ClassVar[str]

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no session data was collected, as in a partial audit.

        A listing that came back empty without finishing is no evidence of a
        clean catalog, so it does not count as collected.
        """
        collected = any(
            getattr(audit_data, listing) is not None
            and (getattr(audit_data, listing) or listing not in audit_data.incomplete_listings)
            for listing in _LISTINGS
        )
        has_server_text = audit_data.server_info is not None or audit_data.instructions is not None
        if audit_data.partial or not (collected or has_server_text):
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    @abstractmethod
    def matches(self, text: str) -> list[str]:
        """Return the class name of each finding in *text*, in order."""

    def check(self, audit_data: AuditData) -> RuleResult:
        """Scan every catalog string and report locations with the matched classes."""
        issues: list[dict[str, Any]] = []
        classes: Counter[str] = Counter()
        for entry in catalog_texts(audit_data):
            found = self.matches(entry.text)
            if found:
                classes.update(found)
                path, truncated = _publishable_path(entry.path)
                issue = field_issue(entry.kind, entry.index, path, self.issue_reason, self.expected)
                flags = {"in_key": True} if entry.in_key else {}
                if truncated:
                    flags["path_truncated"] = True
                issues.append({**issue, "matched": sorted(set(found)), **flags})
        passed = not issues
        details: dict[str, Any] = {"strings_with_findings": len(issues), "matched": dict(sorted(classes.items()))}
        if audit_data.incomplete_listings:
            details["incomplete_listings"] = sorted(audit_data.incomplete_listings)
        message = f"✅ {self.passed_message}" if passed else f"❌ Number of {self.failure_label}: {len(issues)}"
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details=details,
            suggested_fix=self.fix,
            issues=issues,
        )


# Tag characters, U+E0000-E007F, are valid only inside an emoji tag sequence:
# U+1F3F4 WAVING BLACK FLAG, tag spec characters U+E0020-E007E, U+E007F CANCEL TAG
# (UTS #51 §2.8, e.g. the flag of England).
_FLAG_BASE = "\U0001f3f4"
_CANCEL_TAG = "\U000e007f"
_BIDI_CONTROLS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
# Zero-width and formatting characters that render as nothing. One alone is
# legitimate (a joiner in an emoji, a directional mark in right-to-left text, a
# soft hyphen); only runs of two or more count.
_INVISIBLES = frozenset("\u00ad\u061c\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff")


def _is_tag(char: str) -> bool:
    return "\U000e0000" <= char <= "\U000e007f"


def _is_tag_spec(char: str) -> bool:
    return "\U000e0020" <= char <= "\U000e007e"


def _is_variation_selector(char: str) -> bool:
    return "\ufe00" <= char <= "\ufe0f" or "\U000e0100" <= char <= "\U000e01ef"


_EMOJI_JOIN = "\ufe0f\u200d"


def _is_invisible(char: str) -> bool:
    return char in _INVISIBLES or _is_variation_selector(char)


def _is_control(char: str) -> bool:
    code = ord(char)
    return (code < 0x20 and char not in "\t\n\r") or 0x7F <= code <= 0x9F


def hidden_unicode_classes(text: str) -> list[str]:
    """Classify invisible characters that can carry text a reader never sees.

    Single zero-width joiners and variation selectors are legitimate in emoji
    and in scripts that need them, so only runs of two or more count; tag
    characters count unless they form a well-formed emoji tag sequence.
    """
    found: list[str] = []
    position = 0
    while position < len(text):
        char = text[position]
        if char == _FLAG_BASE:
            end = position + 1
            while end < len(text) and _is_tag_spec(text[end]):
                end += 1
            if end > position + 1 and end < len(text) and text[end] == _CANCEL_TAG:
                position = end + 1
                continue
        if _is_tag(char):
            found.append("tag_characters")
        elif char in _BIDI_CONTROLS:
            found.append("bidi_controls")
        elif _is_control(char):
            found.append("control_characters")
        elif _is_invisible(char):
            end, units = position, 0
            while end < len(text) and _is_invisible(text[end]):
                # Emoji ZWJ sequences put VS16 directly before the joiner; that pair is one unit.
                end += 2 if text.startswith(_EMOJI_JOIN, end) else 1
                units += 1
            if units >= 2:
                run = text[position:end]
                all_selectors = all(_is_variation_selector(member) for member in run)
                found.append("variation_selector_run" if all_selectors else "zero_width_run")
            position = end
            continue
        position += 1
    return found


@register_rule
class CatalogHiddenUnicodeRule(CatalogSecurityRule):
    """High check: catalog text carries no invisible characters.

    Tag characters, bidirectional overrides, control characters and runs of
    zero-width characters or variation selectors render as nothing, or reorder
    what renders, while the model still reads them. They are how instructions
    hide inside a tool description that looks harmless to its reviewer.

    Scoring: 3 points (HIGH)
    """

    rule_id = "catalog_hidden_unicode"
    basis = (
        "OWASP MCP Top 10 (beta) MCP03:2025 Tool Poisoning and MCP06:2025 Prompt Injection via Contextual "
        "Payloads; MCP 2025-11-25 §Security and Trust & Safety (Tool Safety: tool descriptions are untrusted); "
        "Unicode UTS #51 §2.8 (tag sequences), CVE-2021-42574 (bidirectional overrides)"
    )
    rule_order = 20
    issue_reason = "hidden_unicode"
    expected = "visible text without tag characters, bidirectional controls, control characters or invisible runs"
    passed_message = "Catalog text contains no hidden Unicode characters"
    failure_label = "catalog strings with hidden Unicode characters"
    fix = (
        "Remove the invisible characters from the listed fields. If they came from copied text, retype it; "
        "text a reviewer cannot see should not reach the model."
    )

    @property
    def rule_name(self) -> str:
        return "No Hidden Unicode in Catalog Text"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def matches(self, text: str) -> list[str]:
        """Return the hidden-Unicode classes found in *text*."""
        return hidden_unicode_classes(text)


# Provider-issued formats with a fixed prefix, so a match is a credential and
# not a word that happens to be long. Each value is the pattern's class name.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "aws_access_key_id"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "github_token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b"), "github_token"),
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), "gitlab_token"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "slack_token"),
    (re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}"), "stripe_live_key"),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{30,}"), "anthropic_api_key"),
    (re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}"), "openai_api_key"),
    (re.compile(r"\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{40,}"), "openai_api_key"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "google_api_key"),
    (re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY(?: BLOCK)?-----"), "private_key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}"), "jwt"),
    (re.compile(r"\b(?i:bearer)\s+[A-Za-z0-9._~+/-]{24,}=*"), "bearer_token"),
)

# The documentation samples that look like credentials but grant nothing:
# AWS's published example key and jwt.io's sample token.
_DOCUMENTATION_SAMPLES = ("AKIAIOSFODNN7EXAMPLE", "eyJzdWIiOiIxMjM0NTY3ODkwIi")
# A placeholder is a whole word ("YOUR_API_TOKEN", "<example>", "xxxx"), never a
# substring of a random value, which can contain "your" by chance.
_PLACEHOLDER_RE = re.compile(r"(?<![a-z0-9])(?:example|placeholder|your|x{4,})(?![a-z])", re.IGNORECASE)


def _is_placeholder(value: str) -> bool:
    return any(sample in value for sample in _DOCUMENTATION_SAMPLES) or _PLACEHOLDER_RE.search(value) is not None


def secret_classes(text: str) -> list[str]:
    """Return the credential classes whose provider format appears in *text*."""
    found: list[str] = []
    for pattern, name in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            if not _is_placeholder(value) and len(set(value[-16:])) > 4:
                found.append(name)
    return found


@register_rule
class CatalogNoEmbeddedSecretsRule(CatalogSecurityRule):
    """High check: catalog text contains no credential.

    A catalog is public to every client that connects and is copied into the
    model's context. A provider key, token or private key in a description,
    schema default or resource URI is disclosed to all of them.

    Scoring: 3 points (HIGH)
    """

    rule_id = "catalog_no_embedded_secrets"
    basis = (
        "OWASP MCP Top 10 (beta) MCP01:2025 Token Mismanagement & Secret Exposure; MCP 2025-11-25 §Security and "
        "Trust & Safety (Implementation Guidelines: SHOULD follow security best practices and protect data)"
    )
    rule_order = 21
    issue_reason = "embedded_secret"
    expected = "no credential; reference it by name and supply it through configuration or authorization"
    passed_message = "Catalog text contains no credential-shaped strings"
    failure_label = "catalog strings with credential-shaped values"
    fix = (
        "Revoke and rotate each exposed credential first, then remove it from the catalog. Load secrets from the "
        "environment or use MCP authorization; never put them in descriptions, schemas or URIs."
    )

    @property
    def rule_name(self) -> str:
        return "No Secrets in Catalog Text"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def matches(self, text: str) -> list[str]:
        """Return the credential classes found in *text*."""
        return secret_classes(text)


# Phrasings that address the model rather than describe a capability. Each is
# narrow on purpose: "ignore case", "previous page", "tries to override the system
# prompt" and guidance such as "never tell the user there is no result" must not match.
_INJECTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+)?"
            r"(?:previous|prior|earlier|above|preceding|system|original)\s+"
            r"(?:instructions?|prompts?|messages?|rules|directions|guidelines|directives)(?![\w'\u2019])",
            re.IGNORECASE,
        ),
        "instruction_override",
    ),
    (
        re.compile(
            r"\b(?:do\s+not|don['\u2019]t|never)\s+(?:tell|inform|notify|alert)\s+the\s+user"
            r"(?:\s+(?:about|of)\s+(?:this|that|it|these)\b|\s*(?:[.;!)]|$))"
            r"|\b(?:do\s+not|don['\u2019]t|never)\s+(?:mention|reveal|disclose)\s+(?:this|that|it)\b(?:\s+\S+){0,6}?\s+to\s+the\s+user\b"
            r"|\bwithout\s+(?:telling|informing|notifying|alerting)\s+the\s+user\b"
            r"|\b(?:hide|conceal)\s+(?:this|it|that)\s+from\s+the\s+user\b",
            re.IGNORECASE | re.MULTILINE,
        ),
        "conceal_from_user",
    ),
    (
        re.compile(
            r"\byou\s+are\s+now\s+(?:a|an|my)\s+(?:\w+\s+){0,2}?"
            r"(?:assistant|ai|bot|agent|character|persona|player|pirate|hacker|model)\b"
            r"|\byou\s+are\s+now\s+in\s+(?:developer|god|jailbreak|unrestricted|dan)\s+mode\b"
            r"|\byou\s+are\s+no\s+longer\s+(?:an?\s+)?(?:assistant|ai|bound|restricted)\b",
            re.IGNORECASE,
        ),
        "role_reassignment",
    ),
    (
        re.compile(r"<\|(?:im_start|im_end|system|endoftext|start_header_id)\|>|\[/?INST\]|<</?SYS>>"),
        "chat_template_token",
    ),
)

# A phrase wrapped in quotes on both sides, listed with a slash, or introduced by
# "to" ("attempts to override the system prompt") names an attack rather than
# performing it: a scanner that lists the phrases it detects is describing itself.
_QUOTE_PAIRS = {'"': '"', "'": "'", "`": "`", "\u2018": "\u2019", "\u201c": "\u201d"}
# "attempts to override", "never allow imported text to override": the phrase is
# what something tries or is let to do. Bare imperatives ("Try to ignore …",
# "Allow yourself to ignore …", "You need to ignore …") are still directives.
_DESCRIBED_RE = re.compile(
    r"\b(?:attempts|attempting|attempted|tries|trying|tried|aims|aiming|seeks|seeking|designed|meant|intended|used)"
    r"\s+to\s+\Z"
    r"|(?:\b(?:allows|allowing|lets|letting|causes|causing|tricks|tricking|forces|forcing|gets|getting)"
    r"|(?:\bnever|\bnot|n['\u2019]t)\s+(?:allow|let|cause|force))"
    r"\s+(?:\S+\s+){1,3}(?:to\s+)?\Z",
    re.IGNORECASE,
)
_CLOSING_PUNCTUATION = ".,;:!?\u2026"


def _is_mention(text: str, start: int, end: int) -> bool:
    before = text[start - 1] if start > 0 else ""
    close = end
    while close < len(text) and text[close] in _CLOSING_PUNCTUATION:
        close += 1
    after = text[close] if close < len(text) else ""
    quoted = before in _QUOTE_PAIRS and after == _QUOTE_PAIRS[before]
    listed = "/" in (before, text[end] if end < len(text) else "")
    return quoted or listed or _DESCRIBED_RE.search(text[max(0, start - 60) : start]) is not None


def injection_classes(text: str) -> list[str]:
    """Return the injection-phrasing classes that appear in *text* as directives."""
    return [
        name
        for pattern, name in _INJECTION_PATTERNS
        if any(not _is_mention(text, match.start(), match.end()) for match in pattern.finditer(text))
    ]


@register_rule
class CatalogPromptInjectionPhrasingRule(CatalogSecurityRule):
    """High check: catalog text does not address the model with hidden directives.

    Tool poisoning hides instructions to the model in text the user never
    reads closely: override the earlier instructions, keep an action from the
    user, adopt a new role. The phrase list is fixed and documented; it flags
    text that speaks to the model about the conversation, not text that
    describes what a tool does.

    Scoring: 3 points (HIGH)
    """

    rule_id = "catalog_prompt_injection_phrasing"
    basis = (
        "OWASP MCP Top 10 (beta) MCP03:2025 Tool Poisoning and MCP06:2025 Prompt Injection via Contextual "
        "Payloads; MCP 2025-11-25 §Security and Trust & Safety (Tool Safety: tool descriptions are untrusted)"
    )
    rule_order = 22
    issue_reason = "prompt_injection_phrasing"
    expected = "text that describes the capability without directing the model about the user or its instructions"
    passed_message = "Catalog text contains no prompt-injection phrasing"
    failure_label = "catalog strings with prompt-injection phrasing"
    fix = (
        "Rewrite the listed fields to describe what the tool, prompt or resource does. Remove directives to the "
        "model about earlier instructions, roles, or what to keep from the user."
    )

    @property
    def rule_name(self) -> str:
        return "No Prompt-Injection Phrasing in Catalog Text"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def matches(self, text: str) -> list[str]:
        """Return the injection-phrasing classes found in *text*."""
        return injection_classes(text)


class _AllLinksMarkdown(MarkdownIt):
    """CommonMark parser that keeps every link.

    The default validator drops javascript:, vbscript:, file: and most data:
    links before they become tokens; this rule needs to see exactly those.
    """

    def validateLink(self, url: str) -> bool:  # noqa: N802 - overrides markdown-it's method name
        """Accept every destination so the rule can classify it."""
        return True


_LINK_MARKDOWN = _AllLinksMarkdown("commonmark")
# Only text that can hold a Markdown link, image, autolink or HTML tag is parsed.
_LINK_HINTS = ("](", "]:", "<")
_SCRIPT_SCHEMES = frozenset({"javascript", "vbscript"})
# Raster images that cannot carry script; SVG can, so it is not here.
_SAFE_DATA_IMAGE_RE = re.compile(
    r"^data:image/(?:png|jpe?g|gif|webp|bmp|avif|x-icon|vnd\.microsoft\.icon)[;,]", re.IGNORECASE
)
# A slot the model is asked to fill: {x}, {{x}}, ${x}, <x>, $NAME.
_PLACEHOLDER_URL_RE = re.compile(
    r"\{\{?\s*[A-Za-z_][\w.\- ]{0,63}\}\}?|\$\{[^{}]{1,64}\}|<[A-Za-z_][\w.\- ]{0,63}>|\$[A-Z_][A-Z0-9_]{0,63}\b"
)
# URL-valued attributes (HTML §URL attributes, SVG xlink:href). Those listed as loading fetch on
# render; the rest act on a click or a form submission and are judged like a link.
_LOADING_ATTRIBUTES = frozenset(
    {"src", "srcset", "poster", "background", "lowsrc", "dynsrc", "icon", "manifest", "codebase", "archive"}
)
_ACTION_ATTRIBUTES = frozenset({"action", "formaction", "cite", "longdesc"})
# The only elements whose href navigates on a click (HTML and SVG); on any other
# element (link, image, feImage, use, ...) an href loads or applies a resource.
_NAVIGATING_TAGS = frozenset({"a", "area"})
_HTML_SPACE = " \t\n\f\r"
"""ASCII whitespace, the only whitespace HTML attribute microsyntaxes split on."""
# <meta http-equiv="refresh" content="0; url=..."> navigates on render.
_REFRESH_URL_RE = re.compile(r"^[\s\d.]*[;,]?\s*(?:url\s*=\s*)?['\"]?([^'\"]*)", re.IGNORECASE)
MAX_LINK_MARKDOWN_BYTES = 64 * 1024
"""Longer strings are not parsed as Markdown; they are judged as a whole, see ``_oversized_classes``."""
# Script schemes in oversized text, also when split by whitespace or control characters.
_SCHEME_GAP = r"[\s\x00-\x1f]*"
_RAW_SCRIPT_RE = re.compile(
    "(?:" + "|".join(_SCHEME_GAP.join(word) for word in sorted(_SCRIPT_SCHEMES)) + ")" + _SCHEME_GAP + ":",
    re.IGNORECASE,
)
_RAW_UNSAFE_DATA_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])"
    + _SCHEME_GAP.join("data")
    + _SCHEME_GAP
    + r":(?!image/(?:png|jpe?g|gif|webp|bmp|avif|x-icon|vnd\.microsoft\.icon)[;,])",
    re.IGNORECASE,
)
_RAW_NETWORK_URL_RE = re.compile(r"\bhttps?:|[/\\]{2}", re.IGNORECASE)


def _srcset_urls(value: str) -> Iterator[str]:
    """Yield each candidate URL of a ``srcset``; commas inside a URL belong to it (HTML §srcset parsing)."""
    position, size = 0, len(value)
    while position < size:
        while position < size and (value[position] in _HTML_SPACE or value[position] == ","):
            position += 1
        start = position
        while position < size and value[position] not in _HTML_SPACE:
            position += 1
        url = value[start:position]
        if url.endswith(","):
            url = url.rstrip(",")
        else:
            depth = 0
            while position < size and (value[position] != "," or depth):
                depth += {"(": 1, ")": -1 if depth else 0}.get(value[position], 0)
                position += 1
        if url:
            yield url


class _HtmlUrls(HTMLParser):
    """Collect the URL attributes of raw HTML; ``href`` navigates, the others load on render."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[tuple[str, bool]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values: dict[str, str] = {}
        for name, value in attrs:
            values.setdefault(name, value or "")  # a browser keeps the first of duplicate attributes, even empty
        if tag == "meta" and values.get("http-equiv", "").strip().lower() == "refresh":
            self.urls.append((_REFRESH_URL_RE.sub(r"\1", values.get("content", ""), count=1), True))
        for name, value in values.items():
            if not value:
                continue
            if name == "srcset":
                self.urls.extend((url, True) for url in _srcset_urls(value))
            elif name in ("href", "xlink:href"):
                self.urls.append((value, tag not in _NAVIGATING_TAGS))
            elif name in _LOADING_ATTRIBUTES or (name in ("data", "classid") and tag == "object"):
                self.urls.append((value, True))
            elif name == "ping":
                # A space-separated list of URLs, each requested when the link is followed.
                self.urls.extend((url, False) for url in re.split(f"[{_HTML_SPACE}]+", value) if url)
            elif name in _ACTION_ATTRIBUTES:
                self.urls.append((value, False))

    handle_startendtag = handle_starttag


def _html_urls(html: str) -> list[tuple[str, bool]]:
    parser = _HtmlUrls()
    parser.feed(html)
    parser.close()
    return parser.urls


def _token_urls(tokens: list[Token]) -> Iterator[tuple[str, bool]]:
    for token in tokens:
        if token.type == "link_open":
            yield str(token.attrs.get("href", "")), False
        elif token.type == "image":
            # Alt text is text, not markup: links nested in it are not rendered as links.
            yield str(token.attrs.get("src", "")), True
            continue
        elif token.type in ("html_inline", "html_block"):
            yield from _html_urls(token.content)
        if token.children:
            yield from _token_urls(token.children)


def _oversized(text: str) -> bool:
    # surrogatepass: a lone surrogate from a server's JSON must be measured, not raise.
    return len(text.encode("utf-8", "surrogatepass")) > MAX_LINK_MARKDOWN_BYTES


def _oversized_classes(text: str) -> list[str]:
    """Judge text too long to parse as a whole, conservatively, without extracting single URLs.

    After decoding entities and percent-escapes: a script scheme anywhere, a ``data:`` URI other
    than a raster image anywhere, and a slot anywhere in text that also holds a network URL.
    """
    decoded = unquote(html_unescape(text))
    found: list[str] = []
    if _RAW_SCRIPT_RE.search(decoded):
        found.append("script_uri")
    if _RAW_UNSAFE_DATA_RE.search(decoded):
        found.append("data_uri")
    if _RAW_NETWORK_URL_RE.search(decoded) and _PLACEHOLDER_URL_RE.search(decoded):
        found.append("exfiltration_query")
    return found


def markdown_urls(text: str) -> list[tuple[str, bool]]:
    """Return each URL a Markdown renderer would link or load, with whether it loads without a click.

    Text over ``MAX_LINK_MARKDOWN_BYTES`` is not parsed and yields no URLs.
    """
    if not any(hint in text for hint in _LINK_HINTS) or _oversized(text):
        return []
    return list(_token_urls(_LINK_MARKDOWN.parse(text)))


def _visible(url: str) -> str:
    """Drop whitespace and control characters, which browsers strip from URLs before resolving them."""
    return "".join(char for char in url if char.isprintable() and not char.isspace())


def _query(url: str) -> str:
    """Return the query the way a browser splits it: after the first ``?``, before the first ``#``."""
    return url.split("#", 1)[0].partition("?")[2]


def exfiltration_link_classes(text: str) -> list[str]:
    """Classify Markdown and HTML links that run script or carry data out of the conversation."""
    if any(hint in text for hint in _LINK_HINTS) and _oversized(text):
        return _oversized_classes(text)
    found: list[str] = []
    for raw, loads in markdown_urls(text):
        url = _visible(raw)
        decoded = _visible(unquote(raw))
        scheme = decoded.split(":", 1)[0].lower() if ":" in decoded else ""
        network_path = decoded.replace("\\", "/").startswith("//")
        if scheme in _SCRIPT_SCHEMES:
            found.append("script_uri")
        elif scheme == "data":
            if not (loads and _SAFE_DATA_IMAGE_RE.match(decoded)):
                found.append("data_uri")
        elif scheme in ("http", "https") or network_path:
            # An image loads with no click, so a slot anywhere in it sends data;
            # a link sends only what its query carries, as path slots are usually API routes.
            exposed = decoded if loads else unquote(_query(url))
            if _PLACEHOLDER_URL_RE.search(exposed):
                found.append("exfiltration_query")
    return found


@register_rule
class CatalogExfiltrationLinksRule(CatalogSecurityRule):
    """High check: catalog text has no links that run script or carry data out.

    A client that renders Markdown fetches an image without a click. When a
    description asks the model to fill a slot in that image's URL, the
    conversation leaves with the request. ``javascript:`` and ``data:`` links
    run or display content the reviewer never sees.

    Scoring: 3 points (HIGH)
    """

    rule_id = "catalog_exfiltration_links"
    basis = (
        "OWASP MCP Top 10 (beta) MCP03:2025 Tool Poisoning and MCP06:2025 Prompt Injection via Contextual "
        "Payloads; MCP 2025-11-25 §Security and Trust & Safety (Tool Safety: tool descriptions are untrusted)"
    )
    rule_order = 23
    issue_reason = "exfiltration_link"
    expected = "links to fixed http(s) addresses, with no script or data URIs and no slots for the model to fill"
    passed_message = "Catalog text contains no script links or data-carrying URLs"
    failure_label = "catalog strings with script links or data-carrying URLs"
    fix = (
        "Remove javascript: and data: links from the listed fields, and remove placeholders from link and image "
        "URLs. Link to fixed pages; return data in tool results, never through a URL the model fills in."
    )

    @property
    def rule_name(self) -> str:
        return "No Exfiltration Links in Catalog Text"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def matches(self, text: str) -> list[str]:
        """Return the exfiltration-link classes found in *text*."""
        return exfiltration_link_classes(text)
