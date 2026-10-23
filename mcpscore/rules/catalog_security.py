"""Security rules over the text a server publishes in its catalog.

Every string a server lists (instructions, names, titles, descriptions,
schemas, URIs) reaches the model's context before any tool runs. These rules
read only collected catalog data: no probe, no ``tools/call``. Evidence names
the location and the matched class, never the matched string, so a report
never repeats a secret or an injected instruction.
"""

from abc import abstractmethod
from bisect import bisect_left
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from html.parser import HTMLParser
import ipaddress
import re
from typing import Any, ClassVar
from urllib.parse import unquote, urljoin, urlsplit

from markdown_it import MarkdownIt
from markdown_it.token import Token
from mcp_types import Icon

from mcpscore.html_text import bound_charrefs
from mcpscore.probes import PROBE_STATELESS_LIST

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
            or cross_tool_classes(text, frozenset())
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

    def text_matcher(self, audit_data: AuditData) -> Callable[[str], list[str]]:
        """Return the matcher for this audit's strings; rules that judge text against the catalog override it."""
        return self.matches

    def check(self, audit_data: AuditData) -> RuleResult:
        """Scan every catalog string and report locations with the matched classes."""
        issues: list[dict[str, Any]] = []
        classes: Counter[str] = Counter()
        matches = self.text_matcher(audit_data)
        for entry in catalog_texts(audit_data):
            found = matches(entry.text)
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

    def normalizeLink(self, url: str) -> str:  # noqa: N802 - overrides markdown-it's method name
        """Keep the destination as written: percent-encoding a tab or space would hide a scheme a client keeps."""
        return url


_LINK_MARKDOWN = _AllLinksMarkdown("commonmark")
# Only text that can hold a Markdown link, image, autolink or HTML tag is parsed.
_LINK_HINTS = ("](", "]:", "<")
_SCRIPT_SCHEMES = frozenset({"javascript", "vbscript"})
# The open-element count key for declarative shadow roots, the only HTML templates kept on the open stack.
_SHADOW_ROOT = "#shadow-root"
# Raster images that cannot carry script; SVG can, so it is not here.
_SAFE_DATA_IMAGE_RE = re.compile(
    r"^data:image/(?:a?png|jpe?g|gif|webp|bmp|avif|x-icon|vnd\.microsoft\.icon)[;,]", re.IGNORECASE
)
# A slot the model is asked to fill: {x}, {{x}}, ${x}, <x>, $NAME.
_PLACEHOLDER_URL_RE = re.compile(
    r"\{\{?\s*[A-Za-z_][\w.\- ]{0,63}\}\}?|\$\{[^{}]{1,64}\}|<[A-Za-z_][\w.\- ]{0,63}>|\$[A-Z_][A-Z0-9_]{0,63}\b"
)
# The element and attribute pairs a browser fetches on render (HTML and SVG); an attribute on any
# other element is inert. srcset-style lists are split into candidates.
_LOADING_ATTRIBUTES: dict[str, frozenset[str]] = {
    "img": frozenset({"src", "srcset"}),
    "video": frozenset({"src", "poster"}),
    "audio": frozenset({"src"}),
    "track": frozenset({"src"}),
    "iframe": frozenset({"src"}),
    "frame": frozenset({"src"}),
    "embed": frozenset({"src"}),
    "script": frozenset({"src"}),
    "object": frozenset({"data"}),
    "body": frozenset({"background"}),
    "table": frozenset({"background"}),
    "td": frozenset({"background"}),
    "th": frozenset({"background"}),
    "image": frozenset({"src", "srcset"}),  # legacy HTML <image>, which browsers parse as <img>
}
# Inside <svg>, these elements load from href or xlink:href instead.
_SVG_LOADING_ATTRIBUTES: dict[str, frozenset[str]] = {
    tag: frozenset({"href", "xlink:href"}) for tag in ("image", "feimage", "use", "script")
}
# SVG presentation attributes whose value can name a resource with url().
_SVG_URL_PROPERTIES = frozenset(
    {"clip-path", "cursor", "fill", "filter", "marker-end", "marker-mid", "marker-start", "mask", "stroke"}
)
# SVG animation elements, which set an attribute to their from, to, by and values over time.
_SVG_ANIMATIONS = frozenset({"animate", "set"})
# HTML's special elements (HTML §13.2.4.2): an end tag the body insertion mode does not list, such as a
# custom element's, is ignored when one of them is open above its match.
_SPECIAL_TAG_NAMES = (
    "address applet area article aside base basefont bgsound blockquote body br button caption center col colgroup"
    " dd details dir div dl dt embed fieldset figcaption figure footer form frame frameset h1 h2 h3 h4 h5 h6 head"
    " header hgroup hr html iframe img input keygen li link listing main marquee menu meta nav noembed noframes"
    " noscript object ol p param plaintext pre script search section select source style summary table tbody td"
    " template textarea tfoot th thead title tr track ul wbr xmp"
)
_SPECIAL_TAGS = frozenset(_SPECIAL_TAG_NAMES.split())
# End tags the body insertion mode handles by name; every other end tag takes the "any other end tag" steps.
_LISTED_END_TAG_NAMES = (
    "a address applet article aside b big blockquote body br button center code dd details dialog dir div dl dt"
    " em fieldset figcaption figure font footer form h1 h2 h3 h4 h5 h6 header hgroup html i li listing main"
    " marquee menu nav nobr object ol p pre s search section small strike strong summary template tt u ul"
)
_LISTED_END_TAGS = frozenset(_LISTED_END_TAG_NAMES.split())
# Elements that bound an end tag's scope (HTML §13.2.4.2): a browser ignores an end tag for an element
# outside them.
_SCOPE_BOUNDARIES = frozenset({"applet", "caption", "html", "marquee", "object", "table", "td", "template", "th"})
# Inside <svg>, only an anchor follows a link.
_SVG_ACTION_ATTRIBUTES: dict[str, frozenset[str]] = {"a": frozenset({"href", "xlink:href", "ping"})}
# HTML parsing in foreign content (HTML §13.2.6.5): children of these SVG and MathML integration points
# are HTML again, and these HTML start tags inside SVG or MathML end the foreign content.
_SVG_INTEGRATION_POINTS = frozenset({"foreignobject", "desc", "title"})
_MATHML_INTEGRATION_POINTS = frozenset({"mi", "mo", "mn", "ms", "mtext"})
_FOREIGN_BREAKOUT_TAGS = frozenset(
    [
        "b",
        "big",
        "blockquote",
        "body",
        "br",
        "center",
        "code",
        "dd",
        "div",
        "dl",
        "dt",
        "em",
        "embed",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "head",
        "hr",
        "i",
        "img",
        "li",
        "listing",
        "menu",
        "meta",
        "nobr",
        "ol",
        "p",
        "pre",
        "ruby",
        "s",
        "small",
        "span",
        "strong",
        "strike",
        "sub",
        "sup",
        "table",
        "tt",
        "u",
        "ul",
        "var",
    ]
)
# HTML elements without an end tag, never left open.
_VOID_TAGS = frozenset(
    {"area", "base", "br", "col", "embed", "frame", "hr", "image", "img", "input", "link", "meta", "param"}
    | {"source", "track", "wbr"}
)
# The pairs that act on a click or a form submission, judged like a link.
_ACTION_ATTRIBUTES: dict[str, frozenset[str]] = {
    "a": frozenset({"href", "ping"}),
    "area": frozenset({"href", "ping"}),
    "form": frozenset({"action"}),
    "button": frozenset({"formaction"}),
    "input": frozenset({"formaction"}),
}
# <link> relations that fetch their href on render; any other relation is metadata.
_FETCHING_LINK_RELATIONS = frozenset(
    {
        "stylesheet",
        "icon",
        "apple-touch-icon",
        "mask-icon",
        "manifest",
        "preload",
        "prefetch",
        "modulepreload",
        "prerender",
    }
)
_LIST_ATTRIBUTES = frozenset({"srcset", "imagesrcset", "ping"})
# <link> relations that resolve their href's hostname on render, sending only the hostname.
_CONNECTION_HINT_RELATIONS = frozenset({"dns-prefetch", "preconnect"})
_HTML_SPACE = " \t\n\f\r"
_URL_TRIMMED = "".join(map(chr, range(0x21)))  # C0 controls and space
# A host this rule reads the way a browser does: ASCII domain labels, or a dotted-decimal IPv4 address.
_PLAIN_HOST_RE = re.compile(r"(?:[a-z0-9_-]+\.)*[a-z0-9_-]+\.?")
_NUMERIC_LABEL_RE = re.compile(r"[0-9]+|0x[0-9a-f]*")
_DOTTED_DECIMAL_RE = re.compile(
    r"(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.?"
)
# The JavaScript MIME type essences (MIME Sniffing §4.6), which make a script element a classic script.
_JAVASCRIPT_TYPES = frozenset(
    {"application/ecmascript", "application/javascript", "application/x-ecmascript", "application/x-javascript"}
    | {"text/ecmascript", "text/javascript", "text/jscript", "text/livescript", "text/x-ecmascript"}
    | {"text/x-javascript"}
    | {f"text/javascript1.{minor}" for minor in range(6)}
)
"""ASCII whitespace, the only whitespace HTML attribute microsyntaxes split on."""
# <meta http-equiv="refresh" content="0; url=..."> navigates on render; without a leading delay it is ignored.
# A quoted destination ends at the matching quote, an unquoted one at the end of the content.
_REFRESH_URL_RE = re.compile(
    r"[ \t\n\f\r]*[\d.]+(?![^;, \t\n\f\r])[ \t\n\f\r]*[;,]?[ \t\n\f\r]*"
    r"(?:url[ \t\n\f\r]*=[ \t\n\f\r]*)?(?:'([^']*)|\"([^\"]*)|([\s\S]*))",
    re.IGNORECASE,
)
# The authority of an http(s) or network-path URL, after any userinfo.
_AUTHORITY_RE = re.compile(r"(?i)^(?:https?:)?//(?:[^/?#]*@)?([^/?#]*)")
# A port after the hostname: digits, or one slot standing for them.
_PORT_RE = re.compile(r":(?:\d*|\{\{?[^{}:]*\}\}?|\$\{[^{}:]*\}|<[^<>:]*>|\$[A-Z_][A-Z0-9_]*)$")
# A CSS escape's hex digits, and the whitespace CSS tokenizing knows after newlines are normalized.
_CSS_HEX_RE = re.compile(r"[0-9a-fA-F]{1,6}")
_CSS_SPACE = " \t\n"
# CSS functions that take a string as an image URL.
_CSS_IMAGE_FUNCTIONS = frozenset({"image-set", "-webkit-image-set"})
# Content of these elements is never rendered as markup (script and style are raw text to HTMLParser).
_INERT_TAGS = frozenset({"template", "textarea", "title"})
# HTML elements whose content a browser with scripting reads as raw text up to their own end tag, whatever
# the Python version's tokenizer does; plaintext content runs to the end of the document.
_RAW_TEXT_TAGS = frozenset({"iframe", "noembed", "noframes", "noscript", "script", "style", "xmp"})
# Raw-text and inert start tags that HTML's "in select" insertion mode ignores (script is still processed).
_SELECT_IGNORED_TAGS = (_RAW_TEXT_TAGS - {"script"}) | {"base", "math", "plaintext", "svg", "title"}
# Elements whose child list (picture, audio, video) decides what a <source> loads.
_SOURCE_PARENTS = frozenset({"picture", "audio", "video"})
MAX_LINK_MARKDOWN_BYTES = 64 * 1024
"""Longer strings holding markup are not parsed and fail as uncheckable; real catalog strings stay far below."""
MAX_SRCDOC_DEPTH = 3
"""Iframe srcdoc documents nested deeper are not followed and fail as uncheckable."""
MAX_RENDERED_CHARS = 4 * MAX_LINK_MARKDOWN_BYTES
"""Markdown rendering to more text and URLs than this (reference links repeat a destination) is uncheckable."""


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


def _css_urls(css: str, *, strings: bool = True) -> list[str]:
    """Return what a stylesheet may load: url() tokens and, unless *strings* is false, resource strings.

    The resource strings are those @import and image-set() take.
    Tokenizes as CSS Syntax §4 does, so comments, strings and url() boundaries are found before escapes are
    decoded inside each token. A string anywhere else, such as a ``content`` value, is only displayed.
    """
    scanner = _CssScanner(re.sub(r"\r\n?|\f", "\n", css).replace("\0", "\ufffd"), strings)
    scanner.scan()
    return [url for url in dict.fromkeys(scanner.urls) if url]


class _CssScanner:
    """One pass over a stylesheet, tracking the open functions and whether an @import prelude is open."""

    def __init__(self, css: str, strings: bool) -> None:
        super().__init__()
        self.css, self.strings = css, strings
        self.urls: list[str] = []
        self.functions: list[str] = []  # open functions and parentheses, innermost last
        self.loading_functions = 0  # how many open functions take a string as an image
        self.importing = False
        self.custom = False  # inside a custom property's value, which var() can carry into image-set()
        self.position = 0

    def scan(self) -> None:
        css = self.css
        while self.position < len(css):
            char = css[self.position]
            if css.startswith("/*", self.position):
                end = css.find("*/", self.position + 2)
                self.position = len(css) if end < 0 else end + 2
            elif char in "\"'":
                value, self.position = _css_string(css, self.position + 1, char)
                if self.strings and (self.importing or self.loading_functions or self.custom):
                    self.urls.append(value)
            elif _css_name_char(char) or _css_valid_escape(css, self.position):
                name, self.position = _css_name(css, self.position)
                if css.startswith("(", self.position):
                    self._function(name.lower())
                elif name.startswith("--") and css.startswith(":", _css_skip_blank(css, self.position)):
                    self.custom = True
            else:
                self._delimiter(char)

    def _function(self, name: str) -> None:
        start = self.position + 1
        while start < len(self.css) and self.css[start] in _CSS_SPACE:
            start += 1
        if name == "url" and not self.css.startswith(('"', "'"), start):
            value, self.position = _css_url(self.css, start)
            self.urls.append(value)
            return
        if name == "url":  # url("...") is a function taking a string, read like any other
            value, self.position = _css_string(self.css, start + 1, self.css[start])
            self.urls.append(value)
        else:
            self.position += 1
        self.functions.append(name)
        self.loading_functions += name in _CSS_IMAGE_FUNCTIONS

    def _delimiter(self, char: str) -> None:
        self.position += 1
        if char == "@":
            name, self.position = _css_name(self.css, self.position)
            self.importing = name.lower() == "import"
        elif char in ";{}":
            self.importing = self.custom = False
        elif char == "(":
            self.functions.append("")
        elif char == ")" and self.functions:
            self.loading_functions -= self.functions.pop() in _CSS_IMAGE_FUNCTIONS


def _css_name_char(char: str) -> bool:
    return (char.isascii() and (char.isalnum() or char in "-_")) or not char.isascii()


def _css_valid_escape(css: str, position: int) -> bool:
    return css.startswith("\\", position) and position + 1 < len(css) and css[position + 1] != "\n"


def _css_escape(css: str, position: int) -> tuple[str, int]:
    """Decode the escape whose backslash is at *position*; return the character and the position after it."""
    digits = _CSS_HEX_RE.match(css, position + 1)
    if digits is None:
        return css[position + 1], position + 2
    end = digits.end() + (digits.end() < len(css) and css[digits.end()] in _CSS_SPACE)
    code = int(digits.group(), 16)
    return (chr(code) if 0 < code <= 0x10FFFF and not 0xD800 <= code <= 0xDFFF else "\ufffd"), end


def _css_name(css: str, position: int) -> tuple[str, int]:
    name: list[str] = []
    while position < len(css):
        if _css_name_char(css[position]):
            name.append(css[position])
            position += 1
        elif _css_valid_escape(css, position):
            char, position = _css_escape(css, position)
            name.append(char)
        else:
            break
    return "".join(name), position


def _css_string(css: str, position: int, quote: str) -> tuple[str, int]:
    value: list[str] = []
    while position < len(css) and css[position] not in (quote, "\n"):
        if css[position] != "\\":
            value.append(css[position])
            position += 1
        elif position + 1 >= len(css) or css[position + 1] == "\n":
            position += 2  # an escaped newline continues the string
        else:
            char, position = _css_escape(css, position)
            value.append(char)
    return "".join(value), position + 1


def _css_skip_blank(css: str, position: int) -> int:
    """Return the position past any whitespace and comments, which CSS allows between a property name and colon."""
    while position < len(css):
        if css[position] in _CSS_SPACE:
            position += 1
        elif css.startswith("/*", position):
            end = css.find("*/", position + 2)
            position = len(css) if end < 0 else end + 2
        else:
            break
    return position


def _css_url(css: str, position: int) -> tuple[str, int]:
    """Read an unquoted url() token's value up to ")"; a malformed one is read on, the stricter side."""
    value: list[str] = []
    while position < len(css) and css[position] != ")":
        if _css_valid_escape(css, position):
            char, position = _css_escape(css, position)
            value.append(char)
        else:
            if css[position] not in _CSS_SPACE:
                value.append(css[position])
            position += 1
    return "".join(value), position + 1


def _runs_as_script(values: dict[str, str], *, html: bool = True) -> bool:
    """Whether a script element runs, and so fetches its source: a classic or module script, not a data block.

    Only an HTML script has a language attribute.
    """
    kind = values.get("type")
    if kind is None:  # language is consulted only when type is absent; an empty type is JavaScript
        language = values.get("language", "") if html else ""
        kind = f"text/{language}" if language else ""
    kind = kind.strip(_HTML_SPACE).lower()
    return kind in ("", "module") or kind in _JAVASCRIPT_TYPES  # an exact essence match: parameters make a data block


def _tokens(value: str) -> set[str]:
    """Return an attribute's keywords, split on ASCII whitespace and matched case-insensitively."""
    return set(re.split(f"[{_HTML_SPACE}]+", value.lower()))


def _relations(values: dict[str, str]) -> set[str]:
    """Return a link's relations, its rel keywords."""
    return _tokens(values.get("rel", ""))


class _HtmlUrls(HTMLParser):
    """Collect, for one HTML document, the URLs a browser fetches on render or follows on a click."""

    def __init__(self, *, scripting: bool = True) -> None:
        super().__init__(convert_charrefs=True)
        self.scripting = scripting
        # With scripting disabled, as in a sandboxed frame without allow-scripts, noscript content is markup.
        self.raw_text_tags = _RAW_TEXT_TAGS if scripting else _RAW_TEXT_TAGS - {"noscript"}
        self.urls: list[tuple[str, bool]] = []
        self.srcdocs: list[tuple[str, bool]] = []  # each srcdoc and whether scripting is enabled in it
        self.hosts: list[str] = []  # hrefs whose hostname alone is resolved
        self.stylesheet: list[str] = []  # the text of the open HTML style block
        self.uncheckable = False  # markup this parser reads differently from a browser
        self.closing = False  # the current start tag closes itself with "/>"
        self.base: str | None = None
        self.inert: list[str] = []  # open elements whose content is never rendered
        self.open: list[tuple[str, str, str]] = []  # open elements: tag, namespace, namespace of children
        self.open_tags: Counter[str] = Counter()  # how many of each tag are open, so end tags never scan the stack
        self.namespace = "html"  # of the current element: "html", "svg" or "math"

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.inert:
            self._start_in_inert(tag)
            return
        values: dict[str, str] = {}
        for name, value in attrs:
            values.setdefault(name, value or "")  # a browser keeps the first of duplicate attributes, even empty
        in_html = (self.open[-1][2] if self.open else "html") == "html"
        if in_html and self.open_tags["select"] and tag in _SELECT_IGNORED_TAGS:
            self.uncheckable = True  # inside a select a browser ignores this start tag; the parser does not
        self._enter(tag, values)
        if "style" in values:  # inline CSS loads its images on render, in every namespace and on inert elements
            self.urls.extend((url, True) for url in _css_urls(values["style"]))
        if tag == "frameset" and self.namespace == "html":
            self.uncheckable = True  # frameset parsing ignores most tags, which this parser does not model
        shadow_root = tag == "template" and values.get("shadowrootmode", "").lower() in ("open", "closed")
        if (tag in _INERT_TAGS or tag == "plaintext") and self.namespace == "html" and not shadow_root:
            self._open_inert(tag)  # a declarative shadow root renders its content, so it is read as markup
            return
        if not (tag in _VOID_TAGS and self.namespace == "html"):
            integration = _SVG_INTEGRATION_POINTS if self.namespace == "svg" else _MATHML_INTEGRATION_POINTS
            html_annotation = (
                self.namespace == "math"
                and tag == "annotation-xml"
                and values.get("encoding", "").lower() in ("text/html", "application/xhtml+xml")
            )
            children = "html" if tag in integration or html_annotation else self.namespace
            self.open.append((tag, self.namespace, children))
            self.open_tags[tag] += 1
            self.open_tags[_SHADOW_ROOT] += (tag, self.namespace) == ("template", "html")
        if self.namespace == "math":
            return  # MathML elements fetch and follow nothing
        if self.namespace == "svg":
            loading, acting = self._svg_attributes(tag, values)
        else:
            self._html_document_effects(tag, values)
            loading = self._loading_attributes(tag, values)
            acting = _ACTION_ATTRIBUTES.get(tag, frozenset()) if self._can_act(tag, values) else frozenset()
        self._collect(values, loading, acting)
        if self.namespace == "html" and tag in self.raw_text_tags:
            self.set_cdata_mode(tag)  # after the element's own attributes, such as an iframe's src

    def _start_in_inert(self, tag: str) -> None:
        """Handle a start tag in inert content: only template content is markup, where some elements still open."""
        if self.inert[-1] != "template":
            return  # textarea and title content is raw text, where no tag opens
        if tag in _INERT_TAGS or tag == "plaintext":
            self._open_inert(tag)
        elif tag in self.raw_text_tags:
            self.set_cdata_mode(tag)
        elif tag in ("svg", "math", "select"):
            # Template content keeps namespaces and insertion modes this parser does not track.
            self.uncheckable = True

    def _svg_attributes(self, tag: str, values: dict[str, str]) -> tuple[frozenset[str], frozenset[str]]:
        """Collect url() in SVG presentation attributes; return the element's loading and acting attributes."""
        for name in values.keys() & _SVG_URL_PROPERTIES:
            self.urls.extend((url, True) for url in _css_urls(values[name], strings=False))
        self._svg_animation(tag, values)
        if "href" in values:
            values.pop("xlink:href", None)  # SVG href overrides xlink:href, even when empty
        linked = "href" in values or "xlink:href" in values  # ping needs a hyperlink destination
        acting = _SVG_ACTION_ATTRIBUTES.get(tag, frozenset()) if linked else frozenset()
        runs = tag != "script" or (self.scripting and _runs_as_script(values, html=False))
        loading = _SVG_LOADING_ATTRIBUTES.get(tag, frozenset()) if runs else frozenset()
        return loading, acting

    def _svg_animation(self, tag: str, values: dict[str, str]) -> None:
        """Collect the URLs an SVG animation sets: on an href, or on a presentation attribute that takes url()."""
        target = values.get("attributename", "").strip().lower()
        if tag not in _SVG_ANIMATIONS or not (target in ("href", "xlink:href") or target in _SVG_URL_PROPERTIES):
            return
        # Without its own href an animation targets its parent: an anchor's href is followed on a click, not
        # loaded, and a parent with no URL-taking href ignores the value. A target named by href is not resolved
        # and counts as a load.
        parent = self.open[-2][0] if len(self.open) > 1 and self.open[-2][1] == "svg" else ""
        on_parent = "href" not in values and "xlink:href" not in values
        if on_parent and target.endswith("href") and parent not in _SVG_LOADING_ATTRIBUTES and parent != "a":
            return
        loads = not (on_parent and parent == "a" and target.endswith("href"))
        animated = [values.get(name, "") for name in ("from", "to", "by")] + values.get("values", "").split(";")
        for value in animated:  # only values is a semicolon-separated list
            urls = [value.strip()] if target.endswith("href") else _css_urls(value, strings=False)
            self.urls.extend((url, loads) for url in urls if url)

    def _enter(self, tag: str, values: dict[str, str]) -> None:
        """Set the namespace of the element starting now, leaving foreign content where HTML says it ends."""
        parent = self.open[-1][2] if self.open else "html"
        breakout = tag in _FOREIGN_BREAKOUT_TAGS or (tag == "font" and values.keys() & {"color", "face", "size"})
        if parent != "html" and breakout:
            self._leave_foreign_content()
            parent = "html"
        if parent == "html" and tag in ("svg", "math"):
            self.namespace = tag
        elif parent == "math" and tag == "svg" and self.open[-1][0] == "annotation-xml":
            self.namespace = "svg"  # SVG may start directly inside annotation-xml, whatever its encoding
        elif (
            parent == "html"
            and tag in ("mglyph", "malignmark")
            and self.open[-1:]
            and self.open[-1][0] in _MATHML_INTEGRATION_POINTS
            and self.open[-1][1] == "math"
        ):
            self.namespace = "math"  # the two MathML children a text integration point keeps in MathML
        else:
            self.namespace = parent
        if tag in ("script", "style") and self.namespace != "html" and not self.closing:
            # The parser reads their content as raw text in any namespace; a browser parses it as markup
            # in SVG and MathML, so the content cannot be checked.
            self.uncheckable = True

    def _collect(self, values: dict[str, str], loading: frozenset[str], acting: frozenset[str]) -> None:
        """Record the URLs in the element's loading and acting attributes."""
        for name, value in values.items():
            # An empty link destination still navigates, to the document's base URL; an empty source loads nothing.
            if not (name in loading or name in acting) or not (value or (name == "href" and name not in loading)):
                continue
            if name == "ping":  # URLs separated by whitespace, each requested when the link is followed
                urls = [url for url in re.split(f"[{_HTML_SPACE}]+", value) if url]
            elif name in _LIST_ATTRIBUTES:
                urls = list(_srcset_urls(value))
            else:
                urls = [value]
            # A ping is a background request, not the page the user sees, so it is checked like a load.
            self.urls.extend((url, name in loading or name == "ping") for url in urls)

    @staticmethod
    def _can_act(tag: str, values: dict[str, str]) -> bool:
        """Whether the element acts: a hyperlink with href, or a control that submits its form."""
        kind = values.get("type", "").lower()  # HTML keywords match case-insensitively, never trimmed
        if tag in ("a", "area"):
            return "href" in values  # without href it is no hyperlink, so its ping is never sent
        if tag == "input":
            return kind in ("submit", "image")
        if tag == "button":
            return kind not in ("button", "reset")
        return True

    def _html_document_effects(self, tag: str, values: dict[str, str]) -> None:
        """Record what an HTML element does to the whole document: its base URL, a refresh, a srcdoc."""
        if tag == "base" and self.base is None and "href" in values and not self.open_tags[_SHADOW_ROOT]:
            # The first base with an href sets the base URL, even an empty one; one in a shadow tree is not
            # in the document tree and sets nothing.
            self.base = values["href"]
        if tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            refresh = _REFRESH_URL_RE.match(values.get("content", ""))
            destination = next((group for group in refresh.groups() if group is not None), "") if refresh else ""
            if destination:  # a delay alone reloads the document, not its base
                self.urls.append((destination, True))
        if tag == "link" and _relations(values) & _CONNECTION_HINT_RELATIONS and values.get("href"):
            self.hosts.append(values["href"])
        if tag == "iframe" and values.get("srcdoc"):
            sandboxed = "sandbox" in values and "allow-scripts" not in _tokens(values["sandbox"])
            self.srcdocs.append((values["srcdoc"], self.scripting and not sandboxed))  # sandboxing is inherited

    def _loading_attributes(self, tag: str, values: dict[str, str]) -> frozenset[str]:
        """Return the attributes this HTML element fetches on render, given its type and relation."""
        if tag == "input" and values.get("type", "").lower() == "image":
            return frozenset({"src"})
        if tag == "script" and not (self.scripting and _runs_as_script(values)):
            return frozenset()  # a data block, such as JSON-LD, or any script with scripting disabled fetches nothing
        if tag == "link":
            relations = _relations(values)
            loading = frozenset({"href"}) if relations & _FETCHING_LINK_RELATIONS else frozenset()
            if "preload" in relations and values.get("as", "").lower() == "image":
                loading |= {"imagesrcset"}
            return loading
        if tag == "iframe" and "srcdoc" in values:
            return frozenset()  # srcdoc replaces src, even when empty
        if tag == "source":  # srcset in a picture, src in audio or video; elsewhere nothing
            parent = self.open[-1][0] if self.open else ""
            if parent not in _SOURCE_PARENTS and any(self.open_tags[media] for media in _SOURCE_PARENTS):
                # Implied end tags and table parsing can make it a media element's child in the browser's tree.
                self.uncheckable |= bool(values.keys() & {"src", "srcset"})
            return {"picture": frozenset({"srcset"}), "audio": frozenset({"src"}), "video": frozenset({"src"})}.get(
                parent, frozenset()
            )
        return _LOADING_ATTRIBUTES.get(tag, frozenset())

    def unknown_decl(self, data: str) -> None:
        # A CDATA section is text in SVG and MathML, but in HTML a browser reads "<![" as a comment
        # ending at the first ">", while this parser skips to "]]>"; what follows cannot be checked.
        if self.inert or (self.open[-1][2] if self.open else "html") == "html":
            self.uncheckable = True

    def handle_endtag(self, tag: str) -> None:
        if tag in ("p", "br") and not self.inert:
            # These end tags leave foreign content even with nothing to close (HTML §13.2.6.5).
            self._leave_foreign_content()
        if self.inert:
            # Open inert elements are templates with at most one raw-text element on top, so a matching end tag
            # always closes the top one; any other end tag is text or stray, and ignored.
            if tag == self.inert[-1] and tag != "plaintext":  # nothing ends plaintext
                self.inert.pop()
        elif not self.inert and self.open_tags[tag]:
            if tag == "style":
                self._flush_stylesheet()
            closed = [self._pop()]
            while closed[-1][0] != tag:
                closed.append(self._pop())
            # Closing several elements across a namespace boundary follows HTML scope rules this parser
            # does not model (a browser may ignore the end tag), so the rest cannot be checked.
            if len(closed) > 1 and len({closed[-1][1]} | {children for _, _, children in closed}) > 1:
                self.uncheckable = True
            # Likewise a media element's end tag with elements still open inside it, which a browser may ignore,
            # leaving later <source> elements as its children.
            if len(closed) > 1 and tag in _SOURCE_PARENTS:
                self.uncheckable = True
            # And an ancestor's end tag that closes a media element or a shadow-root template across a scope
            # boundary, which a browser ignores.
            inside = {name for name, _, _ in closed[:-1]}
            if inside & _SOURCE_PARENTS and inside & _SCOPE_BOUNDARIES:
                self.uncheckable = True
            if any(element[:2] == ("template", "html") for element in closed[:-1]):
                self.uncheckable = True
            # </form> removes only the form and </body> or </html> nothing, keeping the elements inside open.
            if len(closed) > 1 and tag in ("body", "form", "html") and closed[-1][1] == "html":
                self.uncheckable = True
            # And an unlisted end tag above an open special element, which a browser ignores.
            if tag not in _LISTED_END_TAGS and any(
                name in _SPECIAL_TAGS and namespace == "html" for name, namespace, _ in closed[:-1]
            ):
                self.uncheckable = True
            # A browser in select insertion mode ignores an ancestor's end tag, so the select stays open.
            if "select" in inside:
                self.uncheckable = True

    def _open_inert(self, tag: str) -> None:
        self.inert.append(tag)
        if tag in ("textarea", "title"):
            self.set_cdata_mode(tag)  # textarea and title content is text up to the matching end tag

    def handle_comment(self, data: str) -> None:
        # A browser ends "<!-->" and "<!--->" at once and a comment at "--!>"; older Python tokenizers read on
        # to "-->", so what they took as comment may be markup.
        if data.startswith((">", "->")) or "--!>" in data:
            self.uncheckable = True

    def handle_data(self, data: str) -> None:
        self._check_raw_text(data)
        if self.cdata_elem == "style" and self.open and self.open[-1][:2] == ("style", "html"):
            self.stylesheet.append(data)  # a style block may arrive in several pieces

    def close(self) -> None:
        super().close()
        self._check_raw_text(self.rawdata)  # some Python versions keep unparsed raw text here instead
        if self.cdata_elem == "style" and self.open and self.open[-1][:2] == ("style", "html"):
            self.stylesheet.append(self.rawdata)
        self._flush_stylesheet()

    def _flush_stylesheet(self) -> None:
        self.urls.extend((url, True) for url in _css_urls("".join(self.stylesheet)))
        self.stylesheet.clear()

    def _check_raw_text(self, data: str) -> None:
        if not self.cdata_elem:
            return
        # Raw text holding an end tag a browser accepts (such as "</script/>") that this parser did not close on:
        # what follows is markup to a browser and text here, so it cannot be checked.
        if self.cdata_elem != "plaintext" and re.search(rf"(?i)</{self.cdata_elem}[{_HTML_SPACE}/>]", data):
            self.uncheckable = True
        # Some Python tokenizers read these elements as raw text in SVG and MathML too, where a browser parses
        # their content as markup.
        foreign = bool(self.open) and self.open[-1][0] == self.cdata_elem and self.open[-1][1] != "html"
        if foreign and "<" in data:
            self.uncheckable = True
        # "<!--" then "<script" in script text enters the double-escaped state, where a browser reads past the
        # next "</script>"; the parser does not.
        opener = data.find("<!--") if self.cdata_elem == "script" else -1
        if opener >= 0 and re.search(r"(?i)<script[\s/>]", data[opener:]):
            self.uncheckable = True

    def _pop(self) -> tuple[str, str, str]:
        element = self.open.pop()
        self.open_tags[element[0]] -= 1
        self.open_tags[_SHADOW_ROOT] -= element[:2] == ("template", "html")
        return element

    def _leave_foreign_content(self) -> None:
        while self.open and self.open[-1][2] != "html":
            self._pop()

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.closing = True
        self.handle_starttag(tag, attrs)
        self.closing = False
        # HTML ignores "/>" on non-void elements, so <template/> stays open; SVG and MathML honor it.
        if self.namespace != "html" and not self.inert:
            self.handle_endtag(tag)


def _web_url(url: str) -> str:
    """Read backslashes as slashes in an http(s) or network-path URL, as a browser does."""
    visible = _visible(url)
    if re.match(r"(?i)(?:https?:|[/\\]{2})", visible):
        # Any run of slashes after the scheme, or none, leads to the host, as a browser parses it.
        slashed = visible.replace("\\", "/")
        return re.sub(r"(?i)^(https?:)?/*", lambda match: (match.group(1) or "") + "//", slashed, count=1)
    return url


def _resolve(base: str, url: str) -> str:
    """Resolve *url* against a document base, leaving it as written when it cannot be resolved."""
    url = _visible(url)  # a browser trims the URL before reading its scheme or host
    if not base:
        return url
    base = _web_url(base)
    if not re.match(r"(?i)https?:|//", base):
        return url
    try:
        if not re.match(r"(?i)[a-z][a-z0-9+.-]*:", url):
            # Against an http(s) base, backslashes are slashes and a run of slashes starts a host.
            url = re.sub(r"^/{3,}", "//", url.replace("\\", "/"))
            if url.partition("#")[0] == "?":  # an explicit empty query replaces the base's; urljoin keeps it
                return base.partition("#")[0].partition("?")[0] + url
        elif _starts_host(url, base):
            url = _web_url(url)
        return urljoin(base, url)
    except ValueError:
        return url


def _starts_host(url: str, base: str) -> bool:
    """Whether an explicit http(s) URL names a host rather than a path relative to *base*.

    "https:x" and "https:/x" are relative to a base of the same scheme; two or more slashes, or a different
    scheme, start a host.
    """
    explicit = re.match(r"(?i)(https?):([/\\]*)", _visible(url))
    if explicit is None:
        return False
    return explicit.group(1).lower() != base.split(":", 1)[0].lower() or len(explicit.group(2)) >= 2


def _plain_host(netloc: str) -> bool:
    """Whether an http(s) host is one this rule parses as a browser does: an ASCII domain, IPv4 or IPv6 address.

    A slot for the model to fill counts as a label. Other forms (percent-encoded or non-ASCII names, IPv4 in hex
    or octal, IPvFuture, scoped IPv6) go through browser host parsing this rule does not reproduce.
    """
    host_port = netloc.rpartition("@")[2]
    if host_port.startswith("["):
        literal = host_port[1:].partition("]")[0]
        try:
            ipaddress.IPv6Address(literal)
        except ValueError:
            return False
        return "%" not in literal
    host = _PLACEHOLDER_URL_RE.sub("x", host_port.rpartition(":")[0] if ":" in host_port else host_port).lower()
    if not _PLAIN_HOST_RE.fullmatch(host):
        return False
    last = host.rstrip(".").rpartition(".")[2]
    return not _NUMERIC_LABEL_RE.fullmatch(last) or bool(_DOTTED_DECIMAL_RE.fullmatch(host))


def _document_base(inherited: str, declared: str | None) -> tuple[str, bool]:
    """Return a document's base URL, and whether it cannot be checked.

    A malformed, hostless, javascript: or data: base is rejected for the inherited one, as a browser does; an
    http(s) base with a host other than a plain one cannot be checked.
    """
    if not declared:
        return inherited, False
    candidate = _resolve(inherited, declared)
    try:
        parts = urlsplit(_web_url(candidate))
        _ = parts.port  # an out-of-range or non-numeric port raises only when read
    except ValueError:
        return inherited, False
    scheme = parts.scheme.lower()
    web = scheme in ("http", "https") or (not scheme and _web_url(candidate).startswith("//"))  # or a network path
    if scheme in ("javascript", "data") or (web and not parts.hostname):  # a browser rejects http:// with no host
        return inherited, False
    return candidate, web and not _plain_host(parts.netloc)


def _document_urls(
    html: str, inherited_base: str, depth: int, budget: list[int] | None = None, *, scripting: bool = True
) -> tuple[list[tuple[str, bool]], bool]:
    """Return a document's URLs resolved against its base, and whether some markup cannot be checked.

    A srcdoc document inherits its parent's base unless it sets its own. Each level's srcdoc text is
    part of its parent, so parsing is bounded by the input size times ``MAX_SRCDOC_DEPTH``. A long base
    repeats in every relative URL, so the resolved URLs share a budget of ``MAX_RENDERED_CHARS``, spent
    before each URL is built; past it the markup cannot be checked.
    """
    budget = [MAX_RENDERED_CHARS] if budget is None else budget
    parser = _HtmlUrls(scripting=scripting)
    try:
        parser.feed(bound_charrefs(html))
        parser.close()
    except ValueError:  # malformed markup the standard parser rejects
        return [], True
    base, odd_base = _document_base(inherited_base, parser.base)
    urls: list[tuple[str, bool]] = []
    for url, loads in [*parser.urls, *((href, None) for href in parser.hosts)]:
        budget[0] -= len(base) + len(url)  # a resolved URL is never longer than its base and itself
        if budget[0] < 0:
            return urls, True
        resolved = _resolve(base, url)
        if loads is not None:
            urls.append((resolved, loads))
            continue
        # A connection hint sends the hostname alone, so only it is checked.
        authority = _AUTHORITY_RE.match(_web_url(resolved))
        host = _PORT_RE.sub("", authority.group(1)) if authority else ""
        if host:
            urls.append((f"//{host}", True))
    too_deep = parser.uncheckable or odd_base
    for srcdoc, srcdoc_scripting in parser.srcdocs:
        if depth >= MAX_SRCDOC_DEPTH:
            too_deep = True
            break
        nested, nested_too_deep = _document_urls(srcdoc, base, depth + 1, budget, scripting=srcdoc_scripting)
        urls += nested
        too_deep |= nested_too_deep
    return urls, too_deep


def _rendered_chars(tokens: list[Token]) -> int:
    """Count the characters of text and attribute values the tokens render to, before HTML escaping."""
    total = 0
    for token in tokens:
        total += len(token.content) + sum(len(str(value)) for value in token.attrs.values())
        if token.children:
            total += _rendered_chars(token.children)
    return total


def _oversized(text: str) -> bool:
    # surrogatepass: a lone surrogate from a server's JSON must be measured, not raise.
    return len(text.encode("utf-8", "surrogatepass")) > MAX_LINK_MARKDOWN_BYTES


def _visible(url: str) -> str:
    """Remove what a browser's URL parser drops: every ASCII tab or newline, and leading or trailing C0 or space."""
    return re.sub("[\t\n\r]", "", url).strip(_URL_TRIMMED)


def _query(url: str) -> str:
    """Return the query the way a browser splits it: after the first ``?``, before the first ``#``."""
    return url.split("#", 1)[0].partition("?")[2]


def exfiltration_link_classes(text: str) -> list[str]:
    """Classify Markdown and HTML links that run script or carry data out of the conversation."""
    if not any(hint in text for hint in _LINK_HINTS):
        return []
    if _oversized(text):
        return ["uncheckable_markup"]
    # Render as a Markdown client would, then read the resulting HTML document. Reference links repeat
    # their destination at every use, so the rendered size is bounded before rendering.
    env: dict[str, Any] = {}
    tokens = _LINK_MARKDOWN.parse(text, env)
    if _rendered_chars(tokens) > MAX_RENDERED_CHARS:
        return ["uncheckable_markup"]
    urls, too_deep = _document_urls(_LINK_MARKDOWN.renderer.render(tokens, _LINK_MARKDOWN.options, env), "", 0)
    found: list[str] = []
    for raw, loads in urls:
        # A browser reads the scheme and authority before any percent-decoding, so "javascript%3A" is a path.
        url = _visible(raw)
        scheme = url.split(":", 1)[0].lower() if ":" in url else ""
        network_path = url.replace("\\", "/").startswith("//")
        if scheme in _SCRIPT_SCHEMES:
            found.append("script_uri")
        elif scheme == "data":
            if not _SAFE_DATA_IMAGE_RE.match(url):  # a raster image runs no script, loaded or followed
                found.append("data_uri")
        elif scheme in ("http", "https") or network_path:
            # An image loads with no click, so a slot anywhere in it sends data;
            # a link sends only what its query carries, as path slots are usually API routes.
            # A browser never sends the fragment, so a slot after a literal "#" carries nothing.
            exposed = _visible(unquote(url.split("#", 1)[0])) if loads else unquote(_query(url))
            if _PLACEHOLDER_URL_RE.search(exposed):
                found.append("exfiltration_query")
    if too_deep:
        found.append("uncheckable_markup")
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
        "Remove javascript: and data: links and URL placeholders from the listed fields. Link to fixed pages and "
        "return data in tool results, never through a URL the model fills in. Keep markup short and flat."
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


# Tool shadowing: a sentence that directs the model, about a tool the server does not list.
# Sentences end at punctuation, with any closing quotes, backticks or brackets after it, or at a blank line;
# a single line break only wraps the sentence.
_SENTENCE_BREAK_RE = re.compile(r"(?<=[.!?;:])[\x22'`\u201d\u2019)\]]*\s+|\n[ \t]*\n\s*")
_DIRECTIVE_RE = re.compile(
    r"\b(?:must|do\s+not|don['\u2019]t|should|make\s+sure|ensure|be\s+sure)\b"
    # "always"/"never" direct only opening a clause ("Never use …", "…, then always call …"); after a subject
    # or auxiliary ("the tool always returns", "has never been") they describe.
    r"|(?:^|[,;:(\u2014\u201d\x22]|\b(?:and|or|then|but|so|please))[^\w\n]{0,4}(?:always|never)\b"
    r"|\b(?:first|instead),?\s+(?:call|use|invoke|run)\b"
    r"|^[^\w\n]*(?:when|whenever|before|after|instead\s+of|if|call|use|invoke|send|prefer|always|never)\b",
    re.IGNORECASE | re.MULTILINE,
)
_ANY_TOOL_RE = re.compile(
    r"\b(?:use|using|call|calling|invoke|invoking|run|running|with)\s+"
    r"(?:any|every|all|other|another)(?:\s+other)?\s+(?:mcp\s+)?(?:tools?|servers?)\b",
    re.IGNORECASE,
)
# A whole identifier is captured as one token and its shape checked in code (see _code_shaped).
_TOOL_NAME = r"`(?P<ticked>[^`\s]{1,128})`|(?P<bare>[\w./-]+)"
_TOOL_REFERENCES = (
    re.compile(rf"\b(?i:call|calling|invoke|invoking)\s+(?i:the\s+)?(?:{_TOOL_NAME})"),
    re.compile(rf"(?<![\w`./-])(?:{_TOOL_NAME})\s+(?i:tool)\b"),
)
_NAME_JOINERS_RE = re.compile(r"[_./]+")
# MCP methods (2025-11-25 and 2026-07-28, with the Skills and Tasks extensions) are protocol, not tools.
_PROTOCOL_METHODS = frozenset(
    {
        "initialize",
        "ping",
        "server/discover",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "resources/subscribe",
        "resources/unsubscribe",
        "prompts/list",
        "prompts/get",
        "completion/complete",
        "logging/setLevel",
        "sampling/createMessage",
        "roots/list",
        "elicitation/create",
        "skills/list",
        "skills/get",
        "resources/directory/read",
        "tasks/get",
        "tasks/list",
        "tasks/result",
        "tasks/cancel",
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/message",
        "notifications/resources/updated",
        "notifications/resources/list_changed",
        "notifications/tools/list_changed",
        "notifications/prompts/list_changed",
        "notifications/roots/list_changed",
        "notifications/elicitation/complete",
        "notifications/tasks/status",
    }
)
_CAMEL_RE = re.compile(r"[a-z]+(?:[A-Z][a-z0-9]*)+")
_SEPARATORS_RE = re.compile(r"[-._/]+")
# Namespaces a client puts in front of a tool name: mcp__notes__search, notes.search, notes/search.
_NAMESPACE_RE = re.compile(r"__|[./]")
_MAX_NAMESPACES = 3
_QUOTE_PAIRS_DOUBLE = (('"', '"'), ("\u201c", "\u201d"))


class _ForwardFind:
    """Finds a character at or after ever-growing positions, scanning each part of the text once."""

    def __init__(self, text: str, char: str) -> None:
        super().__init__()
        self._text = text
        self._char = char
        self._found = -2  # position of the last hit; -1 once there is none left

    def at_or_after(self, position: int) -> int:
        """Return the first index of the character at or after *position*, or -1."""
        if self._found != -1 and self._found < position:
            self._found = self._text.find(self._char, position)
        return self._found


@dataclass(frozen=True)
class _QuotedSpans:
    """The double-quoted spans of one string, found once and looked up by position."""

    starts: list[int]
    ends: list[int]

    @classmethod
    def of(cls, text: str) -> "_QuotedSpans":
        """Find the quoted spans of *text*, leftmost first, in one forward pass."""
        finders = [_ForwardFind(text, opener) for opener, _ in _QUOTE_PAIRS_DOUBLE]
        closers = [_ForwardFind(text, closer) for _, closer in _QUOTE_PAIRS_DOUBLE]
        starts: list[int] = []
        ends: list[int] = []
        position = 0
        while True:
            spans = []
            for finder, closer in zip(finders, closers, strict=True):
                start = finder.at_or_after(position)
                end = closer.at_or_after(start + 1) if start >= 0 else -1
                if end >= 0:
                    spans.append((start, end + 1))
            if not spans:
                return cls(starts, ends)
            start, end = min(spans)
            starts.append(start)
            ends.append(end)
            position = end

    def contains(self, start: int, end: int) -> bool:
        """Whether *start*..*end* lies strictly inside one quoted span (spans never overlap)."""
        index = bisect_left(self.starts, start) - 1
        return index >= 0 and end < self.ends[index]


def _sentences(text: str, quoted: _QuotedSpans) -> Iterator[tuple[int, str]]:
    """Yield each sentence of *text* with its offset, keeping a quoted span whole so a quoted example stays one."""
    start = 0
    for brk in _SENTENCE_BREAK_RE.finditer(text):
        # Judged at the whitespace: 'say "OK." Then' ends a sentence, '"call x. Never y"' stays one example.
        space = brk.end() - 1
        if not quoted.contains(space, space):
            yield start, text[start : brk.start()]
            start = brk.end()
    yield start, text[start:]


def _code_shaped(token: str) -> str | None:
    """Return *token* as a tool name when it is code-shaped, else None.

    Code-shaped: joined with ``_``, ``.`` or ``/`` (``send_email``, ``mail/send``), or camelCase (``getWeather``),
    with at least one letter. Plain words, hyphen-only words ("read-only") and numbers ("2.0") are prose.
    """
    name = token.rstrip("./-")
    if not any(char.isascii() and char.isalpha() for char in name):
        return None
    if _NAME_JOINERS_RE.search(name):
        parts = _NAME_JOINERS_RE.split(name.strip("_"))
        return name if all(part and part[0].isalnum() and part.isascii() for part in parts) else None
    words = name.split("-")
    if all(word.isascii() and word.isalnum() for word in words) and any(_CAMEL_RE.fullmatch(w) for w in words):
        return name
    return None


def _name_key(name: str) -> str:
    """Fold case and separators, so ``ads.campaign.refresh`` and ``ads/campaign__refresh`` compare equal."""
    return _SEPARATORS_RE.sub("_", name.casefold())


def _is_listed(name: str, listed: frozenset[str]) -> bool:
    """Whether *name* is a listed name, alone or behind up to three client namespaces (``mcp__server__search``)."""
    parts = _NAMESPACE_RE.split(name)
    return any(_name_key("_".join(parts[start:])) in listed for start in range(min(len(parts), _MAX_NAMESPACES + 1)))


def _unlisted(match: re.Match[str], listed: frozenset[str]) -> bool:
    """Whether *match* names a tool, in backticks or code-shaped, that is not among the *listed* names."""
    raw = match["ticked"] or match["bare"].rstrip(".")
    if raw in _PROTOCOL_METHODS:
        return False
    if match["ticked"]:
        return not _is_listed(match["ticked"], listed)
    if _is_listed(match["bare"], listed):
        return False
    name = _code_shaped(match["bare"])
    return name is not None and not _is_listed(name, listed)


def cross_tool_classes(text: str, listed: frozenset[str] | None = None) -> list[str]:
    """Return the cross-tool directive classes in *text*.

    ``any_tool_directive``: a directive about any or other tools or servers. ``unlisted_tool_directive``: a
    directive naming a tool that is not in *listed* (the names the server lists); with *listed* None
    the catalog is unknown and only the first class is judged. *listed* holds :func:`_name_key` forms.
    A phrase in double quotes or named as an attempt (``attempts to call x``) is a mention, not a directive.
    """
    quoted = _QuotedSpans.of(text)
    found: list[str] = []
    for offset, sentence in _sentences(text, quoted):
        # A cue counts only outside quotes: its last character is checked, since an opener may start with punctuation.
        if not any(
            not quoted.contains(offset + cue.end() - 1, offset + cue.end() - 1)
            for cue in _DIRECTIVE_RE.finditer(sentence)
        ):
            continue

        def directs(match: re.Match[str], sentence: str = sentence, offset: int = offset) -> bool:
            start, end = match.start(), match.end()
            return not (_is_mention(sentence, start, end) or quoted.contains(offset + start, offset + end))

        if any(directs(match) for match in _ANY_TOOL_RE.finditer(sentence)):
            found.append("any_tool_directive")
        if listed is not None:
            found.extend(
                "unlisted_tool_directive"
                for pattern in _TOOL_REFERENCES
                for match in pattern.finditer(sentence)
                if directs(match) and _unlisted(match, listed)
            )
    return found


_DECLARED_LISTINGS = (("prompts", "prompts"), ("resources", "resources"), ("resource_templates", "resources"))


def _declares(audit_data: AuditData, capability: str) -> bool:
    """Whether the audited lifecycle declares *capability*: the session's, or ``server/discover``'s without one."""
    return getattr(audit_data.capabilities, capability, None) is not None


def _stateless_page_whole(audit_data: AuditData) -> bool:
    """Whether the stateless ``tools/list`` page is the whole catalog (SEP-2322 ``resultType``, no next cursor)."""
    probe = (audit_data.probes or {}).get(PROBE_STATELESS_LIST)
    page = probe.payload if probe is not None and isinstance(probe.payload, dict) else {}
    return page.get("resultType") == "complete" and page.get("nextCursor") is None


def _listed_names(audit_data: AuditData) -> frozenset[str] | None:
    """Return the names the server lists, folded by :func:`_name_key`, or None when they were not all seen.

    Every listing must have come back whole: a declared catalog that was never listed, or one that pagination
    left incomplete, may hold the very name a description points at. Without a session the tools come from one
    stateless page, which must say it is whole; tools recovered after the session listing failed leave the
    session's names unknown.
    """
    if audit_data.tools is None or any(listing in audit_data.incomplete_listings for listing in _LISTINGS):
        return None
    if any(getattr(audit_data, listing) is None and _declares(audit_data, cap) for listing, cap in _DECLARED_LISTINGS):
        return None
    # Tools recovered from the stateless lifecycle replaced a failed session listing: the session's own text may
    # name the tools it served, which are no longer known.
    if "tools" in audit_data.catalog_versions:
        return None
    if audit_data.session_protocol_version is None and not _stateless_page_whole(audit_data):
        return None
    items = [*audit_data.tools, *(audit_data.prompts or []), *(audit_data.resources or [])]
    items += audit_data.resource_templates or []
    return frozenset(_name_key(item.name) for item in items if item.name)


@register_rule
class CatalogCrossToolDirectivesRule(CatalogSecurityRule):
    """High check: catalog text does not direct the model's use of tools the server does not list.

    Every connected server shares the model's context, so a description can steer how the agent uses
    another server's tools without the describing tool ever running (tool shadowing). Directions about the
    server's own tools are ordinary workflow guidance and pass; a sentence counts only when it directs.

    Scoring: 3 points (HIGH)
    """

    rule_id = "catalog_cross_tool_directives"
    basis = (
        "OWASP MCP Top 10 (beta) MCP03:2025 Tool Poisoning; MCP Local Server Security (a poisoned tool catalog, "
        "tool shadowing); MCP 2025-11-25 §Security and Trust & Safety (Tool Safety: tool descriptions are untrusted)"
    )
    rule_order = 24
    issue_reason = "cross_tool_directive"
    expected = "directions that name only this server's own tools"
    passed_message = "Catalog text directs no tools outside this server"
    failure_label = "catalog strings directing tools outside this server"
    fix = (
        "Rewrite the listed fields so they direct only this server's own tools. Describe how other tools are "
        "used in your documentation, not in text the model reads."
    )

    @property
    def rule_name(self) -> str:
        return "No Directions for Other Tools in Catalog Text"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def matches(self, text: str) -> list[str]:
        """Return the cross-tool directive classes found in *text*, without knowing the server's catalog."""
        return cross_tool_classes(text)

    def text_matcher(self, audit_data: AuditData) -> Callable[[str], list[str]]:
        """Judge each string against the names this server lists."""
        listed = _listed_names(audit_data)
        return lambda text: cross_tool_classes(text, listed)
