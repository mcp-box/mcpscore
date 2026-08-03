"""Shared behavior tests for catalog icon validation rules."""

from collections.abc import Callable

from mcp_types import Icon, Prompt, Resource, ResourceTemplate, Tool
import pytest

from mcpscore.rules import (
    PromptsIconsValidRule,
    ResourcesIconsValidRule,
    ResourceTemplatesIconsValidRule,
    RuleSeverity,
    ToolsIconsValidRule,
)
from mcpscore.rules.base import AuditData, BaseRule

Case = tuple[BaseRule, str, Callable[[list[Icon] | None], AuditData]]


def _resource(icons: list[Icon] | None) -> AuditData:
    return AuditData(resources=[Resource(name="docs", uri="https://example.com/docs", icons=icons)])


def _prompt(icons: list[Icon] | None) -> AuditData:
    return AuditData(prompts=[Prompt(name="summarize", icons=icons)])


def _tool(icons: list[Icon] | None) -> AuditData:
    return AuditData(tools=[Tool(name="search", input_schema={"type": "object"}, icons=icons)])


def _template(icons: list[Icon] | None) -> AuditData:
    return AuditData(resource_templates=[ResourceTemplate(name="files", uri_template="file:///{path}", icons=icons)])


CASES: tuple[Case, ...] = (
    (ResourcesIconsValidRule(), "resources_icons_valid", _resource),
    (PromptsIconsValidRule(), "prompts_icons_valid", _prompt),
    (ToolsIconsValidRule(), "tools_icons_valid", _tool),
    (ResourceTemplatesIconsValidRule(), "resource_templates_icons_valid", _template),
)


@pytest.mark.parametrize(("rule", "rule_id", "make_data"), CASES)
def test_icon_rule_metadata_and_absent_icons_pass(
    rule: BaseRule, rule_id: str, make_data: Callable[[list[Icon] | None], AuditData]
) -> None:
    assert rule.rule_id == rule_id
    assert rule.severity is RuleSeverity.LOW
    assert rule.min_spec_version == "2025-11-25"
    assert rule.check(make_data(None)).passed


@pytest.mark.parametrize(("rule", "_rule_id", "make_data"), CASES)
def test_valid_catalog_icons_pass(
    rule: BaseRule, _rule_id: str, make_data: Callable[[list[Icon] | None], AuditData]
) -> None:
    icons = [
        Icon(src="https://example.com/icon.png", mime_type="image/png", sizes=["48x48", "any"], theme="light"),
        Icon(src="http://example.com/icon.svg", mime_type='image/svg+xml; charset="utf-8"'),
        Icon(src="data:image/png;base64,AAAA"),
        Icon(src="data:image/svg+xml;charset=utf-8;base64,PHN2Zy8+"),
        Icon(src="DATA:IMAGE/PNG;BASE64,AAAA"),
        # Schemes beyond http(s)/data are deliberately allowed: the spec's
        # "May be an HTTP/HTTPS URL or a data: URI" is exemplary, not
        # exhaustive — this case pins the leniency.
        Icon(src="file:///opt/icons/tool.png"),
    ]

    assert rule.check(make_data(icons)).passed


@pytest.mark.parametrize(("rule", "_rule_id", "make_data"), CASES)
def test_invalid_catalog_icon_fields_are_reported_without_payloads(
    rule: BaseRule, _rule_id: str, make_data: Callable[[list[Icon] | None], AuditData]
) -> None:
    oversized_src = "relative/" + "x" * 10_000
    invalid_icon = Icon(
        src=oversized_src,
        mime_type="not a mime type",
        sizes=["48", "0x32", "ANY"],
    )
    result = rule.check(make_data([invalid_icon]))

    assert not result.passed
    assert result.details is not None
    assert len(result.details["invalid_icons"]) == 1
    invalid_detail = result.details["invalid_icons"][0]
    assert invalid_detail["icon_index"] == 0
    assert invalid_detail["invalid_fields"] == ["src", "mimeType", "sizes"]
    assert oversized_src not in repr(result.details)


@pytest.mark.parametrize(
    "src",
    [
        "",  # empty
        "https://example.com/a b.png",  # embedded whitespace
        "http://[::1",  # urlsplit raises ValueError (invalid IPv6 literal)
        "example.com/icon.png",  # no scheme
        "1http://example.com",  # scheme must start with a letter
        "https://",  # HTTP(S) icons require a host
        "https://example.com:bad/icon.png",  # invalid port
        "https://example.com/%ZZ",  # malformed percent escape
        "https://example.com/é.png",  # a URI cannot contain raw non-ASCII
        "data:",  # data icons must contain an image payload
        "data:image/png,not-base64",  # data icons must use base64 encoding
        "data:image/png;base64,not_base64",  # invalid base64 alphabet
        "data:image/png;base64,A",  # regex-valid alphabet, invalid base64 length
        "data:text/plain;base64,AAAA",  # icon data must be an image
    ],
)
def test_invalid_src_variants_are_rejected(src: str) -> None:
    """Reject every malformed-src shape via invalid_fields.

    Includes the urlsplit ValueError path (invalid IPv6 literal), which must
    classify as invalid rather than crash.
    """
    result = ToolsIconsValidRule().check(_tool([Icon(src=src)]))
    assert not result.passed
    assert result.details is not None
    assert result.details["invalid_icons"][0]["invalid_fields"] == ["src"]
