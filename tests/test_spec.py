from datetime import date

from mcpscore import spec
from mcpscore.enums import MCPProtocolVersion
from mcpscore.spec import Lifecycle, SpecStatus


def test_versions_are_ordered_oldest_to_newest():
    """The registry tuple must stay in chronological order."""
    versions = [v.version for v in spec.SPEC_VERSIONS]
    assert versions == sorted(versions)


def test_version_identifiers_match_release_dates():
    """The wire identifier of every entry must equal its release date."""
    for v in spec.SPEC_VERSIONS:
        assert v.version == v.release_date.isoformat()


def test_exactly_one_current_version():
    """Exactly one revision carries CURRENT status at any time."""
    current = [v for v in spec.SPEC_VERSIONS if v.status is SpecStatus.CURRENT]
    assert len(current) == 1
    assert current[0] is spec.LATEST


def test_latest_is_2025_11_25():
    assert spec.LATEST.version == "2025-11-25"
    assert spec.LATEST.lifecycle is Lifecycle.STATEFUL


def test_draft_is_2026_07_28_stateless():
    assert spec.DRAFT is not None
    assert spec.DRAFT.version == "2026-07-28"
    assert spec.DRAFT.lifecycle is Lifecycle.STATELESS
    assert spec.DRAFT.status is SpecStatus.DRAFT


def test_allowed_versions_match_public_enum():
    """The enum re-export and the registry must agree on allowed versions."""
    assert spec.allowed_versions() == [v.value for v in MCPProtocolVersion]


def test_allowed_versions_exclude_drafts():
    assert spec.DRAFT is not None
    assert spec.DRAFT.version not in spec.allowed_versions()


def test_no_deprecated_versions_today():
    """The spec deprecates features, not versions — keep this empty until it does."""
    assert spec.deprecated_versions() == []


def test_get_known_and_unknown_versions():
    entry = spec.get("2025-11-25")
    assert entry is not None
    assert entry.release_date == date(2025, 11, 25)
    assert spec.get("1900-01-01") is None


def test_compare_orders_chronologically():
    assert spec.compare("2024-11-05", "2025-11-25") == -1
    assert spec.compare("2026-07-28", "2025-11-25") == 1
    assert spec.compare("2025-06-18", "2025-06-18") == 0


def test_deprecated_features_are_cumulative():
    """Each revision carries forward the deprecations of the one before it.

    Deprecated features stay deprecated (until removed entirely, at which
    point the removal is a lifecycle change, not an un-deprecation).
    """
    for older, newer in zip(spec.SPEC_VERSIONS, spec.SPEC_VERSIONS[1:], strict=False):
        assert older.deprecated_features <= newer.deprecated_features


def test_2026_deprecates_legacy_primitives():
    draft = spec.get("2026-07-28")
    assert draft is not None
    assert {"roots", "sampling", "logging", "dynamic-client-registration"} <= draft.deprecated_features


def test_required_headers_by_version():
    """MCP-Protocol-Version arrives in 2025-06-18; Mcp-Method in 2026-07-28."""
    assert spec.get("2025-03-26").required_request_headers == frozenset()  # type: ignore[union-attr]
    assert spec.get("2025-06-18").required_request_headers == {"MCP-Protocol-Version"}  # type: ignore[union-attr]
    assert spec.get("2026-07-28").required_request_headers == {"MCP-Protocol-Version", "Mcp-Method"}  # type: ignore[union-attr]


def test_schema_dialect_defined_only_from_2026():
    """Dialect defaulting is a 2026-07-28 addition (SEP-2106)."""
    for v in spec.SPEC_VERSIONS:
        if spec.compare(v.version, "2026-07-28") < 0:
            assert v.tool_schema_default_dialect is None
        else:
            assert v.tool_schema_default_dialect == "2020-12"
