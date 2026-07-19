import dataclasses
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import pytest


@dataclass
class FakeToolsCaps:
    list_changed: bool = False


@dataclass
class FakePromptsCaps:
    list_changed: bool = False


@dataclass
class FakeResourcesCaps:
    list_changed: bool = False
    subscribe: bool = False


@dataclass
class FakeLoggingCaps:
    enabled: bool = True


@dataclass
class FakeServerCapabilities:
    tools: FakeToolsCaps | None = None
    prompts: FakePromptsCaps | None = None
    resources: FakeResourcesCaps | None = None
    logging: FakeLoggingCaps | None = None
    tasks: Any | None = None


@dataclass
class FakeImplementation:
    name: str | None = None
    title: str | None = None
    version: str | None = None
    website_url: str | None = None
    icons: list[Any] | None = None


@pytest.fixture
def capabilities_full() -> FakeServerCapabilities:
    return FakeServerCapabilities(
        tools=FakeToolsCaps(list_changed=True),
        prompts=FakePromptsCaps(list_changed=True),
        resources=FakeResourcesCaps(list_changed=True, subscribe=True),
        logging=FakeLoggingCaps(enabled=True),
    )


@pytest.fixture
def capabilities_missing() -> FakeServerCapabilities:
    return FakeServerCapabilities()


@pytest.fixture
def implementation_full() -> FakeImplementation:
    return FakeImplementation(name="server", title="Server Title", version="1.0.0")


@pytest.fixture
def implementation_missing() -> FakeImplementation:
    return FakeImplementation()


def as_dict(obj: Any) -> dict[str, Any] | dict | MappingProxyType[str, Any] | dict[Any, Any]:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return dataclasses.asdict(obj)

    # If it's not a dataclass, assume it's already a dict-like object
    if isinstance(obj, dict):
        return obj

    # For other objects, try to convert their attributes to a dict
    if hasattr(obj, "__dict__"):
        return obj.__dict__

    # Fallback for edge cases
    return {}


@pytest.fixture(autouse=True)
def _no_network_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep unit tests hermetic: stub the auditor's sessionless probe runner.

    audit() probes the target URL over HTTP; unit tests must never hit the
    network. Probe behavior itself is tested in test_probes.py with a
    MockTransport-backed client, and tests that need a different auditor-level
    stub re-patch mcp_auditor.run_all_probes themselves.
    """
    from mcpscore import mcp_auditor
    from mcpscore.probes import not_applicable_results

    async def stubbed_run_all_probes(url: str, client: Any = None) -> dict:
        return not_applicable_results(reason="stubbed in unit tests")

    monkeypatch.setattr(mcp_auditor, "run_all_probes", stubbed_run_all_probes)
