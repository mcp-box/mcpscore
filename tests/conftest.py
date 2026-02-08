import dataclasses
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

import pytest


@dataclass
class FakeToolsCaps:
    listChanged: bool = False  # noqa: N815


@dataclass
class FakePromptsCaps:
    listChanged: bool = False  # noqa: N815


@dataclass
class FakeResourcesCaps:
    listChanged: bool = False  # noqa: N815
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


@dataclass
class FakeImplementation:
    name: str | None = None
    title: str | None = None
    version: str | None = None


@pytest.fixture
def capabilities_full() -> FakeServerCapabilities:
    return FakeServerCapabilities(
        tools=FakeToolsCaps(listChanged=True),
        prompts=FakePromptsCaps(listChanged=True),
        resources=FakeResourcesCaps(listChanged=True, subscribe=True),
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
