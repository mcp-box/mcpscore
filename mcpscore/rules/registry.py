from collections.abc import Iterable
from typing import Any

from .base import BaseRule
from .retired import RETIRED_RULES

_RETIRED_IDS = frozenset(retired.rule_id for retired in RETIRED_RULES)


class RuleRegistry:
    """Registry for managing and creating MCP audit rules.

    This registry maintains a collection of all available audit rule classes,
    allowing for dynamic rule creation and management. It ensures rule IDs
    are unique and provides methods to create individual rules or all rules at once.
    """

    def __init__(self) -> None:
        """Initialize an empty rule registry."""
        super().__init__()
        self._types: dict[str, type[BaseRule]] = {}

    def register_type(self, cls: type[BaseRule]) -> None:
        """Register a new rule class in the registry.

        Args:
            cls: Rule class to register (must subclass BaseRule and define a
                non-empty ``rule_id`` of its own)

        Raises:
            TypeError: If the class doesn't subclass BaseRule, or leaves
                ``rule_id`` empty (``BaseRule`` defaults it to ``""``, so a
                bare ``hasattr`` check can never fail — the check must be for
                a non-empty value on the concrete class).
            ValueError: If rule_id is already registered, or was retired —
                retired ids are never reused (see ``rules/retired.py``).

        """
        if not issubclass(cls, BaseRule):
            raise TypeError(f"{cls.__name__} must subclass BaseRule")
        if not cls.rule_id:
            raise TypeError(f"{cls.__name__} must define a non-empty `rule_id`")

        if cls.rule_id in _RETIRED_IDS:
            raise ValueError(
                f"rule_id {cls.rule_id!r} is retired and can never be reused (see rules/retired.py); "
                "a rule that means something different must take a new id"
            )
        if cls.rule_id in self._types:
            raise ValueError(f"Duplicate rule_id: {cls.rule_id}")
        self._types[cls.rule_id] = cls

    def create_rule(self, rule_id: str, **kwargs: Any) -> BaseRule:
        """Create a specific rule instance by ID.

        Args:
            rule_id: Unique identifier of the rule to create
            **kwargs: Additional arguments to pass to the rule constructor

        Returns:
            New instance of the requested rule

        Raises:
            KeyError: If rule_id is not found in the registry

        """
        cls = self._types[rule_id]
        return cls(**kwargs)

    def create_all_rules(self, **kwargs: Any) -> Iterable[BaseRule]:
        """Create instances of all registered rules.

        Args:
            **kwargs: Additional arguments to pass to each rule constructor

        Yields:
            New instances of all registered rule classes

        """
        types = list(self._types.values())
        for cls in types:
            yield cls(**kwargs)


_registry = RuleRegistry()


def register_rule(cls: type[BaseRule]) -> type[BaseRule]:
    """Register a rule class automatically.

    Args:
        cls: Rule class to register

    Returns:
        The same class (for use as a decorator)

    Example:
        @register_rule
        class MyCustomRule(BaseRule):
            rule_id = "my_custom_rule"
            # ... implementation

    """
    _registry.register_type(cls)
    return cls


def create_all_rules(**kwargs: Any) -> Iterable[BaseRule]:
    """Create instances of all registered rules.

    Args:
        **kwargs: Additional arguments to pass to each rule constructor

    Returns:
        Iterable of all registered rule instances

    """
    return _registry.create_all_rules(**kwargs)


def all_rule_ids() -> tuple[str, ...]:
    """Return every registered rule_id, in registration order.

    The public view of the registry's keys, for callers that validate
    rule_ids without instantiating rules (the per-project configuration).
    """
    return tuple(_registry._types)
