"""MCP audit rules package.

This package contains the rule system for MCP server auditing:

- BaseRule: Abstract base class for all audit rules
- RuleResult: Container for rule execution results
- RuleSeverity: Severity levels for rule classification
- AuditData: Container for server data used in audits
- RuleRegistry: Registry for managing and creating rules
- Specific rule implementations for protocol version and server info checks

The rule system is designed to be extensible, allowing easy addition of new
audit checks by implementing the BaseRule interface.
"""

from .base import (
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)
from .capabilities import (
    CapabilityLoggingPresentRule,
    CapabilityPromptsListChangedRule,
    CapabilityPromptsPresentRule,
    CapabilityResourcesListChangedRule,
    CapabilityResourcesPresentRule,
    CapabilityResourcesSubscribeRule,
    CapabilityToolsListChangedRule,
)
from .protocol_version import (
    AllowedVersionRule,
    DeprecatedVersionRule,
    LatestVersionRule,
)
from .registry import RuleRegistry, create_all_rules
from .security import (
    ErrorDataLeakRule,
    MalformedRequestHandlingRule,
    TLSEnabledRule,
)
from .server_info import (
    ServerNamePresentRule,
    ServerTitlePresentRule,
    ServerVersionPresentRule,
)
from .tools import (
    ToolsAtLeastOneRule,
    ToolsDescriptionPresentRule,
    ToolsInputSchemaValidRule,
    ToolsNamePresentRule,
    ToolsOutputSchemaValidRule,
    ToolsTitlePresentRule,
)
from .transport import (
    SSETransportSupportRule,
)

__all__ = (
    "AllowedVersionRule",
    "AuditData",
    "BaseRule",
    "CapabilityLoggingPresentRule",
    "CapabilityPromptsListChangedRule",
    "CapabilityPromptsPresentRule",
    "CapabilityResourcesListChangedRule",
    "CapabilityResourcesPresentRule",
    "CapabilityResourcesSubscribeRule",
    "CapabilityToolsListChangedRule",
    "DeprecatedVersionRule",
    "ErrorDataLeakRule",
    "LatestVersionRule",
    "MalformedRequestHandlingRule",
    "RuleRegistry",
    "RuleResult",
    "RuleSeverity",
    "SSETransportSupportRule",
    "ServerNamePresentRule",
    "ServerTitlePresentRule",
    "ServerVersionPresentRule",
    "TLSEnabledRule",
    "ToolsAtLeastOneRule",
    "ToolsDescriptionPresentRule",
    "ToolsInputSchemaValidRule",
    "ToolsNamePresentRule",
    "ToolsOutputSchemaValidRule",
    "ToolsTitlePresentRule",
    "create_all_rules",
)
