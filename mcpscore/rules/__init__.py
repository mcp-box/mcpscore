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

from .auth import (
    AuthAuthorizationServersHttpsRule,
    AuthProtectedResourceMetadataRule,
    AuthWwwAuthenticateRule,
)
from .base import (
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
    SkippedRule,
)
from .capabilities import (
    CapabilityLoggingPresentRule,
    CapabilityPromptsListChangedRule,
    CapabilityPromptsPresentRule,
    CapabilityResourcesListChangedRule,
    CapabilityResourcesPresentRule,
    CapabilityResourcesSubscribeRule,
    CapabilityToolsListChangedRule,
    CapabilityToolsPresentRule,
)
from .prompts import (
    PromptsArgumentsDocumentedRule,
    PromptsDescriptionPresentRule,
)
from .protocol_version import (
    AllowedVersionRule,
    DeprecatedVersionRule,
    LatestVersionRule,
)
from .readiness import (
    CacheMetadataReadinessRule,
    DeprecatedFeaturesReadinessRule,
    ErrorCodeMigrationReadinessRule,
    HeaderValidationReadinessRule,
    MetaValidationReadinessRule,
    NoSessionIdReadinessRule,
    RemovedMethodsReadinessRule,
    ResultTypeReadinessRule,
    ServerDiscoverReadinessRule,
    StatelessRequestReadinessRule,
    ToolSchemaDialectReadinessRule,
    UnsupportedVersionErrorReadinessRule,
)
from .registry import RuleRegistry, create_all_rules
from .resources import (
    ResourcesDescriptionPresentRule,
)
from .security import (
    ErrorDataLeakRule,
    MalformedRequestHandlingRule,
    TLSEnabledRule,
)
from .server_info import (
    ServerIconsPresentRule,
    ServerInstructionsPresentRule,
    ServerNamePresentRule,
    ServerTitlePresentRule,
    ServerVersionPresentRule,
    ServerWebsiteUrlPresentRule,
)
from .tools import (
    ToolsAnnotationsPresentRule,
    ToolsAtLeastOneRule,
    ToolsDescriptionPresentRule,
    ToolsExecutionConsistentRule,
    ToolsInputSchemaValidRule,
    ToolsNamePresentRule,
    ToolsNamesUniqueRule,
    ToolsNamesValidFormatRule,
    ToolsOutputSchemaValidRule,
    ToolsTitlePresentRule,
)
from .transport import (
    StreamableHTTPTransportRule,
)

__all__ = (
    "AllowedVersionRule",
    "AuditData",
    "AuthAuthorizationServersHttpsRule",
    "AuthProtectedResourceMetadataRule",
    "AuthWwwAuthenticateRule",
    "BaseRule",
    "CacheMetadataReadinessRule",
    "CapabilityLoggingPresentRule",
    "CapabilityPromptsListChangedRule",
    "CapabilityPromptsPresentRule",
    "CapabilityResourcesListChangedRule",
    "CapabilityResourcesPresentRule",
    "CapabilityResourcesSubscribeRule",
    "CapabilityToolsListChangedRule",
    "CapabilityToolsPresentRule",
    "DeprecatedFeaturesReadinessRule",
    "DeprecatedVersionRule",
    "ErrorCodeMigrationReadinessRule",
    "ErrorDataLeakRule",
    "HeaderValidationReadinessRule",
    "LatestVersionRule",
    "MalformedRequestHandlingRule",
    "MetaValidationReadinessRule",
    "NoSessionIdReadinessRule",
    "PromptsArgumentsDocumentedRule",
    "PromptsDescriptionPresentRule",
    "RemovedMethodsReadinessRule",
    "ResourcesDescriptionPresentRule",
    "ResultTypeReadinessRule",
    "RuleRegistry",
    "RuleResult",
    "RuleSeverity",
    "ServerDiscoverReadinessRule",
    "ServerIconsPresentRule",
    "ServerInstructionsPresentRule",
    "ServerNamePresentRule",
    "ServerTitlePresentRule",
    "ServerVersionPresentRule",
    "ServerWebsiteUrlPresentRule",
    "SkippedRule",
    "StatelessRequestReadinessRule",
    "StreamableHTTPTransportRule",
    "TLSEnabledRule",
    "ToolSchemaDialectReadinessRule",
    "ToolsAnnotationsPresentRule",
    "ToolsAtLeastOneRule",
    "ToolsDescriptionPresentRule",
    "ToolsExecutionConsistentRule",
    "ToolsInputSchemaValidRule",
    "ToolsNamePresentRule",
    "ToolsNamesUniqueRule",
    "ToolsNamesValidFormatRule",
    "ToolsOutputSchemaValidRule",
    "ToolsTitlePresentRule",
    "UnsupportedVersionErrorReadinessRule",
    "create_all_rules",
)
