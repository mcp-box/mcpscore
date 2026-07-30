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
    AuthChallengeReferencesMetadataRule,
    AuthMetadataHttpsRule,
    AuthProtectedResourceMetadataRule,
    AuthScopesAdvertisedRule,
    AuthServerMetadataPresentRule,
    AuthServerPkceRule,
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
    CapabilityPromptsListChangedRule,
    CapabilityPromptsPresentRule,
    CapabilityResourcesListChangedRule,
    CapabilityResourcesPresentRule,
    CapabilityToolsListChangedRule,
    CapabilityToolsPresentRule,
)
from .prompts import (
    PromptsArgumentNamesPresentRule,
    PromptsArgumentNamesUniqueRule,
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
    ResourcesAnnotationsValidRule,
    ResourcesDescriptionPresentRule,
    ResourcesMimeTypesValidRule,
    ResourcesNamesPresentRule,
    ResourcesSizesValidRule,
    ResourcesUrisValidRule,
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
    ToolsMcpHeadersPrimitiveTypesRule,
    ToolsMcpHeadersStaticallyReachableRule,
    ToolsMcpHeadersUniqueRule,
    ToolsMcpHeadersValidNamesRule,
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
    "AuthChallengeReferencesMetadataRule",
    "AuthMetadataHttpsRule",
    "AuthProtectedResourceMetadataRule",
    "AuthScopesAdvertisedRule",
    "AuthServerMetadataPresentRule",
    "AuthServerPkceRule",
    "AuthWwwAuthenticateRule",
    "BaseRule",
    "CacheMetadataReadinessRule",
    "CapabilityPromptsListChangedRule",
    "CapabilityPromptsPresentRule",
    "CapabilityResourcesListChangedRule",
    "CapabilityResourcesPresentRule",
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
    "PromptsArgumentNamesPresentRule",
    "PromptsArgumentNamesUniqueRule",
    "PromptsArgumentsDocumentedRule",
    "PromptsDescriptionPresentRule",
    "RemovedMethodsReadinessRule",
    "ResourcesAnnotationsValidRule",
    "ResourcesDescriptionPresentRule",
    "ResourcesMimeTypesValidRule",
    "ResourcesNamesPresentRule",
    "ResourcesSizesValidRule",
    "ResourcesUrisValidRule",
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
    "ToolsMcpHeadersPrimitiveTypesRule",
    "ToolsMcpHeadersStaticallyReachableRule",
    "ToolsMcpHeadersUniqueRule",
    "ToolsMcpHeadersValidNamesRule",
    "ToolsNamePresentRule",
    "ToolsNamesUniqueRule",
    "ToolsNamesValidFormatRule",
    "ToolsOutputSchemaValidRule",
    "ToolsTitlePresentRule",
    "UnsupportedVersionErrorReadinessRule",
    "create_all_rules",
)
