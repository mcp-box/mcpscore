"""Rules that judge an MCP server's *packaging*, from registry metadata alone.

These are the only rules that run in a package audit, and they never run in a
server audit — they judge a different kind of target, not a different aspect of
the same one (see ``MCPAuditor.audit_package``). Keeping them out of server
audits is deliberate: a server reached over HTTPS has no package, so listing
these as skipped on every HTTP report would be noise, not information.

Nothing here executes the package. Every check reads a document the registry
already publishes, so a package audit is safe to run on any surface, including a
public web service. The trade-off is stated in the score itself: this pack
scores how well a server is *published*, and says nothing about whether it
speaks MCP correctly. Use ``--stdio`` for that.
"""

from __future__ import annotations

from abc import abstractmethod

from mcpscore.diagnostics import quoted_preview
from mcpscore.packages import PackageMetadata, PackageOutcome, PackageRegistry
from mcpscore.report_evidence import evidence_preview, report_evidence

from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
    requires_fields,
)
from .registry import register_rule

PACKAGING_GROUP = "packaging"
"""Group name of packaging rules. The auditor runs this group *instead of* every
other group, never alongside them — a package audit and a server audit judge
different targets and their scores share no denominator."""


class PackagingBaseRule(BaseRule):
    """Base for rules reading package-registry metadata.

    Handles the two states no subclass should have to think about: metadata that
    was never collected (a server audit — not applicable), and a package the
    registry does not have (nothing to judge — insufficient data). Only
    ``PackageResolvesRule`` overrides the latter, because "it does not exist" is
    precisely its finding.
    """

    group_name = PACKAGING_GROUP
    group_order = 1

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless a real release was resolved and described."""
        package = audit_data.package
        if package is None:
            return SKIP_REASON_NOT_APPLICABLE
        if not package.describes_a_release:
            # The package is absent, unreachable, or the pinned version does not
            # exist. Either way there are no published fields to judge: failing
            # four more rules would multiply one fact into a score, and would
            # blame the publisher for data we never fetched.
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    @requires_fields("package")
    def check(self, package: PackageMetadata | None) -> RuleResult:  # type: ignore[override]
        """Run the rule against collected package metadata."""
        if package is None:  # pragma: no cover — skip_reason gates every caller
            raise RuntimeError(f"{self.rule_id} needs package metadata; skip_reason should have gated this run")
        return self._check_package(package)

    @abstractmethod
    def _check_package(self, package: PackageMetadata) -> RuleResult:
        """Judge the package metadata.

        Args:
            package: Metadata the registry published for this coordinate.

        Returns:
            RuleResult with the outcome.

        """
        ...

    def _result(self, *, passed: bool, message: str, details: dict, suggested_fix: str | None = None) -> RuleResult:
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=report_evidence(message.rstrip(".") + "."),
            details=report_evidence(details),
            suggested_fix=suggested_fix if not passed else None,
        )


@register_rule
class PackageResolvesRule(PackagingBaseRule):
    """Critical check: the package exists on the registry it claims."""

    rule_id = "package_resolves"
    basis = (
        "MCP Registry server.json — a packages[] entry names registryType + identifier so a "
        "client can install the server; an identifier that does not resolve makes the entry unusable"
    )
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "Package - Resolves on its registry"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip only when there is no package to look up at all.

        Unlike its siblings this rule does *not* skip on a missing package:
        reporting that the package could not be found is its entire job. It
        still skips on a fetch error, which is a finding about the network
        rather than about the publisher.
        """
        if audit_data.package is None:
            return SKIP_REASON_NOT_APPLICABLE
        if audit_data.package.outcome is PackageOutcome.ERROR:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def _check_package(self, package: PackageMetadata) -> RuleResult:
        registry = package.coordinate.registry.value
        details = {
            "registry": registry,
            "identifier": package.coordinate.identifier,
            "outcome": package.outcome.value,
        }
        if package.outcome is PackageOutcome.NOT_FOUND:
            return self._result(
                passed=False,
                message=f"❌ Package {evidence_preview(package.coordinate.identifier)} was not found on {registry}",
                suggested_fix=(
                    "Check the npm registry and package identifier, including its scope, for typos. "
                    if package.coordinate.registry is PackageRegistry.NPM
                    else "Check the PyPI project name for typos and confirm it exists on the public PyPI registry. "
                )
                + "If you maintain this package and it is unpublished, publish it through your normal release process.",
                details=details,
            )
        return self._result(
            passed=True,
            message=f"✅ Package {evidence_preview(package.coordinate.identifier)} is published on {registry}",
            details=details,
        )


@register_rule
class PackageVersionResolvesRule(PackagingBaseRule):
    """High check: the requested version exists on the registry."""

    rule_id = "package_version_resolves"
    basis = (
        "MCP Registry server.json — packages[].version pins the release a client installs; "
        "a pinned version missing from the registry cannot be installed"
    )
    rule_order = 2

    @property
    def rule_name(self) -> str:
        return "Package - Pinned version resolves"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when there is no package, or the fetch failed.

        A VERSION_NOT_FOUND outcome is this rule's finding, so — unlike its
        siblings — it does not skip on one.
        """
        package = audit_data.package
        if package is None:
            return SKIP_REASON_NOT_APPLICABLE
        if package.outcome in (PackageOutcome.ERROR, PackageOutcome.NOT_FOUND):
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def _check_package(self, package: PackageMetadata) -> RuleResult:
        requested = package.coordinate.version
        details = {
            "registry": package.coordinate.registry.value,
            "identifier": package.coordinate.identifier,
            "requested_version": requested,
            "resolved_version": package.resolved_version,
            "available_versions": len(package.available_versions),
        }
        if package.outcome is PackageOutcome.VERSION_NOT_FOUND:
            return self._result(
                passed=False,
                message=f"❌ Version {evidence_preview(requested)} was not found for "
                f"{evidence_preview(package.coordinate.identifier)} on {package.coordinate.registry.value}",
                suggested_fix="Choose an existing supported release or correct the pinned version. "
                "If you maintain the MCP registry entry, point it to the intended published release.",
                details=details,
            )
        if requested is None:
            return self._result(
                passed=True,
                message=f"✅ No version pinned; the registry's latest is {evidence_preview(package.resolved_version)}",
                details=details,
            )
        return self._result(
            passed=True,
            message=f"✅ Version {evidence_preview(requested)} is published",
            details=details,
        )


@register_rule
class PackageNotWithdrawnRule(PackagingBaseRule):
    """High check: the resolved release has not been withdrawn."""

    rule_id = "package_not_withdrawn"
    basis = (
        "PEP 592 §Yanked releases (PyPI) and npm deprecate — a withdrawn release is one the "
        "publisher has asked consumers to stop installing"
    )
    rule_order = 3

    @property
    def rule_name(self) -> str:
        return "Package - Release not withdrawn"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_package(self, package: PackageMetadata) -> RuleResult:
        noun = "yanked" if package.coordinate.registry is PackageRegistry.PYPI else "deprecated"
        notice = package.details.get("withdrawal_reason")
        details = {
            "yanked": package.yanked,
            "resolved_version": package.resolved_version,
            "registry": package.coordinate.registry.value,
            **({"withdrawal_reason": notice} if notice else {}),
        }
        if package.yanked:
            return self._result(
                passed=False,
                message=f"❌ Release {evidence_preview(package.resolved_version)} is {noun}"
                + (f". Publisher notice: {quoted_preview(str(report_evidence(notice)), 200)}" if notice else ""),
                suggested_fix=f"Review the publisher's {('yanking' if noun == 'yanked' else 'deprecation')} notice "
                "and choose a supported replacement release. If you maintain the package, resolve the cause "
                "before removing the warning.",
                details=details,
            )
        return self._result(
            passed=True,
            message=f"✅ Release {evidence_preview(package.resolved_version)} is not {noun}",
            details=details,
        )


@register_rule
class PackageRepositoryDeclaredRule(PackagingBaseRule):
    """Medium check: the package links to its source repository."""

    rule_id = "package_repository_declared"
    basis = (
        "npm package.json §repository and PyPI project_urls (PEP 621 §project.urls) — a source "
        "link is what lets a user review the code an MCP server will run on their machine"
    )
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Package - Source repository declared"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_package(self, package: PackageMetadata) -> RuleResult:
        details = {"repository_url": package.repository_url}
        if not package.repository_url:
            return self._result(
                passed=False,
                message="❌ Package metadata has no source repository URL",
                suggested_fix=(
                    "Publisher: add the source URL to package.json repository and publish a new release. "
                    "Consumer: check the project documentation for its source before installing."
                    if package.coordinate.registry is PackageRegistry.NPM
                    else "Publisher: add a Repository URL under [project.urls] in pyproject.toml "
                    "and publish a new release. "
                    "Consumer: check the project documentation for its source before installing."
                ),
                details=details,
            )
        return self._result(
            passed=True,
            message=f"✅ Source repository declared: {evidence_preview(package.repository_url)}",
            details=details,
        )


@register_rule
class PackageLicenseDeclaredRule(PackagingBaseRule):
    """Medium check: the package declares a license."""

    rule_id = "package_license_declared"
    basis = (
        "npm package.json §license and PEP 639 §License-Expression — license metadata helps "
        "consumers find the applicable terms; this check does not determine legal permissions"
    )
    rule_order = 5

    @property
    def rule_name(self) -> str:
        return "Package - License declared"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_package(self, package: PackageMetadata) -> RuleResult:
        details = {"license": package.license}
        if not package.license:
            return self._result(
                passed=False,
                message="❌ Package metadata has no license declaration",
                suggested_fix=(
                    "Publisher: declare the intended license in package.json license and publish a new release. "
                    "Consumer: review the actual license terms before use; this check only reads metadata."
                    if package.coordinate.registry is PackageRegistry.NPM
                    else "Publisher: declare the intended license in pyproject.toml project.license "
                    "using supported build tooling, "
                    "then publish a new release. Consumer: review the actual license terms before use; "
                    "this check only reads metadata."
                ),
                details=details,
            )
        return self._result(
            passed=True,
            message=f"✅ License declared: {evidence_preview(package.license)}",
            details=details,
        )


@register_rule
class PackageDescriptionPresentRule(PackagingBaseRule):
    """Low check: the package carries a description."""

    rule_id = "package_description_present"
    basis = (
        "npm package.json §description and PEP 621 §project.description — the summary a registry "
        "listing shows is how a user decides whether to install an MCP server at all"
    )
    rule_order = 6

    @property
    def rule_name(self) -> str:
        return "Package - Description present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _check_package(self, package: PackageMetadata) -> RuleResult:
        details = {"description": package.description}
        if not package.description:
            return self._result(
                passed=False,
                message="❌ Package metadata has no description",
                suggested_fix=(
                    "Publisher: add a concise description of the server's purpose to package.json description "
                    "and publish a new release. Consumer: consult the README for its purpose."
                    if package.coordinate.registry is PackageRegistry.NPM
                    else "Publisher: add a concise description of the server's purpose to "
                    "pyproject.toml project.description "
                    "and publish a new release. Consumer: consult the README for its purpose."
                ),
                details=details,
            )
        return self._result(
            passed=True,
            message=f"✅ Description present: {evidence_preview(package.description)}",
            details=details,
        )
