"""Audit checks against a parsed pfSense configuration.

Each check is a small function taking a ``PfSenseConfig`` and returning a
list of ``Finding`` objects. Adding a new check = adding a function and
registering it in ``ALL_CHECKS``.
"""

import re
from typing import Callable

from .models import Finding, PfSenseConfig


# Default SNMP community strings considered weak / unsafe.
DEFAULT_SNMP_COMMUNITIES = {"public", "private", "community"}


# ---------------------------------------------------------------------
# Rule-level checks
# ---------------------------------------------------------------------

def check_any_any_rules(config: PfSenseConfig) -> list[Finding]:
    """FW-001: pass rules with any source AND any destination AND no port."""
    findings: list[Finding] = []
    for rule in config.rules:
        if rule.disabled or rule.type != "pass":
            continue
        if (rule.source.any
                and rule.destination.any
                and not rule.destination.port
                and not rule.protocol):
            findings.append(Finding(
                check_id="FW-001",
                severity="high",
                title="Permissive any/any pass rule",
                description=(
                    f"Rule on interface '{rule.interface}' allows any source "
                    "to any destination with no protocol or port restriction."
                ),
                affected=rule.description or "(no description)",
                recommendation=(
                    "Restrict at least one of source, destination, protocol, "
                    "or destination port to follow least privilege."
                ),
            ))
    return findings


def check_rules_without_description(config: PfSenseConfig) -> list[Finding]:
    """FW-002: rules with no description make change review difficult."""
    findings: list[Finding] = []
    for i, rule in enumerate(config.rules):
        if not rule.description or not rule.description.strip():
            findings.append(Finding(
                check_id="FW-002",
                severity="low",
                title="Rule has no description",
                description=(
                    f"Rule #{i + 1} on interface '{rule.interface}' "
                    "(tracker {tr}) has no description.".format(
                        tr=rule.tracker or "n/a"
                    )
                ),
                affected=f"interface={rule.interface}, type={rule.type}",
                recommendation=(
                    "Add a description explaining the rule's purpose, "
                    "owner, and ticket reference for audit traceability."
                ),
            ))
    return findings


def check_rules_without_logging(config: PfSenseConfig) -> list[Finding]:
    """FW-003: pass rules without logging hide successful access from SIEM."""
    findings: list[Finding] = []
    for rule in config.rules:
        if rule.disabled or rule.type != "pass" or rule.log:
            continue
        findings.append(Finding(
            check_id="FW-003",
            severity="medium",
            title="Pass rule does not log matches",
            description=(
                f"Pass rule on interface '{rule.interface}' is not logged. "
                "Successful traffic will not appear in firewall logs."
            ),
            affected=rule.description or "(no description)",
            recommendation=(
                "Enable logging on pass rules to support access-evidence "
                "collection (CMMC AU.L2-3.3.x)."
            ),
        ))
    return findings


def check_disabled_rules(config: PfSenseConfig) -> list[Finding]:
    """FW-004: disabled rules left in the config should be reviewed."""
    findings: list[Finding] = []
    for rule in config.rules:
        if not rule.disabled:
            continue
        findings.append(Finding(
            check_id="FW-004",
            severity="info",
            title="Disabled rule present in configuration",
            description=(
                f"Rule on interface '{rule.interface}' is disabled. "
                "Disabled rules clutter the ruleset and may be re-enabled "
                "accidentally."
            ),
            affected=rule.description or "(no description)",
            recommendation=(
                "Review whether the rule is still needed; remove if not."
            ),
        ))
    return findings


def check_wan_to_self_rules(config: PfSenseConfig) -> list[Finding]:
    """FW-005: rules from WAN to (self) expose management to the internet."""
    findings: list[Finding] = []
    for rule in config.rules:
        if rule.disabled or rule.type != "pass":
            continue
        if rule.interface != "wan":
            continue
        if rule.destination.network and "self" in rule.destination.network:
            findings.append(Finding(
                check_id="FW-005",
                severity="high",
                title="WAN rule targeting firewall itself",
                description=(
                    "A pass rule on WAN has destination '(self)', exposing "
                    "the firewall directly to the internet."
                ),
                affected=rule.description or "(no description)",
                recommendation=(
                    "Restrict management access to specific source IPs or "
                    "place management behind a VPN."
                ),
            ))
    return findings


# ---------------------------------------------------------------------
# Alias checks
# ---------------------------------------------------------------------

def check_unused_aliases(config: PfSenseConfig) -> list[Finding]:
    """FW-006: aliases defined but never referenced by any rule."""
    if not config.aliases:
        return []

    alias_names = {a.name for a in config.aliases}
    referenced: set[str] = set()

    # Collect alias references from rule endpoints and ports.
    for rule in config.rules:
        for ep in (rule.source, rule.destination):
            if ep.address and ep.address in alias_names:
                referenced.add(ep.address)
            if ep.network and ep.network in alias_names:
                referenced.add(ep.network)
            if ep.port and ep.port in alias_names:
                referenced.add(ep.port)

    unused = alias_names - referenced
    findings: list[Finding] = []
    for name in sorted(unused):
        alias = next(a for a in config.aliases if a.name == name)
        findings.append(Finding(
            check_id="FW-006",
            severity="low",
            title="Unreferenced alias",
            description=(
                f"Alias '{name}' ({alias.type}) is defined but not "
                "referenced by any firewall rule."
            ),
            affected=name,
            recommendation=(
                "Remove unused aliases to reduce configuration drift; "
                "leftover aliases may be re-introduced in error."
            ),
        ))
    return findings


# ---------------------------------------------------------------------
# System / service checks
# ---------------------------------------------------------------------

def check_webgui_protocol(config: PfSenseConfig) -> list[Finding]:
    """SYS-001: webConfigurator should use HTTPS, not HTTP."""
    proto = (config.system.webgui.protocol or "").lower()
    if proto == "http":
        return [Finding(
            check_id="SYS-001",
            severity="high",
            title="webConfigurator using HTTP",
            description=(
                "The pfSense web interface is configured for HTTP. "
                "Admin credentials and session cookies are transmitted "
                "in cleartext."
            ),
            affected="System → Advanced → Admin Access",
            recommendation="Switch webConfigurator to HTTPS.",
        )]
    return []


def check_ssh_password_auth(config: PfSenseConfig) -> list[Finding]:
    """SYS-002: if SSH is enabled, key-only auth should be required."""
    if not config.system.ssh.enabled:
        return []
    if not config.system.ssh.key_only:
        return [Finding(
            check_id="SYS-002",
            severity="medium",
            title="SSH allows password authentication",
            description=(
                "SSH is enabled but password authentication is allowed. "
                "Key-only authentication is the recommended baseline."
            ),
            affected="System → Advanced → Admin Access → SSH",
            recommendation=(
                "Set 'SSH Key Only' to require public-key authentication."
            ),
        )]
    return []


def check_default_admin(config: PfSenseConfig) -> list[Finding]:
    """SYS-003: the built-in admin account should be disabled or renamed."""
    findings: list[Finding] = []
    for user in config.system.users:
        if user.name == "admin" and user.scope == "system" and not user.disabled:
            findings.append(Finding(
                check_id="SYS-003",
                severity="medium",
                title="Default 'admin' account is enabled",
                description=(
                    "The built-in 'admin' account is present and enabled. "
                    "Default usernames are common targets for credential "
                    "stuffing and brute-force attacks."
                ),
                affected=f"user={user.name}, uid={user.uid}",
                recommendation=(
                    "Create a named admin account, verify it can log in, "
                    "then disable the default 'admin' account."
                ),
            ))
    return findings


def check_snmp_default_community(config: PfSenseConfig) -> list[Finding]:
    """SYS-004: SNMP enabled with a default community string."""
    if not config.snmp.enabled:
        return []
    community = (config.snmp.ro_community or "").strip().lower()
    if community in DEFAULT_SNMP_COMMUNITIES:
        return [Finding(
            check_id="SYS-004",
            severity="high",
            title="SNMP enabled with default community string",
            description=(
                f"SNMP daemon is enabled with read community '{community}'. "
                "Default community strings allow trivial information "
                "disclosure to anyone who can reach the SNMP port."
            ),
            affected="Services → SNMP",
            recommendation=(
                "Change the community string to a long random value, or "
                "migrate to SNMPv3 with authentication and encryption. "
                "Restrict source IPs via firewall rule."
            ),
        )]
    return []


def check_ntp_configuration(config: PfSenseConfig) -> list[Finding]:
    """SYS-005: NTP should use multiple sources for time consistency."""
    if not config.system.timeservers:
        return [Finding(
            check_id="SYS-005",
            severity="medium",
            title="No NTP servers configured",
            description=(
                "No time servers are configured. Accurate time is required "
                "for log correlation, certificate validation, and Kerberos."
            ),
            affected="System → General Setup → Timeservers",
            recommendation="Configure at least three diverse NTP sources.",
        )]
    if len(config.system.timeservers) < 3:
        return [Finding(
            check_id="SYS-005",
            severity="low",
            title="Fewer than three NTP servers configured",
            description=(
                f"Only {len(config.system.timeservers)} NTP source(s) "
                "configured. Multiple diverse sources prevent a single "
                "bad clock from skewing local time."
            ),
            affected=", ".join(config.system.timeservers),
            recommendation=(
                "Configure at least three diverse NTP sources."
            ),
        )]
    return []


def check_remote_syslog(config: PfSenseConfig) -> list[Finding]:
    """SYS-006: remote syslog forwarding should be configured."""
    if not config.syslog.remote_enabled or not config.syslog.remote_servers:
        return [Finding(
            check_id="SYS-006",
            severity="medium",
            title="No remote syslog forwarding configured",
            description=(
                "Logs are written only to the local filesystem. Local logs "
                "can be lost on reboot or tampered with by an attacker who "
                "compromises the firewall."
            ),
            affected="Status → System Logs → Settings → Remote Logging",
            recommendation=(
                "Forward logs to a remote SIEM or syslog aggregator "
                "(CMMC AU.L2-3.3.8, AU.L2-3.3.9)."
            ),
        )]
    return []


# ---------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------

ALL_CHECKS: list[Callable[[PfSenseConfig], list[Finding]]] = [
    check_any_any_rules,
    check_rules_without_description,
    check_rules_without_logging,
    check_disabled_rules,
    check_wan_to_self_rules,
    check_unused_aliases,
    check_webgui_protocol,
    check_ssh_password_auth,
    check_default_admin,
    check_snmp_default_community,
    check_ntp_configuration,
    check_remote_syslog,
]


def run_all_checks(config: PfSenseConfig) -> list[Finding]:
    """Execute every registered check and return a combined list."""
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(config))
    # Sort by severity (high first), then check_id for stable output
    findings.sort(key=lambda f: (-f.severity_rank(), f.check_id))
    return findings
