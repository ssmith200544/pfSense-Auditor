"""Audit checks against a parsed pfSense configuration.

Each check is a small function taking a ``PfSenseConfig`` and returning a
list of ``Finding`` objects. Adding a new check = adding a function and
registering it in ``ALL_CHECKS``.

Each finding carries ``control_refs`` linking it to specific NIST SP
800-171 / CMMC L2 controls so the output doubles as audit evidence.
"""

from datetime import date, timedelta
from typing import Callable

from .models import Finding, PfSenseConfig


# Default SNMP community strings considered weak / unsafe.
DEFAULT_SNMP_COMMUNITIES = {"public", "private", "community"}

# IPsec algorithms considered weak.
WEAK_ENCRYPTION_ALGOS = {"des", "3des", "blowfish", "cast128"}
WEAK_HASH_ALGOS = {"md5", "sha1"}
# DH groups < 14 are considered weak (group 14 = 2048-bit MODP minimum).
WEAK_DH_GROUPS = {"1", "2", "5"}

# Certificate signature algorithms considered weak.
WEAK_SIG_ALGOS_KEYWORDS = ("md5", "sha1")

# Common high-risk management ports that should not be port-forwarded to
# the internet without compensating controls.
HIGH_RISK_FORWARD_PORTS = {
    "22":   "SSH",
    "23":   "Telnet",
    "3389": "RDP",
    "5900": "VNC",
    "1433": "MSSQL",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "445":  "SMB",
    "139":  "NetBIOS",
}


def _cert_label(cert) -> str:
    """Human-readable cert label for the affected field."""
    return cert.description or cert.subject or cert.refid


# ---------------------------------------------------------------------
# Existing checks (FW-001..006, SYS-001..006) — backfilled with control_refs
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
                control_refs=["AC.L2-3.1.3", "SC.L2-3.13.1"],
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
                    f"(tracker {rule.tracker or 'n/a'}) has no description."
                ),
                affected=f"interface={rule.interface}, type={rule.type}",
                recommendation=(
                    "Add a description explaining the rule's purpose, "
                    "owner, and ticket reference for audit traceability."
                ),
                control_refs=["CM.L2-3.4.1", "CM.L2-3.4.2"],
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
                "collection."
            ),
            control_refs=["AU.L2-3.3.1", "AU.L2-3.3.2"],
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
            control_refs=["CM.L2-3.4.1"],
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
                control_refs=["AC.L2-3.1.3", "AC.L2-3.1.13", "SC.L2-3.13.1"],
            ))
    return findings


def check_unused_aliases(config: PfSenseConfig) -> list[Finding]:
    """FW-006: aliases defined but never referenced by any rule."""
    if not config.aliases:
        return []

    alias_names = {a.name for a in config.aliases}
    referenced: set[str] = set()

    # Collect alias references from rules.
    for rule in config.rules:
        for ep in (rule.source, rule.destination):
            for v in (ep.address, ep.network, ep.port):
                if v and v in alias_names:
                    referenced.add(v)
    # Also from NAT rules.
    for nrule in config.nat_rules:
        for ep in (nrule.source, nrule.destination):
            for v in (ep.address, ep.network, ep.port):
                if v and v in alias_names:
                    referenced.add(v)
        if nrule.local_port and nrule.local_port in alias_names:
            referenced.add(nrule.local_port)

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
                "referenced by any firewall or NAT rule."
            ),
            affected=name,
            recommendation=(
                "Remove unused aliases to reduce configuration drift; "
                "leftover aliases may be re-introduced in error."
            ),
            control_refs=["CM.L2-3.4.2"],
        ))
    return findings


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
            control_refs=["SC.L2-3.13.8", "AC.L2-3.1.13"],
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
            control_refs=["IA.L2-3.5.3", "IA.L2-3.5.7"],
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
                control_refs=["IA.L2-3.5.1", "IA.L2-3.5.2"],
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
            control_refs=["IA.L2-3.5.7", "SC.L2-3.13.1"],
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
            control_refs=["AU.L2-3.3.7"],
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
            control_refs=["AU.L2-3.3.7"],
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
                "Forward logs to a remote SIEM or syslog aggregator."
            ),
            control_refs=["AU.L2-3.3.8", "AU.L2-3.3.9"],
        )]
    return []


# ---------------------------------------------------------------------
# Day 14 new checks
# ---------------------------------------------------------------------

def check_ipsec_weak_crypto(config: PfSenseConfig) -> list[Finding]:
    """FW-007: IPsec phase 1/2 using weak crypto."""
    findings: list[Finding] = []

    for p1 in config.ipsec_phase1:
        issues: list[str] = []
        enc = (p1.encryption_algorithm or "").lower()
        hash_ = (p1.hash_algorithm or "").lower()
        if enc in WEAK_ENCRYPTION_ALGOS:
            issues.append(f"encryption={enc}")
        if hash_ in WEAK_HASH_ALGOS:
            issues.append(f"hash={hash_}")
        if p1.dhgroup and p1.dhgroup in WEAK_DH_GROUPS:
            issues.append(f"DH group={p1.dhgroup}")
        if (p1.iketype or "").lower() == "ikev1" \
                and (p1.mode or "").lower() == "aggressive":
            issues.append("IKEv1 aggressive mode")

        if issues:
            findings.append(Finding(
                check_id="FW-007",
                severity="high",
                title="IPsec phase-1 uses weak parameters",
                description=(
                    f"IPsec phase-1 (IKE) entry uses weak cryptographic "
                    f"parameters: {', '.join(issues)}."
                ),
                affected=(
                    f"phase1 ikeid={p1.ikeid} "
                    f"({p1.description or 'no description'})"
                ),
                recommendation=(
                    "Use IKEv2 with AES-256, SHA-256 or stronger, and DH "
                    "group 14 or higher (groups 19-21 preferred). Remove "
                    "IKEv1 aggressive mode."
                ),
                control_refs=["SC.L2-3.13.8", "SC.L2-3.13.11"],
            ))

    for p2 in config.ipsec_phase2:
        issues = []
        enc = (p2.encryption_algorithm or "").lower()
        hash_ = (p2.hash_algorithm or "").lower()
        if enc in WEAK_ENCRYPTION_ALGOS:
            issues.append(f"encryption={enc}")
        if hash_ in WEAK_HASH_ALGOS:
            issues.append(f"hash={hash_}")
        if p2.pfsgroup == "0":
            issues.append("PFS disabled")
        elif p2.pfsgroup and p2.pfsgroup in WEAK_DH_GROUPS:
            issues.append(f"PFS group={p2.pfsgroup}")

        if issues:
            findings.append(Finding(
                check_id="FW-007",
                severity="high",
                title="IPsec phase-2 uses weak parameters",
                description=(
                    f"IPsec phase-2 (child SA) entry uses weak cryptographic "
                    f"parameters: {', '.join(issues)}."
                ),
                affected=(
                    f"phase2 ikeid={p2.ikeid} "
                    f"({p2.description or 'no description'})"
                ),
                recommendation=(
                    "Use AES-256, SHA-256 or stronger, and enable PFS with "
                    "DH group 14 or higher."
                ),
                control_refs=["SC.L2-3.13.8", "SC.L2-3.13.11"],
            ))

    return findings


def check_high_risk_port_forwards(config: PfSenseConfig) -> list[Finding]:
    """FW-008: inbound NAT rules forwarding sensitive management ports."""
    findings: list[Finding] = []
    for nrule in config.nat_rules:
        if nrule.disabled or nrule.interface != "wan":
            continue
        port = (nrule.destination.port or nrule.local_port or "").strip()
        if port in HIGH_RISK_FORWARD_PORTS:
            service = HIGH_RISK_FORWARD_PORTS[port]
            # Source restriction softens the finding.
            unrestricted = nrule.source.any
            severity = "high" if unrestricted else "medium"
            findings.append(Finding(
                check_id="FW-008",
                severity=severity,
                title=f"Port forward exposes {service} (port {port})",
                description=(
                    f"WAN port-forward sends inbound traffic on port {port} "
                    f"({service}) to internal target "
                    f"'{nrule.target or 'unknown'}'. "
                    + ("Source is unrestricted (any). "
                       if unrestricted else
                       "Source is restricted. ")
                    + f"{service} is a high-value target if reachable from "
                    "the internet."
                ),
                affected=nrule.description or f"WAN→{nrule.target}:{port}",
                recommendation=(
                    "Place the service behind a VPN, restrict source IPs to "
                    "an allowlist, or front the service with an "
                    "authenticating reverse proxy."
                ),
                control_refs=["AC.L2-3.1.3", "SC.L2-3.13.1", "SC.L2-3.13.6"],
            ))
    return findings


def check_certs_expired_or_expiring(config: PfSenseConfig) -> list[Finding]:
    """SYS-007: certificates already expired or expiring within 30 days."""
    findings: list[Finding] = []
    today = date.today()
    soon = today + timedelta(days=30)

    for cert in config.certificates:
        if cert.not_after is None:
            continue
        if cert.not_after < today:
            days_ago = (today - cert.not_after).days
            findings.append(Finding(
                check_id="SYS-007",
                severity="high",
                title="Certificate is expired",
                description=(
                    f"Certificate '{_cert_label(cert)}' expired "
                    f"{days_ago} days ago ({cert.not_after.isoformat()})."
                ),
                affected=_cert_label(cert),
                recommendation=(
                    "Renew or replace the certificate. If the cert is no "
                    "longer needed, remove it from the configuration."
                ),
                control_refs=["SC.L2-3.13.10", "IA.L2-3.5.3"],
            ))
        elif cert.not_after <= soon:
            days_left = (cert.not_after - today).days
            findings.append(Finding(
                check_id="SYS-007",
                severity="medium",
                title="Certificate expires within 30 days",
                description=(
                    f"Certificate '{_cert_label(cert)}' expires in "
                    f"{days_left} days ({cert.not_after.isoformat()})."
                ),
                affected=_cert_label(cert),
                recommendation=(
                    "Renew the certificate before expiry to avoid service "
                    "disruption."
                ),
                control_refs=["SC.L2-3.13.10"],
            ))
    return findings


def check_weak_certificates(config: PfSenseConfig) -> list[Finding]:
    """SYS-008: certificates using weak signature algorithms or small keys."""
    findings: list[Finding] = []
    for cert in config.certificates:
        issues: list[str] = []
        sig = (cert.signature_algorithm or "").lower()
        for keyword in WEAK_SIG_ALGOS_KEYWORDS:
            if keyword in sig:
                issues.append(f"signature uses {keyword}")
                break
        if (cert.key_type or "").upper() == "RSA" and cert.key_size:
            if cert.key_size < 2048:
                issues.append(f"RSA key size = {cert.key_size} bits")
        if issues:
            findings.append(Finding(
                check_id="SYS-008",
                severity="medium",
                title="Certificate uses weak cryptography",
                description=(
                    f"Certificate '{_cert_label(cert)}' has weak "
                    f"cryptographic parameters: {'; '.join(issues)}."
                ),
                affected=_cert_label(cert),
                recommendation=(
                    "Regenerate the certificate with at least RSA 2048 (or "
                    "ECDSA P-256) and a SHA-256 signature algorithm."
                ),
                control_refs=["SC.L2-3.13.8", "SC.L2-3.13.11"],
            ))
    return findings


def check_privileged_users_without_mfa(config: PfSenseConfig) -> list[Finding]:
    """SYS-009: users in the admins group with no TOTP or authorized keys."""
    findings: list[Finding] = []
    for user in config.system.users:
        if user.disabled:
            continue
        if (user.groupname or "").lower() != "admins":
            continue
        # System-level 'admin' is covered separately by SYS-003.
        if user.name == "admin" and user.scope == "system":
            continue
        if not user.has_totp and not user.has_authorized_keys:
            findings.append(Finding(
                check_id="SYS-009",
                severity="medium",
                title="Privileged user without MFA configured",
                description=(
                    f"User '{user.name}' is in the 'admins' group but has "
                    "neither a TOTP seed nor authorized SSH keys configured. "
                    "Authentication appears to rely on password only."
                ),
                affected=f"user={user.name}, uid={user.uid}",
                recommendation=(
                    "Configure TOTP for webGUI access (System → User "
                    "Manager) or require SSH key authentication. For RADIUS "
                    "backed auth, ensure the upstream IdP enforces MFA."
                ),
                control_refs=["IA.L2-3.5.3"],
            ))
    return findings


def check_expired_user_accounts(config: PfSenseConfig) -> list[Finding]:
    """SYS-010: user accounts past their expiry date but still enabled."""
    findings: list[Finding] = []
    today = date.today()
    for user in config.system.users:
        if user.disabled or user.expires is None:
            continue
        if user.expires < today:
            days_ago = (today - user.expires).days
            findings.append(Finding(
                check_id="SYS-010",
                severity="medium",
                title="User account past expiry date but still enabled",
                description=(
                    f"User '{user.name}' has an expiry date of "
                    f"{user.expires.isoformat()} ({days_ago} days ago) "
                    "but the account is not disabled."
                ),
                affected=f"user={user.name}, expires={user.expires.isoformat()}",
                recommendation=(
                    "Disable or remove the account. Account expiry on its "
                    "own does not prevent login in all pfSense auth paths."
                ),
                control_refs=["AC.L2-3.1.1", "IA.L2-3.5.6"],
            ))
    return findings


# ---------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------

ALL_CHECKS: list[Callable[[PfSenseConfig], list[Finding]]] = [
    # Day 7
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
    # Day 14
    check_ipsec_weak_crypto,
    check_high_risk_port_forwards,
    check_certs_expired_or_expiring,
    check_weak_certificates,
    check_privileged_users_without_mfa,
    check_expired_user_accounts,
]


def run_all_checks(config: PfSenseConfig) -> list[Finding]:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(config))
    findings.sort(key=lambda f: (-f.severity_rank(), f.check_id))
    return findings
