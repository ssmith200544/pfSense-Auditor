"""Data models representing a parsed pfSense configuration."""

from dataclasses import dataclass, field
from datetime import date
from typing import Optional


# ---------------------------------------------------------------------
# Network / firewall objects
# ---------------------------------------------------------------------

@dataclass
class Interface:
    """A network interface (wan, lan, opt1, etc.)."""
    name: str
    physical_if: str
    description: Optional[str] = None
    enabled: bool = False
    ipaddr: Optional[str] = None
    subnet: Optional[str] = None


@dataclass
class Endpoint:
    """Source or destination side of a firewall rule."""
    any: bool = False
    network: Optional[str] = None
    address: Optional[str] = None
    port: Optional[str] = None
    not_: bool = False


@dataclass
class Rule:
    """A firewall (filter) rule."""
    type: str
    interface: str
    ipprotocol: str = "inet"
    protocol: Optional[str] = None
    source: Endpoint = field(default_factory=Endpoint)
    destination: Endpoint = field(default_factory=Endpoint)
    description: Optional[str] = None
    log: bool = False
    disabled: bool = False
    tracker: Optional[str] = None


@dataclass
class NATRule:
    """An inbound NAT (port forward) rule."""
    interface: str
    protocol: Optional[str] = None
    source: Endpoint = field(default_factory=Endpoint)
    destination: Endpoint = field(default_factory=Endpoint)
    target: Optional[str] = None        # internal IP traffic is redirected to
    local_port: Optional[str] = None    # internal port
    description: Optional[str] = None
    disabled: bool = False


@dataclass
class Alias:
    name: str
    type: str
    address: str
    description: Optional[str] = None


# ---------------------------------------------------------------------
# IPsec
# ---------------------------------------------------------------------

@dataclass
class IPsecPhase1:
    """An IPsec phase-1 (IKE) entry."""
    ikeid: str
    description: Optional[str] = None
    iketype: Optional[str] = None        # ikev1, ikev2, auto
    mode: Optional[str] = None           # main, aggressive
    encryption_algorithm: Optional[str] = None
    encryption_keylen: Optional[str] = None
    hash_algorithm: Optional[str] = None
    dhgroup: Optional[str] = None        # DH group number as string
    has_psk: bool = False


@dataclass
class IPsecPhase2:
    """An IPsec phase-2 (child SA) entry."""
    ikeid: str                           # parent phase-1 ikeid
    description: Optional[str] = None
    encryption_algorithm: Optional[str] = None
    encryption_keylen: Optional[str] = None
    hash_algorithm: Optional[str] = None
    pfsgroup: Optional[str] = None       # "0" means PFS disabled


# ---------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------

@dataclass
class Certificate:
    """A certificate stored in the pfSense config."""
    refid: str
    description: Optional[str] = None
    cert_type: Optional[str] = None      # server, ca, user
    subject: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[date] = None
    not_after: Optional[date] = None
    signature_algorithm: Optional[str] = None
    key_type: Optional[str] = None       # RSA, EC
    key_size: Optional[int] = None       # bits


# ---------------------------------------------------------------------
# System
# ---------------------------------------------------------------------

@dataclass
class User:
    name: str
    uid: str
    scope: str                  # "system" or "user"
    groupname: Optional[str] = None
    disabled: bool = False
    description: Optional[str] = None
    expires: Optional[date] = None
    has_totp: bool = False
    has_authorized_keys: bool = False


@dataclass
class WebGUI:
    protocol: str = "https"
    port: Optional[str] = None
    ssl_cert_ref: Optional[str] = None


@dataclass
class SSHConfig:
    enabled: bool = False
    port: Optional[str] = None
    key_only: bool = False


@dataclass
class SNMPConfig:
    enabled: bool = False
    ro_community: Optional[str] = None
    bind_ip: Optional[str] = None


@dataclass
class SyslogConfig:
    remote_enabled: bool = False
    remote_servers: list[str] = field(default_factory=list)


@dataclass
class SystemConfig:
    hostname: str = ""
    domain: str = ""
    webgui: WebGUI = field(default_factory=WebGUI)
    ssh: SSHConfig = field(default_factory=SSHConfig)
    timeservers: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    users: list[User] = field(default_factory=list)


@dataclass
class PfSenseConfig:
    """Top-level parsed pfSense configuration."""
    version: str = ""
    system: SystemConfig = field(default_factory=SystemConfig)
    interfaces: list[Interface] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    nat_rules: list[NATRule] = field(default_factory=list)
    aliases: list[Alias] = field(default_factory=list)
    ipsec_phase1: list[IPsecPhase1] = field(default_factory=list)
    ipsec_phase2: list[IPsecPhase2] = field(default_factory=list)
    certificates: list[Certificate] = field(default_factory=list)
    snmp: SNMPConfig = field(default_factory=SNMPConfig)
    syslog: SyslogConfig = field(default_factory=SyslogConfig)


# ---------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    """A single audit finding."""
    check_id: str
    severity: str
    title: str
    description: str
    affected: Optional[str] = None
    recommendation: Optional[str] = None
    # NIST 800-171 / CMMC control references that this finding maps to.
    # Example: ["CM.L2-3.4.1", "AU.L2-3.3.8"]
    control_refs: list[str] = field(default_factory=list)

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, -1)


# ---------------------------------------------------------------------
# Suppressions (allowlist)
# ---------------------------------------------------------------------

@dataclass
class Suppression:
    """A single allowlist entry from .pfsense-audit-allowlist.yaml."""
    check_id: str
    affected_pattern: str        # exact string, fnmatch glob, or "re:<regex>"
    justification: str
    owner: Optional[str] = None
    expires: Optional[date] = None
    ticket: Optional[str] = None

    def is_expired(self, today: Optional[date] = None) -> bool:
        if self.expires is None:
            return False
        if today is None:
            today = date.today()
        return self.expires < today


@dataclass
class SuppressedFinding:
    """A finding that was matched by a suppression rule."""
    finding: Finding
    suppression: Suppression
