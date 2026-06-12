"""Data models representing a parsed pfSense configuration."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Interface:
    """A network interface (wan, lan, opt1, etc.)."""
    name: str  # internal name: "wan", "lan", "opt1"
    physical_if: str  # OS-level: "em0"
    description: Optional[str] = None
    enabled: bool = False
    ipaddr: Optional[str] = None  # "dhcp", an IP, or None
    subnet: Optional[str] = None


@dataclass
class Endpoint:
    """Source or destination side of a firewall rule."""
    any: bool = False
    network: Optional[str] = None   # e.g. "lan", "wan", "opt1", "(self)"
    address: Optional[str] = None   # raw address or alias name
    port: Optional[str] = None      # port number, range, or alias name
    not_: bool = False              # negation flag


@dataclass
class Rule:
    """A firewall (filter) rule."""
    type: str  # "pass", "block", "reject"
    interface: str
    ipprotocol: str = "inet"
    protocol: Optional[str] = None  # tcp, udp, icmp, or None for any
    source: Endpoint = field(default_factory=Endpoint)
    destination: Endpoint = field(default_factory=Endpoint)
    description: Optional[str] = None
    log: bool = False
    disabled: bool = False
    tracker: Optional[str] = None


@dataclass
class Alias:
    """A named alias (host, network, port, url)."""
    name: str
    type: str  # network, host, port, url
    address: str  # space-separated list of values
    description: Optional[str] = None


@dataclass
class User:
    """A local user account."""
    name: str
    uid: str
    scope: str  # "system" (built-in) or "user"
    groupname: Optional[str] = None
    disabled: bool = False
    description: Optional[str] = None


@dataclass
class WebGUI:
    protocol: str = "https"
    port: Optional[str] = None


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
    aliases: list[Alias] = field(default_factory=list)
    snmp: SNMPConfig = field(default_factory=SNMPConfig)
    syslog: SyslogConfig = field(default_factory=SyslogConfig)


# ----------------------------------------------------------------------
# Findings
# ----------------------------------------------------------------------

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    """A single audit finding."""
    check_id: str
    severity: str          # "high" | "medium" | "low" | "info"
    title: str
    description: str
    affected: Optional[str] = None      # what specifically: rule descr, alias name
    recommendation: Optional[str] = None

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, -1)
