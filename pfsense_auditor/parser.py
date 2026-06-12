"""Parse a pfSense config.xml into the internal dataclass model.

pfSense XML uses a quirky convention: an *empty* tag often means the
feature is enabled (e.g. ``<enable></enable>``), and a missing tag means
disabled. The ``_present`` helper encapsulates this.
"""

from pathlib import Path
from typing import Optional

from lxml import etree

from .models import (
    Alias,
    Endpoint,
    Interface,
    PfSenseConfig,
    Rule,
    SNMPConfig,
    SSHConfig,
    SyslogConfig,
    SystemConfig,
    User,
    WebGUI,
)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _present(element, tag: str) -> bool:
    """True if `<tag>` exists as a direct child of element.

    In pfSense XML, presence-as-flag is common (`<enable></enable>` means
    "enabled"; absence means disabled).
    """
    if element is None:
        return False
    return element.find(tag) is not None


def _text(element, tag: str, default: Optional[str] = None) -> Optional[str]:
    """Return text of a direct child element, or default if missing/empty."""
    if element is None:
        return default
    child = element.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip() or default


def _text_list(element, tag: str) -> list[str]:
    """Return text of all direct children with given tag (repeating tags)."""
    if element is None:
        return []
    return [
        c.text.strip()
        for c in element.findall(tag)
        if c.text and c.text.strip()
    ]


# ---------------------------------------------------------------------
# Section parsers
# ---------------------------------------------------------------------

def _parse_system(system_el) -> SystemConfig:
    sys = SystemConfig(
        hostname=_text(system_el, "hostname", "") or "",
        domain=_text(system_el, "domain", "") or "",
    )

    # WebGUI
    webgui_el = system_el.find("webgui")
    if webgui_el is not None:
        sys.webgui = WebGUI(
            protocol=_text(webgui_el, "protocol", "https") or "https",
            port=_text(webgui_el, "port"),
        )

    # SSH
    ssh_el = system_el.find("ssh")
    if ssh_el is not None:
        sys.ssh = SSHConfig(
            enabled=_present(ssh_el, "enable"),
            port=_text(ssh_el, "port"),
            key_only=_present(ssh_el, "sshdkeyonly"),
        )

    # Time / DNS
    sys.timeservers = []
    ts = _text(system_el, "timeservers")
    if ts:
        sys.timeservers = ts.split()
    sys.dns_servers = _text_list(system_el, "dnsserver")

    # Users
    for user_el in system_el.findall("user"):
        sys.users.append(User(
            name=_text(user_el, "name", "") or "",
            uid=_text(user_el, "uid", "") or "",
            scope=_text(user_el, "scope", "") or "",
            groupname=_text(user_el, "groupname"),
            disabled=_present(user_el, "disabled"),
            description=_text(user_el, "descr"),
        ))

    return sys


def _parse_interfaces(interfaces_el) -> list[Interface]:
    interfaces: list[Interface] = []
    if interfaces_el is None:
        return interfaces

    # Each direct child is an interface (wan, lan, opt1, ...)
    for if_el in interfaces_el:
        interfaces.append(Interface(
            name=if_el.tag,
            physical_if=_text(if_el, "if", "") or "",
            description=_text(if_el, "descr"),
            enabled=_present(if_el, "enable"),
            ipaddr=_text(if_el, "ipaddr"),
            subnet=_text(if_el, "subnet"),
        ))
    return interfaces


def _parse_endpoint(endpoint_el) -> Endpoint:
    """Parse a `<source>` or `<destination>` element."""
    ep = Endpoint()
    if endpoint_el is None:
        return ep

    if endpoint_el.find("any") is not None:
        ep.any = True
    ep.network = _text(endpoint_el, "network")
    ep.address = _text(endpoint_el, "address")
    ep.port = _text(endpoint_el, "port")
    ep.not_ = _present(endpoint_el, "not")
    return ep


def _parse_rules(filter_el) -> list[Rule]:
    rules: list[Rule] = []
    if filter_el is None:
        return rules

    for rule_el in filter_el.findall("rule"):
        rules.append(Rule(
            type=_text(rule_el, "type", "pass") or "pass",
            interface=_text(rule_el, "interface", "") or "",
            ipprotocol=_text(rule_el, "ipprotocol", "inet") or "inet",
            protocol=_text(rule_el, "protocol"),
            source=_parse_endpoint(rule_el.find("source")),
            destination=_parse_endpoint(rule_el.find("destination")),
            description=_text(rule_el, "descr"),
            log=_present(rule_el, "log"),
            disabled=_present(rule_el, "disabled"),
            tracker=_text(rule_el, "tracker"),
        ))
    return rules


def _parse_aliases(aliases_el) -> list[Alias]:
    aliases: list[Alias] = []
    if aliases_el is None:
        return aliases

    for alias_el in aliases_el.findall("alias"):
        aliases.append(Alias(
            name=_text(alias_el, "name", "") or "",
            type=_text(alias_el, "type", "") or "",
            address=_text(alias_el, "address", "") or "",
            description=_text(alias_el, "descr"),
        ))
    return aliases


def _parse_snmp(snmp_el) -> SNMPConfig:
    if snmp_el is None:
        return SNMPConfig()
    return SNMPConfig(
        enabled=_present(snmp_el, "enable"),
        ro_community=_text(snmp_el, "rocommunity"),
        bind_ip=_text(snmp_el, "bindip"),
    )


def _parse_syslog(syslog_el) -> SyslogConfig:
    if syslog_el is None:
        return SyslogConfig()
    remote_enabled = _present(syslog_el, "enable")
    servers: list[str] = []
    # pfSense supports several remote server slots; collect any non-empty
    for tag in ("remoteserver", "remoteserver2", "remoteserver3"):
        val = _text(syslog_el, tag)
        if val:
            servers.append(val)
    return SyslogConfig(remote_enabled=remote_enabled, remote_servers=servers)


# ---------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------

def parse_config(path: str | Path) -> PfSenseConfig:
    """Parse a pfSense config.xml file into a PfSenseConfig object."""
    tree = etree.parse(str(path))
    root = tree.getroot()
    if root.tag != "pfsense":
        raise ValueError(
            f"Expected root element <pfsense>, got <{root.tag}>. "
            "Is this actually a pfSense config backup?"
        )

    return PfSenseConfig(
        version=_text(root, "version", "") or "",
        system=_parse_system(root.find("system")),
        interfaces=_parse_interfaces(root.find("interfaces")),
        rules=_parse_rules(root.find("filter")),
        aliases=_parse_aliases(root.find("aliases")),
        snmp=_parse_snmp(root.find("snmpd")),
        syslog=_parse_syslog(root.find("syslog")),
    )
