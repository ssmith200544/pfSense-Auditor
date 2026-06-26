"""Parse a pfSense config.xml into the internal dataclass model.

pfSense XML uses a quirky convention: an *empty* tag often means the
feature is enabled (e.g. ``<enable></enable>``), and a missing tag means
disabled. The ``_present`` helper encapsulates this.
"""

from datetime import date, datetime
from pathlib import Path
from typing import Optional

from lxml import etree

from .models import (
    Alias,
    Certificate,
    Endpoint,
    Interface,
    IPsecPhase1,
    IPsecPhase2,
    NATRule,
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
    """True if `<tag>` exists as a direct child of element."""
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
    if element is None:
        return []
    return [
        c.text.strip()
        for c in element.findall(tag)
        if c.text and c.text.strip()
    ]


def _parse_date(value: Optional[str]) -> Optional[date]:
    """Parse pfSense date strings. Accepts MM/DD/YYYY and ISO formats."""
    if not value:
        return None
    value = value.strip()
    formats = (
        "%m/%d/%Y",
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    )
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


def _parse_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------
# Section parsers
# ---------------------------------------------------------------------

def _parse_user(user_el) -> User:
    return User(
        name=_text(user_el, "name", "") or "",
        uid=_text(user_el, "uid", "") or "",
        scope=_text(user_el, "scope", "") or "",
        groupname=_text(user_el, "groupname"),
        disabled=_present(user_el, "disabled"),
        description=_text(user_el, "descr"),
        expires=_parse_date(_text(user_el, "expires")),
        has_totp=bool(_text(user_el, "otp_seed")),
        has_authorized_keys=bool(_text(user_el, "authorizedkeys")),
    )


def _parse_system(system_el) -> SystemConfig:
    sys = SystemConfig(
        hostname=_text(system_el, "hostname", "") or "",
        domain=_text(system_el, "domain", "") or "",
    )

    webgui_el = system_el.find("webgui")
    if webgui_el is not None:
        sys.webgui = WebGUI(
            protocol=_text(webgui_el, "protocol", "https") or "https",
            port=_text(webgui_el, "port"),
            ssl_cert_ref=_text(webgui_el, "ssl-certref"),
        )

    ssh_el = system_el.find("ssh")
    if ssh_el is not None:
        sys.ssh = SSHConfig(
            enabled=_present(ssh_el, "enable"),
            port=_text(ssh_el, "port"),
            key_only=_present(ssh_el, "sshdkeyonly"),
        )

    ts = _text(system_el, "timeservers")
    if ts:
        sys.timeservers = ts.split()
    sys.dns_servers = _text_list(system_el, "dnsserver")

    for user_el in system_el.findall("user"):
        sys.users.append(_parse_user(user_el))

    return sys


def _parse_interfaces(interfaces_el) -> list[Interface]:
    interfaces: list[Interface] = []
    if interfaces_el is None:
        return interfaces
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


def _parse_nat_rules(nat_el) -> list[NATRule]:
    """Parse inbound NAT (port forward) rules from the <nat> section."""
    nat_rules: list[NATRule] = []
    if nat_el is None:
        return nat_rules
    for rule_el in nat_el.findall("rule"):
        nat_rules.append(NATRule(
            interface=_text(rule_el, "interface", "") or "",
            protocol=_text(rule_el, "protocol"),
            source=_parse_endpoint(rule_el.find("source")),
            destination=_parse_endpoint(rule_el.find("destination")),
            target=_text(rule_el, "target"),
            local_port=_text(rule_el, "local-port"),
            description=_text(rule_el, "descr"),
            disabled=_present(rule_el, "disabled"),
        ))
    return nat_rules


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


def _parse_ipsec(ipsec_el):
    """Return (phase1_list, phase2_list)."""
    phase1: list[IPsecPhase1] = []
    phase2: list[IPsecPhase2] = []
    if ipsec_el is None:
        return phase1, phase2

    for p1_el in ipsec_el.findall("phase1"):
        # The encryption section can have multiple <item> entries; we take
        # the first for simplicity. Real checks may want to inspect all.
        enc_item = p1_el.find("encryption/item")
        enc_algo = None
        enc_keylen = None
        hash_algo = None
        dhgroup = None
        if enc_item is not None:
            enc_algo_el = enc_item.find("encryption-algorithm")
            if enc_algo_el is not None:
                enc_algo = _text(enc_algo_el, "name")
                enc_keylen = _text(enc_algo_el, "keylen")
            hash_algo = _text(enc_item, "hash-algorithm")
            dhgroup = _text(enc_item, "dhgroup")
        phase1.append(IPsecPhase1(
            ikeid=_text(p1_el, "ikeid", "") or "",
            description=_text(p1_el, "descr"),
            iketype=_text(p1_el, "iketype"),
            mode=_text(p1_el, "mode"),
            encryption_algorithm=enc_algo,
            encryption_keylen=enc_keylen,
            hash_algorithm=hash_algo,
            dhgroup=dhgroup,
            has_psk=bool(_text(p1_el, "pre-shared-key")),
        ))

    for p2_el in ipsec_el.findall("phase2"):
        enc_algo_el = p2_el.find("encryption-algorithm-option")
        enc_algo = None
        enc_keylen = None
        if enc_algo_el is not None:
            enc_algo = _text(enc_algo_el, "name")
            enc_keylen = _text(enc_algo_el, "keylen")
        phase2.append(IPsecPhase2(
            ikeid=_text(p2_el, "ikeid", "") or "",
            description=_text(p2_el, "descr"),
            encryption_algorithm=enc_algo,
            encryption_keylen=enc_keylen,
            hash_algorithm=_text(p2_el, "hash-algorithm-option"),
            pfsgroup=_text(p2_el, "pfsgroup"),
        ))

    return phase1, phase2


def _parse_certificates(root_el) -> list[Certificate]:
    """Parse <cert> elements at the top level of the config."""
    certs: list[Certificate] = []
    for cert_el in root_el.findall("cert"):
        certs.append(Certificate(
            refid=_text(cert_el, "refid", "") or "",
            description=_text(cert_el, "descr"),
            cert_type=_text(cert_el, "type"),
            subject=_text(cert_el, "subject"),
            issuer=_text(cert_el, "issuer"),
            not_before=_parse_date(_text(cert_el, "not_before")),
            not_after=_parse_date(_text(cert_el, "not_after")),
            signature_algorithm=_text(cert_el, "signature_algorithm"),
            key_type=_text(cert_el, "key_type"),
            key_size=_parse_int(_text(cert_el, "key_size")),
        ))
    return certs


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
    for tag in ("remoteserver", "remoteserver2", "remoteserver3"):
        val = _text(syslog_el, tag)
        if val:
            servers.append(val)
    return SyslogConfig(remote_enabled=remote_enabled, remote_servers=servers)


# ---------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------

def parse_config(path) -> PfSenseConfig:
    """Parse a pfSense config.xml file into a PfSenseConfig object."""
    tree = etree.parse(str(path))
    root = tree.getroot()
    if root.tag != "pfsense":
        raise ValueError(
            f"Expected root element <pfsense>, got <{root.tag}>. "
            "Is this actually a pfSense config backup?"
        )

    phase1, phase2 = _parse_ipsec(root.find("ipsec"))

    return PfSenseConfig(
        version=_text(root, "version", "") or "",
        system=_parse_system(root.find("system")),
        interfaces=_parse_interfaces(root.find("interfaces")),
        rules=_parse_rules(root.find("filter")),
        nat_rules=_parse_nat_rules(root.find("nat")),
        aliases=_parse_aliases(root.find("aliases")),
        ipsec_phase1=phase1,
        ipsec_phase2=phase2,
        certificates=_parse_certificates(root),
        snmp=_parse_snmp(root.find("snmpd")),
        syslog=_parse_syslog(root.find("syslog")),
    )
