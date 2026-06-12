"""Report formatters: human-readable text and machine-readable JSON."""

import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone

from .models import Finding, PfSenseConfig


# ---------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------

def _hr(char: str = "-", width: int = 72) -> str:
    return char * width


def _format_inventory(config: PfSenseConfig) -> list[str]:
    lines: list[str] = []
    lines.append("INVENTORY SUMMARY")
    lines.append(_hr())

    # System
    sys = config.system
    lines.append(f"  Hostname:        {sys.hostname}.{sys.domain}")
    lines.append(f"  Config version:  {config.version}")
    lines.append(f"  WebGUI:          {sys.webgui.protocol.upper()}"
                 f" (port {sys.webgui.port or 'default'})")
    ssh_state = "enabled" if sys.ssh.enabled else "disabled"
    ssh_auth = "key-only" if sys.ssh.key_only else "password+key"
    lines.append(f"  SSH:             {ssh_state} ({ssh_auth}, "
                 f"port {sys.ssh.port or 'default'})")
    lines.append(f"  NTP servers:     {len(sys.timeservers)} configured")
    lines.append(f"  DNS servers:     {len(sys.dns_servers)} configured")
    lines.append(f"  Local users:     {len(sys.users)}")
    lines.append("")

    # Interfaces
    lines.append(f"  Interfaces ({len(config.interfaces)}):")
    for iface in config.interfaces:
        state = "up" if iface.enabled else "down"
        addr = iface.ipaddr or "n/a"
        if iface.subnet and iface.ipaddr and iface.ipaddr != "dhcp":
            addr = f"{iface.ipaddr}/{iface.subnet}"
        descr = iface.description or iface.name.upper()
        lines.append(f"    - {iface.name:<6} {iface.physical_if:<6} "
                     f"{state:<5} {addr:<22} ({descr})")
    lines.append("")

    # Rules summary per interface
    rules_by_if: Counter[str] = Counter(r.interface for r in config.rules)
    pass_count = sum(1 for r in config.rules if r.type == "pass")
    block_count = sum(1 for r in config.rules
                      if r.type in ("block", "reject"))
    disabled_count = sum(1 for r in config.rules if r.disabled)
    lines.append(f"  Firewall rules:  {len(config.rules)} total "
                 f"({pass_count} pass, {block_count} block/reject, "
                 f"{disabled_count} disabled)")
    for iface_name, count in sorted(rules_by_if.items()):
        lines.append(f"    - {iface_name}: {count} rule(s)")
    lines.append("")

    # Aliases
    if config.aliases:
        by_type: Counter[str] = Counter(a.type for a in config.aliases)
        type_summary = ", ".join(f"{c} {t}" for t, c in by_type.items())
        lines.append(f"  Aliases:         {len(config.aliases)} "
                     f"({type_summary})")
    else:
        lines.append("  Aliases:         none")
    lines.append("")

    # Services
    snmp_state = "enabled" if config.snmp.enabled else "disabled"
    syslog_state = ("forwarding to "
                    + ", ".join(config.syslog.remote_servers)
                    if config.syslog.remote_enabled
                    else "local-only")
    lines.append(f"  SNMP:            {snmp_state}")
    lines.append(f"  Remote syslog:   {syslog_state}")
    lines.append("")
    return lines


def _format_findings(findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    lines.append("FINDINGS")
    lines.append(_hr())

    if not findings:
        lines.append("  No findings. Configuration passed all checks.")
        lines.append("")
        return lines

    counts: Counter[str] = Counter(f.severity for f in findings)
    summary = (f"  Total: {len(findings)}  |  "
               f"High: {counts.get('high', 0)}  "
               f"Medium: {counts.get('medium', 0)}  "
               f"Low: {counts.get('low', 0)}  "
               f"Info: {counts.get('info', 0)}")
    lines.append(summary)
    lines.append("")

    for i, f in enumerate(findings, 1):
        lines.append(f"[{i:02d}] [{f.severity.upper():<6}] "
                     f"{f.check_id}  {f.title}")
        lines.append(f"     {f.description}")
        if f.affected:
            lines.append(f"     Affected:        {f.affected}")
        if f.recommendation:
            lines.append(f"     Recommendation:  {f.recommendation}")
        lines.append("")
    return lines


def render_text_report(config: PfSenseConfig,
                       findings: list[Finding]) -> str:
    """Render a full human-readable audit report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []
    lines.append(_hr("="))
    lines.append("  pfSense Configuration Audit Report")
    lines.append(_hr("="))
    lines.append(f"  Generated: {now}")
    lines.append("")
    lines.extend(_format_inventory(config))
    lines.extend(_format_findings(findings))
    lines.append(_hr("="))
    return "\n".join(lines)


# ---------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------

def render_json_report(config: PfSenseConfig,
                       findings: list[Finding]) -> str:
    """Render a JSON report suitable for downstream tooling / SIEM ingest."""
    counts: Counter[str] = Counter(f.severity for f in findings)
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "config": {
            "version": config.version,
            "hostname": config.system.hostname,
            "domain": config.system.domain,
            "interface_count": len(config.interfaces),
            "rule_count": len(config.rules),
            "alias_count": len(config.aliases),
            "user_count": len(config.system.users),
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": {
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "info": counts.get("info", 0),
            },
        },
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(payload, indent=2)
