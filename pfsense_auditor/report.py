"""Report formatters: text, JSON, and self-contained HTML."""

import html
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from .models import Finding, PfSenseConfig, SuppressedFinding
from .suppressions import ApplyResult


# ---------------------------------------------------------------------
# Helpers shared across formats
# ---------------------------------------------------------------------

SEVERITY_COLORS = {
    "high":   "#dc2626",
    "medium": "#ea580c",
    "low":    "#ca8a04",
    "info":   "#0284c7",
}


def _hr(char: str = "-", width: int = 72) -> str:
    return char * width


def _summary_counts(findings: list[Finding]) -> Counter:
    return Counter(f.severity for f in findings)


# ---------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------

def _format_inventory(config: PfSenseConfig) -> list[str]:
    lines: list[str] = []
    lines.append("INVENTORY SUMMARY")
    lines.append(_hr())

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

    lines.append(f"  NAT (port forward) rules: {len(config.nat_rules)}")
    lines.append(
        f"  IPsec tunnels:   {len(config.ipsec_phase1)} phase-1, "
        f"{len(config.ipsec_phase2)} phase-2"
    )
    lines.append(f"  Certificates:    {len(config.certificates)}")

    if config.aliases:
        by_type: Counter[str] = Counter(a.type for a in config.aliases)
        type_summary = ", ".join(f"{c} {t}" for t, c in by_type.items())
        lines.append(f"  Aliases:         {len(config.aliases)} "
                     f"({type_summary})")
    else:
        lines.append("  Aliases:         none")

    snmp_state = "enabled" if config.snmp.enabled else "disabled"
    syslog_state = ("forwarding to "
                    + ", ".join(config.syslog.remote_servers)
                    if config.syslog.remote_enabled
                    else "local-only")
    lines.append(f"  SNMP:            {snmp_state}")
    lines.append(f"  Remote syslog:   {syslog_state}")
    lines.append("")
    return lines


def _format_finding_block(f: Finding, index: int) -> list[str]:
    lines: list[str] = []
    lines.append(f"[{index:02d}] [{f.severity.upper():<6}] "
                 f"{f.check_id}  {f.title}")
    lines.append(f"     {f.description}")
    if f.affected:
        lines.append(f"     Affected:        {f.affected}")
    if f.recommendation:
        lines.append(f"     Recommendation:  {f.recommendation}")
    if f.control_refs:
        lines.append(f"     Controls:        {', '.join(f.control_refs)}")
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

    counts = _summary_counts(findings)
    lines.append(f"  Total: {len(findings)}  |  "
                 f"High: {counts.get('high', 0)}  "
                 f"Medium: {counts.get('medium', 0)}  "
                 f"Low: {counts.get('low', 0)}  "
                 f"Info: {counts.get('info', 0)}")
    lines.append("")

    for i, f in enumerate(findings, 1):
        lines.extend(_format_finding_block(f, i))
    return lines


def _format_suppressions(apply: ApplyResult) -> list[str]:
    lines: list[str] = []
    if not apply.suppressed:
        return lines
    lines.append(f"SUPPRESSED ({len(apply.suppressed)})")
    lines.append(_hr())
    for i, sf in enumerate(apply.suppressed, 1):
        f = sf.finding
        s = sf.suppression
        lines.append(f"[{i:02d}] {f.check_id}  {f.title}  "
                     f"[{f.severity.upper()}]")
        lines.append(f"     Affected:        {f.affected or '(n/a)'}")
        lines.append(f"     Justification:   {s.justification}")
        if s.owner:
            lines.append(f"     Owner:           {s.owner}")
        if s.ticket:
            lines.append(f"     Ticket:          {s.ticket}")
        if s.expires:
            tag = " (EXPIRED)" if s.is_expired() else ""
            lines.append(f"     Expires:         {s.expires.isoformat()}{tag}")
        lines.append("")

    if apply.expired_suppressions:
        lines.append(
            f"  WARNING: {len(apply.expired_suppressions)} suppression(s) "
            "are past their expiry date and should be re-reviewed."
        )
        lines.append("")
    if apply.unused_suppressions:
        lines.append(
            f"  NOTE: {len(apply.unused_suppressions)} suppression(s) "
            "did not match any finding (stale rules?)."
        )
        lines.append("")
    return lines


def render_text_report(config: PfSenseConfig,
                       apply: ApplyResult,
                       profile=None) -> str:
    """Render a full human-readable audit report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []
    lines.append(_hr("="))
    lines.append("  pfSense Configuration Audit Report")
    lines.append(_hr("="))
    lines.append(f"  Generated: {now}")
    if profile is not None:
        # Count how many checks were affected for the impact summary.
        from .checks import ALL_CHECKS
        lines.append(
            f"  Profile:   {profile.name}  "
            f"({profile.impact_summary(len(ALL_CHECKS))})"
        )
    lines.append("")
    lines.extend(_format_inventory(config))
    lines.extend(_format_findings(apply.active))
    lines.extend(_format_suppressions(apply))
    lines.append(_hr("="))
    return "\n".join(lines)


# ---------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------

def _suppressed_to_dict(sf: SuppressedFinding) -> dict:
    return {
        "finding": asdict(sf.finding),
        "suppression": {
            "check_id": sf.suppression.check_id,
            "affected_pattern": sf.suppression.affected_pattern,
            "justification": sf.suppression.justification,
            "owner": sf.suppression.owner,
            "expires": sf.suppression.expires.isoformat()
                if sf.suppression.expires else None,
            "ticket": sf.suppression.ticket,
            "expired": sf.suppression.is_expired(),
        },
    }


def render_json_report(config: PfSenseConfig, apply: ApplyResult,
                       profile=None) -> str:
    counts = _summary_counts(apply.active)
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "profile": (
            {
                "name": profile.name,
                "description": profile.description,
                "severity_overrides": dict(profile.severity_overrides),
                "suppressed_checks": sorted(profile.suppress_checks),
                "hide_controls": profile.hide_controls,
            }
            if profile is not None else None
        ),
        "config": {
            "version": config.version,
            "hostname": config.system.hostname,
            "domain": config.system.domain,
            "interface_count": len(config.interfaces),
            "rule_count": len(config.rules),
            "nat_rule_count": len(config.nat_rules),
            "ipsec_phase1_count": len(config.ipsec_phase1),
            "ipsec_phase2_count": len(config.ipsec_phase2),
            "certificate_count": len(config.certificates),
            "alias_count": len(config.aliases),
            "user_count": len(config.system.users),
        },
        "summary": {
            "total_findings": len(apply.active),
            "suppressed_count": len(apply.suppressed),
            "by_severity": {
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "info": counts.get("info", 0),
            },
        },
        "findings": [asdict(f) for f in apply.active],
        "suppressed": [_suppressed_to_dict(sf) for sf in apply.suppressed],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------

HTML_CSS = """
* { box-sizing: border-box; }
body {
  font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
  margin: 0; padding: 32px; background: #f8fafc; color: #0f1b2d;
  line-height: 1.55;
}
.container { max-width: 1100px; margin: 0 auto; }
header {
  background: #0f1b2d; color: #fff; padding: 28px 32px;
  border-radius: 8px; margin-bottom: 24px;
}
header h1 { margin: 0 0 6px 0; font-size: 26px; }
header .meta { color: #94a3b8; font-size: 13px; }
section { background: #fff; padding: 24px 28px; border-radius: 8px;
  margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }
section h2 { margin-top: 0; color: #0f1b2d; font-size: 19px;
  border-bottom: 2px solid #e76f51; padding-bottom: 8px;
  display: inline-block; }
.summary-bar { display: flex; gap: 10px; flex-wrap: wrap;
  margin: 16px 0 4px 0; }
.pill {
  padding: 6px 14px; border-radius: 999px; font-size: 13px;
  font-weight: 600; color: #fff;
}
.pill.total { background: #475569; }
.pill.high   { background: #dc2626; }
.pill.medium { background: #ea580c; }
.pill.low    { background: #ca8a04; }
.pill.info   { background: #0284c7; }
.filters { margin: 12px 0 18px 0; }
.filter-btn {
  background: #e2e8f0; border: 0; padding: 6px 14px; border-radius: 999px;
  cursor: pointer; font-size: 13px; margin-right: 6px;
}
.filter-btn.active { background: #0f1b2d; color: #fff; }
.finding {
  padding: 16px 18px; margin: 10px 0; border-radius: 6px;
  background: #f8fafc; border-left: 4px solid #94a3b8;
}
.finding.high   { border-left-color: #dc2626; }
.finding.medium { border-left-color: #ea580c; }
.finding.low    { border-left-color: #ca8a04; }
.finding.info   { border-left-color: #0284c7; }
.finding h3 { margin: 0 0 6px 0; font-size: 15px; color: #0f1b2d; }
.finding .severity-tag {
  display: inline-block; padding: 2px 8px; border-radius: 4px;
  font-size: 11px; font-weight: 700; color: #fff;
  text-transform: uppercase; letter-spacing: 0.5px; margin-right: 8px;
}
.finding .check-id {
  font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
  color: #64748b; font-size: 12px;
}
.finding p { margin: 6px 0; font-size: 14px; }
.finding .label { font-weight: 600; color: #334155; }
.finding .controls { font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
  font-size: 12px; color: #475569; }
.controls .control-ref {
  display: inline-block; background: #e2e8f0; padding: 1px 7px;
  margin: 0 4px 4px 0; border-radius: 3px;
}
table.inventory { width: 100%; border-collapse: collapse;
  font-size: 14px; }
table.inventory td { padding: 6px 10px; vertical-align: top; }
table.inventory td.label { color: #64748b; width: 200px; }
.suppressed-list .finding { background: #fef9c3; border-left-color: #ca8a04; }
.suppressed-list .just { font-style: italic; color: #475569; }
.warn {
  background: #fef3c7; color: #92400e;
  padding: 10px 14px; border-radius: 6px; margin: 10px 0;
  border-left: 4px solid #f59e0b;
}
.empty { color: #64748b; font-style: italic; }
footer { text-align: center; color: #94a3b8; font-size: 12px;
  margin-top: 18px; }
"""

HTML_JS = """
const buttons = document.querySelectorAll('.filter-btn');
buttons.forEach(btn => btn.addEventListener('click', () => {
  buttons.forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const sev = btn.dataset.sev;
  document.querySelectorAll('#findings-list .finding').forEach(card => {
    card.style.display = (sev === 'all' || card.classList.contains(sev))
      ? '' : 'none';
  });
}));
"""


def _esc(s: Optional[str]) -> str:
    return html.escape(s) if s else ""


def _html_finding(f: Finding) -> str:
    rows: list[str] = []
    if f.affected:
        rows.append(
            f'<p><span class="label">Affected:</span> {_esc(f.affected)}</p>'
        )
    if f.recommendation:
        rows.append(
            f'<p><span class="label">Recommendation:</span> '
            f'{_esc(f.recommendation)}</p>'
        )
    if f.control_refs:
        refs = "".join(
            f'<span class="control-ref">{_esc(c)}</span>'
            for c in f.control_refs
        )
        rows.append(
            f'<p class="controls"><span class="label">Controls:</span> {refs}</p>'
        )
    return f"""
    <div class="finding {f.severity}">
      <h3>
        <span class="severity-tag" style="background:{SEVERITY_COLORS.get(f.severity, '#64748b')}">{f.severity}</span>
        <span class="check-id">{_esc(f.check_id)}</span>
        &nbsp;{_esc(f.title)}
      </h3>
      <p>{_esc(f.description)}</p>
      {''.join(rows)}
    </div>
    """


def _html_suppressed(sf: SuppressedFinding) -> str:
    f = sf.finding
    s = sf.suppression
    meta_bits: list[str] = []
    if s.owner:
        meta_bits.append(f"<b>Owner:</b> {_esc(s.owner)}")
    if s.ticket:
        meta_bits.append(f"<b>Ticket:</b> {_esc(s.ticket)}")
    if s.expires:
        exp_tag = " (EXPIRED)" if s.is_expired() else ""
        meta_bits.append(
            f"<b>Expires:</b> {s.expires.isoformat()}{exp_tag}"
        )
    meta = " &middot; ".join(meta_bits)
    meta_html = f'<p style="font-size:12px;color:#64748b">{meta}</p>' if meta else ''
    return f"""
    <div class="finding {f.severity}">
      <h3>
        <span class="check-id">{_esc(f.check_id)}</span>
        &nbsp;{_esc(f.title)}
      </h3>
      <p><b>Affected:</b> {_esc(f.affected or '(n/a)')}</p>
      <p class="just">"{_esc(s.justification)}"</p>
      {meta_html}
    </div>
    """


def render_html_report(config: PfSenseConfig, apply: ApplyResult,
                       profile=None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    counts = _summary_counts(apply.active)

    summary_pills = (
        f'<span class="pill total">Total {len(apply.active)}</span>'
        f'<span class="pill high">High {counts.get("high", 0)}</span>'
        f'<span class="pill medium">Medium {counts.get("medium", 0)}</span>'
        f'<span class="pill low">Low {counts.get("low", 0)}</span>'
        f'<span class="pill info">Info {counts.get("info", 0)}</span>'
    )

    filters_html = ""
    findings_html = ""
    if apply.active:
        filters_html = """
        <div class="filters">
          <button class="filter-btn active" data-sev="all">All</button>
          <button class="filter-btn" data-sev="high">High</button>
          <button class="filter-btn" data-sev="medium">Medium</button>
          <button class="filter-btn" data-sev="low">Low</button>
          <button class="filter-btn" data-sev="info">Info</button>
        </div>
        """
        findings_html = "".join(_html_finding(f) for f in apply.active)
    else:
        findings_html = (
            '<p class="empty">No findings. Configuration passed all checks.</p>'
        )

    # Inventory
    sys_obj = config.system
    inventory_rows = [
        ("Hostname",        f"{sys_obj.hostname}.{sys_obj.domain}"),
        ("Config version",  config.version or "n/a"),
        ("WebGUI",          f"{sys_obj.webgui.protocol.upper()} (port "
                            f"{sys_obj.webgui.port or 'default'})"),
        ("SSH",             ("enabled" if sys_obj.ssh.enabled else "disabled")
                            + (" (key-only)" if sys_obj.ssh.key_only else "")),
        ("Interfaces",      str(len(config.interfaces))),
        ("Firewall rules",  str(len(config.rules))),
        ("NAT rules",       str(len(config.nat_rules))),
        ("IPsec tunnels",   f"{len(config.ipsec_phase1)} phase-1, "
                            f"{len(config.ipsec_phase2)} phase-2"),
        ("Certificates",    str(len(config.certificates))),
        ("Aliases",         str(len(config.aliases))),
        ("Local users",     str(len(sys_obj.users))),
        ("NTP servers",     str(len(sys_obj.timeservers))),
        ("Remote syslog",   ("yes — " + ", ".join(config.syslog.remote_servers)
                             if config.syslog.remote_enabled
                             else "no (local only)")),
    ]
    inv_html = "".join(
        f'<tr><td class="label">{_esc(k)}</td><td>{_esc(v)}</td></tr>'
        for k, v in inventory_rows
    )

    # Suppressed section
    suppressed_section = ""
    if apply.suppressed:
        warnings: list[str] = []
        if apply.expired_suppressions:
            warnings.append(
                f'<div class="warn">⚠ {len(apply.expired_suppressions)} '
                'suppression(s) past expiry — re-review required.</div>'
            )
        if apply.unused_suppressions:
            warnings.append(
                f'<div class="warn">ℹ {len(apply.unused_suppressions)} '
                'suppression(s) did not match any finding.</div>'
            )
        suppressed_section = f"""
        <section class="suppressed-list">
          <h2>Suppressed ({len(apply.suppressed)})</h2>
          {''.join(warnings)}
          {''.join(_html_suppressed(sf) for sf in apply.suppressed)}
        </section>
        """

    profile_html = ""
    if profile is not None:
        profile_html = (
            f'<div class="meta" style="margin-top:6px">Profile: '
            f'<b>{_esc(profile.name)}</b> &mdash; '
            f'{_esc(profile.description)}</div>'
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>pfSense Audit &mdash; {_esc(sys_obj.hostname)}</title>
<style>{HTML_CSS}</style>
</head><body>
<div class="container">
  <header>
    <h1>pfSense Configuration Audit Report</h1>
    <div class="meta">{_esc(sys_obj.hostname)}.{_esc(sys_obj.domain)} &middot;
      Generated {now}</div>
    {profile_html}
  </header>

  <section>
    <h2>Inventory</h2>
    <table class="inventory"><tbody>{inv_html}</tbody></table>
  </section>

  <section>
    <h2>Findings</h2>
    <div class="summary-bar">{summary_pills}</div>
    {filters_html}
    <div id="findings-list">{findings_html}</div>
  </section>

  {suppressed_section}

  <footer>Generated by pfsense-audit</footer>
</div>
<script>{HTML_JS}</script>
</body></html>
"""
