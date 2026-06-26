"""Tests for individual checks and the suppression engine.

Each test constructs the minimal config needed to exercise one check
and asserts the expected ``check_id`` does (or does not) fire. The
synthetic fixture used by the smoke test is intentionally maximalist;
the unit tests here are precise.
"""

from datetime import date, timedelta

import pytest

from pfsense_auditor import checks
from pfsense_auditor.models import (
    Alias,
    Certificate,
    Endpoint,
    Finding,
    Interface,
    IPsecPhase1,
    IPsecPhase2,
    NATRule,
    PfSenseConfig,
    Rule,
    SNMPConfig,
    SSHConfig,
    Suppression,
    SyslogConfig,
    SystemConfig,
    User,
    WebGUI,
)
from pfsense_auditor.suppressions import (
    _pattern_matches,
    apply_suppressions,
)


# ---------------------------------------------------------------------
# Config builders — small helpers to keep tests readable
# ---------------------------------------------------------------------

def _clean_config(**overrides) -> PfSenseConfig:
    """A minimal config that produces zero findings."""
    cfg = PfSenseConfig(
        version="23.5",
        system=SystemConfig(
            hostname="clean",
            domain="example.com",
            webgui=WebGUI(protocol="https"),
            ssh=SSHConfig(enabled=False),
            timeservers=["0.pool.ntp.org",
                         "1.pool.ntp.org",
                         "2.pool.ntp.org"],
            users=[User(name="scott", uid="2000", scope="user")],
        ),
        syslog=SyslogConfig(remote_enabled=True,
                            remote_servers=["siem.example.com"]),
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


def _ids(findings: list[Finding]) -> set[str]:
    return {f.check_id for f in findings}


# ---------------------------------------------------------------------
# Smoke test on the clean config
# ---------------------------------------------------------------------

def test_clean_config_produces_no_findings():
    cfg = _clean_config()
    findings = checks.run_all_checks(cfg)
    assert findings == []


# ---------------------------------------------------------------------
# Existing checks (FW-001..006, SYS-001..006)
# ---------------------------------------------------------------------

def test_any_any_rule_fires():
    cfg = _clean_config()
    cfg.rules.append(Rule(
        type="pass", interface="lan",
        source=Endpoint(any=True), destination=Endpoint(any=True),
        description="LAN to any", log=True,
    ))
    assert "FW-001" in _ids(checks.check_any_any_rules(cfg))


def test_any_any_with_port_does_not_fire():
    cfg = _clean_config()
    cfg.rules.append(Rule(
        type="pass", interface="lan",
        source=Endpoint(any=True),
        destination=Endpoint(any=True, port="443"),
        description="LAN to any:443", log=True,
    ))
    assert "FW-001" not in _ids(checks.check_any_any_rules(cfg))


def test_rule_without_description_fires():
    cfg = _clean_config()
    cfg.rules.append(Rule(type="pass", interface="lan", description=None))
    assert "FW-002" in _ids(checks.check_rules_without_description(cfg))


def test_rule_without_logging_fires():
    cfg = _clean_config()
    cfg.rules.append(Rule(
        type="pass", interface="lan",
        source=Endpoint(any=True),
        destination=Endpoint(network="lan", port="443"),
        description="LAN to LAN HTTPS", log=False,
    ))
    assert "FW-003" in _ids(checks.check_rules_without_logging(cfg))


def test_disabled_rule_fires():
    cfg = _clean_config()
    cfg.rules.append(Rule(
        type="pass", interface="lan",
        description="old", disabled=True,
    ))
    assert "FW-004" in _ids(checks.check_disabled_rules(cfg))


def test_wan_to_self_fires():
    cfg = _clean_config()
    cfg.rules.append(Rule(
        type="pass", interface="wan",
        source=Endpoint(any=True),
        destination=Endpoint(network="(self)", port="443"),
        description="WAN→self HTTPS",
    ))
    assert "FW-005" in _ids(checks.check_wan_to_self_rules(cfg))


def test_unused_alias_fires():
    cfg = _clean_config()
    cfg.aliases.append(Alias(name="Unused", type="network", address="10.0.0.0/8"))
    assert "FW-006" in _ids(checks.check_unused_aliases(cfg))


def test_unused_alias_referenced_by_nat_does_not_fire():
    cfg = _clean_config()
    cfg.aliases.append(Alias(name="WebPorts", type="port", address="80 443"))
    cfg.nat_rules.append(NATRule(
        interface="wan",
        destination=Endpoint(network="wanip", port="WebPorts"),
        target="192.168.1.10", local_port="WebPorts",
        description="HTTPS to webserver",
    ))
    assert "FW-006" not in _ids(checks.check_unused_aliases(cfg))


def test_http_webgui_fires():
    cfg = _clean_config()
    cfg.system.webgui = WebGUI(protocol="http")
    assert "SYS-001" in _ids(checks.check_webgui_protocol(cfg))


def test_ssh_password_auth_fires():
    cfg = _clean_config()
    cfg.system.ssh = SSHConfig(enabled=True, key_only=False)
    assert "SYS-002" in _ids(checks.check_ssh_password_auth(cfg))


def test_default_admin_fires():
    cfg = _clean_config()
    cfg.system.users.append(
        User(name="admin", uid="0", scope="system", groupname="admins")
    )
    assert "SYS-003" in _ids(checks.check_default_admin(cfg))


def test_snmp_default_community_fires():
    cfg = _clean_config()
    cfg.snmp = SNMPConfig(enabled=True, ro_community="public")
    assert "SYS-004" in _ids(checks.check_snmp_default_community(cfg))


def test_few_ntp_sources_fires():
    cfg = _clean_config()
    cfg.system.timeservers = ["0.pool.ntp.org"]
    assert "SYS-005" in _ids(checks.check_ntp_configuration(cfg))


def test_no_remote_syslog_fires():
    cfg = _clean_config()
    cfg.syslog = SyslogConfig(remote_enabled=False)
    assert "SYS-006" in _ids(checks.check_remote_syslog(cfg))


# ---------------------------------------------------------------------
# Day 14 new checks
# ---------------------------------------------------------------------

def test_ipsec_weak_phase1_fires():
    cfg = _clean_config()
    cfg.ipsec_phase1.append(IPsecPhase1(
        ikeid="1", iketype="ikev1", mode="aggressive",
        encryption_algorithm="3des", hash_algorithm="md5", dhgroup="2",
    ))
    assert "FW-007" in _ids(checks.check_ipsec_weak_crypto(cfg))


def test_ipsec_strong_phase1_does_not_fire():
    cfg = _clean_config()
    cfg.ipsec_phase1.append(IPsecPhase1(
        ikeid="2", iketype="ikev2",
        encryption_algorithm="aes", encryption_keylen="256",
        hash_algorithm="sha256", dhgroup="14",
    ))
    assert "FW-007" not in _ids(checks.check_ipsec_weak_crypto(cfg))


def test_ipsec_phase2_pfs_disabled_fires():
    cfg = _clean_config()
    cfg.ipsec_phase2.append(IPsecPhase2(
        ikeid="1",
        encryption_algorithm="aes", encryption_keylen="256",
        hash_algorithm="sha256",
        pfsgroup="0",
    ))
    findings = checks.check_ipsec_weak_crypto(cfg)
    assert any(
        "PFS disabled" in f.description
        for f in findings if f.check_id == "FW-007"
    )


def test_port_forward_rdp_unrestricted_is_high():
    cfg = _clean_config()
    cfg.nat_rules.append(NATRule(
        interface="wan", protocol="tcp",
        source=Endpoint(any=True),
        destination=Endpoint(network="wanip", port="3389"),
        target="192.168.1.20", local_port="3389",
        description="RDP to internal",
    ))
    findings = checks.check_high_risk_port_forwards(cfg)
    assert any(f.check_id == "FW-008" and f.severity == "high"
               for f in findings)


def test_port_forward_with_source_restriction_is_medium():
    cfg = _clean_config()
    cfg.nat_rules.append(NATRule(
        interface="wan", protocol="tcp",
        source=Endpoint(any=False, address="AdminWorkstations"),
        destination=Endpoint(network="wanip", port="22"),
        target="192.168.1.20", local_port="22",
        description="SSH from admin nets",
    ))
    findings = checks.check_high_risk_port_forwards(cfg)
    assert any(f.check_id == "FW-008" and f.severity == "medium"
               for f in findings)


def test_expired_cert_fires():
    cfg = _clean_config()
    cfg.certificates.append(Certificate(
        refid="abc", description="webgui-cert", cert_type="server",
        not_after=date.today() - timedelta(days=10),
    ))
    findings = checks.check_certs_expired_or_expiring(cfg)
    assert any(f.check_id == "SYS-007" and f.severity == "high"
               for f in findings)


def test_cert_expiring_soon_is_medium():
    cfg = _clean_config()
    cfg.certificates.append(Certificate(
        refid="abc", description="webgui-cert", cert_type="server",
        not_after=date.today() + timedelta(days=10),
    ))
    findings = checks.check_certs_expired_or_expiring(cfg)
    assert any(f.check_id == "SYS-007" and f.severity == "medium"
               for f in findings)


def test_weak_cert_sha1_and_small_key_fires():
    cfg = _clean_config()
    cfg.certificates.append(Certificate(
        refid="abc", description="weak-cert", cert_type="server",
        signature_algorithm="sha1WithRSAEncryption",
        key_type="RSA", key_size=1024,
        not_after=date.today() + timedelta(days=365),
    ))
    assert "SYS-008" in _ids(checks.check_weak_certificates(cfg))


def test_admin_without_mfa_fires():
    cfg = _clean_config()
    cfg.system.users.append(User(
        name="powerops", uid="3000", scope="user", groupname="admins",
        has_totp=False, has_authorized_keys=False,
    ))
    assert "SYS-009" in _ids(checks.check_privileged_users_without_mfa(cfg))


def test_admin_with_totp_does_not_fire():
    cfg = _clean_config()
    cfg.system.users.append(User(
        name="scott", uid="2000", scope="user", groupname="admins",
        has_totp=True,
    ))
    assert "SYS-009" not in _ids(checks.check_privileged_users_without_mfa(cfg))


def test_expired_user_account_fires():
    cfg = _clean_config()
    cfg.system.users.append(User(
        name="contractor", uid="2001", scope="user", groupname="admins",
        expires=date.today() - timedelta(days=30),
    ))
    assert "SYS-010" in _ids(checks.check_expired_user_accounts(cfg))


def test_findings_carry_control_refs():
    """Every Day 14 finding should reference at least one CMMC control."""
    cfg = _clean_config()
    cfg.system.webgui = WebGUI(protocol="http")
    findings = checks.run_all_checks(cfg)
    assert findings, "Expected at least one finding"
    for f in findings:
        assert f.control_refs, f"Finding {f.check_id} missing control_refs"


# ---------------------------------------------------------------------
# Suppression engine
# ---------------------------------------------------------------------

class TestPatternMatcher:
    def test_exact_match(self):
        assert _pattern_matches("foo bar", "foo bar")
        assert not _pattern_matches("foo bar", "foo baz")

    def test_wildcard_all(self):
        assert _pattern_matches("*", "anything")
        assert _pattern_matches("*", "")

    def test_glob(self):
        assert _pattern_matches("*DMZ*", "Allow web to DMZ servers")
        assert _pattern_matches("rule-*", "rule-1700000003")
        assert not _pattern_matches("rule-*", "tracker-1700000003")

    def test_regex_prefix(self):
        assert _pattern_matches(r"re:^WAN.*self$", "WAN HTTPS to self")
        assert not _pattern_matches(r"re:^WAN.*self$", "LAN to self")

    def test_invalid_regex_does_not_match(self):
        assert not _pattern_matches("re:[unclosed", "anything")


def test_suppression_filters_matched_finding():
    findings = [
        Finding(check_id="FW-001", severity="high",
                title="t", description="d",
                affected="Default allow LAN to any rule"),
        Finding(check_id="FW-002", severity="low",
                title="t", description="d",
                affected="interface=lan, type=pass"),
    ]
    supps = [Suppression(
        check_id="FW-001",
        affected_pattern="Default allow LAN to any rule",
        justification="accepted risk",
    )]
    result = apply_suppressions(findings, supps)
    assert len(result.active) == 1
    assert result.active[0].check_id == "FW-002"
    assert len(result.suppressed) == 1
    assert result.suppressed[0].finding.check_id == "FW-001"


def test_unused_suppression_is_reported():
    findings = [
        Finding(check_id="FW-001", severity="high",
                title="t", description="d", affected="x"),
    ]
    supps = [Suppression(
        check_id="FW-999",
        affected_pattern="*",
        justification="testing stale",
    )]
    result = apply_suppressions(findings, supps)
    assert len(result.unused_suppressions) == 1


def test_expired_suppression_is_flagged_but_still_applied():
    findings = [
        Finding(check_id="FW-001", severity="high",
                title="t", description="d", affected="anything"),
    ]
    supps = [Suppression(
        check_id="FW-001",
        affected_pattern="*",
        justification="accepted",
        expires=date.today() - timedelta(days=1),
    )]
    result = apply_suppressions(findings, supps)
    assert len(result.suppressed) == 1
    assert len(result.expired_suppressions) == 1
    assert len(result.active) == 0


# ---------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------

from pfsense_auditor.profiles import (
    BUILT_IN_PROFILES,
    PROFILE_BUSINESS,
    PROFILE_CMMC,
    PROFILE_HOME,
    Profile,
    get_profile,
)


def _sample_findings() -> list[Finding]:
    """A handful of findings spanning checks the profiles touch."""
    return [
        Finding(check_id="FW-002", severity="low",
                title="No descr", description="d", affected="x",
                control_refs=["CM.L2-3.4.1"]),
        Finding(check_id="FW-003", severity="medium",
                title="No log", description="d", affected="y",
                control_refs=["AU.L2-3.3.1"]),
        Finding(check_id="SYS-006", severity="medium",
                title="No syslog", description="d", affected="z",
                control_refs=["AU.L2-3.3.8"]),
        Finding(check_id="SYS-004", severity="high",
                title="SNMP default", description="d", affected="snmp",
                control_refs=["IA.L2-3.5.7"]),
    ]


def test_get_profile_returns_builtin():
    assert get_profile("home") is PROFILE_HOME
    assert get_profile("HOME") is PROFILE_HOME       # case-insensitive
    assert get_profile("business") is PROFILE_BUSINESS
    assert get_profile("cmmc") is PROFILE_CMMC


def test_get_profile_returns_none_for_unknown():
    assert get_profile("definitely-not-a-profile") is None


def test_cmmc_profile_is_passthrough():
    """CMMC profile should not change anything."""
    findings = _sample_findings()
    result = PROFILE_CMMC.apply(findings)
    assert len(result) == len(findings)
    for orig, new in zip(findings, result):
        assert orig.check_id == new.check_id
        assert orig.severity == new.severity
        assert orig.control_refs == new.control_refs


def test_business_profile_overrides_severity():
    findings = _sample_findings()
    result = PROFILE_BUSINESS.apply(findings)
    sev_by_id = {f.check_id: f.severity for f in result}
    assert sev_by_id["FW-002"] == "info"     # downgraded from low
    assert sev_by_id["SYS-006"] == "low"     # downgraded from medium
    assert sev_by_id["SYS-004"] == "high"    # untouched


def test_home_profile_suppresses_and_overrides():
    findings = _sample_findings()
    result = PROFILE_HOME.apply(findings)
    ids = {f.check_id for f in result}
    # FW-002 and SYS-006 are suppressed entirely by home profile
    assert "FW-002" not in ids
    assert "SYS-006" not in ids
    # FW-003 stays but gets downgraded to info
    fw003 = next(f for f in result if f.check_id == "FW-003")
    assert fw003.severity == "info"
    # SNMP default is still high - real security issue regardless
    sys004 = next(f for f in result if f.check_id == "SYS-004")
    assert sys004.severity == "high"


def test_home_profile_hides_controls():
    findings = _sample_findings()
    result = PROFILE_HOME.apply(findings)
    for f in result:
        assert f.control_refs == []


def test_business_profile_keeps_controls():
    findings = _sample_findings()
    result = PROFILE_BUSINESS.apply(findings)
    # At least one finding should still carry its control refs
    assert any(f.control_refs for f in result)


def test_profile_impact_summary():
    assert PROFILE_CMMC.impact_summary(18) == "no adjustments"
    assert "suppressed" in PROFILE_HOME.impact_summary(18)
    assert "override" in PROFILE_BUSINESS.impact_summary(18)


def test_high_severity_findings_survive_all_profiles():
    """High-severity findings should never be downgraded by any built-in
    profile — real security issues are real regardless of environment."""
    high_finding = Finding(
        check_id="SYS-004", severity="high",
        title="SNMP default community",
        description="d", affected="x",
        control_refs=["IA.L2-3.5.7"],
    )
    for profile in BUILT_IN_PROFILES.values():
        result = profile.apply([high_finding])
        if result:   # not suppressed
            assert result[0].severity == "high", \
                f"Profile '{profile.name}' downgraded a high finding"


# ---------------------------------------------------------------------
# CLI exit codes
# ---------------------------------------------------------------------

import subprocess
import sys


def _run_cli(*args) -> subprocess.CompletedProcess:
    """Invoke the CLI as a subprocess to capture the real exit code."""
    return subprocess.run(
        [sys.executable, "-m", "pfsense_auditor", *args],
        capture_output=True, text=True,
    )


def test_cli_missing_file_exits_3():
    result = _run_cli("/tmp/this-path-does-not-exist-anywhere.xml")
    assert result.returncode == 3
    assert "does not exist" in result.stderr.lower()


def test_cli_directory_instead_of_file_exits_3(tmp_path):
    result = _run_cli(str(tmp_path))
    assert result.returncode == 3
    assert "not a regular file" in result.stderr.lower()


def test_cli_malformed_xml_exits_3(tmp_path):
    bad = tmp_path / "bogus.xml"
    bad.write_text("<not-pfsense/>")
    result = _run_cli(str(bad))
    assert result.returncode == 3
    assert "error parsing" in result.stderr.lower()


def test_cli_clean_config_exits_0(tmp_path):
    clean = tmp_path / "clean.xml"
    clean.write_text(
        """<?xml version="1.0"?>
        <pfsense>
          <version>23.5</version>
          <system>
            <hostname>clean</hostname><domain>example.com</domain>
            <timeservers>0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org</timeservers>
            <webgui><protocol>https</protocol></webgui>
            <ssh></ssh>
            <user><name>scott</name><uid>2000</uid><scope>user</scope></user>
          </system>
          <interfaces><lan><if>em0</if><enable></enable></lan></interfaces>
          <aliases/><filter/>
          <syslog><enable></enable><remoteserver>siem.example.com</remoteserver></syslog>
        </pfsense>
        """
    )
    result = _run_cli(str(clean))
    assert result.returncode == 0


def test_cli_high_findings_exits_2():
    """The bundled synthetic config has high findings → exit 2."""
    fixture = "tests/fixtures/sample_config.xml"
    result = _run_cli(fixture)
    assert result.returncode == 2


def test_cli_profile_flag_accepts_all_builtins():
    fixture = "tests/fixtures/sample_config.xml"
    for name in BUILT_IN_PROFILES:
        result = _run_cli(fixture, "--profile", name)
        # 2 because the synthetic config has high findings under any profile
        assert result.returncode == 2, (
            f"Profile '{name}' returned exit {result.returncode}"
        )
