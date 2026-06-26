"""Operating profiles that adjust check applicability and severity.

The same configuration finding has different significance in different
environments. Lack of remote syslog forwarding is a serious finding for
a CMMC-regulated enterprise enclave; it's irrelevant noise for a home
user. Profiles let the tool match its output to the operator's context.

A profile can do three things:

1. Suppress a check entirely — the finding is never produced.
2. Override a check's severity — e.g. medium → info for home users.
3. Hide control references — CMMC / NIST IDs are noise for non-compliance
   audiences.

Three profiles ship built-in: ``home``, ``business``, and ``cmmc``
(default — matches Day 14 behaviour).

Custom user-defined profiles (loaded from YAML) are out of scope for
Day 21 but the data model is set up to support them later.
"""

from dataclasses import dataclass, field, replace
from typing import Optional

from .models import Finding


@dataclass(frozen=True)
class Profile:
    """An operating profile for the auditor."""
    name: str
    description: str
    severity_overrides: dict[str, str] = field(default_factory=dict)
    suppress_checks: frozenset[str] = field(default_factory=frozenset)
    hide_controls: bool = False

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """Return findings filtered and adjusted by this profile."""
        result: list[Finding] = []
        for f in findings:
            if f.check_id in self.suppress_checks:
                continue

            changes: dict = {}
            new_sev = self.severity_overrides.get(f.check_id)
            if new_sev is not None and new_sev != f.severity:
                changes["severity"] = new_sev
            if self.hide_controls and f.control_refs:
                changes["control_refs"] = []
            if changes:
                f = replace(f, **changes)
            result.append(f)
        return result

    def impact_summary(self, total_checks: int) -> str:
        """Short human-readable summary of what this profile changes."""
        bits: list[str] = []
        if self.suppress_checks:
            bits.append(f"{len(self.suppress_checks)} check(s) suppressed")
        if self.severity_overrides:
            bits.append(
                f"{len(self.severity_overrides)} severity override(s)"
            )
        if self.hide_controls:
            bits.append("controls hidden")
        if not bits:
            return "no adjustments"
        return ", ".join(bits)


# ---------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------

PROFILE_CMMC = Profile(
    name="cmmc",
    description=(
        "CMMC Level 2 / NIST SP 800-171 - federal contracting baseline. "
        "All checks at documented severity; control references shown."
    ),
    # No overrides or suppressions; default behaviour.
)

PROFILE_BUSINESS = Profile(
    name="business",
    description=(
        "Small/medium business without explicit compliance requirements. "
        "Lightly relaxed from CMMC baseline; control references still shown."
    ),
    severity_overrides={
        "FW-002": "info",   # Rule descriptions: nice to have, not critical
        "SYS-006": "low",   # Remote syslog: recommended, not required
    },
)

PROFILE_HOME = Profile(
    name="home",
    description=(
        "Residential pfSense without compliance considerations. "
        "Audit-trail and SIEM-dependent checks downgraded or suppressed; "
        "control references hidden."
    ),
    severity_overrides={
        "FW-003": "info",   # Pass-rule logging: rarely useful at home
        "SYS-002": "low",   # SSH password auth: still real, less critical
        "SYS-005": "info",  # 1 NTP source is fine for home
        "SYS-009": "info",  # MFA on admin: recommended but not enforced
    },
    suppress_checks=frozenset({
        "FW-002",   # Rule descriptions - no audit trail need
        "FW-004",   # Disabled rules - clutter, not security
        "FW-006",   # Unused aliases - cosmetic
        "SYS-006",  # Remote syslog - home users typically have no SIEM
    }),
    hide_controls=True,
)


BUILT_IN_PROFILES: dict[str, Profile] = {
    PROFILE_HOME.name: PROFILE_HOME,
    PROFILE_BUSINESS.name: PROFILE_BUSINESS,
    PROFILE_CMMC.name: PROFILE_CMMC,
}


def get_profile(name: str) -> Optional[Profile]:
    """Look up a built-in profile by name, or None if unknown."""
    return BUILT_IN_PROFILES.get(name.lower())
