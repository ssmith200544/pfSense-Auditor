"""Findings allowlist (suppression) loader and matcher.

A suppression file is YAML. Schema::

    suppressions:
      - check_id: FW-003
        affected: "Allow web traffic to DMZ servers"
        justification: "DMZ-to-DMZ HTTP intentionally not logged."
        owner: "scott@example.edu"      # optional
        expires: 2026-12-31              # optional (ISO date)
        ticket: "CSE-IT-1847"            # optional

The ``affected`` field supports three pattern styles:

* Exact string match (default)::

    affected: "Allow web traffic to DMZ servers"

* Shell-style glob via ``fnmatch`` (presence of ``*`` or ``?``)::

    affected: "*DMZ*"

* Regular expression (prefix with ``re:``)::

    affected: "re:^WAN.*DMZ servers$"

A bare ``*`` matches every finding of the given ``check_id``.
"""

import fnmatch
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Optional

import yaml

from .models import Finding, SuppressedFinding, Suppression


# ---------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------

class AllowlistError(Exception):
    """Raised when the allowlist file is malformed."""


def load_allowlist(path) -> list[Suppression]:
    """Load and validate a suppression YAML file.

    Returns an empty list if ``path`` does not exist (callers can probe
    for an optional default file without try/except).
    """
    p = Path(path)
    if not p.exists():
        return []

    try:
        raw = yaml.safe_load(p.read_text())
    except yaml.YAMLError as e:
        raise AllowlistError(f"YAML parse error in {p}: {e}") from e

    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise AllowlistError(
            f"{p}: expected top-level mapping, got {type(raw).__name__}"
        )

    entries = raw.get("suppressions", [])
    if not isinstance(entries, list):
        raise AllowlistError(
            f"{p}: 'suppressions' must be a list (got "
            f"{type(entries).__name__})"
        )

    out: list[Suppression] = []
    for i, item in enumerate(entries, 1):
        if not isinstance(item, dict):
            raise AllowlistError(
                f"{p}: suppression #{i} is not a mapping"
            )
        try:
            check_id = item["check_id"]
            affected = item["affected"]
            justification = item["justification"]
        except KeyError as e:
            raise AllowlistError(
                f"{p}: suppression #{i} missing required field: {e}"
            ) from e
        if not str(justification).strip():
            raise AllowlistError(
                f"{p}: suppression #{i} has empty justification"
            )

        expires_raw = item.get("expires")
        expires: Optional[date]
        if expires_raw is None:
            expires = None
        elif isinstance(expires_raw, date):
            expires = expires_raw
        else:
            try:
                expires = date.fromisoformat(str(expires_raw))
            except ValueError as e:
                raise AllowlistError(
                    f"{p}: suppression #{i} expires value "
                    f"{expires_raw!r} is not a valid ISO date"
                ) from e

        out.append(Suppression(
            check_id=str(check_id),
            affected_pattern=str(affected),
            justification=str(justification).strip(),
            owner=item.get("owner"),
            expires=expires,
            ticket=item.get("ticket"),
        ))

    return out


# ---------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------

def _pattern_matches(pattern: str, value: str) -> bool:
    """Match ``value`` against ``pattern`` using exact/glob/regex semantics.

    * ``re:<regex>``  → ``re.fullmatch``
    * ``*`` alone     → match anything
    * contains ``*`` or ``?`` → ``fnmatch.fnmatchcase``
    * else            → exact string equality
    """
    if pattern.startswith("re:"):
        try:
            return re.fullmatch(pattern[3:], value or "") is not None
        except re.error:
            return False
    if pattern == "*":
        return True
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatchcase(value or "", pattern)
    return pattern == (value or "")


def _suppression_matches(supp: Suppression, finding: Finding) -> bool:
    if supp.check_id != finding.check_id:
        return False
    return _pattern_matches(supp.affected_pattern, finding.affected or "")


# ---------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------

@dataclass
class ApplyResult:
    active: list[Finding]
    suppressed: list[SuppressedFinding]
    unused_suppressions: list[Suppression]
    expired_suppressions: list[Suppression]


def apply_suppressions(findings: list[Finding],
                       suppressions: list[Suppression],
                       today: Optional[date] = None) -> ApplyResult:
    """Apply a suppression list to findings.

    Returns active findings (not suppressed), suppressed findings (with
    their matching suppression), suppression entries that didn't match
    anything, and suppressions whose expiry is in the past (which are
    still applied — but flagged so the user re-reviews).
    """
    if today is None:
        today = date.today()

    suppressed: list[SuppressedFinding] = []
    active: list[Finding] = []
    used: set[int] = set()

    for f in findings:
        match: Optional[Suppression] = None
        for i, s in enumerate(suppressions):
            if _suppression_matches(s, f):
                match = s
                used.add(i)
                break
        if match is not None:
            suppressed.append(SuppressedFinding(finding=f, suppression=match))
        else:
            active.append(f)

    unused = [s for i, s in enumerate(suppressions) if i not in used]
    expired = [s for s in suppressions if s.is_expired(today)]

    return ApplyResult(
        active=active,
        suppressed=suppressed,
        unused_suppressions=unused,
        expired_suppressions=expired,
    )
