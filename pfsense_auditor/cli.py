"""Command-line interface for the pfSense config auditor."""

from pathlib import Path

import click

from .checks import run_all_checks
from .parser import parse_config
from .profiles import BUILT_IN_PROFILES, get_profile
from .report import (
    render_html_report,
    render_json_report,
    render_text_report,
)
from .suppressions import (
    AllowlistError,
    apply_suppressions,
    load_allowlist,
)


# Default allowlist filename looked for in the current working directory.
DEFAULT_ALLOWLIST = ".pfsense-audit-allowlist.yaml"

PROFILE_NAMES = sorted(BUILT_IN_PROFILES.keys())


def _exit_code_for(findings) -> int:
    """Map findings to a documented exit code.

    Exit codes:
      0  no findings (or only ``info`` level)
      1  at least one ``low`` or ``medium`` finding
      2  at least one ``high`` finding
      3  parser / runtime / input error
    """
    if any(f.severity == "high" for f in findings):
        return 2
    if any(f.severity in ("medium", "low") for f in findings):
        return 1
    return 0


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument(
    "config_path",
    # Note: we intentionally do NOT use exists=True / dir_okay=False here.
    # Click would emit its own usage-error exit code (2) for missing files,
    # which collides with the documented "high findings" exit code.
    # The manual check below remaps input errors to exit code 3.
    type=click.Path(path_type=Path),
)
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["text", "json", "html"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output", "-o",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write report to a file instead of stdout.",
)
@click.option(
    "--allowlist", "-a",
    type=click.Path(dir_okay=False, path_type=Path),
    help=(
        f"Path to a suppression YAML file. If omitted, "
        f"{DEFAULT_ALLOWLIST} is used when present in the current "
        "directory."
    ),
)
@click.option(
    "--profile", "-p", "profile_name",
    type=click.Choice(PROFILE_NAMES, case_sensitive=False),
    default="cmmc",
    show_default=True,
    help=(
        "Operating profile that adjusts severities and check applicability. "
        "'cmmc' is the federal contracting baseline (default), 'business' "
        "for SMB without compliance requirements, 'home' for residential."
    ),
)
@click.option(
    "--no-exit-code",
    is_flag=True,
    help="Always exit 0 regardless of findings (useful for piping).",
)
def main(config_path: Path,
         fmt: str,
         output: Path | None,
         allowlist: Path | None,
         profile_name: str,
         no_exit_code: bool) -> None:
    """Audit a pfSense config.xml backup file.

    Parses the config, runs a set of security checks, applies the
    selected profile and the suppression allowlist (if any), and
    prints a findings report.
    """
    # ---- Input validation (exit 3 for any input error) -----------
    if not config_path.exists():
        click.echo(f"Error: {config_path} does not exist.", err=True)
        raise SystemExit(3)
    if not config_path.is_file():
        click.echo(
            f"Error: {config_path} is not a regular file.", err=True
        )
        raise SystemExit(3)

    # ---- Resolve profile -----------------------------------------
    profile = get_profile(profile_name)
    if profile is None:
        # Should be unreachable thanks to click.Choice, but defend anyway.
        click.echo(f"Error: unknown profile '{profile_name}'.", err=True)
        raise SystemExit(3)

    # ---- Parse the config ----------------------------------------
    try:
        config = parse_config(config_path)
    except Exception as e:
        click.echo(f"Error parsing {config_path}: {e}", err=True)
        raise SystemExit(3)

    # ---- Resolve allowlist ---------------------------------------
    if allowlist is None:
        candidate = Path.cwd() / DEFAULT_ALLOWLIST
        if candidate.exists():
            allowlist = candidate

    suppressions = []
    if allowlist is not None:
        try:
            suppressions = load_allowlist(allowlist)
        except AllowlistError as e:
            click.echo(f"Error loading allowlist: {e}", err=True)
            raise SystemExit(3)

    # ---- Run pipeline: checks → profile → suppressions -----------
    raw_findings = run_all_checks(config)
    profiled = profile.apply(raw_findings)
    apply = apply_suppressions(profiled, suppressions)

    # ---- Render and emit -----------------------------------------
    if fmt.lower() == "json":
        report = render_json_report(config, apply, profile=profile)
    elif fmt.lower() == "html":
        report = render_html_report(config, apply, profile=profile)
    else:
        report = render_text_report(config, apply, profile=profile)

    if output:
        output.write_text(report)
        click.echo(f"Report written to {output}", err=True)
    else:
        click.echo(report)

    if no_exit_code:
        return
    raise SystemExit(_exit_code_for(apply.active))


if __name__ == "__main__":
    main()
