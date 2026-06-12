"""Command-line interface for the pfSense config auditor."""

from pathlib import Path

import click

from .checks import run_all_checks
from .parser import parse_config
from .report import render_json_report, render_text_report


# Exit codes:
#   0 = no findings or only info-level findings
#   1 = at least one low or medium finding (no highs)
#   2 = at least one high-severity finding
#   3 = parser/runtime error


def _exit_code_for(findings) -> int:
    if any(f.severity == "high" for f in findings):
        return 2
    if any(f.severity in ("medium", "low") for f in findings):
        return 1
    return 0


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument(
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["text", "json"], case_sensitive=False),
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
    "--no-exit-code",
    is_flag=True,
    help="Always exit 0 regardless of findings (useful for piping).",
)
def main(config_path: Path,
         fmt: str,
         output: Path | None,
         no_exit_code: bool) -> None:
    """Audit a pfSense config.xml backup file.

    Parses the config, runs a set of security checks, and prints a
    findings report. Designed for offline analysis of exported pfSense
    configuration backups (Diagnostics -> Backup & Restore).
    """
    try:
        config = parse_config(config_path)
    except Exception as e:
        click.echo(f"Error parsing {config_path}: {e}", err=True)
        raise SystemExit(3)

    findings = run_all_checks(config)

    if fmt.lower() == "json":
        report = render_json_report(config, findings)
    else:
        report = render_text_report(config, findings)

    if output:
        output.write_text(report)
        click.echo(f"Report written to {output}", err=True)
    else:
        click.echo(report)

    if no_exit_code:
        return
    raise SystemExit(_exit_code_for(findings))


if __name__ == "__main__":
    main()
