"""Command-line interface for the pfSense config auditor."""

from pathlib import Path

import click

from .checks import run_all_checks
from .parser import parse_config
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
    "--no-exit-code",
    is_flag=True,
    help="Always exit 0 regardless of findings (useful for piping).",
)
def main(config_path: Path,
         fmt: str,
         output: Path | None,
         allowlist: Path | None,
         no_exit_code: bool) -> None:
    """Audit a pfSense config.xml backup file.

    Parses the config, runs a set of security checks, applies the
    suppression allowlist (if any), and prints a findings report.
    """
    # 1. Parse the configuration.
    try:
        config = parse_config(config_path)
    except Exception as e:
        click.echo(f"Error parsing {config_path}: {e}", err=True)
        raise SystemExit(3)

    # 2. Determine which allowlist to load.
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

    # 3. Run checks and apply suppressions.
    findings = run_all_checks(config)
    apply = apply_suppressions(findings, suppressions)

    # 4. Render and emit.
    if fmt.lower() == "json":
        report = render_json_report(config, apply)
    elif fmt.lower() == "html":
        report = render_html_report(config, apply)
    else:
        report = render_text_report(config, apply)

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
