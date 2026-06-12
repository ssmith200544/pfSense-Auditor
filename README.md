# pfsense-audit

Offline security auditor for pfSense `config.xml` backup files.

`pfsense-audit` parses an exported pfSense configuration, builds a
structured inventory, and runs a set of security checks against it.
Point it at a `config.xml` file you exported from
**Diagnostics → Backup & Restore**. No live API access, no credentials,
no production changes.

---

## Quick Start

You need **Python 3.10 or later** installed. Verify by running
`python --version` (Windows) or `python3 --version` (macOS / Linux).
If you don't have it, install from <https://www.python.org/downloads/>.
On Windows, check **"Add Python to PATH"** during installation.

### Windows (PowerShell or Command Prompt)

From the project root (the folder containing `run.bat`):

```powershell
.\run.bat tests\fixtures\sample_config.xml
```

That's it. The wrapper installs dependencies on first run and then
executes the tool. You should see an audit report with 14 findings
against the included synthetic config.

### macOS / Linux

```bash
chmod +x run.sh                                  # one-time, makes it executable
./run.sh tests/fixtures/sample_config.xml
```

### What the wrapper does

The `run.bat` / `run.sh` scripts are convenience wrappers that:

1. Verify Python is installed and on `PATH`.
2. Install dependencies (`lxml`, `click`) from `requirements.txt`.
3. Invoke the tool with whatever arguments you passed.

They are safe to run repeatedly; `pip` skips packages that are
already installed.

---

## Running Against Your Own Config

Export a backup from your pfSense web UI:
**Diagnostics → Backup & Restore → Download configuration**.

Save the file somewhere outside this repo (real configs should never
be committed). Then:

```powershell
# Windows
.\run.bat "C:\path\to\config.xml"
.\run.bat "C:\path\to\config.xml" -f json
.\run.bat "C:\path\to\config.xml" -o report.txt
```

```bash
# macOS / Linux
./run.sh ~/configs/firewall.xml
./run.sh ~/configs/firewall.xml -f json
./run.sh ~/configs/firewall.xml -o report.txt
```

### Options

| Flag                 | Description                                    |
|----------------------|------------------------------------------------|
| `-f`, `--format`     | `text` (default) or `json`                     |
| `-o`, `--output`     | Write report to a file instead of stdout       |
| `--no-exit-code`     | Always exit 0 (useful when piping)             |
| `-h`, `--help`       | Show usage information                         |

### Exit codes

| Code | Meaning                                  |
|------|------------------------------------------|
| 0    | No findings, or only `info` findings     |
| 1    | At least one `low` or `medium` finding   |
| 2    | At least one `high` finding              |
| 3    | Parser / runtime error                   |

---

## Running Without the Wrapper

If you'd rather invoke Python directly (e.g. in a CI pipeline), the
wrapper is just shorthand for two commands. From the project root:

```
pip install -r requirements.txt
python -m pfsense_auditor tests/fixtures/sample_config.xml
```

On Windows use `python`; on macOS / Linux use `python3` if `python`
isn't aliased.

---

## Checks Implemented (Day 7 MVP)

| ID      | Severity      | Check                                            |
|---------|---------------|--------------------------------------------------|
| FW-001  | high          | Permissive any/any pass rules                    |
| FW-002  | low           | Rules with no description                        |
| FW-003  | medium        | Pass rules with logging disabled                 |
| FW-004  | info          | Disabled rules left in the configuration         |
| FW-005  | high          | WAN pass rules with destination `(self)`         |
| FW-006  | low           | Aliases defined but never referenced             |
| SYS-001 | high          | webConfigurator running on HTTP                  |
| SYS-002 | medium        | SSH enabled with password auth allowed           |
| SYS-003 | medium        | Built-in `admin` account still enabled           |
| SYS-004 | high          | SNMP enabled with default community string       |
| SYS-005 | low / medium  | NTP missing or fewer than three sources          |
| SYS-006 | medium        | No remote syslog forwarding configured           |

---

## Project Layout

```
pfsense_auditor/                  <- repo root
├── pfsense_auditor/              <- the Python package
│   ├── __init__.py
│   ├── __main__.py               <- enables `python -m pfsense_auditor`
│   ├── cli.py                    <- Click CLI definition
│   ├── parser.py                 <- config.xml -> dataclasses
│   ├── models.py                 <- PfSenseConfig, Rule, Finding, ...
│   ├── checks.py                 <- audit checks; ALL_CHECKS registry
│   └── report.py                 <- text and JSON formatters
├── tests/
│   └── fixtures/
│       └── sample_config.xml     <- synthetic config (safe to share)
├── run.bat                       <- Windows wrapper
├── run.sh                        <- macOS / Linux wrapper
├── requirements.txt              <- pip dependencies
├── pyproject.toml                <- packaging metadata
├── LICENSE
└── README.md
```

---

## Why Offline?

- Auditors review configuration evidence, not live systems.
- No credentials, no API access, no production firewall changes.
- The same input file produces the same report — repeatable evidence.
- Works against any pfSense version emitting compatible `config.xml`.

---

## Roadmap

**Day 14** — expanded coverage and HTML reporting:

- Data-driven check definitions (YAML) so non-developers can add checks.
- ~40 checks aligned to the CIS pfSense Benchmark, Level 1.
- Jinja2-based HTML report with grouped findings and filtering.
- CMMC control cross-references on each finding.

**Day 21** — diff mode for change-control evidence:

- `pfsense-audit diff old.xml new.xml` — compare two configs.
- Highlight added / removed / modified rules, aliases, users, services.
- Risk-classify changes (e.g. "rule loosened" vs "rule tightened").
- HTML side-by-side view.

---

## Development

For active development with isolated dependencies, use a virtual
environment and an editable install. Run these from the project root.

### Windows

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
pfsense-audit tests\fixtures\sample_config.xml
```

If PowerShell blocks the activation script with an execution-policy
error, run this once (as your normal user, not Admin):

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pfsense-audit tests/fixtures/sample_config.xml
```

The editable install (`-e`) creates a `pfsense-audit` command on your
`PATH` and reflects code changes immediately without reinstall.

### Adding a New Check

1. Write a function in `pfsense_auditor/checks.py` that takes a
   `PfSenseConfig` and returns `list[Finding]`. Use a stable
   `check_id` (e.g. `FW-007`).
2. Append the function to the `ALL_CHECKS` list at the bottom of
   `checks.py`.
3. Document it in the Checks Implemented table above.

---

## License

MIT — see `LICENSE`.
