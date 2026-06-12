# pfsense-audit

Offline security auditor for pfSense `config.xml` backup files.

`pfsense-audit` parses an exported pfSense configuration, builds a
structured inventory, and runs a set of security checks against it.
Point it at a `config.xml` file you exported from
**Diagnostics → Backup & Restore**. No live API access, no credentials,
no production changes.

---

## Problem Definition

### What specific problem are you addressing?

Firewall configurations drift over time. Rules pile up, services get
enabled and forgotten, default community strings and HTTP management
endpoints linger from initial setup, and "temporary" any/any rules
become permanent. The configuration that was reviewed and approved on
day one is rarely the configuration running on day 300.

Detecting that drift in pfSense today means either clicking through
dozens of web UI screens manually, or reading a ~3,000-line XML file
by hand. Both approaches are slow, error-prone, and produce no
artifact an auditor can re-run six months later to verify the same
results.

### Why is the problem important?

A firewall is a perimeter control. A single misconfiguration —
SNMP open with the `public` community, the webConfigurator on HTTP,
a forgotten WAN-to-management rule — can undermine every other
control behind it. These are also exactly the kinds of findings
that show up repeatedly in real penetration tests and audit reports.

Configuration assessment is also an explicit compliance requirement.
NIST SP 800-171 CM.L2-3.4.1 / 3.4.2 require organizations to
establish and enforce baseline configurations. CMMC Level 2 inherits
those requirements. AU.L2-3.3.x requires evidence that successful
network access is being logged — which only works if pass rules
actually have logging enabled. A tool that produces deterministic,
machine-readable evidence of these checks meaningfully reduces the
effort of demonstrating compliance.

### What existing tools or approaches exist?

- **Manual review** of the web UI or raw `config.xml` — the
  baseline. Slow, inconsistent, and produces no durable artifact.
- **CIS-CAT Assessor** — the official CIS benchmark runner.
  Excellent for OS-level checks (Windows, Linux), but its pfSense
  coverage is limited and the Pro version requires a CIS membership.
- **Nipper Studio** (Titania) — commercial multi-vendor network
  device auditor. Capable, but expensive and a heavyweight install
  for a single-firewall use case.
- **Ad-hoc scripts** — many organizations maintain internal grep /
  XPath one-liners over `config.xml`. Useful but unsharable, undocumented,
  and rarely cover more than a handful of checks.
- **Host-level vulnerability scanners** (Tenable, Qualys, Rapid7) —
  scan for CVEs against running services; they do not review the
  firewall's *own* configuration.

### What gap does your tool fill?

A free, open-source, pfSense-specific configuration auditor that is:

- **Offline.** Reads an exported `config.xml`; never touches the live
  firewall. Safe to run against backups, sanitized configs, or
  archived snapshots without risk to production.
- **Repeatable.** Same input file → same findings. Suitable as
  audit evidence and for use in change-control diff workflows.
- **CMMC / NIST 800-171 aware.** Findings reference the control
  families they map to, so a finding doubles as documentation of
  why it matters.
- **Pipeline-friendly.** JSON output and severity-aware exit codes
  make the tool usable in CI or scheduled-evidence-collection jobs.
- **Lightweight.** Two Python dependencies. No database, no web
  server, no agent. Two-line installation, one-line invocation.

---

## System Design

### High-level architecture

The tool follows a straightforward three-stage pipeline:

```
config.xml  ──►  Parser  ──►  Models  ──►  Checks  ──►  Report
                 (XML)      (dataclasses) (functions)  (text/JSON)
```

1. **Parser** (`parser.py`) reads `config.xml` with `lxml` and
   constructs strongly-typed Python dataclasses. It handles pfSense's
   quirky "presence-as-flag" XML convention (`<enable></enable>`
   means enabled; absence means disabled) so downstream code never
   has to.
2. **Models** (`models.py`) define the dataclass shapes —
   `PfSenseConfig`, `Rule`, `Alias`, `User`, `Finding`, etc. Every
   later stage works against these typed objects, never against raw
   XML.
3. **Checks** (`checks.py`) are pure functions that each take a
   `PfSenseConfig` and return a list of `Finding` objects. They are
   registered in an `ALL_CHECKS` list; adding a check is one
   function and one list append.
4. **Report** (`report.py`) formats the parsed inventory and the
   findings as either human-readable text or machine-readable JSON.
5. **CLI** (`cli.py`) is a thin Click wrapper that wires the above
   together and sets a severity-aware exit code (0 / 1 / 2 / 3).

This separation matters: the parser shields the rest of the code
from XML quirks, the checks contain no I/O so they are trivially
unit-testable, and a new output format (HTML in Day 14) plugs in
without touching parsing or checks.

### Technology choices and justification

- **Python 3.10+** — type hints and built-in dataclasses keep the
  code self-documenting. Python is also the de-facto language for
  security tooling, making the tool easy for other security
  practitioners to read, modify, and extend.
- **lxml** — chosen over the standard library's `ElementTree` for
  faster parsing and full XPath 1.0 support. pfSense config files
  on busy firewalls can reach several thousand lines; `lxml` handles
  them without noticeable delay.
- **Click** — chosen over `argparse` for a cleaner declarative CLI,
  better help output, and easier expansion when sub-commands
  (`audit`, `diff`, etc.) are added in later milestones.
- **`dataclasses` (stdlib), no Pydantic** — keeps the dependency
  surface minimal. Pydantic's validation features would be
  overkill given the parser is the only producer of model objects.
- **No database, no web framework, no agents** — the tool reads
  one file and writes one report. Anything more would be added
  complexity without added value at this scope.
- **JSON output by default option, not HTML** — JSON ingests
  cleanly into Splunk and other SIEMs, which is the deployment
  target most aligned with how this would actually be used. HTML
  reporting is planned for Day 14.

---

## Evaluation

### How did you test the tool?

- A synthetic `tests/fixtures/sample_config.xml` was hand-crafted
  to deliberately trigger every check. The fixture contains
  realistic-looking but fully fake IPs, hostnames, and bcrypt
  hashes so it is safe to commit to a public repository.
- The tool was run against the synthetic config and the produced
  findings were cross-checked by hand against the deliberate
  misconfigurations.
- A minimal "clean" config (no findings expected) was also tested
  to verify the zero-findings path produces an empty findings
  section and a `0` exit code.
- Error handling was tested with (a) a non-pfSense XML document
  and (b) a non-existent file path; both produce clear error
  messages and a non-zero exit code.
- JSON output was validated by piping into `python -c "import
  json,sys; json.load(sys.stdin)"` to confirm the format is parseable.

### Results

- Against the synthetic fixture: **14 findings produced** across
  all 12 checks (some checks legitimately fire multiple times when
  a config violates the same rule in several places — for example,
  multiple pass rules without logging each generate their own
  finding).
- Severity distribution: 4 `high`, 6 `medium`, 3 `low`, 1 `info`.
- Exit code `2` returned, as expected when any `high` findings exist.
- Against the minimal clean config: zero findings, exit code `0`.
- JSON output round-trips correctly through `json.loads`.
- Total runtime on the synthetic config: under 100 ms.

### Known issues and limitations

- **Coverage is Day 7 MVP scope.** 12 checks cover common
  misconfigurations but are not exhaustive — the CIS pfSense
  Benchmark defines ~40 controls at Level 1, and full coverage is
  planned for Day 14.
- **Only tested against synthetic configs.** Real production
  `config.xml` exports may use sections (CARP, complex IPsec
  phase-2 entries, captive portal, package configs) the synthetic
  fixture does not exercise. The parser is defensive — missing
  elements return `None` rather than raising — but additional
  real-world testing is required before production use.
- **OPNsense compatibility unverified.** OPNsense forked from
  pfSense and uses a very similar XML format. The tool may work
  out of the box, may need minor adjustments, or may need a
  dedicated parser; this has not been tested.
- **Checks are hardcoded in Python.** Adding a check requires
  editing source. A YAML-driven check definition system is planned
  for Day 14 so non-developers can contribute checks.
- **No diff capability yet.** Comparing two `config.xml` files for
  drift is the Day 21 milestone.
- **No HTML report yet.** Text and JSON only at Day 7; HTML is
  planned for Day 14.
- **Bcrypt hash strength is not evaluated.** The tool detects that
  the default `admin` account exists but does not assess password
  hash quality. This is a deliberate scope decision — assessing
  hashes requires either a brute-force harness or strong
  assumptions about pfSense's hash format.

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
