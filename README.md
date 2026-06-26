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

- A synthetic `tests/fixtures/sample_config.xml` was hand-crafted to
  trigger every check. The fixture contains realistic-looking but
  fully fake IPs, hostnames, certificates, and bcrypt hashes so it
  is safe to commit to a public repository.
- A **pytest suite** in `tests/test_checks.py` covers each check
  function in isolation, plus the suppression engine's pattern
  matching (exact / glob / regex), unused-suppression detection, and
  expired-suppression handling. 35 tests total.
- The tool was also run end-to-end against the synthetic config and
  the findings cross-checked by hand against the deliberate
  misconfigurations.
- A minimal "clean" config (no findings expected) was tested to
  verify the zero-findings path produces an empty findings section
  and a `0` exit code.
- Error handling was tested with a non-pfSense XML document and a
  non-existent file path; both produce clear error messages and a
  non-zero exit code.
- JSON output was validated by piping through `python -c "import
  json,sys; json.load(sys.stdin)"`. HTML output was validated by
  rendering in a browser.

### Results

- Against the synthetic fixture: **23 findings produced** across
  all 18 checks (9 high, 10 medium, 3 low, 1 info). Exit code `2`
  returned as expected when high findings exist.
- With the sample allowlist applied: 3 findings suppressed, 1
  expired suppression flagged, 1 unused suppression flagged.
- Against the minimal clean config: zero findings, exit code `0`.
- JSON output round-trips correctly through `json.loads`.
- HTML report renders correctly with severity filtering working.
- Total runtime on the synthetic config: under 100 ms.
- Pytest suite: 35 tests, all passing, runs in under one second.

### Known issues and limitations

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
- **Checks are hardcoded in Python.** A YAML-driven check
  definition system would let non-developers contribute checks
  without touching source.
- **No diff capability yet.** Comparing two `config.xml` files for
  drift is the Day 21 milestone.
- **Certificate parsing relies on metadata fields.** The tool reads
  `<not_after>`, `<key_size>`, etc. as exposed by recent pfSense
  versions. Older configs storing only the raw PEM in `<crt>` would
  need an additional decode step (planned).
- **No support for evaluating bcrypt password strength.** The tool
  detects whether MFA factors exist; it does not score the
  password itself.

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

| Flag                 | Description                                                 |
|----------------------|-------------------------------------------------------------|
| `-f`, `--format`     | `text` (default), `json`, or `html`                         |
| `-o`, `--output`     | Write report to a file instead of stdout                    |
| `-a`, `--allowlist`  | Path to a YAML suppression file (see below)                 |
| `--no-exit-code`     | Always exit 0 (useful when piping)                          |
| `-h`, `--help`       | Show usage information                                      |

If `--allowlist` is not provided, `.pfsense-audit-allowlist.yaml` is
loaded from the current directory if present.

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

## Checks Implemented

Eighteen checks, each tagged with the NIST SP 800-171 / CMMC control
families it maps to. Control references appear inline in every report
format.

### Firewall (FW)

| ID      | Severity      | Check                                            | Controls                            |
|---------|---------------|--------------------------------------------------|-------------------------------------|
| FW-001  | high          | Permissive any/any pass rules                    | AC.L2-3.1.3, SC.L2-3.13.1           |
| FW-002  | low           | Rules with no description                        | CM.L2-3.4.1, CM.L2-3.4.2            |
| FW-003  | medium        | Pass rules with logging disabled                 | AU.L2-3.3.1, AU.L2-3.3.2            |
| FW-004  | info          | Disabled rules left in the configuration         | CM.L2-3.4.1                         |
| FW-005  | high          | WAN pass rules with destination `(self)`         | AC.L2-3.1.3, AC.L2-3.1.13           |
| FW-006  | low           | Aliases defined but never referenced             | CM.L2-3.4.2                         |
| FW-007  | high          | **IPsec phase 1/2 using weak crypto**            | SC.L2-3.13.8, SC.L2-3.13.11         |
| FW-008  | high / medium | **NAT port-forwards exposing SSH, RDP, etc.**    | AC.L2-3.1.3, SC.L2-3.13.6           |

### System (SYS)

| ID      | Severity      | Check                                            | Controls                            |
|---------|---------------|--------------------------------------------------|-------------------------------------|
| SYS-001 | high          | webConfigurator running on HTTP                  | SC.L2-3.13.8                        |
| SYS-002 | medium        | SSH enabled with password auth allowed           | IA.L2-3.5.3, IA.L2-3.5.7            |
| SYS-003 | medium        | Built-in `admin` account still enabled           | IA.L2-3.5.1, IA.L2-3.5.2            |
| SYS-004 | high          | SNMP enabled with default community string       | IA.L2-3.5.7, SC.L2-3.13.1           |
| SYS-005 | low / medium  | NTP missing or fewer than three sources          | AU.L2-3.3.7                         |
| SYS-006 | medium        | No remote syslog forwarding configured           | AU.L2-3.3.8, AU.L2-3.3.9            |
| SYS-007 | high / medium | **Certificates expired or expiring (≤30 days)** | SC.L2-3.13.10                       |
| SYS-008 | medium        | **Certificates with weak crypto (SHA-1, RSA<2048)** | SC.L2-3.13.8, SC.L2-3.13.11      |
| SYS-009 | medium        | **Admin users without TOTP or SSH keys**         | IA.L2-3.5.3                         |
| SYS-010 | medium        | **User accounts past expiry but still enabled**  | AC.L2-3.1.1, IA.L2-3.5.6            |

Bold entries are new in Day 14.

---

## Suppressions (Allowlist)

Some findings represent accepted risks. The tool supports a YAML
**allowlist** file that suppresses specific findings — with a required
justification so suppressions are auditable rather than invisible.

By default the tool loads `.pfsense-audit-allowlist.yaml` from the
current directory. Pass `-a /path/to/file.yaml` to use a different one.

### Schema

```yaml
suppressions:
  - check_id: FW-003                              # required
    affected: "Allow web traffic to DMZ servers"  # required
    justification: "Covered by Suricata on DMZ uplink."  # required
    owner: "scott@example.edu"                    # optional
    expires: 2026-12-31                           # optional (ISO date)
    ticket: "CSE-IT-1847"                         # optional
```

### Affected matching

The `affected` field supports three styles:

| Pattern style       | Example                       | Behaviour                                |
|---------------------|-------------------------------|------------------------------------------|
| Exact string        | `"Allow web traffic"`         | Match must be identical                  |
| Wildcard (`*` only) | `"*"`                         | Matches every finding of this `check_id` |
| Glob (`*` or `?`)   | `"*DMZ*"`                     | Shell-style match via `fnmatch`          |
| Regex               | `"re:^WAN.*self$"`            | Python regex via `re.fullmatch`          |

### Audit behaviour

The report shows a **Suppressed** section listing every suppressed
finding alongside its justification, owner, ticket, and expiry. Two
warnings are emitted automatically:

- **Expired suppressions** — entries whose `expires` date is in the
  past. Still applied, but flagged for re-review.
- **Unused suppressions** — entries that did not match any finding.
  Useful for catching stale rules after a config change.

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

### ✅ Day 14 — delivered

- 6 new checks: IPsec weak crypto, high-risk port forwards, certificate
  expiry, certificate weak crypto, privileged users without MFA,
  expired-but-enabled user accounts (total: 18 checks)
- **Findings allowlist** with exact / glob / regex matching, expiry
  tracking, and unused-rule detection
- **HTML report** with severity filtering, control mapping inline
- **CMMC / NIST 800-171 control mapping** on every finding
- Pytest test suite (35 tests covering checks and suppression engine)

### Day 21 — diff mode (planned)

- `pfsense-audit diff old.xml new.xml` — compare two configs
- Risk-classify changes (rule loosened, service added, user added)
- HTML side-by-side view for change-control evidence

### Future

- Full CIS pfSense Benchmark Level 1 coverage (~40 checks)
- SARIF output for GitHub PR integration
- CSV output for auditor workflows
- YAML-driven check definitions for non-developer contributions

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
   `check_id` (e.g. `FW-009`).
2. Include `control_refs` listing the NIST 800-171 / CMMC controls
   the check maps to.
3. Append the function to the `ALL_CHECKS` list at the bottom of
   `checks.py`.
4. Add a unit test in `tests/test_checks.py` that builds a minimal
   config exercising the check and asserts the expected `check_id`
   fires.
5. Document it in the Checks Implemented table above.

### Running the Test Suite

```bash
pip install -e ".[test]"
pytest -v
```

The suite has 35 tests covering each check function and the
suppression engine (exact, glob, regex matching, expired and unused
suppressions). Runs in under a second.

---

## AI Usage

This tool was developed in collaboration with **Claude (Anthropic)**.
The workflow was iterative and roughly followed these steps:

1. **Scoping conversation.** Several candidate tool ideas were
   discussed against the CSC-842 theme and the 7 / 14 / 21-day
   cadence. The pfSense configuration auditor was selected for its
   tight scope and direct fit with the author's work environment.
2. **Architecture review.** The three-stage pipeline
   (Parser → Models → Checks → Report) was sketched and agreed on
   before any code was written.
3. **Initial implementation.** Claude generated the first pass of
   `parser.py`, `models.py`, `checks.py`, `report.py`, `cli.py`, the
   synthetic test fixture, the wrapper scripts, and the project
   scaffolding.
4. **Iterative refinement.** The README was rewritten after Windows
   usability issues surfaced during the first test run. Cross-platform
   wrapper scripts were added in response. The Phase 1 documentation
   sections were added later to match the assignment requirements.

All design decisions were reviewed before adoption. The generated
code was executed end-to-end against the synthetic fixture and the
expected findings verified by hand. The author is responsible for
the correctness, integrity, and ongoing maintenance of the tool.

---

## License

MIT — see `LICENSE`.
